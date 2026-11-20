use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use tracing::{debug, info};

use crate::{
    config::{StreamConfig, StreamMode},
    proxy_protocol::{self, Addresses, Version},
};

pub(crate) struct BufferedStream {
    prefix: Bytes,
    inner: TcpStream,
}

impl BufferedStream {
    pub(crate) fn new(prefix: Bytes, inner: TcpStream) -> Self {
        Self { prefix, inner }
    }
}

impl AsyncRead for BufferedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let count = self.prefix.len().min(buffer.remaining());
            buffer.put_slice(&self.prefix.split_to(count));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for BufferedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

pub struct StreamProxy {
    listener: StreamConfig,
    routes: Arc<[StreamRoute]>,
}

pub(crate) struct StreamRoute {
    sni: Option<String>,
    upstreams: Vec<String>,
    next_upstream: AtomicUsize,
    proxy_protocol: Option<Version>,
}

impl StreamProxy {
    pub fn new(config: StreamConfig) -> Self {
        let routes = config
            .routes
            .iter()
            .map(|route| StreamRoute {
                sni: route
                    .sni
                    .as_deref()
                    .map(|name| name.trim_end_matches('.').to_ascii_lowercase()),
                upstreams: route.upstreams.clone(),
                next_upstream: AtomicUsize::new(0),
                proxy_protocol: route.proxy_protocol,
            })
            .collect::<Vec<_>>();
        Self {
            listener: config,
            routes: routes.into(),
        }
    }

    pub async fn run(self) -> Result<()> {
        run_proxies([self]).await
    }
}

async fn accept_loop(proxy: Arc<StreamProxy>, listener: TcpListener) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            if let Err(error) = proxy.serve_socket(stream).await {
                debug!(%peer, %error, "stream connection closed");
            }
        });
    }
}

pub(crate) fn listener_workers() -> usize {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return std::thread::available_parallelism().map_or(1, usize::from);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return 1;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn bind_listener(address: std::net::SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(address))?;
    socket.listen(4096)?;
    TcpListener::from_std(socket.into()).map_err(Into::into)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn bind_listener(address: std::net::SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(address).await?)
}

impl StreamProxy {
    pub(crate) async fn serve_socket(&self, client: TcpStream) -> Result<()> {
        let addresses =
            client
                .peer_addr()
                .ok()
                .zip(client.local_addr().ok())
                .map(|(source, destination)| Addresses {
                    source,
                    destination,
                });
        self.serve_socket_with_addresses(client, addresses).await
    }

    pub(crate) async fn serve_socket_with_addresses(
        &self,
        mut client: TcpStream,
        addresses: Option<Addresses>,
    ) -> Result<()> {
        let (sni, prefix) = match self.listener.mode {
            StreamMode::Tcp => (None, BytesMut::new()),
            StreamMode::TlsPassthrough => {
                let mut prefix = BytesMut::with_capacity(self.listener.max_handshake_bytes);
                let sni = timeout(
                    Duration::from_secs(self.listener.handshake_timeout_secs),
                    read_sni(&mut client, &mut prefix, self.listener.max_handshake_bytes),
                )
                .await
                .context("timed out reading TLS ClientHello")??;
                (sni, prefix)
            }
        };
        let route = self.route(sni.as_deref()).ok_or_else(|| {
            anyhow!(
                "no TLS passthrough route for SNI {}",
                sni.as_deref().unwrap_or("<absent>")
            )
        })?;
        self.relay(client, route, &prefix, sni.as_deref(), addresses)
            .await
    }

    pub(crate) fn handshake_settings(&self) -> (Duration, usize) {
        (
            Duration::from_secs(self.listener.handshake_timeout_secs),
            self.listener.max_handshake_bytes,
        )
    }

    pub(crate) async fn relay(
        &self,
        mut client: TcpStream,
        route: &StreamRoute,
        prefix: &[u8],
        sni: Option<&str>,
        addresses: Option<Addresses>,
    ) -> Result<()> {
        client.set_nodelay(true)?;
        let upstream_address = route.select();
        let mut upstream = timeout(
            Duration::from_secs(self.listener.connect_timeout_secs),
            TcpStream::connect(upstream_address),
        )
        .await
        .context("timed out connecting to upstream")?
        .with_context(|| format!("failed to connect to upstream {upstream_address}"))?;
        upstream.set_nodelay(true)?;
        let idle = Duration::from_secs(self.listener.idle_timeout_secs);
        timeout(idle, async {
            if let Some(version) = route.proxy_protocol {
                proxy_protocol::write(&mut upstream, version, addresses).await?;
            }
            upstream.write_all(prefix).await
        })
        .await??;
        debug!(
            sni = sni.unwrap_or("-"),
            upstream = upstream_address,
            "stream connected"
        );
        copy_bidirectional_idle(&mut client, &mut upstream, idle).await?;
        Ok(())
    }

    pub(crate) fn route(&self, sni: Option<&str>) -> Option<&StreamRoute> {
        match self.listener.mode {
            StreamMode::Tcp => self.routes.first(),
            StreamMode::TlsPassthrough => {
                let fallback = || {
                    self.routes
                        .iter()
                        .find(|route| route.sni.as_deref() == Some("*"))
                };
                let Some(sni) = sni.map(|sni| sni.trim_end_matches('.').to_ascii_lowercase())
                else {
                    return fallback();
                };
                self.routes
                    .iter()
                    .find(|route| route.sni.as_deref() == Some(sni.as_str()))
                    .or_else(|| {
                        self.routes.iter().find(|route| {
                            route
                                .sni
                                .as_deref()
                                .is_some_and(|pattern| pattern != "*" && sni_matches(pattern, &sni))
                        })
                    })
                    .or_else(fallback)
            }
        }
    }
}

impl StreamRoute {
    pub(crate) fn specificity(&self) -> u8 {
        match self.sni.as_deref() {
            None | Some("*") => 0,
            Some(name) if name.starts_with("*.") => 1,
            Some(_) => 2,
        }
    }
}

impl StreamRoute {
    fn select(&self) -> &str {
        &self.upstreams[self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.upstreams.len()]
    }
}

pub fn sni_matches(pattern: &str, sni: &str) -> bool {
    if pattern == "*" || pattern.eq_ignore_ascii_case(sni) {
        return true;
    }
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        let Some((first, rest)) = sni.split_once('.') else {
            return false;
        };
        !first.is_empty() && rest.eq_ignore_ascii_case(suffix)
    })
}

pub(crate) async fn read_sni(
    stream: &mut TcpStream,
    buffer: &mut BytesMut,
    limit: usize,
) -> Result<Option<String>> {
    let mut record_offset = 0;
    let mut fragmented = Vec::new();
    let mut hello_length = None;
    loop {
        while buffer.len() < record_offset + 5 {
            read_chunk(stream, buffer, limit).await?;
        }
        if buffer[record_offset] != 22 {
            bail!("TLS connection does not start with a handshake record");
        }
        let record_length = usize::from(u16::from_be_bytes([
            buffer[record_offset + 3],
            buffer[record_offset + 4],
        ]));
        let record_end = record_offset
            .checked_add(
                5_usize
                    .checked_add(record_length)
                    .ok_or_else(|| anyhow!("TLS record length overflow"))?,
            )
            .ok_or_else(|| anyhow!("TLS record length overflow"))?;
        if record_end > limit {
            bail!("TLS record exceeds handshake limit");
        }
        while buffer.len() < record_end {
            read_chunk(stream, buffer, limit).await?;
        }
        let handshake = &buffer[record_offset + 5..record_end];
        if record_offset == 0 && handshake.len() >= 4 {
            let length = client_hello_length(handshake, limit)?;
            if let Some(hello) = handshake.get(..length) {
                return parse_client_hello(hello);
            }
            hello_length = Some(length);
        }
        fragmented.extend_from_slice(handshake);
        if hello_length.is_none() && fragmented.len() >= 4 {
            hello_length = Some(client_hello_length(&fragmented, limit)?);
        }
        if let Some(hello) = hello_length.and_then(|length| fragmented.get(..length)) {
            return parse_client_hello(hello);
        }
        record_offset = record_end;
    }
}

async fn read_chunk(stream: &mut TcpStream, buffer: &mut BytesMut, limit: usize) -> Result<()> {
    if buffer.len() >= limit {
        bail!("TLS handshake exceeds configured limit");
    }
    let remaining = limit - buffer.len();
    if stream.read_buf(&mut buffer.limit(remaining)).await? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed during ClientHello",
        )
        .into());
    }
    Ok(())
}

fn client_hello_length(header: &[u8], limit: usize) -> Result<usize> {
    if header[0] != 1 {
        bail!("first TLS handshake message is not ClientHello");
    }
    let length = 4 + u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
    if length > limit {
        bail!("ClientHello exceeds handshake limit");
    }
    Ok(length)
}

fn parse_client_hello(data: &[u8]) -> Result<Option<String>> {
    if data.len() < 39 || data[0] != 1 {
        bail!("truncated or invalid ClientHello");
    }
    let session_len = data[38] as usize;
    let cipher_len_offset = 39 + session_len;
    let cipher_len = take_u16(data, cipher_len_offset)? as usize;
    if !cipher_len.is_multiple_of(2) {
        bail!("odd cipher suite length");
    }
    let compression_offset = cipher_len_offset + 2 + cipher_len;
    if compression_offset >= data.len() {
        bail!("missing compression methods");
    }
    let compression_len = data[compression_offset] as usize;
    let extensions_offset = compression_offset + 1 + compression_len;
    if extensions_offset == data.len() {
        return Ok(None);
    }
    if extensions_offset + 2 > data.len() {
        bail!("truncated ClientHello extensions length");
    }
    let extension_bytes = take_u16(data, extensions_offset)? as usize;
    let mut cursor = extensions_offset + 2;
    let end = cursor
        .checked_add(extension_bytes)
        .ok_or_else(|| anyhow!("extension length overflow"))?;
    if end > data.len() {
        bail!(
            "truncated ClientHello extensions: end={} len={}",
            end,
            data.len()
        );
    }
    while cursor < end {
        if cursor + 4 > end {
            bail!("truncated TLS extension header");
        }
        let kind = take_u16(data, cursor)?;
        let length = take_u16(data, cursor + 2)? as usize;
        cursor += 4;
        let extension_end = cursor
            .checked_add(length)
            .filter(|extension_end| *extension_end <= end)
            .ok_or_else(|| anyhow!("truncated TLS extension"))?;
        if kind != 0 {
            cursor = extension_end;
            continue;
        }
        let list_length = take_u16(data, cursor)? as usize;
        let mut names = cursor + 2;
        let names_end = names
            .checked_add(list_length)
            .filter(|end| *end <= extension_end)
            .ok_or_else(|| anyhow!("truncated SNI extension"))?;
        let mut sni = None;
        while names < names_end {
            let name_type = take_u8(data, names)?;
            let length = take_u16(data, names + 1)? as usize;
            names += 3;
            let name_end = names
                .checked_add(length)
                .filter(|end| *end <= names_end)
                .ok_or_else(|| anyhow!("truncated SNI name"))?;
            if name_type == 0 {
                if sni.is_some() {
                    bail!("ClientHello contains multiple host_name entries");
                }
                let name = std::str::from_utf8(&data[names..name_end])?;
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
                {
                    bail!("invalid SNI hostname");
                }
                sni = Some(name.trim_end_matches('.').to_ascii_lowercase());
            }
            names = name_end;
        }
        if names != names_end {
            bail!("invalid SNI extension");
        }
        return Ok(sni);
    }
    Ok(None)
}

fn take_u8(data: &[u8], offset: usize) -> Result<u8> {
    data.get(offset)
        .copied()
        .ok_or_else(|| anyhow!("truncated ClientHello"))
}

fn take_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("truncated ClientHello"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

async fn copy_bidirectional_idle(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle: Duration,
) -> Result<()> {
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let start = Instant::now();
    let last_write = AtomicU64::new(0);
    let copying = async {
        tokio::try_join!(
            copy_direction(&mut client_read, &mut upstream_write, start, &last_write),
            copy_direction(&mut upstream_read, &mut client_write, start, &last_write),
        )?;
        Ok(())
    };
    let watchdog = async {
        loop {
            let latest = Duration::from_nanos(last_write.load(Ordering::Relaxed));
            let elapsed = start.elapsed().saturating_sub(latest);
            if elapsed >= idle {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "stream idle timeout").into());
            }
            sleep_until(Instant::now() + (idle - elapsed)).await;
        }
    };
    tokio::select! {
        result = copying => result,
        result = watchdog => result,
    }
}

async fn copy_direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    start: Instant,
    last_write: &AtomicU64,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return writer.shutdown().await;
        }
        let mut pending = &buffer[..count];
        while !pending.is_empty() {
            let sent = writer.write(pending).await?;
            if sent == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            last_write.store(
                u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            pending = &pending[sent..];
        }
    }
}

pub async fn run_all(configs: Vec<StreamConfig>) -> Result<()> {
    run_proxies(configs.into_iter().map(StreamProxy::new)).await
}

async fn run_proxies(proxies: impl IntoIterator<Item = StreamProxy>) -> Result<()> {
    let workers = listener_workers();
    let mut listeners = Vec::new();
    let mut addresses = std::collections::HashSet::new();
    for proxy in proxies {
        if !addresses.insert(proxy.listener.listen) {
            bail!(
                "use Runtime for shared stream listeners on {}",
                proxy.listener.listen
            );
        }
        let proxy = Arc::new(proxy);
        for _ in 0..workers {
            let listener = bind_listener(proxy.listener.listen)
                .await
                .with_context(|| {
                    format!(
                        "could not bind stream listener on {}",
                        proxy.listener.listen
                    )
                })?;
            listeners.push((proxy.clone(), listener));
        }
        info!(address = %proxy.listener.listen, mode = ?proxy.listener.mode, workers, "TCP stream listening");
    }
    let mut tasks = JoinSet::new();
    for (proxy, listener) in listeners {
        tasks.spawn(accept_loop(proxy, listener));
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_routes_match_one_label_wildcards() {
        assert!(sni_matches("example.com", "EXAMPLE.com"));
        assert!(sni_matches("*.example.com", "www.example.com"));
        assert!(!sni_matches("*.example.com", "a.b.example.com"));
        assert!(!sni_matches("*.example.com", "example.com"));
        assert!(sni_matches("*", "anything.example.com"));
    }

    #[test]
    fn tls_routes_prioritize_exact_names_then_wildcards_then_fallback() {
        let config = StreamConfig {
            listen: "127.0.0.1:9443".parse().unwrap(),
            mode: StreamMode::TlsPassthrough,
            routes: ["*.example.com", "*", "app.example.com"]
                .into_iter()
                .map(|name| crate::config::StreamRouteConfig {
                    sni: Some(name.to_owned()),
                    upstreams: vec!["127.0.0.1:443".to_owned()],
                    proxy_protocol: None,
                })
                .collect(),
            connect_timeout_secs: 10,
            idle_timeout_secs: 300,
            handshake_timeout_secs: 10,
            max_handshake_bytes: 16384,
        };
        let proxy = StreamProxy::new(config);
        for (sni, pattern) in [
            (Some("app.example.com"), "app.example.com"),
            (Some("www.example.com"), "*.example.com"),
            (Some("other.test"), "*"),
            (None, "*"),
        ] {
            assert_eq!(proxy.route(sni).unwrap().sni.as_deref(), Some(pattern));
        }
    }

    fn test_client_hello() -> Vec<u8> {
        let name = b"www.example.com";
        let mut names = vec![0_u8];
        names.extend_from_slice(&(name.len() as u16).to_be_bytes());
        names.extend_from_slice(name);
        let mut sni_extension = Vec::new();
        sni_extension.extend_from_slice(&0_u16.to_be_bytes());
        sni_extension.extend_from_slice(&(2 + names.len() as u16).to_be_bytes());
        sni_extension.extend_from_slice(&(names.len() as u16).to_be_bytes());
        sni_extension.extend_from_slice(&names);
        let mut hello = vec![1, 0, 0, 0, 3, 3];
        hello.extend_from_slice(&[0_u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0_u8, 2]);
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
        hello.extend_from_slice(&sni_extension);
        let length = hello.len() - 4;
        hello[1..4].copy_from_slice(&(length as u32).to_be_bytes()[1..]);
        hello
    }

    #[test]
    fn parses_fragmented_and_tls13_client_hello() {
        let parsed = parse_client_hello(&test_client_hello()).unwrap();
        assert_eq!(parsed.as_deref(), Some("www.example.com"));
    }

    #[tokio::test]
    async fn fragmented_handshake_is_parsed_and_preserved() {
        let hello = test_client_hello();
        let mut record = Vec::new();
        for fragment in [&hello[..2], &hello[2..3], &hello[3..]] {
            record.extend_from_slice(&[22, 3, 3]);
            record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            record.extend_from_slice(fragment);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected = record.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = BytesMut::with_capacity(16384);
            let sni = read_sni(&mut stream, &mut buffer, 16384).await.unwrap();
            assert_eq!(sni.as_deref(), Some("www.example.com"));
            assert_eq!(buffer.as_ref(), expected);
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        for chunk in record.chunks(3) {
            client.write_all(chunk).await.unwrap();
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn later_listener_bind_failure_is_reported() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap();
        let config = StreamConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            mode: StreamMode::Tcp,
            routes: Vec::new(),
            connect_timeout_secs: 1,
            idle_timeout_secs: 1,
            handshake_timeout_secs: 1,
            max_handshake_bytes: 16384,
        };
        let result = timeout(
            Duration::from_secs(2),
            run_all(vec![
                config.clone(),
                StreamConfig {
                    listen: address,
                    ..config
                },
            ]),
        )
        .await
        .unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains(&address.to_string())
        );
    }

    #[tokio::test]
    async fn idle_timeout_is_shared_across_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, relay) = tokio::join!(TcpStream::connect(address), listener.accept());
        let (mut client, (mut relay_client, _)) = (client.unwrap(), relay.unwrap());
        let (upstream, relay) = tokio::join!(TcpStream::connect(address), listener.accept());
        let (mut upstream, (mut relay_upstream, _)) = (upstream.unwrap(), relay.unwrap());
        let idle = Duration::from_millis(200);
        timeout(Duration::from_secs(5), async {
            let traffic = async {
                for value in 0..12_u8 {
                    upstream.write_all(&[value]).await.unwrap();
                    assert_eq!(client.read_u8().await.unwrap(), value);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            };
            let relay = async {
                let error = copy_bidirectional_idle(&mut relay_client, &mut relay_upstream, idle)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.downcast_ref::<io::Error>().unwrap().kind(),
                    io::ErrorKind::TimedOut
                );
                drop(relay_client);
                drop(relay_upstream);
            };
            tokio::join!(traffic, relay);
        })
        .await
        .unwrap();
    }

    #[test]
    fn rejects_truncated_hello() {
        let hello = test_client_hello();
        for length in 0..39 {
            assert!(parse_client_hello(&hello[..length]).is_err());
        }
    }
}
