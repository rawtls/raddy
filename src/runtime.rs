use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::BytesMut;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    cloudflare::Cloudflare,
    config::{Config, StreamMode},
    proxy_protocol::{self, Addresses},
    server::Server,
    stream::{BufferedStream, StreamProxy, read_sni},
};

#[derive(Clone, Default)]
pub(crate) struct Connections {
    pub drain: CancellationToken,
    pub force: CancellationToken,
    pub tasks: TaskTracker,
    pub(crate) addresses: Option<Addresses>,
    pub(crate) admission: Option<Arc<Admission>>,
}

#[derive(Default)]
struct ConnectionLimit {
    active: AtomicUsize,
}

pub(crate) struct Admission(Arc<ConnectionLimit>);

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConnectionLimit {
    fn admit(self: &Arc<Self>, max: usize) -> Option<Admission> {
        self.active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (max == 0 || active < max).then(|| active + 1)
            })
            .ok()?;
        Some(Admission(self.clone()))
    }
}

#[derive(Clone)]
enum Endpoint {
    Http(Arc<Server>, CancellationToken),
    Tls(Arc<TlsEndpoint>),
    Stream(Arc<StreamProxy>),
}

#[derive(Default)]
struct TlsEndpoint {
    https: Option<HttpsEndpoint>,
    passthrough: Option<Arc<StreamProxy>>,
    tcp: Option<Arc<StreamProxy>>,
}

struct HttpsEndpoint {
    server: Arc<Server>,
    acceptor: TlsAcceptor,
    drain: CancellationToken,
}

enum Inspection {
    Closed,
    Tcp,
    Tls(Option<String>),
}

impl TlsEndpoint {
    async fn serve(
        &self,
        mut socket: TcpStream,
        peer: SocketAddr,
        connections: Connections,
    ) -> Result<()> {
        if self.passthrough.is_none()
            && self.tcp.is_none()
            && let Some(https) = &self.https
        {
            let mut connections = connections;
            connections.drain = https.drain.clone();
            https
                .server
                .clone()
                .serve_socket(socket, peer, Some(https.acceptor.clone()), connections)
                .await;
            return Ok(());
        }
        let (handshake_timeout, limit) = self
            .passthrough
            .as_ref()
            .map_or((Duration::from_secs(10), 16384), |proxy| {
                proxy.handshake_settings()
            });
        let mut prefix = BytesMut::new();
        let mut started_tls = false;
        let sni = match timeout(handshake_timeout, async {
            let mut first = [0];
            let count = socket.peek(&mut first).await?;
            if count == 0 {
                return Ok::<_, anyhow::Error>(Inspection::Closed);
            }
            if first[0] != 22 {
                return Ok(Inspection::Tcp);
            }
            started_tls = true;
            let mut header = [0; 3];
            socket.read_exact(&mut header).await?;
            prefix.extend_from_slice(&header);
            if header[1] != 3 || header[2] > 4 {
                return Ok(Inspection::Tcp);
            }
            prefix.reserve(limit - header.len());
            Ok(Inspection::Tls(
                read_sni(&mut socket, &mut prefix, limit).await?,
            ))
        })
        .await
        {
            Ok(Ok(Inspection::Closed)) => return Ok(()),
            Ok(Ok(Inspection::Tcp)) => {
                return self
                    .tcp_fallback(socket, &prefix, connections.addresses)
                    .await;
            }
            Ok(Ok(Inspection::Tls(sni))) => sni,
            Err(_) if !started_tls => {
                return self.tcp_fallback(socket, &[], connections.addresses).await;
            }
            Err(error) => return Err(error).context("timed out reading TLS ClientHello"),
            Ok(Err(error)) => return Err(error),
        };
        let name = sni.as_deref();
        let passthrough = self
            .passthrough
            .as_ref()
            .and_then(|proxy| proxy.route(name).map(|route| (proxy, route)));
        let https = self.https.as_ref().and_then(|https| {
            https
                .server
                .tls_sni_specificity(name?)
                .map(|priority| (https, priority))
        });
        match (https, passthrough) {
            (Some((https, priority)), route)
                if route.is_none_or(|(_, route)| priority > route.specificity()) =>
            {
                socket.set_nodelay(true)?;
                let mut connections = connections;
                connections.drain = https.drain.clone();
                https
                    .server
                    .clone()
                    .serve_tls(
                        BufferedStream::new(prefix.freeze(), socket),
                        peer,
                        https.acceptor.clone(),
                        connections,
                    )
                    .await;
                Ok(())
            }
            (_, Some((proxy, route))) => {
                proxy
                    .relay(socket, route, &prefix, name, connections.addresses)
                    .await
            }
            _ => {
                self.tcp_fallback(socket, &prefix, connections.addresses)
                    .await
            }
        }
    }

    async fn tcp_fallback(
        &self,
        socket: TcpStream,
        prefix: &[u8],
        addresses: Option<Addresses>,
    ) -> Result<()> {
        if let Some(proxy) = &self.tcp
            && let Some(route) = proxy.route(None)
        {
            proxy.relay(socket, route, prefix, None, addresses).await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ListenerEndpoint {
    handler: Endpoint,
    trusted: Option<Arc<[ipnet::IpNet]>>,
    max_connections: usize,
}

type Endpoints = HashMap<SocketAddr, ListenerEndpoint>;

pub struct Runtime {
    endpoints: watch::Sender<Endpoints>,
    listeners: HashMap<SocketAddr, CancellationToken>,
    workers: JoinSet<Result<()>>,
    drain: CancellationToken,
    connections: Connections,
    limit: Arc<ConnectionLimit>,
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            endpoints: watch::channel(HashMap::new()).0,
            listeners: HashMap::new(),
            workers: JoinSet::new(),
            drain: CancellationToken::new(),
            connections: Connections::default(),
            limit: Arc::default(),
        }
    }

    pub async fn apply(&mut self, config: Config) -> Result<()> {
        config.validate()?;
        let max_connections = config.max_connections;
        let http = (!config.sites.is_empty()).then_some(config.http_addr);
        let https = config
            .sites
            .iter()
            .any(|site| site.tls)
            .then_some(config.https_addr);
        let mut addresses = std::collections::BTreeMap::new();
        for address in config.streams.iter().map(|stream| stream.listen) {
            addresses.insert(address, true);
        }
        for address in http.into_iter().chain(https) {
            addresses.insert(address, false);
        }
        let mut new_listeners = Vec::new();
        for (address, stream) in addresses {
            if self.listeners.contains_key(&address) {
                continue;
            }
            let mut sockets = Vec::new();
            if stream {
                for _ in 0..crate::stream::listener_workers() {
                    sockets.push(
                        crate::stream::bind_listener(address)
                            .await
                            .with_context(|| {
                                format!("could not bind stream listener on {address}")
                            })?,
                    );
                }
            } else {
                sockets.push(
                    TcpListener::bind(address)
                        .await
                        .with_context(|| format!("could not bind HTTP(S) listener on {address}"))?,
                );
            }
            new_listeners.push((address, sockets));
        }
        let mut endpoints = HashMap::new();
        let trusted: HashMap<_, Arc<[ipnet::IpNet]>> = config
            .proxy_protocol_networks()?
            .into_iter()
            .map(|(port, sources)| (port, sources.into()))
            .collect();
        let mut stream_ports: HashMap<SocketAddr, TlsEndpoint> = HashMap::new();
        for stream in &config.streams {
            let endpoint = stream_ports.entry(stream.listen).or_default();
            let proxy = Arc::new(StreamProxy::new(stream.clone()));
            match stream.mode {
                StreamMode::Tcp => endpoint.tcp = Some(proxy),
                StreamMode::TlsPassthrough => endpoint.passthrough = Some(proxy),
            }
        }
        let drain = CancellationToken::new();
        let mut health = None;
        if let Some(http) = http {
            let cloudflare = config
                .sites
                .iter()
                .any(|site| site.tls && site.certificate_file.is_none())
                .then(|| -> Result<_> {
                    Ok(Arc::new(Cloudflare::new(config.cloudflare_config()?)?))
                })
                .transpose()?;
            let server = Arc::new(tokio::task::spawn_blocking(move || Server::new(config)).await??);
            if let Some(https) = https {
                let acceptor = server
                    .tls_acceptor(cloudflare, &drain)
                    .await?
                    .context("HTTPS listener requires TLS")?;
                stream_ports.entry(https).or_default().https = Some(HttpsEndpoint {
                    server: server.clone(),
                    acceptor,
                    drain: drain.clone(),
                });
            }
            health = Some(server.clone());
            endpoints.insert(http, Endpoint::Http(server, drain.clone()));
        }
        for (address, mut endpoint) in stream_ports {
            let endpoint = if endpoint.https.is_none()
                && (endpoint.tcp.is_none() || endpoint.passthrough.is_none())
            {
                Endpoint::Stream(
                    endpoint
                        .tcp
                        .take()
                        .or(endpoint.passthrough.take())
                        .expect("stream listener has a proxy"),
                )
            } else {
                Endpoint::Tls(Arc::new(endpoint))
            };
            endpoints.insert(address, endpoint);
        }
        self.listeners.retain(|address, stop| {
            if endpoints.contains_key(address) {
                true
            } else {
                stop.cancel();
                false
            }
        });
        self.endpoints.send_replace(
            endpoints
                .into_iter()
                .map(|(address, handler)| {
                    (
                        address,
                        ListenerEndpoint {
                            handler,
                            trusted: trusted.get(&address.port()).cloned(),
                            max_connections,
                        },
                    )
                })
                .collect(),
        );
        if let Some(server) = health {
            server.spawn_health_checks(&drain);
        }
        std::mem::replace(&mut self.drain, drain).cancel();
        for (address, sockets) in new_listeners {
            let stop = CancellationToken::new();
            tracing::info!(%address, workers = sockets.len(), "listener ready");
            self.listeners.insert(address, stop.clone());
            for socket in sockets {
                self.workers.spawn(accept(
                    address,
                    socket,
                    self.endpoints.subscribe(),
                    stop.clone(),
                    self.connections.clone(),
                    self.limit.clone(),
                ));
            }
        }
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<()> {
        while let Some(result) = self.workers.join_next().await {
            result??;
        }
        anyhow::bail!("no listeners running")
    }

    pub async fn shutdown(mut self, grace: Duration) {
        for stop in self.listeners.values() {
            stop.cancel();
        }
        self.drain.cancel();
        while let Some(result) = self.workers.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%error, "listener failed during shutdown"),
                Err(error) => tracing::warn!(%error, "listener task failed during shutdown"),
            }
        }
        self.connections.tasks.close();
        if timeout(grace, self.connections.tasks.wait()).await.is_err() {
            tracing::warn!(
                remaining = self.connections.tasks.len(),
                "shutdown grace period elapsed"
            );
            self.connections.force.cancel();
            self.connections.tasks.wait().await;
        }
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

async fn accept(
    address: SocketAddr,
    listener: TcpListener,
    endpoints: watch::Receiver<Endpoints>,
    stop: CancellationToken,
    connections: Connections,
    limit: Arc<ConnectionLimit>,
) -> Result<()> {
    let mut last_warning = None;
    loop {
        let result = tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(()),
            result = listener.accept() => result,
        };
        let (socket, peer) = match result {
            Ok(pair) => pair,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(error) if accept_resource_error(&error) => {
                if last_warning
                    .is_none_or(|previous: Instant| previous.elapsed() >= Duration::from_secs(5))
                {
                    tracing::warn!(%address, %error, "accept resource limit; backing off");
                    last_warning = Some(Instant::now());
                }
                tokio::select! {
                    _ = stop.cancelled() => return Ok(()),
                    _ = sleep(Duration::from_millis(100)) => continue,
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to accept on {address}"));
            }
        };
        let endpoint = endpoints.borrow().get(&address).cloned();
        if let Some(endpoint) = endpoint {
            let Some(admission) = limit.admit(endpoint.max_connections) else {
                if last_warning.is_none_or(|previous| previous.elapsed() >= Duration::from_secs(5))
                {
                    tracing::warn!(%address, max_connections = endpoint.max_connections, "connection limit reached");
                    last_warning = Some(Instant::now());
                }
                continue;
            };
            let mut connections = connections.clone();
            connections.admission = Some(Arc::new(admission));
            let force = connections.force.clone();
            connections.tasks.clone().spawn(async move {
                tokio::select! {
                    biased;
                    _ = force.cancelled() => {},
                    _ = serve(endpoint, socket, peer, connections) => {},
                }
            });
        }
    }
}

fn accept_resource_error(error: &io::Error) -> bool {
    #[cfg(unix)]
    if matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    ) {
        return true;
    }
    error.kind() == io::ErrorKind::OutOfMemory
}

async fn serve(
    endpoint: ListenerEndpoint,
    mut socket: TcpStream,
    mut peer: SocketAddr,
    mut connections: Connections,
) {
    if let Ok(destination) = socket.local_addr() {
        connections.addresses = Some(Addresses {
            source: peer,
            destination,
        });
    }
    if let Some(trusted) = &endpoint.trusted {
        if !trusted
            .iter()
            .any(|network| network.contains(&peer.ip().to_canonical()))
        {
            tracing::debug!(%peer, "untrusted peer on PROXY protocol listener");
            return;
        }
        match timeout(
            proxy_protocol::HEADER_TIMEOUT,
            proxy_protocol::read(&mut socket),
        )
        .await
        {
            Ok(Ok(Some(addresses))) => {
                peer = addresses.source;
                connections.addresses = Some(addresses);
            }
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                tracing::debug!(%peer, %error, "invalid PROXY protocol header");
                return;
            }
            Err(_) => {
                tracing::debug!(%peer, "PROXY protocol header timed out");
                return;
            }
        }
    }
    match endpoint.handler {
        Endpoint::Http(server, drain) => {
            connections.drain = drain;
            server.serve_socket(socket, peer, None, connections).await;
        }
        Endpoint::Tls(endpoint) => {
            if let Err(error) = endpoint.serve(socket, peer, connections).await {
                tracing::debug!(%peer, %error, "TLS listener connection closed");
            }
        }
        Endpoint::Stream(proxy) => {
            if let Err(error) = proxy
                .serve_socket_with_addresses(socket, connections.addresses)
                .await
            {
                tracing::debug!(%peer, %error, "stream connection closed");
            }
        }
    }
}
