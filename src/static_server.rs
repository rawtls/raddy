use std::{io, net::SocketAddr, os::fd::AsRawFd, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use http::{HeaderMap, StatusCode, Uri};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout, timeout_at},
};

use crate::{
    server::{BoxError, Server},
    static_files::{CachedFile, FileReply, REQUEST_CONDITIONS},
    stream::BufferedStream,
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(75);

#[cfg(test)]
async fn serve_connection(
    stream: TcpStream,
    server: Arc<Server>,
    peer: SocketAddr,
) -> Result<(), BoxError> {
    serve_connection_with_drain(stream, server, peer, crate::runtime::Connections::default()).await
}

pub async fn serve_connection_with_drain(
    stream: TcpStream,
    server: Arc<Server>,
    peer: SocketAddr,
    connections: crate::runtime::Connections,
) -> Result<(), BoxError> {
    let mut stream = stream;
    let _ = stream.set_nodelay(false);
    let mut buffer = BytesMut::with_capacity(16 * 1024);
    loop {
        let request = tokio::select! {
            biased;
            _ = connections.drain.cancelled() => return Ok(()),
            result = read_request(&mut stream, &mut buffer, server.max_header_size()) => result?,
        };
        let Some(request) = request else {
            return Ok(());
        };
        let host = request.host.as_deref().unwrap_or_default();
        let site = server.static_site(host, &request.path);
        if site.is_none() {
            let stream = BufferedStream::new(buffer.freeze(), stream);
            return super::server::serve_connection_with_drain(
                stream,
                server,
                peer,
                false,
                connections,
            )
            .await;
        }
        buffer.advance(request.consumed);
        let close = request.close || request.has_body || connections.drain.is_cancelled();
        if request.has_body {
            write_error(
                &mut stream,
                StatusCode::BAD_REQUEST,
                "request body is not supported for static files\n",
            )
            .await?;
            return Ok(());
        }
        if request.method == StaticMethod::Other {
            write_error(
                &mut stream,
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed\n",
            )
            .await?;
            return Ok(());
        }
        let files = site.expect("static route checked").clone();
        match files.resolve(&request.path).await {
            Ok(file) => {
                let head = request.method == StaticMethod::Head;
                let reply = request
                    .conditions
                    .as_ref()
                    .map_or(FileReply::Full, |headers| file.evaluate(headers, head));
                send_file(
                    &mut stream,
                    &file,
                    &files.response_headers,
                    reply,
                    head,
                    close,
                )
                .await?;
            }
            Err(error) => {
                write_error(&mut stream, error.status(), error.message()).await?;
                return Ok(());
            }
        }
        if close {
            return Ok(());
        }
    }
}

#[derive(PartialEq, Eq)]
enum StaticMethod {
    Get,
    Head,
    Other,
}

struct RequestHead {
    method: StaticMethod,
    path: String,
    host: Option<String>,
    close: bool,
    has_body: bool,
    conditions: Option<HeaderMap>,
    consumed: usize,
}

async fn read_request(
    stream: &mut TcpStream,
    buffer: &mut BytesMut,
    max_size: usize,
) -> Result<Option<RequestHead>, BoxError> {
    if buffer.is_empty() && timeout(IDLE_TIMEOUT, stream.read_buf(buffer)).await?? == 0 {
        return Ok(None);
    }
    let mut deadline = None;
    loop {
        match parse_request(buffer)? {
            Some(request) if request.consumed <= max_size => return Ok(Some(request)),
            None if buffer.len() < max_size => {}
            _ => {
                write_error(
                    stream,
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "request headers too large\n",
                )
                .await?;
                return Ok(None);
            }
        }
        let deadline = *deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(15));
        if timeout_at(deadline, stream.read_buf(buffer)).await?? == 0 {
            return Ok(None);
        }
    }
}

fn parse_request(buffer: &[u8]) -> Result<Option<RequestHead>, BoxError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buffer)? {
        httparse::Status::Partial => Ok(None),
        httparse::Status::Complete(consumed) => {
            let method = request
                .method
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP method"))?;
            let uri = request
                .path
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP URI"))?
                .parse::<Uri>()?;
            let minor = request.version.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing HTTP version")
            })?;
            let mut host = uri
                .authority()
                .map(|authority| normalize_host(authority.as_str()))
                .transpose()?;
            let mut connection_close = minor == 0;
            let mut has_body = false;
            let mut conditions: Option<HeaderMap> = None;
            for header in request.headers {
                if header.name.eq_ignore_ascii_case("host") {
                    if host.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "multiple Host headers",
                        )
                        .into());
                    }
                    host = Some(normalize_host(std::str::from_utf8(header.value)?)?);
                } else if header.name.eq_ignore_ascii_case("connection") {
                    for token in std::str::from_utf8(header.value)?.split(',').map(str::trim) {
                        if token.eq_ignore_ascii_case("close") {
                            connection_close = true;
                        }
                        if token.eq_ignore_ascii_case("keep-alive") {
                            connection_close = false;
                        }
                    }
                } else if header.name.eq_ignore_ascii_case("content-length") {
                    let length = std::str::from_utf8(header.value)?.parse::<u64>()?;
                    has_body |= length != 0;
                } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                    has_body = true;
                } else if matches!(
                    header.name.as_bytes().first(),
                    Some(b'i' | b'I' | b'r' | b'R')
                ) && let Some(name) = REQUEST_CONDITIONS
                    .iter()
                    .find(|name| name.as_str().eq_ignore_ascii_case(header.name))
                    && let Ok(value) = http::HeaderValue::from_bytes(header.value)
                {
                    conditions
                        .get_or_insert_with(HeaderMap::new)
                        .append(name, value);
                }
            }
            if minor == 1 && host.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP/1.1 request without Host",
                )
                .into());
            }
            let result = RequestHead {
                method: match method {
                    "GET" => StaticMethod::Get,
                    "HEAD" => StaticMethod::Head,
                    _ => StaticMethod::Other,
                },
                path: uri.path().to_owned(),
                host,
                close: connection_close,
                has_body,
                conditions,
                consumed,
            };
            Ok(Some(result))
        }
    }
}

fn normalize_host(authority: &str) -> io::Result<String> {
    let host = if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 Host"))?;
        &authority[..=end]
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, port)| {
                if port.bytes().all(|byte| byte.is_ascii_digit()) {
                    host
                } else {
                    authority
                }
            })
    };
    Ok(host.trim_end_matches('.').to_ascii_lowercase())
}

#[cfg(target_os = "macos")]
async fn writable(stream: &TcpStream) -> io::Result<()> {
    timeout(Duration::from_secs(30), stream.writable()).await?
}

async fn write_error(
    stream: &mut TcpStream,
    status: StatusCode,
    message: &str,
) -> Result<(), BoxError> {
    let header = response_header(
        status,
        message.len() as u64,
        Some("text/plain; charset=utf-8"),
        None,
        true,
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(message.as_bytes()).await?;
    Ok(())
}

async fn send_file(
    stream: &mut TcpStream,
    file: &CachedFile,
    extra: &HeaderMap,
    reply: FileReply,
    head: bool,
    close: bool,
) -> Result<(), BoxError> {
    if matches!(reply, FileReply::Full) {
        let header = if close {
            &file.response_header_close
        } else {
            &file.response_header
        };
        if head || file.length == 0 {
            stream.write_all(header).await?;
            return Ok(());
        }
        return sendfile(stream, file, header, 0, file.length).await;
    }
    let headers = file.response_headers(extra, &reply);
    let status = reply.status();
    let mut header = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Unknown")
    );
    use std::fmt::Write;
    for (name, value) in &headers {
        if let Ok(value) = value.to_str() {
            write!(header, "{}: {value}\r\n", name.as_str()).expect("write to string");
        }
    }
    if close {
        header.push_str("Connection: close\r\n");
    }
    header.push_str("\r\n");
    match reply {
        FileReply::Partial(range) => {
            sendfile(
                stream,
                file,
                header.as_bytes(),
                range.start,
                range.end - range.start,
            )
            .await
        }
        FileReply::Status(_) => {
            stream.write_all(header.as_bytes()).await?;
            Ok(())
        }
        FileReply::Full => unreachable!(),
    }
}

fn response_header(
    status: StatusCode,
    length: u64,
    content_type: Option<&str>,
    extra: Option<&HeaderMap>,
    close: bool,
) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(256);
    write!(
        output,
        "HTTP/1.1 {} {}\r\nContent-Length: {length}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Unknown")
    )
    .expect("write to string");
    if let Some(content_type) = content_type {
        write!(output, "Content-Type: {content_type}\r\n").expect("write to string");
    }
    output.push_str("Accept-Ranges: none\r\n");
    if let Some(extra) = extra {
        for (name, value) in extra {
            if !matches!(
                name.as_str(),
                "content-length" | "connection" | "transfer-encoding"
            ) && let Ok(value) = value.to_str()
            {
                write!(output, "{}: {value}\r\n", name.as_str()).expect("write to string");
            }
        }
    }
    if close {
        output.push_str("Connection: close\r\n");
    }
    output.push_str("\r\n");
    output
}

#[cfg(target_os = "macos")]
async fn sendfile(
    stream: &mut TcpStream,
    file: &CachedFile,
    header: &[u8],
    start: u64,
    len: u64,
) -> Result<(), BoxError> {
    let partial = start != 0 || len != file.length;
    if partial {
        stream.write_all(header).await?;
    }
    let header = if partial { &[][..] } else { header };
    let total = header
        .len()
        .checked_add(usize::try_from(len)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file too large"))?;
    let start = libc::off_t::try_from(start)?;
    let end = start + libc::off_t::try_from(len)?;
    let (result, sent) = {
        let mut length = libc::off_t::try_from(total)?;
        let mut iovec = libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: header.len(),
        };
        let mut headers = libc::sf_hdtr {
            headers: &mut iovec,
            hdr_cnt: 1,
            trailers: std::ptr::null_mut(),
            trl_cnt: 0,
        };
        let result = unsafe {
            libc::sendfile(
                file.file.as_raw_fd(),
                stream.as_raw_fd(),
                start,
                &mut length,
                if partial {
                    std::ptr::null_mut()
                } else {
                    &mut headers
                },
                0,
            )
        };
        (result, length)
    };
    let sent = usize::try_from(sent)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative sendfile byte count"))?;
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            writable(stream).await?;
        } else if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    if sent < header.len() {
        stream.write_all(&header[sent..]).await?;
    }
    let mut offset = start + libc::off_t::try_from(sent.saturating_sub(header.len()))?;
    while offset < end {
        let mut remaining = end - offset;
        let result = unsafe {
            libc::sendfile(
                file.file.as_raw_fd(),
                stream.as_raw_fd(),
                offset,
                &mut remaining,
                std::ptr::null_mut(),
                0,
            )
        };
        let sent = usize::try_from(remaining).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "negative sendfile byte count")
        })?;
        if result < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => writable(stream).await?,
                io::ErrorKind::Interrupted => {}
                _ => return Err(error.into()),
            }
        }
        offset = offset
            .checked_add(libc::off_t::try_from(sent)?)
            .ok_or_else(|| io::Error::other("sendfile offset overflow"))?;
        if sent == 0 && result == 0 {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "file truncated during sendfile").into(),
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn sendfile(
    stream: &mut TcpStream,
    file: &CachedFile,
    header: &[u8],
    start: u64,
    len: u64,
) -> Result<(), BoxError> {
    use std::os::unix::fs::FileExt;
    use tokio::io::Interest;

    if len < INLINE_LIMIT {
        let mut response = Vec::with_capacity(header.len() + len as usize);
        response.extend_from_slice(header);
        if let Some(body) = &file.body {
            response.extend_from_slice(&body[start as usize..(start + len) as usize]);
        } else {
            response.resize(header.len() + len as usize, 0);
            file.file
                .read_exact_at(&mut response[header.len()..], start)?;
        }
        timeout(WRITE_TIMEOUT, stream.write_all(&response)).await??;
        return Ok(());
    }
    let mut offset = libc::off_t::try_from(start)?;
    let total = offset + libc::off_t::try_from(len)?;
    let corked = set_cork(stream, true);
    timeout(WRITE_TIMEOUT, stream.write_all(header)).await??;
    while offset < total {
        let count = (total - offset).min(SENDFILE_CHUNK) as usize;
        timeout(
            WRITE_TIMEOUT,
            stream.async_io(Interest::WRITABLE, || {
                loop {
                    let sent = unsafe {
                        libc::sendfile(
                            stream.as_raw_fd(),
                            file.file.as_raw_fd(),
                            &mut offset,
                            count,
                        )
                    };
                    if sent > 0 {
                        return Ok(());
                    }
                    if sent == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "file truncated during sendfile",
                        ));
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }),
        )
        .await??;
        if offset < total {
            tokio::task::consume_budget().await;
        }
    }
    if corked {
        set_cork(stream, false);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_cork(stream: &TcpStream, enabled: bool) -> bool {
    let value = libc::c_int::from(enabled);
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CORK,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    result == 0
}

#[cfg(target_os = "linux")]
const SENDFILE_CHUNK: libc::off_t = 2 * 1024 * 1024;

#[cfg(target_os = "linux")]
const INLINE_LIMIT: u64 = 128 * 1024;

#[cfg(target_os = "linux")]
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_proxy_request_reaches_upstream_with_host_and_body() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let config =
            crate::caddyfile::parse(&format!("http://proxy.test {{ reverse_proxy {address} }}"))
                .unwrap();
        let server = Arc::new(Server::new(config).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend = listener.local_addr().unwrap();

        timeout(Duration::from_secs(5), async {
            let relay = async {
                let (stream, peer) = listener.accept().await.unwrap();
                serve_connection(stream, server, peer).await.unwrap();
            };
            let backend = async {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 1024];
                while !request.ends_with(b"\r\n\r\nhello") {
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&chunk[..count]);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.starts_with("post /path?q=1 http/1.1\r\n"));
                assert!(request.contains("\r\nhost: proxy.test:8080\r\n"));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
            };
            let client = async {
                let mut stream = TcpStream::connect(frontend).await.unwrap();
                stream.write_all(b"POST /path?q=1 HTTP/1.1\r\nHost: proxy.test:8080\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello").await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
                assert!(response.ends_with(b"\r\n\r\nok"));
            };
            tokio::join!(relay, backend, client);
        })
        .await
        .expect("proxy request timed out");
    }

    async fn two_request_exchange() -> io::Result<Vec<u8>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut input = vec![0_u8; 4096];
            let mut received = 0;
            while !input[..received]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                let count = stream.read(&mut input[received..]).await?;
                if count == 0 {
                    break;
                }
                received += count;
            }
            let first = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
            let second = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo";
            stream.write_all(first).await?;
            stream.write_all(second).await?;
            stream.shutdown().await?;
            Ok::<_, io::Error>(())
        });
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(b"GET /one HTTP/1.1\r\nHost: static.local\r\n\r\nGET /two HTTP/1.1\r\nHost: static.local\r\nConnection: close\r\n\r\n").await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        server.await??;
        Ok(response)
    }

    #[tokio::test]
    async fn two_requests_reuse_a_connection() {
        let response = two_request_exchange().await.unwrap();
        let text = String::from_utf8(response).unwrap();
        assert_eq!(text.matches("200 OK").count(), 2);
        assert_eq!(text.matches("Content-Length: 3").count(), 2);
        assert!(text.contains("one"));
        assert!(text.ends_with("two"));
    }

    #[test]
    fn parses_keepalive_and_queries() {
        let buffer = b"GET /file.txt?q=test HTTP/1.1\r\nHost: Static.local:8080\r\n\r\n";
        let request = parse_request(buffer).unwrap().unwrap();
        assert_eq!(request.path, "/file.txt");
        assert_eq!(request.host.as_deref(), Some("static.local"));
        assert!(!request.close);
        assert!(!request.has_body);
        assert_eq!(request.consumed, buffer.len());
    }

    #[test]
    fn rejects_body_and_multiple_hosts() {
        let buffer = b"POST / HTTP/1.1\r\nHost: static.local\r\nContent-Length: 1\r\n\r\nx";
        let request = parse_request(buffer).unwrap().unwrap();
        assert!(request.has_body);
        assert_eq!(&buffer[request.consumed..], b"x");
        assert!(parse_request(b"GET / HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n").is_err());
    }

    #[test]
    fn builds_head_and_error_headers() {
        let header = response_header(StatusCode::OK, 13, Some("text/plain"), None, false);
        assert!(header.starts_with("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n"));
        assert!(header.ends_with("\r\n\r\n"));
    }
}
