use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::StreamExt;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{
        self, CONNECTION, HOST, LOCATION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY,
        SEC_WEBSOCKET_VERSION, UPGRADE,
    },
};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    body::{Body as _, Frame, Incoming},
    service::service_fn,
};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use ring::digest::{Context as Digest, SHA1_FOR_LEGACY_USE_ONLY};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{Instant, timeout, timeout_at},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tower_service::Service;
use tracing::{info, warn};

use crate::{
    acme::CertificateStore,
    config::{Config, ProxyHeader, ProxyPolicy, ProxySettings, SiteConfig},
    proxy_protocol::{self, Addresses, Version as ProxyVersion},
    routes::{HttpAction, HttpRoute, RequestMatcher, TryFilesPolicy},
    static_files::{FileLookup, StaticFiles},
};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;
type ProxyClient = Client<HttpsConnector<HttpConnector>, Body>;

#[derive(Clone)]
struct ProxyConnector {
    inner: HttpConnector,
    version: ProxyVersion,
    addresses: Option<Addresses>,
}

impl Service<Uri> for ProxyConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context).map_err(BoxError::from)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connect = self.inner.call(uri);
        let (version, addresses) = (self.version, self.addresses);
        Box::pin(async move {
            let mut socket = connect.await?;
            timeout(
                proxy_protocol::HEADER_TIMEOUT,
                proxy_protocol::write(socket.inner_mut(), version, addresses),
            )
            .await??;
            Ok(socket)
        })
    }
}

pub struct Server {
    config: Arc<Config>,
    sites: Arc<[Site]>,
    http_routes: HostRoutes,
    https_routes: Arc<HostRoutes>,
    clients: Arc<ProxyClients>,
    handshake_log: Arc<crate::tls_log::HandshakeLog>,
}

struct ProxyClients {
    client: ProxyClient,
    websocket_client: ProxyClient,
    h2c_client: Client<HttpConnector, Body>,
    connector: HttpConnector,
}

impl ProxyClients {
    fn new(connect_timeout: Duration) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(connect_timeout));
        let mut h2c_connector = connector.clone();
        h2c_connector.enforce_http(true);
        let h2c_client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(128)
            .http2_only(true)
            .build(h2c_connector);
        let websocket_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector.clone());
        let proxy_connector = connector.clone();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(128)
            .build(connector);
        Self {
            client,
            websocket_client: Client::builder(TokioExecutor::new()).build(websocket_connector),
            h2c_client,
            connector: proxy_connector,
        }
    }

    async fn request_upstream(
        &self,
        upstream: &Upstream,
        websocket: bool,
        proxy_protocol: Option<ProxyVersion>,
        addresses: Option<Addresses>,
        request: Request<Body>,
    ) -> Result<Response<Incoming>, BoxError> {
        if let Some(version) = proxy_protocol {
            let connector = ProxyConnector {
                inner: self.connector.clone(),
                version,
                addresses,
            };
            let mut builder = Client::builder(TokioExecutor::new());
            builder.pool_max_idle_per_host(0);
            if upstream.scheme == http::uri::Scheme::HTTP {
                return Ok(builder
                    .http2_only(upstream.h2c)
                    .build(connector)
                    .request(request)
                    .await?);
            }
            let tls = hyper_rustls::HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1();
            let connector = if websocket {
                tls.wrap_connector(connector)
            } else {
                tls.enable_http2().wrap_connector(connector)
            };
            return Ok(builder.build(connector).request(request).await?);
        }
        Ok(if upstream.h2c {
            self.h2c_client.request(request).await?
        } else if websocket {
            self.websocket_client.request(request).await?
        } else {
            self.client.request(request).await?
        })
    }
}

#[derive(Default)]
struct HostRoutes {
    exact: HashMap<String, usize>,
    wildcard: HashMap<String, usize>,
    fallback: Option<usize>,
}

impl HostRoutes {
    fn insert(&mut self, pattern: &str, index: usize) {
        let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
        if pattern == "*" {
            self.fallback.get_or_insert(index);
        } else if let Some(suffix) = pattern.strip_prefix("*.") {
            if !self.wildcard.contains_key(suffix) {
                self.wildcard.insert(suffix.to_owned(), index);
            }
        } else {
            self.exact.entry(pattern).or_insert(index);
        }
    }

    fn matched(&self, host: &str) -> Option<usize> {
        self.exact.get(host).copied().or_else(|| {
            let (label, suffix) = host.split_once('.')?;
            if label.is_empty() {
                return None;
            }
            self.wildcard.get(suffix).copied()
        })
    }
}

struct Site {
    config: SiteConfig,
    proxy_response_headers: HeaderMap,
    static_files: Option<Arc<StaticFiles>>,
    proxy: Option<Arc<ProxyHandler>>,
    responses: Vec<Respond>,
    routes: Vec<Route>,
    error_routes: Vec<(crate::routes::ErrorRoute, Vec<Route>)>,
}

struct ProxyHandler {
    clients: Option<Box<ProxyClients>>,
    settings: ProxySettings,
    upstreams: Vec<Upstream>,
    header_up: Vec<HeaderOperation>,
    header_down: Vec<HeaderOperation>,
    next_upstream: AtomicUsize,
}

impl ProxyHandler {
    fn new(upstreams: &[String], settings: &ProxySettings) -> Result<Arc<Self>> {
        settings.validate()?;
        Ok(Arc::new(Self {
            clients: settings
                .connect_timeout_secs
                .filter(|&secs| secs != 10)
                .map(|secs| Box::new(ProxyClients::new(Duration::from_secs(secs)))),
            settings: settings.clone(),
            upstreams: upstreams
                .iter()
                .map(|url| Upstream::new(url))
                .collect::<Result<_>>()?,
            header_up: settings
                .header_up
                .iter()
                .map(HeaderOperation::new)
                .collect::<Result<_>>()?,
            header_down: settings
                .header_down
                .iter()
                .map(HeaderOperation::new)
                .collect::<Result<_>>()?,
            next_upstream: AtomicUsize::new(0),
        }))
    }
}

struct Route {
    matcher: Match,
    action: Action,
}

#[derive(PartialEq, Eq)]
struct Match {
    paths: Vec<PathMatcher>,
    methods: Vec<Method>,
    headers: Vec<(HeaderName, Vec<HeaderValue>)>,
    query: Option<std::collections::BTreeMap<String, Vec<String>>>,
    path_regexp: Option<RouteRegexp>,
    header_regexp: Vec<(HeaderName, RouteRegexp)>,
    expression: Option<crate::expression::Expression>,
}

#[derive(Default)]
struct RouteCaptures {
    latest: HashMap<String, String>,
    named: HashMap<String, HashMap<String, String>>,
}

impl RouteCaptures {
    fn value(&self, name: &str) -> Option<&str> {
        let name = name
            .strip_prefix("re.")
            .or_else(|| name.strip_prefix("http.regexp."))?;
        let value = if let Some((namespace, key)) = name.rsplit_once('.') {
            self.named.get(namespace).and_then(|values| values.get(key))
        } else {
            self.latest.get(name)
        };
        value.map(String::as_str)
    }
}

struct RouteRegexp {
    name: String,
    regex: regex::Regex,
}

impl PartialEq for RouteRegexp {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.regex.as_str() == other.regex.as_str()
    }
}

impl Eq for RouteRegexp {}

impl RouteRegexp {
    fn new(config: &crate::routes::RegexpMatcher) -> Result<Self> {
        Ok(Self {
            name: config.name.clone(),
            regex: config.compile()?,
        })
    }

    fn captures(&self, value: &str, context: &mut RouteCaptures) -> bool {
        let Some(captures) = self.regex.captures(value) else {
            return false;
        };
        let mut current = HashMap::with_capacity(captures.len());
        for (index, name) in self.regex.capture_names().enumerate() {
            let value = captures.get(index).map_or("", |capture| capture.as_str());
            current.insert(index.to_string(), value.to_owned());
            if let Some(name) = name {
                current.insert(name.to_owned(), value.to_owned());
            }
        }
        if !self.name.is_empty() {
            context
                .named
                .entry(self.name.clone())
                .or_default()
                .extend(current.clone());
        }
        context.latest.extend(current);
        true
    }
}

#[derive(PartialEq, Eq)]
struct PathMatcher {
    pattern: String,
    mode: PathMode,
    preserve_slashes: bool,
}

#[derive(PartialEq, Eq)]
enum PathMode {
    Any,
    Exact,
    Prefix,
    Suffix,
    Contains,
    Glob(Vec<glob::Pattern>),
    Escaped(Vec<glob::Pattern>),
}

impl PathMatcher {
    fn new(pattern: &str) -> Result<Self> {
        let preserve_slashes = pattern.contains("//");
        let lowered = pattern.to_lowercase();
        let stars = lowered.bytes().filter(|byte| *byte == b'*').count();
        let (pattern, mode) = if lowered == "*" {
            ("", PathMode::Any)
        } else if lowered.contains('%') {
            (
                lowered.as_str(),
                PathMode::Escaped(crate::routes::compile_path_glob(
                    &lowered.replace("%*", "*"),
                )?),
            )
        } else if let Some(prefix) = lowered.strip_suffix('*').filter(|_| stars == 1) {
            (prefix, PathMode::Prefix)
        } else if let Some(suffix) = lowered.strip_prefix('*').filter(|_| stars == 1) {
            (suffix, PathMode::Suffix)
        } else if stars == 2 && lowered.starts_with('*') && lowered.ends_with('*') {
            (&lowered[1..lowered.len() - 1], PathMode::Contains)
        } else if lowered.contains(['*', '?', '[', '\\']) {
            (
                lowered.as_str(),
                PathMode::Glob(crate::routes::compile_path_glob(&lowered)?),
            )
        } else {
            (lowered.as_str(), PathMode::Exact)
        };
        Ok(Self {
            pattern: pattern.to_owned(),
            mode,
            preserve_slashes,
        })
    }

    fn matches(&self, path: &str, raw: &str) -> bool {
        if let PathMode::Escaped(patterns) = &self.mode {
            let path = clean_path(raw, !self.preserve_slashes);
            return escaped_match_input(&self.pattern, &path)
                .is_some_and(|path| match_glob(patterns, &path, true));
        }
        let preserved;
        let path = if self.preserve_slashes {
            preserved = normalize_match_path_with(raw, false);
            preserved.as_ref()
        } else {
            path
        };
        match &self.mode {
            PathMode::Any => true,
            PathMode::Exact => path.eq_ignore_ascii_case(&self.pattern),
            PathMode::Prefix => path
                .as_bytes()
                .get(..self.pattern.len())
                .is_some_and(|part| part.eq_ignore_ascii_case(self.pattern.as_bytes())),
            PathMode::Suffix => path
                .as_bytes()
                .get(path.len().saturating_sub(self.pattern.len())..)
                .is_some_and(|part| part.eq_ignore_ascii_case(self.pattern.as_bytes())),
            PathMode::Contains => {
                self.pattern.is_empty()
                    || path
                        .as_bytes()
                        .windows(self.pattern.len())
                        .any(|part| part.eq_ignore_ascii_case(self.pattern.as_bytes()))
            }
            PathMode::Glob(patterns) => match_glob(patterns, path, false),
            PathMode::Escaped(_) => unreachable!(),
        }
    }
}

fn match_glob(patterns: &[glob::Pattern], path: &str, case_sensitive: bool) -> bool {
    let mut segments = path.split('/');
    let options = glob::MatchOptions {
        case_sensitive,
        ..glob::MatchOptions::new()
    };
    patterns.iter().all(|pattern| {
        segments
            .next()
            .is_some_and(|segment| pattern.matches_with(segment, options))
    }) && segments.next().is_none()
}

fn escaped_match_input(pattern: &str, path: &str) -> Option<String> {
    let mut pattern = pattern.as_bytes().iter().copied().peekable();
    let mut output = Vec::with_capacity(path.len());
    let mut remaining = path.as_bytes();
    while let Some(next) = pattern.next() {
        if remaining.is_empty() {
            break;
        }
        if next == b'*' || next == b'%' && pattern.peek() == Some(&b'*') {
            let preserve = next == b'%';
            if preserve {
                pattern.next();
            }
            let mut limit = remaining.len();
            if let Some(delimiter) = pattern.peek() {
                limit = remaining.iter().position(|byte| byte == delimiter)?;
            }
            let (span, tail) = remaining.split_at(limit);
            if preserve {
                output.extend_from_slice(span);
            } else {
                output.extend(percent_encoding::percent_decode(span));
            }
            remaining = tail;
        } else if next == b'%' {
            pattern.next();
            pattern.next();
            let escape = remaining.get(..3)?.strip_prefix(b"%")?;
            if !escape.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            output.push(b'%');
            output.extend(escape.iter().map(u8::to_ascii_lowercase));
            remaining = &remaining[3..];
        } else if remaining[0] == b'%' {
            let escape = remaining.get(..3)?;
            if !escape[1..].iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            output.extend(percent_encoding::percent_decode(escape));
            remaining = &remaining[3..];
        } else {
            output.push(remaining[0]);
            remaining = &remaining[1..];
        }
    }
    if !remaining.is_empty() {
        return None;
    }
    String::from_utf8(output).ok()
}

impl Match {
    fn new(matcher: &RequestMatcher) -> Result<Self> {
        Ok(Self {
            paths: matcher
                .paths
                .iter()
                .map(|path| PathMatcher::new(path))
                .collect::<Result<_>>()?,
            methods: matcher
                .methods
                .iter()
                .map(|method| Method::from_bytes(method.as_bytes()))
                .collect::<Result<_, _>>()?,
            headers: matcher
                .headers
                .iter()
                .map(|(name, values)| -> Result<_> {
                    Ok((
                        HeaderName::from_bytes(name.as_bytes())?,
                        values
                            .iter()
                            .map(|value| HeaderValue::from_str(value))
                            .collect::<Result<_, _>>()?,
                    ))
                })
                .collect::<Result<_>>()?,
            query: matcher.query.clone(),
            path_regexp: matcher
                .path_regexp
                .as_ref()
                .map(RouteRegexp::new)
                .transpose()?,
            header_regexp: matcher
                .header_regexp
                .iter()
                .map(|(name, regexp)| -> Result<_> {
                    Ok((
                        HeaderName::from_bytes(name.as_bytes())?,
                        RouteRegexp::new(regexp)?,
                    ))
                })
                .collect::<Result<_>>()?,
            expression: matcher
                .expression
                .as_deref()
                .map(crate::expression::Expression::new)
                .transpose()?,
        })
    }

    fn matches(
        &self,
        request: &Request<Option<Incoming>>,
        path: Option<&str>,
        captures: &mut RouteCaptures,
    ) -> bool {
        if !self.methods.is_empty() && !self.methods.contains(request.method()) {
            return false;
        }
        if !self.headers.iter().all(|(name, values)| {
            if name == HOST
                && let Some(host) = request.uri().authority()
            {
                return values.iter().any(|allowed| {
                    header_value_matches(allowed.as_bytes(), host.as_str().as_bytes())
                });
            }
            if values.is_empty() {
                !request.headers().contains_key(name)
            } else {
                request.headers().get_all(name).iter().any(|value| {
                    values
                        .iter()
                        .any(|allowed| header_value_matches(allowed.as_bytes(), value.as_bytes()))
                })
            }
        }) {
            return false;
        }
        if !self.paths.is_empty()
            && !path.is_some_and(|path| {
                self.paths
                    .iter()
                    .any(|pattern| pattern.matches(path, request.uri().path()))
            })
        {
            return false;
        }
        if !self
            .query
            .as_ref()
            .is_none_or(|query| query_matches(query, request.uri()))
        {
            return false;
        }
        if let Some(regexp) = &self.path_regexp {
            let path =
                percent_encoding::percent_decode_str(request.uri().path()).decode_utf8_lossy();
            if !regexp.captures(&clean_path(&path, true), captures) {
                return false;
            }
        }
        self.header_regexp.iter().all(|(name, regexp)| {
            if name == HOST
                && let Some(host) = request.uri().authority()
            {
                return regexp.captures(host.as_str(), captures);
            }
            request
                .headers()
                .get_all(name)
                .iter()
                .any(|value| regexp.captures(&String::from_utf8_lossy(value.as_bytes()), captures))
        })
    }
}

fn header_value_matches(pattern: &[u8], value: &[u8]) -> bool {
    match pattern {
        b"*" => true,
        [b'*', needle @ .., b'*'] => {
            needle.is_empty() || value.windows(needle.len()).any(|part| part == needle)
        }
        [b'*', suffix @ ..] => value.ends_with(suffix),
        [prefix @ .., b'*'] => value.starts_with(prefix),
        pattern => pattern == value,
    }
}

fn query_matches(expected: &std::collections::BTreeMap<String, Vec<String>>, uri: &Uri) -> bool {
    let raw = uri.query().unwrap_or_default();
    if expected.is_empty() {
        return raw
            .split('&')
            .filter(|pair| valid_query_pair(pair))
            .all(str::is_empty);
    }
    if !raw.split('&').all(valid_query_pair) {
        return false;
    }
    let pairs: Vec<_> = url::form_urlencoded::parse(raw.as_bytes()).collect();
    expected.iter().all(|(name, values)| {
        let name = expand_request_values(name, uri);
        pairs.iter().any(|(actual, value)| {
            actual == &name
                && values.iter().any(|candidate| {
                    let candidate = expand_request_values(candidate, uri);
                    candidate == "*" || &candidate == value
                })
        })
    })
}

fn valid_query_pair(pair: &str) -> bool {
    !pair.contains(';')
        && pair
            .as_bytes()
            .split(|byte| *byte == b'%')
            .skip(1)
            .all(|tail| {
                tail.get(..2)
                    .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
            })
}

enum Action {
    Handle {
        routes: Vec<Route>,
        strip_prefix: Option<String>,
    },
    Route(Vec<Route>),
    Rewrite(String),
    Error(StatusCode, String),
    Header(ResponseHeaders),
    TryFiles {
        root: Arc<FileLookup>,
        paths: Arc<[String]>,
        status: Option<u16>,
        policy: TryFilesPolicy,
    },
    Respond(Respond),
    Proxy(Arc<ProxyHandler>),
    Files(Arc<StaticFiles>),
}

impl Route {
    fn compile(routes: &[HttpRoute], site: &SiteConfig, global: &Config) -> Result<Vec<Self>> {
        routes
            .iter()
            .map(|route| {
                let matcher = Match::new(&route.matcher)?;
                let action = match &route.action {
                    HttpAction::Handle {
                        routes,
                        strip_prefix,
                    } => Action::Handle {
                        routes: Self::compile(routes, site, global)?,
                        strip_prefix: strip_prefix.clone(),
                    },
                    HttpAction::Route { routes } => {
                        Action::Route(Self::compile(routes, site, global)?)
                    }
                    HttpAction::Rewrite { to } => Action::Rewrite(to.clone()),
                    HttpAction::Error { status, message } => {
                        Action::Error(StatusCode::from_u16(*status)?, message.clone())
                    }
                    HttpAction::Header {
                        operations,
                        defer,
                        condition,
                    } => Action::Header(ResponseHeaders::new(
                        operations,
                        *defer,
                        condition.as_ref(),
                    )?),
                    HttpAction::TryFiles {
                        root,
                        paths,
                        status,
                        policy,
                    } => Action::TryFiles {
                        root: Arc::new(FileLookup::new(root, global).with_context(|| {
                            format!("could not open try_files root {}", root.display())
                        })?),
                        paths: paths.clone().into(),
                        status: *status,
                        policy: *policy,
                    },
                    HttpAction::Respond { response } => {
                        Action::Respond(Respond::new(response, site)?)
                    }
                    HttpAction::ReverseProxy { upstreams, proxy } => {
                        Action::Proxy(ProxyHandler::new(upstreams, proxy)?)
                    }
                    HttpAction::FileServer { root, index } => Action::Files(
                        StaticFiles::with_root(root, index, &site.response_headers, global)
                            .with_context(|| {
                                format!("could not open file_server root {}", root.display())
                            })?,
                    ),
                };
                Ok(Self { matcher, action })
            })
            .collect()
    }
}

struct RouteCursor<'a> {
    remaining: &'a [Route],
    handled: bool,
    rewrite_matcher: Option<&'a Match>,
    rewrite_chain_matched: bool,
    rewritten: bool,
}

impl<'a> RouteCursor<'a> {
    fn new(remaining: &'a [Route]) -> Self {
        Self {
            remaining,
            handled: false,
            rewrite_matcher: None,
            rewrite_chain_matched: false,
            rewritten: false,
        }
    }
}

struct Peer {
    address: SocketAddr,
    forwarded_for: HeaderValue,
}

impl Peer {
    fn new(address: SocketAddr) -> Result<Self, header::InvalidHeaderValue> {
        Ok(Self {
            address,
            forwarded_for: HeaderValue::try_from(address.ip().to_string())?,
        })
    }
}

struct RouteRequest<'a> {
    request: &'a mut Request<Option<Incoming>>,
    site: &'a Site,
    peer: Option<&'a Peer>,
    secure: bool,
    connections: &'a crate::runtime::Connections,
    captures: RouteCaptures,
    immediate_headers: HeaderMap,
    immediate_replacements: HashSet<HeaderName>,
}

struct RouteError {
    status: StatusCode,
    message: String,
}

impl RouteError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn response(&self) -> Response<Body> {
        text_response(self.status, &self.message)
    }

    fn empty_response(&self) -> Response<Body> {
        let mut response = route_empty_response();
        *response.status_mut() = self.status;
        response
    }
}

fn empty_body() -> Body {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

fn route_empty_response() -> Response<Body> {
    Response::new(
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed(),
    )
}

const REWRITE_PATH_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`');

fn replace_uri(uri: &mut Uri, target: &str) -> Result<()> {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (if path.is_empty() { uri.path() } else { path }, Some(query)),
        None => (target, uri.query()),
    };
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('#')
        || query.is_some_and(|query| query.contains('#'))
    {
        anyhow::bail!("rewrite must produce an origin URI");
    }
    let path = Cow::from(percent_encoding::utf8_percent_encode(
        path,
        REWRITE_PATH_ENCODE,
    ));
    let path_and_query = if let Some(query) = query.filter(|query| !query.is_empty()) {
        format!("{path}?{query}").parse::<http::uri::PathAndQuery>()?
    } else {
        path.as_ref().parse::<http::uri::PathAndQuery>()?
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query);
    *uri = Uri::from_parts(parts)?;
    Ok(())
}

pub(crate) fn expression_path(
    context: &cel::FunctionContext<'_, '_>,
    cel::extractors::Arguments(values): cel::extractors::Arguments,
) -> std::result::Result<bool, cel::ExecutionError> {
    let Some(raw) = context.ptx.get_variable("__raddy_path") else {
        return Ok(false);
    };
    let Some(raw) = raw.downcast_ref::<cel::common::types::CelString>() else {
        return Ok(false);
    };
    let raw = raw.inner();
    let path = normalize_match_path(raw);
    for value in values.iter() {
        let cel::Value::String(pattern) = value else {
            return Err(context.error("path expects string arguments"));
        };
        crate::routes::validate_match_path(pattern).map_err(|error| context.error(error))?;
        if PathMatcher::new(pattern)
            .map_err(|error| context.error(error))?
            .matches(&path, raw)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn expression_value(
    name: &str,
    request: &Request<Option<Incoming>>,
    peer: Option<SocketAddr>,
    secure: bool,
    error: Option<&RouteError>,
    captures: &RouteCaptures,
) -> cel::Value {
    match name {
        "http.request.uri.path.escaped" => request.uri().path().into(),
        "path" | "http.request.uri.path" => {
            percent_encoding::percent_decode_str(request.uri().path())
                .decode_utf8_lossy()
                .into_owned()
                .into()
        }
        "query" | "http.request.uri.query" => request.uri().query().unwrap_or_default().into(),
        "uri" | "http.request.uri" => request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .into(),
        "method" | "http.request.method" => request.method().as_str().into(),
        "host" | "http.request.host" => request_host(request).unwrap_or_default().into(),
        "scheme" | "http.request.scheme" => (if secure { "https" } else { "http" }).into(),
        "remote_host" | "http.request.remote.host" | "client_ip" | "http.vars.client_ip" => peer
            .map(|peer| cel::Value::from(peer.ip().to_string()))
            .unwrap_or(cel::Value::Null),
        "err.status_code" | "http.error.status_code" => error
            .map(|error| cel::Value::Int(i64::from(error.status.as_u16())))
            .unwrap_or(cel::Value::Null),
        "err.message" | "http.error.message" => error
            .map(|error| error.message.clone().into())
            .unwrap_or(cel::Value::Null),
        name if name.starts_with("header.") || name.starts_with("http.request.header.") => {
            let field = name
                .strip_prefix("header.")
                .or_else(|| name.strip_prefix("http.request.header."))
                .expect("header prefix");
            let host = field
                .eq_ignore_ascii_case("host")
                .then(|| request.uri().authority())
                .flatten();
            host.map(|authority| authority.as_str().into())
                .or_else(|| {
                    request
                        .headers()
                        .get_all(field)
                        .iter()
                        .map(|value| String::from_utf8_lossy(value.as_bytes()))
                        .reduce(|left, right| Cow::Owned(format!("{left},{right}")))
                        .map(|value| value.into_owned().into())
                })
                .unwrap_or(cel::Value::Null)
        }
        name => captures
            .value(name)
            .map(cel::Value::from)
            .unwrap_or(cel::Value::Null),
    }
}

fn request_value<'a>(name: &str, uri: &'a Uri) -> Option<&'a str> {
    match name {
        "path" => Some(uri.path()),
        "query" => Some(uri.query().unwrap_or_default()),
        "uri" => Some(uri.path_and_query().map_or("/", |path| path.as_str())),
        _ => None,
    }
}

fn expand_request_values<'a>(template: &'a str, uri: &Uri) -> Cow<'a, str> {
    expand_values(template, uri, None, None)
}

fn expand_values<'a>(
    template: &'a str,
    uri: &Uri,
    error: Option<&RouteError>,
    captures: Option<&RouteCaptures>,
) -> Cow<'a, str> {
    expand_values_with(template, uri, error, captures, false)
}

fn expand_values_with<'a>(
    template: &'a str,
    uri: &Uri,
    error: Option<&RouteError>,
    captures: Option<&RouteCaptures>,
    file_pattern: bool,
) -> Cow<'a, str> {
    let Some((first, mut rest)) = template.split_once('{') else {
        return Cow::Borrowed(template);
    };
    let mut output = String::with_capacity(template.len());
    output.push_str(first);
    loop {
        if let Some((name, tail)) = rest.split_once('}') {
            if let Some(error) = error
                && matches!(name, "err.status_code" | "http.error.status_code")
            {
                output.push_str(error.status.as_str());
            } else if let Some(error) = error
                && matches!(name, "err.status_text" | "http.error.status_text")
            {
                output.push_str(error.status.canonical_reason().unwrap_or(""));
            } else if let Some(error) = error
                && matches!(name, "err.message" | "http.error.message")
            {
                output.push_str(&error.message);
            } else if let Some(value) = request_value(name, uri)
                .or_else(|| captures.and_then(|captures| captures.value(name)))
            {
                if file_pattern {
                    const GLOB_LITERAL: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
                        .add(b'*')
                        .add(b'?')
                        .add(b'[')
                        .add(b']')
                        .add(b'\\')
                        .add(b'#');
                    output.extend(percent_encoding::utf8_percent_encode(value, GLOB_LITERAL));
                } else {
                    output.push_str(value);
                }
            } else {
                output.push('{');
                output.push_str(name);
                output.push('}');
            }
            rest = tail;
        } else {
            output.push('{');
            output.push_str(rest);
            break;
        }
        if let Some((literal, tail)) = rest.split_once('{') {
            output.push_str(literal);
            rest = tail;
        } else {
            output.push_str(rest);
            break;
        }
    }
    Cow::Owned(output)
}

fn select_try_file(
    root: &FileLookup,
    candidates: Vec<(String, Option<String>)>,
    policy: TryFilesPolicy,
) -> Option<String> {
    let first_match = matches!(
        policy,
        TryFilesPolicy::FirstExist | TryFilesPolicy::FirstExistFallback
    );
    let mut selected: Option<((String, Option<String>), std::fs::Metadata)> = None;
    let mut candidates = candidates.into_iter().peekable();
    while let Some((path, query)) = candidates.next() {
        let end_of_group =
            query.is_some() || candidates.peek().is_none_or(|(_, query)| query.is_some());
        for (path, metadata) in root.candidates(
            &path,
            first_match && !(policy == TryFilesPolicy::FirstExistFallback && end_of_group),
        ) {
            if first_match {
                return Some(try_file_target(path, query));
            }
            let preferable = match (policy, &selected) {
                (TryFilesPolicy::LargestSize, current) => {
                    metadata.len() > current.as_ref().map_or(0, |(_, info)| info.len())
                }
                (TryFilesPolicy::SmallestSize, Some((_, info))) => {
                    info.len() == 0 || metadata.len() < info.len()
                }
                (TryFilesPolicy::MostRecentlyModified, Some((_, info))) => {
                    metadata.modified().ok() > info.modified().ok()
                }
                (_, None) => true,
                _ => false,
            };
            if preferable {
                selected = Some(((path, query.clone()), metadata));
            }
        }
        if end_of_group && let Some(((path, query), _)) = selected.take() {
            return Some(try_file_target(path, query));
        }
    }
    None
}

fn try_file_target(path: String, query: Option<String>) -> String {
    match query {
        Some(query) => format!("{path}?{query}"),
        None => path,
    }
}

fn strip_route_prefix(uri: &mut Uri, prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Ok(());
    }
    let raw = uri.path().as_bytes();
    let mut offset = 0;
    for expected in prefix.bytes() {
        let Some(&first) = raw.get(offset) else {
            return Ok(());
        };
        let decoded = if first == b'%' {
            let Some(bytes) = raw.get(offset + 1..offset + 3) else {
                return Ok(());
            };
            let (Some(a), Some(b)) = (
                char::from(bytes[0]).to_digit(16),
                char::from(bytes[1]).to_digit(16),
            ) else {
                return Ok(());
            };
            offset += 3;
            (a * 16 + b) as u8
        } else {
            offset += 1;
            first
        };
        if !decoded.eq_ignore_ascii_case(&expected) {
            return Ok(());
        }
    }
    let Some(suffix) = uri.path().get(offset..) else {
        return Ok(());
    };
    let target = if suffix.starts_with('/') {
        suffix.to_owned()
    } else {
        format!("/{suffix}")
    };
    replace_uri(uri, &target)
}

struct Upstream {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    host_header: HeaderValue,
    h2c: bool,
    healthy: AtomicBool,
}

impl Upstream {
    fn new(url: &str) -> Result<Self> {
        let url = url::Url::parse(url)?;
        let h2c = url.scheme() == "h2c";
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        Ok(Self {
            scheme: if h2c { "http" } else { url.scheme() }.parse()?,
            authority: authority.parse()?,
            host_header: HeaderValue::from_str(authority)?,
            h2c,
            healthy: AtomicBool::new(true),
        })
    }

    fn apply_host(&self, headers: &mut HeaderMap) {
        if self.scheme == http::uri::Scheme::HTTPS || !headers.contains_key(HOST) {
            headers.insert(HOST, self.host_header.clone());
        }
    }

    fn uri(&self, path: http::uri::PathAndQuery) -> Result<Uri, http::Error> {
        Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(path)
            .build()
    }
}

struct HeaderOperation {
    name: HeaderName,
    value: Option<HeaderValue>,
    append: bool,
}

impl HeaderOperation {
    fn new(header: &ProxyHeader) -> Result<Self> {
        let name = header.name.strip_prefix(['+', '-']).unwrap_or(&header.name);
        Ok(Self {
            name: HeaderName::from_bytes(name.as_bytes())?,
            value: header
                .value
                .as_deref()
                .map(HeaderValue::from_str)
                .transpose()?,
            append: header.name.starts_with('+'),
        })
    }

    fn apply_all(operations: &[Self], headers: &mut HeaderMap) {
        for operation in operations {
            operation.apply(headers, operation.value.clone());
        }
    }

    fn apply(&self, headers: &mut HeaderMap, value: Option<HeaderValue>) {
        match value {
            Some(value) if self.append => {
                headers.append(&self.name, value);
            }
            Some(value) => {
                headers.insert(&self.name, value);
            }
            None => {
                headers.remove(&self.name);
            }
        }
    }
}

struct ResponseHeaders {
    operations: Vec<ResponseHeaderOp>,
    defer: bool,
    statuses: Vec<u16>,
    conditions: Vec<(HeaderName, Vec<String>)>,
}

enum ResponseHeaderOp {
    Set(HeaderName, String, bool),
    Add(HeaderName, String),
    Delete(String),
    Replace(Option<HeaderName>, regex::Regex, String),
}

impl ResponseHeaders {
    fn new(
        operations: &[crate::routes::ResponseHeader],
        defer: bool,
        condition: Option<&crate::routes::ResponseCondition>,
    ) -> Result<Self> {
        let ops = operations
            .iter()
            .map(|op| {
                let name = op
                    .name
                    .strip_prefix(['+', '-', '?', '>'])
                    .unwrap_or(&op.name);
                if op.name.starts_with('-') {
                    return Ok(ResponseHeaderOp::Delete(name.to_ascii_lowercase()));
                }
                let value = op.value.clone().unwrap_or_default();
                if let Some(replacement) = &op.replacement {
                    let field = (name != "*")
                        .then(|| HeaderName::from_bytes(name.as_bytes()))
                        .transpose()?;
                    let regex = crate::routes::RegexpMatcher {
                        name: String::new(),
                        pattern: value,
                    }
                    .compile()?;
                    return Ok(ResponseHeaderOp::Replace(field, regex, replacement.clone()));
                }
                let name = HeaderName::from_bytes(name.as_bytes())?;
                Ok(if op.name.starts_with('+') {
                    ResponseHeaderOp::Add(name, value)
                } else {
                    ResponseHeaderOp::Set(name, value, op.name.starts_with('?'))
                })
            })
            .collect::<Result<_>>()?;
        let mut compiled = Self {
            operations: ops,
            defer: defer
                || condition.is_some()
                || operations
                    .iter()
                    .any(|op| op.replacement.is_some() || op.name.starts_with(['-', '>', '?'])),
            statuses: Vec::new(),
            conditions: Vec::new(),
        };
        if let Some(condition) = condition {
            compiled.statuses.clone_from(&condition.statuses);
            compiled.conditions = condition
                .headers
                .iter()
                .map(|(name, values)| {
                    Ok((HeaderName::from_bytes(name.as_bytes())?, values.clone()))
                })
                .collect::<Result<_>>()?;
        }
        Ok(compiled)
    }

    fn applies(&self, response: &Response<Body>) -> bool {
        let status = response.status().as_u16();
        (self.statuses.is_empty()
            || self
                .statuses
                .iter()
                .any(|code| *code == status || *code == status / 100))
            && self.conditions.iter().all(|(name, values)| {
                if values.is_empty() {
                    return !response.headers().contains_key(name);
                }
                response.headers().get_all(name).iter().any(|value| {
                    values
                        .iter()
                        .any(|pattern| header_value_matches(pattern.as_bytes(), value.as_bytes()))
                })
            })
    }

    fn apply(&self, headers: &mut HeaderMap, expand: impl Fn(&str) -> String) {
        self.apply_with_replacements(headers, None, expand);
    }

    fn apply_with_replacements(
        &self,
        headers: &mut HeaderMap,
        mut replacements: Option<&mut HashSet<HeaderName>>,
        expand: impl Fn(&str) -> String,
    ) {
        if self
            .operations
            .iter()
            .any(|operation| matches!(operation, ResponseHeaderOp::Delete(name) if name == "*"))
        {
            remove_response_headers(headers, "*");
        }
        let mut set = HashMap::<&HeaderName, Vec<String>>::new();
        for operation in &self.operations {
            match operation {
                ResponseHeaderOp::Add(name, template) => {
                    if let Ok(value) = HeaderValue::from_bytes(expand(template).as_bytes()) {
                        headers.append(name, value);
                    }
                }
                ResponseHeaderOp::Set(name, template, false) => {
                    set.entry(name).or_default().push(expand(template))
                }
                _ => {}
            }
        }
        for (name, values) in set {
            if let Ok(value) = HeaderValue::from_bytes(values.join(",").as_bytes()) {
                if let Some(replacements) = &mut replacements {
                    replacements.insert(name.clone());
                }
                headers.insert(name, value);
            }
        }
        for operation in &self.operations {
            match operation {
                ResponseHeaderOp::Delete(pattern) if pattern != "*" => {
                    remove_response_headers(headers, pattern);
                }
                ResponseHeaderOp::Replace(field, regex, template) => {
                    let replacement = expand(template);
                    for (name, value) in headers.iter_mut() {
                        if protected_response_header(name)
                            || field.as_ref().is_some_and(|field| field != name)
                        {
                            continue;
                        }
                        if let Ok(text) = value.to_str()
                            && let Cow::Owned(replaced) =
                                regex.replace_all(text, replacement.as_str())
                            && let Ok(replaced) = HeaderValue::from_bytes(replaced.as_bytes())
                        {
                            *value = replaced;
                        }
                    }
                }
                _ => {}
            }
        }
        let mut defaults = self
            .operations
            .iter()
            .filter_map(|operation| match operation {
                ResponseHeaderOp::Set(name, value, true) => Some((name, value)),
                _ => None,
            })
            .peekable();
        if defaults.peek().is_some()
            && defaults
                .clone()
                .all(|(name, _)| !headers.contains_key(name))
        {
            for (name, template) in defaults {
                if let Ok(value) = HeaderValue::from_bytes(expand(template).as_bytes()) {
                    headers.insert(name, value);
                }
            }
        }
    }
}

fn remove_response_headers(headers: &mut HeaderMap, pattern: &str) {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| {
            !protected_response_header(name)
                && header_value_matches(pattern.as_bytes(), name.as_str().as_bytes())
        })
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

fn protected_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "content-length"
            | "transfer-encoding"
            | "trailer"
            | "connection"
            | "upgrade"
            | "sec-websocket-accept"
    )
}

struct Respond {
    path: Option<PathMatcher>,
    status: StatusCode,
    implicit_status: bool,
    template: Option<String>,
    headers: HeaderMap,
    body: Bytes,
    close: bool,
}

impl Respond {
    fn new(rule: &crate::config::RespondConfig, site: &SiteConfig) -> Result<Self> {
        rule.validate()?;
        let status = StatusCode::from_u16(rule.status)?;
        let body = if matches!(status.as_u16(), 204 | 205 | 304) {
            Bytes::new()
        } else {
            Bytes::copy_from_slice(rule.body.as_bytes())
        };
        let mut headers = HeaderMap::new();
        if !body.is_empty() {
            let content = rule.body.trim_start();
            let content_type = if content.starts_with(['{', '['])
                && serde_json::from_str::<serde_json::Value>(content).is_ok()
            {
                "application/json"
            } else {
                "text/plain; charset=utf-8"
            };
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        add_configured_headers(&mut headers, site);
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::TRANSFER_ENCODING);
        headers.remove(header::TRAILER);
        let path = rule.path.as_deref().map(PathMatcher::new).transpose()?;
        Ok(Self {
            path,
            status,
            implicit_status: rule.implicit_status,
            template: rule.body.contains('{').then(|| rule.body.clone()),
            headers,
            body,
            close: rule.close,
        })
    }

    fn response(
        &self,
        request: &Request<Option<Incoming>>,
        error: Option<&RouteError>,
        captures: Option<&RouteCaptures>,
    ) -> Response<Body> {
        let status = if self.implicit_status {
            error.map_or(self.status, |error| error.status)
        } else {
            self.status
        };
        let content = if matches!(status.as_u16(), 204 | 205 | 304) {
            Bytes::new()
        } else if let Some(template) = &self.template {
            Bytes::from(expand_values(template, request.uri(), error, captures).into_owned())
        } else {
            self.body.clone()
        };
        let head = request.method() == Method::HEAD;
        let mut headers = self.headers.clone();
        if head && !matches!(status.as_u16(), 204 | 304) {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(content.len()));
        }
        if self.close
            && matches!(
                request.version(),
                http::Version::HTTP_10 | http::Version::HTTP_11
            )
        {
            headers.insert(CONNECTION, HeaderValue::from_static("close"));
        }
        let body = if head { Bytes::new() } else { content };
        let mut response = Response::new(Full::new(body).map_err(|never| match never {}).boxed());
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }
}

impl Site {
    fn apply_proxy_response_headers(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.proxy_response_headers {
            headers.insert(name, value.clone());
        }
    }

    fn respond(&self, path: &str) -> Option<&Respond> {
        let first = self.responses.first()?;
        if first.path.is_none() {
            return Some(first);
        }
        let raw = path;
        let path = normalize_match_path(path);
        self.responses.iter().find(|rule| {
            rule.path
                .as_ref()
                .is_none_or(|pattern| pattern.matches(&path, raw))
        })
    }
}

fn normalize_match_path(path: &str) -> Cow<'_, str> {
    normalize_match_path_with(path, true)
}

fn normalize_match_path_with(path: &str, merge_slashes: bool) -> Cow<'_, str> {
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    let path = match clean_path(&decoded, merge_slashes) {
        Cow::Owned(path) => Cow::Owned(path),
        Cow::Borrowed(_) => decoded,
    };
    if path.is_ascii() {
        path
    } else {
        Cow::Owned(path.to_lowercase())
    }
}

fn clean_path(path: &str, merge_slashes: bool) -> Cow<'_, str> {
    if merge_slashes && path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        Cow::Owned(normalize_response_path(path, merge_slashes))
    } else {
        Cow::Borrowed(path)
    }
}

fn normalize_response_path(path: &str, merge_slashes: bool) -> String {
    let mut segments = Vec::new();
    let mut input = path.strip_prefix('/').unwrap_or(path).split('/').peekable();
    while let Some(segment) = input.next() {
        match segment {
            "" if merge_slashes && input.peek().is_some() => {}
            "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    format!("/{}", segments.join("/"))
}

impl Server {
    pub fn new(config: Config) -> Result<Self> {
        let sites =
            config
                .sites
                .iter()
                .map(|site| {
                    let mut responses = site
                        .responses
                        .iter()
                        .map(|rule| Respond::new(rule, site))
                        .collect::<Result<Vec<_>>>()?;
                    responses.sort_by_key(|rule| {
                        std::cmp::Reverse(rule.path.as_ref().map(|path| {
                            (path.pattern.len(), !matches!(path.mode, PathMode::Prefix))
                        }))
                    });
                    crate::routes::validate_routes(&site.routes, 0)?;
                    let mut proxy_response_headers = HeaderMap::new();
                    add_configured_headers(&mut proxy_response_headers, site);
                    Ok(Site {
                        proxy_response_headers,
                        routes: Route::compile(&site.routes, site, &config)?,
                        error_routes: site
                            .error_routes
                            .iter()
                            .map(|route| -> Result<_> {
                                route.validate()?;
                                Ok((route.clone(), Route::compile(&route.routes, site, &config)?))
                            })
                            .collect::<Result<_>>()?,
                        proxy: (!site.upstreams.is_empty())
                            .then(|| ProxyHandler::new(&site.upstreams, &site.proxy))
                            .transpose()?,
                        static_files: StaticFiles::new(site, &config)?,
                        config: site.clone(),
                        responses,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
        let mut http_routes = HostRoutes::default();
        let mut https_routes = HostRoutes::default();
        for (index, site) in sites.iter().enumerate() {
            let routes = if site.config.tls {
                if site.config.listen.unwrap_or(config.https_addr) != config.https_addr {
                    continue;
                }
                &mut https_routes
            } else {
                &mut http_routes
            };
            for host in &site.config.hosts {
                routes.insert(host, index);
            }
        }
        Ok(Self {
            config: Arc::new(config),
            sites: sites.into(),
            http_routes,
            https_routes: Arc::new(https_routes),
            clients: Arc::new(ProxyClients::new(Duration::from_secs(10))),
            handshake_log: Arc::default(),
        })
    }

    pub(crate) fn spawn_health_checks(
        self: &Arc<Self>,
        stop: &tokio_util::sync::CancellationToken,
    ) {
        let mut proxies = Vec::new();
        for site in self.sites.iter() {
            proxies.extend(site.proxy.iter().cloned());
            let mut routes: Vec<_> = site
                .routes
                .iter()
                .chain(site.error_routes.iter().flat_map(|(_, routes)| routes))
                .collect();
            while let Some(route) = routes.pop() {
                match &route.action {
                    Action::Proxy(proxy) => proxies.push(proxy.clone()),
                    Action::Route(nested) | Action::Handle { routes: nested, .. } => {
                        routes.extend(nested)
                    }
                    _ => {}
                }
            }
        }
        for proxy in proxies {
            let Some(path) = &proxy.settings.health_uri else {
                continue;
            };
            let interval = Duration::from_secs(proxy.settings.health_interval_secs.unwrap_or(30));
            let deadline = Duration::from_secs(proxy.settings.health_timeout_secs.unwrap_or(5));
            for (j, upstream) in proxy.upstreams.iter().enumerate() {
                let Ok(path) = path.parse() else {
                    continue;
                };
                let Ok(uri) = upstream.uri(path) else {
                    continue;
                };
                let server = self.clone();
                let proxy = proxy.clone();
                let stop = stop.clone();
                tokio::spawn(async move {
                    let upstream = &proxy.upstreams[j];
                    loop {
                        let healthy = tokio::select! {
                            biased;
                            _ = stop.cancelled() => return,
                            result = timeout(deadline, async {
                                let request = Request::get(uri.clone())
                                    .header(HOST, upstream.authority.as_str())
                                    .version(if upstream.h2c { http::Version::HTTP_2 } else { http::Version::HTTP_11 })
                                    .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())?;
                                let response = proxy.clients.as_deref().unwrap_or(&server.clients).request_upstream(upstream, false, proxy.settings.proxy_protocol, None, request).await?;
                                Ok::<_, BoxError>(response.status() == StatusCode::OK)
                            }) => matches!(result, Ok(Ok(true))),
                        };
                        if upstream.healthy.swap(healthy, Ordering::Relaxed) != healthy {
                            info!(upstream = %upstream.authority, healthy, "upstream health changed");
                        }
                        tokio::select! {
                            _ = stop.cancelled() => return,
                            _ = tokio::time::sleep(interval) => {},
                        }
                    }
                });
            }
        }
    }

    pub async fn run(self, cloudflare: Option<Arc<crate::cloudflare::Cloudflare>>) -> Result<()> {
        let server = Arc::new(self);
        let stop = tokio_util::sync::CancellationToken::new();
        let _stop = stop.clone().drop_guard();
        let listeners = server.tls_endpoints(cloudflare, &stop).await?;
        let mut tasks = tokio::task::JoinSet::new();
        let http = TcpListener::bind(server.config.http_addr).await?;
        for (address, view, acceptor) in listeners {
            let socket = TcpListener::bind(address)
                .await
                .with_context(|| format!("could not bind HTTPS listener on {address}"))?;
            tasks.spawn(accept_loop(socket, view, Some(acceptor)));
        }
        server.spawn_health_checks(&stop);
        tasks.spawn(accept_loop(http, server, None));
        while let Some(result) = tasks.join_next().await {
            result??;
        }
        Ok(())
    }

    pub(crate) async fn tls_endpoints(
        self: &Arc<Self>,
        cloudflare: Option<Arc<crate::cloudflare::Cloudflare>>,
        stop: &tokio_util::sync::CancellationToken,
    ) -> Result<Vec<(SocketAddr, Arc<Self>, TlsAcceptor)>> {
        let addresses = self.config.https_listeners();
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let store = CertificateStore::new(self.config.clone(), cloudflare);
        store.provision().await?;
        let mut endpoints = Vec::with_capacity(addresses.len());
        for address in addresses {
            let view = if address == self.config.https_addr {
                self.clone()
            } else {
                let mut routes = HostRoutes::default();
                for (index, site) in self.sites.iter().enumerate().filter(|(_, site)| {
                    site.config.tls
                        && site.config.listen.unwrap_or(self.config.https_addr) == address
                }) {
                    for host in &site.config.hosts {
                        routes.insert(host, index);
                    }
                }
                Arc::new(Self {
                    config: self.config.clone(),
                    sites: self.sites.clone(),
                    http_routes: HostRoutes::default(),
                    https_routes: Arc::new(routes),
                    clients: self.clients.clone(),
                    handshake_log: Arc::default(),
                })
            };
            let mut tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(store.resolver_for(address));
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            view.handshake_log.start(address, stop.clone());
            endpoints.push((address, view, TlsAcceptor::from(Arc::new(tls))));
        }
        store.spawn_renewals(stop.clone());
        Ok(endpoints)
    }

    pub(crate) fn tls_sni_specificity(&self, sni: &str) -> Option<u8> {
        if self.https_routes.exact.contains_key(sni) {
            Some(2)
        } else {
            self.https_routes.matched(sni).map(|_| 1)
        }
    }

    fn site(&self, host: &str, secure: bool) -> Option<&Site> {
        let index = if secure {
            self.https_routes
                .matched(host)
                .or(self.https_routes.fallback)
        } else {
            self.http_routes
                .matched(host)
                .or_else(|| {
                    self.config
                        .redirect_http
                        .then(|| self.https_routes.matched(host))
                        .flatten()
                })
                .or(self.http_routes.fallback)
        }?;
        self.sites.get(index)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn static_site(
        &self,
        host: &str,
        path: &str,
    ) -> Option<&Arc<crate::static_files::StaticFiles>> {
        let site = self.site(host, false)?;
        if site.config.tls && self.config.redirect_http || !site.error_routes.is_empty() {
            return None;
        }
        let files = site.static_files.as_ref()?;
        site.respond(path).is_none().then_some(files)
    }

    pub(crate) fn max_header_size(&self) -> usize {
        self.config.max_header_size
    }

    async fn handle(
        &self,
        request: Request<Option<Incoming>>,
        peer: Option<&Peer>,
        secure: bool,
        connections: &crate::runtime::Connections,
    ) -> Result<Response<Body>, Infallible> {
        let host = request_host(&request).unwrap_or_default();
        let Some(site) = self.site(&host, secure) else {
            return Ok(text_response(
                StatusCode::NOT_FOUND,
                "no site is configured for this host\n",
            ));
        };
        if !secure && site.config.tls && self.config.redirect_http {
            let mut target = if self.config.https_addr.port() == 443 {
                format!("https://{host}")
            } else {
                format!("https://{host}:{}", self.config.https_addr.port())
            };
            if let Some(path) = request.uri().path_and_query() {
                target.push_str(path.as_str());
            }
            let mut response = text_response(StatusCode::PERMANENT_REDIRECT, "");
            if let Ok(location) = HeaderValue::from_str(&target) {
                response.headers_mut().insert(LOCATION, location);
            }
            return Ok(response);
        }
        if !site.routes.is_empty() || !site.error_routes.is_empty() {
            return Ok(self
                .route_request(request, site, peer, secure, connections)
                .await);
        }
        if let Some(rule) = site.respond(request.uri().path()) {
            return Ok(rule.response(&request, None, None));
        }
        Ok(if let Some(proxy) = &site.proxy {
            self.proxy_response(request, site, proxy, peer, secure, connections)
                .await
        } else if let Some(files) = &site.static_files {
            Self::static_response(request, files).await
        } else {
            route_empty_response()
        })
    }

    async fn route_request(
        &self,
        mut request: Request<Option<Incoming>>,
        site: &Site,
        peer: Option<&Peer>,
        secure: bool,
        connections: &crate::runtime::Connections,
    ) -> Response<Body> {
        let mut context = RouteRequest {
            request: &mut request,
            site,
            peer,
            secure,
            connections,
            captures: RouteCaptures::default(),
            immediate_headers: HeaderMap::new(),
            immediate_replacements: HashSet::new(),
        };
        let original_uri = (!site.error_routes.is_empty()).then(|| context.request.uri().clone());
        let result = self.run_routes(&site.routes, &mut context, None).await;
        match result {
            Ok(response) => response,
            Err(error) => {
                if let Some(uri) = original_uri {
                    *context.request.uri_mut() = uri;
                }
                for (condition, routes) in &site.error_routes {
                    if condition.matches(error.status.as_u16()) {
                        return self
                            .run_routes(routes, &mut context, Some(&error))
                            .await
                            .unwrap_or_else(|_| error.response());
                    }
                }
                error.response()
            }
        }
    }

    async fn run_routes(
        &self,
        routes: &[Route],
        context: &mut RouteRequest<'_>,
        error: Option<&RouteError>,
    ) -> Result<Response<Body>, RouteError> {
        let request = &mut *context.request;
        let mut response_headers = Vec::new();
        let mut stack = Vec::with_capacity(4);
        stack.push(RouteCursor::new(routes));
        let mut response = loop {
            let Some(scope) = stack.last_mut() else {
                break error.map_or_else(route_empty_response, |error| error.empty_response());
            };
            let Some((route, remaining)) = scope.remaining.split_first() else {
                stack.pop();
                continue;
            };
            scope.remaining = remaining;
            if scope.handled && matches!(route.action, Action::Handle { .. }) {
                continue;
            }
            let rewrite = matches!(route.action, Action::Rewrite(_));
            if !rewrite || scope.rewrite_matcher != Some(&route.matcher) {
                scope.rewrite_chain_matched = false;
            }
            scope.rewrite_matcher = rewrite.then_some(&route.matcher);
            if rewrite && scope.rewritten && !scope.rewrite_chain_matched {
                continue;
            }
            let path = (!route.matcher.paths.is_empty())
                .then(|| normalize_match_path(request.uri().path()));
            if !scope.rewrite_chain_matched {
                if !route
                    .matcher
                    .matches(request, path.as_deref(), &mut context.captures)
                {
                    continue;
                }
                if let Some(expression) = &route.matcher.expression {
                    match expression.matches(|name| {
                        expression_value(
                            name,
                            request,
                            context.peer.map(|peer| peer.address),
                            context.secure,
                            error,
                            &context.captures,
                        )
                    }) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(error) => {
                            tracing::debug!(%error, "CEL matcher failed");
                            return Err(RouteError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "CEL matcher failed\n",
                            ));
                        }
                    }
                }
            }
            match &route.action {
                Action::Route(routes) => stack.push(RouteCursor::new(routes)),
                Action::Handle {
                    routes,
                    strip_prefix,
                } => {
                    scope.handled = true;
                    if let Some(prefix) = strip_prefix
                        && strip_route_prefix(request.uri_mut(), prefix).is_err()
                    {
                        return Err(RouteError::new(
                            StatusCode::BAD_REQUEST,
                            "invalid path after handle_path\n",
                        ));
                    }
                    stack.push(RouteCursor::new(routes));
                }
                Action::Error(status, message) => {
                    return Err(RouteError::new(
                        *status,
                        expand_values(message, request.uri(), error, Some(&context.captures)),
                    ));
                }
                Action::Header(headers) => {
                    if headers.defer {
                        response_headers.push(headers);
                    } else {
                        headers.apply_with_replacements(
                            &mut context.immediate_headers,
                            Some(&mut context.immediate_replacements),
                            |template| {
                                expand_values(
                                    template,
                                    request.uri(),
                                    error,
                                    Some(&context.captures),
                                )
                                .into_owned()
                            },
                        );
                    }
                }
                Action::Rewrite(to) => {
                    scope.rewritten = true;
                    scope.rewrite_chain_matched = true;
                    let to = expand_values(to, request.uri(), error, Some(&context.captures))
                        .into_owned();
                    if replace_uri(request.uri_mut(), &to).is_err() {
                        return Err(RouteError::new(
                            StatusCode::BAD_REQUEST,
                            "invalid rewrite target\n",
                        ));
                    }
                }
                Action::TryFiles {
                    root,
                    paths,
                    status,
                    policy,
                } => {
                    let candidates: Vec<_> = paths
                        .iter()
                        .map(|path| {
                            let (file, query) = path
                                .split_once('?')
                                .map_or((path.as_str(), None), |(file, query)| (file, Some(query)));
                            (
                                expand_values_with(
                                    file,
                                    request.uri(),
                                    error,
                                    Some(&context.captures),
                                    true,
                                )
                                .into_owned(),
                                query.map(|query| {
                                    expand_values(
                                        query,
                                        request.uri(),
                                        error,
                                        Some(&context.captures),
                                    )
                                    .into_owned()
                                }),
                            )
                        })
                        .collect();
                    let root = root.clone();
                    let policy = *policy;
                    let found = tokio::task::spawn_blocking(move || {
                        select_try_file(&root, candidates, policy)
                    })
                    .await;
                    match found {
                        Ok(Some(to)) => {
                            let to = if to.starts_with('/') {
                                to
                            } else {
                                format!("/{to}")
                            };
                            if replace_uri(request.uri_mut(), &to).is_err() {
                                return Err(RouteError::new(
                                    StatusCode::BAD_REQUEST,
                                    "invalid try_files target\n",
                                ));
                            }
                        }
                        Ok(None) => {
                            if let Some(status) = status {
                                return Err(RouteError::new(
                                    StatusCode::from_u16(*status).expect("validated HTTP status"),
                                    "not found\n",
                                ));
                            }
                        }
                        Err(error) => {
                            warn!(%error, "try_files task failed");
                            return Err(RouteError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "could not check files\n",
                            ));
                        }
                    }
                }
                Action::Respond(rule) => {
                    break rule.response(request, error, Some(&context.captures));
                }
                Action::Proxy(proxy) => {
                    break self
                        .proxy_attempt(
                            request,
                            context.site,
                            proxy,
                            context.peer,
                            context.secure,
                            context.connections,
                        )
                        .await?;
                }
                Action::Files(files) => break Self::try_static_response(request, files).await?,
            }
        };
        for name in context.immediate_headers.keys() {
            if context.immediate_replacements.contains(name) {
                response.headers_mut().remove(name);
            }
            for value in context.immediate_headers.get_all(name) {
                response.headers_mut().append(name, value.clone());
            }
        }
        for headers in response_headers.into_iter().rev() {
            if headers.applies(&response) {
                headers.apply(response.headers_mut(), |template| {
                    expand_values(template, request.uri(), error, Some(&context.captures))
                        .into_owned()
                });
            }
        }

        Ok(response)
    }

    async fn proxy_response(
        &self,
        mut request: Request<Option<Incoming>>,
        site: &Site,
        proxy: &ProxyHandler,
        peer: Option<&Peer>,
        secure: bool,
        connections: &crate::runtime::Connections,
    ) -> Response<Body> {
        self.proxy_attempt(&mut request, site, proxy, peer, secure, connections)
            .await
            .unwrap_or_else(|error| error.response())
    }

    async fn proxy_attempt(
        &self,
        request: &mut Request<Option<Incoming>>,
        site: &Site,
        proxy: &ProxyHandler,
        peer: Option<&Peer>,
        secure: bool,
        connections: &crate::runtime::Connections,
    ) -> Result<Response<Body>, RouteError> {
        match self
            .proxy(request, site, proxy, peer, secure, connections)
            .await
        {
            Ok(response) => Ok(response),
            Err(error) if error.is::<UpstreamTimeout>() => Err(RouteError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream request timed out\n",
            )),
            Err(error) => {
                warn!(%error, "upstream request failed");
                Err(RouteError::new(
                    StatusCode::BAD_GATEWAY,
                    "upstream request failed\n",
                ))
            }
        }
    }

    async fn proxy(
        &self,
        request: &mut Request<Option<Incoming>>,
        site: &Site,
        proxy: &ProxyHandler,
        peer: Option<&Peer>,
        secure: bool,
        connections: &crate::runtime::Connections,
    ) -> std::result::Result<Response<Body>, BoxError> {
        let websocket = if header_has_token(request.headers(), UPGRADE, "websocket") {
            let Some(key) = websocket_key(request) else {
                return Ok(text_response(
                    StatusCode::BAD_REQUEST,
                    "invalid WebSocket upgrade\n",
                ));
            };
            Some((websocket_accept(key), hyper::upgrade::on(&mut *request)))
        } else {
            None
        };
        let start = match proxy.settings.lb_policy {
            ProxyPolicy::RoundRobin if proxy.upstreams.len() > 1 => {
                proxy.next_upstream.fetch_add(1, Ordering::Relaxed) % proxy.upstreams.len()
            }
            _ => 0,
        };
        let replayable = websocket.is_none()
            && matches!(*request.method(), Method::GET | Method::HEAD)
            && request
                .body()
                .as_ref()
                .is_none_or(hyper::body::Body::is_end_stream);
        let mut parts = Request::new(()).into_parts().0;
        parts.method = request.method().clone();
        parts.uri = request.uri().clone();
        parts.version = request.version();
        parts.headers = if site.error_routes.is_empty() {
            std::mem::take(request.headers_mut())
        } else {
            request.headers().clone()
        };
        let start_time = Instant::now();
        let mut progress = None;
        let mut body = request
            .body_mut()
            .take()
            .filter(|body| !body.is_end_stream())
            .map(|body| {
                let (sender, receiver) = tokio::sync::watch::channel(start_time);
                progress = Some(receiver);
                UploadBody {
                    body,
                    progress: sender,
                }
                .boxed()
            });
        let trailers = prepare_proxy_headers(&mut parts.headers, &parts.uri, peer, secure)?;
        let mut parts = Some(parts);
        let mut retries = if replayable {
            proxy.settings.lb_retries
        } else {
            0
        };
        let mut last_error = None;
        let mut response = None;
        for upstream in proxy.upstreams[start..]
            .iter()
            .chain(&proxy.upstreams[..start])
        {
            if !upstream.healthy.load(Ordering::Relaxed) || upstream.h2c && websocket.is_some() {
                continue;
            }
            let mut attempt = if retries == 0 {
                parts
                    .take()
                    .expect("request parts exist before final attempt")
            } else {
                parts
                    .as_ref()
                    .expect("request parts exist before a retry")
                    .clone()
            };
            attempt.uri = upstream.uri(
                attempt
                    .uri
                    .path_and_query()
                    .cloned()
                    .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/")),
            )?;
            if upstream.h2c {
                attempt.version = http::Version::HTTP_2;
                if trailers {
                    attempt
                        .headers
                        .insert(header::TE, HeaderValue::from_static("trailers"));
                }
            } else {
                attempt.version = http::Version::HTTP_11;
            }
            upstream.apply_host(&mut attempt.headers);
            HeaderOperation::apply_all(&proxy.header_up, &mut attempt.headers);
            if websocket.is_some() {
                set_websocket_upgrade(&mut attempt.headers);
            }
            let request = Request::from_parts(attempt, body.take().unwrap_or_else(empty_body));
            let result = response_deadline(
                proxy
                    .clients
                    .as_deref()
                    .unwrap_or(&self.clients)
                    .request_upstream(
                        upstream,
                        websocket.is_some(),
                        proxy.settings.proxy_protocol,
                        connections.addresses,
                        request,
                    ),
                proxy
                    .settings
                    .response_header_timeout_secs
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| self.config.request_timeout()),
                start_time,
                progress.as_ref(),
            )
            .await;
            match result {
                Ok(winner) => {
                    response = Some(winner);
                    break;
                }
                Err(error) if error.is::<UpstreamTimeout>() => return Err(error),
                Err(error) => {
                    last_error = Some((upstream, error));
                    if retries == 0 {
                        break;
                    }
                    retries -= 1;
                }
            }
        }
        let mut response = match (response, last_error) {
            (Some(response), _) => response,
            (_, Some((upstream, error))) => {
                let error = anyhow::Error::from_boxed(error);
                return Err(format!("{}: {error:#}", upstream.authority).into());
            }
            _ if websocket.is_some() && proxy.upstreams.iter().all(|upstream| upstream.h2c) => {
                return Err("HTTP/1.1 WebSocket upgrade is not supported by h2c upstreams".into());
            }
            _ => {
                return Ok(text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no healthy upstream available\n",
                ));
            }
        };
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some((accept, downstream)) = websocket else {
                return Err("unexpected upstream protocol switch".into());
            };
            let headers = response.headers();
            if !header_has_token(headers, CONNECTION, "upgrade")
                || !header_is(headers, UPGRADE, "websocket")
                || single_header(headers, SEC_WEBSOCKET_ACCEPT) != Some(accept.as_str())
            {
                return Err("invalid WebSocket upgrade from upstream".into());
            }
            let upstream = hyper::upgrade::on(&mut response).await?;
            let (mut parts, _) = response.into_parts();
            strip_hop_by_hop_headers(&mut parts.headers);
            site.apply_proxy_response_headers(&mut parts.headers);
            HeaderOperation::apply_all(&proxy.header_down, &mut parts.headers);
            strip_hop_by_hop_headers(&mut parts.headers);
            set_websocket_upgrade(&mut parts.headers);
            parts.headers.remove(header::CONTENT_LENGTH);
            parts
                .headers
                .insert(SEC_WEBSOCKET_ACCEPT, HeaderValue::from_str(&accept)?);
            let peer = peer.map(|peer| peer.address);
            let force = connections.force.clone();
            let admission = connections.admission.clone();
            connections.tasks.spawn(async move {
                let _admission = admission;
                tokio::select! {
                    biased;
                    _ = force.cancelled() => {},
                    _ = async {
                        match downstream.await {
                            Ok(downstream) => {
                                if let Err(error) = relay_websocket(
                                    TokioIo::new(downstream),
                                    TokioIo::new(upstream),
                                )
                                .await
                                {
                                    tracing::debug!(?peer, %error, "WebSocket tunnel closed");
                                }
                            }
                            Err(error) => tracing::debug!(?peer, %error, "WebSocket client upgrade failed"),
                        }
                    } => {},
                }
            });
            return Ok(Response::from_parts(
                parts,
                http_body_util::Empty::new()
                    .map_err(|never| match never {})
                    .boxed(),
            ));
        }
        let (mut parts, body) = response.into_parts();
        strip_hop_by_hop_headers(&mut parts.headers);
        site.apply_proxy_response_headers(&mut parts.headers);
        HeaderOperation::apply_all(&proxy.header_down, &mut parts.headers);
        Ok(Response::from_parts(
            parts,
            upstream_body(
                body,
                proxy
                    .settings
                    .stream_idle_timeout_secs
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| self.config.request_timeout()),
                progress.filter(|_| proxy.settings.stream_idle_timeout_secs.is_some()),
            ),
        ))
    }

    async fn static_response(
        request: Request<Option<Incoming>>,
        files: &Arc<StaticFiles>,
    ) -> Response<Body> {
        Self::try_static_response(&request, files)
            .await
            .unwrap_or_else(|error| error.response())
    }

    async fn try_static_response(
        request: &Request<Option<Incoming>>,
        files: &Arc<StaticFiles>,
    ) -> Result<Response<Body>, RouteError> {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return Err(RouteError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed\n",
            ));
        }
        let file = files
            .resolve(request.uri().path())
            .await
            .map_err(|error| RouteError::new(error.status(), error.message()))?;
        Ok(file_response(request, files.clone(), file).await)
    }
}

impl Server {
    pub(crate) async fn serve_socket(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        tls: Option<TlsAcceptor>,
        connections: crate::runtime::Connections,
    ) {
        if let Err(error) = stream.set_nodelay(true) {
            warn!(%peer, %error, "failed to set TCP_NODELAY");
        }
        let result = match tls {
            Some(acceptor) => {
                self.serve_tls(stream, peer, acceptor, connections).await;
                return;
            }
            None => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    crate::static_server::serve_connection_with_drain(
                        stream,
                        self,
                        peer,
                        connections,
                    )
                    .await
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    serve_connection_with_drain(stream, self, peer, false, connections).await
                }
            }
        };
        log_connection_result(peer, result);
    }

    pub(crate) async fn serve_tls<I>(
        self: Arc<Self>,
        stream: I,
        peer: SocketAddr,
        acceptor: TlsAcceptor,
        connections: crate::runtime::Connections,
    ) where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let handshake = tokio::select! {
            biased;
            _ = connections.drain.cancelled() => return,
            result = timeout(Duration::from_secs(10), acceptor.accept(stream)) => result,
        };
        match handshake {
            Ok(Ok(stream)) => log_connection_result(
                peer,
                serve_connection_with_drain(stream, self, peer, true, connections).await,
            ),
            Ok(Err(error)) => self.handshake_log.failed(peer, error),
            Err(_) => self.handshake_log.timeout(peer),
        }
    }
}

fn log_connection_result(peer: SocketAddr, result: std::result::Result<(), BoxError>) {
    if let Err(error) = result {
        if matches!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        ) {
            tracing::debug!(%peer, %error, "HTTP connection closed");
        } else {
            warn!(%peer, %error, "HTTP connection ended with an error");
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    server: Arc<Server>,
    tls: Option<TlsAcceptor>,
) -> Result<()> {
    let connections = crate::runtime::Connections::default();
    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(
            server
                .clone()
                .serve_socket(stream, peer, tls.clone(), connections.clone()),
        );
    }
}

#[cfg(test)]
pub(crate) async fn serve_connection<I>(
    io: I,
    server: Arc<Server>,
    peer: SocketAddr,
    secure: bool,
) -> std::result::Result<(), BoxError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    serve_connection_with_drain(
        io,
        server,
        peer,
        secure,
        crate::runtime::Connections::default(),
    )
    .await
}

pub(crate) async fn serve_connection_with_drain<I>(
    io: I,
    server: Arc<Server>,
    peer: SocketAddr,
    secure: bool,
    connections: crate::runtime::Connections,
) -> std::result::Result<(), BoxError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let max_header_size = server.config.max_header_size;
    let drain = connections.drain.clone();
    let session = Arc::new((server, connections, Peer::new(peer)?));
    let service = service_fn(move |request: Request<Incoming>| {
        let session = session.clone();
        async move {
            session
                .0
                .handle(request.map(Some), Some(&session.2), secure, &session.1)
                .await
        }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15))
        .max_buf_size(max_header_size);
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result?,
        _ = drain.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await?;
        }
    }
    Ok(())
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
}

fn single_header(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value.trim())
}

fn header_is(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    single_header(headers, name).is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn websocket_key(request: &Request<Option<Incoming>>) -> Option<&str> {
    let headers = request.headers();
    if request.version() != http::Version::HTTP_11
        || request.method() != Method::GET
        || request
            .body()
            .as_ref()
            .is_some_and(|body| !body.is_end_stream())
        || !header_has_token(headers, CONNECTION, "upgrade")
        || !header_is(headers, UPGRADE, "websocket")
        || !header_is(headers, SEC_WEBSOCKET_VERSION, "13")
    {
        return None;
    }
    let key = single_header(headers, SEC_WEBSOCKET_KEY)?;
    let mut nonce = [0; 18];
    (key.len() == 24 && STANDARD.decode_slice(key, &mut nonce).ok()? == 16).then_some(key)
}

async fn relay_websocket(
    downstream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    upstream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
) -> std::io::Result<()> {
    use tokio_util::io::InspectReader;

    const HALF_CLOSE_GRACE: Duration = Duration::from_secs(10);
    let eof = tokio::sync::Notify::new();
    let on_read = |bytes: &[u8]| {
        if bytes.is_empty() {
            eof.notify_one();
        }
    };
    let mut downstream = InspectReader::new(downstream, on_read);
    let mut upstream = InspectReader::new(upstream, on_read);
    let copy = tokio::io::copy_bidirectional(&mut downstream, &mut upstream);
    tokio::pin!(copy);
    tokio::select! {
        result = &mut copy => result?,
        _ = eof.notified() => timeout(HALF_CLOSE_GRACE, copy).await??,
    };
    Ok(())
}

fn websocket_accept(key: &str) -> String {
    let mut sha1 = Digest::new(&SHA1_FOR_LEGACY_USE_ONLY);
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(sha1.finish())
}

fn set_websocket_upgrade(headers: &mut HeaderMap) {
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
}

#[derive(Debug, thiserror::Error)]
#[error("timed out waiting for upstream response or upload progress")]
struct UpstreamTimeout;

struct UploadBody {
    body: Incoming,
    progress: tokio::sync::watch::Sender<Instant>,
}

impl hyper::body::Body for UploadBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.body).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.data_ref().is_none_or(|data| !data.is_empty()) || self.body.is_end_stream()
                {
                    self.progress.send_replace(Instant::now());
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.progress.send_replace(Instant::now());
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

async fn response_deadline<T>(
    future: impl Future<Output = Result<T, BoxError>>,
    idle: Duration,
    started: Instant,
    progress: Option<&tokio::sync::watch::Receiver<Instant>>,
) -> Result<T, BoxError> {
    with_idle_timeout(future, idle, started, progress).await?
}

async fn with_idle_timeout<T>(
    future: impl Future<Output = T>,
    idle: Duration,
    started: Instant,
    progress: Option<&tokio::sync::watch::Receiver<Instant>>,
) -> Result<T, UpstreamTimeout> {
    let mut future = std::pin::pin!(future);
    let mut last = started;
    loop {
        let Some(deadline) = last.checked_add(idle) else {
            return Ok(future.await);
        };
        match timeout_at(deadline, future.as_mut()).await {
            Ok(result) => return Ok(result),
            Err(_) => {
                let updated = progress.map(|receiver| *receiver.borrow());
                match updated {
                    Some(updated) if updated > last && updated.elapsed() < idle => last = updated,
                    _ => return Err(UpstreamTimeout),
                }
            }
        }
    }
}

fn upstream_body(
    body: Incoming,
    idle: Duration,
    progress: Option<tokio::sync::watch::Receiver<Instant>>,
) -> Body {
    let stream = futures_util::stream::unfold(Some((body, progress)), move |state| async move {
        let (mut body, progress) = state?;
        match with_idle_timeout(body.frame(), idle, Instant::now(), progress.as_ref()).await {
            Ok(Some(Ok(frame))) => Some((Ok(frame), Some((body, progress)))),
            Ok(Some(Err(error))) => Some((Err(BoxError::from(error)), None)),
            Ok(None) => None,
            Err(_) => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream response body timed out",
                )
                .into()),
                None,
            )),
        }
    });
    BodyExt::boxed(StreamBody::new(stream))
}

async fn file_response(
    request: &Request<Option<Incoming>>,
    files: Arc<crate::static_files::StaticFiles>,
    file: Arc<crate::static_files::CachedFile>,
) -> Response<Body> {
    use crate::static_files::FileReply;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let head = request.method() == Method::HEAD;
    let reply;
    let mut selected = file;
    let body = if head || selected.body.is_some() {
        reply = selected.evaluate(request.headers(), head);
        let bytes = match (&reply, &selected.body) {
            (FileReply::Full, Some(bytes)) if !head => bytes.clone(),
            (FileReply::Partial(range), Some(bytes)) => {
                bytes.slice(range.start as usize..range.end as usize)
            }
            _ => Bytes::new(),
        };
        Full::new(bytes).map_err(|never| match never {}).boxed()
    } else {
        let opened = {
            let files = files.clone();
            let file = selected.clone();
            tokio::task::spawn_blocking(move || files.open_for_streaming(&file)).await
        };
        let Ok(Ok((opened, current))) = opened else {
            return text_response(StatusCode::NOT_FOUND, "not found\n");
        };
        selected = current;
        reply = selected.evaluate(request.headers(), false);
        match &reply {
            FileReply::Status(_) => Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
            FileReply::Full | FileReply::Partial(_) => {
                let mut opened = tokio::fs::File::from_std(opened);
                let len = if let FileReply::Partial(range) = &reply {
                    if opened
                        .seek(std::io::SeekFrom::Start(range.start))
                        .await
                        .is_err()
                    {
                        return text_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "could not seek file\n",
                        );
                    }
                    range.end - range.start
                } else {
                    selected.length
                };
                let stream = ReaderStream::with_capacity(opened.take(len), 128 * 1024);
                BodyExt::boxed(StreamBody::new(
                    stream.map(|chunk| chunk.map(Frame::data).map_err(BoxError::from)),
                ))
            }
        }
    };
    let mut response = Response::new(body);
    *response.status_mut() = reply.status();
    *response.headers_mut() = selected.response_headers(&files.response_headers, &reply);
    response
}

fn request_host(request: &Request<Option<Incoming>>) -> Option<String> {
    request_host_parts(request)
}

fn request_host_parts<B>(request: &Request<B>) -> Option<String> {
    let authority = request.uri().authority().map_or_else(
        || request.headers().get(HOST)?.to_str().ok(),
        |authority| Some(authority.as_str()),
    )?;
    if authority.starts_with('[') {
        return authority.split(']').next().map(|host| format!("{}]", host));
    }
    Some(
        authority
            .split(':')
            .next()?
            .trim_end_matches('.')
            .to_ascii_lowercase(),
    )
}

const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

fn prepare_proxy_headers(
    headers: &mut HeaderMap,
    uri: &Uri,
    peer: Option<&Peer>,
    secure: bool,
) -> Result<bool, header::InvalidHeaderValue> {
    let host = uri
        .authority()
        .map(|authority| HeaderValue::from_str(authority.as_str()))
        .transpose()?
        .or_else(|| headers.get(HOST).cloned());
    let trailers = header_has_token(headers, header::TE, "trailers");
    let te_nominated = strip_hop_by_hop_headers(headers);
    if let Some(host) = host {
        headers.entry(HOST).or_insert_with(|| host.clone());
        headers.insert(X_FORWARDED_HOST, host);
    } else {
        headers.remove(X_FORWARDED_HOST);
    }
    headers.insert(
        X_FORWARDED_PROTO,
        HeaderValue::from_static(if secure { "https" } else { "http" }),
    );
    if let Some(peer) = peer {
        headers.insert(X_FORWARDED_FOR, peer.forwarded_for.clone());
    } else {
        headers.remove(X_FORWARDED_FOR);
    }
    Ok(trailers && !te_nominated)
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) -> bool {
    let extra = headers
        .get_all(CONNECTION)
        .iter()
        .skip(1)
        .cloned()
        .collect::<Vec<_>>();
    let first = headers.remove(CONNECTION);
    let mut te_nominated = false;
    for value in first.into_iter().chain(extra) {
        if let Ok(value) = value.to_str() {
            for name in value.split(',').map(str::trim) {
                if name.eq_ignore_ascii_case("te") {
                    te_nominated = true;
                } else if name.eq_ignore_ascii_case("keep-alive") {
                    continue;
                } else if name.eq_ignore_ascii_case("close") {
                    headers.remove(HeaderName::from_static("close"));
                } else if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
                    headers.remove(name);
                }
            }
        }
    }
    static HOP_HEADERS: [HeaderName; 7] = [
        HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        UPGRADE,
    ];
    for name in &HOP_HEADERS {
        headers.remove(name);
    }
    te_nominated
}

fn add_configured_headers(headers: &mut HeaderMap, config: &SiteConfig) {
    for (name, value) in &config.response_headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) else {
            warn!(header = name, "ignoring invalid configured response header");
            continue;
        };
        headers.insert(name, value);
    }
}

pub fn text_response(status: StatusCode, text: &str) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::copy_from_slice(text.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::static_files::safe_relative_path;
    use http_body_util::Empty;

    use super::*;

    fn site(host: &str) -> SiteConfig {
        SiteConfig {
            listen: None,
            hosts: vec![host.to_owned()],
            tls: false,
            certificate_file: None,
            private_key_file: None,
            upstreams: vec![],
            proxy: Default::default(),
            root: None,
            index: vec![],
            response_headers: BTreeMap::new(),
            responses: vec![],
            routes: vec![],
            error_routes: vec![],
        }
    }

    #[tokio::test]
    async fn respond_takes_precedence_over_reverse_proxy() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let config = crate::caddyfile::parse(&format!(
            "http://health.test {{\n  reverse_proxy {addr}\n  respond /api* 403\n  respond /api/ready ok 201\n  respond /api/no-content ignored 204\n  header X-Health configured\n}}"
        ))
        .unwrap();
        let server = Arc::new(Server::new(config).unwrap());
        let (client, relay) = tokio::io::duplex(4096);
        let relay_task = tokio::spawn(serve_connection(relay, server, addr, false));
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let client_task = tokio::spawn(connection);
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|_| async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"upstream",
                        ))))
                    }),
                )
                .await
                .unwrap();
        });
        for (method, path, status, length, expected) in [
            (Method::GET, "/API//./%72eady?probe=1", 201, Some("2"), "ok"),
            (Method::HEAD, "/api/ready", 201, Some("2"), ""),
            (Method::GET, "/api/unready", 403, Some("0"), ""),
            (Method::GET, "/api/no-content", 204, None, ""),
            (Method::GET, "/proxy", 200, Some("8"), "upstream"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(HOST, "health.test")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let response = timeout(Duration::from_secs(5), sender.send_request(request))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["x-health"], "configured");
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .map(|v| v.to_str().unwrap()),
                length
            );
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                expected
            );
        }
        drop(sender);
        client_task.await.unwrap().unwrap();
        relay_task.await.unwrap().unwrap();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn http2_client_can_reach_http1_only_https_upstream() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = crate::caddyfile::parse(&format!(
            "http://relay.test {{ reverse_proxy https://localhost:{} }}",
            upstream.local_addr().unwrap().port(),
        ))
        .unwrap();
        let pem = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pem.cert.der().clone()).unwrap();
        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut upstream_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![pem.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(pem.signing_key.serialize_der()).into(),
            )
            .unwrap();
        upstream_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut server = Server::new(config).unwrap();
        Arc::get_mut(&mut server.clients).unwrap().client = Client::builder(TokioExecutor::new())
            .build(
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(client_tls)
                    .https_only()
                    .enable_http1()
                    .enable_http2()
                    .build(),
            );
        let (relay, client) = tokio::io::duplex(8192);
        let relay = tokio::spawn(serve_connection(
            relay,
            Arc::new(server),
            upstream.local_addr().unwrap(),
            false,
        ));
        let backend = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap();
            let io = TlsAcceptor::from(Arc::new(upstream_tls))
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(io.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(io),
                    service_fn(|request: Request<Incoming>| async move {
                        assert_eq!(request.version(), http::Version::HTTP_11);
                        assert_eq!(request.uri().path(), "/h2-to-h1");
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"upstream",
                        ))))
                    }),
                )
                .await
                .unwrap();
        });
        timeout(Duration::from_secs(5), async {
            let (mut tx, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                    .await
                    .unwrap();
            let connection = tokio::spawn(conn);
            let response = tx
                .send_request(
                    Request::get("http://relay.test/h2-to-h1")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "upstream"
            );
            connection.abort();
        })
        .await
        .unwrap();
        relay.abort();
        backend.abort();
    }

    #[tokio::test]
    async fn h2c_relay_preserves_grpc_streaming_and_trailers() {
        grpc_exchange(false).await;
    }

    #[tokio::test]
    async fn grpc_preserves_streaming_and_trailers_after_a_proxy_v2_header() {
        grpc_exchange(true).await;
    }

    async fn grpc_exchange(with_proxy: bool) {
        use futures_util::stream;
        use hyper::{client::conn::http2, server::conn::http2 as h2_server};
        use tokio::{net::TcpStream, sync::oneshot};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = frontend.local_addr().unwrap();
        let config = crate::caddyfile::parse(&format!(
            "http://grpc.test {{\n handle /test.Service/* {{\n reverse_proxy h2c://{} {}\n }}\n handle {{\n respond 404\n }}\n}}",
            upstream.local_addr().unwrap(),
            if with_proxy { "{ proxy_protocol v2 }" } else { "" },
        ))
        .unwrap();
        let server = Arc::new(Server::new(config).unwrap());
        let (continue_upload, upload) = oneshot::channel();
        let initial_message = Bytes::from_static(b"\0\0\0\0\x01a");
        let final_message = Bytes::from_static(b"\0\0\0\0\x01b");
        let (upload_a, upload_b) = (initial_message.clone(), final_message.clone());
        let (upstream_a, upstream_b) = (initial_message.clone(), final_message.clone());

        let (stream, peer) = tokio::join!(TcpStream::connect(addr), frontend.accept());
        let (relay, peer) = peer.unwrap();
        let addresses = Addresses {
            source: peer,
            destination: addr,
        };
        let relay_task = tokio::spawn(serve_connection_with_drain(
            relay,
            server,
            peer,
            false,
            crate::runtime::Connections {
                addresses: Some(addresses),
                ..Default::default()
            },
        ));
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            if with_proxy {
                assert_eq!(
                    proxy_protocol::read(&mut stream).await.unwrap(),
                    Some(addresses)
                );
            }
            let service = service_fn(move |request: Request<Incoming>| {
                let (upstream_a, upstream_b) = (upstream_a.clone(), upstream_b.clone());
                async move {
                    assert_eq!(request.version(), http::Version::HTTP_2);
                    assert_eq!(
                        request.uri().path_and_query().unwrap().as_str(),
                        "/test.Service/Tunnel?q=1"
                    );
                    assert_eq!(request.headers()[header::TE], "trailers");
                    assert_eq!(request.headers()[HOST], "grpc.test");
                    let frames =
                        stream::unfold((request.into_body(), 0), move |(mut body, step)| {
                            let (a, b) = (upstream_a.clone(), upstream_b.clone());
                            async move {
                                let frame = match step {
                                    0 | 1 => {
                                        let data = body
                                            .frame()
                                            .await
                                            .unwrap()
                                            .unwrap()
                                            .into_data()
                                            .unwrap();
                                        assert_eq!(data, if step == 0 { a } else { b });
                                        Frame::data(data)
                                    }
                                    2 => {
                                        while let Some(frame) = body.frame().await {
                                            assert!(frame.unwrap().into_data().unwrap().is_empty());
                                        }
                                        let mut trailers = HeaderMap::new();
                                        trailers
                                            .insert("grpc-status", HeaderValue::from_static("0"));
                                        Frame::trailers(trailers)
                                    }
                                    _ => return None,
                                };
                                Some((Ok::<_, Infallible>(frame), (body, step + 1)))
                            }
                        });
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header(header::CONTENT_TYPE, "application/grpc")
                            .body(StreamBody::new(frames))
                            .unwrap(),
                    )
                }
            });
            h2_server::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
        });
        let (mut client, conn) =
            http2::handshake(TokioExecutor::new(), TokioIo::new(stream.unwrap()))
                .await
                .unwrap();
        let client_task = tokio::spawn(conn);
        timeout(Duration::from_secs(5), async {
            let frames = stream::iter([Ok::<_, Infallible>(Frame::data(upload_a))]).chain(
                stream::once(async move {
                    upload.await.unwrap();
                    Ok(Frame::data(upload_b))
                }),
            );
            let request = Request::post("https://grpc.test/test.Service/Tunnel?q=1")
                .version(http::Version::HTTP_2)
                .header(header::CONTENT_TYPE, "application/grpc")
                .header(header::TE, "trailers")
                .body(StreamBody::new(frames.boxed()))
                .unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/grpc");
            let mut body = response.into_body();
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                initial_message
            );
            continue_upload.send(()).unwrap();
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                final_message
            );
            let trailers = body
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap();
            assert_eq!(trailers["grpc-status"], "0");
            assert!(body.frame().await.is_none());
        })
        .await
        .unwrap();
        client_task.abort();
        relay_task.abort();
        upstream_task.abort();
    }

    async fn read_header(stream: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt;

        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 8192);
            bytes.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap().to_ascii_lowercase()
    }

    async fn websocket_exchange(accept: &'static str, expected: &'static str, with_proxy: bool) {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpStream,
        };

        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = frontend.local_addr().unwrap();
        let config = crate::caddyfile::parse(&format!(
            "http://ws.test {{\n handle_path /socket/* {{\n reverse_proxy {} {}\n }}\n handle {{\n respond 404\n }}\n}}",
            upstream.local_addr().unwrap(),
            if with_proxy { "{ proxy_protocol v1 }" } else { "" },
        ))
        .unwrap();
        let server = Arc::new(Server::new(config).unwrap());
        timeout(Duration::from_secs(5), async {
            let backend = async {
                let (mut stream, _) = upstream.accept().await.unwrap();
                if with_proxy {
                    let addresses = proxy_protocol::read(&mut stream).await.unwrap().unwrap();
                    assert_eq!(addresses.destination, address);
                }
                let request = read_header(&mut stream).await;
                assert!(request.starts_with("get /ws?mode=test http/1.1\r\n"));
                assert!(request.contains("\r\nconnection: upgrade\r\n"));
                assert!(request.contains("\r\nupgrade: websocket\r\n"));
                assert!(request.contains("\r\nhost: ws.test\r\n"));
                assert!(!request.contains("\r\nx-hop:"));
                let early_frame = [0x82, 0x02, b'o', b'k'];
                let mut reply = format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").into_bytes();
                reply.extend_from_slice(&early_frame);
                stream.write_all(&reply).await.unwrap();
                if expected == "101" {
                    let mut masked_frame = [0; 8];
                    stream.read_exact(&mut masked_frame).await.unwrap();
                    assert_eq!(masked_frame, [0x82, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]);
                    stream.write_all(&[0x82, 0x02, b'h', b'i']).await.unwrap();
                }
            };
            let relay = async {
                let (stream, peer) = frontend.accept().await.unwrap();
                let addresses = Addresses { source: peer, destination: address };
                serve_connection_with_drain(stream, server, peer, false, crate::runtime::Connections {addresses: Some(addresses), ..Default::default()}).await.unwrap();
            };
            let client = async {
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(b"GET /socket/ws?mode=test HTTP/1.1\r\nHost: ws.test\r\nConnection: keep-alive, UpGrAdE, X-Hop\r\nUpgrade: websocket\r\nX-Hop: strip-me\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").await.unwrap();
                let response = read_header(&mut stream).await;
                assert!(response.starts_with(&format!("http/1.1 {expected} ")), "{response}");
                if expected == "101" {
                    assert!(response.contains("\r\nupgrade: websocket\r\n"));
                    let mut frame = [0; 4];
                    stream.read_exact(&mut frame).await.unwrap();
                    assert_eq!(frame, [0x82, 0x02, b'o', b'k']);
                    stream.write_all(&[0x82, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]).await.unwrap();
                    stream.read_exact(&mut frame).await.unwrap();
                    assert_eq!(frame, [0x82, 0x02, b'h', b'i']);
                }
            };
            tokio::join!(backend, relay, client);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn websocket_upgrade_relays_frames_in_both_directions() {
        websocket_exchange("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "101", false).await;
    }

    #[tokio::test]
    async fn websocket_relays_frames_after_a_proxy_v1_header() {
        websocket_exchange("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "101", true).await;
    }

    #[tokio::test]
    async fn invalid_upstream_websocket_accept_does_not_upgrade() {
        websocket_exchange("invalid-accept", "502", false).await;
    }

    #[test]
    fn proxy_keeps_the_original_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("www.example.com"));
        let http = Upstream::new("http://127.0.0.1:9000").unwrap();
        let uri = Uri::from_static("/");
        prepare_proxy_headers(&mut headers, &uri, None, false).unwrap();
        http.apply_host(&mut headers);
        assert_eq!(headers[HOST], "www.example.com");
        assert_eq!(headers[X_FORWARDED_HOST], "www.example.com");
        assert_eq!(headers["x-forwarded-proto"], "http");

        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_HOST, HeaderValue::from_static("untrusted"));
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("203.0.113.7"));
        prepare_proxy_headers(&mut headers, &uri, None, true).unwrap();
        http.apply_host(&mut headers);
        assert!(!headers.contains_key(X_FORWARDED_HOST));
        assert!(!headers.contains_key(X_FORWARDED_FOR));
        assert_eq!(headers[HOST], "127.0.0.1:9000");
        assert_eq!(headers["x-forwarded-proto"], "https");
    }

    #[test]
    fn proxy_replaces_untrusted_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        headers.append(X_FORWARDED_FOR, HeaderValue::from_static("other"));
        let peer = Peer::new("198.51.100.4:1234".parse().unwrap()).unwrap();
        prepare_proxy_headers(&mut headers, &Uri::from_static("/"), Some(&peer), false).unwrap();
        assert_eq!(
            single_header(&headers, X_FORWARDED_FOR),
            Some("198.51.100.4")
        );
    }

    #[test]
    fn proxy_prepares_headers_before_applying_per_upstream_host() {
        let uri = Uri::from_static("http://public.example:8080/test");
        let peer = Peer::new("[2001:db8::1]:4321".parse().unwrap()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("client.example"));
        headers.insert(CONNECTION, HeaderValue::from_static("x-drop, Close"));
        headers.append(CONNECTION, HeaderValue::from_static("Connection, tE"));
        headers.append(
            CONNECTION,
            HeaderValue::from_bytes(b"\xff, x-keep").unwrap(),
        );
        headers.insert(header::TE, HeaderValue::from_static("Trailers"));
        for name in ["close", "x-drop", "x-keep"] {
            headers.insert(name, HeaderValue::from_static("1"));
        }
        assert!(!prepare_proxy_headers(&mut headers, &uri, Some(&peer), false).unwrap());
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key(header::TE));
        assert!(!headers.contains_key("x-drop"));
        assert!(!headers.contains_key("close"));
        assert_eq!(headers["x-keep"], "1");
        assert_eq!(headers[X_FORWARDED_FOR], "2001:db8::1");
        assert_eq!(headers[X_FORWARDED_HOST], "public.example:8080");
        let http = Upstream::new("http://origin.example").unwrap();
        http.apply_host(&mut headers);
        assert_eq!(headers[HOST], "client.example");
        Upstream::new("https://other.example:8443")
            .unwrap()
            .apply_host(&mut headers);
        assert_eq!(headers[HOST], "other.example:8443");
        assert_eq!(headers[X_FORWARDED_HOST], "public.example:8080");

        headers.insert(
            CONNECTION,
            HeaderValue::from_static("HOST, x-forwarded-proto"),
        );
        headers.insert(header::TE, HeaderValue::from_static("deflate, Trailers"));
        assert!(prepare_proxy_headers(&mut headers, &uri, None, true).unwrap());
        assert_eq!(headers[HOST], "public.example:8080");
        assert_eq!(headers[X_FORWARDED_PROTO], "https");
        assert!(!headers.contains_key(header::TE));
    }

    #[test]
    fn proxy_cached_response_headers_preserve_replacement_order() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = site("*");
        config
            .response_headers
            .insert("X-Site".into(), "first".into());
        config
            .response_headers
            .insert("x-site".into(), "last".into());
        let server = Server::new(Config {
            sites: vec![config],
            ..Config::default()
        })
        .unwrap();
        let site = &server.sites[0];
        let mut headers = HeaderMap::new();
        headers.append("x-site", HeaderValue::from_static("one"));
        headers.append("x-site", HeaderValue::from_static("two"));
        let mut expected = headers.clone();
        add_configured_headers(&mut expected, &site.config);
        site.apply_proxy_response_headers(&mut headers);
        assert_eq!(headers, expected);
        assert_eq!(headers["x-site"], "last");
    }

    #[test]
    fn selects_exact_then_single_label_wildcard_then_catchall() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = Server::new(Config {
            sites: vec![site("*"), site("*.example.com"), site("APP.example.com")],
            ..Config::default()
        })
        .unwrap();
        assert_eq!(
            server.site("app.example.com", false).unwrap().config.hosts,
            ["APP.example.com"]
        );
        assert_eq!(
            server
                .site("other.example.com", false)
                .unwrap()
                .config
                .hosts,
            ["*.example.com"]
        );
        assert_eq!(
            server
                .site("multi.other.example.com", false)
                .unwrap()
                .config
                .hosts,
            ["*"]
        );
        assert!(server.site("app.example.com", true).is_none());
    }

    #[test]
    fn host_matching_does_not_cross_label_boundaries() {
        assert!(site("*.example.com").matches_host("www.example.com"));
        assert!(site("example.com").matches_host("example.com"));
        assert!(!site("*.example.com").matches_host("example.com"));
        assert!(!site("*.example.com").matches_host("notexample.com"));
    }

    #[test]
    fn host_matching_ignores_case_in_patterns_and_requests() {
        assert!(site("*.EXAMPLE.com").matches_host("www.example.com"));
        assert!(site("*.example.com").matches_host("WWW.EXAMPLE.COM"));
        assert!(site("EXAMPLE.com").matches_host("example.com"));
        assert!(site("example.com").matches_host("Example.Com"));
        assert!(site("*.example.com").matches_host("www.example.com."));
    }

    #[test]
    fn request_hosts_remove_ports_and_trailing_dots() {
        let request = Request::builder()
            .uri("/")
            .header(HOST, "www.example.com:8443")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(
            request_host_parts(&request),
            Some("www.example.com".to_owned())
        );
        let request = Request::builder()
            .uri("/")
            .header(HOST, "WWW.example.com.")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(
            request_host_parts(&request),
            Some("www.example.com".to_owned())
        );
    }

    #[test]
    fn hop_headers_and_nominated_headers_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-remove-me"),
        );
        headers.insert("x-remove-me", HeaderValue::from_static("private"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=30"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("x-keep", HeaderValue::from_static("yes"));
        strip_hop_by_hop_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-keep"], "yes");
    }

    #[test]
    fn static_paths_reject_traversal_and_null_bytes() {
        for path in ["/../secret", "/a/../../secret", "/a%2f..%2fsecret", "/%00"] {
            assert_eq!(safe_relative_path(path), None);
        }
        assert_eq!(safe_relative_path("/"), Some(std::path::PathBuf::new()));
        assert_eq!(
            safe_relative_path("/a.txt"),
            Some(std::path::PathBuf::from("a.txt"))
        );
    }
}
