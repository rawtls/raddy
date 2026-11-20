use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::cloudflare::CloudflareConfig;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(skip)]
    pub(crate) source_files: Vec<PathBuf>,
    #[serde(default = "default_http_addr")]
    pub http_addr: SocketAddr,
    #[serde(default = "default_https_addr")]
    pub https_addr: SocketAddr,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default = "default_acme_ca")]
    pub acme_ca: String,
    #[serde(default)]
    pub cloudflare: CloudflareSettings,
    #[serde(default = "default_true")]
    pub redirect_http: bool,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,
    #[serde(default)]
    pub max_connections: usize,
    #[serde(default = "default_static_cache_entries")]
    pub static_cache_entries: usize,
    #[serde(default = "default_static_cache_ttl")]
    pub static_cache_ttl_secs: u64,
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
    #[serde(default)]
    pub streams: Vec<StreamConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proxy_protocol_accept: BTreeMap<u16, Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamMode {
    #[default]
    Tcp,
    TlsPassthrough,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StreamConfig {
    pub listen: SocketAddr,
    #[serde(rename = "type", default)]
    pub mode: StreamMode,
    pub routes: Vec<StreamRouteConfig>,
    #[serde(default = "default_stream_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_stream_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_stream_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_stream_handshake_limit")]
    pub max_handshake_bytes: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StreamRouteConfig {
    #[serde(default)]
    pub sni: Option<String>,
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub proxy_protocol: Option<crate::proxy_protocol::Version>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CloudflareSettings {
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub zone_token: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default = "default_cloudflare_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cloudflare_retries")]
    pub retries: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SiteConfig {
    pub hosts: Vec<String>,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub certificate_file: Option<PathBuf>,
    #[serde(default)]
    pub private_key_file: Option<PathBuf>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub proxy: ProxySettings,
    #[serde(default)]
    pub root: Option<PathBuf>,
    #[serde(default)]
    pub index: Vec<String>,
    #[serde(default)]
    pub response_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub responses: Vec<RespondConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<crate::routes::HttpRoute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_routes: Vec<crate::routes::ErrorRoute>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxySettings {
    pub lb_policy: ProxyPolicy,
    pub lb_retries: usize,
    pub health_uri: Option<String>,
    pub health_interval_secs: Option<u64>,
    pub health_timeout_secs: Option<u64>,
    pub header_up: Vec<ProxyHeader>,
    pub header_down: Vec<ProxyHeader>,
    pub proxy_protocol: Option<crate::proxy_protocol::Version>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyPolicy {
    #[default]
    RoundRobin,
    First,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyHeader {
    pub name: String,
    pub value: Option<String>,
}

impl ProxySettings {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(path) = &self.health_uri {
            if !path.starts_with('/')
                || path.contains('#')
                || path.parse::<http::uri::PathAndQuery>().is_err()
            {
                bail!("health_uri must be an origin path with an optional query");
            }
        } else if self.health_interval_secs.is_some() || self.health_timeout_secs.is_some() {
            bail!("health_interval and health_timeout require health_uri");
        }
        if self.health_interval_secs == Some(0) || self.health_timeout_secs == Some(0) {
            bail!("health_interval and health_timeout must be positive");
        }
        for (headers, upstream) in [(&self.header_up, true), (&self.header_down, false)] {
            for header in headers {
                header.validate(upstream)?;
            }
        }
        Ok(())
    }
}

impl ProxyHeader {
    pub(crate) fn validate(&self, upstream: bool) -> Result<()> {
        let name = self.name.strip_prefix(['+', '-']).unwrap_or(&self.name);
        let name =
            http::HeaderName::from_bytes(name.as_bytes()).context("invalid proxy header name")?;
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "upgrade"
                | "transfer-encoding"
                | "content-length"
                | "trailer"
                | "te"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "sec-websocket-accept"
        ) || upstream && name == http::header::HOST && self.name.starts_with(['+', '-'])
        {
            bail!("cannot mutate protocol-managed header {name}");
        }
        match (&self.value, self.name.starts_with('-')) {
            (None, true) => {}
            (Some(value), false) => {
                http::HeaderValue::from_str(value).context("invalid proxy header value")?;
            }
            _ => bail!("proxy header requires a value for set/append and no value for deletion"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RespondConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_response_status")]
    pub status: u16,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub implicit_status: bool,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub close: bool,
}

fn default_response_status() -> u16 {
    200
}

impl RespondConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if !(200..=599).contains(&self.status) {
            bail!("respond status must be a final HTTP status in 200..=599");
        }
        if let Some(path) = &self.path {
            crate::routes::validate_match_path(path)?;
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_addr: default_http_addr(),
            https_addr: default_https_addr(),
            data_dir: default_data_dir(),
            email: None,
            acme_ca: default_acme_ca(),
            cloudflare: CloudflareSettings {
                timeout_secs: default_cloudflare_timeout(),
                retries: default_cloudflare_retries(),
                ..CloudflareSettings::default()
            },
            redirect_http: true,
            request_timeout_secs: default_request_timeout(),
            max_header_size: default_max_header_size(),
            max_connections: 0,
            static_cache_entries: default_static_cache_entries(),
            static_cache_ttl_secs: default_static_cache_ttl(),
            sites: Vec::new(),
            streams: Vec::new(),
            proxy_protocol_accept: BTreeMap::new(),
            source_files: Vec::new(),
        }
    }
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self> {
        if path.extension().is_none_or(|extension| extension != "json") {
            let source = path.to_owned();
            return tokio::task::spawn_blocking(move || crate::caddyfile::parse_file(&source))
                .await?
                .with_context(|| format!("invalid Caddyfile configuration in {}", path.display()));
        }
        let text = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read configuration {}", path.display()))?;
        let expanded = expand_env_placeholders(&text)?;
        let mut config: Self = serde_json::from_str(&expanded)
            .with_context(|| format!("invalid JSON configuration in {}", path.display()))?;
        config
            .source_files
            .push(tokio::fs::canonicalize(path).await?);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.sites.is_empty() && self.streams.is_empty() {
            bail!("configuration must contain at least one site or stream");
        }
        self.validate_listener_ports()?;
        self.proxy_protocol_networks()?;
        if self.request_timeout_secs == 0 {
            bail!("request_timeout_secs must be greater than zero");
        }
        if self.max_header_size < 8192 {
            bail!("max_header_size must be at least 8192 bytes");
        }
        if self.sites.iter().any(|site| site.tls) && self.https_addr.port() == 0 {
            bail!("https_addr must use a fixed port when TLS is enabled");
        }
        for (index, site) in self.sites.iter().enumerate() {
            if site.hosts.is_empty() {
                bail!("sites[{index}].hosts must not be empty");
            }
            if !site.upstreams.is_empty() && site.root.is_some() {
                bail!("sites[{index}] cannot configure both upstreams and root");
            }
            site.proxy
                .validate()
                .with_context(|| format!("invalid sites[{index}].proxy"))?;
            for (route, response) in site.responses.iter().enumerate() {
                response
                    .validate()
                    .with_context(|| format!("invalid sites[{index}].responses[{route}]"))?;
            }
            if site.certificate_file.is_some() != site.private_key_file.is_some() {
                bail!("sites[{index}] must set both certificate_file and private_key_file");
            }
            if site.tls && site.certificate_file.is_none() {
                self.cloudflare_config()?.validate()?;
            }
            for host in &site.hosts {
                if host.is_empty()
                    || host.contains('/')
                    || host.contains("://")
                    || host.chars().any(char::is_whitespace)
                {
                    bail!("invalid host name {host:?} in sites[{index}]");
                }
                if host == "*" && site.tls {
                    bail!(
                        "a wildcard-only host cannot receive an ACME certificate; list concrete names"
                    );
                }
            }
            validate_http_upstreams(&site.upstreams)?;
            if (!site.routes.is_empty() || !site.error_routes.is_empty())
                && (!site.responses.is_empty() || !site.upstreams.is_empty() || site.root.is_some())
            {
                bail!("sites[{index}].routes cannot be combined with legacy site handlers");
            }
            crate::routes::validate_routes(&site.routes, 0)
                .with_context(|| format!("invalid sites[{index}].routes"))?;
            for route in &site.error_routes {
                route
                    .validate()
                    .with_context(|| format!("invalid sites[{index}].error_routes"))?;
            }
        }
        for (index, stream) in self.streams.iter().enumerate() {
            if stream.listen.port() == 0 {
                bail!("streams[{index}].listen must use a fixed port in 1..65535");
            }
            if stream.connect_timeout_secs == 0
                || stream.idle_timeout_secs == 0
                || stream.handshake_timeout_secs == 0
                || !(5..=16384).contains(&stream.max_handshake_bytes)
            {
                bail!(
                    "streams[{index}] timeouts must be positive and max_handshake_bytes must be 5..16384"
                );
            }
            if stream.routes.is_empty() {
                bail!("streams[{index}].routes must not be empty");
            }
            if stream.mode == StreamMode::Tcp && stream.routes.len() != 1 {
                bail!("TCP streams[{index}] must have exactly one default route");
            }
            let mut sni_names = BTreeMap::new();
            for route in &stream.routes {
                if route.upstreams.is_empty() {
                    bail!("streams[{index}] route requires at least one upstream");
                }
                match (&stream.mode, route.sni.as_deref()) {
                    (StreamMode::Tcp, None | Some("*")) => {}
                    (StreamMode::Tcp, Some(_)) => bail!("TCP route cannot use SNI"),
                    (StreamMode::TlsPassthrough, None) => {
                        bail!("TLS passthrough route requires sni; use \"*\" for fallback")
                    }
                    (StreamMode::TlsPassthrough, Some(name)) => {
                        validate_sni_pattern(name)?;
                        let normalized = name.trim_end_matches('.').to_ascii_lowercase();
                        if sni_names.insert(normalized.clone(), ()).is_some() {
                            bail!("duplicate SNI route {normalized}");
                        }
                    }
                }
                for upstream in &route.upstreams {
                    validate_tcp_upstream(upstream)?;
                }
            }
        }
        Ok(())
    }

    fn validate_listener_ports(&self) -> Result<()> {
        let https = self.sites.iter().any(|site| site.tls);
        if https && self.http_addr.port() == self.https_addr.port() {
            bail!(
                "HTTP and HTTPS listeners cannot share TCP port {}",
                self.https_addr.port()
            );
        }
        let mut streams: BTreeMap<u16, (SocketAddr, bool, bool)> = BTreeMap::new();
        let mut https_names = std::collections::BTreeSet::new();
        if https {
            for host in self
                .sites
                .iter()
                .filter(|site| site.tls)
                .flat_map(|site| &site.hosts)
            {
                https_names.insert(host.trim_end_matches('.').to_ascii_lowercase());
            }
        }
        for (index, stream) in self.streams.iter().enumerate() {
            let port = stream.listen.port();
            if !self.sites.is_empty() && port == self.http_addr.port() {
                bail!(
                    "streams[{index}] conflicts with the HTTP listener on TCP port {port}; use a separate stream port"
                );
            }
            if https && port == self.https_addr.port() {
                if stream.listen != self.https_addr {
                    bail!(
                        "streams[{index}] and HTTPS must use the same bind address to share TCP port {port}: {} != {}",
                        stream.listen.ip(),
                        self.https_addr.ip()
                    );
                }
                if stream.mode == StreamMode::TlsPassthrough {
                    for route in &stream.routes {
                        if let Some(name) = &route.sni
                            && https_names
                                .contains(&name.trim_end_matches('.').to_ascii_lowercase())
                        {
                            bail!(
                                "duplicate SNI pattern {name:?} between TLS passthrough and HTTPS on TCP port {port}"
                            );
                        }
                    }
                }
            }
            let (address, tcp, tls) = streams.entry(port).or_insert((stream.listen, false, false));
            if stream.listen != *address {
                bail!(
                    "stream blocks must use the same bind address to share TCP port {port}: {} != {}",
                    stream.listen.ip(),
                    address.ip()
                );
            }
            let used = match stream.mode {
                StreamMode::Tcp => tcp,
                StreamMode::TlsPassthrough => tls,
            };
            if std::mem::replace(used, true) {
                bail!(
                    "streams[{index}] conflicts with another stream listener of the same mode on TCP port {port}"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn proxy_protocol_networks(&self) -> Result<BTreeMap<u16, Vec<ipnet::IpNet>>> {
        self.proxy_protocol_accept
            .iter()
            .map(|(&port, sources)| {
                if port == 0 || sources.is_empty() {
                    bail!(
                        "proxy_protocol_accept requires a fixed port and trusted source addresses"
                    );
                }
                let has_listener = !self.sites.is_empty() && self.http_addr.port() == port
                    || self.sites.iter().any(|site| site.tls) && self.https_addr.port() == port
                    || self
                        .streams
                        .iter()
                        .any(|stream| stream.listen.port() == port);
                if !has_listener {
                    bail!("proxy_protocol_accept port {port} has no listener");
                }
                let networks = sources
                    .iter()
                    .map(|source| {
                        let network = source
                            .parse::<ipnet::IpNet>()
                            .or_else(|_| source.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                            .with_context(|| {
                                format!("invalid PROXY protocol trusted source {source:?}")
                            })?;
                        if network.prefix_len() == 0 {
                            bail!("proxy_protocol_accept cannot trust all addresses");
                        }
                        Ok(network)
                    })
                    .collect::<Result<_>>()?;
                Ok((port, networks))
            })
            .collect()
    }

    pub fn cloudflare_config(&self) -> Result<CloudflareConfig> {
        let mut config = CloudflareConfig::new(self.cloudflare.api_token.clone());
        config.zone_token = self.cloudflare.zone_token.clone();
        if let Some(base) = &self.cloudflare.api_base {
            config.api_base = base.clone();
        }
        config.timeout = Duration::from_secs(self.cloudflare.timeout_secs.max(1));
        config.retries = self.cloudflare.retries;
        Ok(config)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}

pub(crate) fn validate_http_upstreams(upstreams: &[String]) -> Result<()> {
    for upstream in upstreams {
        let url =
            url::Url::parse(upstream).with_context(|| format!("invalid upstream {upstream:?}"))?;
        if !matches!(url.scheme(), "http" | "https" | "h2c") || url.host_str().is_none() {
            bail!("upstream must be an absolute http://, https:// or h2c:// URL: {upstream}");
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("upstream must be an origin URL without credentials, query or fragment");
        }
        if !url.path().is_empty() && url.path() != "/" {
            bail!(
                "upstream paths are not supported; use an origin URL such as http://127.0.0.1:9000"
            );
        }
    }
    Ok(())
}

impl SiteConfig {
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        self.hosts.iter().any(|pattern| {
            let pattern = pattern.trim_end_matches('.');
            pattern == "*"
                || pattern.eq_ignore_ascii_case(host)
                || pattern.strip_prefix("*.").is_some_and(|suffix| {
                    host.split_once('.').is_some_and(|(label, rest)| {
                        !label.is_empty() && rest.eq_ignore_ascii_case(suffix)
                    })
                })
        })
    }

    pub fn index_files(&self) -> Vec<&str> {
        if self.index.is_empty() {
            vec!["index.html", "index.htm"]
        } else {
            self.index.iter().map(String::as_str).collect()
        }
    }
}

fn validate_sni_pattern(pattern: &str) -> Result<()> {
    let name = pattern.trim_end_matches('.').to_ascii_lowercase();
    if name == "*" {
        return Ok(());
    }
    let domain = name.strip_prefix("*.").unwrap_or(&name);
    if name.is_empty()
        || domain.split('.').any(|label| {
            label.is_empty()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
        || name != "*" && name.contains('*') && !name.starts_with("*.")
    {
        bail!("invalid SNI pattern {pattern:?}");
    }
    Ok(())
}

fn validate_tcp_upstream(upstream: &str) -> Result<()> {
    if upstream.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    let (host, port) = upstream
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid TCP upstream {upstream:?}; expected host:port"))?;
    if host.is_empty()
        || host.contains('/')
        || host.contains('@')
        || host.contains(':') && !(host.starts_with('[') && host.ends_with(']'))
    {
        bail!("invalid TCP upstream {upstream:?}; expected host:port");
    }
    if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
        bail!("invalid TCP upstream {upstream:?}; port must be 1..65535");
    }
    if host.starts_with('[') && !host.ends_with(']') {
        bail!("invalid TCP upstream {upstream:?}; malformed IPv6 address");
    }
    Ok(())
}

pub(crate) fn expand_env_placeholders(input: &str) -> Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{env.") {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 5..];
        let Some(end) = after_start.find('}') else {
            bail!("unterminated environment placeholder");
        };
        let name = &after_start[..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("invalid environment variable name {name:?}");
        }
        let value =
            env::var(name).with_context(|| format!("environment variable {name} is not set"))?;
        output.push_str(&value);
        rest = &after_start[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn default_http_addr() -> SocketAddr {
    "0.0.0.0:80".parse().expect("valid default address")
}
fn default_https_addr() -> SocketAddr {
    "0.0.0.0:443".parse().expect("valid default address")
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("./raddy-data")
}
fn default_acme_ca() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_owned()
}
fn default_true() -> bool {
    true
}
fn default_request_timeout() -> u64 {
    60
}
fn default_max_header_size() -> usize {
    64 * 1024
}
fn default_static_cache_entries() -> usize {
    1024
}
fn default_static_cache_ttl() -> u64 {
    30
}
fn default_stream_connect_timeout() -> u64 {
    10
}
fn default_stream_idle_timeout() -> u64 {
    300
}
fn default_stream_handshake_timeout() -> u64 {
    10
}
fn default_stream_handshake_limit() -> usize {
    16384
}
fn default_cloudflare_timeout() -> u64 {
    30
}
fn default_cloudflare_retries() -> usize {
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(port: u16) -> StreamConfig {
        StreamConfig {
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            mode: StreamMode::Tcp,
            routes: vec![StreamRouteConfig {
                sni: None,
                upstreams: vec!["127.0.0.1:9000".to_owned()],
                proxy_protocol: None,
            }],
            connect_timeout_secs: 10,
            idle_timeout_secs: 300,
            handshake_timeout_secs: 10,
            max_handshake_bytes: 16384,
        }
    }

    fn site(_port: u16, tls: bool) -> SiteConfig {
        SiteConfig {
            hosts: vec!["example.com".to_owned()],
            tls,
            ..SiteConfig::default()
        }
    }

    #[test]
    fn http_and_https_cannot_share_one_port() {
        let addr = "127.0.0.1:8443".parse().unwrap();
        let config = Config {
            http_addr: addr,
            https_addr: addr,
            sites: vec![site(8443, true)],
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("HTTP and HTTPS listeners cannot share"),
            "{error}"
        );
    }

    #[test]
    fn a_stream_cannot_use_the_http_listener_port() {
        let config = Config {
            http_addr: "127.0.0.1:8080".parse().unwrap(),
            sites: vec![site(8080, false)],
            streams: vec![stream(8080)],
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("conflicts with the HTTP listener"),
            "{error}"
        );
    }

    #[test]
    fn tcp_and_https_share_the_same_bind_address() {
        let config = Config {
            https_addr: "127.0.0.1:8443".parse().unwrap(),
            sites: vec![SiteConfig {
                certificate_file: Some("cert.pem".into()),
                private_key_file: Some("key.pem".into()),
                ..site(8443, true)
            }],
            streams: vec![stream(8443)],
            ..Config::default()
        };
        config.validate().unwrap();
        let mut config = config;
        config.streams[0].listen.set_ip("0.0.0.0".parse().unwrap());
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("must use the same bind address")
        );
    }

    #[test]
    fn two_streams_cannot_share_one_port() {
        let config = Config {
            streams: vec![stream(9000), stream(9000)],
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("conflicts with another stream listener"),
            "{error}"
        );
    }

    #[test]
    fn a_tls_passthrough_may_use_the_https_port_without_termination() {
        let config = Config {
            https_addr: "127.0.0.1:8443".parse().unwrap(),
            sites: vec![site(8443, false)],
            streams: vec![StreamConfig {
                mode: StreamMode::TlsPassthrough,
                routes: vec![StreamRouteConfig {
                    sni: Some("example.com".to_owned()),
                    upstreams: vec!["127.0.0.1:9000".to_owned()],
                    proxy_protocol: None,
                }],
                ..stream(8443)
            }],
            ..Config::default()
        };
        config.validate().unwrap();
    }
}
