use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Result, anyhow};
use http::{HeaderName, HeaderValue};

use crate::config::{
    CloudflareSettings, Config, ProxyHeader, ProxyPolicy, RespondConfig, SiteConfig, StreamConfig,
    StreamMode, StreamRouteConfig,
};

use crate::routes::{
    ErrorRoute, HttpAction, HttpRoute, RegexpMatcher, RequestMatcher, ResponseCondition,
    ResponseHeader, TryFilesPolicy, validate_match_path,
};

use super::{
    directives::{self, Directive},
    lexer::Token,
};

struct Builder {
    config: Config,
    stream_settings: BTreeMap<SocketAddr, StreamSettings>,
    automatic_https: bool,
    default_bind: IpAddr,
    http_bind: Option<IpAddr>,
    https_bind: Option<IpAddr>,
    global_http_bind: Option<IpAddr>,
    global_https_bind: Option<IpAddr>,
    default_http_port: u16,
    default_https_port: u16,
    http_port_explicit: bool,
    https_port_explicit: bool,
    connect_timeout_secs: u64,
    idle_timeout_secs: u64,
    handshake_timeout_secs: u64,
    max_handshake_bytes: usize,
}

impl Builder {
    fn new() -> Self {
        Self {
            config: Config::default(),
            stream_settings: BTreeMap::new(),
            automatic_https: true,
            default_bind: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            http_bind: None,
            https_bind: None,
            global_http_bind: None,
            global_https_bind: None,
            default_http_port: 80,
            default_https_port: 443,
            http_port_explicit: false,
            https_port_explicit: false,
            connect_timeout_secs: 10,
            idle_timeout_secs: 300,
            handshake_timeout_secs: 10,
            max_handshake_bytes: 16384,
        }
    }

    fn global(&mut self, directive: &Directive) -> Result<()> {
        let args = strings(&directive.args);
        match directive.name.text.as_str() {
            "email" => {
                no_children(directive)?;
                one_arg(directive)?;
                self.config.email = Some(args[0].to_owned());
            }
            "acme_ca" => {
                no_children(directive)?;
                one_arg(directive)?;
                self.config.acme_ca = args[0].to_owned();
            }
            "data_dir" => {
                no_children(directive)?;
                one_arg(directive)?;
                self.config.data_dir = PathBuf::from(args[0]);
            }
            "default_bind" => {
                no_children(directive)?;
                one_arg(directive)?;
                let ip = parse_ip(args[0], &directive.args[0])?;
                self.default_bind = ip;
                if self.global_http_bind.is_none() {
                    self.config.http_addr.set_ip(ip);
                }
                if self.global_https_bind.is_none() {
                    self.config.https_addr.set_ip(ip);
                }
            }
            "http_port" | "https_port" => {
                no_children(directive)?;
                one_arg(directive)?;
                let port = parse_port(args[0], &directive.args[0])?;
                let https = directive.name.text == "https_port";
                if https {
                    self.default_https_port = port;
                    self.config.https_addr.set_port(port);
                } else {
                    self.default_http_port = port;
                    self.config.http_addr.set_port(port);
                }
            }
            "http_addr" | "https_addr" => {
                no_children(directive)?;
                one_arg(directive)?;
                let address = parse_listen(args[0], &directive.args[0])?;
                let https = directive.name.text == "https_addr";
                self.set_port(address.port(), https, &directive.args[0])?;
                if https {
                    self.default_https_port = address.port();
                } else {
                    self.default_http_port = address.port();
                }
                let target = if https {
                    &mut self.config.https_addr
                } else {
                    &mut self.config.http_addr
                };
                target.set_ip(address.ip());
                let bind = if https {
                    &mut self.global_https_bind
                } else {
                    &mut self.global_http_bind
                };
                *bind = Some(address.ip());
            }
            "auto_https" => {
                no_children(directive)?;
                one_arg(directive)?;
                match args[0] {
                    "off" => self.automatic_https = false,
                    "disable_redirects" => self.config.redirect_http = false,
                    option => {
                        return Err(at(
                            &directive.args[0],
                            format!("unsupported auto_https option {option:?}"),
                        ));
                    }
                }
            }
            "proxy_protocol_accept" => {
                no_children(directive)?;
                let [port, sources @ ..] = args.as_slice() else {
                    return Err(at(
                        &directive.name,
                        "proxy_protocol_accept expects a listener port and trusted IP addresses or CIDRs",
                    ));
                };
                if sources.is_empty() {
                    return Err(at(
                        &directive.name,
                        "proxy_protocol_accept requires trusted sources",
                    ));
                }
                let port = parse_port(port, &directive.args[0])?;
                self.config
                    .proxy_protocol_accept
                    .entry(port)
                    .or_default()
                    .extend(sources.iter().map(|source| (*source).to_owned()));
            }
            "max_connections" => {
                no_children(directive)?;
                one_arg(directive)?;
                self.config.max_connections = parse_number(args[0], &directive.args[0])?;
            }
            "request_timeout" => {
                no_children(directive)?;
                self.config.request_timeout_secs = duration_arg(directive)?;
            }
            "max_header_size" => {
                no_children(directive)?;
                one_arg(directive)?;
                self.config.max_header_size = parse_number(args[0], &directive.args[0])?;
            }
            "static_cache_entries" => {
                no_children(directive)?;
                one_arg(directive)?;
                self.config.static_cache_entries = parse_number(args[0], &directive.args[0])?;
            }
            "static_cache_ttl" => {
                no_children(directive)?;
                self.config.static_cache_ttl_secs = duration_arg(directive)?;
            }
            "stream_connect_timeout" => {
                no_children(directive)?;
                self.connect_timeout_secs = duration_arg(directive)?;
            }
            "stream_idle_timeout" => {
                no_children(directive)?;
                self.idle_timeout_secs = duration_arg(directive)?;
            }
            "stream_handshake_timeout" => {
                no_children(directive)?;
                self.handshake_timeout_secs = duration_arg(directive)?;
            }
            "stream_max_handshake_bytes" => {
                no_children(directive)?;
                one_arg(directive)?;
                self.max_handshake_bytes = parse_number(args[0], &directive.args[0])?;
            }
            "dns" | "cloudflare" => {
                let settings = cloudflare(directive)?;
                merge_cloudflare(&mut self.config.cloudflare, settings, &directive.name)?;
            }
            "layer4" => {
                if !args.is_empty() {
                    return Err(at(&directive.name, "layer4 does not accept arguments"));
                }
                for listener in &directive.children {
                    self.layer4_listener(listener)?;
                }
            }
            option => {
                return Err(at(
                    &directive.name,
                    format!("unsupported global option {option:?}"),
                ));
            }
        }
        Ok(())
    }

    fn site(&mut self, directive: &Directive) -> Result<()> {
        let mut addresses = Vec::new();
        for address in std::iter::once(directive.name.text.as_str()).chain(strings(&directive.args))
        {
            for address in address.split(',').filter(|address| !address.is_empty()) {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            return Err(at(&directive.name, "site block requires an address"));
        }
        let parsed = addresses
            .into_iter()
            .map(|address| {
                site_address(
                    address,
                    &directive.name,
                    self.automatic_https,
                    self.default_http_port,
                    self.default_https_port,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut bind = None;
        for child in directive
            .children
            .iter()
            .filter(|child| child.name.text == "bind")
        {
            no_children(child)?;
            one_arg(child)?;
            let ip = parse_ip(&child.args[0].text, &child.args[0])?;
            if bind.replace(ip).is_some_and(|previous| previous != ip) {
                return Err(at(&child.name, "conflicting bind addresses in site block"));
            }
        }
        for tls in [false, true] {
            let hosts = parsed
                .iter()
                .filter(|address| address.tls == tls)
                .map(|address| address.host.clone())
                .collect::<Vec<_>>();
            if hosts.is_empty() {
                continue;
            }
            let mut site = SiteConfig {
                hosts,
                tls,
                ..SiteConfig::default()
            };
            let has_proxy = directive
                .children
                .iter()
                .any(|child| child.name.text == "reverse_proxy");
            let multiple_handlers = has_proxy
                && directive
                    .children
                    .iter()
                    .filter(|child| {
                        matches!(
                            child.name.text.as_str(),
                            "root" | "file_server" | "reverse_proxy"
                        )
                    })
                    .count()
                    > 1;
            if multiple_handlers || directive.children.iter().any(needs_http_routes) {
                for child in &directive.children {
                    if child.name.text == "tls" {
                        self.site_directive(child, &mut site, &mut false)?;
                    }
                }
                site.routes = self.http_routes(
                    &directive.children,
                    &BTreeMap::new(),
                    &PathBuf::from("."),
                    false,
                    true,
                )?;
                let matchers = collect_http_matchers(&directive.children, &BTreeMap::new())?;
                for handler in directive
                    .children
                    .iter()
                    .filter(|child| child.name.text == "handle_errors")
                {
                    if !handler.has_block {
                        return Err(at(&handler.name, "handle_errors requires a block"));
                    }
                    let route = ErrorRoute {
                        statuses: handler
                            .args
                            .iter()
                            .map(|status| {
                                if let Some(class) = status
                                    .text
                                    .strip_suffix("xx")
                                    .filter(|part| part.len() == 1)
                                {
                                    return parse_number(class, status);
                                }
                                if status.text.len() != 3 {
                                    return Err(at(
                                        status,
                                        "expected status code or class, e.g. 404 or 5xx",
                                    ));
                                }
                                parse_number(&status.text, status)
                            })
                            .collect::<Result<_>>()?,
                        routes: self.http_routes(
                            &handler.children,
                            &matchers,
                            &PathBuf::from("."),
                            false,
                            false,
                        )?,
                    };
                    route.validate().map_err(|error| at(&handler.name, error))?;
                    site.error_routes.push(route);
                }
            } else {
                let mut file_server = false;
                for child in &directive.children {
                    if child.name.text != "bind" {
                        self.site_directive(child, &mut site, &mut file_server)?;
                    }
                }
                if file_server {
                    site.root.get_or_insert_with(|| PathBuf::from("."));
                } else {
                    site.root = None;
                }
            }
            for address in parsed.iter().filter(|address| address.tls == tls) {
                let default_port = if site.tls {
                    self.default_https_port
                } else {
                    self.default_http_port
                };
                self.set_port(
                    address.port.unwrap_or(default_port),
                    site.tls,
                    &directive.name,
                )?;
            }
            if site.tls {
                self.set_bind(true, bind, &directive.name)?;
            } else {
                self.set_bind(false, bind, &directive.name)?;
            }
            self.config.sites.push(site);
        }
        Ok(())
    }

    fn stream_site(&mut self, directive: &Directive) -> Result<()> {
        if !directive.args.is_empty() {
            return Err(at(
                &directive.name,
                "tcp:// and tls:// accept one listener address, not multiple addresses",
            ));
        }
        let address = stream_address(&directive.name)?;
        let mut listen_ip = address.listen.unwrap_or(self.default_bind);
        let mut route = StreamRouteConfig {
            sni: address.sni,
            upstreams: Vec::new(),
            proxy_protocol: None,
        };
        let mut settings = StreamConfig {
            listen: SocketAddr::new(listen_ip, address.port),
            mode: address.mode.clone(),
            routes: Vec::new(),
            connect_timeout_secs: self.connect_timeout_secs,
            idle_timeout_secs: self.idle_timeout_secs,
            handshake_timeout_secs: self.handshake_timeout_secs,
            max_handshake_bytes: self.max_handshake_bytes,
        };
        let mut specified = StreamSettings::default();
        for child in &directive.children {
            let args = strings(&child.args);
            match child.name.text.as_str() {
                "proxy" => {
                    if !route.upstreams.is_empty() {
                        return Err(at(
                            &child.name,
                            "only one proxy is allowed per stream block",
                        ));
                    }
                    (route.upstreams, route.proxy_protocol) = layer4_upstreams(child)?;
                }
                "bind" => {
                    no_children(child)?;
                    one_arg(child)?;
                    let ip = parse_ip(args[0], &child.args[0])?;
                    if address.listen.is_some_and(|configured| configured != ip) {
                        return Err(at(
                            &child.name,
                            "bind address conflicts with the IP in tcp:// listener address",
                        ));
                    }
                    listen_ip = ip;
                    settings.listen.set_ip(ip);
                }
                "connect_timeout" => {
                    no_children(child)?;
                    settings.connect_timeout_secs = duration_arg(child)?;
                    specified.connect_timeout = true;
                }
                "idle_timeout" => {
                    no_children(child)?;
                    settings.idle_timeout_secs = duration_arg(child)?;
                    specified.idle_timeout = true;
                }
                "handshake_timeout" if address.mode == StreamMode::TlsPassthrough => {
                    no_children(child)?;
                    settings.handshake_timeout_secs = duration_arg(child)?;
                    specified.handshake_timeout = true;
                }
                "max_handshake_bytes" if address.mode == StreamMode::TlsPassthrough => {
                    no_children(child)?;
                    one_arg(child)?;
                    settings.max_handshake_bytes = parse_number(args[0], &child.args[0])?;
                    specified.max_handshake_bytes = true;
                }
                "tls" => {
                    return Err(at(
                        &child.name,
                        "tls:// means TLS passthrough; use an https:// site for TLS termination",
                    ));
                }
                option => {
                    return Err(at(
                        &child.name,
                        format!("unsupported stream directive {option:?}"),
                    ));
                }
            }
        }
        if route.upstreams.is_empty() {
            return Err(at(&directive.name, "stream block requires proxy"));
        }
        if let Some(index) =
            self.config.streams.iter().position(|stream| {
                stream.listen.port() == address.port && stream.mode == address.mode
            })
        {
            let stream = &mut self.config.streams[index];
            if stream.listen.ip() != listen_ip {
                return Err(at(
                    &directive.name,
                    format!(
                        "all {:?} blocks on port {} must use the same bind address: {} != {}",
                        address.mode,
                        address.port,
                        stream.listen.ip(),
                        listen_ip
                    ),
                ));
            }
            if address.mode == StreamMode::Tcp {
                return Err(at(
                    &directive.name,
                    format!(
                        "TCP port {} is already configured; use one tcp:// block",
                        address.port
                    ),
                ));
            }
            let previous = self.stream_settings.entry(settings.listen).or_default();
            merge_stream_settings(stream, &settings, previous, &specified, &directive.name)?;
            if let Some(sni) = &route.sni {
                let normalized = sni.trim_end_matches('.').to_ascii_lowercase();
                if stream.routes.iter().any(|route| {
                    route.sni.as_deref().is_some_and(|current| {
                        current
                            .trim_end_matches('.')
                            .eq_ignore_ascii_case(&normalized)
                    })
                }) {
                    return Err(at(
                        &directive.name,
                        format!(
                            "duplicate TLS SNI route {normalized} on port {}; use one block per SNI",
                            address.port
                        ),
                    ));
                }
            }
            stream.routes.push(route);
        } else {
            settings.routes.push(route);
            if settings.mode == StreamMode::TlsPassthrough {
                self.stream_settings.insert(settings.listen, specified);
            }
            self.config.streams.push(settings);
        }
        Ok(())
    }

    fn http_routes(
        &mut self,
        directives: &[Directive],
        matchers: &BTreeMap<String, RequestMatcher>,
        inherited_root: &std::path::Path,
        ordered: bool,
        top: bool,
    ) -> Result<Vec<HttpRoute>> {
        let local_matchers = collect_http_matchers(directives, matchers)?;
        let matchers = &local_matchers;
        let mut root = inherited_root.to_owned();
        let mut root_set = false;
        if !ordered {
            for directive in directives.iter().filter(|d| d.name.text == "root") {
                route_root(directive, &mut root, &mut root_set)?;
            }
        }
        let mut routes = Vec::new();
        for directive in directives {
            let name = directive.name.text.as_str();
            if name.starts_with('@') || top && matches!(name, "tls" | "bind" | "handle_errors") {
                continue;
            }
            if name == "root" {
                if ordered {
                    route_root(directive, &mut root, &mut root_set)?;
                }
                continue;
            }
            let (matcher, args) = take_matcher(directive, matchers)?;
            let action = match name {
                "handle" | "handle_path" | "route" => {
                    if !args.is_empty() || !directive.has_block {
                        return Err(at(
                            &directive.name,
                            "expected optional matcher followed by a block",
                        ));
                    }
                    let nested = self.http_routes(
                        &directive.children,
                        matchers,
                        &root,
                        name == "route",
                        false,
                    )?;
                    if name == "route" {
                        HttpAction::Route { routes: nested }
                    } else {
                        let strip_prefix = if name == "handle_path" {
                            let first = directive.args.first().map(|token| token.text.as_str());
                            match (first, matcher.paths.as_slice()) {
                                (Some(first), [path]) if first.starts_with('/') => Some(
                                    path.strip_suffix("/*")
                                        .or_else(|| path.strip_suffix('*'))
                                        .unwrap_or(path)
                                        .to_owned(),
                                ),
                                _ => {
                                    return Err(at(
                                        &directive.name,
                                        "handle_path requires an inline path matcher",
                                    ));
                                }
                            }
                        } else {
                            None
                        };
                        HttpAction::Handle {
                            routes: nested,
                            strip_prefix,
                        }
                    }
                }
                "rewrite" => {
                    no_children(directive)?;
                    let [target] = args else {
                        return Err(at(&directive.name, "rewrite expects one target"));
                    };
                    HttpAction::Rewrite {
                        to: target.text.clone(),
                    }
                }
                "try_files" => {
                    let policy = match directive.children.as_slice() {
                        [] => TryFilesPolicy::FirstExist,
                        [child] if child.name.text == "policy" => {
                            no_children(child)?;
                            one_arg(child)?;
                            match child.args[0].text.as_str() {
                                "first_exist" => TryFilesPolicy::FirstExist,
                                "first_exist_fallback" => TryFilesPolicy::FirstExistFallback,
                                "smallest_size" => TryFilesPolicy::SmallestSize,
                                "largest_size" => TryFilesPolicy::LargestSize,
                                "most_recently_modified" => TryFilesPolicy::MostRecentlyModified,
                                _ => {
                                    return Err(at(&child.args[0], "unsupported try_files policy"));
                                }
                            }
                        }
                        _ => {
                            return Err(at(
                                &directive.name,
                                "try_files expects at most one policy option",
                            ));
                        }
                    };
                    let mut paths = args;
                    let mut status = None;
                    if let Some((last, rest)) = paths.split_last()
                        && let Some(code) = last.text.strip_prefix('=')
                    {
                        status = Some(parse_number(code, last)?);
                        paths = rest;
                    }
                    HttpAction::TryFiles {
                        root: root.clone(),
                        paths: paths.iter().map(|t| t.text.clone()).collect(),
                        status,
                        policy,
                    }
                }
                "header" => route_headers(directive, args)?,
                "error" => {
                    no_children(directive)?;
                    let (status, message) = match args {
                        [status]
                            if status.text.len() == 3
                                && status.text.bytes().all(|byte| byte.is_ascii_digit()) =>
                        {
                            (parse_number(&status.text, status)?, String::new())
                        }
                        [message] => (500, message.text.clone()),
                        [message, status] => {
                            (parse_number(&status.text, status)?, message.text.clone())
                        }
                        _ => {
                            return Err(at(
                                &directive.name,
                                "error expects a message, a status or both",
                            ));
                        }
                    };
                    HttpAction::Error { status, message }
                }
                "respond" => HttpAction::Respond {
                    response: respond_body(directive, None, args)?,
                },
                "reverse_proxy" | "file_server" => {
                    let mut handler = SiteConfig::default();
                    let mut directive = directive.clone();
                    directive.args = args.to_vec();
                    self.site_directive(&directive, &mut handler, &mut false)?;
                    if name == "reverse_proxy" {
                        HttpAction::ReverseProxy {
                            upstreams: handler.upstreams,
                            proxy: handler.proxy,
                        }
                    } else {
                        HttpAction::FileServer {
                            root: handler.root.unwrap_or_else(|| root.clone()),
                            index: handler.index,
                        }
                    }
                }
                _ => {
                    return Err(at(
                        &directive.name,
                        format!("unsupported HTTP route directive {name:?}"),
                    ));
                }
            };
            let route = HttpRoute { matcher, action };
            crate::routes::validate_routes(std::slice::from_ref(&route), 0)
                .map_err(|error| at(&directive.name, error))?;
            routes.push(route);
        }
        if !ordered {
            routes.sort_by(|a, b| route_order(&a.action).cmp(&route_order(&b.action)));
            let mut start = 0;
            while start < routes.len() {
                let order = route_order(&routes[start].action);
                let end = start
                    + routes[start..]
                        .iter()
                        .take_while(|route| route_order(&route.action) == order)
                        .count();
                let group = &mut routes[start..end];
                group.sort_by_key(|route| matcher_order(&route.matcher).0 == 2);
                let mut i = 0;
                while i < group.len() {
                    let run = group[i..]
                        .iter()
                        .take_while(|route| matcher_order(&route.matcher).0 == 0)
                        .count();
                    if run == 0 {
                        i += 1;
                        continue;
                    }
                    group[i..i + run].sort_by(|a, b| {
                        matcher_order(&b.matcher)
                            .1
                            .cmp(&matcher_order(&a.matcher).1)
                            .then_with(|| a.matcher.paths[0].cmp(&b.matcher.paths[0]))
                    });
                    i += run;
                }
                start = end;
            }
        }
        Ok(routes)
    }

    fn site_directive(
        &mut self,
        directive: &Directive,
        site: &mut SiteConfig,
        file_server: &mut bool,
    ) -> Result<()> {
        let args = strings(&directive.args);
        match directive.name.text.as_str() {
            "root" => {
                no_children(directive)?;
                let path = match args.as_slice() {
                    [path] => *path,
                    ["*", path] => *path,
                    _ => {
                        return Err(at(
                            &directive.name,
                            "root expects a path; request matchers are not supported",
                        ));
                    }
                };
                set_root(site, PathBuf::from(path), &directive.name)?;
            }
            "file_server" => {
                if !args.is_empty() && args != ["*"] {
                    return Err(at(
                        &directive.name,
                        "file_server supports no matcher or *, but not paths, browse or other matchers",
                    ));
                }
                *file_server = true;
                for child in &directive.children {
                    let child_args = strings(&child.args);
                    match child.name.text.as_str() {
                        "root" => {
                            one_arg(child)?;
                            set_root(site, PathBuf::from(child_args[0]), &child.name)?;
                        }
                        "index" => {
                            if child_args.is_empty() || !child.children.is_empty() {
                                return Err(at(
                                    &child.name,
                                    "file_server index expects filenames and no block",
                                ));
                            }
                            site.index =
                                child_args.iter().map(|value| (*value).to_owned()).collect();
                        }
                        option => {
                            return Err(at(
                                &child.name,
                                format!("unsupported file_server option {option:?}"),
                            ));
                        }
                    }
                }
            }
            "reverse_proxy" => {
                for upstream in args.iter().skip(usize::from(args.first() == Some(&"*"))) {
                    if upstream.starts_with('/') || upstream.starts_with('@') {
                        return Err(at(
                            &directive.name,
                            "reverse_proxy request matchers are not supported",
                        ));
                    }
                    site.upstreams
                        .push(http_upstream(upstream, &directive.name)?);
                }
                for child in &directive.children {
                    let child_args = strings(&child.args);
                    match child.name.text.as_str() {
                        "to" | "upstream" => {
                            if child_args.is_empty() || !child.children.is_empty() {
                                return Err(at(
                                    &child.name,
                                    "nested upstream options are not supported by HTTP reverse_proxy",
                                ));
                            }
                            for upstream in child_args {
                                site.upstreams.push(http_upstream(upstream, &child.name)?);
                            }
                        }
                        "lb_policy" => {
                            no_children(child)?;
                            one_arg(child)?;
                            site.proxy.lb_policy = match child_args[0] {
                                "round_robin" => ProxyPolicy::RoundRobin,
                                "first" => ProxyPolicy::First,
                                other => {
                                    return Err(at(
                                        &child.name,
                                        format!("unsupported HTTP load-balancing policy {other:?}"),
                                    ));
                                }
                            };
                        }
                        "lb_retries" => {
                            no_children(child)?;
                            one_arg(child)?;
                            site.proxy.lb_retries = parse_number(child_args[0], &child.args[0])?;
                        }
                        "health_uri" => {
                            no_children(child)?;
                            one_arg(child)?;
                            site.proxy.health_uri = Some(child_args[0].to_owned());
                        }
                        "health_interval" => {
                            no_children(child)?;
                            site.proxy.health_interval_secs = Some(duration_arg(child)?);
                        }
                        "health_timeout" => {
                            no_children(child)?;
                            site.proxy.health_timeout_secs = Some(duration_arg(child)?);
                        }
                        "proxy_protocol" => {
                            set_proxy_protocol(child, &mut site.proxy.proxy_protocol)?
                        }
                        "header_up" | "header_down" => {
                            no_children(child)?;
                            let (name, value) = match child_args.as_slice() {
                                [name] => (*name, None),
                                [name, value] => (*name, Some((*value).to_owned())),
                                _ => {
                                    return Err(at(
                                        &child.name,
                                        "proxy header expects a name and an optional literal value",
                                    ));
                                }
                            };
                            let header = ProxyHeader {
                                name: name.to_owned(),
                                value,
                            };
                            let upstream = child.name.text == "header_up";
                            header
                                .validate(upstream)
                                .map_err(|error| at(&child.name, error))?;
                            if upstream {
                                site.proxy.header_up.push(header);
                            } else {
                                site.proxy.header_down.push(header);
                            }
                        }
                        option => {
                            return Err(at(
                                &child.name,
                                format!("unsupported reverse_proxy option {option:?}"),
                            ));
                        }
                    }
                }
                if site.upstreams.is_empty() {
                    return Err(at(&directive.name, "reverse_proxy requires an upstream"));
                }
                site.proxy
                    .validate()
                    .map_err(|error| at(&directive.name, error))?;
            }
            "respond" => site.responses.push(respond(directive)?),
            "header" => {
                if !args.is_empty() && !directive.children.is_empty() {
                    return Err(at(
                        &directive.name,
                        "header cannot mix arguments and a block",
                    ));
                }
                if directive.children.is_empty() {
                    response_header(site, &directive.name, &args)?;
                } else {
                    for child in &directive.children {
                        let values = std::iter::once(child.name.text.as_str())
                            .chain(strings(&child.args))
                            .collect::<Vec<_>>();
                        response_header(site, &child.name, &values)?;
                    }
                }
            }
            "tls" => {
                match args.as_slice() {
                    [] if !directive.children.is_empty() => {}
                    ["off"] if directive.children.is_empty() => site.tls = false,
                    ["force_automate"] if directive.children.is_empty() => {}
                    [email] if directive.children.is_empty() && email.contains('@') => {
                        set_email(&mut self.config, email, &directive.args[0])?;
                    }
                    [certificate, key] => {
                        site.certificate_file = Some(PathBuf::from(certificate));
                        site.private_key_file = Some(PathBuf::from(key));
                    }
                    _ => {
                        return Err(at(
                            &directive.name,
                            "tls expects an email, certificate and key, or a supported block",
                        ));
                    }
                }
                for child in &directive.children {
                    match child.name.text.as_str() {
                        "dns" => {
                            let settings = cloudflare(child)?;
                            merge_cloudflare(&mut self.config.cloudflare, settings, &child.name)?;
                        }
                        "email" => {
                            no_children(child)?;
                            one_arg(child)?;
                            set_email(&mut self.config, strings(&child.args)[0], &child.args[0])?;
                        }
                        "ca" => {
                            no_children(child)?;
                            one_arg(child)?;
                            let ca = strings(&child.args)[0];
                            if self.config.acme_ca != Config::default().acme_ca
                                && self.config.acme_ca != ca
                            {
                                return Err(at(&child.name, "all sites must use the same ACME CA"));
                            }
                            self.config.acme_ca = ca.to_owned();
                        }
                        "protocols"
                            if strings(&child.args) == ["tls1.2", "tls1.3"]
                                && child.children.is_empty() => {}
                        option => {
                            return Err(at(
                                &child.name,
                                format!("unsupported tls option {option:?}"),
                            ));
                        }
                    }
                }
            }
            option => {
                return Err(at(
                    &directive.name,
                    format!("unsupported site directive {option:?}"),
                ));
            }
        }
        Ok(())
    }

    fn set_bind(&mut self, https: bool, requested: Option<IpAddr>, token: &Token) -> Result<()> {
        let (address, previous, global) = if https {
            (
                &mut self.config.https_addr,
                &mut self.https_bind,
                self.global_https_bind,
            )
        } else {
            (
                &mut self.config.http_addr,
                &mut self.http_bind,
                self.global_http_bind,
            )
        };
        let ip = requested.or(global).unwrap_or(self.default_bind);
        if previous.or(global).is_some_and(|previous| previous != ip) {
            return Err(at(
                token,
                format!(
                    "conflicting bind addresses for the {} listener",
                    if https { "HTTPS" } else { "HTTP" }
                ),
            ));
        }
        *previous = Some(ip);
        address.set_ip(ip);
        Ok(())
    }

    fn set_port(&mut self, port: u16, https: bool, token: &Token) -> Result<()> {
        let (address, explicit) = if https {
            (&mut self.config.https_addr, &mut self.https_port_explicit)
        } else {
            (&mut self.config.http_addr, &mut self.http_port_explicit)
        };
        if *explicit && address.port() != port {
            return Err(at(
                token,
                format!(
                    "one Raddy listener cannot serve multiple {} ports",
                    if https { "HTTPS" } else { "HTTP" }
                ),
            ));
        }
        address.set_port(port);
        *explicit = true;
        Ok(())
    }

    fn layer4_listener(&mut self, directive: &Directive) -> Result<()> {
        if !directive.args.is_empty() {
            return Err(at(&directive.name, "layer4 listener takes one address"));
        }
        let mut stream = StreamConfig {
            listen: parse_listen(&directive.name.text, &directive.name)?,
            mode: StreamMode::Tcp,
            routes: Vec::new(),
            connect_timeout_secs: self.connect_timeout_secs,
            idle_timeout_secs: self.idle_timeout_secs,
            handshake_timeout_secs: self.handshake_timeout_secs,
            max_handshake_bytes: self.max_handshake_bytes,
        };
        let mut matchers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut specified = StreamSettings::default();
        for child in &directive.children {
            let args = strings(&child.args);
            if child.name.text.starts_with('@') {
                if matchers.contains_key(&child.name.text) {
                    return Err(at(&child.name, "duplicate layer4 matcher"));
                }
                let names = tls_matcher(child)?;
                matchers.insert(child.name.text.clone(), names);
                continue;
            }
            match child.name.text.as_str() {
                "route" => {
                    let (matcher, proxy) = match args.as_slice() {
                        [] if child.children.len() == 1 => (None, &child.children[0]),
                        [matcher] if child.children.len() == 1 && matcher.starts_with('@') => {
                            (Some(*matcher), &child.children[0])
                        }
                        _ => {
                            return Err(at(
                                &child.name,
                                "route expects an optional @matcher and a block containing proxy",
                            ));
                        }
                    };
                    let (upstreams, proxy_protocol) = layer4_upstreams(proxy)?;
                    if let Some(matcher) = matcher {
                        let sni = matchers.get(matcher).ok_or_else(|| {
                            anyhow!(
                                "{}:{}: undefined layer4 matcher {matcher}",
                                child.name.line,
                                child.name.column
                            )
                        })?;
                        stream.mode = StreamMode::TlsPassthrough;
                        for pattern in sni {
                            stream.routes.push(StreamRouteConfig {
                                sni: Some(pattern.clone()),
                                upstreams: upstreams.clone(),
                                proxy_protocol,
                            });
                        }
                    } else {
                        stream.routes.push(StreamRouteConfig {
                            sni: None,
                            upstreams,
                            proxy_protocol,
                        });
                    }
                }
                "connect_timeout" => {
                    no_children(child)?;
                    stream.connect_timeout_secs = duration_arg(child)?;
                    specified.connect_timeout = true;
                }
                "idle_timeout" => {
                    no_children(child)?;
                    stream.idle_timeout_secs = duration_arg(child)?;
                    specified.idle_timeout = true;
                }
                "handshake_timeout" => {
                    no_children(child)?;
                    stream.handshake_timeout_secs = duration_arg(child)?;
                    specified.handshake_timeout = true;
                }
                "max_handshake_bytes" => {
                    no_children(child)?;
                    one_arg(child)?;
                    stream.max_handshake_bytes = parse_number(args[0], &child.args[0])?;
                    specified.max_handshake_bytes = true;
                }
                option => {
                    return Err(at(
                        &child.name,
                        format!("unsupported layer4 listener option {option:?}"),
                    ));
                }
            }
        }
        if stream.mode == StreamMode::TlsPassthrough
            && !stream
                .routes
                .iter()
                .any(|route| route.sni.as_deref() == Some("*"))
            && let Some(fallback) = stream.routes.iter_mut().find(|route| route.sni.is_none())
        {
            fallback.sni = Some("*".to_owned());
        }
        if let Some(index) = self.config.streams.iter().position(|current| {
            current.listen.port() == stream.listen.port() && current.mode == stream.mode
        }) {
            let current = &mut self.config.streams[index];
            if current.mode == StreamMode::Tcp {
                return Err(at(
                    &directive.name,
                    "TCP listener is already configured on this port",
                ));
            }
            if current.listen.ip() != stream.listen.ip() {
                return Err(at(
                    &directive.name,
                    "all TLS blocks on one port must use the same bind address",
                ));
            }
            let previous = self.stream_settings.entry(stream.listen).or_default();
            merge_stream_settings(current, &stream, previous, &specified, &directive.name)?;
            current.routes.extend(stream.routes);
        } else {
            if stream.mode == StreamMode::TlsPassthrough {
                self.stream_settings.insert(stream.listen, specified);
            }
            self.config.streams.push(stream);
        }
        Ok(())
    }
}

fn tls_matcher(directive: &Directive) -> Result<Vec<String>> {
    let args = strings(&directive.args);
    if args.first() != Some(&"tls") {
        return Err(at(
            &directive.name,
            "only the tls layer4 matcher is supported",
        ));
    }
    let mut names = Vec::new();
    match &args[1..] {
        [] if directive.children.is_empty() => names.push("*".to_owned()),
        [] => {}
        ["sni", patterns @ ..] if !patterns.is_empty() => {
            names.extend(patterns.iter().map(|name| (*name).to_owned()));
        }
        _ => {
            return Err(at(
                &directive.name,
                "tls matcher supports only sni <names...>",
            ));
        }
    }
    for child in &directive.children {
        if child.name.text != "sni" || child.args.is_empty() || !child.children.is_empty() {
            return Err(at(
                &child.name,
                "tls matcher block supports only sni <names...>",
            ));
        }
        names.extend(strings(&child.args).iter().map(|name| (*name).to_owned()));
    }
    Ok(names)
}

fn layer4_upstreams(
    directive: &Directive,
) -> Result<(Vec<String>, Option<crate::proxy_protocol::Version>)> {
    if directive.name.text != "proxy" {
        return Err(at(
            &directive.name,
            "layer4 route requires proxy; TLS termination is not supported here",
        ));
    }
    let mut upstreams = strings(&directive.args)
        .iter()
        .map(|upstream| tcp_upstream(upstream, &directive.name))
        .collect::<Result<Vec<_>>>()?;
    let mut proxy_protocol = None;
    for child in &directive.children {
        let args = strings(&child.args);
        match child.name.text.as_str() {
            "upstream" => {
                for upstream in args {
                    upstreams.push(tcp_upstream(upstream, &child.name)?);
                }
                for option in &child.children {
                    if option.name.text != "dial"
                        || option.args.is_empty()
                        || !option.children.is_empty()
                    {
                        return Err(at(
                            &option.name,
                            "layer4 upstream block supports only dial <addresses...>",
                        ));
                    }
                    for upstream in strings(&option.args) {
                        upstreams.push(tcp_upstream(upstream, &option.name)?);
                    }
                }
            }
            "proxy_protocol" => set_proxy_protocol(child, &mut proxy_protocol)?,
            "lb_policy" if args == ["round_robin"] && child.children.is_empty() => {}
            option => {
                return Err(at(
                    &child.name,
                    format!("unsupported layer4 proxy option {option:?}"),
                ));
            }
        }
    }
    if upstreams.is_empty() {
        return Err(at(&directive.name, "proxy requires at least one upstream"));
    }
    Ok((upstreams, proxy_protocol))
}

fn set_proxy_protocol(
    directive: &Directive,
    target: &mut Option<crate::proxy_protocol::Version>,
) -> Result<()> {
    no_children(directive)?;
    one_arg(directive)?;
    if target.is_some() {
        return Err(at(&directive.name, "duplicate proxy_protocol"));
    }
    *target = Some(
        directive.args[0]
            .text
            .parse()
            .map_err(|error| at(&directive.args[0], error))?,
    );
    Ok(())
}

fn cloudflare(directive: &Directive) -> Result<CloudflareSettings> {
    let mut args = strings(&directive.args);
    if directive.name.text == "dns" {
        if args.first() != Some(&"cloudflare") {
            return Err(at(
                &directive.name,
                "only the cloudflare DNS provider is supported",
            ));
        }
        args.remove(0);
    }
    let mut settings = CloudflareSettings {
        timeout_secs: 30,
        retries: 3,
        ..CloudflareSettings::default()
    };
    if let [token] = args.as_slice() {
        if !directive.children.is_empty() {
            return Err(at(
                &directive.name,
                "cloudflare accepts a token or a block, not both",
            ));
        }
        settings.api_token = (*token).to_owned();
        return Ok(settings);
    }
    if !args.is_empty() || directive.children.is_empty() {
        return Err(at(
            &directive.name,
            "cloudflare expects one API token or a block with api_token/zone_token",
        ));
    }
    for child in &directive.children {
        no_children(child)?;
        one_arg(child)?;
        let value = strings(&child.args)[0];
        match child.name.text.as_str() {
            "api_token" => settings.api_token = value.to_owned(),
            "zone_token" => settings.zone_token = Some(value.to_owned()),
            "api_base" => settings.api_base = Some(value.to_owned()),
            "timeout" => settings.timeout_secs = duration_arg(child)?,
            "retries" => settings.retries = parse_number(value, &child.args[0])?,
            option => {
                return Err(at(
                    &child.name,
                    format!("unsupported cloudflare option {option:?}"),
                ));
            }
        }
    }
    if settings.api_token.is_empty() {
        return Err(at(&directive.name, "cloudflare api_token is missing"));
    }
    Ok(settings)
}

fn merge_cloudflare(
    target: &mut CloudflareSettings,
    source: CloudflareSettings,
    token: &Token,
) -> Result<()> {
    if !target.api_token.is_empty() && target.api_token != source.api_token {
        return Err(at(
            token,
            "all sites must use the same Cloudflare API token",
        ));
    }
    if target.zone_token.is_some() && target.zone_token != source.zone_token {
        return Err(at(
            token,
            "all sites must use the same Cloudflare zone token",
        ));
    }
    target.api_token = source.api_token;
    target.zone_token = source.zone_token;
    if source.api_base.is_some() {
        if target.api_base.is_some() && target.api_base != source.api_base {
            return Err(at(token, "all sites must use the same Cloudflare API URL"));
        }
        target.api_base = source.api_base;
    }
    target.timeout_secs = source.timeout_secs;
    target.retries = source.retries;
    Ok(())
}

#[derive(Default)]
struct StreamSettings {
    connect_timeout: bool,
    idle_timeout: bool,
    handshake_timeout: bool,
    max_handshake_bytes: bool,
}

fn merge_stream_settings(
    target: &mut StreamConfig,
    source: &StreamConfig,
    previous: &mut StreamSettings,
    specified: &StreamSettings,
    token: &Token,
) -> Result<()> {
    let settings = [
        (
            "connect_timeout",
            previous.connect_timeout,
            specified.connect_timeout,
            target.connect_timeout_secs,
            source.connect_timeout_secs,
        ),
        (
            "idle_timeout",
            previous.idle_timeout,
            specified.idle_timeout,
            target.idle_timeout_secs,
            source.idle_timeout_secs,
        ),
        (
            "handshake_timeout",
            previous.handshake_timeout,
            specified.handshake_timeout,
            target.handshake_timeout_secs,
            source.handshake_timeout_secs,
        ),
    ];
    for (name, was_set, is_set, current, new) in settings {
        if was_set && is_set && current != new {
            return Err(at(
                token,
                format!(
                    "conflicting {name} for stream port {}",
                    target.listen.port()
                ),
            ));
        }
        if is_set {
            match name {
                "connect_timeout" => target.connect_timeout_secs = new,
                "idle_timeout" => target.idle_timeout_secs = new,
                _ => target.handshake_timeout_secs = new,
            }
        }
    }
    if previous.max_handshake_bytes
        && specified.max_handshake_bytes
        && target.max_handshake_bytes != source.max_handshake_bytes
    {
        return Err(at(
            token,
            format!(
                "conflicting max_handshake_bytes for stream port {}",
                target.listen.port()
            ),
        ));
    }
    if specified.max_handshake_bytes {
        target.max_handshake_bytes = source.max_handshake_bytes;
    }
    previous.connect_timeout |= specified.connect_timeout;
    previous.idle_timeout |= specified.idle_timeout;
    previous.handshake_timeout |= specified.handshake_timeout;
    previous.max_handshake_bytes |= specified.max_handshake_bytes;
    Ok(())
}

struct StreamAddress {
    mode: StreamMode,
    sni: Option<String>,
    port: u16,
    listen: Option<IpAddr>,
}

fn stream_address(token: &Token) -> Result<StreamAddress> {
    let address = &token.text;
    let (scheme, rest) = address.split_once("://").ok_or_else(|| {
        anyhow!(
            "{}:{}: invalid stream address {address:?}",
            token.line,
            token.column
        )
    })?;
    let (host, port) = rest.rsplit_once(':').ok_or_else(|| {
        anyhow!(
            "{}:{}: {address:?} requires an explicit listener port",
            token.line,
            token.column
        )
    })?;
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || host.is_empty() && !rest.starts_with(':')
        || matches!(scheme, "tls" if host.is_empty())
    {
        return Err(at(token, format!("invalid stream address {address:?}")));
    }
    if matches!(scheme, "tcp" if host.is_empty()) {
        return Ok(StreamAddress {
            mode: StreamMode::Tcp,
            sni: None,
            port: parse_port(port, token)?,
            listen: None,
        });
    }
    if !host.starts_with('[') && host.matches(':').count() != 0 {
        return Err(at(
            token,
            "IPv6 listener addresses must be written in brackets, for example tcp://[::1]:5432",
        ));
    }
    let url = url::Url::parse(address).map_err(|error| {
        anyhow!(
            "{}:{}: invalid stream address {address:?}: {error}",
            token.line,
            token.column
        )
    })?;
    if url.path() != ""
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port() != Some(parse_port(port, token)?)
    {
        return Err(at(
            token,
            "stream address must contain only scheme, host and listener port",
        ));
    }
    match scheme {
        "tls" => {
            let host = url.host_str().ok_or_else(|| {
                anyhow!(
                    "{}:{}: tls:// requires an SNI name or * for fallback",
                    token.line,
                    token.column
                )
            })?;
            Ok(StreamAddress {
                mode: StreamMode::TlsPassthrough,
                sni: Some(host.trim_end_matches('.').to_ascii_lowercase()),
                port: parse_port(port, token)?,
                listen: None,
            })
        }
        "tcp" => {
            let listen = url
                .host_str()
                .map(|host| {
                    host.trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse()
                        .map_err(|_| {
                            anyhow!(
                                "{}:{}: tcp:// listener must be :port or an IP:port, not a hostname",
                                token.line,
                                token.column
                            )
                        })
                })
                .transpose()?;
            Ok(StreamAddress {
                mode: StreamMode::Tcp,
                sni: None,
                port: parse_port(port, token)?,
                listen,
            })
        }
        scheme => Err(at(token, format!("unsupported stream scheme {scheme:?}"))),
    }
}

struct SiteAddress {
    host: String,
    tls: bool,
    port: Option<u16>,
}

fn site_address(
    address: &str,
    token: &Token,
    automatic_https: bool,
    http_port: u16,
    https_port: u16,
) -> Result<SiteAddress> {
    let (scheme, rest) = address
        .split_once("://")
        .map_or((None, address), |(scheme, rest)| (Some(scheme), rest));
    if scheme.is_some_and(|scheme| !matches!(scheme, "http" | "https")) {
        return Err(at(token, format!("unsupported site scheme in {address:?}")));
    }
    if rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
        return Err(at(
            token,
            "site address must not contain a path, query or userinfo",
        ));
    }
    if rest.is_empty() {
        if scheme == Some("https") {
            return Err(at(token, "https:// without a hostname is not supported"));
        }
        return Ok(SiteAddress {
            host: "*".to_owned(),
            tls: false,
            port: None,
        });
    }
    if let Some(port) = rest.strip_prefix(':') {
        let port = parse_port(port, token)?;
        return Ok(SiteAddress {
            host: "*".to_owned(),
            tls: site_tls(
                scheme,
                Some(port),
                false,
                automatic_https,
                http_port,
                https_port,
                token,
            )?,
            port: Some(port),
        });
    }
    let url = url::Url::parse(&format!("http://{rest}")).map_err(|_| {
        anyhow!(
            "{}:{}: invalid site address {address:?}",
            token.line,
            token.column
        )
    })?;
    let host = url
        .host_str()
        .ok_or_else(|| {
            anyhow!(
                "{}:{}: site address has no hostname",
                token.line,
                token.column
            )
        })?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let host_end = if rest.starts_with('[') {
        rest.find(']').map_or(rest.len(), |end| end + 1)
    } else {
        rest.find(':').unwrap_or(rest.len())
    };
    let port = rest[host_end..]
        .strip_prefix(':')
        .map(|value| parse_port(value, token))
        .transpose()?;
    let tls = site_tls(
        scheme,
        port,
        true,
        automatic_https,
        http_port,
        https_port,
        token,
    )?;
    Ok(SiteAddress { host, tls, port })
}

fn site_tls(
    scheme: Option<&str>,
    port: Option<u16>,
    has_host: bool,
    automatic_https: bool,
    http_port: u16,
    https_port: u16,
    token: &Token,
) -> Result<bool> {
    match scheme {
        Some("http") if port == Some(https_port) => Err(at(
            token,
            "http:// conflicts with the configured HTTPS port",
        )),
        Some("https") if port == Some(http_port) => Err(at(
            token,
            "https:// conflicts with the configured HTTP port",
        )),
        Some("http") => Ok(false),
        Some("https") => Ok(true),
        _ if port == Some(http_port) => Ok(false),
        _ => Ok(automatic_https && (has_host || port == Some(https_port))),
    }
}

fn set_root(site: &mut SiteConfig, root: PathBuf, token: &Token) -> Result<()> {
    if site.root.as_ref().is_some_and(|current| *current != root) {
        return Err(at(token, "conflicting site root paths"));
    }
    site.root = Some(root);
    Ok(())
}

fn set_email(config: &mut Config, email: &str, token: &Token) -> Result<()> {
    if config
        .email
        .as_deref()
        .is_some_and(|current| current != email)
    {
        return Err(at(token, "all sites must use the same ACME email"));
    }
    config.email = Some(email.to_owned());
    Ok(())
}

fn needs_http_routes(directive: &Directive) -> bool {
    let name = directive.name.text.as_str();
    name.starts_with('@')
        || matches!(
            name,
            "handle"
                | "handle_path"
                | "handle_errors"
                | "route"
                | "rewrite"
                | "try_files"
                | "error"
        )
        || name == "header"
            && (directive.args.len() > 2
                || directive
                    .args
                    .first()
                    .is_some_and(|token| token.text.starts_with(['+', '-', '?', '>']))
                || directive.children.iter().any(|child| {
                    child.has_block
                        || matches!(child.name.text.as_str(), "defer" | "match")
                        || child.name.text.starts_with(['+', '-', '?', '>'])
                        || child.args.len() > 1
                }))
        || matches!(name, "reverse_proxy" | "file_server" | "header" | "respond")
            && directive.args.first().is_some_and(|token| {
                token.text.starts_with('@') || name != "respond" && token.text.starts_with('/')
            })
}

fn route_root(directive: &Directive, root: &mut PathBuf, used: &mut bool) -> Result<()> {
    no_children(directive)?;
    let args = strings(&directive.args);
    let path = match args.as_slice() {
        [path] | ["*", path] => *path,
        _ => {
            return Err(at(
                &directive.name,
                "root expects a path and no request matcher",
            ));
        }
    };
    if *used && root.as_os_str() != std::ffi::OsStr::new(path) {
        return Err(at(&directive.name, "conflicting root paths in one block"));
    }
    *root = PathBuf::from(path);
    *used = true;
    Ok(())
}

fn take_matcher<'a>(
    directive: &'a Directive,
    named: &BTreeMap<String, RequestMatcher>,
) -> Result<(RequestMatcher, &'a [Token])> {
    let mut args = directive.args.as_slice();
    if directive.name.text == "try_files" || directive.name.text == "rewrite" && args.len() == 1 {
        return Ok((RequestMatcher::default(), args));
    }
    let mut matcher = RequestMatcher::default();
    if let Some((first, rest)) = args.split_first() {
        let value = &first.text;
        if value.starts_with('@') {
            matcher = named
                .get(value)
                .ok_or_else(|| at(first, format!("undefined HTTP matcher {value:?}")))?
                .clone();
            args = rest;
        } else if value.starts_with('/') {
            validate_match_path(value).map_err(|error| at(first, error))?;
            matcher.paths.push(value.clone());
            args = rest;
        } else if value == "*" {
            args = rest;
        }
    }
    Ok((matcher, args))
}

fn collect_http_matchers(
    directives: &[Directive],
    matchers: &BTreeMap<String, RequestMatcher>,
) -> Result<BTreeMap<String, RequestMatcher>> {
    let mut local_matchers = matchers.clone();
    for directive in directives.iter().filter(|d| d.name.text.starts_with('@')) {
        if local_matchers.contains_key(&directive.name.text) {
            return Err(at(&directive.name, "duplicate named HTTP matcher"));
        }
        local_matchers.insert(directive.name.text.clone(), named_matcher(directive)?);
    }
    Ok(local_matchers)
}

fn named_matcher(directive: &Directive) -> Result<RequestMatcher> {
    if directive.name.text.len() < 2 || directive.has_block && !directive.args.is_empty() {
        return Err(at(
            &directive.name,
            "expected a named HTTP matcher with either a rule or a block",
        ));
    }
    let mut matcher = RequestMatcher::default();
    let scope_name = &directive.name.text[1..];
    if directive.has_block {
        if directive.children.is_empty() {
            return Err(at(&directive.name, "named HTTP matcher requires a rule"));
        }
        for rule in &directive.children {
            no_children(rule)?;
            add_matcher(&mut matcher, scope_name, &rule.name, &rule.args)?;
        }
    } else if let [expression] = directive.args.as_slice()
        && expression.quoted
    {
        matcher.expression = Some(expression.text.clone());
    } else if let Some((name, args)) = directive.args.split_first() {
        add_matcher(&mut matcher, scope_name, name, args)?;
    } else {
        return Err(at(&directive.name, "named HTTP matcher requires a rule"));
    }
    matcher
        .validate()
        .map_err(|error| at(&directive.name, error))?;
    Ok(matcher)
}

fn add_matcher(
    matcher: &mut RequestMatcher,
    scope: &str,
    name: &Token,
    tokens: &[Token],
) -> Result<()> {
    if tokens.is_empty() {
        return Err(at(name, "HTTP matcher requires arguments"));
    }
    let args = tokens.iter().map(|token| token.text.clone());
    match name.text.as_str() {
        "path" => matcher.paths.extend(args),
        "method" => matcher
            .methods
            .extend(args.map(|method| method.to_ascii_uppercase())),
        "header" if tokens.len() == 1 && tokens[0].text.starts_with('!') => {
            matcher
                .headers
                .insert(tokens[0].text[1..].to_ascii_lowercase(), Vec::new());
        }
        "header" if tokens.len() == 2 && !tokens[0].text.starts_with('!') => matcher
            .headers
            .entry(tokens[0].text.to_ascii_lowercase())
            .or_default()
            .push(tokens[1].text.clone()),
        "expression" => {
            let [expression] = tokens else {
                return Err(at(
                    name,
                    "expression expects a single quoted CEL expression",
                ));
            };
            if matcher
                .expression
                .replace(expression.text.clone())
                .is_some()
            {
                return Err(at(name, "duplicate expression matcher"));
            }
        }
        "path_regexp" => {
            let (capture_name, pattern) = match tokens {
                [pattern] => (scope, pattern),
                [capture, pattern] => (capture.text.as_str(), pattern),
                _ => return Err(at(name, "path_regexp expects [name] pattern")),
            };
            if matcher.path_regexp.is_some() {
                return Err(at(name, "duplicate path_regexp matcher"));
            }
            matcher.path_regexp = Some(RegexpMatcher {
                name: capture_name.to_owned(),
                pattern: pattern.text.clone(),
            });
        }
        "header_regexp" => {
            let (capture_name, field, pattern) = match tokens {
                [field, pattern] => (scope, field, pattern),
                [capture, field, pattern] => (capture.text.as_str(), field, pattern),
                _ => return Err(at(name, "header_regexp expects [name] field pattern")),
            };
            let regexp = RegexpMatcher {
                name: capture_name.to_owned(),
                pattern: pattern.text.clone(),
            };
            if matcher
                .header_regexp
                .insert(field.text.to_ascii_lowercase(), regexp)
                .is_some()
            {
                return Err(at(field, "duplicate header_regexp for this field"));
            }
        }
        "query" => {
            let query = matcher.query.get_or_insert_with(BTreeMap::new);
            for token in tokens.iter().filter(|token| !token.text.is_empty()) {
                let Some((key, value)) = token.text.split_once('=') else {
                    return Err(at(token, "query matcher expects parameter=value"));
                };
                query
                    .entry(key.to_owned())
                    .or_default()
                    .push(value.to_owned());
            }
        }
        _ => {
            return Err(at(name, "unsupported HTTP matcher"));
        }
    }
    Ok(())
}

fn route_headers(directive: &Directive, args: &[Token]) -> Result<HttpAction> {
    fn operation(name: &Token, args: &[Token]) -> Result<ResponseHeader> {
        let (value, replacement) = match args {
            [] => (None, None),
            [value] => (Some(value.text.clone()), None),
            [pattern, replacement] => (Some(pattern.text.clone()), Some(replacement.text.clone())),
            _ => {
                return Err(at(
                    name,
                    "header expects a field, optional value and optional regexp replacement",
                ));
            }
        };
        let operation = ResponseHeader {
            name: name.text.trim_end_matches(':').to_owned(),
            value,
            replacement,
        };
        operation.validate().map_err(|error| at(name, error))?;
        Ok(operation)
    }
    let mut operations = Vec::new();
    let mut defer = false;
    let mut condition = None;
    if let Some((name, values)) = args.split_first() {
        operations.push(operation(name, values)?);
    }
    for child in &directive.children {
        match child.name.text.as_str() {
            "defer" if child.args.is_empty() && !child.has_block => defer = true,
            "match" if child.has_block && child.args.is_empty() && condition.is_none() => {
                let mut response = ResponseCondition::default();
                for rule in &child.children {
                    no_children(rule)?;
                    match rule.name.text.as_str() {
                        "status" if !rule.args.is_empty() => {
                            for code in &rule.args {
                                let value = code
                                    .text
                                    .strip_suffix("xx")
                                    .filter(|part| part.len() == 1)
                                    .unwrap_or(&code.text);
                                response.statuses.push(parse_number(value, code)?);
                            }
                        }
                        "header" => {
                            let mut parsed = RequestMatcher::default();
                            add_matcher(&mut parsed, "", &rule.name, &rule.args)?;
                            for (name, values) in parsed.headers {
                                if values.is_empty() {
                                    response.headers.insert(name, values);
                                } else {
                                    response.headers.entry(name).or_default().extend(values);
                                }
                            }
                        }
                        _ => {
                            return Err(at(
                                &rule.name,
                                "response matcher expects status or header",
                            ));
                        }
                    }
                }
                condition = Some(response);
            }
            _ if args.is_empty() => {
                no_children(child)?;
                operations.push(operation(&child.name, &child.args)?);
            }
            _ => {
                return Err(at(
                    &child.name,
                    "header cannot set fields in both arguments and block",
                ));
            }
        }
    }
    if operations.is_empty() {
        return Err(at(&directive.name, "header expects at least one operation"));
    }
    Ok(HttpAction::Header {
        operations,
        defer,
        condition,
    })
}

fn route_order(action: &HttpAction) -> u8 {
    match action {
        HttpAction::Header { .. } => 0,
        HttpAction::Rewrite { .. } => 1,
        HttpAction::TryFiles { .. } => 2,
        HttpAction::Handle { .. } => 3,
        HttpAction::Route { .. } => 4,
        HttpAction::Error { .. } => 5,
        HttpAction::Respond { .. } => 6,
        HttpAction::ReverseProxy { .. } => 7,
        HttpAction::FileServer { .. } => 8,
    }
}

fn matcher_order(matcher: &RequestMatcher) -> (u8, (usize, bool)) {
    match matcher.paths.as_slice() {
        [] if matcher.methods.is_empty()
            && matcher.headers.is_empty()
            && matcher.query.is_none()
            && matcher.path_regexp.is_none()
            && matcher.header_regexp.is_empty()
            && matcher.expression.is_none() =>
        {
            (2, (0, false))
        }
        [path] => {
            let prefix = path.strip_suffix('*');
            (0, (prefix.unwrap_or(path).len(), prefix.is_none()))
        }
        _ => (1, (0, false)),
    }
}

fn respond(directive: &Directive) -> Result<RespondConfig> {
    let mut args = directive.args.as_slice();
    let mut path = None;
    if let Some((first, remaining)) = args.split_first() {
        if first.text.starts_with('@') {
            return Err(at(first, "respond does not support named request matchers"));
        }
        if first.text == "*" || first.text.starts_with('/') {
            if first.text != "*" {
                path = Some(first.text.clone());
            }
            args = remaining;
        }
    }
    respond_body(directive, path, args)
}

fn respond_body(
    directive: &Directive,
    path: Option<String>,
    args: &[Token],
) -> Result<RespondConfig> {
    let (mut body, status) = match args {
        [value]
            if value.text.len() == 3 && value.text.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            (None, parse_number(&value.text, value)?)
        }
        [body] => (Some(body.text.clone()), 200),
        [body, status] => (Some(body.text.clone()), parse_number(&status.text, status)?),
        _ => {
            return Err(at(
                &directive.name,
                "respond expects [path] <body|status> [status]",
            ));
        }
    };
    let mut close = false;
    for option in &directive.children {
        no_children(option)?;
        match option.name.text.as_str() {
            "body" if body.is_none() => {
                one_arg(option)?;
                body = Some(option.args[0].text.clone());
            }
            "body" => return Err(at(&option.name, "respond body already specified")),
            "close" if !close && option.args.is_empty() => close = true,
            "close" => {
                return Err(at(
                    &option.name,
                    "respond close takes no arguments and may appear only once",
                ));
            }
            other => {
                return Err(at(
                    &option.name,
                    format!("unsupported respond option {other:?}"),
                ));
            }
        }
    }
    let response = RespondConfig {
        path,
        status,
        implicit_status: matches!(args, [value] if value.text.len() != 3 || !value.text.bytes().all(|byte| byte.is_ascii_digit())),
        body: body.unwrap_or_default(),
        close,
    };
    response
        .validate()
        .map_err(|error| at(&directive.name, error))?;
    Ok(response)
}

fn response_header(site: &mut SiteConfig, token: &Token, values: &[&str]) -> Result<()> {
    if let [name, values @ ..] = values
        && !values.is_empty()
        && !name.starts_with(['-', '+', '?', '<', '>'])
    {
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            anyhow!(
                "{}:{}: invalid header name {name:?}",
                token.line,
                token.column
            )
        })?;
        let value = values.join(" ");
        HeaderValue::from_str(&value).map_err(|_| {
            anyhow!(
                "{}:{}: invalid value for response header {name}",
                token.line,
                token.column
            )
        })?;
        site.response_headers.insert((*name).to_owned(), value);
        return Ok(());
    }
    Err(at(
        token,
        "header expects a name and value; mutations and matchers are not supported",
    ))
}

fn http_upstream(upstream: &str, token: &Token) -> Result<String> {
    if upstream.starts_with("unix/") {
        return Err(at(token, format!("unsupported HTTP upstream {upstream:?}")));
    }
    if upstream.contains("://") {
        Ok(upstream.to_owned())
    } else {
        Ok(format!("http://{upstream}"))
    }
}

fn tcp_upstream(upstream: &str, token: &Token) -> Result<String> {
    let upstream = upstream.strip_prefix("tcp/").unwrap_or(upstream);
    if upstream.contains("://") || upstream.starts_with("udp/") || upstream.starts_with("unix/") {
        return Err(at(token, format!("unsupported TCP upstream {upstream:?}")));
    }
    Ok(upstream.to_owned())
}

fn parse_listen(value: &str, token: &Token) -> Result<SocketAddr> {
    let address = value.strip_prefix("tcp/").unwrap_or(value);
    if address.contains('/') {
        return Err(at(
            token,
            format!("unsupported listener network in {value:?}"),
        ));
    }
    let address = if let Some(port) = address.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        address.to_owned()
    };
    address.parse().map_err(|_| {
        anyhow!(
            "{}:{}: invalid TCP listener {value:?}",
            token.line,
            token.column
        )
    })
}

fn parse_ip(value: &str, token: &Token) -> Result<IpAddr> {
    value.parse().map_err(|_| {
        anyhow!(
            "{}:{}: invalid bind address {value:?}",
            token.line,
            token.column
        )
    })
}

fn parse_port(value: &str, token: &Token) -> Result<u16> {
    let port = parse_number(value, token)?;
    if port == 0 {
        return Err(at(token, "port must be in 1..65535"));
    }
    Ok(port)
}

fn parse_number<T: std::str::FromStr>(value: &str, token: &Token) -> Result<T> {
    value
        .parse()
        .map_err(|_| anyhow!("{}:{}: invalid number {value:?}", token.line, token.column))
}

fn duration_arg(directive: &Directive) -> Result<u64> {
    one_arg(directive)?;
    let value = &directive.args[0];
    let duration = parse_duration(&value.text)
        .map_err(|message| anyhow!("{}:{}: {message}", value.line, value.column))?;
    if duration.subsec_nanos() != 0 {
        return Err(at(value, "this setting requires a whole number of seconds"));
    }
    Ok(duration.as_secs())
}

pub(super) fn parse_duration(input: &str) -> std::result::Result<Duration, String> {
    if input.is_empty() || input.starts_with('-') {
        return Err(format!("invalid duration {input:?}"));
    }
    if input.bytes().all(|byte| byte.is_ascii_digit()) {
        let seconds = input
            .parse::<u64>()
            .map_err(|_| format!("invalid duration {input:?}"))?;
        return Ok(Duration::from_secs(seconds));
    }
    let mut rest = input;
    let mut total = Duration::ZERO;
    while !rest.is_empty() {
        let digits = rest
            .find(|character: char| !character.is_ascii_digit())
            .ok_or_else(|| format!("duration unit is missing in {input:?}"))?;
        let (whole, after_whole) = rest.split_at(digits);
        let (fraction, after_number) = if let Some(after_dot) = after_whole.strip_prefix('.') {
            let end = after_dot
                .find(|character: char| !character.is_ascii_digit())
                .unwrap_or(after_dot.len());
            if end == 0 {
                return Err(format!("invalid duration {input:?}"));
            }
            (&after_dot[..end], &after_dot[end..])
        } else {
            ("", after_whole)
        };
        let unit_end = after_number
            .find(|character: char| character.is_ascii_digit())
            .unwrap_or(after_number.len());
        let (unit, remainder) = after_number.split_at(unit_end);
        let seconds_per_unit = match unit {
            "ms" => 0.001,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            _ => return Err(format!("unknown duration unit {unit:?}")),
        };
        let seconds = whole
            .parse::<u64>()
            .map_err(|_| format!("invalid duration {input:?}"))? as f64
            * seconds_per_unit;
        let fraction = if fraction.is_empty() {
            0.0
        } else {
            format!("0.{fraction}")
                .parse::<f64>()
                .map_err(|_| format!("invalid duration {input:?}"))?
                * seconds_per_unit
        };
        total = total
            .checked_add(
                Duration::try_from_secs_f64(seconds + fraction)
                    .map_err(|_| format!("duration is too large {input:?}"))?,
            )
            .ok_or_else(|| format!("duration is too large {input:?}"))?;
        rest = remainder;
    }
    Ok(total)
}

fn at(token: &Token, message: impl std::fmt::Display) -> anyhow::Error {
    token.error(message)
}

fn strings(tokens: &[Token]) -> Vec<&str> {
    tokens.iter().map(|token| token.text.as_str()).collect()
}

fn one_arg(directive: &Directive) -> Result<()> {
    if directive.args.len() != 1 {
        return Err(at(&directive.name, "expected exactly one argument"));
    }
    Ok(())
}

fn no_children(directive: &Directive) -> Result<()> {
    if directive.has_block {
        return Err(at(&directive.name, "directive does not accept a block"));
    }
    Ok(())
}

pub(super) fn build(tokens: &[Token]) -> Result<Config> {
    let directives = directives::parse(tokens)?;
    let mut builder = Builder::new();
    for (index, directive) in directives.iter().enumerate() {
        if directive.name.text.is_empty() {
            if index != 0 || !directive.args.is_empty() {
                return Err(at(
                    &directive.name,
                    "global options must be the first block",
                ));
            }
            for option in &directive.children {
                builder.global(option)?;
            }
        } else if directive.name.text.starts_with("tls://")
            || directive.name.text.starts_with("tcp://")
        {
            builder.stream_site(directive)?;
        } else {
            builder.site(directive)?;
        }
    }
    builder.config.validate()?;
    Ok(builder.config)
}
