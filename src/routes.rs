use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Result, bail};
use http::{HeaderName, HeaderValue, Method, uri::PathAndQuery};
use serde::{Deserialize, Serialize};

use crate::config::{ProxySettings, RespondConfig, validate_http_upstreams};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RequestMatcher {
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub query: Option<BTreeMap<String, Vec<String>>>,
    pub path_regexp: Option<RegexpMatcher>,
    pub header_regexp: BTreeMap<String, RegexpMatcher>,
    pub expression: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegexpMatcher {
    #[serde(default)]
    pub name: String,
    pub pattern: String,
}

impl RegexpMatcher {
    pub(crate) fn compile(&self) -> Result<regex::Regex> {
        if !self.name.is_empty()
            && !self
                .name
                .bytes()
                .any(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("invalid regexp name: {:?}", self.name);
        }
        Ok(regex::RegexBuilder::new(&normalize_regexp(&self.pattern))
            .size_limit(2 * 1024 * 1024)
            .build()?)
    }
}

fn normalize_regexp(pattern: &str) -> String {
    let mut normalized = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    let mut in_class = false;
    while let Some(ch) = chars.next() {
        match (ch, in_class) {
            ('\\', _) => {
                let replacement = match chars.next() {
                    Some('d') => "0-9",
                    Some('w') => "0-9A-Za-z_",
                    Some('s') => r"\t\n\x0c\r ",
                    Some(ch) => {
                        normalized.push('\\');
                        normalized.push(ch);
                        continue;
                    }
                    None => {
                        normalized.push('\\');
                        break;
                    }
                };
                if !in_class {
                    normalized.push('[');
                }
                normalized.push_str(replacement);
                if !in_class {
                    normalized.push(']');
                }
            }
            ('[', false) => {
                in_class = true;
                normalized.push(ch);
            }
            (']', true) => {
                in_class = false;
                normalized.push(ch);
            }
            _ => normalized.push(ch),
        }
    }
    normalized
}

impl RequestMatcher {
    pub fn validate(&self) -> Result<()> {
        for path in &self.paths {
            validate_match_path(path)?;
        }
        for method in &self.methods {
            Method::from_bytes(method.as_bytes())?;
        }
        for (name, values) in &self.headers {
            HeaderName::from_bytes(name.as_bytes())?;
            for value in values {
                HeaderValue::from_str(value)?;
            }
        }
        if let Some(query) = &self.query
            && query.values().any(Vec::is_empty)
        {
            bail!("query matcher requires at least one value per parameter");
        }
        if let Some(regexp) = &self.path_regexp {
            regexp.compile()?;
        }
        if let Some(expression) = &self.expression {
            crate::expression::Expression::new(expression)?;
        }
        for (header, regexp) in &self.header_regexp {
            HeaderName::from_bytes(header.as_bytes())?;
            regexp.compile()?;
        }
        Ok(())
    }
}

pub(crate) fn validate_match_path(path: &str) -> Result<()> {
    if !path.starts_with(['/', '*'])
        || path.contains(['#', '{', '}'])
        || path.chars().any(char::is_control)
    {
        bail!("invalid path matcher: {path:?}");
    }
    if path.contains('%') {
        let mut remaining = path.as_bytes();
        while let Some(index) = remaining.iter().position(|byte| *byte == b'%') {
            remaining = &remaining[index + 1..];
            if let Some(tail) = remaining.strip_prefix(b"*") {
                remaining = tail;
            } else if remaining
                .get(..2)
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
            {
                remaining = &remaining[2..];
            } else {
                bail!("invalid escape in path matcher: {path:?}");
            }
        }
        compile_path_glob(&path.to_lowercase().replace("%*", "*"))?;
    } else if path.contains(['*', '?', '[', '\\']) && !simple_path_pattern(path) {
        compile_path_glob(&path.to_lowercase())?;
    }
    Ok(())
}

pub(crate) fn simple_path_pattern(pattern: &str) -> bool {
    match pattern.bytes().filter(|byte| *byte == b'*').count() {
        1 => pattern.starts_with('*') || pattern.ends_with('*'),
        2 => pattern.starts_with('*') && pattern.ends_with('*'),
        _ => false,
    }
}

pub(crate) fn compile_path_glob(pattern: &str) -> Result<Vec<glob::Pattern>> {
    pattern
        .split('/')
        .map(|part| {
            let mut literal = String::with_capacity(part.len());
            let mut chars = part.chars().peekable();
            let mut in_class = false;
            while let Some(ch) = chars.next() {
                match ch {
                    '\\' if !in_class => {
                        let Some(escaped) = chars.next() else {
                            bail!("incomplete escape in path pattern")
                        };
                        literal.push_str(&glob::Pattern::escape(&escaped.to_string()));
                    }
                    '[' if !in_class => {
                        literal.push('[');
                        in_class = true;
                        if chars.next_if_eq(&'^').is_some() {
                            literal.push('!');
                        }
                    }
                    ']' if in_class => {
                        in_class = false;
                        literal.push(ch);
                    }
                    '*' if !in_class => {
                        while chars.next_if_eq(&'*').is_some() {}
                        literal.push('*');
                    }
                    _ => literal.push(ch),
                }
            }
            Ok(glob::Pattern::new(&literal)?)
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ErrorRoute {
    pub statuses: Vec<u16>,
    pub routes: Vec<HttpRoute>,
}

impl ErrorRoute {
    pub(crate) fn matches(&self, status: u16) -> bool {
        self.statuses.is_empty()
            || self
                .statuses
                .iter()
                .any(|code| *code == status || *code == status / 100)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self
            .statuses
            .iter()
            .any(|status| !matches!(status, 1..=5 | 100..=599))
        {
            bail!("handle_errors expects HTTP status codes or classes");
        }
        validate_routes(&self.routes, 0)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpRoute {
    #[serde(default)]
    pub matcher: RequestMatcher,
    #[serde(flatten)]
    pub action: HttpAction,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HttpAction {
    Handle {
        routes: Vec<HttpRoute>,
        strip_prefix: Option<String>,
    },
    Route {
        routes: Vec<HttpRoute>,
    },
    Rewrite {
        to: String,
    },
    Error {
        status: u16,
        message: String,
    },
    Header {
        operations: Vec<ResponseHeader>,
        #[serde(default)]
        defer: bool,
        #[serde(default)]
        condition: Option<ResponseCondition>,
    },
    TryFiles {
        root: PathBuf,
        paths: Vec<String>,
        status: Option<u16>,
        #[serde(default)]
        policy: TryFilesPolicy,
    },
    Respond {
        response: RespondConfig,
    },
    ReverseProxy {
        upstreams: Vec<String>,
        #[serde(default)]
        proxy: ProxySettings,
    },
    FileServer {
        root: PathBuf,
        #[serde(default)]
        index: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TryFilesPolicy {
    #[default]
    FirstExist,
    FirstExistFallback,
    SmallestSize,
    LargestSize,
    MostRecentlyModified,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseHeader {
    pub name: String,
    pub value: Option<String>,
    #[serde(default)]
    pub replacement: Option<String>,
}

impl ResponseHeader {
    pub(crate) fn validate(&self) -> Result<()> {
        let name = self
            .name
            .strip_prefix(['+', '-', '?', '>'])
            .unwrap_or(&self.name);
        let glob = name.trim_start_matches('*').trim_end_matches('*');
        if self.name.starts_with('-') && name.contains('*') {
            if !glob.is_empty() {
                HeaderName::from_bytes(glob.as_bytes())?;
            }
            if self.value.is_some() || self.replacement.is_some() {
                bail!("header deletion takes no value");
            }
        } else if name == "*"
            && self.replacement.is_some()
            && !self.name.starts_with(['+', '-', '?'])
        {
        } else {
            crate::config::ProxyHeader {
                name: self
                    .name
                    .strip_prefix(['?', '>'])
                    .unwrap_or(&self.name)
                    .to_owned(),
                value: self.value.clone(),
            }
            .validate(false)?;
        }
        if let Some(replacement) = &self.replacement {
            if self.name.starts_with(['+', '-', '?']) {
                bail!("regexp header replacement expects an unmodified field name or '>'");
            }
            HeaderValue::from_str(replacement)?;
            let pattern = self
                .value
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing header regexp"))?;
            RegexpMatcher {
                name: String::new(),
                pattern: pattern.to_owned(),
            }
            .compile()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ResponseCondition {
    pub statuses: Vec<u16>,
    pub headers: BTreeMap<String, Vec<String>>,
}

impl ResponseCondition {
    fn validate(&self) -> Result<()> {
        if self
            .statuses
            .iter()
            .any(|status| !matches!(status, 1..=5 | 100..=599))
        {
            bail!("invalid response match status");
        }
        RequestMatcher {
            headers: self.headers.clone(),
            ..Default::default()
        }
        .validate()
    }
}

pub(crate) fn validate_routes(routes: &[HttpRoute], depth: usize) -> Result<()> {
    if depth > 32 {
        bail!("HTTP route nesting exceeds 32 blocks");
    }
    for route in routes {
        route.matcher.validate()?;
        match &route.action {
            HttpAction::Handle {
                routes,
                strip_prefix,
            } => {
                if let Some(prefix) = strip_prefix
                    && !prefix.is_empty()
                    && !prefix.starts_with('/')
                {
                    bail!("handle_path strip prefix must begin with '/'");
                }
                validate_routes(routes, depth + 1)?;
            }
            HttpAction::Route { routes } => validate_routes(routes, depth + 1)?,
            HttpAction::Rewrite { to } => validate_target(to, false)?,
            HttpAction::Error { status, .. } if !(400..=599).contains(status) => {
                bail!("error expects status 400..=599")
            }
            HttpAction::Error { .. } => {}
            HttpAction::Header {
                operations,
                condition,
                ..
            } => {
                for operation in operations {
                    operation.validate()?;
                }
                if let Some(condition) = condition {
                    condition.validate()?;
                }
            }
            HttpAction::TryFiles {
                paths,
                status,
                policy,
                ..
            } => {
                if paths.is_empty()
                    || !matches!(
                        policy,
                        TryFilesPolicy::FirstExist | TryFilesPolicy::FirstExistFallback
                    ) && status.is_some()
                    || status.is_some_and(|status| !(400..=599).contains(&status))
                {
                    bail!(
                        "try_files requires at least one path and an optional =4xx or =5xx fallback"
                    );
                }
                for path in paths {
                    validate_target(path, true)?;
                }
            }
            HttpAction::ReverseProxy { upstreams, proxy } => {
                if upstreams.is_empty() {
                    bail!("reverse_proxy requires at least one upstream");
                }
                validate_http_upstreams(upstreams)?;
                proxy.validate()?;
            }
            HttpAction::Respond { response } => {
                if response.path.is_some() {
                    bail!("put the path matcher on the HTTP route, not its nested respond action");
                }
                response.validate()?;
            }
            HttpAction::FileServer { .. } => {}
        }
    }
    Ok(())
}

fn validate_target(target: &str, file: bool) -> Result<()> {
    let mut template = target
        .replace("{path}", "/path")
        .replace("{uri}", "/path")
        .replace("{query}", "query");
    while let Some(start) = template
        .find("{re.")
        .or_else(|| template.find("{http.regexp."))
    {
        let Some(end) = template[start..].find('}') else {
            break;
        };
        template.replace_range(start..=start + end, "capture");
    }
    if target.is_empty()
        || file && target.contains("{uri}")
        || template.starts_with("//")
        || template.contains(['{', '}', '#'])
        || !(file || template.starts_with('/') || template.starts_with('?'))
        || (if file && !template.starts_with('/') {
            format!("/{template}")
        } else {
            template
        })
        .parse::<PathAndQuery>()
        .is_err()
    {
        bail!(
            "expected an origin path, with optional query and supported placeholders: {target:?}"
        );
    }
    Ok(())
}
