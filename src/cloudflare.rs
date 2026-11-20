use std::{collections::HashMap, sync::Arc, time::Duration};

use futures_util::{StreamExt, TryStreamExt, stream};
use reqwest::{Method, StatusCode, header::AUTHORIZATION};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::sync::{Mutex, OnceCell};

const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const PAGE_SIZE: u32 = 100;
const CONCURRENT_RECORD_REQUESTS: usize = 8;

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("invalid Cloudflare API token; expected a scoped API token, not a global API key")]
    InvalidToken,
    #[error("Cloudflare API token is missing (set CF_API_TOKEN or cloudflare.api_token)")]
    MissingToken,
    #[error("expected one Cloudflare zone for {zone}, found {count}")]
    ZoneNotUnique { zone: String, count: usize },
    #[error("no Cloudflare zone found for DNS name {0}")]
    ZoneNotFound(String),
    #[error("found more than one {kind} record named {name}; refusing an ambiguous update")]
    AmbiguousRecord { kind: String, name: String },
    #[error("Cloudflare API returned HTTP {status}: {messages}")]
    Api {
        status: StatusCode,
        messages: String,
    },
    #[error("Cloudflare API returned an invalid response: {0}")]
    InvalidResponse(String),
    #[error("malformed TXT record content: {0}")]
    MalformedTxt(String),
    #[error("HTTP request to Cloudflare failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CloudflareError>;

#[derive(Clone, Debug)]
pub struct CloudflareConfig {
    pub api_token: String,
    pub zone_token: Option<String>,
    pub api_base: String,
    pub timeout: Duration,
    pub retries: usize,
}

impl CloudflareConfig {
    pub fn new(api_token: impl Into<String>) -> Self {
        Self {
            api_token: api_token.into(),
            zone_token: None,
            api_base: DEFAULT_API_BASE.to_owned(),
            timeout: Duration::from_secs(30),
            retries: 3,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.api_token.is_empty() {
            return Err(CloudflareError::MissingToken);
        }
        if !valid_cloudflare_token(&self.api_token) {
            return Err(CloudflareError::InvalidToken);
        }
        if let Some(token) = &self.zone_token
            && !token.is_empty()
            && !valid_cloudflare_token(token)
        {
            return Err(CloudflareError::InvalidToken);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct DnsRecord {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ttl: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl DnsRecord {
    pub fn new(
        kind: impl Into<String>,
        name: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into().to_ascii_uppercase(),
            name: name.into(),
            content: content.into(),
            ttl: 1,
            ..Self::default()
        }
    }

    pub fn txt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new("TXT", name, value)
    }
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    #[serde(default)]
    per_page: u32,
    #[serde(default)]
    total_count: u64,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    result: Option<T>,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(default)]
    success: bool,
    result_info: Option<ResultInfo>,
}

struct ApiResult<T> {
    result: T,
    info: Option<ResultInfo>,
}

pub struct Cloudflare {
    config: CloudflareConfig,
    client: reqwest::Client,
    zones: Mutex<HashMap<String, Arc<OnceCell<Zone>>>>,
}

impl Cloudflare {
    pub fn new(config: CloudflareConfig) -> Result<Self> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(config.timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent(concat!("raddy/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            config,
            client,
            zones: Mutex::new(HashMap::new()),
        })
    }

    pub fn from_env() -> Result<Self> {
        let api_token = std::env::var("CF_API_TOKEN").map_err(|_| CloudflareError::MissingToken)?;
        let mut config = CloudflareConfig::new(api_token);
        config.zone_token = std::env::var("CF_ZONE_TOKEN")
            .ok()
            .filter(|v| !v.is_empty());
        if let Ok(base) = std::env::var("RADDY_CLOUDFLARE_API_BASE") {
            config.api_base = base;
        }
        Self::new(config)
    }

    pub async fn list_zones(&self) -> Result<Vec<Zone>> {
        let mut zones = Vec::new();
        let mut page = 1;
        loop {
            let response: ApiResult<Vec<Zone>> = self
                .request::<_, ()>(
                    Method::GET,
                    "/zones",
                    Some(&[
                        ("page", page.to_string()),
                        ("per_page", PAGE_SIZE.to_string()),
                    ]),
                    None,
                    true,
                )
                .await?;
            let count = response.result.len();
            zones.extend(response.result);
            if last_page(response.info.as_ref(), page, count) {
                break;
            }
            page += 1;
        }
        Ok(zones)
    }

    pub async fn get_records(&self, zone: &str) -> Result<Vec<DnsRecord>> {
        let zone = normalize_zone(zone);
        let zone_info = self.zone(&zone).await?;
        let path = format!("/zones/{}/dns_records", zone_info.id);
        let mut records = Vec::new();
        let mut page = 1;
        loop {
            let response: ApiResult<Vec<DnsRecord>> = self
                .request::<_, ()>(
                    Method::GET,
                    &path,
                    Some(&[
                        ("page", page.to_string()),
                        ("per_page", PAGE_SIZE.to_string()),
                    ]),
                    None,
                    false,
                )
                .await?;
            let count = response.result.len();
            records.extend(
                response
                    .result
                    .into_iter()
                    .map(|record| relative_record(record, &zone)),
            );
            if last_page(response.info.as_ref(), page, count) {
                break;
            }
            page += 1;
        }
        Ok(records)
    }

    pub async fn append_records(
        &self,
        zone: &str,
        records: Vec<DnsRecord>,
    ) -> Result<Vec<DnsRecord>> {
        let zone = normalize_zone(zone);
        let zone_info = self.zone(&zone).await?;
        let path = format!("/zones/{}/dns_records", zone_info.id);
        stream::iter(records.into_iter().map(|record| {
            let path = &path;
            let zone = &zone;
            async move {
                let payload = api_record(record, zone);
                let created: ApiResult<DnsRecord> = self
                    .request(Method::POST, path, None, Some(payload), false)
                    .await?;
                Ok(relative_record(created.result, zone))
            }
        }))
        .buffer_unordered(CONCURRENT_RECORD_REQUESTS)
        .try_collect()
        .await
    }

    pub async fn set_records(&self, zone: &str, records: Vec<DnsRecord>) -> Result<Vec<DnsRecord>> {
        let zone = normalize_zone(zone);
        let zone_info = self.zone(&zone).await?;
        let path = format!("/zones/{}/dns_records", zone_info.id);
        stream::iter(records.into_iter().map(|record| {
            let path = &path;
            let zone = &zone;
            let zone_info = &zone_info;
            async move {
                let matches = self.find_records(zone_info, &record, false).await?;
                if matches.len() > 1 {
                    return Err(CloudflareError::AmbiguousRecord {
                        kind: record.kind,
                        name: record.name,
                    });
                }
                let payload = api_record(record, zone);
                let result = if let Some(existing) = matches.first() {
                    let update_path = format!("{path}/{}", existing.id);
                    self.request(Method::PATCH, &update_path, None, Some(payload), false)
                        .await?
                } else {
                    self.request(Method::POST, path, None, Some(payload), false)
                        .await?
                };
                Ok(relative_record(result.result, zone))
            }
        }))
        .buffer_unordered(CONCURRENT_RECORD_REQUESTS)
        .try_collect()
        .await
    }

    pub async fn delete_records(
        &self,
        zone: &str,
        records: Vec<DnsRecord>,
    ) -> Result<Vec<DnsRecord>> {
        let zone = normalize_zone(zone);
        let zone_info = self.zone(&zone).await?;
        let base_path = format!("/zones/{}/dns_records", zone_info.id);
        stream::iter(records.into_iter().map(|record| {
            let zone = &zone;
            let zone_info = &zone_info;
            let base_path = &base_path;
            async move {
                let matches = self.find_records(zone_info, &record, true).await?;
                stream::iter(matches.into_iter().map(|existing| async move {
                    let path = format!("{base_path}/{}", existing.id);
                    self.request::<serde_json::Value, ()>(Method::DELETE, &path, None, None, false)
                        .await?;
                    Ok(relative_record(existing, zone))
                }))
                .buffer_unordered(CONCURRENT_RECORD_REQUESTS)
                .try_collect::<Vec<_>>()
                .await
            }
        }))
        .buffer_unordered(CONCURRENT_RECORD_REQUESTS)
        .try_collect::<Vec<Vec<_>>>()
        .await
        .map(|nested| nested.into_iter().flatten().collect())
    }

    pub async fn find_zone_for_name(&self, name: &str) -> Result<Zone> {
        let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = normalized
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            match self.zone(&candidate).await {
                Ok(zone) => return Ok(zone),
                Err(CloudflareError::ZoneNotUnique { count: 0, .. }) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(CloudflareError::ZoneNotFound(normalized))
    }

    async fn zone(&self, zone: &str) -> Result<Zone> {
        let zone = normalize_zone(zone);
        let cell = {
            let mut zones = self.zones.lock().await;
            zones
                .entry(zone.clone())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };
        cell.get_or_try_init(|| async {
            let query = [("name", zone.clone())];
            let response: ApiResult<Vec<Zone>> = self
                .request::<_, ()>(Method::GET, "/zones", Some(&query), None, true)
                .await?;
            if response.result.len() != 1 {
                return Err(CloudflareError::ZoneNotUnique {
                    zone,
                    count: response.result.len(),
                });
            }
            Ok(response.result.into_iter().next().expect("length checked"))
        })
        .await
        .cloned()
    }

    async fn find_records(
        &self,
        zone: &Zone,
        record: &DnsRecord,
        match_content: bool,
    ) -> Result<Vec<DnsRecord>> {
        let kind = record.kind.to_ascii_uppercase();
        let name = absolute_name(&record.name, &zone.name);
        let mut query = vec![("type", kind.clone()), ("name", name)];
        if match_content
            && !matches!(kind.as_str(), "TXT" | "SRV" | "HTTPS" | "SVCB")
            && !record.content.is_empty()
        {
            query.push((
                "content.exact",
                api_record(record.clone(), &zone.name).content,
            ));
        }
        let path = format!("/zones/{}/dns_records", zone.id);
        let mut records = Vec::new();
        let mut page = 1;
        loop {
            let mut page_query = query.clone();
            page_query.extend([
                ("page", page.to_string()),
                ("per_page", PAGE_SIZE.to_string()),
            ]);
            let response: ApiResult<Vec<DnsRecord>> = self
                .request(Method::GET, &path, Some(&page_query), None::<&()>, false)
                .await?;
            let done = last_page(response.info.as_ref(), page, response.result.len());
            for candidate in response.result {
                if match_content && !record.content.is_empty() {
                    let exact = if kind == "TXT" {
                        decode_txt(&candidate.content)? == record.content
                    } else if matches!(kind.as_str(), "CNAME" | "NS" | "MX") {
                        candidate
                            .content
                            .trim_end_matches('.')
                            .eq_ignore_ascii_case(record.content.trim_end_matches('.'))
                    } else {
                        candidate.content == record.content
                    };
                    if !exact {
                        continue;
                    }
                }
                records.push(candidate);
            }
            if done {
                return Ok(records);
            }
            page += 1;
        }
    }

    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        path: &str,
        query: Option<&[(&str, String)]>,
        body: Option<B>,
        zone_auth: bool,
    ) -> Result<ApiResult<T>> {
        let body = body.map(|value| serde_json::to_vec(&value)).transpose()?;
        let token = if zone_auth {
            self.config
                .zone_token
                .as_deref()
                .filter(|token| !token.is_empty())
                .unwrap_or(&self.config.api_token)
        } else {
            &self.config.api_token
        };
        let url = format!(
            "{}/{}",
            self.config.api_base.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut last_transport_error = None;

        for attempt in 0..=self.config.retries {
            let mut request = self
                .client
                .request(method.clone(), &url)
                .header(AUTHORIZATION, format!("Bearer {token}"));
            if let Some(query) = query {
                request = request.query(query);
            }
            if let Some(body) = &body {
                request = request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.clone());
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    let retry_after = response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    let bytes = response.bytes().await?;
                    if attempt < self.config.retries
                        && (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                    {
                        let delay = retry_after
                            .unwrap_or_else(|| Duration::from_millis(100_u64 << attempt.min(7)))
                            .min(Duration::from_secs(10));
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    let envelope: Envelope<T> =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            CloudflareError::InvalidResponse(format!("HTTP {status}: {error}"))
                        })?;
                    if !status.is_success() || !envelope.errors.is_empty() || !envelope.success {
                        let messages = if envelope.errors.is_empty() {
                            "unspecified API error".to_owned()
                        } else {
                            envelope
                                .errors
                                .iter()
                                .map(|error| format!("{} ({})", error.message, error.code))
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        return Err(CloudflareError::Api { status, messages });
                    }
                    return Ok(ApiResult {
                        result: envelope.result.ok_or_else(|| {
                            CloudflareError::InvalidResponse("missing result".to_owned())
                        })?,
                        info: envelope.result_info,
                    });
                }
                Err(error) => {
                    if attempt >= self.config.retries
                        || !error.is_timeout() && !error.is_connect() && !error.is_request()
                    {
                        return Err(CloudflareError::Transport(error));
                    }
                    last_transport_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(100_u64 << attempt.min(7))).await;
                }
            }
        }
        Err(CloudflareError::Transport(
            last_transport_error.expect("retry loop always executes"),
        ))
    }
}

pub fn valid_cloudflare_token(token: &str) -> bool {
    let legacy = (35..=50).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    let modern = token
        .strip_prefix("cfut_")
        .or_else(|| token.strip_prefix("cfat_"))
        .is_some_and(|suffix| {
            (32..=256).contains(&suffix.len())
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        });
    legacy || modern
}

pub fn encode_txt(text: &str) -> String {
    if text.is_empty() {
        return "\"\"".to_owned();
    }
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(bytes.len() + bytes.len() / 255 * 2 + 2);
    for (index, chunk) in bytes.chunks(255).enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push('"');
        for &byte in chunk {
            match byte {
                b'"' => output.push_str("\\\""),
                b'\\' => output.push_str("\\\\"),
                0x20..=0x7e => output.push(char::from(byte)),
                _ => output.push_str(&format!("\\{byte:03}")),
            }
        }
        output.push('"');
    }
    output
}

pub fn decode_txt(content: &str) -> Result<String> {
    if !content.starts_with('"') {
        return Ok(content.to_owned());
    }
    let bytes = content.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        if bytes[index] != b'"' {
            return Err(CloudflareError::MalformedTxt(format!(
                "unexpected byte at offset {index}"
            )));
        }
        index += 1;
        let mut closed = false;
        while index < bytes.len() {
            match bytes[index] {
                b'"' => {
                    index += 1;
                    closed = true;
                    break;
                }
                b'\\' => {
                    if index + 1 >= bytes.len() {
                        return Err(CloudflareError::MalformedTxt(
                            "trailing backslash".to_owned(),
                        ));
                    }
                    if bytes[index + 1].is_ascii_digit() {
                        if index + 3 >= bytes.len() {
                            return Err(CloudflareError::MalformedTxt(format!(
                                "incomplete decimal escape at offset {index}"
                            )));
                        }
                        let digits = &bytes[index + 1..index + 4];
                        if !digits.iter().all(u8::is_ascii_digit) {
                            return Err(CloudflareError::MalformedTxt(format!(
                                "invalid decimal escape at offset {index}"
                            )));
                        }
                        let value = u16::from(digits[0] - b'0') * 100
                            + u16::from(digits[1] - b'0') * 10
                            + u16::from(digits[2] - b'0');
                        if value > 255 {
                            return Err(CloudflareError::MalformedTxt(format!(
                                "decimal escape {value} is out of range"
                            )));
                        }
                        output.push(value as u8);
                        index += 4;
                    } else {
                        output.push(bytes[index + 1]);
                        index += 2;
                    }
                }
                byte => {
                    output.push(byte);
                    index += 1;
                }
            }
        }
        if !closed {
            return Err(CloudflareError::MalformedTxt(
                "unterminated quoted string".to_owned(),
            ));
        }
    }
    String::from_utf8(output)
        .map_err(|error| CloudflareError::MalformedTxt(format!("TXT value is not UTF-8: {error}")))
}

fn api_record(mut record: DnsRecord, zone: &str) -> DnsRecord {
    record.id.clear();
    record.kind = record.kind.to_ascii_uppercase();
    record.name = absolute_name(&record.name, zone);
    if record.kind == "TXT" {
        record.content = encode_txt(&record.content);
    } else if matches!(record.kind.as_str(), "CNAME" | "NS" | "MX") {
        record.content = record.content.trim_end_matches('.').to_owned();
    }
    record
}

fn relative_record(mut record: DnsRecord, zone: &str) -> DnsRecord {
    record.name = relative_name(&record.name, zone);
    if record.kind == "TXT"
        && let Ok(content) = decode_txt(&record.content)
    {
        record.content = content;
    }
    record
}

fn normalize_zone(zone: &str) -> String {
    zone.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn absolute_name(name: &str, zone: &str) -> String {
    let name = name.trim().trim_end_matches('.');
    let zone = normalize_zone(zone);
    if name.is_empty() || name == "@" || name.eq_ignore_ascii_case(&zone) {
        zone
    } else if name.to_ascii_lowercase().ends_with(&format!(".{zone}")) {
        name.to_owned()
    } else {
        format!("{name}.{zone}")
    }
}

fn relative_name(name: &str, zone: &str) -> String {
    let name = name.trim().trim_end_matches('.');
    let zone = normalize_zone(zone);
    if name.eq_ignore_ascii_case(&zone) {
        "@".to_owned()
    } else if name.len() > zone.len()
        && name.as_bytes()[name.len() - zone.len() - 1] == b'.'
        && name[name.len() - zone.len()..].eq_ignore_ascii_case(&zone)
    {
        name[..name.len() - zone.len() - 1].to_owned()
    } else {
        name.to_owned()
    }
}

fn last_page(info: Option<&ResultInfo>, page: u32, count: usize) -> bool {
    let Some(info) = info else {
        return true;
    };
    info.per_page == 0
        || count == 0
        || u64::from(page) * u64::from(info.per_page) >= info.total_count
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use http_body_util::BodyExt;
    use hyper::{body::Incoming, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::*;

    type CapturedRequest = (String, String, Option<String>, String);

    struct MockCloudflare {
        base: String,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        zone_requests: Arc<AtomicUsize>,
    }

    async fn mock_cloudflare() -> MockCloudflare {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let zone_requests = Arc::new(AtomicUsize::new(0));
        let task_requests = requests.clone();
        let task_zone_requests = zone_requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let requests = task_requests.clone();
                let zone_requests = task_zone_requests.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: hyper::Request<Incoming>| {
                        let requests = requests.clone();
                        let zone_requests = zone_requests.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let path = parts.uri.path().to_owned();
                            let query = parts.uri.query().unwrap_or_default().to_owned();
                            let body = String::from_utf8(
                                body.collect().await.unwrap().to_bytes().to_vec(),
                            )
                            .unwrap();
                            let auth = parts
                                .headers
                                .get(AUTHORIZATION)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_owned();
                            requests.lock().await.push((
                                parts.method.to_string(),
                                path.clone(),
                                Some(query.clone()),
                                auth,
                            ));
                            let result = match (parts.method.as_str(), path.as_str()) {
                                ("GET", "/zones") => {
                                    zone_requests.fetch_add(1, Ordering::Relaxed);
                                    if query.contains("name=missing.example") {
                                        json!([])
                                    } else {
                                        json!([{"id": "zone-id", "name": "example.com", "status": "active"}])
                                    }
                                }
                                ("GET", "/zones/zone-id/dns_records")
                                    if query.contains("page=") && !query.contains("type=") =>
                                {
                                    if query.contains("page=2") {
                                        json!([{"id":"third","type":"A","name":"third.example.com","content":"192.0.2.3","ttl":60}])
                                    } else {
                                        json!([
                                            {"id":"first","type":"A","name":"first.example.com","content":"192.0.2.1","ttl":60},
                                            {"id":"second","type":"A","name":"second.example.com","content":"192.0.2.2","ttl":60}
                                        ])
                                    }
                                }
                                ("GET", "/zones/zone-id/dns_records")
                                    if query.contains("type=TXT") =>
                                {
                                    json!([
                                        {"id":"old","type":"TXT","name":"_acme-challenge.example.com","content":"\"other\"","ttl":120},
                                        {"id":"wanted","type":"TXT","name":"_acme-challenge.example.com","content":"\"dns-challenge\"","ttl":120}
                                    ])
                                }
                                ("GET", "/zones/zone-id/dns_records")
                                    if query.contains("type=A") =>
                                {
                                    json!([{"id":"a-id","type":"A","name":"www.example.com","content":"192.0.2.1","ttl":60}])
                                }
                                ("POST", "/zones/zone-id/dns_records") => {
                                    serde_json::from_str::<Value>(&body).unwrap()
                                }
                                ("PATCH", "/zones/zone-id/dns_records/a-id") => {
                                    serde_json::from_str::<Value>(&body).unwrap()
                                }
                                ("DELETE", "/zones/zone-id/dns_records/wanted") => {
                                    json!({"id":"wanted"})
                                }
                                ("DELETE", "/zones/zone-id/dns_records/a-id") => {
                                    json!({"id":"a-id"})
                                }
                                ("GET", "/error") => {
                                    return Ok::<_, Infallible>(json_response(
                                        StatusCode::FORBIDDEN,
                                        json!({"success":false,"errors":[{"code":10000,"message":"authentication error"}]}),
                                    ));
                                }
                                _ => json!(null),
                            };
                            let info = if query.contains("page=") && !query.contains("type=") {
                                let page = if query.contains("page=2") { 2 } else { 1 };
                                json!({"page":page,"per_page":2,"count":2,"total_count":3})
                            } else {
                                Value::Null
                            };
                            Ok::<_, Infallible>(json_response(
                                StatusCode::OK,
                                json!({"success":true,"errors":[],"result":result,"result_info":info}),
                            ))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        MockCloudflare {
            base: format!("http://{address}"),
            requests,
            zone_requests,
        }
    }

    fn json_response(
        status: StatusCode,
        value: Value,
    ) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
        hyper::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                value.to_string(),
            )))
            .unwrap()
    }

    fn client(mock: &MockCloudflare) -> Cloudflare {
        let mut config = CloudflareConfig::new("abcdefghijklmnopqrstuvwxyzABCDEFGHI");
        config.api_base = mock.base.clone();
        config.zone_token = Some("zone_abcdefghijklmnopqrstuvwxyzABCDE".to_owned());
        config.timeout = Duration::from_secs(5);
        config.retries = 0;
        Cloudflare::new(config).unwrap()
    }

    #[test]
    fn token_validation_matches_plugin_formats() {
        assert!(valid_cloudflare_token(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHI"
        ));
        assert!(valid_cloudflare_token(&format!("cfut_{}", "a".repeat(32))));
        assert!(valid_cloudflare_token(&format!(
            "cfat_{}",
            "A_9-".repeat(64)
        )));
        assert!(!valid_cloudflare_token("cfut_short"));
        assert!(!valid_cloudflare_token("global@example.com"));
        assert!(!valid_cloudflare_token("{env.CF_API_TOKEN}"));
    }

    #[test]
    fn txt_encoding_matches_rfc1035_presentation() {
        assert_eq!(encode_txt(""), "\"\"");
        assert_eq!(encode_txt("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(encode_txt("a\nб"), "\"a\\010\\208\\177\"");
        let long = "a".repeat(511);
        assert_eq!(
            encode_txt(&long),
            format!("\"{}\" \"{}\" \"a\"", "a".repeat(255), "a".repeat(255))
        );
        for value in ["", "simple", "quote \" slash \\", &long] {
            assert_eq!(decode_txt(&encode_txt(value)).unwrap(), value);
        }
        assert_eq!(decode_txt("unquoted\\255").unwrap(), "unquoted\\255");
        assert!(decode_txt("\"unterminated").is_err());
        assert!(decode_txt("\"\\999\"").is_err());
    }

    #[test]
    fn dns_names_handle_roots_subdomains_and_foreign_domains() {
        assert_eq!(absolute_name("@", "example.com"), "example.com");
        assert_eq!(absolute_name("www", "Example.COM."), "www.example.com");
        assert_eq!(
            absolute_name("www.example.com.", "example.com"),
            "www.example.com"
        );
        assert_eq!(relative_name("www.example.com", "example.com"), "www");
        assert_eq!(relative_name("example.com.", "example.com"), "@");
        assert_eq!(
            relative_name("notexample.com", "example.com"),
            "notexample.com"
        );
    }

    #[tokio::test]
    async fn lists_pages_and_reuses_cached_zones() {
        let mock = mock_cloudflare().await;
        let client = client(&mock);
        let zones = client.list_zones().await.unwrap();
        assert_eq!(zones[0].name, "example.com");
        assert_eq!(mock.zone_requests.load(Ordering::Relaxed), 2);
        mock.zone_requests.store(0, Ordering::Relaxed);
        client.get_records("example.com.").await.unwrap();
        client.get_records("EXAMPLE.COM").await.unwrap();
        assert_eq!(mock.zone_requests.load(Ordering::Relaxed), 1);
        assert!(mock.requests.lock().await.iter().any(|(_, _, query, _)| {
            query
                .as_deref()
                .is_some_and(|query| query.contains("per_page=100"))
        }));
        assert!(
            mock.requests
                .lock()
                .await
                .iter()
                .all(|(_, path, _, auth)| if path == "/zones" {
                    auth == "Bearer zone_abcdefghijklmnopqrstuvwxyzABCDE"
                } else {
                    auth == "Bearer abcdefghijklmnopqrstuvwxyzABCDEFGHI"
                })
        );
    }

    #[tokio::test]
    async fn append_encodes_txt_and_deletes_only_matching_content() {
        let mock = mock_cloudflare().await;
        let client = client(&mock);
        let created = client
            .append_records(
                "example.com",
                vec![DnsRecord::txt("_acme-challenge", "dns-challenge")],
            )
            .await
            .unwrap();
        assert_eq!(created[0].content, "dns-challenge");
        assert_eq!(created[0].name, "_acme-challenge");
        let requests = mock.requests.lock().await;
        assert!(
            !requests
                .iter()
                .any(|(_, _, _, auth)| auth.contains("dns-challenge"))
        );
        drop(requests);
        let deleted = client
            .delete_records(
                "example.com",
                vec![DnsRecord::txt("_acme-challenge", "dns-challenge")],
            )
            .await
            .unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].id, "wanted");
    }

    #[tokio::test]
    async fn set_updates_without_deleting_existing_records() {
        let mock = mock_cloudflare().await;
        let client = client(&mock);
        let updated = client
            .set_records("example.com", vec![DnsRecord::new("A", "www", "192.0.2.2")])
            .await
            .unwrap();
        assert_eq!(updated[0].name, "www");
        assert!(
            mock.requests
                .lock()
                .await
                .iter()
                .any(|(method, path, _, _)| method == "PATCH"
                    && path == "/zones/zone-id/dns_records/a-id")
        );
        assert!(
            !mock
                .requests
                .lock()
                .await
                .iter()
                .any(|(method, _, _, _)| method == "DELETE")
        );
    }

    #[tokio::test]
    async fn locates_a_zone_for_nested_names() {
        let mock = mock_cloudflare().await;
        let client = client(&mock);
        let zone = client.find_zone_for_name("a.b.example.com").await.unwrap();
        assert_eq!(zone.id, "zone-id");
    }
}
