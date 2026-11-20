use std::{
    collections::{HashMap, VecDeque},
    fs::{File, Metadata},
    io,
    ops::Range,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use thiserror::Error;

use crate::config::{Config, SiteConfig};

#[derive(Debug, Error)]
pub enum StaticError {
    #[error("invalid static path")]
    BadRequest,
    #[error("static file not found")]
    NotFound,
    #[error("static path is forbidden")]
    Forbidden,
    #[error("static file I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl StaticError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::BadRequest => "invalid path\n",
            Self::NotFound => "not found\n",
            Self::Forbidden => "invalid path\n",
            Self::Io(_) => "could not read file\n",
        }
    }
}

#[cfg(unix)]
const MAX_CACHED_BODY: usize = 16 * 1024;

pub struct CachedFile {
    pub file: Arc<File>,
    pub(crate) body: Option<Bytes>,
    pub relative: PathBuf,
    pub length: u64,
    pub content_type: HeaderValue,
    etag: HeaderValue,
    last_modified: Option<HeaderValue>,
    identity: FileIdentity,
    modified: Option<SystemTime>,
    pub response_header: bytes::Bytes,
    pub response_header_close: bytes::Bytes,
    opened_at: Instant,
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    length: u64,
    modified: Option<Duration>,
    #[cfg(unix)]
    inode: (u64, u64, i64, i64),
}

impl From<&Metadata> for FileIdentity {
    fn from(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            length: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok()),
            #[cfg(unix)]
            inode: (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        }
    }
}

pub(crate) enum FileReply {
    Full,
    Partial(Range<u64>),
    Status(StatusCode),
}

pub(crate) const REQUEST_CONDITIONS: [HeaderName; 6] = [
    header::IF_MATCH,
    header::IF_UNMODIFIED_SINCE,
    header::IF_NONE_MATCH,
    header::IF_MODIFIED_SINCE,
    header::IF_RANGE,
    header::RANGE,
];

impl CachedFile {
    pub(crate) fn evaluate(&self, headers: &HeaderMap, head: bool) -> FileReply {
        if headers.contains_key(header::IF_MATCH) {
            if !headers
                .get_all(header::IF_MATCH)
                .iter()
                .any(|value| etag_matches(value, &self.etag, false))
            {
                return FileReply::Status(StatusCode::PRECONDITION_FAILED);
            }
        } else if self
            .date_test(headers, header::IF_UNMODIFIED_SINCE)
            .is_some_and(|unchanged| !unchanged)
        {
            return FileReply::Status(StatusCode::PRECONDITION_FAILED);
        }
        if headers.contains_key(header::IF_NONE_MATCH) {
            if headers
                .get_all(header::IF_NONE_MATCH)
                .iter()
                .any(|value| etag_matches(value, &self.etag, true))
            {
                return FileReply::Status(StatusCode::NOT_MODIFIED);
            }
        } else if self.date_test(headers, header::IF_MODIFIED_SINCE) == Some(true) {
            return FileReply::Status(StatusCode::NOT_MODIFIED);
        }
        if !head && let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
            if let Some(value) = headers.get(header::IF_RANGE) {
                let matches = value == self.etag
                    || self
                        .last_modified
                        .as_ref()
                        .is_some_and(|date| value == date);
                if !matches {
                    return FileReply::Full;
                }
            }
            if let Some(reply) = single_range(range, self.length) {
                return reply;
            }
        }
        FileReply::Full
    }

    fn date_test(&self, headers: &HeaderMap, name: HeaderName) -> Option<bool> {
        let date = httpdate::parse_http_date(headers.get(name)?.to_str().ok()?).ok()?;
        let modified = self.modified?;
        Some(modified <= date)
    }

    pub(crate) fn response_headers(&self, extra: &HeaderMap, reply: &FileReply) -> HeaderMap {
        let mut headers = extra.clone();
        headers.remove(header::TRANSFER_ENCODING);
        headers.remove(header::CONNECTION);
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::CONTENT_RANGE);
        headers.remove(header::LAST_MODIFIED);
        headers.insert(header::ETAG, self.etag.clone());
        if let Some(date) = &self.last_modified {
            headers.insert(header::LAST_MODIFIED, date.clone());
        }
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        match reply {
            FileReply::Full | FileReply::Partial(_) => {
                headers
                    .entry(header::CONTENT_TYPE)
                    .or_insert_with(|| self.content_type.clone());
                let len = if let FileReply::Partial(range) = reply {
                    headers.insert(
                        header::CONTENT_RANGE,
                        content_range(format!(
                            "bytes {}-{}/{}",
                            range.start,
                            range.end - 1,
                            self.length
                        )),
                    );
                    range.end - range.start
                } else {
                    self.length
                };
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            }
            FileReply::Status(status) => {
                if *status != StatusCode::NOT_MODIFIED {
                    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
                }
                if *status == StatusCode::RANGE_NOT_SATISFIABLE {
                    headers.insert(
                        header::CONTENT_RANGE,
                        content_range(format!("bytes */{}", self.length)),
                    );
                }
            }
        }
        headers
    }
}

impl FileReply {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Full => StatusCode::OK,
            Self::Partial(_) => StatusCode::PARTIAL_CONTENT,
            Self::Status(status) => *status,
        }
    }
}

fn content_range(value: String) -> HeaderValue {
    HeaderValue::from_str(&value).expect("valid content range")
}

fn etag_matches(value: &HeaderValue, etag: &HeaderValue, weak: bool) -> bool {
    let Ok(values) = value.to_str() else {
        return false;
    };
    let Ok(tag) = etag.to_str() else { return false };
    values.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate == tag || weak && candidate.strip_prefix("W/") == Some(tag)
    })
}

fn single_range(value: &str, length: u64) -> Option<FileReply> {
    let (unit, value) = value.split_once('=')?;
    if !unit.eq_ignore_ascii_case("bytes") || value.contains(',') {
        return None;
    }
    let (first, last) = value.trim().split_once('-')?;
    let unsatisfiable = Some(FileReply::Status(StatusCode::RANGE_NOT_SATISFIABLE));
    let (start, end) = if first.is_empty() {
        let suffix = range_number(last)?;
        if suffix == 0 || length == 0 {
            return unsatisfiable;
        }
        (length.saturating_sub(suffix), length)
    } else {
        let start = range_number(first)?;
        let inclusive = if last.is_empty() {
            u64::MAX
        } else {
            range_number(last)?
        };
        if inclusive < start {
            return None;
        }
        if start >= length {
            return unsatisfiable;
        }
        (start, inclusive.saturating_add(1).min(length))
    };
    Some(FileReply::Partial(start..end))
}

fn range_number(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(value.parse().unwrap_or(u64::MAX))
}

fn validators(identity: &FileIdentity) -> (HeaderValue, Option<HeaderValue>, Option<SystemTime>) {
    let stamp = identity.modified.map_or(0, |time| time.as_nanos());
    #[cfg(unix)]
    let inode = {
        let (device, inode, seconds, nanos) = identity.inode;
        format!("{device:x}-{inode:x}-{seconds:x}-{nanos:x}")
    };
    #[cfg(not(unix))]
    let inode = String::new();
    let etag = HeaderValue::from_str(&format!("\"{inode}-{stamp:x}-{:x}\"", identity.length))
        .expect("valid etag");
    let modified = identity
        .modified
        .filter(|time| time.as_secs() < 253402300800)
        .and_then(|time| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(time.as_secs())));
    let last_modified = modified.map(|time| {
        HeaderValue::from_str(&httpdate::fmt_http_date(time)).expect("valid HTTP date")
    });
    (etag, last_modified, modified)
}

struct Cache {
    entries: HashMap<PathBuf, Arc<CachedFile>>,
    insertion_order: VecDeque<PathBuf>,
}

pub struct StaticFiles {
    root: File,
    protected: ProtectedPaths,
    indexes: Vec<PathBuf>,
    pub response_headers: Arc<HeaderMap>,
    ttl: Duration,
    capacity: usize,
    cache: Mutex<Cache>,
}

impl StaticFiles {
    pub fn new(config: &SiteConfig, global: &Config) -> Result<Option<Arc<Self>>, StaticError> {
        let Some(root) = &config.root else {
            return Ok(None);
        };
        Self::with_root(root, &config.index, &config.response_headers, global).map(Some)
    }

    pub(crate) fn with_root(
        path: &Path,
        index: &[String],
        headers: &std::collections::BTreeMap<String, String>,
        global: &Config,
    ) -> Result<Arc<Self>, StaticError> {
        let path = path.canonicalize()?;
        let protected = ProtectedPaths::new(&path, global)?;
        let root = open_root(&path)?;
        let response_headers = headers
            .iter()
            .filter_map(|(name, value)| {
                let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
                let value = HeaderValue::from_str(value).ok()?;
                Some((name, value))
            })
            .collect();
        Ok(Arc::new(Self {
            root,
            protected,
            indexes: if index.is_empty() {
                vec![PathBuf::from("index.html"), PathBuf::from("index.htm")]
            } else {
                index.iter().map(PathBuf::from).collect()
            },
            response_headers: Arc::new(response_headers),
            ttl: Duration::from_secs(global.static_cache_ttl_secs),
            capacity: global.static_cache_entries,
            cache: Mutex::new(Cache {
                entries: HashMap::new(),
                insertion_order: VecDeque::new(),
            }),
        }))
    }

    pub async fn resolve(self: &Arc<Self>, uri_path: &str) -> Result<Arc<CachedFile>, StaticError> {
        let relative = if uri_path.contains('%') {
            safe_relative_path(uri_path)
        } else {
            raw_relative_path(uri_path)
        }
        .ok_or(StaticError::BadRequest)?;
        if self.protected.contains(&relative) {
            return Err(StaticError::NotFound);
        }
        if let Some(file) = self.cached(&relative)? {
            return Ok(file);
        }
        let files = self.clone();
        tokio::task::spawn_blocking(move || {
            let file = files.open(&relative)?;
            files.insert(relative, file.clone());
            Ok(file)
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
    }

    pub(crate) fn open_for_streaming(
        &self,
        cached: &Arc<CachedFile>,
    ) -> io::Result<(File, Arc<CachedFile>)> {
        let file = open_at(&self.root, &cached.relative)?;
        let metadata = file.metadata()?;
        if self.protected.contains_metadata(&metadata) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "not a file"));
        }
        if !metadata.is_file() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "not a file"));
        }
        let current = if FileIdentity::from(&metadata) == cached.identity {
            cached.clone()
        } else {
            self.entry(file.try_clone()?, cached.relative.clone(), metadata, false)
                .map_err(io::Error::other)?
        };
        Ok((file, current))
    }

    fn cached(&self, relative: &Path) -> Result<Option<Arc<CachedFile>>, StaticError> {
        let candidate = {
            self.cache
                .lock()
                .map_err(|_| io::Error::other("static cache lock poisoned"))?
                .entries
                .get(relative)
                .cloned()
        };
        let Some(file) = candidate else {
            return Ok(None);
        };
        Ok((file.opened_at.elapsed() < self.ttl).then_some(file))
    }

    fn open(&self, relative: &Path) -> Result<Arc<CachedFile>, StaticError> {
        let file = open_at(&self.root, relative).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => StaticError::NotFound,
            io::ErrorKind::PermissionDenied => StaticError::Forbidden,
            _ if error.raw_os_error() == Some(libc::ELOOP) => StaticError::Forbidden,
            _ => error.into(),
        })?;
        let metadata = file.metadata()?;
        if metadata.is_dir() {
            for index in &self.indexes {
                let relative = relative.join(index);
                if self.protected.contains(&relative) {
                    continue;
                }
                match open_at(&self.root, &relative) {
                    Ok(file) => {
                        let metadata = file.metadata()?;
                        if metadata.is_file() {
                            return self.entry(file, relative, metadata, true);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            return Err(StaticError::NotFound);
        }
        if !metadata.is_file() {
            return Err(StaticError::NotFound);
        }
        self.entry(file, relative.to_path_buf(), metadata, true)
    }

    fn entry(
        &self,
        file: File,
        relative: PathBuf,
        metadata: Metadata,
        cacheable: bool,
    ) -> Result<Arc<CachedFile>, StaticError> {
        if self.protected.contains_metadata(&metadata) {
            return Err(StaticError::NotFound);
        }
        let identity = FileIdentity::from(&metadata);
        #[cfg(unix)]
        let body = if cacheable && self.capacity != 0 && !self.ttl.is_zero() {
            use std::os::unix::fs::FileExt;

            usize::try_from(identity.length)
                .ok()
                .filter(|&length| length <= MAX_CACHED_BODY)
                .and_then(|length| {
                    let mut body = vec![0; length];
                    file.read_exact_at(&mut body, 0).ok()?;
                    let current = file.metadata().ok()?;
                    (FileIdentity::from(&current) == identity).then(|| Bytes::from(body))
                })
        } else {
            None
        };
        #[cfg(not(unix))]
        let body = {
            let _ = cacheable;
            None
        };
        let content_type = HeaderValue::from_str(
            mime_guess::from_path(&relative)
                .first_or_octet_stream()
                .essence_str(),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let (etag, last_modified, modified) = validators(&identity);
        let configured_type = self
            .response_headers
            .get(header::CONTENT_TYPE)
            .unwrap_or(&content_type);
        let mut response_prefix = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nAccept-Ranges: bytes\r\nETag: {}\r\n",
            metadata.len(),
            configured_type
                .to_str()
                .unwrap_or("application/octet-stream"),
            etag.to_str().unwrap(),
        );
        use std::fmt::Write;
        if let Some(date) = &last_modified {
            write!(
                response_prefix,
                "Last-Modified: {}\r\n",
                date.to_str().unwrap()
            )
            .expect("write to string");
        }
        for (name, value) in self.response_headers.iter() {
            if !matches!(
                name.as_str(),
                "content-length"
                    | "connection"
                    | "transfer-encoding"
                    | "content-type"
                    | "accept-ranges"
                    | "etag"
                    | "last-modified"
                    | "content-range"
            ) && let Ok(value) = value.to_str()
            {
                write!(response_prefix, "{}: {value}\r\n", name.as_str()).expect("write to string");
            }
        }
        let response_header_close =
            bytes::Bytes::from(format!("{response_prefix}Connection: close\r\n\r\n"));
        response_prefix.push_str("\r\n");
        Ok(Arc::new(CachedFile {
            file: Arc::new(file),
            body,
            relative,
            length: metadata.len(),
            content_type,
            etag,
            identity,
            last_modified,
            modified,
            response_header: bytes::Bytes::from(response_prefix),
            response_header_close,
            opened_at: Instant::now(),
        }))
    }

    fn insert(&self, key: PathBuf, file: Arc<CachedFile>) {
        if self.capacity == 0 {
            return;
        }
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.entries.insert(key.clone(), file).is_some()
            && let Some(position) = cache.insertion_order.iter().position(|entry| *entry == key)
        {
            cache.insertion_order.remove(position);
        }
        cache.insertion_order.push_back(key);
        while cache.entries.len() > self.capacity {
            let Some(oldest) = cache.insertion_order.pop_front() else {
                break;
            };
            cache.entries.remove(&oldest);
        }
    }
}

#[derive(Default)]
struct ProtectedPaths {
    files: Vec<PathBuf>,
    data_dir: Option<PathBuf>,
    #[cfg(unix)]
    identities: Vec<(u64, u64)>,
}

impl ProtectedPaths {
    fn new(root: &Path, config: &Config) -> io::Result<Self> {
        let mut protected = Self::default();
        for path in config.source_files.iter().chain(
            config
                .sites
                .iter()
                .flat_map(|site| site.certificate_file.iter().chain(&site.private_key_file)),
        ) {
            if let Ok(path) = path.canonicalize() {
                #[cfg(unix)]
                if let Ok(metadata) = std::fs::metadata(&path) {
                    use std::os::unix::fs::MetadataExt;
                    protected.identities.push((metadata.dev(), metadata.ino()));
                }
                if let Ok(relative) = path.strip_prefix(root) {
                    protected.files.push(relative.to_owned());
                }
            }
        }
        let data = absolute_normalized(&config.data_dir)?;
        let data = data.canonicalize().unwrap_or(data);
        if root.starts_with(&data) {
            protected.data_dir = Some(PathBuf::new());
        } else if let Ok(relative) = data.strip_prefix(root) {
            protected.data_dir = Some(relative.to_owned());
        }
        Ok(protected)
    }

    fn contains(&self, path: &Path) -> bool {
        self.files.iter().any(|file| file == path)
            || self
                .data_dir
                .as_ref()
                .is_some_and(|data| path.starts_with(data))
    }

    fn contains_metadata(&self, _metadata: &Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            self.identities
                .contains(&(_metadata.dev(), _metadata.ino()))
        }
        #[cfg(not(unix))]
        false
    }
}

fn absolute_normalized(path: &Path) -> io::Result<PathBuf> {
    let mut result = PathBuf::new();
    for part in std::path::absolute(path)?.components() {
        if part == Component::ParentDir {
            result.pop();
        } else if part != Component::CurDir {
            result.push(part);
        }
    }
    Ok(result)
}

pub(crate) struct FileLookup(File, ProtectedPaths);

impl FileLookup {
    pub(crate) fn new(root: &Path, config: &Config) -> io::Result<Self> {
        let root = root.canonicalize()?;
        Ok(Self(open_root(&root)?, ProtectedPaths::new(&root, config)?))
    }

    pub(crate) fn candidates(&self, path: &str, strict: bool) -> Vec<(String, Metadata)> {
        if !path.contains(['*', '?', '[', '\\']) {
            return self
                .metadata(path, strict)
                .into_iter()
                .map(|metadata| (path.to_owned(), metadata))
                .collect();
        }
        let mut paths = Vec::new();
        let parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
        if parts.len() > 64 {
            return paths;
        }
        let patterns = parts
            .iter()
            .map(|part| lookup_pattern(part))
            .collect::<Option<Vec<_>>>();
        let Some(patterns) = patterns else {
            return paths;
        };
        let mut remaining = 50_000;
        self.walk(&patterns, &mut PathBuf::new(), &mut remaining, &mut paths);
        paths.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let directory = path.ends_with('/');
        paths
            .into_iter()
            .filter_map(|(mut path, metadata)| {
                if !file_kind_matches(&metadata, strict, directory) {
                    return None;
                }
                if directory && path != "/" {
                    path.push('/');
                }
                Some((path, metadata))
            })
            .collect()
    }

    fn metadata(&self, path: &str, strict: bool) -> Option<Metadata> {
        let relative = safe_relative_path(path)?;
        if self.1.contains(&relative) {
            return None;
        }
        let metadata = open_at(&self.0, &relative).ok()?.metadata().ok()?;
        if self.1.contains_metadata(&metadata) {
            return None;
        }
        file_kind_matches(&metadata, strict, path.ends_with('/')).then_some(metadata)
    }

    fn walk(
        &self,
        segments: &[LookupPattern],
        relative: &mut PathBuf,
        budget: &mut usize,
        matches: &mut Vec<(String, Metadata)>,
    ) {
        if *budget == 0 || matches.len() >= 4096 || self.1.contains(relative) {
            return;
        }
        *budget -= 1;
        let Some((segment, remaining)) = segments.split_first() else {
            if let Some((path, metadata)) = relative.to_str().zip(
                open_at(&self.0, relative)
                    .and_then(|file| file.metadata())
                    .ok(),
            ) {
                if self.1.contains_metadata(&metadata) {
                    return;
                }
                let escaped = percent_encoding::utf8_percent_encode(path, LOOKUP_ENCODE);
                matches.push((format!("/{escaped}"), metadata));
            }
            return;
        };
        match segment {
            LookupPattern::Exact(name) => {
                relative.push(name);
                self.walk(remaining, relative, budget, matches);
                relative.pop();
            }
            LookupPattern::Glob(pattern) => {
                let Ok(dir) = open_at(&self.0, relative) else {
                    return;
                };
                if let Ok(names) = lookup_entries(&dir, budget) {
                    for name in names.into_iter().filter(|name| pattern.matches(name)) {
                        relative.push(name);
                        self.walk(remaining, relative, budget, matches);
                        relative.pop();
                    }
                }
            }
        }
    }
}

const LOOKUP_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b'%')
    .add(b'?')
    .add(b'#')
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`');

fn file_kind_matches(metadata: &Metadata, strict: bool, directory: bool) -> bool {
    if directory {
        metadata.is_dir()
    } else {
        metadata.is_file() || !strict && metadata.is_dir()
    }
}

enum LookupPattern {
    Exact(String),
    Glob(glob::Pattern),
}

fn lookup_pattern(segment: &str) -> Option<LookupPattern> {
    let decoded = percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .ok()?;
    if matches!(decoded.as_ref(), "." | "..") || decoded.contains(['/', '\0']) {
        return None;
    }
    if !segment.contains(['*', '?', '[', '\\']) {
        return Some(LookupPattern::Exact(decoded.into_owned()));
    }
    let mut translated = String::with_capacity(segment.len());
    let mut input = segment;
    while let Some(index) = input.find('%') {
        translated.push_str(&input[..index]);
        let mut end = index;
        while let Some(escape) = input.as_bytes().get(end..end + 3) {
            if escape[0] != b'%' || !escape[1..].iter().all(u8::is_ascii_hexdigit) {
                break;
            }
            end += 3;
        }
        if end == index {
            translated.push('%');
            input = &input[index + 1..];
        } else {
            let literal = percent_encoding::percent_decode_str(&input[index..end])
                .decode_utf8()
                .ok()?;
            translated.push_str(&glob::Pattern::escape(&literal));
            input = &input[end..];
        }
    }
    translated.push_str(input);
    glob::Pattern::new(&translated)
        .ok()
        .map(LookupPattern::Glob)
}

#[cfg(unix)]
fn lookup_entries(directory: &File, budget: &mut usize) -> io::Result<Vec<String>> {
    use std::{
        ffi::CStr,
        os::fd::{AsRawFd, IntoRawFd},
    };

    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    use std::os::fd::FromRawFd;
    let file = unsafe { File::from_raw_fd(fd) };
    let dir = unsafe { libc::fdopendir(file.as_raw_fd()) };
    if dir.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _fd = file.into_raw_fd();
    let mut names = Vec::new();
    while *budget > 0 {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        *budget -= 1;
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if let Ok(name) = name.to_str()
            && !matches!(name, "." | "..")
        {
            names.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(dir) };
    names.sort_unstable();
    Ok(names)
}

#[cfg(not(unix))]
fn lookup_entries(_directory: &File, _budget: &mut usize) -> io::Result<Vec<String>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure file descriptors require Unix",
    ))
}

fn open_root(path: &Path) -> io::Result<File> {
    let root = File::open(path.canonicalize()?)?;
    if root.metadata()?.is_dir() {
        Ok(root)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "static root is not a directory",
        ))
    }
}

fn raw_relative_path(path: &str) -> Option<PathBuf> {
    if path.contains('\0') {
        return None;
    }
    let relative = Path::new(path.trim_start_matches('/'));
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    Some(relative.to_path_buf())
}

pub fn safe_relative_path(path: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    if decoded.as_bytes().contains(&0) {
        return None;
    }
    let relative = Path::new(decoded.trim_start_matches('/'));
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    Some(relative.to_path_buf())
}

#[cfg(unix)]
fn open_at(root: &File, relative: &Path) -> io::Result<File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };

    let mut directory = root.try_clone()?;
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path escapes static root",
            ));
        };
        let name = CString::new(name.as_bytes())?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if index + 1 < components.len() {
                libc::O_DIRECTORY
            } else {
                libc::O_NONBLOCK
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn open_at(_root: &File, _relative: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure file descriptors require Unix",
    ))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn config(root: PathBuf, ttl: u64) -> Config {
        serde_json::from_value(serde_json::json!({
            "http_addr": "127.0.0.1:0",
            "static_cache_ttl_secs": ttl,
            "sites": [{"hosts":["localhost"],"tls":false,"root":root}]
        }))
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn file_globs_walk_only_non_symlink_paths_and_keep_encoded_stars_literal() {
        let base = std::env::temp_dir().join(format!("raddy-file-glob-{}", std::process::id()));
        let root = base.join("root");
        std::fs::create_dir_all(root.join("safe")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        for path in ["safe/x.txt", "safe/*.txt", "safe/name space.txt"] {
            std::fs::write(root.join(path), "ok").unwrap();
        }
        std::fs::write(base.join("outside/hidden.txt"), "hidden").unwrap();
        std::os::unix::fs::symlink(base.join("outside"), root.join("linked")).unwrap();
        std::os::unix::fs::symlink(base.join("outside/hidden.txt"), root.join("safe/link.txt"))
            .unwrap();
        let files = FileLookup::new(&root, &Config::default()).unwrap();
        let paths = |pattern| {
            files
                .candidates(pattern, true)
                .into_iter()
                .map(|(path, _)| path)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            paths("/*/*.txt"),
            ["/safe/*.txt", "/safe/name%20space.txt", "/safe/x.txt"]
        );
        assert_eq!(paths("/safe/%2A.txt"), ["/safe/%2A.txt"]);
        assert_eq!(paths("/safe/%2A.*"), ["/safe/*.txt"]);
        assert!(paths("/%2e%2e/*").is_empty());
        assert_eq!(paths("/sa*/"), ["/safe/"]);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn single_range_handles_bounds_and_ignores_unsupported_syntax() {
        for (value, expected) in [
            ("bytes=1-3", 1..4),
            ("bytes=7-", 7..10),
            ("bytes=-2", 8..10),
            ("bytes=0-100", 0..10),
        ] {
            assert!(
                matches!(single_range(value, 10), Some(FileReply::Partial(range)) if range == expected)
            );
        }
        for value in ["bytes=10-", "bytes=-0", "bytes=18446744073709551618-"] {
            assert!(matches!(
                single_range(value, 10),
                Some(FileReply::Status(StatusCode::RANGE_NOT_SATISFIABLE))
            ));
        }
        for value in ["bytes=0-1,8-9", "items=1-3", "bytes=5-1", "bytes=+1-"] {
            assert!(single_range(value, 10).is_none());
        }
    }

    #[tokio::test]
    async fn cache_serves_file_and_sanitizes_paths() {
        let root = std::env::temp_dir().join(format!("raddy-static-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), "home").unwrap();
        std::fs::write(root.join("file.txt"), "file").unwrap();
        let config = config(root.clone(), 30);
        let files = StaticFiles::new(&config.sites[0], &config)
            .unwrap()
            .unwrap();
        assert_eq!(files.resolve("/").await.unwrap().length, 4);
        assert_eq!(files.resolve("/file.txt").await.unwrap().length, 4);
        assert_eq!(files.resolve("/file.txt").await.unwrap().length, 4);
        assert_eq!(
            files.resolve("/missing.txt").await.err().unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(files.cache.lock().unwrap().entries.len(), 2);
        for path in ["/../secret", "/a/../../secret", "/a%2f..%2fsecret", "/%00"] {
            assert!(files.resolve(path).await.is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_cannot_escape_static_root() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("raddy-static-symlink-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("secret"), "secret").unwrap();
        symlink("secret", root.join("escape")).unwrap();
        let config = config(root.clone(), 30);
        let files = StaticFiles::new(&config.sites[0], &config)
            .unwrap()
            .unwrap();
        assert!(files.resolve("/escape").await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cache_does_not_grow_without_bound_on_reinsert() {
        let root = std::env::temp_dir().join(format!("raddy-static-growth-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), "old").unwrap();
        let config = config(root.clone(), 0);
        let files = StaticFiles::new(&config.sites[0], &config)
            .unwrap()
            .unwrap();
        for round in 0..50 {
            std::fs::write(root.join("file.txt"), format!("new-{round}")).unwrap();
            let _ = files.resolve("/file.txt").await.unwrap();
        }
        let cache = files.cache.lock().unwrap();
        assert_eq!(
            cache.insertion_order.len(),
            cache.entries.len(),
            "the eviction queue must not grow beyond the number of cached entries"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn small_file_body_is_bounded_by_cache_policy() {
        let root = std::env::temp_dir().join(format!("raddy-static-body-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("small.txt"), "old").unwrap();
        std::fs::write(root.join("large.txt"), vec![0; MAX_CACHED_BODY + 1]).unwrap();
        let mut config = config(root.clone(), 30);
        let files = StaticFiles::new(&config.sites[0], &config)
            .unwrap()
            .unwrap();
        let mut old = files.resolve("/small.txt").await.unwrap();
        assert_eq!(old.body.as_deref(), Some(b"old".as_slice()));
        assert!(files.resolve("/large.txt").await.unwrap().body.is_none());
        std::fs::write(root.join("replacement.txt"), "new").unwrap();
        std::fs::rename(root.join("replacement.txt"), root.join("small.txt")).unwrap();
        assert!(Arc::ptr_eq(
            &old,
            &files.resolve("/small.txt").await.unwrap()
        ));
        let etag = old.etag.clone();
        files
            .cache
            .lock()
            .unwrap()
            .entries
            .remove(Path::new("small.txt"));
        Arc::get_mut(&mut old).unwrap().opened_at -= files.ttl;
        files
            .cache
            .lock()
            .unwrap()
            .entries
            .insert(PathBuf::from("small.txt"), old);
        let new = files.resolve("/small.txt").await.unwrap();
        assert_eq!(new.body.as_deref(), Some(b"new".as_slice()));
        assert_ne!(etag, new.etag);
        config.static_cache_entries = 0;
        let files = StaticFiles::new(&config.sites[0], &config)
            .unwrap()
            .unwrap();
        assert!(files.resolve("/small.txt").await.unwrap().body.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn zero_ttl_detects_replaced_file() {
        let root =
            std::env::temp_dir().join(format!("raddy-static-refresh-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), "old").unwrap();
        let config = config(root.clone(), 0);
        let files = StaticFiles::new(&config.sites[0], &config)
            .unwrap()
            .unwrap();
        let old = files.resolve("/file.txt").await.unwrap();
        std::fs::write(root.join("replacement.txt"), "new-content").unwrap();
        std::fs::rename(root.join("replacement.txt"), root.join("file.txt")).unwrap();
        let new = files.resolve("/file.txt").await.unwrap();
        assert_ne!(old.length, new.length);
        std::fs::remove_dir_all(root).unwrap();
    }
}
