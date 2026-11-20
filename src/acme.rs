use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{CLOUDFLARE, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::{crypto::CryptoProvider, server::ResolvesServerCert, sign::CertifiedKey};
use std::sync::RwLock;

use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::{
    cloudflare::{Cloudflare, DnsRecord},
    config::Config,
};

const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const RENEW_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

pub struct CertificateStore {
    certificates: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    config: Arc<Config>,
    cloudflare: Option<Arc<Cloudflare>>,
    issuances: tokio::sync::Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>,
    account: OnceCell<Account>,
}

impl CertificateStore {
    pub fn new(config: Arc<Config>, cloudflare: Option<Arc<Cloudflare>>) -> Arc<Self> {
        Arc::new(Self {
            certificates: RwLock::new(HashMap::new()),
            config,
            cloudflare,
            issuances: tokio::sync::Mutex::new(HashMap::new()),
            account: OnceCell::new(),
        })
    }

    pub fn resolver(self: &Arc<Self>) -> Arc<Self> {
        self.clone()
    }

    pub async fn provision(&self) -> Result<()> {
        for site in self.config.sites.iter().filter(|site| site.tls) {
            match self.load_or_issue(&site.hosts).await {
                Ok(certificate) => {
                    for host in &site.hosts {
                        self.certificates
                            .write()
                            .expect("certificate store lock poisoned")
                            .insert(normalize_host(host), certificate.clone());
                    }
                }
                Err(error) => {
                    if site.certificate_file.is_none()
                        && let Some(certificate) = self.load_existing(&site.hosts).await
                    {
                        warn!(hosts = ?site.hosts, %error, "certificate renewal failed; using the existing certificate");
                        for host in &site.hosts {
                            self.certificates
                                .write()
                                .expect("certificate store lock poisoned")
                                .insert(normalize_host(host), certificate.clone());
                        }
                    } else {
                        return Err(error).with_context(|| {
                            format!("could not provision certificate for {:?}", site.hosts)
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn spawn_renewals(self: &Arc<Self>) {
        let store = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RENEW_INTERVAL).await;
                let Some(store) = store.upgrade() else {
                    break;
                };
                for site in store
                    .config
                    .sites
                    .iter()
                    .filter(|site| site.tls && site.certificate_file.is_none())
                {
                    match store.load_or_issue(&site.hosts).await {
                        Ok(certificate) => {
                            let mut certificates = store
                                .certificates
                                .write()
                                .expect("certificate store lock poisoned");
                            for host in &site.hosts {
                                certificates.insert(normalize_host(host), certificate.clone());
                            }
                        }
                        Err(error) => {
                            warn!(hosts = ?site.hosts, %error, "scheduled certificate renewal failed")
                        }
                    }
                }
            }
        });
    }

    async fn load_or_issue(&self, hosts: &[String]) -> Result<Arc<CertifiedKey>> {
        let site = self
            .config
            .sites
            .iter()
            .find(|site| site.tls && site.hosts == hosts);
        if let Some((certificate_path, key_path)) = site.and_then(|site| {
            Some((
                site.certificate_file.as_ref()?,
                site.private_key_file.as_ref()?,
            ))
        }) {
            return load_pem_pair(certificate_path, key_path, hosts).await;
        }
        let directory = self.certificate_directory(hosts);
        let lock = {
            self.issuances
                .lock()
                .await
                .entry(directory)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _issuance = lock.lock().await;
        if let Some(certificate) = self.load_existing(hosts).await
            && certificate_lifetime(&certificate).is_ok_and(|remaining| remaining > RENEW_BEFORE)
            && certificate_covers_hosts(&certificate, hosts).is_ok()
        {
            info!(hosts = ?hosts, "using a cached certificate");
            return Ok(certificate);
        }
        info!(hosts = ?hosts, "issuing a certificate with ACME DNS-01");
        let (certificate_pem, private_key_pem) = self.issue(hosts).await?;
        let directory = self.certificate_directory(hosts);
        tokio::fs::create_dir_all(&directory).await?;
        let certificate =
            parse_certified_key(certificate_pem.as_bytes(), private_key_pem.as_bytes())?;
        validate_certificate(&certificate, hosts)?;
        let bundle = format!("{certificate_pem}\n{private_key_pem}");
        write_atomic(&directory.join("bundle.pem"), bundle.as_bytes(), true).await?;
        info!(hosts = ?hosts, "certificate issued and stored");
        Ok(certificate)
    }

    async fn load_existing(&self, hosts: &[String]) -> Option<Arc<CertifiedKey>> {
        let directory = self.certificate_directory(hosts);
        let result = match tokio::fs::read(directory.join("bundle.pem")).await {
            Ok(bundle) => parse_certified_key(&bundle, &bundle).and_then(|certificate| {
                validate_certificate(&certificate, hosts)?;
                Ok(certificate)
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                load_pem_pair(
                    &directory.join("certificate.pem"),
                    &directory.join("private_key.pem"),
                    hosts,
                )
                .await
            }
            Err(error) => Err(error.into()),
        };
        match result {
            Ok(certificate) => Some(certificate),
            Err(error) => {
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_none_or(|error| error.kind() != std::io::ErrorKind::NotFound)
                {
                    warn!(hosts = ?hosts, %error, "ignoring an invalid cached certificate");
                }
                None
            }
        }
    }

    fn certificate_directory(&self, hosts: &[String]) -> PathBuf {
        let name = hosts
            .first()
            .map(|host| host.replace('*', "_wildcard_"))
            .unwrap_or_else(|| "default".to_owned());
        let digest = ring::digest::digest(&ring::digest::SHA256, hosts.join("\0").as_bytes());
        self.config.data_dir.join("certificates").join(format!(
            "{}-{}",
            name,
            &hex_digest(digest.as_ref())[..16]
        ))
    }

    async fn account(&self) -> Result<&Account> {
        self.account
            .get_or_try_init(|| async {
                let path = self.account_path();
                if let Ok(bytes) = tokio::fs::read(&path).await {
                    let stored: StoredAccount =
                        serde_json::from_slice(&bytes).context("invalid stored ACME account")?;
                    if stored.directory_url == self.config.acme_ca {
                        return Account::builder()?
                            .from_credentials(stored.credentials)
                            .await
                            .map_err(Into::into);
                    }
                }
                let contact = self
                    .config
                    .email
                    .as_deref()
                    .map(|email| format!("mailto:{email}"));
                let contacts = contact.as_deref().into_iter().collect::<Vec<_>>();
                let (account, credentials) = Account::builder()?
                    .create(
                        &NewAccount {
                            contact: &contacts,
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        self.config.acme_ca.clone(),
                        None,
                    )
                    .await?;
                let stored = StoredAccount {
                    directory_url: self.config.acme_ca.clone(),
                    credentials,
                };
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                write_atomic(&path, &serde_json::to_vec(&stored)?, true).await?;
                Ok(account)
            })
            .await
    }

    fn account_path(&self) -> PathBuf {
        let digest = ring::digest::digest(&ring::digest::SHA256, self.config.acme_ca.as_bytes());
        self.config
            .data_dir
            .join("accounts")
            .join(format!("{}.json", hex_digest(digest.as_ref())))
    }

    async fn issue(&self, hosts: &[String]) -> Result<(String, String)> {
        let cloudflare = self
            .cloudflare
            .as_ref()
            .context("Cloudflare is required for automatic ACME certificates")?;
        let account = self.account().await?;
        let identifiers = hosts
            .iter()
            .map(|host| Identifier::Dns(host.clone()))
            .collect::<Vec<_>>();
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let mut cleanup = Vec::new();
        let operation = async {
            {
                let mut authorizations = order.authorizations();
                while let Some(authorization) = authorizations.next().await {
                    let mut authorization = authorization?;
                    if authorization.status == AuthorizationStatus::Valid {
                        continue;
                    }
                    if authorization.status != AuthorizationStatus::Pending {
                        bail!(
                            "ACME authorization is {:?}, expected pending",
                            authorization.status
                        );
                    }
                    let mut challenge = authorization
                        .challenge(ChallengeType::Dns01)
                        .ok_or_else(|| anyhow!("CA offered no DNS-01 challenge"))?;
                    let identifier = challenge.identifier().to_string();
                    let challenge_name =
                        format!("_acme-challenge.{}", identifier.trim_start_matches("*."));
                    let value = challenge.key_authorization().dns_value();
                    let zone = cloudflare
                        .find_zone_for_name(identifier.trim_start_matches("*."))
                        .await?;
                    let record = DnsRecord {
                        ttl: 120,
                        ..DnsRecord::txt(challenge_name.clone(), value.clone())
                    };
                    cloudflare
                        .append_records(&zone.name, vec![record.clone()])
                        .await?;
                    cleanup.push((zone.name, record));
                    wait_for_txt(&challenge_name, &value).await?;
                    challenge.set_ready().await?;
                }
            }
            let policy = RetryPolicy::default().timeout(Duration::from_secs(120));
            if order.poll_ready(&policy).await? != OrderStatus::Ready {
                bail!("ACME order did not become ready");
            }
            let private_key = order.finalize().await?;
            let certificate = order.poll_certificate(&policy).await?;
            Ok((certificate, private_key))
        }
        .await;
        for (zone, record) in cleanup {
            if let Err(error) = cloudflare.delete_records(&zone, vec![record]).await {
                warn!(%error, "failed to clean up an ACME DNS record");
            }
        }
        operation
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredAccount {
    directory_url: String,
    credentials: AccountCredentials,
}

impl std::fmt::Debug for CertificateStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertificateStore")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertificateStore {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = normalize_host(client_hello.server_name()?);
        if let Ok(certificates) = self.certificates.read() {
            if let Some(certificate) = certificates.get(&host) {
                return Some(certificate.clone());
            }
            let suffix = host.split_once('.').map(|(_, suffix)| suffix)?;
            return certificates.get(&format!("*.{suffix}")).cloned();
        }
        None
    }
}

fn parse_certified_key(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<Arc<CertifiedKey>> {
    let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(certificate_pem))
        .collect::<std::io::Result<Vec<_>>>()?;
    if certificates.is_empty() {
        bail!("certificate PEM contains no certificates");
    }
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(private_key_pem))?
        .ok_or_else(|| anyhow!("private key PEM contains no supported keys"))?;
    let provider = CryptoProvider::get_default()
        .ok_or_else(|| anyhow!("Rustls crypto provider is not installed"))?;
    let certificate = CertifiedKey::from_der(certificates, key, provider)?;
    certificate.keys_match()?;
    Ok(Arc::new(certificate))
}

pub async fn validate_configured_certificates(config: &Config) -> Result<()> {
    for site in config.sites.iter().filter(|site| site.tls) {
        if let (Some(cert), Some(key)) = (&site.certificate_file, &site.private_key_file) {
            load_pem_pair(cert, key, &site.hosts)
                .await
                .with_context(|| format!("invalid configured certificate for {:?}", site.hosts))?;
        }
    }
    Ok(())
}

async fn load_pem_pair(cert: &Path, key: &Path, hosts: &[String]) -> Result<Arc<CertifiedKey>> {
    let (certificate, private_key) = tokio::try_join!(tokio::fs::read(cert), tokio::fs::read(key))?;
    let certificate = parse_certified_key(&certificate, &private_key)?;
    validate_certificate(&certificate, hosts)?;
    Ok(certificate)
}

fn validate_certificate(certificate: &CertifiedKey, hosts: &[String]) -> Result<()> {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.end_entity_cert()?.as_ref())
        .map_err(|error| anyhow!("invalid X.509 certificate: {error}"))?;
    if !parsed.validity().is_valid() {
        bail!("TLS certificate is expired or not yet valid");
    }
    certificate_covers_hosts(certificate, hosts)
}

fn certificate_lifetime(certificate: &CertifiedKey) -> Result<Duration> {
    let der = certificate.end_entity_cert()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|error| anyhow!("invalid X.509 certificate: {error}"))?;
    let expires = parsed.validity().not_after.to_datetime().unix_timestamp();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;
    Ok(Duration::from_secs(
        expires.saturating_sub(now).max(0) as u64
    ))
}

fn certificate_covers_hosts(certificate: &CertifiedKey, hosts: &[String]) -> Result<()> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    let (_, certificate) =
        x509_parser::parse_x509_certificate(certificate.end_entity_cert()?.as_ref())
            .map_err(|error| anyhow!("invalid X.509 certificate: {error}"))?;
    for host in hosts {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let covered = certificate.extensions().iter().any(|extension| {
            matches!(extension.parsed_extension(), ParsedExtension::SubjectAlternativeName(san)
            if san.general_names.iter().any(|name| match name {
                GeneralName::DNSName(pattern) => dns_pattern_matches(pattern, &host),
                GeneralName::IPAddress(address) => host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| match ip {
                        std::net::IpAddr::V4(ip) => ip.octets().as_slice() == *address,
                        std::net::IpAddr::V6(ip) => ip.octets().as_slice() == *address,
                    }),
                _ => false,
            }))
        });
        if !covered {
            bail!("certificate does not include host {host} in Subject Alternative Names");
        }
    }
    Ok(())
}

fn dns_pattern_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let Some((first, rest)) = host.split_once('.') else {
            return false;
        };
        !first.is_empty() && rest.eq_ignore_ascii_case(suffix)
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

async fn wait_for_txt(name: &str, expected: &str) -> Result<()> {
    let mut options = ResolverOpts::default();
    options.cache_size = 0;
    let resolver: TokioResolver = Resolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(options)
    .build()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(records) = resolver.txt_lookup(name).await
            && records.answers().iter().any(|record| {
                matches!(&record.data, hickory_resolver::proto::rr::RData::TXT(text)
                    if text.txt_data.iter().flat_map(|part| part.iter().copied()).eq(expected.bytes()))
            })
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for TXT record {name} to propagate");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn write_atomic(path: &Path, contents: &[u8], secret: bool) -> Result<()> {
    use ring::rand::{SecureRandom, SystemRandom};
    use tokio::io::AsyncWriteExt;

    let mut nonce = [0; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow!("could not generate a temporary filename"))?;
    let temporary = path.with_extension(format!("{}.tmp", hex_digest(&nonce)));
    let mut options = tokio::fs::OpenOptions::new();
    #[cfg(unix)]
    if secret {
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await?;
    let written = async {
        file.write_all(contents).await?;
        file.flush().await?;
        file.sync_all().await
    }
    .await;
    drop(file);
    let result = match written {
        Ok(()) => tokio::fs::rename(&temporary, path).await,
        Err(error) => Err(error),
    };
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result.map_err(Into::into)
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{dns_pattern_matches, write_atomic};

    #[test]
    fn certificate_names_match_only_their_dns_labels() {
        assert!(dns_pattern_matches("example.com", "example.com"));
        assert!(dns_pattern_matches("EXAMPLE.com", "example.com"));
        assert!(dns_pattern_matches("*.example.com", "www.example.com"));
        assert!(!dns_pattern_matches("*.example.com", "example.com"));
        assert!(!dns_pattern_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_pattern_matches("example.com", "notexample.com"));
    }

    #[test]
    fn mismatched_certificate_and_key_are_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let first = rcgen::generate_simple_self_signed(vec!["example.test".to_owned()]).unwrap();
        let second = rcgen::generate_simple_self_signed(vec!["example.test".to_owned()]).unwrap();
        let pem = first.cert.pem();
        assert!(
            super::parse_certified_key(
                pem.as_bytes(),
                second.signing_key.serialize_pem().as_bytes()
            )
            .is_err()
        );
        let bundle = format!("{pem}\n{}", first.signing_key.serialize_pem());
        let cert = super::parse_certified_key(bundle.as_bytes(), bundle.as_bytes()).unwrap();
        super::validate_certificate(&cert, &["example.test".to_owned()]).unwrap();
    }

    #[tokio::test]
    async fn secret_files_are_not_readable_by_others() {
        let directory = std::env::temp_dir().join(format!("raddy-acme-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("private_key.pem");
        let old_temp = path.with_extension("tmp");
        std::fs::write(&old_temp, b"stale").unwrap();
        write_atomic(&path, b"secret", true).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "private key must not be group or world readable"
            );
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        assert_eq!(std::fs::read(&old_temp).unwrap(), b"stale");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn public_files_keep_default_permissions() {
        let directory =
            std::env::temp_dir().join(format!("raddy-acme-public-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("certificate.pem");
        write_atomic(&path, b"public", false).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"public");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
