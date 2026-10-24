//! The TLS modes of the API and UI listener (OPS-22, TGL-08) and the TLS material for
//! modes a and b.

use std::{
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use tenko_core::Timestamp;
use tenko_vault::SecretBytes;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{TlsError, TrustedProxies};

/// How the API and UI listener does TLS (OPS-22). Stored in the settings; the first-run
/// wizard offers all three.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TlsMode {
    /// (a) A server certificate from the internal CA for the configured host name; admin
    /// clients install the CA root ([`InternalCa::root_pem`](super::InternalCa::root_pem)).
    InternalCa,
    /// (b) An imported certificate chain and key in PEM files, reloaded when they change,
    /// with expiry warnings in the health view.
    Imported {
        /// PEM file with the leaf certificate first, then intermediates.
        cert_path: PathBuf,
        /// PEM file with the private key (PKCS#8, PKCS#1 or SEC1).
        key_path: PathBuf,
    },
    /// (c) TLS terminates in a reverse proxy (`HAProxy`, nginx, Caddy). The listener speaks
    /// plain HTTP, or the `PROXY` protocol when `proxy_protocol` is set, and only to
    /// `trusted_proxies`; client address, scheme and host come from the forwarded headers
    /// of trusted peers only. The WebAuthn relying-party ID and the `Secure` cookie flag
    /// follow `public_host`.
    ReverseProxy {
        /// Peers allowed to connect and to send forwarded headers.
        trusted_proxies: TrustedProxies,
        /// Expect the PROXY protocol (v1 or v2) instead of forwarded headers.
        #[serde(default)]
        proxy_protocol: bool,
        /// The public host name clients use (the relying-party ID).
        public_host: String,
    },
}

impl TlsMode {
    /// Whether this listener terminates TLS itself (modes a and b).
    pub fn terminates_tls(&self) -> bool {
        !matches!(self, TlsMode::ReverseProxy { .. })
    }

    /// The trusted proxies of mode c.
    pub fn trusted_proxies(&self) -> Option<&TrustedProxies> {
        match self {
            TlsMode::ReverseProxy {
                trusted_proxies, ..
            } => Some(trusted_proxies),
            _ => None,
        }
    }

    /// The public host of mode c.
    pub fn public_host(&self) -> Option<&str> {
        match self {
            TlsMode::ReverseProxy { public_host, .. } => Some(public_host),
            _ => None,
        }
    }

    /// The stable `snake_case` name of the mode.
    pub fn name(&self) -> &'static str {
        match self {
            TlsMode::InternalCa => "internal_ca",
            TlsMode::Imported { .. } => "imported",
            TlsMode::ReverseProxy { .. } => "reverse_proxy",
        }
    }
}

/// Protocol policy of the listener (TGL-08: the Hardened profile allows TLS 1.3 only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPolicy {
    /// Refuse TLS 1.2.
    pub tls13_only: bool,
}

/// Where a certificate came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CertSource {
    /// Issued by the internal CA.
    InternalCa,
    /// Imported from files.
    Imported {
        /// The certificate file.
        cert_path: PathBuf,
        /// The key file.
        key_path: PathBuf,
    },
    /// Given directly (tests, uploads not yet written to disk).
    Inline,
}

/// What a certificate says, for the settings page and the health view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    /// Subject distinguished name (RFC 4514 text).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// DNS names in the subject alternative name.
    pub dns_names: Vec<String>,
    /// IP addresses in the subject alternative name.
    pub ip_addresses: Vec<IpAddr>,
    /// URIs in the subject alternative name (node certificates carry
    /// `urn:tenko:node:<id>`).
    pub uris: Vec<String>,
    /// Serial number, lowercase hexadecimal.
    pub serial: String,
    /// Start of validity.
    pub not_before: Timestamp,
    /// End of validity.
    pub not_after: Timestamp,
    /// SHA-256 of the DER encoding, lowercase hexadecimal.
    pub sha256: String,
    /// Whether it is a CA certificate.
    pub is_ca: bool,
}

/// Days before expiry from which the health view warns.
pub const EXPIRY_WARNING_DAYS: i64 = 30;
/// Days before expiry from which the health view reports critical.
pub const EXPIRY_CRITICAL_DAYS: i64 = 7;

/// How close a certificate is to expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryState {
    /// At least [`EXPIRY_WARNING_DAYS`] whole days left.
    Valid,
    /// Fewer than [`EXPIRY_WARNING_DAYS`] whole days left.
    Warning,
    /// Fewer than [`EXPIRY_CRITICAL_DAYS`] whole days left.
    Critical,
    /// Expired.
    Expired,
    /// Not valid yet (clock skew or a future-dated certificate).
    NotYetValid,
}

/// Expiry of a certificate at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expiry {
    /// End of validity.
    pub not_after: Timestamp,
    /// Whole days left (negative once expired).
    pub days_left: i64,
    /// The classification.
    pub state: ExpiryState,
}

impl CertInfo {
    /// Parses a DER certificate.
    ///
    /// # Errors
    ///
    /// [`TlsError::InvalidCertificate`].
    pub fn from_der(der: &[u8]) -> Result<Self, TlsError> {
        use x509_parser::{extensions::GeneralName, prelude::FromDer};
        let invalid = |reason: String| TlsError::InvalidCertificate { reason };
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| invalid(e.to_string()))?;
        let mut info = Self {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            uris: Vec::new(),
            serial: hex(cert.raw_serial()),
            not_before: timestamp(cert.validity().not_before.timestamp())?,
            not_after: timestamp(cert.validity().not_after.timestamp())?,
            sha256: hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der).as_ref()),
            is_ca: cert.is_ca(),
        };
        if let Some(san) = cert
            .subject_alternative_name()
            .map_err(|e| invalid(e.to_string()))?
        {
            for name in &san.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => info.dns_names.push((*dns).to_owned()),
                    GeneralName::URI(uri) => info.uris.push((*uri).to_owned()),
                    GeneralName::IPAddress(bytes) => {
                        if let Ok(v4) = <[u8; 4]>::try_from(*bytes) {
                            info.ip_addresses.push(IpAddr::from(v4));
                        } else if let Ok(v6) = <[u8; 16]>::try_from(*bytes) {
                            info.ip_addresses.push(IpAddr::from(v6));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(info)
    }

    /// The expiry classification at `now`.
    pub fn expiry(&self, now: Timestamp) -> Expiry {
        let days_left = (self.not_after.0 - now.0).whole_days();
        let state = if now.0 < self.not_before.0 {
            ExpiryState::NotYetValid
        } else if now.0 >= self.not_after.0 {
            ExpiryState::Expired
        } else if days_left < EXPIRY_CRITICAL_DAYS {
            ExpiryState::Critical
        } else if days_left < EXPIRY_WARNING_DAYS {
            ExpiryState::Warning
        } else {
            ExpiryState::Valid
        };
        Expiry {
            not_after: self.not_after,
            days_left,
            state,
        }
    }
}

fn timestamp(unix: i64) -> Result<Timestamp, TlsError> {
    OffsetDateTime::from_unix_timestamp(unix)
        .map(Timestamp::from)
        .map_err(|e| TlsError::InvalidCertificate {
            reason: e.to_string(),
        })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// A certificate chain with its private key, ready for rustls (modes a and b). The key
/// lives only inside rustls' signing key; the encoded key bytes passed in are wiped after
/// loading.
#[derive(Clone)]
pub struct TlsMaterial {
    certified: Arc<CertifiedKey>,
    info: CertInfo,
    source: CertSource,
}

impl fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMaterial")
            .field("info", &self.info)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl TlsMaterial {
    /// Builds material from a DER chain (leaf first) and a PKCS#8 key.
    ///
    /// # Errors
    ///
    /// [`TlsError::NoCertificate`], [`TlsError::NoPrivateKey`], [`TlsError::KeyMismatch`]
    /// or [`TlsError::InvalidCertificate`].
    pub fn from_der(
        chain: Vec<CertificateDer<'static>>,
        pkcs8_key: &SecretBytes,
        source: CertSource,
    ) -> Result<Self, TlsError> {
        // `PrivateKeyDer` implements `Zeroize` but does not wipe itself on drop.
        let key = Zeroizing::new(PrivateKeyDer::Pkcs8(pkcs8_key.expose().to_vec().into()));
        Self::build(chain, &key, source)
    }

    /// Parses PEM: every `CERTIFICATE` block of `cert_pem` (leaf first) and the first
    /// private key of `key_pem`.
    ///
    /// # Errors
    ///
    /// As [`from_der`](TlsMaterial::from_der).
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8], source: CertSource) -> Result<Self, TlsError> {
        let chain = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::InvalidCertificate {
                reason: e.to_string(),
            })?;
        let key = Zeroizing::new(PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| {
            TlsError::NoPrivateKey {
                reason: e.to_string(),
            }
        })?);
        Self::build(chain, &key, source)
    }

    /// Reads and parses the files of mode b.
    ///
    /// # Errors
    ///
    /// [`TlsError::Io`] or as [`from_pem`](TlsMaterial::from_pem).
    pub fn load_files(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let read = |path: &Path| {
            std::fs::read(path).map_err(|e| TlsError::Io {
                path: path.display().to_string(),
                reason: e.to_string(),
            })
        };
        let cert = read(cert_path)?;
        let key = Zeroizing::new(read(key_path)?);
        Self::from_pem(
            &cert,
            &key,
            CertSource::Imported {
                cert_path: cert_path.to_owned(),
                key_path: key_path.to_owned(),
            },
        )
    }

    fn build(
        chain: Vec<CertificateDer<'static>>,
        key: &PrivateKeyDer<'_>,
        source: CertSource,
    ) -> Result<Self, TlsError> {
        let leaf = chain.first().ok_or(TlsError::NoCertificate)?;
        let info = CertInfo::from_der(leaf)?;
        // Loading by reference leaves the only copy of the key bytes with the caller, which
        // wipes it; the signing key keeps its own form inside aws-lc-rs.
        let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(key).map_err(|e| {
            TlsError::NoPrivateKey {
                reason: e.to_string(),
            }
        })?;
        let certified = CertifiedKey::new(chain, signing);
        certified.keys_match().map_err(|_| TlsError::KeyMismatch)?;
        Ok(Self {
            certified: Arc::new(certified),
            info,
            source,
        })
    }

    /// What the leaf certificate says.
    pub fn info(&self) -> &CertInfo {
        &self.info
    }

    /// Where the material came from.
    pub fn source(&self) -> &CertSource {
        &self.source
    }

    /// The chain, leaf first.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.certified.cert
    }

    /// The rustls certified key.
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified)
    }

    /// A server configuration serving exactly this material (no hot reload; see
    /// `TlsService::server_config` for a listener that follows reloads). ALPN offers
    /// `h2` and `http/1.1`.
    ///
    /// # Errors
    ///
    /// [`TlsError::Config`] if rustls refuses the protocol versions.
    pub fn server_config(&self, policy: TlsPolicy) -> Result<Arc<ServerConfig>, TlsError> {
        let resolver = TlsResolver::default();
        resolver.set(Some(self.clone()));
        server_config(Arc::new(resolver), policy)
    }
}

/// A rustls certificate resolver whose material can be swapped while the listener runs:
/// new handshakes use the new certificate, established connections keep theirs. Without
/// material every handshake fails.
#[derive(Debug, Default)]
pub struct TlsResolver {
    current: ArcSwapOption<CertifiedKey>,
}

impl TlsResolver {
    /// Installs material (or removes it with `None`).
    pub fn set(&self, material: Option<TlsMaterial>) {
        self.current.store(material.map(|m| m.certified));
    }

    /// Whether material is installed.
    pub fn has_material(&self) -> bool {
        self.current.load().is_some()
    }

    /// The certified key new handshakes get.
    pub fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current.load_full()
    }
}

impl ResolvesServerCert for TlsResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.load_full()
    }
}

/// A server configuration over a resolver: aws-lc-rs provider, TLS 1.3 (and 1.2 unless the
/// policy forbids it), no client authentication, ALPN `h2` and `http/1.1`.
///
/// # Errors
///
/// [`TlsError::Config`] if rustls refuses the protocol versions.
pub fn server_config(
    resolver: Arc<dyn ResolvesServerCert>,
    policy: TlsPolicy,
) -> Result<Arc<ServerConfig>, TlsError> {
    let versions: &[&'static rustls::SupportedProtocolVersion] = if policy.tls13_only {
        &[&rustls::version::TLS13]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .map_err(|e| TlsError::Config {
        reason: e.to_string(),
    })?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A certificate found in the imported files that the listener does not serve: the
/// operator's profile does not accept a replacement from outside, so it is loaded at the
/// next start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCertificate {
    /// What the leaf certificate in the files says.
    pub certificate: CertInfo,
    /// Number of certificates in the chain file.
    pub chain_len: usize,
    /// When the watcher first saw this certificate in the files.
    pub detected_at: Timestamp,
}

/// What the TLS layer currently serves, published on `TlsService::watch` for the API
/// listener and the health view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsStatus {
    /// The active mode.
    pub mode: TlsMode,
    /// The served certificate (modes a and b, once loaded).
    pub certificate: Option<CertInfo>,
    /// Number of certificates in the served chain (the leaf and its intermediates).
    pub chain_len: usize,
    /// The last load or reload failure; the previous material keeps serving.
    pub last_error: Option<String>,
    /// When the served material was installed.
    pub loaded_at: Option<Timestamp>,
    /// Whether a certificate replaced in the imported files is loaded while the listener
    /// runs (the profile decides, see `tls.accept_external_replacement`).
    pub accept_replacement: bool,
    /// Mode b: a newer certificate is on disk and waits for the next start, because
    /// `accept_replacement` is off.
    pub pending: Option<PendingCertificate>,
    /// Mode b: how often the watcher looks at the files, once it runs.
    pub watch_interval: Option<std::time::Duration>,
    /// Incremented on every change of mode, material or error.
    pub revision: u64,
}

impl TlsStatus {
    /// The expiry of the served certificate at `now`.
    pub fn expiry(&self, now: Timestamp) -> Option<Expiry> {
        self.certificate.as_ref().map(|info| info.expiry(now))
    }
}
