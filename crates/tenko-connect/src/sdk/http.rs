//! HTTP for plugins that read a web API (feature `http-client`, on by default).
//!
//! The pieces every web-API plugin needs, so that each plugin checks certificates the same
//! way and reports the same codes:
//!
//! - [`TlsSettings`]: how the server certificate is checked, as an operator chooses it in
//!   the instance's settings ([`settings_schema`] returns the matching schema properties):
//!   the operating system's certificate authorities ([`TlsMode::System`]), only a pinned
//!   certificate authority ([`TlsMode::Ca`]), only the server certificate with a pinned
//!   SHA-256 fingerprint ([`TlsMode::Fingerprint`]), or no check ([`TlsMode::Insecure`],
//!   for a lab, and loud). An optional connect address makes the client connect to an IP
//!   address while it checks the certificate against the host name of the URL.
//! - [`WebClient`]: a `reqwest` client for one base URL with those checks, without proxies
//!   from the environment and without following redirects.
//! - [`WebClient::failure`]: what went wrong with a request, naming the cause of a TLS
//!   failure (unknown issuer, a certificate that does not name the host, an expired
//!   certificate, a pin that does not match, plain HTTP on an `https` URL).
//! - [`WebClient::presented_fingerprint`]: the SHA-256 fingerprint of the certificate the
//!   server presents, for a health detail that lets the operator pin it after checking it.
//! - [`read_json`] and [`read_bytes`]: bounded reads; a JSON error names the line and
//!   column, never the value that did not fit.
//! - [`status_error`]: the [`ConnectorError`] of an HTTP status.
//!
//! Nothing here logs. A plugin never puts a secret into a URL; send credentials in headers
//! and mark them sensitive ([`sensitive_header`]).

use std::{
    error::Error as StdError,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use aws_lc_rs::digest;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub use reqwest;

use crate::ConnectorError;

/// How long a TCP and TLS connection may take, at most (and never longer than the request
/// timeout).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default limit of one answer body, in bytes.
pub const DEFAULT_BODY_LIMIT: usize = 32 * 1024 * 1024;

/// Longest PEM text accepted for a pinned certificate authority, in bytes.
pub const MAX_CA_PEM: usize = 65_536;

/// How the server certificate is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// The certificate authorities the operating system trusts (`SSL_CERT_FILE` and
    /// `SSL_CERT_DIR` are honoured), and the host name of the URL.
    #[default]
    System,
    /// Only the certificate authority (or authorities) of the settings, and the host name of
    /// the URL.
    Ca,
    /// Only the server certificate with the SHA-256 fingerprint of the settings; its names
    /// and dates are not checked. The handshake signature is still verified.
    Fingerprint,
    /// No check at all. For a lab; the plugin says so in every health check.
    Insecure,
}

impl TlsMode {
    /// The name in the settings.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsMode::System => "system",
            TlsMode::Ca => "ca",
            TlsMode::Fingerprint => "fingerprint",
            TlsMode::Insecure => "insecure",
        }
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The TLS settings of an instance as its settings carry them (the properties of
/// [`settings_schema`]): `tls`, `tls_fingerprint`, `tls_ca` and `connect_address`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsSettings {
    /// The mode (`tls`).
    pub mode: TlsMode,
    /// The pinned SHA-256 fingerprint of the server certificate (`tls_fingerprint`), hex
    /// with or without colons; used in [`TlsMode::Fingerprint`].
    pub fingerprint: Option<String>,
    /// The pinned certificate authority in PEM (`tls_ca`); used in [`TlsMode::Ca`].
    pub ca: Option<String>,
    /// An IP address to connect to instead of resolving the host of the URL
    /// (`connect_address`).
    pub connect_address: Option<String>,
}

/// Checked TLS settings.
#[derive(Clone, PartialEq, Eq)]
struct Tls {
    mode: TlsMode,
    pin: Option<[u8; 32]>,
    roots: Vec<Vec<u8>>,
    connect: Option<IpAddr>,
}

impl TlsSettings {
    fn check(&self) -> Result<Tls, ConnectorError> {
        let blank = |value: &Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let pin = match (self.mode, blank(&self.fingerprint)) {
            (TlsMode::Fingerprint, None) => {
                return Err(ConnectorError::invalid_settings(
                    "tls is `fingerprint` but tls_fingerprint is empty",
                ));
            }
            (TlsMode::Fingerprint, Some(text)) => Some(parse_fingerprint(&text).ok_or_else(
                || {
                    ConnectorError::invalid_settings(
                        "tls_fingerprint is not a SHA-256 fingerprint (64 hexadecimal digits, colons allowed)",
                    )
                },
            )?),
            _ => None,
        };
        let roots = match (self.mode, blank(&self.ca)) {
            (TlsMode::Ca, None) => {
                return Err(ConnectorError::invalid_settings(
                    "tls is `ca` but tls_ca is empty",
                ));
            }
            (TlsMode::Ca, Some(text)) => pem_certificates(&text).map_err(|problem| {
                ConnectorError::invalid_settings(format!("tls_ca: {problem}"))
            })?,
            _ => Vec::new(),
        };
        let connect = blank(&self.connect_address)
            .map(|text| {
                text.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .map_err(|_| {
                        ConnectorError::invalid_settings(
                            "connect_address is not an IPv4 or IPv6 address",
                        )
                    })
            })
            .transpose()?;
        Ok(Tls {
            mode: self.mode,
            pin,
            roots,
            connect,
        })
    }
}

/// The schema properties of the TLS settings, to merge into the `properties` of a plugin's
/// settings schema: `tls` (default `system`), `tls_fingerprint`, `tls_ca` and
/// `connect_address`. Declare `/connect_address` as a network target as well.
pub fn settings_schema() -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(properties) = serde_json::json!({
        "tls": {
            "type": "string",
            "title": "Certificate check",
            "description": "system: the certificate authorities this machine trusts and the host name of the URL. ca: only the certificate authority in tls_ca, and the host name. fingerprint: only the server certificate with the SHA-256 fingerprint in tls_fingerprint (names and dates are not checked; a renewed certificate needs the new fingerprint). insecure: no check, for a lab only.",
            "enum": ["system", "ca", "fingerprint", "insecure"],
            "default": "system"
        },
        "tls_fingerprint": {
            "type": "string",
            "title": "Pinned certificate fingerprint (SHA-256)",
            "description": "The SHA-256 fingerprint of the server certificate, as hexadecimal digits with or without colons. Used when the certificate check is `fingerprint`.",
            "pattern": "^\\s*[0-9A-Fa-f]{2}(:?[0-9A-Fa-f]{2}){31}\\s*$",
            "examples": ["AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"]
        },
        "tls_ca": {
            "type": "string",
            "title": "Pinned certificate authority (PEM)",
            "description": "The certificate authority that signed the server certificate, in PEM (-----BEGIN CERTIFICATE----- ...). Used when the certificate check is `ca`.",
            "maxLength": MAX_CA_PEM
        },
        "connect_address": {
            "type": "string",
            "title": "Connect to address",
            "description": "An IP address to connect to instead of looking up the host name of the URL. The certificate is still checked against the host name in the URL, so a certificate that names a host this machine cannot resolve can be checked fully.",
            "maxLength": 64,
            "examples": ["192.0.2.10"]
        }
    }) else {
        unreachable!("a JSON object literal")
    };
    properties
}

/// A client for one web API: its base URL and the certificate checks of its settings.
#[derive(Clone)]
pub struct WebClient {
    client: reqwest::Client,
    base: reqwest::Url,
    tls: Tls,
    timeout: Duration,
}

impl fmt::Debug for WebClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebClient")
            .field("scheme", &self.base.scheme())
            .field("tls", &self.tls.mode)
            .finish_non_exhaustive()
    }
}

impl WebClient {
    /// A client for the base URL `base` (`http` or `https`, a host, an optional port and
    /// path, no credentials, query or fragment) with the given TLS settings, a timeout per
    /// request and a user agent.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::InvalidSettings`] for a URL or TLS settings that cannot be used.
    pub fn new(
        base: &str,
        tls: &TlsSettings,
        timeout: Duration,
        user_agent: &str,
    ) -> Result<Self, ConnectorError> {
        let base = parse_base_url(base)?;
        let tls = tls.check()?;
        let host_is_ip = base.host_str().is_some_and(|host| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok()
        });
        if tls.connect.is_some() && host_is_ip {
            return Err(ConnectorError::invalid_settings(
                "connect_address needs a host name in the URL, not an IP address",
            ));
        }
        let client = build(&base, &tls, timeout, user_agent, None)?;
        Ok(Self {
            client,
            base,
            tls,
            timeout,
        })
    }

    /// The `reqwest` client.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The base URL.
    pub fn base(&self) -> &reqwest::Url {
        &self.base
    }

    /// The TLS mode.
    pub fn mode(&self) -> TlsMode {
        self.tls.mode
    }

    /// The URL of `path` (starting with `/`) under the base URL's path.
    pub fn url(&self, path: &str) -> reqwest::Url {
        let mut url = self.base.clone();
        let joined = format!(
            "{}/{}",
            self.base.path().trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        url.set_path(&joined);
        url
    }

    /// A GET request of `path` under the base URL.
    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client.get(self.url(path))
    }

    /// What went wrong with a request: a TLS failure with its cause, a timeout, a connection
    /// failure, or another failure.
    pub fn failure(&self, error: &reqwest::Error) -> Failure {
        failure_of(error, self.tls.mode, self.base.scheme() == "https")
    }

    /// The [`ConnectorError`] of a failed request: a TLS failure is
    /// [`ConnectorError::InvalidSettings`] naming the cause (an operator fixes it in the
    /// settings), everything else that kept the server from answering is
    /// [`ConnectorError::Unreachable`].
    pub fn error(&self, error: &reqwest::Error) -> ConnectorError {
        self.failure(error).into_error()
    }

    /// Notes for a health detail about how the connection is secured: no encryption, no
    /// certificate check, a fingerprint pin, a connect address.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.base.scheme() == "http" {
            notes.push(
                "the connection is not encrypted (http); credentials travel in clear text"
                    .to_owned(),
            );
        } else {
            match self.tls.mode {
                TlsMode::Insecure => notes.push(
                    "certificate checks are off (tls = insecure); use this in a lab only".to_owned(),
                ),
                TlsMode::Fingerprint => notes.push(
                    "the server certificate is pinned by its fingerprint; a renewed certificate needs the new fingerprint".to_owned(),
                ),
                TlsMode::Ca => notes.push("the server certificate is checked against the pinned certificate authority".to_owned()),
                TlsMode::System => {}
            }
        }
        if let Some(ip) = self.tls.connect {
            notes.push(format!("connecting to {ip} for the host of the URL"));
        }
        notes
    }

    /// The SHA-256 fingerprint (colon-separated upper-case hex) of the certificate the
    /// server presents, read through a separate connection that sends nothing after the
    /// handshake; `None` for an `http` URL or when no certificate could be read.
    pub async fn presented_fingerprint(&self) -> Option<String> {
        if self.base.scheme() != "https" {
            return None;
        }
        let seen = Arc::new(Mutex::new(None));
        let verifier = Arc::new(CaptureVerifier {
            seen: Arc::clone(&seen),
            provider: provider(),
        });
        let config = client_config(verifier).ok()?;
        let client = build(
            &self.base,
            &self.tls,
            self.timeout.min(CONNECT_TIMEOUT),
            "tenko-connect",
            Some(config),
        )
        .ok()?;
        let _ = client.head(self.base.clone()).send().await;
        let digest = *seen.lock().unwrap_or_else(PoisonError::into_inner);
        digest.map(|digest| fingerprint_text(&digest))
    }
}

/// What went wrong with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The TLS handshake failed; the text names the cause and what to change.
    Tls(String),
    /// The request did not finish in time.
    Timeout,
    /// No connection: refused, no route, a name that does not resolve.
    Connect,
    /// The client could not build the request.
    Request(String),
    /// Something else interrupted the exchange.
    Other,
}

impl Failure {
    /// The [`ConnectorError`] of the failure.
    pub fn into_error(self) -> ConnectorError {
        match self {
            Failure::Tls(cause) => ConnectorError::InvalidSettings(format!("TLS: {cause}")),
            Failure::Request(detail) => ConnectorError::InvalidSettings(detail),
            Failure::Timeout | Failure::Connect | Failure::Other => ConnectorError::Unreachable,
        }
    }

    /// An English text for a health detail or a log line.
    pub fn describe(&self) -> String {
        match self {
            Failure::Tls(cause) => format!("TLS: {cause}"),
            Failure::Timeout => "the server did not answer in time".to_owned(),
            Failure::Connect => {
                "no connection to the server (refused, no route, or the name does not resolve)"
                    .to_owned()
            }
            Failure::Request(detail) => detail.clone(),
            Failure::Other => "the exchange with the server was interrupted".to_owned(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

fn failure_of(error: &reqwest::Error, mode: TlsMode, https: bool) -> Failure {
    if let Some(tls) = find_tls(error) {
        return Failure::Tls(tls_cause(tls, mode));
    }
    if error.is_timeout() {
        return Failure::Timeout;
    }
    if error.is_builder() {
        return Failure::Request("the request cannot be built from the settings".to_owned());
    }
    if error.is_connect() {
        // A plain-HTTP server on an https URL breaks the handshake without a TLS alert.
        if https && io_kind(error) == Some(std::io::ErrorKind::InvalidData) {
            return Failure::Tls(
                "the server does not speak TLS on this address; is the URL http instead of https?"
                    .to_owned(),
            );
        }
        return Failure::Connect;
    }
    Failure::Other
}

/// The rustls error somewhere in the source chain of `error`.
fn find_tls<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a TlsError> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(tls) = error.downcast_ref::<TlsError>() {
            return Some(tls);
        }
        if let Some(io) = error.downcast_ref::<std::io::Error>()
            && let Some(inner) = io.get_ref()
        {
            let inner: &(dyn StdError + 'static) = inner;
            if let Some(tls) = find_tls(inner) {
                return Some(tls);
            }
        }
        current = error.source();
    }
    None
}

/// The kind of the first I/O error in the source chain of `error`.
fn io_kind(error: &(dyn StdError + 'static)) -> Option<std::io::ErrorKind> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            return Some(io.kind());
        }
        current = error.source();
    }
    None
}

/// The cause of a TLS failure in words, with what to change.
fn tls_cause(error: &TlsError, mode: TlsMode) -> String {
    let fix = match mode {
        TlsMode::System => {
            "; pin the certificate authority (tls = ca) or the certificate (tls = fingerprint)"
        }
        TlsMode::Ca => "; check tls_ca, or pin the certificate (tls = fingerprint)",
        TlsMode::Fingerprint | TlsMode::Insecure => "",
    };
    match error {
        TlsError::InvalidCertificate(certificate) => match certificate {
            CertificateError::UnknownIssuer => format!(
                "the server certificate is not signed by a trusted certificate authority (unknown issuer){fix}"
            ),
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "the server certificate does not name the host of the URL; use the host name the certificate carries in the URL (with connect_address if this machine cannot resolve it), or pin the certificate (tls = fingerprint)".to_owned()
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                format!("the server certificate has expired{fix}")
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "the server certificate is not valid yet (check the clocks)".to_owned()
            }
            CertificateError::Revoked => "the server certificate is revoked".to_owned(),
            CertificateError::BadSignature => "the server certificate has a bad signature".to_owned(),
            CertificateError::BadEncoding => "the server certificate cannot be read".to_owned(),
            CertificateError::ApplicationVerificationFailure if mode == TlsMode::Fingerprint => {
                "the server certificate does not match the pinned fingerprint (tls_fingerprint); a renewed certificate has a new fingerprint".to_owned()
            }
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
                "the server certificate is not meant for a TLS server".to_owned()
            }
            _ => format!("the server certificate was refused{fix}"),
        },
        TlsError::AlertReceived(alert) => {
            format!("the server ended the handshake with the alert {alert:?}")
        }
        TlsError::NoCertificatesPresented => "the server presented no certificate".to_owned(),
        TlsError::InvalidMessage(_)
        | TlsError::InappropriateMessage { .. }
        | TlsError::InappropriateHandshakeMessage { .. } => {
            "the server does not speak TLS on this address; is the URL http instead of https?"
                .to_owned()
        }
        TlsError::PeerIncompatible(_) => {
            "the server offers no TLS version or cipher this client accepts (TLS 1.2 or 1.3)"
                .to_owned()
        }
        _ => "the TLS handshake failed".to_owned(),
    }
}

/// The [`ConnectorError`] of an HTTP status that is not a success: 401 is
/// [`ConnectorError::Unauthorized`], 403 [`ConnectorError::Forbidden`], 404
/// [`ConnectorError::NotFound`], 429 [`ConnectorError::RateLimited`] (after
/// `retry_after`, else 60 seconds), a server error [`ConnectorError::Unreachable`], and
/// anything else [`ConnectorError::Protocol`].
pub fn status_error(status: reqwest::StatusCode, retry_after: Option<Duration>) -> ConnectorError {
    match status.as_u16() {
        401 => ConnectorError::Unauthorized,
        403 => ConnectorError::Forbidden,
        404 => ConnectorError::NotFound,
        429 => ConnectorError::RateLimited {
            retry_after: retry_after.unwrap_or(Duration::from_secs(60)),
        },
        500..=599 => ConnectorError::Unreachable,
        _ => ConnectorError::protocol(format!("the server answered with the status {status}")),
    }
}

/// The delay of a `Retry-After` header in seconds, if the response has one.
pub fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// A header value marked sensitive, so that it never appears in `Debug` output.
///
/// # Errors
///
/// [`ConnectorError::InvalidSettings`] naming `what` when the value is not a valid header
/// value (a line break, for example); the value itself is never part of the error.
pub fn sensitive_header(
    value: &str,
    what: &str,
) -> Result<reqwest::header::HeaderValue, ConnectorError> {
    let mut header = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
        ConnectorError::invalid_settings(format!("{what} contains characters that cannot be sent"))
    })?;
    header.set_sensitive(true);
    Ok(header)
}

/// The body of a response, at most `limit` bytes.
///
/// # Errors
///
/// [`ConnectorError::Protocol`] for a larger body, [`ConnectorError::Unreachable`] when the
/// transfer breaks off.
pub async fn read_bytes(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ConnectorError> {
    let too_large = || ConnectorError::protocol(format!("the answer is larger than {limit} bytes"));
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ConnectorError::Unreachable)?
    {
        if body.len() + chunk.len() > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The body of a response as JSON, at most `limit` bytes.
///
/// # Errors
///
/// As [`read_bytes`], and [`ConnectorError::Protocol`] for a body that is not the expected
/// JSON; the message names the line and column, never the value.
pub async fn read_json<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> Result<T, ConnectorError> {
    let body = read_bytes(response, limit).await?;
    from_json(&body)
}

/// Bytes as JSON of the expected shape; the error names the line and column, never the
/// value.
///
/// # Errors
///
/// [`ConnectorError::Protocol`].
pub fn from_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ConnectorError> {
    serde_json::from_slice(body).map_err(|error| {
        let kind = match error.classify() {
            serde_json::error::Category::Io => "unreadable",
            serde_json::error::Category::Syntax => "not JSON",
            serde_json::error::Category::Data => "JSON of an unexpected shape",
            serde_json::error::Category::Eof => "cut off",
        };
        ConnectorError::protocol(format!(
            "the answer is {kind} (line {}, column {})",
            error.line(),
            error.column()
        ))
    })
}

/// Parses a base URL: `http` or `https`, a host, no credentials, query or fragment.
///
/// # Errors
///
/// [`ConnectorError::InvalidSettings`] naming the problem.
pub fn parse_base_url(text: &str) -> Result<reqwest::Url, ConnectorError> {
    let url = reqwest::Url::parse(text.trim())
        .map_err(|_| ConnectorError::invalid_settings("url is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ConnectorError::invalid_settings(
            "url must start with https:// or http://",
        ));
    }
    if url.host().is_none() {
        return Err(ConnectorError::invalid_settings("url has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConnectorError::invalid_settings(
            "url must not carry credentials; they belong in the instance's secrets",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConnectorError::invalid_settings(
            "url must not have a query or a fragment",
        ));
    }
    Ok(url)
}

/// Parses a SHA-256 fingerprint: 64 hexadecimal digits, with or without colons or spaces.
pub fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !matches!(b, b':' | b' ' | b'\t'))
        .collect();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out[i] = high << 4 | low;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The SHA-256 fingerprint of a DER certificate as colon-separated upper-case hex.
pub fn fingerprint_of(der: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, der);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(digest.as_ref());
    fingerprint_text(&bytes)
}

fn fingerprint_text(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The DER certificates of a PEM text. Lenient about layout: line breaks inside the base64
/// body may be missing or replaced by spaces, as when a PEM is pasted into a single-line
/// field.
///
/// # Errors
///
/// A short English problem: no certificate, a missing end line, or invalid base64.
pub fn pem_certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if text.len() > MAX_CA_PEM {
        return Err(format!("the PEM text is longer than {MAX_CA_PEM} bytes"));
    }
    let mut certificates = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after
            .find(END)
            .ok_or_else(|| "a certificate has no -----END CERTIFICATE----- line".to_owned())?;
        let body: String = after[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = base64_decode(&body)
            .filter(|der| !der.is_empty())
            .ok_or_else(|| "a certificate is not valid base64".to_owned())?;
        certificates.push(der);
        rest = &after[end + END.len()..];
    }
    if certificates.is_empty() {
        return Err("no certificate (-----BEGIN CERTIFICATE-----) found".to_owned());
    }
    Ok(certificates)
}

/// Standard base64 with padding.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, quad) in bytes.chunks(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let padding = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 || (padding > 0 && !last) {
            return None;
        }
        let mut word = 0u32;
        for &c in &quad[..4 - padding] {
            word = word << 6 | value(c)?;
        }
        word <<= 6 * u32::try_from(padding).unwrap_or(0);
        let [_, a, b, c] = word.to_be_bytes();
        out.push(a);
        if padding < 2 {
            out.push(b);
        }
        if padding < 1 {
            out.push(c);
        }
    }
    Some(out)
}

/// The crypto provider of the pinned configurations: aws-lc-rs, as everywhere in Tenko.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn client_config(verifier: Arc<dyn ServerCertVerifier>) -> Result<ClientConfig, ConnectorError> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| ConnectorError::PluginFailed("no TLS protocol version available".to_owned()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn build(
    base: &reqwest::Url,
    tls: &Tls,
    timeout: Duration,
    user_agent: &str,
    preconfigured: Option<ClientConfig>,
) -> Result<reqwest::Client, ConnectorError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT.min(timeout))
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(config) = preconfigured {
        builder = builder.use_preconfigured_tls(config);
    } else {
        match tls.mode {
            TlsMode::System => {}
            TlsMode::Ca => {
                builder = builder.tls_built_in_root_certs(false);
                for der in &tls.roots {
                    let certificate = reqwest::Certificate::from_der(der).map_err(|_| {
                        ConnectorError::invalid_settings("tls_ca: a certificate cannot be read")
                    })?;
                    builder = builder.add_root_certificate(certificate);
                }
            }
            TlsMode::Fingerprint => {
                let pin = tls.pin.ok_or_else(|| {
                    ConnectorError::invalid_settings(
                        "tls is `fingerprint` but tls_fingerprint is empty",
                    )
                })?;
                let verifier = Arc::new(PinnedVerifier {
                    pin,
                    provider: provider(),
                });
                builder = builder.use_preconfigured_tls(client_config(verifier)?);
            }
            TlsMode::Insecure => builder = builder.danger_accept_invalid_certs(true),
        }
    }
    if let (Some(ip), Some(host)) = (tls.connect, base.host_str()) {
        builder = builder.resolve(host, SocketAddr::new(ip, 0));
    }
    builder.build().map_err(|error| {
        ConnectorError::invalid_settings(format!(
            "the HTTP client cannot be built: {}",
            error.without_url()
        ))
    })
}

/// Accepts exactly the server certificate with the pinned SHA-256 fingerprint and verifies
/// the handshake signature with its key.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let digest = digest::digest(&digest::SHA256, end_entity.as_ref());
        if digest.as_ref() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Records the fingerprint of the presented certificate and refuses the connection.
#[derive(Debug)]
struct CaptureVerifier {
    seen: Arc<Mutex<Option<[u8; 32]>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let digest = digest::digest(&digest::SHA256, end_entity.as_ref());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_ref());
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(bytes);
        Err(TlsError::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    #[test]
    fn fingerprints_parse_with_or_without_colons() {
        let text = "ab:CD:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89";
        let pin = parse_fingerprint(text).expect("pin");
        assert_eq!(pin[0], 0xab);
        assert_eq!(pin[31], 0x89);
        assert_eq!(parse_fingerprint(&text.replace(':', "")), Some(pin));
        assert_eq!(parse_fingerprint(&text.replace(':', " ")), Some(pin));
        assert_eq!(parse_fingerprint(&text[3..]), None);
        assert_eq!(parse_fingerprint(&text.replace('a', "g")), None);
        assert_eq!(fingerprint_text(&pin), text.to_ascii_uppercase());
    }

    #[test]
    fn base64_decodes_with_padding_and_refuses_garbage() {
        assert_eq!(base64_decode("").expect("empty"), Vec::<u8>::new());
        assert_eq!(base64_decode("TWFu").expect("man"), b"Man");
        assert_eq!(base64_decode("TWE=").expect("ma"), b"Ma");
        assert_eq!(base64_decode("TQ==").expect("m"), b"M");
        assert_eq!(base64_decode("TQ"), None);
        assert_eq!(base64_decode("TQ=a"), None);
        assert_eq!(base64_decode("TQ==TWFu"), None);
        assert_eq!(base64_decode("T===").as_deref(), None);
        assert_eq!(base64_decode("TW*u"), None);
    }

    #[test]
    fn pem_text_is_read_even_without_line_breaks() {
        let pem = "-----BEGIN CERTIFICATE-----\nTWFu\nTWFu\n-----END CERTIFICATE-----\n";
        assert_eq!(
            pem_certificates(pem).expect("pem"),
            vec![b"ManMan".to_vec()]
        );
        let pasted = "-----BEGIN CERTIFICATE----- TWFu TWFu -----END CERTIFICATE----------BEGIN CERTIFICATE-----TQ==-----END CERTIFICATE-----";
        assert_eq!(
            pem_certificates(pasted).expect("pem"),
            vec![b"ManMan".to_vec(), b"M".to_vec()]
        );
        assert!(
            pem_certificates("TWFu")
                .expect_err("none")
                .contains("no certificate")
        );
        assert!(
            pem_certificates("-----BEGIN CERTIFICATE-----TWFu")
                .expect_err("open")
                .contains("END")
        );
        assert!(
            pem_certificates("-----BEGIN CERTIFICATE-----T*Fu-----END CERTIFICATE-----")
                .expect_err("base64")
                .contains("base64")
        );
    }

    #[test]
    fn tls_settings_are_checked() {
        let settings = |mode, fingerprint: Option<&str>, ca: Option<&str>| TlsSettings {
            mode,
            fingerprint: fingerprint.map(str::to_owned),
            ca: ca.map(str::to_owned),
            connect_address: None,
        };
        assert!(settings(TlsMode::System, None, None).check().is_ok());
        assert!(matches!(
            settings(TlsMode::Fingerprint, None, None).check(),
            Err(ConnectorError::InvalidSettings(text)) if text.contains("tls_fingerprint")
        ));
        assert!(matches!(
            settings(TlsMode::Fingerprint, Some("abc"), None).check(),
            Err(ConnectorError::InvalidSettings(_))
        ));
        assert!(matches!(
            settings(TlsMode::Ca, None, Some("  ")).check(),
            Err(ConnectorError::InvalidSettings(text)) if text.contains("tls_ca")
        ));
        // Values of other modes are ignored.
        assert!(
            settings(TlsMode::System, Some("abc"), Some("x"))
                .check()
                .is_ok()
        );
        let mut connect = settings(TlsMode::System, None, None);
        connect.connect_address = Some("[2001:db8::10]".to_owned());
        assert_eq!(
            connect.check().expect("connect").connect,
            Some("2001:db8::10".parse().expect("ip"))
        );
        connect.connect_address = Some("pve.example.test".to_owned());
        assert!(connect.check().is_err());
    }

    #[test]
    fn base_urls_are_checked() {
        assert!(parse_base_url("https://pve.example.test:8006").is_ok());
        assert!(parse_base_url(" http://192.0.2.10:8123/ ").is_ok());
        for bad in [
            "pve.example.test",
            "ftp://pve.example.test",
            "https://user:pass@pve.example.test",
            "https://pve.example.test/?a=b",
            "https://pve.example.test/#x",
        ] {
            assert!(
                matches!(parse_base_url(bad), Err(ConnectorError::InvalidSettings(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn urls_join_under_the_base_path() {
        let tls = TlsSettings::default();
        let client = WebClient::new(
            "https://proxy.example.test/pve/",
            &tls,
            Duration::from_secs(5),
            "t",
        )
        .expect("client");
        assert_eq!(
            client.url("/api2/json/version").as_str(),
            "https://proxy.example.test/pve/api2/json/version"
        );
        let client = WebClient::new("http://192.0.2.10:8123", &tls, Duration::from_secs(5), "t")
            .expect("client");
        assert_eq!(client.url("api/").as_str(), "http://192.0.2.10:8123/api/");
        assert!(client.notes()[0].contains("not encrypted"));
        let connect = TlsSettings {
            connect_address: Some("192.0.2.10".to_owned()),
            ..TlsSettings::default()
        };
        assert!(matches!(
            WebClient::new("https://192.0.2.10:8006", &connect, Duration::from_secs(5), "t"),
            Err(ConnectorError::InvalidSettings(text)) if text.contains("host name")
        ));
        assert!(
            WebClient::new(
                "https://pve.example.test:8006",
                &connect,
                Duration::from_secs(5),
                "t"
            )
            .is_ok()
        );
    }

    #[test]
    fn statuses_map_to_connector_errors() {
        use reqwest::StatusCode;
        assert_eq!(
            status_error(StatusCode::UNAUTHORIZED, None),
            ConnectorError::Unauthorized
        );
        assert_eq!(
            status_error(StatusCode::FORBIDDEN, None),
            ConnectorError::Forbidden
        );
        assert_eq!(
            status_error(StatusCode::NOT_FOUND, None),
            ConnectorError::NotFound
        );
        assert_eq!(
            status_error(StatusCode::TOO_MANY_REQUESTS, Some(Duration::from_secs(5))),
            ConnectorError::RateLimited {
                retry_after: Duration::from_secs(5)
            }
        );
        assert_eq!(
            status_error(StatusCode::BAD_GATEWAY, None),
            ConnectorError::Unreachable
        );
        assert!(matches!(
            status_error(StatusCode::IM_A_TEAPOT, None),
            ConnectorError::Protocol(_)
        ));
    }

    #[test]
    fn json_errors_never_echo_the_value() {
        #[derive(Debug, Deserialize)]
        struct Shape {
            #[allow(dead_code, reason = "only the shape matters")]
            count: u32,
        }
        let error = from_json::<Shape>(br#"{"count": "secret-name"}"#).expect_err("shape");
        let text = error.to_string();
        assert!(!text.contains("secret-name"), "{text}");
        assert!(text.contains("line 1"), "{text}");
        assert!(
            from_json::<Shape>(b"{")
                .expect_err("eof")
                .to_string()
                .contains("cut off")
        );
    }

    #[test]
    fn the_schema_fragment_is_a_valid_settings_schema() {
        let mut properties = settings_schema();
        properties.insert(
            "url".to_owned(),
            serde_json::json!({ "type": "string", "format": "uri" }),
        );
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "manifest_version": 1,
            "name": "web-test",
            "version": "0.1.0",
            "description": "A test manifest.",
            "protocol": [1],
            "capabilities": ["inventory"],
            "settings": {
                "type": "object",
                "properties": properties,
                "required": ["url"],
                "additionalProperties": false
            },
            "network": [
                { "setting": "/url", "description": "The API." },
                { "setting": "/connect_address", "description": "The address to connect to." }
            ],
            "platforms": ["any"]
        }))
        .expect("manifest");
        manifest.validate().expect("valid");
        let filled = manifest
            .validate_settings(&serde_json::json!({ "url": "https://pve.example.test" }))
            .expect("defaults");
        assert_eq!(filled["tls"], "system");
        assert!(
            manifest
                .validate_settings(&serde_json::json!({
                    "url": "https://pve.example.test",
                    "tls_fingerprint": "not hex"
                }))
                .is_err()
        );
    }
}
