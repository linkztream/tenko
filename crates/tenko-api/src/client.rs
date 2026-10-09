//! The API client of the `tenko` command line (API-03): a `reqwest` client over rustls that
//! shares [`crate::dto`] and [`ProblemDetails`] with the server and needs no axum.
//!
//! ```no_run
//! use tenko_api::client::{Client, ClientConfig};
//!
//! # async fn demo() -> Result<(), tenko_api::client::ClientError> {
//! let mut config = ClientConfig::new("https://ddi.example.org");
//! config.token = Some("a personal API token".to_owned());
//! let client = Client::new(config)?;
//!
//! // Typed helpers cover the platform endpoints ...
//! let status = client.system_status().await?;
//! println!("{} up for {} s", status.version, status.uptime_seconds);
//!
//! // ... and the generic verbs reach every other endpoint. Paths are relative to
//! // `/api/v1` and start with a slash.
//! let page: tenko_api::dto::Page<serde_json::Value> = client.get("/prefixes").await?;
//! # drop(page);
//! # Ok(())
//! # }
//! ```
//!
//! # Behavior
//!
//! - Only rustls is used (no OpenSSL). The built-in web PKI roots are trusted; the internal
//!   CA root from the setup wizard is added with [`ClientConfig::root_ca_pem`].
//! - The personal API token travels as `Authorization: Bearer` on every request, marked
//!   sensitive so that it never shows up in debug output, and is never part of an error.
//! - Redirects are not followed. The API never redirects, so a 3xx almost always means the
//!   base URL points at the wrong scheme or host, and the token must not follow it.
//! - A non-2xx answer becomes [`ClientError::Problem`] when it is
//!   `application/problem+json` and [`ClientError::UnexpectedStatus`] otherwise.
//! - `POST` can carry an `Idempotency-Key`, and `PATCH` and `DELETE` an `If-Match` with the
//!   revision of the object being changed (API-04).
//! - The interactive login flows of the command line are not part of this module.

#![allow(
    clippy::result_large_err,
    reason = "ProblemDetails is part of the public error type (API-03), and errors are the rare path"
)]

use std::{error::Error, fmt, time::Duration};

use reqwest::{
    Method, RequestBuilder, Response, Url,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, IF_MATCH},
    redirect,
};
use serde::{Serialize, de::DeserializeOwned};
use tenko_core::{AuditSeq, Revision, audit::AuditRecord};

use crate::{
    API_BASE,
    dto::{
        Page,
        audit::{AuditQuery, AuditVerifyReport},
        system::{Health, Readiness, SystemStatus},
    },
    problem::{PROBLEM_JSON, ProblemDetails},
};

/// The request timeout of [`ClientConfig::new`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest wait for the TCP and TLS handshake, whatever the request timeout is.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most bytes of an unexpected error body that [`ClientError::UnexpectedStatus`] keeps.
const BODY_EXCERPT: usize = 2048;

/// Most bytes of a problem document the client reads.
const PROBLEM_LIMIT: usize = 64 * 1024;

/// Page size of [`Client::audit_all`] when the query sets none (the server's maximum).
const AUDIT_ALL_PAGE: u32 = 1000;

const ACCEPT_JSON: &str = "application/json";
const ACCEPT_ANY: &str = "*/*";

/// Settings of a [`Client`].
#[derive(Clone)]
pub struct ClientConfig {
    /// Base URL of the server, for example `https://ddi.example.org`. It must be `http` or
    /// `https` without credentials, query or fragment; a path is kept (a reverse proxy may
    /// serve Tenko below one). The client appends [`API_BASE`] (`/api/v1`).
    pub base_url: String,
    /// Personal API token, sent as `Authorization: Bearer`.
    pub token: Option<String>,
    /// Extra trust anchor in PEM form (one or more certificates), for example the internal
    /// CA root from the setup wizard. The web PKI roots stay trusted.
    pub root_ca_pem: Option<Vec<u8>>,
    /// Limit for a whole request, body included. Must not be zero.
    pub timeout: Duration,
}

impl ClientConfig {
    /// A configuration for `base_url` without token or extra trust anchor and with the
    /// [`DEFAULT_TIMEOUT`] of 30 seconds.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token: None,
            root_ca_pem: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("root_ca_pem", &self.root_ca_pem.as_ref().map(Vec::len))
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Why a request failed.
#[derive(Debug)]
pub enum ClientError {
    /// The configuration or the request cannot be built: an unusable base URL, token or
    /// trust anchor, a path that does not start with `/`, a header value or a body or query
    /// that cannot be encoded. Nothing was sent.
    InvalidConfig(String),
    /// The request could not be sent or the answer not be read: DNS, connection, TLS,
    /// timeout. The text of the error includes the underlying causes.
    Transport(reqwest::Error),
    /// The server answered with a non-2xx status and `application/problem+json`.
    Problem(ProblemDetails),
    /// The server answered with a non-2xx status and anything else (a proxy's error page,
    /// for example). The body is cut to 2 KiB.
    UnexpectedStatus {
        /// The HTTP status code.
        status: u16,
        /// The start of the response body, as text.
        body: String,
    },
    /// A successful answer that is not what the call expected.
    Decode(String),
}

impl ClientError {
    /// The problem details of a [`ClientError::Problem`].
    pub fn problem(&self) -> Option<&ProblemDetails> {
        match self {
            ClientError::Problem(problem) => Some(problem),
            _ => None,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::InvalidConfig(reason) => write!(f, "invalid client setup: {reason}"),
            ClientError::Transport(error) => {
                write!(f, "request failed: {error}")?;
                let mut cause = error.source();
                while let Some(source) = cause {
                    write!(f, ": {source}")?;
                    cause = source.source();
                }
                Ok(())
            }
            ClientError::Problem(problem) => fmt::Display::fmt(problem, f),
            ClientError::UnexpectedStatus { status, body } if body.trim().is_empty() => {
                write!(f, "unexpected HTTP status {status}")
            }
            ClientError::UnexpectedStatus { status, body } => {
                write!(f, "unexpected HTTP status {status}: {}", body.trim())
            }
            ClientError::Decode(reason) => write!(f, "cannot use the response: {reason}"),
        }
    }
}

// The causes of `Transport` are part of its text, so no `source` is reported: a printer that
// walks the chain would show them twice.
impl Error for ClientError {}

/// A client of the Tenko API. Cheap to clone; clones share their connections.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    /// The base URL as given, normalized, without a trailing slash.
    base_url: String,
    /// The path every endpoint URL must stay below, for example `/api/v1/`.
    api_prefix: String,
    authenticated: bool,
}

impl fmt::Debug for Client {
    /// Shows the base URL and whether a token is set, never the token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("authenticated", &self.authenticated)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Builds a client.
    ///
    /// # Errors
    ///
    /// [`ClientError::InvalidConfig`] for a base URL that is not `http` or `https`, has
    /// credentials, a query or a fragment, an empty token or one that cannot be a header
    /// value, a zero timeout, a trust anchor that holds no usable certificate, or a TLS
    /// stack that cannot be initialized.
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let ClientConfig {
            base_url,
            token,
            root_ca_pem,
            timeout,
        } = config;
        let invalid = ClientError::InvalidConfig;
        let (base_url, base_path) = parse_base_url(&base_url)?;
        if timeout.is_zero() {
            return Err(invalid("the timeout must not be zero".to_owned()));
        }

        let authenticated = token.is_some();
        let mut headers = HeaderMap::new();
        if let Some(token) = token {
            if token.is_empty() {
                return Err(invalid("the API token is empty".to_owned()));
            }
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| invalid("the API token is not valid in a header".to_owned()))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }

        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .user_agent(format!("tenko/{}", crate::version()))
            .default_headers(headers)
            .redirect(redirect::Policy::none())
            .timeout(timeout)
            .connect_timeout(timeout.min(CONNECT_TIMEOUT));
        if let Some(pem) = root_ca_pem {
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|error| invalid(format!("the root CA is not valid PEM: {error}")))?;
            if certificates.is_empty() {
                return Err(invalid("the root CA holds no PEM certificate".to_owned()));
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = builder.build().map_err(|error| {
            invalid(format!(
                "the HTTP client cannot be built (is the root CA a certificate?): {error}"
            ))
        })?;

        Ok(Self {
            http,
            api_prefix: format!("{base_path}{API_BASE}/"),
            base_url,
            authenticated,
        })
    }

    /// The base URL the client talks to, without a trailing slash and without [`API_BASE`].
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// `GET path`, with the JSON answer decoded as `T`. `path` is relative to
    /// [`API_BASE`] and starts with `/`.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type; [`ClientError::Decode`] if the answer is not a `T`.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        self.json(Method::GET, path, |request| request).await
    }

    /// `GET path?query`, with `query` encoded as URL parameters (`None` fields of a struct
    /// should be skipped with `skip_serializing_if`).
    ///
    /// # Errors
    ///
    /// As [`Client::get`]; a `query` that cannot be encoded is
    /// [`ClientError::InvalidConfig`].
    pub async fn get_query<Q: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T, ClientError> {
        self.json(Method::GET, path, |request| request.query(query))
            .await
    }

    /// `GET path`, with the answer as text (CSV exports, metrics).
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type; [`ClientError::Decode`] if the answer is not UTF-8.
    pub async fn get_text(&self, path: &str) -> Result<String, ClientError> {
        let response = self
            .call(Method::GET, path, ACCEPT_ANY, |request| request)
            .await?;
        let body = response.bytes().await.map_err(transport)?;
        std::str::from_utf8(&body)
            .map(str::to_owned)
            .map_err(|_| ClientError::Decode(format!("GET {path}: the answer is not UTF-8 text")))
    }

    /// `POST path` with `body` as JSON, and the JSON answer decoded as `T`. With
    /// `idempotency_key` the request carries `Idempotency-Key`, so that a retry does not
    /// run twice; without it none is sent.
    ///
    /// # Errors
    ///
    /// As [`Client::get`]; a body that cannot be encoded or a key that is not a valid
    /// header value is [`ClientError::InvalidConfig`].
    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<T, ClientError> {
        self.json(Method::POST, path, |request| {
            let request = request.json(body);
            match idempotency_key {
                Some(key) => request.header("Idempotency-Key", key),
                None => request,
            }
        })
        .await
    }

    /// `PATCH path` with `body` as JSON, and the JSON answer decoded as `T`. With
    /// `if_match` the request carries `If-Match: "<revision>"`, and the server refuses it
    /// when the object has changed since.
    ///
    /// # Errors
    ///
    /// As [`Client::post`].
    pub async fn patch<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        if_match: Option<Revision>,
    ) -> Result<T, ClientError> {
        self.json(Method::PATCH, path, |request| {
            with_if_match(request.json(body), if_match)
        })
        .await
    }

    /// `DELETE path`, optionally with `If-Match: "<revision>"`; any 2xx answer is success
    /// and its body is ignored.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn delete(&self, path: &str, if_match: Option<Revision>) -> Result<(), ClientError> {
        self.call(Method::DELETE, path, ACCEPT_JSON, |request| {
            with_if_match(request, if_match)
        })
        .await
        .map(drop)
    }

    /// `GET /health`: the liveness probe.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn health(&self) -> Result<Health, ClientError> {
        self.get("/health").await
    }

    /// `GET /health/ready`: the readiness probe. A node that is not ready answers 503, which
    /// is a [`ClientError::Problem`] with code `sys.not_ready`.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn ready(&self) -> Result<Readiness, ClientError> {
        self.get("/health/ready").await
    }

    /// `GET /system/status`: version, store, TLS and warnings of the node.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn system_status(&self) -> Result<SystemStatus, ClientError> {
        self.get("/system/status").await
    }

    /// `GET /audit`: one page of audit records.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn audit(&self, query: &AuditQuery) -> Result<Page<AuditRecord>, ClientError> {
        self.get_query("/audit", query).await
    }

    /// Every record that matches `query`: `GET /audit`, following `next_cursor` until the
    /// last page. `query.limit` is the page size (1,000 when unset) and `query.cursor` the
    /// place to start from.
    ///
    /// # Errors
    ///
    /// The first failing page; [`ClientError::Decode`] if the server answers with the
    /// cursor it was given, which would never end.
    pub async fn audit_all(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, ClientError> {
        let mut query = query.clone();
        query.limit.get_or_insert(AUDIT_ALL_PAGE);
        let mut records = Vec::new();
        loop {
            let page = self.audit(&query).await?;
            records.extend(page.items);
            match page.next_cursor {
                None => return Ok(records),
                Some(next) if query.cursor.as_deref() == Some(next.as_str()) => {
                    return Err(ClientError::Decode(
                        "GET /audit: the next cursor is the one that was sent".to_owned(),
                    ));
                }
                Some(next) => query.cursor = Some(next),
            }
        }
    }

    /// `GET /audit/{seq}`: one audit record. An unknown sequence number is a
    /// [`ClientError::Problem`] with code `sys.audit.not_found`.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn audit_record(&self, seq: AuditSeq) -> Result<AuditRecord, ClientError> {
        self.get(&format!("/audit/{seq}")).await
    }

    /// `GET /audit/verify`: the server walks the audit hash chain and reports.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn audit_verify(&self) -> Result<AuditVerifyReport, ClientError> {
        self.get("/audit/verify").await
    }

    /// `GET /openapi.json`: the OpenAPI document of the server.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn openapi(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/openapi.json").await
    }

    /// `GET /metrics`: the metrics in the `OpenMetrics` text format (needs a token with
    /// access to the metrics).
    ///
    /// # Errors
    ///
    /// [`ClientError`]: see the type.
    pub async fn metrics(&self) -> Result<String, ClientError> {
        self.get_text("/metrics").await
    }

    /// The URL of an endpoint below the API base.
    fn endpoint(&self, path: &str) -> Result<Url, ClientError> {
        let invalid =
            |reason: &str| ClientError::InvalidConfig(format!("API path `{path}`: {reason}"));
        if !path.starts_with('/') {
            return Err(invalid("must start with `/`"));
        }
        let url = Url::parse(&format!("{}{API_BASE}{path}", self.base_url))
            .map_err(|error| invalid(&error.to_string()))?;
        // URL parsing resolves `.` and `..`; the result must not leave the API.
        if !url.path().starts_with(&self.api_prefix) {
            return Err(invalid("leaves the API base"));
        }
        Ok(url)
    }

    /// Sends a request and returns the response if its status is 2xx.
    async fn call(
        &self,
        method: Method,
        path: &str,
        accept: &'static str,
        customize: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<Response, ClientError> {
        let url = self.endpoint(path)?;
        let request = customize(self.http.request(method, url).header(ACCEPT, accept));
        let response = request.send().await.map_err(transport)?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(failure(response).await)
        }
    }

    /// [`Client::call`] for a JSON answer.
    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        customize: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<T, ClientError> {
        let response = self
            .call(method.clone(), path, ACCEPT_JSON, customize)
            .await?;
        let body = response.bytes().await.map_err(transport)?;
        decode(&body).map_err(|reason| ClientError::Decode(format!("{method} {path}: {reason}")))
    }
}

/// Splits and validates a base URL into its normalized text (no trailing slash) and its
/// path (empty or starting with `/`, no trailing slash).
fn parse_base_url(text: &str) -> Result<(String, String), ClientError> {
    // The text is not echoed: it may carry credentials.
    let invalid = |reason: &str| ClientError::InvalidConfig(format!("base URL: {reason}"));
    let url = Url::parse(text.trim()).map_err(|error| invalid(&error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid("must use http or https"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("must not contain credentials; use the API token"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("must not contain a query or a fragment"));
    }
    let base = url.as_str().trim_end_matches('/').to_owned();
    let path = url.path().trim_end_matches('/').to_owned();
    Ok((base, path))
}

fn with_if_match(request: RequestBuilder, if_match: Option<Revision>) -> RequestBuilder {
    match if_match {
        Some(revision) => request.header(IF_MATCH, format!("\"{revision}\"")),
        None => request,
    }
}

/// Maps a `reqwest` error: one raised while building the request is the caller's, anything
/// else is the network's.
fn transport(error: reqwest::Error) -> ClientError {
    if error.is_builder() {
        ClientError::InvalidConfig(format!(
            "the request cannot be built: {}",
            error.without_url()
        ))
    } else {
        ClientError::Transport(error)
    }
}

/// Decodes a JSON answer. An empty body counts as `null`, so `()` and `Option<_>` accept a
/// `204`.
fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, String> {
    if body.trim_ascii().is_empty() {
        return serde_json::from_slice(b"null").map_err(|_| "the answer has no body".to_owned());
    }
    serde_json::from_slice(body).map_err(|error| error.to_string())
}

/// The error for a response with a non-2xx status.
async fn failure(mut response: Response) -> ClientError {
    let status = response.status().as_u16();
    let is_problem = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_problem_json);
    let limit = if is_problem {
        PROBLEM_LIMIT
    } else {
        BODY_EXCERPT
    };
    let body = read_prefix(&mut response, limit).await;
    if is_problem && let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&body) {
        return ClientError::Problem(problem);
    }
    ClientError::UnexpectedStatus {
        status,
        body: excerpt(&body),
    }
}

/// Whether a `Content-Type` value is `application/problem+json`, parameters aside.
fn is_problem_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(PROBLEM_JSON))
}

/// The first `limit` bytes of a body. A read error ends the body early.
async fn read_prefix(response: &mut Response, limit: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < limit {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = limit - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    body
}

/// Text of the first [`BODY_EXCERPT`] bytes, without half a character at the end.
fn excerpt(body: &[u8]) -> String {
    let body = &body[..body.len().min(BODY_EXCERPT)];
    match std::str::from_utf8(body) {
        Ok(text) => text.to_owned(),
        Err(error) if error.error_len().is_none() => {
            String::from_utf8_lossy(&body[..error.valid_up_to()]).into_owned()
        }
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(base_url: &str) -> Client {
        Client::new(ClientConfig::new(base_url)).expect("client")
    }

    #[test]
    fn base_url_is_normalized() {
        assert_eq!(
            client("https://ddi.example.org").base_url(),
            "https://ddi.example.org"
        );
        assert_eq!(
            client("https://ddi.example.org/").base_url(),
            "https://ddi.example.org"
        );
        assert_eq!(
            client(" HTTP://DDI.example.org:8443/tenko/ ").base_url(),
            "http://ddi.example.org:8443/tenko"
        );
        assert_eq!(
            client("http://[2001:db8::10]:8080").base_url(),
            "http://[2001:db8::10]:8080"
        );
    }

    #[test]
    fn unusable_base_urls_are_refused() {
        for url in [
            "",
            "ddi.example.org",
            "ftp://ddi.example.org",
            "file:///etc",
            "https://",
            "https://admin:secret@ddi.example.org",
            "https://ddi.example.org/?a=b",
            "https://ddi.example.org/#top",
        ] {
            let error = Client::new(ClientConfig::new(url)).expect_err(url);
            assert!(
                matches!(error, ClientError::InvalidConfig(_)),
                "{url}: {error}"
            );
            assert!(!error.to_string().contains("secret"), "{url}: {error}");
        }
    }

    #[test]
    fn unusable_settings_are_refused() {
        let mut config = ClientConfig::new("https://ddi.example.org");
        config.timeout = Duration::ZERO;
        assert!(matches!(
            Client::new(config),
            Err(ClientError::InvalidConfig(_))
        ));

        for token in ["", "line\nbreak"] {
            let mut config = ClientConfig::new("https://ddi.example.org");
            config.token = Some(token.to_owned());
            assert!(matches!(
                Client::new(config),
                Err(ClientError::InvalidConfig(_))
            ));
        }

        for pem in [
            &b""[..],
            b"not a certificate",
            b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            let mut config = ClientConfig::new("https://ddi.example.org");
            config.root_ca_pem = Some(pem.to_vec());
            assert!(matches!(
                Client::new(config),
                Err(ClientError::InvalidConfig(_))
            ));
        }
    }

    #[test]
    fn endpoints_stay_below_the_api_base() {
        let plain = client("https://ddi.example.org");
        assert_eq!(
            plain
                .endpoint("/prefixes/tree?vrf=a")
                .expect("url")
                .as_str(),
            "https://ddi.example.org/api/v1/prefixes/tree?vrf=a"
        );
        assert_eq!(
            plain.endpoint("/a/./b/../c").expect("url").as_str(),
            "https://ddi.example.org/api/v1/a/c"
        );
        let nested = client("https://ddi.example.org/tenko/");
        assert_eq!(
            nested.endpoint("/health").expect("url").as_str(),
            "https://ddi.example.org/tenko/api/v1/health"
        );
        for path in [
            "",
            "health",
            "//x",
            "/../x",
            "/%2e%2e/x",
            "/a/../../x",
            "/../../x",
        ] {
            let accepted = plain.endpoint(path);
            // `//x` is a (strange) path below the API base; the rest must be refused.
            if path == "//x" {
                assert_eq!(accepted.expect("url").path(), "/api/v1//x");
            } else {
                assert!(
                    matches!(accepted, Err(ClientError::InvalidConfig(_))),
                    "{path}"
                );
            }
        }
        assert!(nested.endpoint("/../x").is_err());
        assert!(nested.endpoint("/../../x").is_err());
    }

    #[test]
    fn debug_output_hides_the_token() {
        let mut config = ClientConfig::new("https://ddi.example.org");
        config.token = Some("tk_secret_value".to_owned());
        config.root_ca_pem = Some(b"-----BEGIN CERTIFICATE-----".to_vec());
        assert!(!format!("{config:?}").contains("tk_secret_value"));
        let client = Client::new(ClientConfig {
            root_ca_pem: None,
            ..config
        })
        .expect("client");
        let debug = format!("{client:?}");
        assert!(!debug.contains("tk_secret_value"), "{debug}");
        assert!(debug.contains("https://ddi.example.org"), "{debug}");
    }

    #[test]
    fn problem_content_types_are_recognized() {
        assert!(is_problem_json("application/problem+json"));
        assert!(is_problem_json("Application/Problem+JSON; charset=utf-8"));
        assert!(!is_problem_json("application/json"));
        assert!(!is_problem_json("text/html"));
        assert!(!is_problem_json(""));
    }

    #[test]
    fn excerpts_are_cut_on_a_character_boundary() {
        assert_eq!(excerpt(b"short"), "short");
        let text = "a".repeat(BODY_EXCERPT - 1) + "\u{e9}\u{e9}";
        let cut = excerpt(text.as_bytes());
        assert_eq!(cut.len(), BODY_EXCERPT - 1);
        assert!(cut.chars().all(|c| c == 'a'));
        assert_eq!(excerpt(&[b'a'; 5000]).len(), BODY_EXCERPT);
    }

    #[test]
    fn empty_answers_decode_as_null() {
        assert_eq!(decode::<()>(b""), Ok(()));
        assert_eq!(decode::<Option<u8>>(b" \n"), Ok(None));
        assert_eq!(decode::<u8>(b"7"), Ok(7));
        assert!(decode::<u8>(b"").is_err());
        assert!(decode::<u8>(b"seven").is_err());
    }

    #[test]
    fn errors_read_well() {
        let problem = ProblemDetails {
            type_: "about:blank".to_owned(),
            status: 404,
            code: "sys.route_not_found".to_owned(),
            title: "Not Found".to_owned(),
            detail: "no API route matches GET /api/v1/nope".to_owned(),
            params: std::collections::BTreeMap::new(),
            errors: Vec::new(),
            instance: None,
        };
        let error = ClientError::Problem(problem);
        assert_eq!(
            error.to_string(),
            "sys.route_not_found (404): no API route matches GET /api/v1/nope"
        );
        assert_eq!(error.problem().map(|p| p.status), Some(404));
        let error = ClientError::UnexpectedStatus {
            status: 502,
            body: "<html>Bad Gateway</html>\n".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "unexpected HTTP status 502: <html>Bad Gateway</html>"
        );
        assert!(error.problem().is_none());
        let error = ClientError::UnexpectedStatus {
            status: 503,
            body: String::new(),
        };
        assert_eq!(error.to_string(), "unexpected HTTP status 503");
    }
}
