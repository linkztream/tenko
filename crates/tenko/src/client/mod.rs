//! The client commands of the `tenko` binary: they talk to a controller over the public API
//! (API-03) with [`tenko_api::client`], and with a small raw HTTP helper for the two
//! exchanges that client does not cover (the session cookie of the login ceremony and the
//! multipart upload of an import).
//!
//! # Credentials
//!
//! `tenko login` signs in with a password and, when the account needs one, a second factor,
//! creates a personal API token from that session (IAM-10), ends the session, and stores the
//! token with the server URL in a credentials file readable by the user only:
//! `%APPDATA%\tenko\credentials.json` on Windows, `$XDG_CONFIG_HOME/tenko/credentials.json`
//! or `~/.config/tenko/credentials.json` elsewhere (`TENKO_CREDENTIALS` overrides the path).
//! The operating system keyrings are not used yet: the Linux secret service needs a desktop
//! session that controllers do not have. `tenko logout` revokes the token and deletes the
//! file. Scripts can set `TENKO_TOKEN` instead; secrets are never accepted as flags.
//!
//! # Output
//!
//! Errors print one line, `error[<code>]: <detail>`, and set the exit status of
//! [`crate::exit`]. With `--json`, the raw JSON bodies are printed instead, problem details
//! included.

pub mod audit;
pub mod export;
pub mod health;
pub mod hibp;
pub mod import;
pub mod login;
pub mod prefix;

use std::{
    fmt::Write as _,
    future::Future,
    io::{IsTerminal as _, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context as _;
use clap::Args;
use reqwest::{
    StatusCode,
    header::{CONTENT_TYPE, COOKIE, HeaderMap, ORIGIN, SET_COOKIE},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_api::{
    client::{Client, ClientConfig, ClientError},
    problem::ProblemDetails,
};
use tenko_auth::service::SecretString;
use tenko_core::Role;

use crate::exit;

/// Environment variable with a personal API token; it takes precedence over the stored one.
pub const TOKEN_ENV: &str = "TENKO_TOKEN";

/// Environment variable naming the credentials file.
pub const CREDENTIALS_ENV: &str = "TENKO_CREDENTIALS";

/// Request timeout of the client commands.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Options every client command takes.
#[derive(Debug, Clone, Default, Args)]
pub struct ClientOpts {
    /// Base URL of the controller, for example `https://ddi.example.org:8443`. Defaults to
    /// the URL stored by `tenko login`.
    #[arg(long, value_name = "URL", env = "TENKO_URL")]
    pub url: Option<String>,

    /// PEM file with the root certificate to trust besides the system roots, for example
    /// the internal CA root (`<data_dir>/tls/ca-root.pem`). Defaults to the one stored by
    /// `tenko login`.
    #[arg(long, value_name = "FILE", env = "TENKO_CA_FILE")]
    pub ca_file: Option<PathBuf>,

    /// Print the raw JSON bodies of the API, problem details included.
    #[arg(long)]
    pub json: bool,
}

/// What `tenko login` stores.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// The controller.
    pub url: String,
    /// The trust anchor used at login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// The account.
    pub user: String,
    /// The personal API token (secret).
    pub token: String,
    /// Its identifier, for `tenko logout`.
    pub token_id: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("url", &self.url)
            .field("user", &self.user)
            .field("token", &"<redacted>")
            .field("token_id", &self.token_id)
            .finish_non_exhaustive()
    }
}

/// The credentials file.
pub fn credentials_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(CREDENTIALS_ENV).filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
    };
    base.map(|base| base.join("tenko").join("credentials.json"))
}

/// Reads the stored credentials, if any.
///
/// # Errors
///
/// The file exists but cannot be read or parsed.
pub fn load_credentials() -> anyhow::Result<Option<Credentials>> {
    let Some(path) = credentials_path() else {
        return Ok(None);
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("the credentials file {} is damaged", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("cannot read credentials {}", path.display()))
        }
    }
}

/// Writes the credentials file, readable by the user only, and returns its path.
///
/// # Errors
///
/// No location for the file, or an I/O error.
pub fn store_credentials(credentials: &Credentials) -> anyhow::Result<PathBuf> {
    let path = credentials_path().context(
        "no place for the credentials file: set APPDATA, XDG_CONFIG_HOME, HOME or TENKO_CREDENTIALS",
    )?;
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(credentials).context("encoding the credentials")?;
    let temporary = path.with_extension("json.tmp");
    write_private(&temporary, &bytes)?;
    std::fs::rename(&temporary, &path)
        .with_context(|| format!("cannot write credentials {}", path.display()))?;
    Ok(path)
}

/// Deletes the credentials file; a missing file is fine.
///
/// # Errors
///
/// An I/O error other than a missing file.
pub fn delete_credentials() -> anyhow::Result<Option<PathBuf>> {
    let Some(path) = credentials_path() else {
        return Ok(None);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("cannot delete credentials {}", path.display()))
        }
    }
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create {}", dir.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot restrict {}", path.display()))?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", path.display()))
}

/// A connection to a controller: where it is and how to authenticate.
#[derive(Debug, Clone)]
pub struct Target {
    /// Base URL.
    pub url: String,
    /// The root certificate file.
    pub ca_file: Option<PathBuf>,
    /// The token, if any.
    token: Option<String>,
    /// Print raw JSON.
    pub json: bool,
}

impl Target {
    /// The target of `opts`: flags first, then `TENKO_TOKEN`, then the stored credentials.
    ///
    /// # Errors
    ///
    /// No URL anywhere, or unreadable credentials.
    pub fn resolve(opts: &ClientOpts, need_token: bool) -> Result<Self, Failure> {
        let stored = load_credentials().map_err(Failure::other)?;
        let env_token = std::env::var(TOKEN_ENV)
            .ok()
            .filter(|token| !token.is_empty());
        let url = opts
            .url
            .clone()
            .or_else(|| stored.as_ref().map(|credentials| credentials.url.clone()))
            .ok_or_else(|| {
                Failure::new(
                    exit::USAGE,
                    "no server: pass --url (or set TENKO_URL), or sign in with `tenko login`",
                )
            })?;
        let same_server = stored
            .as_ref()
            .is_some_and(|credentials| same_url(&credentials.url, &url));
        let ca_file = opts.ca_file.clone().or_else(|| {
            stored
                .as_ref()
                .filter(|_| same_server)
                .and_then(|credentials| credentials.ca_file.clone())
        });
        let token = env_token.or_else(|| {
            stored
                .filter(|_| same_server)
                .map(|credentials| credentials.token)
        });
        if need_token && token.is_none() {
            return Err(Failure::new(
                exit::AUTH,
                format!("not signed in to {url}: run `tenko login` (or set {TOKEN_ENV})"),
            ));
        }
        Ok(Self {
            url,
            ca_file,
            token,
            json: opts.json,
        })
    }

    /// The API client.
    ///
    /// # Errors
    ///
    /// The root certificate file cannot be read, or the client cannot be built.
    pub fn client(&self) -> Result<Client, Failure> {
        let mut config = ClientConfig::new(self.url.clone());
        config.token.clone_from(&self.token);
        config.root_ca_pem = self.root_pem()?;
        config.timeout = TIMEOUT;
        Client::new(config).map_err(|error| Failure::from_client(&error))
    }

    /// The raw HTTP helper for cookies and uploads.
    ///
    /// # Errors
    ///
    /// As [`Target::client`].
    pub fn raw(&self) -> Result<Raw, Failure> {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .user_agent(format!("tenko/{}", crate::version()))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT);
        if let Some(pem) = self.root_pem()? {
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|error| Failure::other(format!("the CA file is not PEM: {error}")))?;
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = builder
            .build()
            .map_err(|error| Failure::other(format!("HTTP client: {error}")))?;
        let base = self.url.trim_end_matches('/').to_owned();
        let origin = origin_of(&base).ok_or_else(|| {
            Failure::new(exit::USAGE, format!("`{}` is not an http(s) URL", self.url))
        })?;
        Ok(Raw {
            http,
            base,
            origin,
            token: self.token.clone(),
        })
    }

    fn root_pem(&self) -> Result<Option<Vec<u8>>, Failure> {
        self.ca_file
            .as_ref()
            .map(|path| {
                std::fs::read(path).map_err(|error| {
                    Failure::new(
                        exit::USAGE,
                        format!("cannot read the CA file {}: {error}", path.display()),
                    )
                })
            })
            .transpose()
    }
}

/// Whether two base URLs name the same server (case and a trailing slash aside).
fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim_end_matches('/'))
}

/// `scheme://host[:port]` of a URL.
fn origin_of(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

/// Requests outside the typed client: the login ceremony with its session cookie, and
/// multipart uploads.
#[derive(Debug, Clone)]
pub struct Raw {
    http: reqwest::Client,
    base: String,
    origin: String,
    token: Option<String>,
}

/// A raw answer.
#[derive(Debug)]
pub struct RawResponse {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Vec<u8>,
}

impl RawResponse {
    /// The JSON body as `T` after a 2xx, or the failure of a problem answer.
    ///
    /// # Errors
    ///
    /// A non-2xx answer, or a body that is not a `T`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Failure> {
        self.check()?;
        serde_json::from_slice(&self.body)
            .map_err(|error| Failure::other(format!("unexpected answer: {error}")))
    }

    /// `Ok` for a 2xx answer.
    ///
    /// # Errors
    ///
    /// The problem details or status of anything else.
    pub fn check(&self) -> Result<(), Failure> {
        if self.status.is_success() {
            return Ok(());
        }
        let is_problem = self
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/problem+json"));
        if is_problem && let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&self.body) {
            return Err(Failure::problem(problem));
        }
        Err(Failure::new(
            exit::API,
            format!(
                "unexpected HTTP status {}: {}",
                self.status.as_u16(),
                String::from_utf8_lossy(&self.body[..self.body.len().min(512)]).trim()
            ),
        ))
    }

    /// The value of the session cookie the answer sets.
    pub fn session_cookie(&self) -> Option<String> {
        self.headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, value)| *name == tenko_core::auth::SESSION_COOKIE && !value.is_empty())
            .map(|(_, value)| value.to_owned())
    }
}

impl Raw {
    /// `POST /api/v1{path}` with a JSON body, the session cookie when given, and the
    /// server's own `Origin` (the CSRF guard asks for it next to a cookie).
    ///
    /// # Errors
    ///
    /// The server cannot be reached.
    pub async fn post_json<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
        session: Option<&str>,
    ) -> Result<RawResponse, Failure> {
        let request = self
            .http
            .post(self.url(path))
            .header(ORIGIN, &self.origin)
            .json(body);
        self.send(with_session(request, session)).await
    }

    /// `DELETE /api/v1{path}` authenticated with `token`.
    ///
    /// # Errors
    ///
    /// The server cannot be reached.
    pub async fn delete_with_token(&self, path: &str, token: &str) -> Result<RawResponse, Failure> {
        let request = self.http.delete(self.url(path)).bearer_auth(token);
        self.send(request).await
    }

    /// `POST /api/v1{path}` with a `multipart/form-data` body of one file field, with the
    /// token. No `Idempotency-Key`: the idempotency middleware buffers keyed requests under
    /// a smaller limit than an upload may have.
    ///
    /// # Errors
    ///
    /// The server cannot be reached.
    pub async fn upload(
        &self,
        path: &str,
        field: &str,
        file_name: &str,
        bytes: Vec<u8>,
    ) -> Result<RawResponse, Failure> {
        let boundary = format!("tenko-{}", uuid::Uuid::now_v7().simple());
        let mut body = Vec::with_capacity(bytes.len() + 512);
        let safe_name: String = file_name
            .chars()
            .map(|c| if c == '"' || c.is_control() { '_' } else { c })
            .collect();
        let _ = write!(
            Header(&mut body),
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; \
             filename=\"{safe_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        );
        body.extend_from_slice(&bytes);
        let _ = write!(Header(&mut body), "\r\n--{boundary}--\r\n");
        let mut request = self
            .http
            .post(self.url(path))
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        self.send(request).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}{path}", self.base, tenko_api::API_BASE)
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<RawResponse, Failure> {
        let response = request.send().await.map_err(|error| {
            Failure::new(
                exit::UNREACHABLE,
                format!("cannot reach {}: {}", self.base, chain(&error)),
            )
        })?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .map_err(|error| {
                Failure::new(
                    exit::UNREACHABLE,
                    format!("reading the answer: {}", chain(&error)),
                )
            })?
            .to_vec();
        Ok(RawResponse {
            status,
            headers,
            body,
        })
    }
}

/// `fmt::Write` over a byte buffer.
struct Header<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for Header<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.0.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

fn with_session(
    request: reqwest::RequestBuilder,
    session: Option<&str>,
) -> reqwest::RequestBuilder {
    match session {
        Some(secret) => {
            let mut value = reqwest::header::HeaderValue::from_str(&format!(
                "{}={secret}",
                tenko_core::auth::SESSION_COOKIE
            ))
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
            value.set_sensitive(true);
            request.header(COOKIE, value)
        }
        None => request,
    }
}

/// An error with its causes on one line.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(source) = cause {
        let _ = write!(text, ": {source}");
        cause = source.source();
    }
    text
}

/// Why a client command failed: the exit status, one line for people, and the raw problem
/// details for `--json`.
#[derive(Debug, Clone)]
pub struct Failure {
    /// The exit status.
    pub status: u8,
    /// One line, without the `error` prefix.
    pub message: String,
    /// The problem details, when the server sent them.
    pub problem: Option<Box<ProblemDetails>>,
}

impl Failure {
    /// A failure with a status and a message.
    pub fn new(status: u8, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            problem: None,
        }
    }

    /// An unexpected failure (exit status 1).
    pub fn other(message: impl std::fmt::Display) -> Self {
        Self::new(exit::FAILURE, message.to_string())
    }

    /// The failure of a problem answer.
    pub fn problem(problem: ProblemDetails) -> Self {
        let status = if problem.status == 401 {
            exit::AUTH
        } else {
            exit::API
        };
        let hint = if problem.status == 401 {
            " (sign in again with `tenko login`)"
        } else {
            ""
        };
        let fields = if problem.errors.is_empty() {
            String::new()
        } else {
            let list: Vec<String> = problem
                .errors
                .iter()
                .map(|error| format!("{}: {}", error.field, error.code))
                .collect();
            format!(" [{}]", list.join(", "))
        };
        Self {
            status,
            message: format!(
                "[{}] {}{fields} (HTTP {}){hint}",
                problem.code, problem.detail, problem.status
            ),
            problem: Some(Box::new(problem)),
        }
    }

    /// The failure of an API client error.
    pub fn from_client(error: &ClientError) -> Self {
        match error {
            ClientError::Problem(problem) => Self::problem(problem.clone()),
            ClientError::Transport(_) => Self::new(exit::UNREACHABLE, error.to_string()),
            ClientError::UnexpectedStatus { status: 401, .. } => {
                Self::new(exit::AUTH, error.to_string())
            }
            ClientError::UnexpectedStatus { .. } => Self::new(exit::API, error.to_string()),
            ClientError::InvalidConfig(_) => Self::new(exit::USAGE, error.to_string()),
            ClientError::Decode(_) => Self::other(error),
        }
    }

    /// Prints the failure: problem details as JSON on `out` with `--json`, else one line on
    /// `err`. Returns the exit status.
    pub fn report(
        &self,
        command: &str,
        json: bool,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> u8 {
        match (&self.problem, json) {
            (Some(problem), true) => {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(problem).unwrap_or_default()
                );
            }
            _ => {
                let _ = writeln!(err, "tenko {command}: error{}", prefixed(&self.message));
            }
        }
        self.status
    }
}

/// `[code] detail` stays as is after `error`; anything else gets `: `.
fn prefixed(message: &str) -> String {
    if message.starts_with('[') {
        message.to_owned()
    } else {
        format!(": {message}")
    }
}

impl From<ClientError> for Failure {
    fn from(error: ClientError) -> Self {
        Self::from_client(&error)
    }
}

/// The result of a client command.
pub type Outcome = Result<(), Failure>;

/// Runs a client command future on a small runtime and maps the outcome to an exit status.
pub fn block_on(
    command: &str,
    json: bool,
    out: &mut impl Write,
    err: &mut impl Write,
    future: impl Future<Output = Result<Output, Failure>>,
) -> u8 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "tenko {command}: error: runtime: {error}");
            return exit::FAILURE;
        }
    };
    match runtime.block_on(future) {
        Ok(output) => output.write(out, err),
        Err(failure) => failure.report(command, json, out, err),
    }
}

/// What a successful command prints.
#[derive(Debug, Default)]
pub struct Output {
    /// Standard output.
    pub stdout: String,
    /// Standard error (notes, warnings).
    pub stderr: String,
    /// The exit status (0 unless a command reports a non-fatal condition).
    pub status: u8,
}

impl Output {
    /// Output with text on standard output.
    pub fn text(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            ..Self::default()
        }
    }

    /// Pretty JSON on standard output.
    pub fn json(value: &impl Serialize) -> Self {
        let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
        text.push('\n');
        Self::text(text)
    }

    /// Adds a note on standard error.
    #[must_use]
    pub fn note(mut self, note: impl std::fmt::Display) -> Self {
        let _ = writeln!(self.stderr, "{note}");
        self
    }

    fn write(self, out: &mut impl Write, err: &mut impl Write) -> u8 {
        let _ = out.write_all(self.stdout.as_bytes());
        let _ = err.write_all(self.stderr.as_bytes());
        let _ = out.flush();
        self.status
    }
}

/// Reads a secret: one line of standard input with `from_stdin`, else a prompt without echo
/// on the terminal.
///
/// # Errors
///
/// No terminal and no `--password-stdin`, or an I/O error.
pub fn read_secret(prompt: &str, from_stdin: bool) -> Result<Secret, Failure> {
    if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|error| Failure::other(format!("reading standard input: {error}")))?;
        let secret = line.trim_end_matches(['\r', '\n']).to_owned();
        line.clear();
        return Ok(Secret::new(secret));
    }
    if !std::io::stdin().is_terminal() {
        return Err(Failure::new(
            exit::USAGE,
            "no terminal to ask for the secret: pass it on standard input with --password-stdin",
        ));
    }
    rpassword::prompt_password(prompt)
        .map(Secret::new)
        .map_err(|error| Failure::other(format!("reading the secret: {error}")))
}

/// Reads one visible line (a TOTP code) from the terminal or standard input.
///
/// # Errors
///
/// An I/O error.
pub fn read_line(prompt: &str) -> Result<String, Failure> {
    if std::io::stdin().is_terminal() {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
    }
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| Failure::other(format!("reading standard input: {error}")))?;
    Ok(line.trim().to_owned())
}

/// A secret typed by the user (a password, a recovery code); wiped when dropped, redacted in
/// `Debug` output.
pub struct Secret(SecretString);

impl Secret {
    /// Wraps a string.
    pub fn new(value: String) -> Self {
        Self(SecretString::new(value))
    }

    /// The text.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// The value as the DTO type of the API.
    pub fn to_dto(&self) -> SecretString {
        SecretString::new(self.0.expose())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Renders `tenko roles list`: one line per role with its description.
pub fn render_roles() -> String {
    let width = Role::ALL
        .iter()
        .map(|role| role.as_str().len())
        .max()
        .unwrap_or_default();
    let mut out = String::new();
    for role in Role::ALL {
        let _ = writeln!(out, "{:<width$}  {}", role.as_str(), role.description());
    }
    out
}

/// A table with left-aligned columns and two spaces between them.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|title| title.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(cell.chars().count());
            }
        }
    }
    let mut out = String::new();
    let mut line = |cells: &mut dyn Iterator<Item = &str>| {
        let mut text = String::new();
        for (index, cell) in cells.enumerate() {
            if index > 0 {
                text.push_str("  ");
            }
            let width = widths.get(index).copied().unwrap_or_default();
            let _ = write!(text, "{cell:<width$}");
        }
        let _ = writeln!(out, "{}", text.trim_end());
    };
    line(&mut header.iter().copied());
    for row in rows {
        line(&mut row.iter().map(String::as_str));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_render_one_line_per_role() {
        let output = render_roles();
        assert_eq!(output.lines().count(), Role::ALL.len());
        for role in Role::ALL {
            assert!(output.contains(role.as_str()));
            assert!(output.contains(role.description()));
        }
    }

    #[test]
    fn tables_align_columns() {
        let text = table(
            &["CIDR", "STATUS"],
            &[
                vec!["192.0.2.0/24".to_owned(), "active".to_owned()],
                vec!["10.0.0.0/8".to_owned(), "reserved".to_owned()],
            ],
        );
        assert_eq!(
            text,
            "CIDR          STATUS\n192.0.2.0/24  active\n10.0.0.0/8    reserved\n"
        );
    }

    #[test]
    fn origins_drop_the_path_and_keep_the_port() {
        assert_eq!(
            origin_of("https://DDI.example.org:8443/tenko/").as_deref(),
            Some("https://ddi.example.org:8443")
        );
        assert_eq!(
            origin_of("https://ddi.example.org:443").as_deref(),
            Some("https://ddi.example.org")
        );
        assert_eq!(origin_of("ftp://x"), None);
        assert!(same_url("https://a.example/", "HTTPS://A.EXAMPLE"));
    }

    #[test]
    fn problems_print_one_line_with_the_code() {
        let problem = ProblemDetails {
            type_: "about:blank".to_owned(),
            status: 409,
            code: "ipam.prefix.overlap".to_owned(),
            title: "Conflict".to_owned(),
            detail: "192.0.2.0/25 overlaps 192.0.2.0/24".to_owned(),
            params: std::collections::BTreeMap::new(),
            errors: Vec::new(),
            instance: None,
        };
        let failure = Failure::problem(problem);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            failure.report("prefix create", false, &mut out, &mut err),
            exit::API
        );
        assert_eq!(out, b"");
        assert_eq!(
            String::from_utf8(err).expect("UTF-8"),
            "tenko prefix create: error[ipam.prefix.overlap] 192.0.2.0/25 overlaps 192.0.2.0/24 \
             (HTTP 409)\n"
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        failure.report("prefix create", true, &mut out, &mut err);
        assert_eq!(err, b"");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("JSON");
        assert_eq!(value["code"], "ipam.prefix.overlap");
    }

    #[test]
    fn unauthenticated_problems_suggest_login() {
        let problem = ProblemDetails {
            type_: "about:blank".to_owned(),
            status: 401,
            code: "auth.unauthenticated".to_owned(),
            title: "Unauthorized".to_owned(),
            detail: "no valid session or token".to_owned(),
            params: std::collections::BTreeMap::new(),
            errors: Vec::new(),
            instance: None,
        };
        let failure = Failure::problem(problem);
        assert_eq!(failure.status, exit::AUTH);
        assert!(failure.message.contains("tenko login"));
    }

    #[test]
    fn session_cookies_are_found_among_other_cookies() {
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, "other=1; Path=/".parse().expect("header"));
        headers.append(
            SET_COOKIE,
            "tenko_session=abc; Path=/; HttpOnly"
                .parse()
                .expect("header"),
        );
        let response = RawResponse {
            status: StatusCode::OK,
            headers,
            body: Vec::new(),
        };
        assert_eq!(response.session_cookie().as_deref(), Some("abc"));
    }

    #[test]
    fn credentials_never_print_the_token() {
        let credentials = Credentials {
            url: "https://ddi.example.org".to_owned(),
            ca_file: None,
            user: "admin".to_owned(),
            token: "tnk_secret".to_owned(),
            token_id: "id".to_owned(),
        };
        assert!(!format!("{credentials:?}").contains("tnk_secret"));
    }
}
