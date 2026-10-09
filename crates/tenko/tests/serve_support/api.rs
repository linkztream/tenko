//! A JSON client of the public API for the acceptance tests: the requests a browser or a
//! script sends to a running [`Node`], synchronous for the test, with the session cookie
//! kept between calls.
//!
//! - Paths are relative to `/api/v1`. Every answer comes back as a [`Reply`] (status,
//!   headers, body); the test decides what it expects, and failures print the body.
//! - Mutations carry the node's origin in `Origin`, as a browser does: the CSRF guard
//!   refuses a request with the session cookie and without it. `POST` carries a fresh
//!   `Idempotency-Key` unless the call says otherwise (uploads and logins send none).
//! - The session is the `tenko_session` cookie of the last setup or login. A session, not
//!   a personal token, is what a person has: storing operator secrets needs one (IAM-07).
//! - [`Totp`] computes the codes of an enrolled authenticator app with the product's
//!   RFC 6238 implementation (its vectors are tested in `tenko-auth`), never reusing a step.
//! - [`Events`] reads the server-sent event stream.

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::{Method, header::HeaderMap};
use serde_json::{Value, json};
use tenko_auth::totp::{TotpParams, code_at, step_at};

use super::{ADMIN, Node, PASSWORD};

/// The display name of the administrator the API helpers create.
pub const ADMIN_DISPLAY_NAME: &str = "Ada Admin";

/// How long one request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// One answer of the API.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The response headers.
    pub headers: HeaderMap,
    /// The body as text.
    pub text: String,
}

impl Reply {
    /// The body as JSON, or `null` when it is not JSON.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    /// The stable code of problem details.
    pub fn code(&self) -> Option<String> {
        self.json()["code"].as_str().map(str::to_owned)
    }

    /// A header as text.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// Asserts the status and returns the JSON body.
    #[track_caller]
    pub fn expect(&self, status: u16) -> Value {
        assert_eq!(self.status, status, "unexpected answer: {}", self.text);
        self.json()
    }

    /// Asserts a 2xx status and returns the JSON body.
    #[track_caller]
    pub fn ok(&self) -> Value {
        assert!(
            (200..300).contains(&self.status),
            "HTTP {}: {}",
            self.status,
            self.text
        );
        self.json()
    }
}

/// The codes of one enrolled authenticator app.
pub struct Totp {
    secret: Vec<u8>,
    params: TotpParams,
    last_step: Option<u64>,
}

impl Totp {
    /// An authenticator for a base32 secret as the enrolment shows it.
    #[track_caller]
    pub fn new(secret_base32: &str) -> Self {
        let secret = tenko_auth::encoding::base32_decode(secret_base32.trim())
            .expect("the enrolment secret is base32");
        Self {
            secret,
            params: TotpParams::default(),
            last_step: None,
        }
    }

    /// A code the server accepts now: the current step, or the next one when the current
    /// one was used already (the server refuses a replayed step and allows one step of
    /// drift).
    #[track_caller]
    pub fn code(&mut self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_secs();
        let current = step_at(&self.params, now);
        let step = self.last_step.map_or(current, |last| current.max(last + 1));
        assert!(
            step <= current + 1,
            "no unused TOTP step within the drift the server allows"
        );
        self.last_step = Some(step);
        code_at(&self.secret, &self.params, step * self.params.period).to_string()
    }
}

/// A client of one node's API.
pub struct Api {
    runtime: Arc<tokio::runtime::Runtime>,
    client: reqwest::Client,
    base: String,
    cookie: Option<String>,
}

impl Api {
    /// A client of `node`, trusting the node's internal CA when it serves HTTPS.
    pub fn new(node: &Node) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT);
        if let Some(path) = node.ca_file() {
            let pem = std::fs::read(&path).expect("the CA root of the node");
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).expect("the CA root is PEM"),
            );
        }
        Self {
            runtime: Arc::new(runtime),
            client: builder.build().expect("an HTTP client"),
            base: node.url(),
            cookie: None,
        }
    }

    /// A second client of the same node without a session.
    pub fn anonymous(&self) -> Self {
        Self {
            runtime: Arc::clone(&self.runtime),
            client: self.client.clone(),
            base: self.base.clone(),
            cookie: None,
        }
    }

    /// The node's origin.
    pub fn origin(&self) -> &str {
        &self.base
    }

    /// The session cookie (`tenko_session=...`), if signed in.
    pub fn cookie(&self) -> Option<&str> {
        self.cookie.as_deref()
    }

    /// Uses a session cookie kept from before (a restart).
    pub fn set_cookie(&mut self, cookie: Option<String>) {
        self.cookie = cookie;
    }

    /// The absolute URL of an API path.
    pub fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.base)
    }

    /// Sends one request. `headers` come on top of the cookie and, for mutations, `Origin`.
    pub fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<(&str, Vec<u8>)>,
        headers: &[(&str, String)],
    ) -> Reply {
        let mutation = method != Method::GET && method != Method::HEAD;
        let mut request = self.client.request(method, self.url(path));
        if let Some(cookie) = &self.cookie {
            request = request.header("Cookie", cookie);
        }
        if mutation {
            request = request.header("Origin", &self.base);
        }
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        if let Some((content_type, bytes)) = body {
            request = request.header("Content-Type", content_type).body(bytes);
        }
        self.runtime.block_on(async {
            let response = request
                .send()
                .await
                .unwrap_or_else(|error| panic!("{path}: {error:?}"));
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let text = response.text().await.expect("a readable body");
            Reply {
                status,
                headers,
                text,
            }
        })
    }

    fn json_body(body: &Value) -> (&'static str, Vec<u8>) {
        ("application/json", serde_json::to_vec(body).expect("JSON"))
    }

    /// `GET`.
    pub fn get(&self, path: &str) -> Reply {
        self.send(Method::GET, path, None, &[])
    }

    /// `POST` with a JSON body and a fresh `Idempotency-Key`.
    pub fn post(&self, path: &str, body: &Value) -> Reply {
        let key = uuid::Uuid::now_v7().to_string();
        self.send(
            Method::POST,
            path,
            Some(Self::json_body(body)),
            &[("Idempotency-Key", key)],
        )
    }

    /// `POST` with a JSON body and no `Idempotency-Key`.
    pub fn post_unkeyed(&self, path: &str, body: &Value) -> Reply {
        self.send(Method::POST, path, Some(Self::json_body(body)), &[])
    }

    /// `PUT` with a JSON body.
    pub fn put(&self, path: &str, body: &Value) -> Reply {
        self.send(Method::PUT, path, Some(Self::json_body(body)), &[])
    }

    /// `PATCH` with `If-Match` of `revision`, or `*`.
    pub fn patch(&self, path: &str, body: &Value, revision: Option<u64>) -> Reply {
        let if_match = revision.map_or_else(|| "*".to_owned(), |r| format!("\"{r}\""));
        self.send(
            Method::PATCH,
            path,
            Some(Self::json_body(body)),
            &[("If-Match", if_match)],
        )
    }

    /// `DELETE` with `If-Match` of `revision`, or `*`.
    pub fn delete(&self, path: &str, revision: Option<u64>) -> Reply {
        let if_match = revision.map_or_else(|| "*".to_owned(), |r| format!("\"{r}\""));
        self.send(Method::DELETE, path, None, &[("If-Match", if_match)])
    }

    /// A `multipart/form-data` upload of files in the field `file`, without an
    /// `Idempotency-Key` (the idempotency middleware buffers keyed bodies under a small
    /// limit).
    pub fn upload(&self, path: &str, files: &[(&str, &[u8])]) -> Reply {
        let boundary = format!("tenko-test-{}", uuid::Uuid::now_v7().simple());
        let mut body = Vec::new();
        for (name, bytes) in files {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
                     Content-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let content_type = format!("multipart/form-data; boundary={boundary}");
        self.send(Method::POST, path, Some((&content_type, body)), &[])
    }

    /// Keeps the session cookie a reply sets.
    fn keep_cookie(&mut self, reply: &Reply) {
        for value in reply.headers.get_all("set-cookie") {
            let Ok(text) = value.to_str() else { continue };
            let pair = text.split(';').next().unwrap_or_default().trim();
            if let Some(secret) = pair.strip_prefix("tenko_session=") {
                self.cookie = (!secret.is_empty()).then(|| pair.to_owned());
            }
        }
    }

    /// First-run setup through the API with the administrator of the tests under the Home
    /// profile; the answer signs this client in. Returns the answer.
    #[track_caller]
    pub fn setup(&mut self, token: &str) -> Value {
        let reply = self.post_unkeyed(
            "/setup",
            &json!({
                "setup_token": token,
                "profile": "home",
                "admin": { "name": ADMIN, "display_name": ADMIN_DISPLAY_NAME, "password": PASSWORD },
                "host_name": "localhost",
                "language": "en",
            }),
        );
        let body = reply.expect(200);
        self.keep_cookie(&reply);
        assert!(self.cookie.is_some(), "setup set no session cookie");
        body
    }

    /// The password step of a login as the administrator; keeps the cookie when the login
    /// is complete. Returns the answer (`authenticated` or `second_factor`).
    #[track_caller]
    pub fn login_password(&mut self) -> Value {
        let reply = self.post_unkeyed(
            "/auth/login/password",
            &json!({ "user_name": ADMIN, "password": PASSWORD }),
        );
        let body = reply.expect(200);
        self.keep_cookie(&reply);
        body
    }

    /// A login with the password and, when asked for, a code of `totp`. Returns the
    /// session.
    #[track_caller]
    pub fn login(&mut self, totp: Option<&mut Totp>) -> Value {
        let first = self.login_password();
        if first["status"] == "authenticated" {
            return first["session"].clone();
        }
        assert_eq!(first["status"], "second_factor", "{first}");
        let totp = totp.expect("the login asks for a second factor");
        let reply = self.post_unkeyed(
            "/auth/login/totp",
            &json!({ "challenge_id": first["challenge_id"], "code": totp.code() }),
        );
        let body = reply.expect(200);
        self.keep_cookie(&reply);
        assert_eq!(body["status"], "authenticated", "{body}");
        body["session"].clone()
    }

    /// Ends the session.
    #[track_caller]
    pub fn logout(&mut self) {
        let reply = self.post_unkeyed("/auth/logout", &json!({}));
        assert!(
            reply.status < 300,
            "logout: HTTP {} {}",
            reply.status,
            reply.text
        );
        self.cookie = None;
    }

    /// Enrols an authenticator app for the signed-in user; its first code is spent.
    #[track_caller]
    pub fn enrol_totp(&self) -> Totp {
        let start = self
            .post_unkeyed("/auth/totp/enroll/start", &json!({}))
            .expect(200);
        let mut totp = Totp::new(start["secret"].as_str().expect("a secret"));
        self.post_unkeyed(
            "/auth/totp/enroll/finish",
            &json!({ "enrolment_id": start["enrolment_id"], "code": totp.code() }),
        )
        .expect(200);
        totp
    }

    /// Setup, an authenticator app, and a new session with password and TOTP: the
    /// strength that may store operator secrets (IAM-07).
    #[track_caller]
    pub fn setup_strong(&mut self, token: &str) -> Totp {
        self.setup(token);
        let mut totp = self.enrol_totp();
        self.logout();
        let session = self.login(Some(&mut totp));
        assert_eq!(session["strength"], "password_totp", "{session}");
        totp
    }

    /// Every item of a list, following `next_cursor`.
    #[track_caller]
    pub fn list_all(&self, path: &str) -> Vec<Value> {
        let separator = if path.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page_path = match &cursor {
                Some(cursor) => format!("{path}{separator}limit=1000&cursor={cursor}"),
                None => format!("{path}{separator}limit=1000"),
            };
            let page = self.get(&page_path).expect(200);
            items.extend(page["items"].as_array().cloned().unwrap_or_default());
            match page["next_cursor"].as_str() {
                Some(next) if !next.is_empty() => cursor = Some(next.to_owned()),
                _ => return items,
            }
        }
    }

    /// `GET /jobs/{id}` until the job is final or `timeout` passed; the last detail.
    #[track_caller]
    pub fn wait_for_job(&self, id: &str, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let detail = self.get(&format!("/jobs/{id}")).expect(200);
            let state = detail["job"]["state"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let done = matches!(
                state.as_str(),
                "succeeded" | "failed" | "rolled_back" | "cancelled"
            );
            if done || Instant::now() > deadline {
                return detail;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `GET /jobs/{id}` until `wanted` accepts the detail or `timeout` passed.
    #[track_caller]
    pub fn wait_for_job_until(
        &self,
        id: &str,
        timeout: Duration,
        wanted: impl Fn(&Value) -> bool,
    ) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let detail = self.get(&format!("/jobs/{id}")).expect(200);
            if wanted(&detail) {
                return detail;
            }
            assert!(
                Instant::now() < deadline,
                "job {id} did not reach the wanted state: {detail}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Opens the event stream (`GET /events?<query>`).
    #[track_caller]
    pub fn events(&self, query: &str) -> Events {
        let mut request = self
            .client
            .get(self.url(&format!("/events?{query}")))
            .timeout(Duration::from_secs(3600));
        if let Some(cookie) = &self.cookie {
            request = request.header("Cookie", cookie);
        }
        let response = self
            .runtime
            .block_on(async { request.send().await })
            .unwrap_or_else(|error| panic!("events: {error:?}"));
        assert_eq!(response.status().as_u16(), 200, "the event stream opens");
        Events {
            runtime: Arc::clone(&self.runtime),
            response,
            buffer: String::new(),
        }
    }
}

/// One server-sent event.
#[derive(Debug, Clone, Default)]
pub struct SseEvent {
    /// The event name (the topic, `reset` or `shutdown`).
    pub event: String,
    /// The event id (a store revision).
    pub id: Option<String>,
    /// The data, lines joined.
    pub data: String,
}

impl SseEvent {
    /// The data as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.data).unwrap_or(Value::Null)
    }
}

/// An open event stream.
pub struct Events {
    runtime: Arc<tokio::runtime::Runtime>,
    response: reqwest::Response,
    buffer: String,
}

impl Events {
    /// The next event (comments skipped), or `None` when the stream ends or `timeout`
    /// passes.
    pub fn next(&mut self, timeout: Duration) -> Option<SseEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(event) = self.take_event() {
                return Some(event);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            let chunk = self
                .runtime
                .block_on(async { tokio::time::timeout(left, self.response.chunk()).await });
            match chunk {
                Ok(Ok(Some(bytes))) => self
                    .buffer
                    .push_str(&String::from_utf8_lossy(&bytes).replace("\r\n", "\n")),
                Ok(Ok(None) | Err(_)) | Err(_) => return None,
            }
        }
    }

    /// The first event `wanted` accepts, skipping others, within `timeout`.
    pub fn next_matching(
        &mut self,
        timeout: Duration,
        wanted: impl Fn(&SseEvent) -> bool,
    ) -> Option<SseEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            let event = self.next(left)?;
            if wanted(&event) {
                return Some(event);
            }
        }
    }

    /// Parses one complete event out of the buffer.
    fn take_event(&mut self) -> Option<SseEvent> {
        loop {
            let end = self.buffer.find("\n\n")?;
            let block: String = self.buffer[..end].to_owned();
            self.buffer.drain(..end + 2);
            let mut event = SseEvent::default();
            let mut data = Vec::new();
            let mut any = false;
            for line in block.lines() {
                if line.starts_with(':') {
                    continue;
                }
                let (field, value) = line.split_once(':').unwrap_or((line, ""));
                let value = value.strip_prefix(' ').unwrap_or(value);
                any = true;
                match field {
                    "event" => value.clone_into(&mut event.event),
                    "id" => event.id = Some(value.to_owned()),
                    "data" => data.push(value.to_owned()),
                    _ => {}
                }
            }
            if any {
                event.data = data.join("\n");
                if event.event.is_empty() {
                    "message".clone_into(&mut event.event);
                }
                return Some(event);
            }
        }
    }
}
