//! An in-process stand-in for a UniFi Network application, for the integration tests of the
//! plugin.
//!
//! [`FakeController`] serves, on a loopback port, the parts of the classic API and of the
//! Integration API that the plugin uses, in the two deployments the plugin knows (a
//! self-hosted application and a UniFi OS console), over plain HTTP or over TLS with a fresh
//! self-signed certificate. It is loaded with the fixtures under `tests/fixtures/classic`
//! (one site, six devices of which one is not adopted, clients, networks, wireless networks
//! and port profiles) and behaves like a controller where the plugin depends on it: sessions
//! with a cookie and a CSRF token, error codes, name and VLAN uniqueness, and rate limits.
//!
//! A test changes the data through [`FakeController::state`] between calls and checks what
//! the plugin wrote through [`FakeController::writes`].

#![allow(
    dead_code,
    reason = "every test binary uses a different part of the shared fake controller"
)]

mod classic;
pub mod integration;
mod tls;

use std::{
    collections::HashMap,
    hash::BuildHasher as _,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State as AxumState},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use tenko_connect::{CallContext, Secrets};
use tokio::{net::TcpListener, task::JoinHandle};

/// The user name of the local account the fake accepts.
pub const USERNAME: &str = "tenko-test";

/// The password of the local account the fake accepts.
pub const PASSWORD: &str = "fake-password-1";

/// The Integration API key the fake accepts.
pub const API_KEY: &str = "fake-integration-key-0001";

/// The version the fake reports.
pub const VERSION: &str = "9.0.0";

/// The `_id` of the one site (short name `default`).
pub const SITE_ID: &str = "5f0000000000000000000001";

/// The ids and MAC addresses of the fixtures, for the assertions of the tests.
pub mod ids {
    /// The Default network (untagged, `attr_no_delete`).
    pub const NET_DEFAULT: &str = "5f1000000000000000000001";
    /// The `IoT` network (VLAN 30, given as text in the fixture).
    pub const NET_IOT: &str = "5f1000000000000000000002";
    /// The Guest network (VLAN 40).
    pub const NET_GUEST: &str = "5f1000000000000000000003";
    /// The Lab network (VLAN-only, VLAN 50).
    pub const NET_LAB: &str = "5f1000000000000000000004";
    /// The Relay network (VLAN 60, DHCP relay).
    pub const NET_RELAY: &str = "5f1000000000000000000005";
    /// The WAN network.
    pub const NET_WAN: &str = "5f1000000000000000000006";

    /// The "All" port profile.
    pub const PROFILE_ALL: &str = "5f2000000000000000000001";
    /// The "Disabled" port profile.
    pub const PROFILE_DISABLED: &str = "5f2000000000000000000002";
    /// The "`IoT`" port profile (native `IoT`).
    pub const PROFILE_IOT: &str = "5f2000000000000000000003";
    /// The "Trunk" port profile (native Default, tagged `IoT` and Guest).
    pub const PROFILE_TRUNK: &str = "5f2000000000000000000004";
    /// The "Old custom" port profile (excludes Guest, no tagged list).
    pub const PROFILE_OLD_CUSTOM: &str = "5f2000000000000000000005";

    /// The `home.example` wireless network.
    pub const WLAN_HOME: &str = "5f3000000000000000000001";
    /// The `iot.example` wireless network.
    pub const WLAN_IOT: &str = "5f3000000000000000000002";
    /// The `guest.example` wireless network.
    pub const WLAN_GUEST: &str = "5f3000000000000000000003";
    /// The `legacy.example` wireless network (VLAN 30, no network).
    pub const WLAN_LEGACY: &str = "5f3000000000000000000004";
    /// The `off.example` wireless network (disabled).
    pub const WLAN_OFF: &str = "5f3000000000000000000005";

    /// The `_id` of the gateway.
    pub const DEV_GATEWAY: &str = "5f4000000000000000000001";
    /// The `_id` of sw-core.
    pub const DEV_CORE: &str = "5f4000000000000000000002";
    /// The `_id` of sw-access.
    pub const DEV_ACCESS: &str = "5f4000000000000000000003";
    /// The `_id` of ap-hall.
    pub const DEV_HALL: &str = "5f4000000000000000000004";
    /// The `_id` of ap-garden.
    pub const DEV_GARDEN: &str = "5f4000000000000000000005";
    /// The `_id` of the device that is not adopted.
    pub const DEV_PENDING: &str = "5f4000000000000000000006";

    /// The gateway (UXG).
    pub const GATEWAY: &str = "00:00:5e:00:53:01";
    /// The core switch `sw-core.example.test` (16 ports).
    pub const CORE: &str = "00:00:5e:00:53:10";
    /// The access switch `sw-access.example.test` (8 ports).
    pub const ACCESS: &str = "00:00:5e:00:53:11";
    /// The access point `ap-hall.example.test` (wired).
    pub const HALL: &str = "00:00:5e:00:53:20";
    /// The mesh access point `ap-garden.example.test`.
    pub const GARDEN: &str = "00:00:5e:00:53:21";
    /// The device that is not adopted.
    pub const PENDING: &str = "00:00:5e:00:53:2f";

    /// The wired printer on sw-access port 5 (`IoT`).
    pub const PRINTER: &str = "00:00:5e:00:53:40";
    /// The wired host on sw-core port 7 (192.0.2.10).
    pub const HOST: &str = "00:00:5e:00:53:41";
    /// The wireless phone on ap-hall (`home.example`, override to `IoT` in its record).
    pub const PHONE: &str = "00:00:5e:00:53:42";
    /// The wireless sensor on ap-garden (`iot.example`).
    pub const SENSOR: &str = "00:00:5e:00:53:43";
    /// The guest laptop on ap-hall (`guest.example`).
    pub const LAPTOP: &str = "00:00:5e:00:53:44";
    /// The wired client without an address on sw-access port 6.
    pub const IDLE: &str = "00:00:5e:00:53:45";
    /// A known client that is offline (a record in `user.json`, not in `sta.json`).
    pub const TABLET: &str = "00:00:5e:00:53:46";
    /// The wired NAS on sw-core port 12 (the non-UniFi LLDP neighbour).
    pub const NAS: &str = "00:00:5e:00:53:80";
}

/// The deployment the fake imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// A self-hosted Network Application: no path prefix, login at `/api/login`.
    SelfHosted,
    /// A UniFi OS console: the Network application behind `/proxy/network`, login at
    /// `/api/auth/login`.
    UnifiOs,
}

impl Flavor {
    /// The prefix of the Network application (`P` in the paths below).
    pub fn network(self) -> &'static str {
        match self {
            Flavor::SelfHosted => "",
            Flavor::UnifiOs => "/proxy/network",
        }
    }

    /// The login path.
    pub fn login(self) -> &'static str {
        match self {
            Flavor::SelfHosted => "/api/login",
            Flavor::UnifiOs => "/api/auth/login",
        }
    }

    /// The logout path.
    pub fn logout(self) -> &'static str {
        match self {
            Flavor::SelfHosted => "/api/logout",
            Flavor::UnifiOs => "/api/auth/logout",
        }
    }

    /// The prefix of the Integration API.
    pub fn integration(self) -> &'static str {
        match self {
            Flavor::SelfHosted => "/integration/v1",
            Flavor::UnifiOs => "/proxy/network/integration/v1",
        }
    }
}

/// One write the plugin sent to the classic site API.
#[derive(Debug, Clone, PartialEq)]
pub struct Write {
    /// The HTTP method (`POST`, `PUT` or `DELETE`).
    pub method: String,
    /// The request path as received, with the deployment's prefix
    /// (`/api/s/default/rest/networkconf/<id>` or `/proxy/network/api/s/default/...`).
    pub path: String,
    /// The JSON body, or `null` when there was none.
    pub body: Value,
}

impl Write {
    /// The part of the path after `/api/s/<site>/` (`rest/networkconf/<id>`).
    pub fn route(&self) -> &str {
        self.path
            .split_once("/api/s/")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map_or(self.path.as_str(), |(_, route)| route)
    }
}

/// The data the fake serves and the knobs of its behaviour. Change the arrays between
/// calls to change what the plugin reads; keep the guard out of `.await` points.
#[derive(Debug)]
pub struct State {
    /// `stat/device`: managed devices, including the one that is not adopted.
    pub devices: Vec<Value>,
    /// `stat/sta`: connected clients.
    pub clients: Vec<Value>,
    /// `rest/networkconf`.
    pub networks: Vec<Value>,
    /// `rest/wlanconf`.
    pub wlans: Vec<Value>,
    /// `rest/portconf`.
    pub profiles: Vec<Value>,
    /// Client records, read by `stat/user/<mac>` and written by `rest/user/<id>`.
    pub users: Vec<Value>,
    /// Whether the Integration API serves the networks, as Network 10 does (`true`, the
    /// default); `false` answers 404 like the 9.x releases.
    pub integration_networks: bool,
    /// Open sessions: cookie token to CSRF token.
    sessions: HashMap<String, String>,
    writes: Vec<Write>,
    logins: usize,
    login_attempts: usize,
    logouts: usize,
    log: Vec<String>,
    drift_after_write: bool,
    rate_limit: u32,
    counter: u64,
}

impl State {
    fn fixtures() -> Self {
        Self {
            devices: fixture(include_str!("../fixtures/classic/device.json")),
            clients: fixture(include_str!("../fixtures/classic/sta.json")),
            networks: fixture(include_str!("../fixtures/classic/networkconf.json")),
            wlans: fixture(include_str!("../fixtures/classic/wlanconf.json")),
            profiles: fixture(include_str!("../fixtures/classic/portconf.json")),
            users: fixture(include_str!("../fixtures/classic/user.json")),
            integration_networks: true,
            sessions: HashMap::new(),
            writes: Vec::new(),
            logins: 0,
            login_attempts: 0,
            logouts: 0,
            log: Vec::new(),
            drift_after_write: false,
            rate_limit: 0,
            counter: 0,
        }
    }

    /// The anonymised recordings of a real controller (`tests/fixtures/recorded`), in place
    /// of the documented fixtures.
    fn recorded() -> Self {
        Self {
            devices: fixture(include_str!("../fixtures/recorded/device.json")),
            clients: fixture(include_str!("../fixtures/recorded/sta.json")),
            networks: fixture(include_str!("../fixtures/recorded/networkconf.json")),
            wlans: fixture(include_str!("../fixtures/recorded/wlanconf.json")),
            profiles: fixture(include_str!("../fixtures/recorded/portconf.json")),
            users: fixture(include_str!("../fixtures/recorded/user.json")),
            ..Self::fixtures()
        }
    }

    /// The number of open sessions (logged in and not logged out).
    pub fn open_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Random-looking hex text of 32 characters, unique within the process.
    fn token(&mut self) -> String {
        self.counter += 1;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let hasher = std::collections::hash_map::RandomState::new();
        format!(
            "{:016x}{:016x}",
            hasher.hash_one((self.counter, nanos, 1u8)),
            hasher.hash_one((self.counter, nanos, 2u8))
        )
    }

    /// A new record id: 24 lowercase hex characters, not used by any network.
    fn new_id(&mut self) -> String {
        loop {
            self.counter += 1;
            let id = format!("5f9{:021x}", self.counter);
            if !self.networks.iter().any(|n| n["_id"] == id.as_str()) {
                return id;
            }
        }
    }
}

/// The `data` array of a fixture file.
fn fixture(text: &str) -> Vec<Value> {
    let envelope: Value = serde_json::from_str(text).expect("a fixture is JSON");
    envelope["data"]
        .as_array()
        .expect("a fixture has a data array")
        .clone()
}

/// What the server tasks share.
struct Shared {
    flavor: Flavor,
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A fake UniFi Network application on a loopback port. The server stops when the value is
/// dropped.
pub struct FakeController {
    addr: SocketAddr,
    fingerprint: Option<String>,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl FakeController {
    /// Starts a controller that speaks plain HTTP on `127.0.0.1` and a free port, loaded
    /// with the fixtures.
    pub async fn start(flavor: Flavor) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local address");
        let (shared, app) = app(flavor);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            addr,
            fingerprint: None,
            shared,
            task,
        }
    }

    /// Starts a controller that speaks HTTPS with a fresh self-signed certificate for
    /// `unifi.example.test`.
    pub async fn start_tls(flavor: Flavor) -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = tcp.local_addr().expect("local address");
        let (listener, fingerprint) = tls::listener(tcp);
        let (shared, app) = app(flavor);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            addr,
            fingerprint: Some(fingerprint),
            shared,
            task,
        }
    }

    /// The deployment the controller imitates.
    pub fn flavor(&self) -> Flavor {
        self.shared.flavor
    }

    /// The base URL: `http://127.0.0.1:<port>`, or `https://...` for a TLS controller.
    pub fn url(&self) -> String {
        let scheme = if self.fingerprint.is_some() {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{}", self.addr)
    }

    /// The SHA-256 fingerprint of the certificate (colon-separated upper-case hex), for a
    /// TLS controller.
    pub fn fingerprint(&self) -> Option<String> {
        self.fingerprint.clone()
    }

    /// The settings of an instance that reaches this controller with the local account; a
    /// TLS controller is pinned by its fingerprint.
    pub fn settings(&self) -> Value {
        let mut settings = json!({
            "url": self.url(),
            "site": "default",
            "username": USERNAME,
        });
        if let Some(fingerprint) = &self.fingerprint {
            settings["tls"] = json!("fingerprint");
            settings["tls_fingerprint"] = json!(fingerprint);
        }
        settings
    }

    /// A call context with the settings and the secret `password`.
    pub fn context(&self) -> CallContext {
        Self::context_with(self.settings(), &[("password", PASSWORD)])
    }

    /// A call context for the Integration API: the settings without `username` and the
    /// secret `api_key`.
    pub fn key_context(&self) -> CallContext {
        let mut settings = self.settings();
        if let Value::Object(map) = &mut settings {
            map.remove("username");
        }
        Self::context_with(settings, &[("api_key", API_KEY)])
    }

    /// A call context with the given settings and secrets.
    pub fn context_with(settings: Value, secrets: &[(&str, &str)]) -> CallContext {
        let mut all = Secrets::new();
        for (purpose, value) in secrets {
            all.insert_bytes(*purpose, value.as_bytes().to_vec());
        }
        CallContext {
            settings,
            secrets: all,
            request_id: "fake-controller-test".to_owned(),
            ..CallContext::default()
        }
    }

    /// Every write to the classic site API so far (`POST`, `PUT` and `DELETE` under
    /// `/api/s/<site>/` that passed the session and CSRF checks, whether or not the site
    /// or the data was accepted), in order. Login and
    /// logout are not writes.
    pub fn writes(&self) -> Vec<Write> {
        self.shared.lock().writes.clone()
    }

    /// The number of accepted logins.
    pub fn logins(&self) -> usize {
        self.shared.lock().logins
    }

    /// The number of login requests, accepted or not.
    pub fn login_attempts(&self) -> usize {
        self.shared.lock().login_attempts
    }

    /// The number of logouts of a valid session.
    pub fn logouts(&self) -> usize {
        self.shared.lock().logouts
    }

    /// The number of requests the server has answered, rate-limited ones included.
    pub fn requests(&self) -> usize {
        self.shared.lock().log.len()
    }

    /// Every request so far as `METHOD path` (without the query), in order.
    pub fn request_log(&self) -> Vec<String> {
        self.shared.lock().log.clone()
    }

    /// Makes writes answer `ok` but store something else: the network keeps a name with
    /// `-drift` appended, the device keeps its port profiles, the client record stays as it
    /// was. The answer of such a write is the one a faithful write would give.
    pub fn set_drift_after_write(&self, on: bool) {
        self.shared.lock().drift_after_write = on;
    }

    /// Makes the next `n` requests (any path) answer `429` with `Retry-After: 0`.
    pub fn rate_limit_next(&self, n: u32) {
        self.shared.lock().rate_limit = n;
    }

    /// Replaces the documented fixtures with the anonymised recordings of a real controller
    /// (`tests/fixtures/recorded`); the sessions and counters stay.
    pub fn load_recorded(&self) {
        let recorded = State::recorded();
        let mut state = self.shared.lock();
        state.devices = recorded.devices;
        state.clients = recorded.clients;
        state.networks = recorded.networks;
        state.wlans = recorded.wlans;
        state.profiles = recorded.profiles;
        state.users = recorded.users;
    }

    /// Direct access to the data and the knobs. Do not hold the guard across an `.await`.
    pub fn state(&self) -> MutexGuard<'_, State> {
        self.shared.lock()
    }
}

impl Drop for FakeController {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl std::fmt::Debug for FakeController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeController")
            .field("url", &self.url())
            .field("flavor", &self.shared.flavor)
            .finish_non_exhaustive()
    }
}

fn app(flavor: Flavor) -> (Arc<Shared>, Router) {
    let shared = Arc::new(Shared {
        flavor,
        state: Mutex::new(State::fixtures()),
    });
    let app = Router::new()
        .fallback(dispatch)
        .with_state(Arc::clone(&shared));
    (shared, app)
}

/// A request as the handlers see it.
struct Req {
    method: Method,
    path: String,
    query: HashMap<String, String>,
    headers: HeaderMap,
    body: Value,
}

impl Req {
    fn is_get(&self) -> bool {
        self.method == Method::GET
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

async fn dispatch(AxumState(shared): AxumState<Arc<Shared>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 16 << 20)
        .await
        .unwrap_or_default();
    let query = parts
        .uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    let req = Req {
        method: parts.method,
        path: parts.uri.path().to_owned(),
        query,
        headers: parts.headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    };
    route(&shared, &req)
}

fn route(shared: &Shared, req: &Req) -> Response {
    let mut state = shared.lock();
    state.log.push(format!("{} {}", req.method, req.path));
    if state.rate_limit > 0 {
        state.rate_limit -= 1;
        let mut response = text(StatusCode::TOO_MANY_REQUESTS, "slow down");
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("0"));
        return response;
    }
    let flavor = shared.flavor;
    let path = req.path.as_str();
    if req.is_get() {
        match (flavor, path) {
            (Flavor::SelfHosted, "/") => {
                let mut response = text(StatusCode::FOUND, "");
                response
                    .headers_mut()
                    .insert(header::LOCATION, HeaderValue::from_static("/manage"));
                return response;
            }
            (Flavor::UnifiOs, "/") => {
                return html(StatusCode::OK, "<html><body>UniFi OS</body></html>");
            }
            (Flavor::SelfHosted, "/status") | (Flavor::UnifiOs, "/proxy/network/status") => {
                return reply(
                    StatusCode::OK,
                    &json!({
                        "meta": {
                            "rc": "ok",
                            "up": true,
                            "server_version": VERSION,
                            "uuid": "00000000-0000-0000-0000-000000000000",
                        },
                        "data": [],
                    }),
                );
            }
            _ => {}
        }
    }
    if req.method == Method::POST && path == flavor.login() {
        return login(&mut state, flavor, req);
    }
    if req.method == Method::POST && path == flavor.logout() {
        return logout(&mut state, req);
    }
    if let Some(rest) = path
        .strip_prefix(flavor.network())
        .and_then(|rest| rest.strip_prefix("/api/"))
    {
        return classic::handle(&mut state, req, rest);
    }
    if let Some(rest) = path.strip_prefix(flavor.integration()) {
        return integration::handle(&state, req, rest);
    }
    html(StatusCode::NOT_FOUND, "<html><body>Not found</body></html>")
}

fn login(state: &mut State, flavor: Flavor, req: &Req) -> Response {
    state.login_attempts += 1;
    let given = |member: &str| req.body.get(member).and_then(Value::as_str);
    if given("username") != Some(USERNAME) || given("password") != Some(PASSWORD) {
        return error(StatusCode::BAD_REQUEST, "api.err.Invalid");
    }
    let (token, csrf) = (state.token(), state.token());
    state.sessions.insert(token.clone(), csrf.clone());
    state.logins += 1;
    let mut response = ok(Vec::new());
    let headers = response.headers_mut();
    let mut cookie = |text: String| {
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_str(&text).expect("a cookie is a header value"),
        );
    };
    match flavor {
        Flavor::SelfHosted => {
            cookie(format!("unifises={token}; Path=/; HttpOnly"));
            cookie(format!("csrf_token={csrf}; Path=/"));
        }
        Flavor::UnifiOs => {
            cookie(format!("TOKEN={token}; Path=/; HttpOnly"));
            headers.insert(
                "X-CSRF-Token",
                HeaderValue::from_str(&csrf).expect("a token is a header value"),
            );
        }
    }
    response
}

fn logout(state: &mut State, req: &Req) -> Response {
    let Some(token) = session_token(state, req) else {
        return error(StatusCode::UNAUTHORIZED, "api.err.LoginRequired");
    };
    state.sessions.remove(&token);
    state.logouts += 1;
    ok(Vec::new())
}

/// The cookie token of the request's session, when the session is open.
fn session_token(state: &State, req: &Req) -> Option<String> {
    req.headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|text| text.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| matches!(*name, "unifises" | "TOKEN"))
        .map(|(_, value)| value)
        .find(|value| state.sessions.contains_key(*value))
        .map(str::to_owned)
}

/// A JSON answer.
fn reply(status: StatusCode, body: &Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("a response")
}

/// A text answer.
fn text(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(body.to_owned()))
        .expect("a response")
}

/// An HTML answer.
fn html(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html")
        .body(Body::from(body.to_owned()))
        .expect("a response")
}

/// A classic answer with `data`.
fn ok(data: Vec<Value>) -> Response {
    reply(
        StatusCode::OK,
        &json!({ "meta": { "rc": "ok" }, "data": Value::Array(data) }),
    )
}

/// A classic error answer.
fn error(status: StatusCode, msg: &str) -> Response {
    reply(
        status,
        &json!({ "meta": { "rc": "error", "msg": msg }, "data": [] }),
    )
}
