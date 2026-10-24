//! The HTTP server: listener, TLS modes, its own runtime, the full application router and
//! graceful shutdown.
//!
//! [`serve`] is the entry point of the server binary (WP1.8):
//!
//! ```ignore
//! let tls = TlsService::new(mode, policy)?;          // WP1.3, material installed by the CA
//! let mut config = ServerConfig::new(vec!["[::]:8443".parse()?], tls, policy);
//! config.workers = 2;
//! let mut state = AppState::new(store);
//! state.auth = Some(auth);
//! state.authorizer = Some(authorizer);
//! tenko_api::serve(config, state, tenko_api::shutdown_signal()).await?;
//! ```
//!
//! The server runs on a runtime of its own (2 to 4 workers, ADR 0008), on a dedicated
//! thread, so that the API never competes with the data plane for worker threads. The
//! returned future only waits for it. [`start`] is the same without the signal, for tests
//! and embedding: it returns a [`RunningServer`] with the bound addresses.
//!
//! Shutdown: the event hub sends `shutdown` to every SSE stream and ends it, the accept
//! loops stop, open connections finish their requests (HTTP/2 gets `GOAWAY`), and after
//! [`ServerConfig::shutdown_grace`] whatever is left is dropped.

pub(crate) mod forwarded;
mod listener;
pub mod proxy_protocol;

use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::Request,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
};
use socket2::{Domain, Protocol, Socket, Type};
use tenko_cluster::ca::{TlsMode, TlsPolicy, TlsService};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, oneshot, watch},
};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use crate::{
    dto::system::{self, CertificateStatus, StatusWarning, UiStatus},
    middleware::{self, HttpConfig, Layers, idempotency},
    problem::{ApiError, codes},
    state::AppState,
    ui::{self, UiError, UiSource},
};

/// Settings of the HTTP server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Addresses to listen on.
    pub listen: Vec<SocketAddr>,
    /// Worker threads of the API runtime: 2 to 4 (ADR 0008), at most 16.
    pub workers: usize,
    /// The TLS mode and certificate (WP1.3). Mode and certificate changes apply to new
    /// connections without a restart.
    pub tls: TlsService,
    /// The policy `tls` was built with, for `/system/status` (TLS 1.3 only in Hardened).
    pub tls_policy: TlsPolicy,
    /// TGL-08 Lab profile only: in mode c, serve plain HTTP to any source instead of
    /// refusing sources that are not trusted proxies. Forwarded headers are still taken
    /// from trusted proxies only.
    pub lab_plain_http: bool,
    /// Middleware settings: CSRF origins, rate limits, idempotency, HSTS.
    pub http: HttpConfig,
    /// Where the web UI comes from; a directory only in debug builds (ADR 0008).
    pub ui: UiSource,
    /// How long open connections may finish after shutdown starts.
    pub shutdown_grace: Duration,
    /// Limit for the TLS handshake and the PROXY protocol header.
    pub handshake_timeout: Duration,
    /// Limit for reading the request head of HTTP/1.1 (slow clients).
    pub header_read_timeout: Duration,
    /// Most open connections; more are closed at once.
    pub max_connections: usize,
    /// Request extensions added to every request before routing: the domain services of
    /// the server binary (`Arc<tenko_auth::AuthService>`, `Arc<tenko_ipam::IpamService>`,
    /// `tenko_jobs::JobEngine`). Area handlers read them with `Extension<T>`.
    pub extensions: axum::http::Extensions,
    /// The key of the idempotency fingerprints, derived from the installation's cluster
    /// key so every controller computes the same fingerprints; `None` draws a random key
    /// for this process.
    pub fingerprint_key: Option<idempotency::FingerprintKey>,
}

impl ServerConfig {
    /// A configuration with defaults: 2 workers, HSTS on, the embedded UI.
    pub fn new(listen: Vec<SocketAddr>, tls: TlsService, tls_policy: TlsPolicy) -> Self {
        Self {
            listen,
            workers: 2,
            tls,
            tls_policy,
            lab_plain_http: false,
            http: HttpConfig::default(),
            ui: UiSource::Embedded,
            shutdown_grace: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(30),
            max_connections: 20_000,
            extensions: axum::http::Extensions::new(),
            fingerprint_key: None,
        }
    }

    /// Checks the settings.
    ///
    /// # Errors
    ///
    /// [`ServeError::Config`] naming the first problem.
    pub fn validate(&self) -> Result<(), ServeError> {
        let invalid = |reason: &str| Err(ServeError::Config(reason.to_owned()));
        if self.listen.is_empty() {
            return invalid("no listen address");
        }
        if !(1..=16).contains(&self.workers) {
            return invalid("workers must be between 1 and 16 (2 to 4 recommended)");
        }
        if self.max_connections == 0 {
            return invalid("max_connections must be at least 1");
        }
        if cfg!(not(debug_assertions)) && matches!(self.ui, UiSource::Dir(_)) {
            return invalid(
                "serving the UI from a directory is a development feature of debug builds",
            );
        }
        self.http
            .rate_limit
            .validate()
            .map_err(ServeError::Config)?;
        Ok(())
    }
}

/// Why the server could not start or stopped with an error.
#[derive(Debug)]
pub enum ServeError {
    /// An invalid setting.
    Config(String),
    /// The UI directory is unusable.
    Ui(UiError),
    /// A listen address could not be bound.
    Bind {
        /// The address.
        addr: SocketAddr,
        /// The operating system's error.
        source: io::Error,
    },
    /// The runtime could not be built or its thread died.
    Runtime(String),
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::Config(reason) => write!(f, "invalid server configuration: {reason}"),
            ServeError::Ui(error) => write!(f, "{error}"),
            ServeError::Bind { addr, source } => write!(f, "cannot listen on {addr}: {source}"),
            ServeError::Runtime(reason) => write!(f, "API runtime failed: {reason}"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServeError::Ui(error) => Some(error),
            ServeError::Bind { source, .. } => Some(source),
            ServeError::Config(_) | ServeError::Runtime(_) => None,
        }
    }
}

/// What `/system/status` reports about the listener.
#[derive(Debug, Clone)]
pub(crate) struct ListenerInfo {
    pub(crate) tls: TlsService,
    pub(crate) policy: TlsPolicy,
    pub(crate) lab_plain_http: bool,
    pub(crate) hsts: bool,
    pub(crate) ui_from_directory: bool,
}

impl ListenerInfo {
    /// The mode as the API names it: mode c without a trusted-proxy rule is plain HTTP.
    pub(crate) fn mode_of(&self, mode: &TlsMode) -> system::TlsMode {
        match mode {
            TlsMode::InternalCa => system::TlsMode::InternalCa,
            TlsMode::Imported { .. } => system::TlsMode::Imported,
            TlsMode::ReverseProxy { .. } if self.lab_plain_http => system::TlsMode::Plain,
            TlsMode::ReverseProxy { .. } => system::TlsMode::ReverseProxy,
        }
    }

    /// The TLS status and the warnings it implies.
    pub(crate) fn status(
        &self,
        now: tenko_core::Timestamp,
    ) -> (system::TlsStatus, Vec<StatusWarning>) {
        let status = self.tls.status();
        let mut warnings = Vec::new();
        let mode = self.mode_of(&status.mode);
        if mode == system::TlsMode::Plain {
            warnings.push(warning(
                "sys.tls.plain_http",
                "plain HTTP is accepted from every source (Lab profile)",
                &[],
            ));
        }
        let certificate = status.certificate.as_ref().map(|info| {
            let expiry = info.expiry(now);
            let state = format!("{:?}", expiry.state).to_ascii_lowercase();
            if state != "valid" {
                warnings.push(warning(
                    "sys.tls.certificate_expiry",
                    &format!(
                        "the server certificate is {state}: {} days left",
                        expiry.days_left
                    ),
                    &[
                        ("state", state.clone()),
                        ("days_left", expiry.days_left.to_string()),
                    ],
                ));
            }
            let mut names = info.dns_names.clone();
            names.extend(info.ip_addresses.iter().map(ToString::to_string));
            CertificateStatus {
                names,
                not_after: Some(expiry.not_after),
                days_remaining: Some(expiry.days_left),
                loaded_at: status.loaded_at.unwrap_or(now),
            }
        });
        if mode.terminates_tls() && certificate.is_none() {
            warnings.push(warning(
                "sys.tls.no_certificate",
                "TLS is on but no certificate is installed; handshakes fail",
                &[],
            ));
        }
        if let Some(pending) = &status.pending {
            warnings.push(warning(
                "sys.tls.certificate_pending",
                &format!(
                    "a newer certificate (valid until {}) is on disk and is not served: this                      security profile does not accept a replaced certificate while the                      listener runs; restart to apply it",
                    pending.certificate.not_after
                ),
                &[
                    ("not_after", pending.certificate.not_after.to_string()),
                    ("sha256", pending.certificate.sha256.clone()),
                ],
            ));
        }
        if let Some(error) = &status.last_error {
            warnings.push(warning(
                "sys.tls.reload_failed",
                &format!("the last certificate reload failed: {error}"),
                &[],
            ));
        }
        let (trusted_proxies, proxy_protocol) = match &status.mode {
            TlsMode::ReverseProxy {
                trusted_proxies,
                proxy_protocol,
                ..
            } => (
                trusted_proxies
                    .networks()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                *proxy_protocol,
            ),
            _ => (Vec::new(), false),
        };
        let tls = system::TlsStatus {
            mode,
            certificate,
            min_version: mode
                .terminates_tls()
                .then(|| if self.policy.tls13_only { "1.3" } else { "1.2" }.to_owned()),
            hsts: self.hsts && mode != system::TlsMode::Plain,
            trusted_proxies,
            proxy_protocol,
        };
        (tls, warnings)
    }

    pub(crate) fn ui(&self) -> UiStatus {
        UiStatus {
            stub: ui::UI_STUB,
            from_directory: self.ui_from_directory,
        }
    }
}

fn warning(code: &str, detail: &str, params: &[(&str, String)]) -> StatusWarning {
    StatusWarning {
        code: code.to_owned(),
        detail: detail.to_owned(),
        params: params
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect(),
    }
}

/// The complete application: the API under `/api/v1` with its middleware, problem details
/// for unknown API paths, and the web UI for everything else.
///
/// # Errors
///
/// [`UiError`] when the UI directory has no `index.html`.
pub fn app(state: AppState, http: &HttpConfig, ui_source: &UiSource) -> Result<Router, UiError> {
    build_app(state, http, ui_source, axum::http::Extensions::new()).map(|(router, _)| router)
}

fn build_app(
    state: AppState,
    http: &HttpConfig,
    ui_source: &UiSource,
    extensions: axum::http::Extensions,
) -> Result<(Router, Arc<Layers>), UiError> {
    let (api, document) = crate::api(state.clone());
    // The request metrics are sealed from the document of this router, which is dropped.
    let route_table = middleware::RouteTable::get_or_seal(&document);
    drop(document);
    let layers = Arc::new(Layers::new(state, http, route_table));
    let ui = ui::router(ui_source)?;
    let api = api
        .method_not_allowed_fallback(method_not_allowed)
        .route_layer(from_fn_with_state(Arc::clone(&layers), middleware::api));
    let router = api
        .fallback(move |request: Request| fallback(ui.clone(), request))
        .layer(from_fn_with_state(Arc::clone(&layers), middleware::outer))
        .layer(axum::middleware::from_fn(
            move |mut request: Request, next: axum::middleware::Next| {
                let extensions = extensions.clone();
                async move {
                    request.extensions_mut().extend(extensions);
                    next.run(request).await
                }
            },
        ))
        // The request span covers everything above (OPS-05, `middleware::trace`).
        .layer(from_fn_with_state(
            Arc::clone(&layers),
            middleware::trace::request,
        ));
    Ok((router, layers))
}

/// Unknown API paths get problem details; everything else goes to the UI.
async fn fallback(ui: Router, request: Request) -> Response {
    if middleware::is_api_path(request.uri().path()) {
        let detail = format!(
            "no API route matches {} {}",
            request.method(),
            request.uri().path()
        );
        return ApiError::new(codes::ROUTE_NOT_FOUND, 404, detail).into_response();
    }
    match ui.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

async fn method_not_allowed(request: Request) -> Response {
    ApiError::new(
        codes::METHOD_NOT_ALLOWED,
        405,
        format!(
            "{} is not allowed on {}",
            request.method(),
            request.uri().path()
        ),
    )
    .into_response()
}

/// A server started by [`start`].
#[derive(Debug)]
pub struct RunningServer {
    addrs: Vec<SocketAddr>,
    stop: watch::Sender<bool>,
    done: oneshot::Receiver<Result<(), ServeError>>,
}

impl RunningServer {
    /// The bound addresses (useful with port 0).
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Starts the graceful shutdown; [`RunningServer::wait`] returns when it is done.
    /// Dropping the handle has the same effect.
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }

    /// Runs until the server stops on its own or `shutdown` resolves, then shuts it down
    /// gracefully and waits for it.
    ///
    /// # Errors
    ///
    /// [`ServeError::Runtime`] when the server thread died, or the error the server
    /// stopped with.
    pub async fn run_until(
        self,
        shutdown: impl Future<Output = ()> + Send,
    ) -> Result<(), ServeError> {
        let Self {
            addrs: _,
            stop,
            done,
        } = self;
        let mut done = done;
        tokio::select! {
            result = &mut done => {
                return result.unwrap_or_else(|_| Err(ServeError::Runtime("the server thread ended".to_owned())));
            }
            () = shutdown => {}
        }
        tracing::info!("API shutting down");
        let _ = stop.send(true);
        done.await
            .unwrap_or_else(|_| Err(ServeError::Runtime("the server thread ended".to_owned())))
    }

    /// Waits until the server has stopped.
    ///
    /// # Errors
    ///
    /// [`ServeError::Runtime`] when the server thread died.
    pub async fn wait(self) -> Result<(), ServeError> {
        let Self { stop, done, .. } = self;
        let result = done
            .await
            .unwrap_or_else(|_| Err(ServeError::Runtime("the server thread ended".to_owned())));
        drop(stop);
        result
    }
}

/// Starts the server on its own runtime and returns once every address is bound.
///
/// # Errors
///
/// [`ServeError`] for an invalid configuration, an unusable UI directory, an address that
/// cannot be bound, or a runtime that cannot be built.
pub async fn start(config: ServerConfig, state: AppState) -> Result<RunningServer, ServeError> {
    config.validate()?;
    if let Some(key) = &config.fingerprint_key {
        state.platform.in_flight.set_key(key.clone());
    }
    let (router, layers) = build_app(
        state.clone(),
        &config.http,
        &config.ui,
        config.extensions.clone(),
    )
    .map_err(ServeError::Ui)?;
    let (ready_tx, ready_rx) = oneshot::channel::<Result<Vec<SocketAddr>, ServeError>>();
    let (done_tx, done_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = watch::channel(false);
    let workers = config.workers;
    std::thread::Builder::new()
        .name("tenko-api".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .thread_name("tenko-api-worker")
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(ServeError::Runtime(error.to_string())));
                    return;
                }
            };
            let result = runtime.block_on(async move {
                let listeners = match bind_all(&config.listen) {
                    Ok(listeners) => listeners,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return Ok(());
                    }
                };
                let addrs = listeners
                    .iter()
                    .filter_map(|listener| listener.local_addr().ok())
                    .collect();
                let _ = ready_tx.send(Ok(addrs));
                run(listeners, config, state, (router, layers), stop_rx).await
            });
            runtime.shutdown_timeout(Duration::from_secs(1));
            let _ = done_tx.send(result);
        })
        .map_err(|error| ServeError::Runtime(error.to_string()))?;
    let addrs = ready_rx
        .await
        .map_err(|_| ServeError::Runtime("the server thread ended during start".to_owned()))??;
    Ok(RunningServer {
        addrs,
        stop: stop_tx,
        done: done_rx,
    })
}

/// Runs the server until `shutdown` resolves, then shuts it down gracefully.
///
/// This is the entry point of `tenko serve`; pass [`shutdown_signal`] or a future of the
/// service manager.
///
/// # Errors
///
/// See [`start`]; also [`ServeError::Runtime`] when the server thread dies.
pub async fn serve(
    config: ServerConfig,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServeError> {
    let server = start(config, state).await?;
    tracing::info!(addrs = ?server.local_addrs(), "API listening");
    server.run_until(shutdown).await
}

/// Resolves on Ctrl-C, and on Unix also on `SIGTERM`.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

fn bind_all(addrs: &[SocketAddr]) -> Result<Vec<TcpListener>, ServeError> {
    addrs
        .iter()
        .map(|addr| {
            bind(*addr).map_err(|source| ServeError::Bind {
                addr: *addr,
                source,
            })
        })
        .collect()
}

fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // An IPv6 address serves IPv6 only, so that `listen = ["0.0.0.0:8443", "[::]:8443"]`
    // (the same for both families) binds on Linux, where a plain `[::]` socket would
    // also take the IPv4 port.
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // SO_REUSEADDR has port-stealing semantics on Windows; only set it elsewhere.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    // A deep backlog absorbs reconnect storms (every SSE client reconnecting at once).
    socket.listen(4096)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// The server proper, on the API runtime.
async fn run(
    listeners: Vec<TcpListener>,
    config: ServerConfig,
    state: AppState,
    (router, layers): (Router, Arc<Layers>),
    mut stop: watch::Receiver<bool>,
) -> Result<(), ServeError> {
    state.platform.listener.store(Some(Arc::new(ListenerInfo {
        tls: config.tls.clone(),
        policy: config.tls_policy,
        lab_plain_http: config.lab_plain_http,
        hsts: config.http.hsts,
        ui_from_directory: matches!(config.ui, UiSource::Dir(_)),
    })));
    if let TlsMode::ReverseProxy {
        trusted_proxies, ..
    } = &config.tls.status().mode
        && trusted_proxies.is_empty()
        && !config.lab_plain_http
    {
        tracing::warn!("reverse proxy mode without trusted proxies: every connection is refused");
    }

    let (tasks_tx, tasks_rx) = watch::channel(false);
    state
        .events()
        .spawn_tasks(Arc::clone(&state.store), tasks_rx.clone());
    spawn_housekeeping(layers, tasks_rx);

    let shared = Arc::new(listener::Shared {
        router,
        acceptor: TlsAcceptor::from(config.tls.server_config()),
        tls: config.tls.clone(),
        lab_plain_http: config.lab_plain_http,
        handshake_timeout: config.handshake_timeout,
        header_read_timeout: config.header_read_timeout,
        connections: Arc::new(Semaphore::new(config.max_connections)),
        state: state.clone(),
    });
    let graceful = Arc::new(hyper_util::server::graceful::GracefulShutdown::new());
    let accept_loops: Vec<_> = listeners
        .into_iter()
        .map(|listener| {
            tokio::spawn(listener::accept_loop(
                listener,
                Arc::clone(&shared),
                Arc::clone(&graceful),
                stop.clone(),
            ))
        })
        .collect();

    // A dropped sender also means stop.
    while !*stop.borrow() {
        if stop.changed().await.is_err() {
            break;
        }
    }

    state.events().shutdown();
    let _ = tasks_tx.send(true);
    for accept_loop in accept_loops {
        let _ = accept_loop.await;
    }
    drop(shared);
    if let Ok(graceful) = Arc::try_unwrap(graceful) {
        if tokio::time::timeout(config.shutdown_grace, graceful.shutdown())
            .await
            .is_err()
        {
            tracing::warn!(
                grace = ?config.shutdown_grace,
                "connections still open after the shutdown grace period; closing them"
            );
        }
    } else {
        tracing::warn!("graceful shutdown handle still shared; closing connections");
    }
    state.platform.listener.store(None);
    Ok(())
}

/// Periodic work of this controller: idle rate-limit buckets every minute. The limiter is
/// per controller; the expired idempotency records in the store are purged by the leader
/// ([`idempotency::purge_expired`], a leader-only service of the server binary).
fn spawn_housekeeping(layers: Arc<Layers>, mut stop: watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = stop.changed() => return,
            }
            layers.limiter.purge_idle(std::time::Instant::now());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_ipv4_and_an_ipv6_wildcard_bind_the_same_port() {
        // A host without IPv6 has nothing to check.
        let Ok(probe) = bind("[::1]:0".parse().expect("address")) else {
            return;
        };
        drop(probe);
        let v4 = bind("0.0.0.0:0".parse().expect("address")).expect("the IPv4 wildcard binds");
        let port = v4.local_addr().expect("local address").port();
        let v6 = bind(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)))
            .expect("the IPv6 wildcard binds next to the IPv4 one");
        assert_eq!(v6.local_addr().expect("local address").port(), port);
    }
}
