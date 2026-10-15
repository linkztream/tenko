//! `tenko serve`: runs the roles of this node.
//!
//! Phase 1 implements the `controller` role. It starts in this order, each step logged with
//! its duration, and refuses to start with a coded error when a step fails:
//!
//! | # | Step | What comes up |
//! |---|---|---|
//! | 1 | `kek` | the key-encryption keys (created on the first start, required afterwards) |
//! | 2 | `store` | the replicated store: openraft over redb, with the fsync probe (OPS-19) |
//! | 3 | `cluster` | the controller cluster (WP3.1a): peer transport and Raft service, join or rejoin, missing key generations, the catch-up gate; nothing to do on a single controller |
//! | 4 | `vault` | the vault; it refuses to open when the store holds secrets no loaded KEK opens |
//! | 5 | `tls` | the TLS mode (OPS-22): the internal CA's certificate, imported files or the reverse proxy |
//! | 6 | `auth` | users, sessions, passkeys, TOTP, settings; the setup token while setup is open |
//! | 7 | `languages` | language packs: the files in `<data_dir>/i18n/` imported as uploads by the system (S3-Q8); a file the validation refuses is logged and audited, an oversized or unreadable one logged; never a start error |
//! | 8 | `ipam` | the IPAM domain over the job engine, its prefix tree and alarms |
//! | 9 | `jobs` | the job engine; the runner of the jobs pinned to this controller (the job runner of the installation is a leader service) |
//! | 10 | `connectors` | connector plugins and their supervisor (ADR 0012) |
//! | 11 | `nodes` | the node transport: internal CA node certificate, node registry, the mutual TLS listener for enrolled nodes (OPS-04), configuration sync and commands to nodes |
//! | 12 | `scans` | the scan control (probe configuration, scans on demand, the kill switch) and the probe role in process |
//! | 13 | `api` | the HTTP API, the web UI and server-sent events; the metrics timer and the optional loopback metrics listener (`[metrics]`, [`metrics`]) |
//!
//! After the last step the leader supervisor ([`leader`]) starts the leader-only services
//! (`tenko_core::cluster::LeaderService`) once this controller has taken office; on a single
//! controller that is at once. The steps register their services in the
//! [`leader::LeaderRegistry`] that the start sequence hands around: the online KEK rotation
//! (`vault.kek_rotation`, step `vault`), the reconciler with its purge (`ipam.reconcile`,
//! step `ipam`, which also seeds its settings in the store), the job runner (`jobs.runner`,
//! step `jobs`), the poll schedule of the connectors (`connect.poll`, step `connectors`), the
//! prune of the node registry (`cluster.prune`, step `nodes`), the purge of expired
//! idempotency records (`api.idempotency_purge`, step `api`) and the scheduled backups
//! (`backup.schedule`, step `api`, which also records a restore at the first start after it).
//!
//! The cluster step comes before the vault because a controller that was offline during an
//! online KEK rotation fetches the new key generation from its peers before the vault opens
//! its envelopes. The vault needs the store to check its envelopes, so it opens right after
//! the store and the cluster.
//!
//! Shutdown (Ctrl-C, `SIGTERM`, the service manager, or the end of standard input with
//! `--stop-on-eof`) runs in reverse: the API ends its event streams and lets open requests
//! finish, the leader services and the job runners stop, the background tasks end, and the
//! store makes its state durable and closes its files.
//!
//! The data directory holds `kek/` (key generations), `store/` (`log.redb`, `sm.redb`,
//! `snapshots/`), `tls/ca-root.pem` (the public root of the internal CA) and `logs/`
//! (the service log). While first-run setup is open it also holds `setup-token`, the
//! one-time setup token that `tenko setup token` prints (see [`setup_token`]).

pub mod cluster_key;
mod imports;
pub(crate) mod leader;
mod maintenance;
mod metrics;
pub mod queue;
pub mod setup_token;
mod tls;

use std::{
    fmt,
    future::Future,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Args;
use tenko_api::{
    ServerConfig,
    dto::system::NodeStatus,
    middleware::HttpConfig,
    routes::system::CaRootSource,
    sse::EventRoutes,
    state::{AppState, StateOptions},
    ui::UiSource,
};
use tenko_auth::{AuthConfig, AuthService, hibp::HibpFilter};
use tenko_cluster::kek::PeerKekFetch;
use tenko_core::{Coded, Role, RoleSet};
use tenko_ipam::{IpamConfig, IpamService};
use tenko_jobs::{EngineConfig, JobEngine, RunnerHandle};
use tenko_store::{
    Store,
    raft::{RaftStore, RaftStoreConfig, SmDurability, SnapshotPolicy},
};
use tenko_vault::{
    KekInit, KekRing, StoreVault, VaultStart,
    distribution::{KekAdmin, KekPeers, NoPeers},
};
use tokio::{sync::watch, task::JoinHandle};

use self::imports::Imports;
use crate::{
    config::{self, ConfigError, DurabilityName, Resolved, TlsSpec},
    exit, logging, version,
};

/// fsync p50 above which the store's disk is too slow (OPS-19), in microseconds.
pub const FSYNC_WARN_MICROS: u64 = 10_000;

/// How long the job runner may take to stop.
const RUNNER_STOP_TIMEOUT: Duration = Duration::from_secs(15);

/// The start steps of the controller role, in order.
pub const START_ORDER: [(&str, &str); 13] = [
    ("kek", "key-encryption keys"),
    ("store", "replicated store (openraft over redb)"),
    (
        "cluster",
        "controller cluster: peers, join, key generations, catch-up",
    ),
    ("vault", "envelope encryption of secrets"),
    ("tls", "TLS mode and certificate"),
    ("auth", "users, sessions, passkeys and TOTP"),
    ("languages", "language packs of the data directory"),
    ("ipam", "IPAM domain and job engine"),
    ("jobs", "job runner"),
    ("connectors", "connector plugins and their supervisor"),
    (
        "nodes",
        "node transport: enrolment, mutual TLS listener, node registry",
    ),
    (
        "scans",
        "scan control: probe configuration, scans on demand, probe role in process",
    ),
    ("api", "HTTP API, web UI and server-sent events"),
];

/// Arguments of `tenko serve`.
#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// The configuration file (`tenko.toml`). Without it, the defaults and the `TENKO_*`
    /// environment variables apply.
    #[arg(long, value_name = "FILE", env = "TENKO_CONFIG")]
    pub config: Option<PathBuf>,

    /// Directory that holds the state of this node; overrides `data_dir` of the file.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Roles to run: a comma-separated list of controller, dns, dhcp and probe, or `all`;
    /// overrides `roles` of the file. Phase 1 implements `controller`.
    #[arg(long, value_name = "ROLES")]
    pub roles: Option<String>,

    /// Stop gracefully when standard input reaches its end, for supervisors that cannot
    /// send signals.
    #[arg(long, hide = true)]
    pub stop_on_eof: bool,
}

impl ServeArgs {
    /// The configuration sources these flags name.
    pub fn sources(&self) -> config::Sources {
        config::Sources {
            file: self.config.clone(),
            data_dir: self.data_dir.clone(),
            roles: self.roles.clone(),
        }
    }
}

/// A start step that failed. The server does not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError {
    /// The step: `kek`, `store`, `vault`, `tls`, `auth`, `ipam`, `jobs`, `api`, or `data_dir`.
    pub step: &'static str,
    /// The stable code of the cause, for example `vault.kek_unavailable`.
    pub code: String,
    /// What went wrong, in English, without secrets.
    pub message: String,
}

impl StartError {
    /// An error with a code of this binary.
    pub fn new(step: &'static str, code: &str, message: impl Into<String>) -> Self {
        Self {
            step,
            code: code.to_owned(),
            message: message.into(),
        }
    }

    /// An error of a component, with the component's own code.
    pub fn coded(step: &'static str, error: &(impl Coded + ?Sized)) -> Self {
        Self {
            step,
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "start step `{}` failed [{}]: {}",
            self.step, self.code, self.message
        )
    }
}

impl std::error::Error for StartError {}

/// Why `tenko serve` ended with an error.
#[derive(Debug)]
pub enum ServeError {
    /// A start step failed; nothing is serving.
    Start(StartError),
    /// The server stopped with an error after it had started.
    Runtime(String),
    /// The server stopped so that its service manager starts it again (an installed
    /// update, a changed module set, a switch back to the previous version).
    Restart(String),
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => fmt::Display::fmt(error, f),
            Self::Runtime(reason) => write!(f, "the server stopped with an error: {reason}"),
            Self::Restart(reason) => write!(f, "the server stopped to restart: {reason}"),
        }
    }
}

impl std::error::Error for ServeError {}

impl ServeError {
    /// The exit status for this error: 3 for a data directory with a newer format than
    /// this binary (`upgrade.format_newer`, a deployment error), 4 for other failed steps.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Start(error) if error.code == "upgrade.format_newer" => exit::CONFIG,
            Self::Start(_) => exit::START,
            Self::Runtime(_) => exit::FAILURE,
            Self::Restart(_) => exit::RESTART,
        }
    }
}

/// A start error from the data-directory format check.
fn upgrade_error(step: &'static str, error: &crate::upgrade::datadir::UpgradeError) -> StartError {
    StartError::new(step, error.code(), error.to_string())
}

/// The server is up.
#[derive(Debug, Clone)]
pub struct Ready {
    /// The bound addresses.
    pub addrs: Vec<SocketAddr>,
    /// Time from the first step to readiness.
    pub elapsed: Duration,
}

/// Called once when the API listens.
pub type ReadyHook = Box<dyn FnOnce(&Ready) + Send>;

/// Called once when the shutdown begins.
pub type StoppingHook = Box<dyn FnOnce() + Send>;

/// Callbacks for the service manager (systemd, the Windows SCM).
#[derive(Default)]
pub struct Hooks {
    /// Called once when the API listens.
    pub ready: Option<ReadyHook>,
    /// Called once when the shutdown begins.
    pub stopping: Option<StoppingHook>,
}

impl fmt::Debug for Hooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hooks")
            .field("ready", &self.ready.is_some())
            .field("stopping", &self.stopping.is_some())
            .finish()
    }
}

/// A shutdown request, from any source.
pub type Shutdown = Pin<Box<dyn Future<Output = ()> + Send>>;

/// `tenko serve` from the command line: loads and checks the configuration, sets up
/// logging, runs the server in the foreground until a signal, and returns the exit status.
pub fn command(args: &ServeArgs, err: &mut impl Write) -> u8 {
    let resolved = match load(args) {
        Ok(resolved) => resolved,
        Err(error) => {
            let _ = writeln!(err, "tenko serve: {error}");
            return exit::CONFIG;
        }
    };
    if let Some(status) = check_roles(resolved.roles, err) {
        return status;
    }
    if !resolved.roles.contains(Role::Controller) {
        return crate::node::agent::command(resolved, args.stop_on_eof, err);
    }
    let runtime = match runtime(&resolved) {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "tenko serve: {error}");
            return exit::FAILURE;
        }
    };
    // The trace exporter's channel runs on the server's runtime: the layer is built and the
    // subscriber installed inside it.
    let telemetry = {
        let _guard = runtime.enter();
        let (extra, telemetry) = match crate::telemetry::layer(
            &resolved.config.telemetry,
            resolved.node_id,
            tenko_api::version(),
        ) {
            Ok(Some((layer, telemetry))) => (Some(layer), Some(telemetry)),
            Ok(None) => (None, None),
            Err(error) => {
                let _ = writeln!(err, "tenko serve: {error}");
                return exit::FAILURE;
            }
        };
        let layers = logging::Layers {
            event_log: None,
            extra,
        };
        if let Err(error) = logging::init_server_with(
            &resolved.config.log,
            resolved.config.log.file.as_deref(),
            logging::Sink::Console,
            layers,
        ) {
            let _ = writeln!(err, "tenko serve: {error}");
            return exit::FAILURE;
        }
        telemetry
    };
    crate::backup::service::remember_config_file(args.config.clone());
    let stop_on_eof = args.stop_on_eof;
    let shutdown = move || -> Shutdown {
        Box::pin(async move {
            if stop_on_eof {
                tokio::select! {
                    () = shutdown_signal() => {}
                    () = stdin_closed() => tracing::info!("standard input closed"),
                }
            } else {
                shutdown_signal().await;
            }
        })
    };
    match run_on(
        runtime,
        resolved,
        shutdown,
        crate::platform::notify_hooks(),
        telemetry,
    ) {
        Ok(()) => exit::OK,
        Err(ServeError::Restart(reason)) => {
            tracing::info!(%reason, "tenko serve stopped for a restart (exit status 12)");
            let _ = writeln!(
                err,
                "tenko serve: stopped for a restart ({reason}); exit status 12 asks the \
                 service manager to start it again"
            );
            exit::RESTART
        }
        Err(error) => {
            tracing::error!(%error, "tenko serve ended with an error");
            let _ = writeln!(err, "tenko serve: {error}");
            error.exit_code()
        }
    }
}

/// Loads and validates the configuration of `tenko serve`.
///
/// # Errors
///
/// The [`ConfigError`] of the first problem.
pub fn load(args: &ServeArgs) -> Result<Resolved, ConfigError> {
    config::load(&args.sources(), std::env::vars())?
        .config
        .resolve()
}

/// Reports roles this build does not run. Returns the exit status when the node has nothing
/// to run: a node without the controller runs the probe role through `crate::node::agent`;
/// a controller node runs the probe role in process when it is listed.
pub fn check_roles(roles: RoleSet, err: &mut impl Write) -> Option<u8> {
    let missing: Vec<&str> = roles
        .roles()
        .filter(|role| !matches!(role, Role::Controller | Role::Probe))
        .map(Role::as_str)
        .collect();
    if roles.contains(Role::Controller) {
        if !missing.is_empty() {
            let running = if roles.contains(Role::Probe) {
                "the controller and probe roles"
            } else {
                "the controller role only"
            };
            let _ = writeln!(
                err,
                "tenko serve: role(s) {}: not implemented on a controller node in Phase 1; \
                 this node runs {running}",
                missing.join(", ")
            );
        }
        return None;
    }
    if !missing.is_empty() {
        let _ = writeln!(
            err,
            "tenko serve: role(s) {}: not implemented in Phase 1",
            missing.join(", ")
        );
    }
    (!roles.contains(Role::Probe)).then_some(exit::USAGE)
}

/// The runtime the server runs on, with `[runtime] workers` worker threads.
///
/// # Errors
///
/// [`ServeError::Runtime`] when the runtime cannot be built.
pub fn runtime(resolved: &Resolved) -> Result<tokio::runtime::Runtime, ServeError> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(resolved.config.runtime.workers)
        .thread_name("tenko-core")
        .enable_all()
        .build()
        .map_err(|error| ServeError::Runtime(format!("core runtime: {error}")))
}

/// Runs the server on `runtime` (from [`runtime`]) until `shutdown` resolves, flushes the
/// traces of `telemetry` inside the runtime, and shuts the runtime down.
///
/// `shutdown` is called once, inside the runtime, to build the shutdown future (signals
/// need a runtime to register).
///
/// # Errors
///
/// [`ServeError::Start`] when a step fails, [`ServeError::Runtime`] when the API stops with
/// an error.
pub fn run_on(
    runtime: tokio::runtime::Runtime,
    resolved: Resolved,
    shutdown: impl FnOnce() -> Shutdown + Send + 'static,
    hooks: Hooks,
    telemetry: Option<crate::telemetry::Telemetry>,
) -> Result<(), ServeError> {
    if let Some(telemetry) = &telemetry {
        telemetry.log_start();
    }
    let result = runtime.block_on(async move {
        let result = serve(resolved, shutdown(), hooks).await;
        if let Some(telemetry) = telemetry {
            telemetry.shutdown().await;
        }
        result
    });
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

/// Resolves on Ctrl-C and `SIGTERM`, and on Windows also on Ctrl-Break and when the console
/// closes or the system shuts down.
pub async fn shutdown_signal() {
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let wait = |signal: std::io::Result<_>| async move {
            match signal {
                Ok(mut signal) => {
                    signal_recv(&mut signal).await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            () = tenko_api::shutdown_signal() => {}
            () = wait(windows::ctrl_break().map(WinSignal::Break)) => {}
            () = wait(windows::ctrl_close().map(WinSignal::Close)) => {}
            () = wait(windows::ctrl_shutdown().map(WinSignal::Shutdown)) => {}
        }
    }
    #[cfg(not(windows))]
    tenko_api::shutdown_signal().await;
}

/// The console events of Windows that end the server.
#[cfg(windows)]
enum WinSignal {
    Break(tokio::signal::windows::CtrlBreak),
    Close(tokio::signal::windows::CtrlClose),
    Shutdown(tokio::signal::windows::CtrlShutdown),
}

#[cfg(windows)]
async fn signal_recv(signal: &mut WinSignal) {
    match signal {
        WinSignal::Break(signal) => signal.recv().await,
        WinSignal::Close(signal) => signal.recv().await,
        WinSignal::Shutdown(signal) => signal.recv().await,
    };
}

/// Resolves when standard input reaches its end (`--stop-on-eof`).
async fn stdin_closed() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let spawned = std::thread::Builder::new()
        .name("tenko-stdin".to_owned())
        .spawn(move || {
            let mut sink = Vec::new();
            let mut stdin = std::io::stdin().lock();
            let mut buffer = [0u8; 256];
            loop {
                match std::io::Read::read(&mut stdin, &mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        sink.clear();
                        sink.extend_from_slice(&buffer[..read]);
                    }
                }
            }
            let _ = tx.send(());
        });
    if spawned.is_err() {
        std::future::pending::<()>().await;
    }
    let _ = rx.await;
}

/// Times one start step and logs its outcome.
struct Steps {
    started: Instant,
    timings: Vec<(&'static str, Duration)>,
}

impl Steps {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            timings: Vec::new(),
        }
    }

    async fn run<T>(
        &mut self,
        name: &'static str,
        step: impl Future<Output = Result<(T, String), StartError>>,
    ) -> Result<T, StartError> {
        let number = START_ORDER
            .iter()
            .position(|(step, _)| *step == name)
            .map_or(0, |index| index + 1);
        let total = START_ORDER.len();
        let began = Instant::now();
        match step.await {
            Ok((value, summary)) => {
                let elapsed = began.elapsed();
                self.timings.push((name, elapsed));
                tracing::info!(
                    step = name,
                    elapsed_ms = millis(elapsed),
                    "step {number}/{total} {name} ready in {} ms: {summary}",
                    millis(elapsed)
                );
                Ok(value)
            }
            Err(error) => {
                tracing::error!(
                    step = name,
                    code = %error.code,
                    "step {number}/{total} {name} failed: {}",
                    error.message
                );
                Err(error)
            }
        }
    }

    fn summary(&self) -> String {
        self.timings
            .iter()
            .map(|(name, elapsed)| format!("{name} {} ms", millis(*elapsed)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Everything that must be stopped, in reverse start order.
struct Running {
    store: Option<RaftStore>,
    /// The leader supervisor and its services, the leader's job runner among them.
    leader: Option<leader::SupervisorHandle>,
    /// The runner of the jobs pinned to this controller.
    runner: Option<RunnerHandle>,
    stop: watch::Sender<bool>,
    /// Tasks that end when `stop` is set.
    tasks: Vec<JoinHandle<()>>,
    /// Tasks that are aborted.
    watchers: Vec<JoinHandle<()>>,
}

/// How long a background task may take to end after the stop signal.
const TASK_STOP_TIMEOUT: Duration = Duration::from_secs(10);

impl Running {
    fn new() -> Self {
        let (stop, _) = watch::channel(false);
        Self {
            store: None,
            leader: None,
            runner: None,
            stop,
            tasks: Vec::new(),
            watchers: Vec::new(),
        }
    }

    /// Stops the leader services, the runner and the background tasks, then closes the
    /// store.
    async fn stop(mut self) {
        if let Some(leader) = self.leader.take() {
            let began = Instant::now();
            leader.stop(RUNNER_STOP_TIMEOUT).await;
            tracing::info!(
                elapsed_ms = millis(began.elapsed()),
                "leader services stopped"
            );
        }
        if let Some(runner) = self.runner.take() {
            let began = Instant::now();
            if tokio::time::timeout(RUNNER_STOP_TIMEOUT, runner.stop())
                .await
                .is_err()
            {
                tracing::warn!("the job runner did not stop in time");
            }
            tracing::info!(elapsed_ms = millis(began.elapsed()), "job runner stopped");
        }
        let _ = self.stop.send(true);
        for watcher in self.watchers.drain(..) {
            watcher.abort();
            let _ = watcher.await;
        }
        for mut task in self.tasks.drain(..) {
            if tokio::time::timeout(TASK_STOP_TIMEOUT, &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        if let Some(store) = self.store.take() {
            let began = Instant::now();
            match store.shutdown().await {
                Ok(()) => tracing::info!(
                    elapsed_ms = millis(began.elapsed()),
                    "store closed: state durable"
                ),
                Err(error) => tracing::error!(%error, "store shutdown failed"),
            }
        }
    }
}

/// The controller role: start, serve, stop.
async fn serve(resolved: Resolved, shutdown: Shutdown, hooks: Hooks) -> Result<(), ServeError> {
    let Hooks { ready, stopping } = hooks;
    tracing::info!(
        roles = %resolved.roles,
        data_dir = %resolved.data_dir.display(),
        "tenko {} starting",
        crate::upgrade::running_version()
    );
    let mut running = Running::new();
    let restart = crate::upgrade::restart::Restart::new();
    // A newly installed version is on probation (OPS-24): read before anything else, so a
    // switched-back previous version restores its store before the format check.
    let probation = probation_at_start(&resolved, &restart)?;
    let started = Box::pin(start(&resolved, &mut running, &restart, probation.as_ref())).await;
    let services = match started {
        Ok(services) => services,
        Err(error) => {
            running.stop().await;
            if let Some(probation) = &probation
                && probation.switch_back(&error.code)
            {
                return Err(ServeError::Restart(format!(
                    "the new version failed to start ({}); switched back",
                    error.code
                )));
            }
            return Err(ServeError::Start(error));
        }
    };
    let ready_info = Ready {
        addrs: services.server.local_addrs().to_vec(),
        elapsed: services.elapsed,
    };
    announce(&resolved, &services, &ready_info);
    if let Some(probation) = &probation
        && !probation.confirm()
    {
        tracing::warn!("ready after the probation deadline; the previous version takes over");
    }
    if let Some(updates) = &services.updates {
        let updates = updates.clone();
        running.tasks.push(tokio::spawn(async move {
            updates.report_outcome().await;
        }));
    }
    if let Some(ready) = ready {
        ready(&ready_info);
    }
    let Services {
        server,
        auth,
        ipam,
        engine,
        vault,
        updates,
        ..
    } = services;
    let requested = Arc::new(std::sync::OnceLock::<Instant>::new());
    let mark = Arc::clone(&requested);
    let restart_requested = restart.clone();
    let notify_stopping = async move {
        tokio::select! {
            () = shutdown => tracing::info!("shutdown requested"),
            reason = restart_requested.requested() => {
                tracing::info!(%reason, "stopping for a restart");
            }
        }
        let _ = mark.set(Instant::now());
        if let Some(stopping) = stopping {
            stopping();
        }
    };
    let result = server.run_until(notify_stopping).await;
    let since = |requested: &std::sync::OnceLock<Instant>| {
        requested.get().map_or(0, |at| millis(at.elapsed()))
    };
    tracing::info!(
        elapsed_ms = since(&requested),
        "API stopped: requests finished, event streams ended"
    );
    drop((auth, ipam, engine, vault, updates));
    running.stop().await;
    match (result, restart.reason()) {
        (Ok(()), Some(reason)) => {
            tracing::info!(
                elapsed_ms = since(&requested),
                "tenko stopped for a restart"
            );
            Err(ServeError::Restart(reason))
        }
        (Ok(()), None) => {
            tracing::info!(elapsed_ms = since(&requested), "tenko stopped");
            Ok(())
        }
        (Err(error), _) => Err(ServeError::Runtime(error.to_string())),
    }
}

/// Reads the update attempt at start: the probation of a newly installed version, or an
/// immediate switch back when a previous start of it did not become ready.
fn probation_at_start(
    resolved: &Resolved,
    restart: &crate::upgrade::restart::Restart,
) -> Result<Option<crate::upgrade::probation::Probation>, ServeError> {
    use crate::upgrade::probation::{StartAction, on_start};

    let own = crate::upgrade::running_version();
    match on_start(&resolved.data_dir, &own) {
        Ok(StartAction::Normal) => Ok(None),
        Ok(StartAction::Probation(probation)) => {
            tracing::warn!(
                version = %own,
                deadline_secs = probation.snapshot().deadline_secs,
                "this version was just installed and runs on probation"
            );
            probation.watch(restart.clone());
            Ok(Some(probation))
        }
        Ok(StartAction::SwitchBack(probation)) => {
            probation.switch_back("upgrade.not_confirmed");
            Err(ServeError::Restart(
                "the new version did not become ready at its first start".to_owned(),
            ))
        }
        Err(error) => Err(ServeError::Start(StartError::new(
            "data_dir",
            "upgrade.attempt_unreadable",
            format!("the update attempt record cannot be used: {error}"),
        ))),
    }
}

/// What a successful start leaves running.
struct Services {
    server: tenko_api::RunningServer,
    auth: Arc<AuthService>,
    /// The IPAM domain; `None` while the module is off (OPS-25).
    ipam: Option<Arc<IpamService>>,
    /// In-app updates (OPS-24); `None` when the service cannot run.
    updates: Option<crate::upgrade::updates::Updates>,
    engine: JobEngine,
    vault: Arc<StoreVault>,
    setup_token: Option<tenko_auth::secret::SetupToken>,
    /// The SHA-256 fingerprint of the internal CA root (mode a).
    ca_root_sha256: Option<String>,
    https: bool,
    elapsed: Duration,
    lab_plain_http: bool,
}

/// Runs the start steps. Whatever started is recorded in `running` for the cleanup.
#[allow(
    clippy::too_many_lines,
    reason = "the start order reads best as one sequence"
)]
async fn start(
    resolved: &Resolved,
    running: &mut Running,
    restart: &crate::upgrade::restart::Restart,
    probation: Option<&crate::upgrade::probation::Probation>,
) -> Result<Services, StartError> {
    let config = &resolved.config;
    let layout = resolved.layout();
    let mut steps = Steps::new();
    create_data_dir(&resolved.data_dir)?;
    // The data-directory format (OPS-23): a newer format is refused before anything, the
    // keys included, is touched; an older one is copied aside before the store opens and
    // migrated after.
    let registry = crate::upgrade::migrations::Registry::builtin();
    let plan = crate::upgrade::datadir::preflight(&layout.store(), registry)
        .map_err(|error| upgrade_error("store", &error))?;

    let fresh = layout.is_fresh();
    // The leader-only services of every step; the supervisor runs them after the last one.
    let leaders = leader::LeaderRegistry::new();
    let leader_view = leader::LeaderView::default();
    let ring: KekRing = steps
        .run("kek", async {
            let kek = resolved.kek.clone();
            let options = resolved.kek_options.clone();
            let init = if fresh {
                KekInit::CreateIfMissing
            } else {
                KekInit::Require
            };
            let ring = tokio::task::spawn_blocking(move || kek.load_with(init, &options))
                .await
                .map_err(|error| StartError::new("kek", "start.kek.panic", error.to_string()))?
                .map_err(|error| StartError::coded("kek", &error))?;
            // The vault logs its own loud warning for a key without OS protection.
            let active = ring.active();
            let protection = active.protection();
            let retired = ring.retired_ids().count();
            let summary = format!(
                "{} key {} ({}){}",
                if fresh { "created" } else { "loaded" },
                active.id(),
                protection.describe(),
                if retired > 0 {
                    format!(", {retired} retired")
                } else {
                    String::new()
                }
            );
            Ok((ring, summary))
        })
        .await?;

    let store: RaftStore = steps
        .run("store", async {
            // A migration (and the copy before it) may take longer than the service
            // manager's start timeout; the extension ends with this step.
            let _extension = plan
                .needs_backup()
                .then(|| crate::platform::extend_start("copying and migrating the data directory"));
            let backup = if let crate::upgrade::datadir::Plan::Migrate { from, to, .. } = plan {
                let (data_dir, store_dir) = (resolved.data_dir.clone(), layout.store());
                let copy = tokio::task::spawn_blocking(move || {
                    crate::upgrade::datadir::backup(&data_dir, &store_dir, from, to)
                })
                .await
                .map_err(|error| StartError::new("store", "start.store.panic", error.to_string()))?
                .map_err(|error| upgrade_error("store", &error))?;
                if let Some(probation) = probation {
                    probation.set_backup(&copy);
                }
                Some(copy)
            } else {
                None
            };
            let store = RaftStore::open(store_config(resolved))
                .await
                .map_err(|error| StartError::coded("store", &error))?;
            // A migration does not count against the probation deadline of a new version.
            if let Some(probation) = probation {
                probation.pause();
            }
            // A member of a controller cluster leaves the migration to the leader, which
            // runs it once every voter's binary knows the format (OPS-08).
            let membership = store.membership();
            let member = membership.voters.len() + membership.learners.len() > 1;
            let finished = crate::upgrade::datadir::finish_with(
                &store,
                &layout.store(),
                plan,
                registry,
                version(),
                member,
            )
            .await;
            if let Some(probation) = probation {
                probation.resume();
            }
            let format = match finished {
                Ok(outcome) => outcome,
                Err(error) => {
                    let _ = store.shutdown().await;
                    if let Some(copy) = &backup {
                        tracing::error!(
                            backup = %copy.display(),
                            "the migration failed; the store copy taken before it is kept"
                        );
                    }
                    return Err(upgrade_error("store", &error));
                }
            };
            let status = store.status();
            let fsync = match status.fsync_p50_micros {
                Some(p50) if p50 > FSYNC_WARN_MICROS => {
                    tracing::warn!(
                        fsync_p50_micros = p50,
                        data_dir = %layout.store().display(),
                        "the data directory is slow: a durable commit takes {:.1} ms at the \
                         median, above the 10 ms limit; use SSD or NVMe storage (OPS-19)",
                        micros_as_ms(p50)
                    );
                    format!(", fsync p50 {:.1} ms (SLOW)", micros_as_ms(p50))
                }
                Some(p50) => format!(", fsync p50 {:.1} ms", micros_as_ms(p50)),
                None => String::new(),
            };
            let disk = maintenance::at_start(&store, maintenance::Policy::new(&config.store)).await;
            let summary = format!(
                "{} at revision {}, audit head {}, {}{fsync}; {disk}",
                if fresh { "created" } else { "opened" },
                status.revision,
                status.audit_head,
                format.summary(),
            );
            Ok((store, summary))
        })
        .await?;
    running.store = Some(store.clone());
    running.tasks.push(tokio::spawn(maintenance::run(
        store.clone(),
        maintenance::Policy::new(&config.store),
        running.stop.subscribe(),
    )));
    let store_dyn: Arc<dyn Store> = Arc::new(store.clone());
    // Rolling upgrades (OPS-08): the leader migrates the data format once every voter's
    // binary knows it; every member keeps its marker and the format status.
    let format_follower = {
        let members = store.clone();
        let voters: crate::upgrade::rolling::Voters = Arc::new(move || members.membership().voters);
        leaders.register(Arc::new(crate::upgrade::rolling::Migrator::new(
            Arc::clone(&store_dyn),
            Arc::clone(&voters),
            registry,
            version(),
        )));
        let follower = crate::upgrade::rolling::Follower::new(
            Arc::clone(&store_dyn),
            layout.store(),
            voters,
            registry,
            version(),
        );
        running
            .tasks
            .push(follower.clone().spawn(running.stop.subscribe()));
        follower
    };
    // The module switch (OPS-25): tenko.toml, else the installation's choice, else all.
    let stored_modules = crate::modules::stored(store_dyn.as_ref())
        .await
        .map_err(|error| StartError::coded("store", &error))?;
    let modules = crate::modules::effective(config.modules, stored_modules);
    if let (Some(pinned), Some(chosen)) = (config.modules, stored_modules)
        && pinned != chosen
    {
        tracing::info!(
            pinned = %pinned,
            chosen = %chosen,
            "modules in tenko.toml decide; the installation's choice is not used"
        );
    }
    let ipam_on = modules.contains(crate::modules::Module::Ipam);

    let (mut cluster_peers, ring) = steps
        .run(
            "cluster",
            crate::cluster::start_peers(crate::cluster::Start {
                resolved,
                store: &store,
                ring,
                stop: running.stop.subscribe(),
            }),
        )
        .await?;
    running.tasks.extend(cluster_peers.tasks());

    let (vault, kek_admin, cluster_key) = steps
        .run("vault", async {
            let start = VaultStart {
                node: resolved.node_id,
                provider: resolved.kek.provider_name().to_owned(),
            };
            let vault = StoreVault::start(Arc::clone(&store_dyn), ring, &start)
                .await
                .map_err(|error| StartError::coded("vault", &error))?;
            let vault = Arc::new(vault);
            // Missing generations are fetched from the members of a cluster; a single
            // controller has nobody to ask.
            let peers: Arc<dyn KekPeers> = match cluster_peers.port() {
                Some(_) => Arc::new(PeerKekFetch::new(cluster_peers.peers().clone())),
                None => Arc::new(NoPeers),
            };
            let admin = KekAdmin::new(
                Arc::clone(&vault),
                resolved.kek.clone(),
                resolved.kek_options.clone(),
                resolved.node_id,
                peers,
            );
            // The cluster key (WP3.1b): every controller derives the same idempotency
            // fingerprints and ceremony seals from it. Without it this process keys them
            // itself, as a single controller did before.
            let (cluster_key, key_summary) =
                match cluster_key::ClusterKey::load_or_create(store_dyn.as_ref(), vault.as_ref())
                    .await
                {
                    Ok((key, true)) => (Some(key), "cluster key created"),
                    Ok((key, false)) => (Some(key), "cluster key loaded"),
                    Err(error) => {
                        tracing::warn!(
                            code = %error.code,
                            "the cluster key could not be read or created ({}); retried requests \
                             and sign-in ceremonies are keyed by this process only",
                            error.detail
                        );
                        (None, "no cluster key")
                    }
                };
            let summary = format!(
                "{} key(s) loaded, {}, {key_summary}",
                vault.ring().ids().count(),
                vault.ring().active().protection().describe()
            );
            Ok(((vault, admin, cluster_key), summary))
        })
        .await?;
    // Every controller follows the KEK state (new generations, rotations); the leader runs
    // the rotation itself.
    running.tasks.push(tokio::spawn(
        Arc::clone(&kek_admin).run(leader::stop_token(running.stop.subscribe())),
    ));
    leaders.register(kek_admin.rotation_service());
    leaders.register(crate::node::scan::control::housekeeping(
        resolved,
        Arc::clone(&store_dyn),
    ));

    let tls = steps
        .run("tls", async {
            let tls = tls::start(resolved, &store_dyn, &vault, &running.stop.subscribe()).await?;
            let summary = format!("{} (profile {})", tls.summary, tls.profile.as_str());
            Ok((tls, summary))
        })
        .await?;
    running.tasks.extend(tls.tasks);
    running.watchers.extend(tls.watchers);

    let (auth, setup_token) = steps
        .run("auth", async {
            let auth = AuthService::new(
                Arc::clone(&store_dyn),
                Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>,
                auth_config(resolved).await?,
            )
            .await
            .map_err(|error| StartError::coded("auth", &error))?;
            if let Some(cluster_key) = &cluster_key {
                auth.set_ceremony_key(cluster_key.ceremony_key());
            }
            let token = auth
                .prepare_setup()
                .await
                .map_err(|error| StartError::coded("auth", &error))?;
            // The token goes to a file, not to the log (API-10); a closed setup leaves none.
            publish_setup_token(&layout.setup_token(), token.as_ref())?;
            let summary = match (&token, auth.installation().await) {
                (Some(_), _) => "first-run setup is open".to_owned(),
                (None, Ok(Some(installation))) => format!(
                    "installation {} (profile {})",
                    installation.host_name,
                    auth.settings().profile.as_str()
                ),
                (None, _) => "setup complete".to_owned(),
            };
            Ok(((auth, token), summary))
        })
        .await?;
    if setup_token.is_some() {
        running.tasks.extend(setup_token::follow(
            Arc::clone(&store_dyn),
            layout.setup_token(),
            running.stop.subscribe(),
        ));
    }

    // Language packs (WP3.7): the key set of the UI this server serves, and the packs an
    // operator dropped into `<data_dir>/i18n/`, imported as uploads by the system. A file the
    // validation refuses is logged and audited as a failed upload; a file over the size limit
    // or one that cannot be read is logged. Neither stops the start.
    let languages = steps
        .run("languages", async {
            let languages = match &config.server.ui_dir {
                Some(dir) => tenko_api::i18n::service::Languages::from_ui_dir(dir),
                None => tenko_api::i18n::service::Languages::embedded(),
            };
            let dir = resolved.data_dir.join("i18n");
            let summary = match languages.import_dir(store_dyn.as_ref(), &dir).await {
                Ok(done) => format!(
                    "{} keys; {} imported, {} skipped, {} refused from {}",
                    languages.keys().len(),
                    done.imported,
                    done.skipped,
                    done.refused,
                    dir.display()
                ),
                Err(error) => {
                    tracing::warn!(dir = %dir.display(), %error, "the language pack directory cannot be read");
                    format!("{} keys; {} not readable", languages.keys().len(), dir.display())
                }
            };
            Ok((languages, summary))
        })
        .await?;

    // The network controllers of the VLAN provision job and the topology (WP2.7): filled
    // once the connector service runs; the job steps read it when they run.
    let vlan_controllers = tenko_ipam::vlan::Controllers::new();
    // The anchors of IPAM objects for scoped authorization (IAM-01, WP3.2): registered on
    // the store and given to the authorizer while the IPAM module runs. Without the module
    // it stays empty, so the event filter below passes nothing of IPAM to a scoped
    // principal.
    let scope = Arc::new(tenko_ipam::scope::ScopeIndex::new());
    let (ipam, mut engine, imports) = steps
        .run("ipam", async {
            let mut engine = JobEngine::new(
                Arc::clone(&store_dyn),
                EngineConfig {
                    node: resolved.node_id,
                    workers: config.jobs.workers,
                    default_group_limit: config.jobs.default_group_limit,
                    lease_ttl: Duration::from_secs(config.jobs.lease_ttl_secs),
                    scan_interval: Duration::from_secs(config.jobs.scan_interval_secs),
                    ..EngineConfig::default()
                },
            );
            if !ipam_on {
                // A disabled module registers no step, builds no tree and starts no task.
                return Ok((
                    (None, engine, None),
                    format!(
                        "the IPAM module is off ({})",
                        crate::modules::describe(modules, config.modules)
                    ),
                ));
            }
            tenko_ipam::jobs::register_steps(&mut engine);
            tenko_ipam::vlan::register_steps(&mut engine, &vlan_controllers);
            tenko_ipam::moves::register_steps(&mut engine, &vlan_controllers);
            let ipam = IpamService::new(
                Arc::clone(&store_dyn),
                Arc::new(engine.clone()),
                IpamConfig::default(),
            )
            .map_err(|error| StartError::coded("ipam", &error))?;
            store_dyn
                .register_index(scope.clone())
                .map_err(|error| StartError::coded("ipam", &error))?;
            auth.set_anchor_resolver(scope.clone());
            let tree = Arc::clone(ipam.tree());
            engine.set_prefix_resolver(Arc::new(move |prefix| {
                tree.prefix(prefix).map(|(_, network)| network)
            }));
            // An installation whose setup is closed has the default tenant and VRF from now on.
            if setup_token.is_none()
                && let Err(error) = ipam
                    .ensure_defaults(&tenko_core::RequestCtx::system(
                        tenko_core::SystemComponent::Ipam,
                    ))
                    .await
            {
                tracing::warn!(%error, "the default tenant and VRF could not be created");
            }
            let (imports, import_summary) = Imports::start(&ipam, &engine, &vault, &layout)?;
            Ok((
                (Some(ipam), engine, Some(imports)),
                format!("prefix tree built, step handlers registered, {import_summary}"),
            ))
        })
        .await?;
    if let Some(imports) = &imports {
        running
            .tasks
            .extend(imports.spawn_purge(running.stop.subscribe()));
        leaders.extend(imports.leader_services());
    }
    if let Some(ipam) = &ipam {
        let mut stop = running.stop.subscribe();
        running
            .tasks
            .push(tokio::spawn(Arc::clone(ipam).run_alarms(async move {
                let _ = stop.wait_for(|stopped| *stopped).await;
            })));
    }
    // The reconciler compares intent with observation (ADR 0005) while the IPAM module runs.
    let reconciler = match &ipam {
        Some(ipam) => Some(
            tenko_ipam::reconcile::Reconciler::new(
                Arc::clone(ipam),
                tenko_ipam::reconcile::ReconcilerConfig::default(),
            )
            .map_err(|error| StartError::coded("ipam", &error))?,
        ),
        None => None,
    };
    if let Some(reconciler) = &reconciler {
        // The settings live in the store (plan 2.6): seeded from the code defaults once, then
        // read by every run. The loop and the purge run on the leader.
        let defaults = tenko_ipam::reconcile::settings::ReconcilerSettings::of(reconciler.config());
        match tenko_ipam::reconcile::settings::seed(store_dyn.as_ref(), defaults).await {
            Ok(true) => tracing::info!("reconciler settings seeded with the defaults"),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(error = %error.code_str(), "the reconciler settings could not be seeded; the defaults apply");
            }
        }
        leaders.register(reconciler.leader_service());
    }
    let sink: Arc<dyn tenko_connect::host::normalize::ObservationSink> = match &reconciler {
        Some(reconciler) => {
            let reconciler = Arc::clone(reconciler);
            tenko_connect::host::normalize::sink_fn(
                move |batch: tenko_connect::host::normalize::ObservationBatch| {
                    let reconciler = Arc::clone(&reconciler);
                    async move {
                        reconciler
                            .ingest(tenko_ipam::observe::IngestBatch {
                                source: batch.source,
                                observations: batch.observations,
                                complete: batch.complete,
                                received_at: batch.received_at,
                            })
                            .await
                            .map(drop)
                            .map_err(tenko_ipam::IpamError::into_coded)
                    }
                },
            )
        }
        None => Arc::new(tenko_connect::host::normalize::DiscardSink),
    };
    // Operator secrets (IAM-16): the metadata layer over the vault, and the one-time adoption
    // of credentials imported before the metadata existed.
    let operator_secrets = Arc::new(tenko_vault::operator::OperatorSecrets::new(
        Arc::clone(&store_dyn),
        Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>,
    ));
    match operator_secrets
        .adopt_unmanaged(&tenko_core::RequestCtx::system(
            tenko_core::SystemComponent::Vault,
        ))
        .await
    {
        Ok(adopted) if adopted > 0 => {
            tracing::info!(adopted, "imported credentials adopted as operator secrets");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(%error, "imported credentials could not be adopted as operator secrets");
        }
    }

    // In-app updates (OPS-24): the service and the steps of its install job, registered
    // before the runner starts.
    let updates = {
        let raft = store.clone();
        let env = crate::upgrade::updates::Environment::detect(
            resolved.data_dir.clone(),
            resolved.node_id,
            &config.updates,
        );
        let parts = crate::upgrade::updates::Parts {
            section: config.updates.clone(),
            store: Arc::clone(&store_dyn),
            raft: Some(store.clone()),
            policy: Arc::clone(&auth) as Arc<dyn crate::upgrade::updates::Policy>,
            engine: engine.clone(),
            restart: restart.clone(),
            cluster: Box::new(move || {
                raft.raft()
                    .metrics()
                    .borrow()
                    .membership_config
                    .membership()
                    .voter_ids()
                    .count()
                    > 1
            }),
        };
        match crate::upgrade::updates::Updates::new(env, parts) {
            Ok(updates) => {
                updates.register_steps(&mut engine);
                Some(updates)
            }
            Err(error) => {
                tracing::warn!(code = %error.code, detail = %error.detail, "in-app updates are off");
                None
            }
        }
    };

    let runner = steps
        .run("jobs", async {
            // The job runner of the installation runs on the leader; every controller runs
            // the jobs pinned to it.
            let runner = engine
                .start_pinned()
                .map_err(|error| StartError::coded("jobs", &error))?;
            leaders.register(engine.leader_service());
            let summary = format!(
                "{} workers; the runner of jobs pinned to node {} runs, the job runner of the                  installation runs on the leader",
                config.jobs.workers, resolved.node_id
            );
            Ok((runner, summary))
        })
        .await?;
    running.runner = Some(runner);
    let mut connectors = steps
        .run(
            "connectors",
            crate::plugin::start(
                &store_dyn,
                &vault,
                &engine,
                &resolved.data_dir,
                running.stop.subscribe(),
                sink,
                resolved.config.profile.name,
            ),
        )
        .await?;
    running.tasks.push(connectors.task());
    leaders.register(connectors.leader_service());
    // The guardrails of network-controller writes are settings in the store (plan 2.6):
    // seeded from the defaults once, then followed on every controller.
    let defaults = tenko_connect::Guardrails::default();
    match tenko_connect::host::guardrails::seed(store_dyn.as_ref(), &defaults).await {
        Ok(true) => tracing::info!("guardrails seeded with the defaults"),
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(%error, "the guardrails could not be seeded; the defaults apply");
        }
    }
    let guardrails = match tenko_connect::host::guardrails::follow(
        Arc::clone(&store_dyn),
        running.stop.subscribe(),
    )
    .await
    {
        Ok((guardrails, task)) => {
            running.tasks.push(task);
            guardrails
        }
        Err(error) => {
            tracing::warn!(%error, "the guardrails could not be read; the defaults apply");
            tokio::sync::watch::channel(defaults).1
        }
    };
    vlan_controllers.set(tenko_api::routes::vlans::host::HostControllers::following(
        Arc::clone(connectors.host()),
        guardrails,
    ));
    let mut cluster = steps
        .run(
            "nodes",
            crate::node::controller::start_with(
                crate::node::controller::Parts {
                    resolved,
                    store: Arc::clone(&store_dyn),
                    vault: Arc::clone(&vault),
                    engine: engine.clone(),
                    reconciler: reconciler.clone(),
                    stop: running.stop.subscribe(),
                },
                Some(cluster_peers.clone()),
            ),
        )
        .await?;
    running.tasks.extend(cluster.tasks());
    leaders.extend(cluster.leader_services());
    let mut scans = steps
        .run(
            "scans",
            crate::node::scan::control::start(crate::node::scan::control::Parts {
                resolved,
                store: Arc::clone(&store_dyn),
                vault: Arc::clone(&vault) as Arc<dyn tenko_vault::Vault>,
                engine: engine.clone(),
                registry: Arc::clone(cluster.registry()),
                probe_sink: cluster.probe_sink(),
                stop: running.stop.subscribe(),
            }),
        )
        .await?;
    running.tasks.extend(scans.tasks());

    // The queue of changes made while this controller is cut off from its cluster
    // (OPS-26): local to the controller and drained by it after the heal.
    let change_queue = match &ipam {
        Some(ipam) => {
            let started = queue::start(queue::Parts {
                data_dir: resolved.data_dir.clone(),
                node: resolved.node_id,
                ipam: Arc::clone(ipam),
                authorizer: Some(auth.authorizer()),
                scope: Some(Arc::clone(&scope)),
                quorum: Some(store.quorum()),
                stop: running.stop.subscribe(),
            })
            .map_err(|error| StartError::new("ipam", "start.queue.io", error.to_string()))?;
            running.tasks.push(started.task);
            Some(started.queue)
        }
        None => None,
    };

    let lab_plain_http = tls.lab_plain_http;
    let https = tls.https;
    let metrics_stop = running.stop.subscribe();
    let (server, events, warnings_state, metrics_tasks) = steps
        .run("api", async {
            let mut state = AppState::with_options(
                Arc::clone(&store_dyn),
                StateOptions {
                    sse: config.sse.to_config(),
                    event_routes: event_routes(),
                    node: NodeStatus {
                        id: Some(resolved.node_id),
                        roles: vec![Role::Controller.as_str().to_owned()],
                    },
                    modules,
                },
            );
            state.auth = Some(Arc::clone(&auth) as Arc<dyn tenko_core::Authenticator>);
            state.authorizer = Some(auth.authorizer());
            // Scoped principals receive only the events and references they may read.
            state
                .events()
                .set_filter(Box::new(tenko_api::sse::filter::ScopedEvents::new(
                    auth.authorizer(),
                    Arc::clone(&scope),
                    Arc::clone(&store_dyn),
                )));
            let mut server =
                ServerConfig::new(resolved.listen.clone(), tls.service.clone(), tls.policy);
            server.workers = config.server.workers;
            server.lab_plain_http = tls.lab_plain_http;
            server.http = HttpConfig {
                allowed_origins: config.server.allowed_origins.clone(),
                rate_limit: config.rate_limit.to_config(),
                hsts: config.tls.hsts,
                ..HttpConfig::default()
            };
            server.ui = match &config.server.ui_dir {
                Some(dir) => UiSource::Dir(dir.clone()),
                None => UiSource::Embedded,
            };
            server.shutdown_grace = config.server.shutdown_grace();
            server.handshake_timeout = Duration::from_secs(config.server.handshake_timeout_secs);
            server.header_read_timeout =
                Duration::from_secs(config.server.header_read_timeout_secs);
            server.max_connections = config.server.max_connections;
            server.extensions.insert(Arc::clone(&auth));
            server.extensions.insert(Arc::clone(&languages));
            if let Some(change_queue) = &change_queue {
                server.extensions.insert(Arc::clone(change_queue));
            }
            if let Some(ipam) = &ipam {
                server.extensions.insert(Arc::clone(ipam));
                server.extensions.insert(Arc::clone(&scope));
                server.extensions.insert(Arc::clone(&vlan_controllers));
                server
                    .extensions
                    .insert(tenko_ipam::topology::TopologyService::new(
                        Arc::clone(ipam),
                        Arc::clone(&vlan_controllers),
                        tenko_ipam::topology::TopologyConfig::default(),
                    ));
            }
            server.extensions.insert(engine.clone());
            let module_switch: Arc<dyn tenko_api::routes::system::modules::ModuleService> =
                Arc::new(crate::modules::ModuleSwitch::new(
                    Arc::clone(&store_dyn),
                    state.clone(),
                    modules,
                    config.modules,
                    restart.clone(),
                ));
            server.extensions.insert(module_switch);
            if let Some(updates) = &updates {
                let service: Arc<dyn tenko_api::routes::system::updates::UpdateService> =
                    Arc::new(updates.clone());
                server.extensions.insert(service);
            }
            server
                .extensions
                .insert(tenko_api::routes::system::RunningVersion::new(
                    crate::upgrade::running_version().to_string(),
                ));
            if let Some((pem, fingerprint)) = &tls.ca_root {
                server.extensions.insert(Arc::new(CaRootSource::new(
                    tls.service.clone(),
                    pem.as_str(),
                    fingerprint.as_str(),
                )));
            }
            if let Some(imports) = &imports {
                imports.register(&mut server);
            }
            connectors.register(&mut server);
            connectors.publish_health(&state);
            cluster.register(&mut server, &state);
            scans.register(&mut server);
            if let Some(reconciler) = &reconciler {
                server.extensions.insert(Arc::clone(reconciler));
            }
            server.extensions.insert(Arc::clone(&operator_secrets));
            // The audit export (WP3.3): the settings service for the API on every
            // controller, the exporter as a leader service.
            let (export_admin, exporter) = audit_export(resolved, &store_dyn, &vault);
            server.extensions.insert(export_admin);
            leaders.register(exporter);
            server.extensions.insert(Arc::clone(&kek_admin));
            state.set_kek(Arc::clone(&kek_admin));
            let backups = crate::backup::service::BackupService::new(
                store.clone(),
                Arc::clone(&vault),
                &engine,
                crate::backup::service::Config::of(resolved),
            );
            if let Err(error) = backups.record_restore().await {
                tracing::warn!(%error, "the restore could not be recorded; it is recorded at the next start");
            }
            leaders.register(backups.schedule());
            let backup_status: Arc<dyn tenko_api::routes::backup::BackupService> = backups;
            server.extensions.insert(Arc::clone(&backup_status));
            server.extensions.insert(leader_view.source());
            server.extensions.insert(format_follower.source());
            server.fingerprint_key = cluster_key
                .as_ref()
                .map(cluster_key::ClusterKey::fingerprint_key);
            leaders.register(leader::idempotency_purge(
                Arc::clone(&store_dyn),
                server.http.idempotency.ttl,
            ));
            leaders.register(leader::used_challenges_purge(Arc::clone(&store_dyn)));
            // The metrics timer (gauges from the status interfaces of the services) and the
            // optional loopback listener; both stop with the server.
            let mut gauges = metrics::Sources::of(state.clone());
            gauges.store = Some(store.clone());
            gauges.engine = Some(engine.clone());
            gauges.connectors = Some(Arc::clone(connectors.host()));
            gauges.sessions = Some(Arc::clone(cluster.registry().sessions()));
            gauges.leader = Some(leader_view.source());
            gauges.kek = Some(Arc::clone(&kek_admin));
            gauges.backups = Some(backup_status);
            // The metrics topic shows the other controllers and answers their reads.
            gauges.peers = Some(cluster_peers.peers().clone());
            gauges.node_registry = Some(Arc::clone(cluster.registry()));
            let metrics_listen = config
                .metrics
                .listen_addr()
                .map_err(|error| StartError::new("api", "config.invalid", error.to_string()))?;
            let (metrics_tasks, metrics_summary) = Box::pin(metrics::start(
                gauges,
                Duration::from_secs(config.metrics.gauge_interval_secs),
                metrics_listen,
                &metrics_stop,
            ))
            .await
            .map_err(|error| StartError::new("api", "start.metrics.bind", error.to_string()))?;
            let events = state.events().clone();
            let warnings_state = state.clone();
            let running = tenko_api::start(server, state).await.map_err(|error| {
                let code = match &error {
                    tenko_api::ServeError::Bind { .. } => "start.api.bind",
                    tenko_api::ServeError::Config(_) => "start.api.config",
                    tenko_api::ServeError::Ui(_) => "start.api.ui",
                    tenko_api::ServeError::Runtime(_) => "start.api.runtime",
                };
                StartError::new("api", code, error.to_string())
            })?;
            let summary = format!(
                "listening on {}; metrics: {metrics_summary}",
                running
                    .local_addrs()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(((running, events, warnings_state, metrics_tasks), summary))
        })
        .await?;
    running.tasks.extend(metrics_tasks);
    leaders.register(leader::clock::beat_service(
        Arc::clone(&store_dyn),
        resolved.node_id,
    ));
    if let Some(task) = leader::clock::follow(
        Arc::clone(&store_dyn),
        leader_view.clone(),
        running.stop.subscribe(),
    ) {
        running.tasks.push(task);
    }
    {
        let stop = running.stop.subscribe();
        running
            .tasks
            .push(tenko_api::routes::audit_export::follow_warnings(
                warnings_state,
                stop,
            ));
    }
    running.leader = Some(leader::spawn(
        Arc::clone(&store_dyn),
        &leaders,
        leader_view,
        Some(events),
        leader::SupervisorConfig::default(),
    ));

    if let Some(updates) = &updates {
        running
            .tasks
            .push(updates.spawn_checks(running.stop.subscribe()));
    }
    tracing::info!(
        elapsed_ms = millis(steps.started.elapsed()),
        "started in {} ms ({})",
        millis(steps.started.elapsed()),
        steps.summary()
    );
    Ok(Services {
        server,
        auth,
        ipam,
        engine,
        vault,
        setup_token,
        ca_root_sha256: tls.ca_root.as_ref().map(|(_, sha256)| sha256.clone()),
        updates: updates.clone(),
        https,
        elapsed: steps.started.elapsed(),
        lab_plain_http,
    })
}

/// The event routes of the server: the defaults, and a new release manifest on the `admin`
/// topic (OPS-24).
fn event_routes() -> EventRoutes {
    let mut routes = EventRoutes::default();
    routes.table(
        crate::upgrade::updates::MANIFEST.name().clone(),
        tenko_api::sse::Topic::Admin,
        None,
    );
    routes
}

/// Creates the data directory, private to the service account on Unix (R15).
fn create_data_dir(dir: &std::path::Path) -> Result<(), StartError> {
    let error = |error: std::io::Error| {
        StartError::new(
            "data_dir",
            "start.data_dir",
            format!("cannot create {}: {error}", dir.display()),
        )
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(error)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(error)
    }
}

/// The store settings of the configuration.
pub(crate) fn store_config(resolved: &Resolved) -> RaftStoreConfig {
    let section = &resolved.config.store;
    let mib = |value: usize| value.saturating_mul(1024 * 1024);
    let mut config = RaftStoreConfig::new(resolved.layout().store());
    config.node_id = resolved.node_id;
    config.address.clone_from(&resolved.config.node.address);
    config.log_cache_bytes = mib(section.log_cache_mib);
    config.sm_cache_bytes = mib(section.sm_cache_mib);
    config.durability = match section.durability {
        DurabilityName::Deferred => SmDurability::Deferred {
            checkpoint_interval: Duration::from_millis(section.checkpoint_interval_ms),
        },
        DurabilityName::Immediate => SmDurability::Immediate,
    };
    config.journal_retention = section.journal_retention;
    config.snapshot = SnapshotPolicy {
        every_entries: section.snapshot_every_entries,
        every_log_bytes: section.snapshot_every_log_mib.saturating_mul(1024 * 1024),
        keep_entries: section.snapshot_keep_entries,
    };
    config.write_timeout = Duration::from_secs(section.write_timeout_secs);
    config.read_wait = Duration::from_secs(section.read_wait_secs);
    config.fsync_probe_samples = section.fsync_probe_samples;
    config.verify_full_audit_chain = section.verify_full_audit_chain;
    config.journal_max_bytes = section.journal_max_mib.saturating_mul(1024 * 1024);
    config
}

#[allow(
    clippy::cast_precision_loss,
    reason = "a display value in milliseconds"
)]
fn micros_as_ms(micros: u64) -> f64 {
    micros as f64 / 1000.0
}

/// The authentication settings: relying party, cookie flag and breach-check sources.
async fn auth_config(resolved: &Resolved) -> Result<AuthConfig, StartError> {
    let config = &resolved.config;
    let rp_id = config.auth.rp_id.clone().or_else(|| match &resolved.tls {
        TlsSpec::ReverseProxy { public_host, .. } => Some(public_host.clone()),
        _ => None,
    });
    let hibp_online: Option<Arc<dyn tenko_auth::hibp::HibpRangeSource>> = if config.hibp.online {
        let source = match &config.hibp.range_url {
            Some(url) => tenko_auth::hibp::HttpRangeSource::with_base_url(url.clone()),
            None => tenko_auth::hibp::HttpRangeSource::new(),
        }
        .map_err(|error| StartError::new("auth", "start.auth.hibp", error.to_string()))?;
        Some(Arc::new(source))
    } else {
        None
    };
    let hibp_offline = match &config.hibp.offline_filter {
        Some(path) => {
            let path = path.clone();
            let filter = tokio::task::spawn_blocking(move || HibpFilter::open(&path))
                .await
                .map_err(|error| StartError::new("auth", "start.auth.hibp", error.to_string()))?
                .map_err(|error| {
                    StartError::new(
                        "auth",
                        "start.auth.hibp",
                        format!("the offline HIBP filter cannot be opened: {error}"),
                    )
                })?;
            Some(Arc::new(filter))
        }
        None => None,
    };
    let mut attestation_roots = Vec::new();
    for path in &config.auth.attestation_roots {
        attestation_roots.extend(read_certificates(path)?);
    }
    Ok(AuthConfig {
        rp_id,
        origins: config.auth.origins.clone(),
        rp_name: config.auth.rp_name.clone(),
        attestation_roots,
        // Off only for plain HTTP (Lab, TGL-08): browsers drop `Secure` cookies there.
        cookie_secure: !matches!(resolved.tls, TlsSpec::Plain),
        hibp_online,
        hibp_offline,
        ..AuthConfig::default()
    })
}

/// DER certificates from a DER or PEM file.
fn read_certificates(path: &std::path::Path) -> Result<Vec<Vec<u8>>, StartError> {
    let bytes = std::fs::read(path).map_err(|error| {
        StartError::new(
            "auth",
            "start.auth.attestation_roots",
            format!("{}: {error}", path.display()),
        )
    })?;
    if !bytes.starts_with(b"-----BEGIN") {
        return Ok(vec![bytes]);
    }
    let certificates = pem_certificates(&bytes);
    if certificates.is_empty() {
        return Err(StartError::new(
            "auth",
            "start.auth.attestation_roots",
            format!("{} holds no PEM certificate", path.display()),
        ));
    }
    Ok(certificates)
}

/// The DER bodies of the `CERTIFICATE` blocks of a PEM file.
pub(crate) fn pem_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line == "-----BEGIN CERTIFICATE-----" {
            body = Some(String::new());
        } else if line == "-----END CERTIFICATE-----" {
            if let Some(encoded) = body.take()
                && let Some(der) = base64_decode(&encoded)
            {
                out.push(der);
            }
        } else if let Some(encoded) = body.as_mut() {
            encoded.push_str(line);
        }
    }
    out
}

/// Standard base64 (with or without padding); `None` for anything else.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let url_safe: String = text
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    tenko_auth::encoding::base64url_decode(&url_safe).ok()
}

/// Logs readiness and prints the console notes: where to connect, and the setup token
/// while setup is open.
fn announce(resolved: &Resolved, services: &Services, ready: &Ready) {
    let url = public_url(resolved, services, &ready.addrs);
    tracing::info!(url = %url, "tenko {} ready", crate::upgrade::running_version());
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "tenko {} ready at {url}",
        crate::upgrade::running_version()
    );
    if services.lab_plain_http {
        let _ = writeln!(
            out,
            "WARNING: plain HTTP from every source (Lab profile); do not use this in production"
        );
    }
    if let Some(sha256) = &services.ca_root_sha256 {
        let _ = writeln!(
            out,
            "internal CA root (install it on admin clients): {}",
            resolved.layout().ca_root().display()
        );
        let _ = writeln!(out, "  SHA-256 fingerprint: {sha256}");
        let _ = writeln!(
            out,
            "  download: {url}api/v1/system/ca-root, or `tenko ca-root --url {url} --fingerprint {sha256}`"
        );
    }
    if let Some(token) = &services.setup_token {
        use std::io::IsTerminal as _;

        // The setup token is single-use, changes at every start and only works until setup
        // completes (API-10). The log never carries it: it names the command that prints it
        // from `<data_dir>/setup-token`. Standard output shows it to a terminal only, so
        // that the journal or a container log never holds it either.
        tracing::warn!("{}", setup_token::open_notice(&resolved.data_dir));
        let rule = "=".repeat(72);
        let _ = writeln!(out, "{rule}");
        let _ = writeln!(out, "First-run setup is open.");
        let _ = writeln!(
            out,
            "{}",
            setup_token::console_line(
                token.expose(),
                &resolved.layout().setup_token(),
                &resolved.data_dir,
                out.is_terminal(),
            )
        );
        let _ = writeln!(out, "Open {url} in a browser, or run:");
        let _ = writeln!(
            out,
            "  tenko setup --url {url} --admin <name> --host-name <host> --setup-token <token>"
        );
        let _ = writeln!(
            out,
            "The token changes at every start until setup is complete."
        );
        let _ = writeln!(out, "{rule}");
    }
    let _ = out.flush();
}

/// Writes the setup token of this start to its file while setup is open, atomically and
/// before the server is ready; removes a leftover file when setup is closed.
fn publish_setup_token(
    path: &std::path::Path,
    token: Option<&tenko_auth::secret::SetupToken>,
) -> Result<(), StartError> {
    let Some(token) = token else {
        if let Err(error) = setup_token::remove(path) {
            tracing::warn!(
                %error,
                path = %path.display(),
                "a leftover setup token file could not be removed"
            );
        }
        return Ok(());
    };
    setup_token::write(path, token.expose()).map_err(|error| {
        StartError::new(
            "auth",
            "start.setup_token",
            format!(
                "cannot write the setup token file {}: {error}",
                path.display()
            ),
        )
    })
}

/// The audit export's settings service and its exporter (WP3.3): file sinks write into
/// `[audit_export] file_dir`, TLS client keys come from the vault, and the syslog
/// HOSTNAME is this controller's TLS host name (`-` when it has none).
fn audit_export(
    resolved: &Resolved,
    store: &Arc<dyn Store>,
    vault: &Arc<StoreVault>,
) -> (
    Arc<tenko_auth::audit_export::admin::AuditExportAdmin>,
    Arc<dyn tenko_core::cluster::LeaderService>,
) {
    use tenko_auth::audit_export::{
        admin::AuditExportAdmin,
        exporter::AuditExporter,
        sink::{Opener, Timeouts},
    };
    let opener = Opener {
        file_dir: Some(resolved.audit_export_dir()),
        vault: Some(Arc::clone(vault) as Arc<dyn tenko_vault::Vault>),
        timeouts: Timeouts::default(),
    };
    let hostname = match &resolved.tls {
        TlsSpec::InternalCa { host_name, .. } => host_name.clone(),
        TlsSpec::ReverseProxy { public_host, .. } => public_host.clone(),
        _ => "-".to_owned(),
    };
    let version = crate::upgrade::running_version().to_string();
    let admin = AuditExportAdmin::new(
        Arc::clone(store),
        opener.clone(),
        hostname.clone(),
        version.clone(),
    );
    let exporter = AuditExporter::new(Arc::clone(store), opener, hostname, version);
    (Arc::new(admin), Arc::new(exporter))
}

/// The URL clients use: the public host behind a proxy, else the first bound address.
fn public_url(resolved: &Resolved, services: &Services, addrs: &[SocketAddr]) -> String {
    if let TlsSpec::ReverseProxy { public_host, .. } = &resolved.tls {
        return format!("https://{public_host}/");
    }
    let scheme = if services.https { "https" } else { "http" };
    let Some(addr) = addrs.first() else {
        return format!("{scheme}://localhost/");
    };
    let host = match (&resolved.tls, addr.ip()) {
        (TlsSpec::InternalCa { host_name, .. }, _) => host_name.clone(),
        (_, ip) if ip.is_unspecified() => "localhost".to_owned(),
        (_, IpAddr::V6(ip)) => format!("[{ip}]"),
        (_, IpAddr::V4(ip)) => ip.to_string(),
    };
    format!("{scheme}://{host}:{}/", addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_order_names_every_step_once() {
        let names: Vec<&str> = START_ORDER.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "kek",
                "store",
                "cluster",
                "vault",
                "tls",
                "auth",
                "languages",
                "ipam",
                "jobs",
                "connectors",
                "nodes",
                "scans",
                "api"
            ]
        );
    }

    #[test]
    fn roles_without_the_controller_are_refused() {
        let mut err = Vec::new();
        let status = check_roles("dns,dhcp".parse().expect("roles"), &mut err);
        assert_eq!(status, Some(exit::USAGE));
        let text = String::from_utf8(err).expect("UTF-8");
        assert!(
            text.contains("dns, dhcp: not implemented in Phase 1"),
            "{text}"
        );
    }

    #[test]
    fn roles_with_the_controller_run_the_controller_and_the_probe() {
        let mut err = Vec::new();
        assert_eq!(check_roles(RoleSet::ALL, &mut err), None);
        let text = String::from_utf8(err).expect("UTF-8");
        assert!(
            text.contains("runs the controller and probe roles"),
            "{text}"
        );
        let mut err = Vec::new();
        assert_eq!(
            check_roles("controller".parse().expect("roles"), &mut err),
            None
        );
        assert_eq!(err, b"");
    }

    #[test]
    fn start_errors_name_step_and_code() {
        let error = StartError::new("kek", "vault.kek_unavailable", "no usable key");
        assert_eq!(
            error.to_string(),
            "start step `kek` failed [vault.kek_unavailable]: no usable key"
        );
        assert_eq!(ServeError::Start(error).exit_code(), exit::START);
    }

    #[test]
    fn pem_certificates_are_decoded() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAEC\nAw==\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_certificates(pem), vec![vec![0, 1, 2, 3]]);
        assert_eq!(base64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(base64_decode("a*"), None);
    }
}
