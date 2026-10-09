//! `tenko serve`: runs the roles of this node.
//!
//! Phase 1 implements the `controller` role. It starts in this order, each step logged with
//! its duration, and refuses to start with a coded error when a step fails:
//!
//! | # | Step | What comes up |
//! |---|---|---|
//! | 1 | `kek` | the key-encryption keys (created on the first start, required afterwards) |
//! | 2 | `store` | the replicated store: openraft over redb, one voter, with the fsync probe (OPS-19) |
//! | 3 | `vault` | the vault; it refuses to open when the store holds secrets no loaded KEK opens |
//! | 4 | `tls` | the TLS mode (OPS-22): the internal CA's certificate, imported files or the reverse proxy |
//! | 5 | `auth` | users, sessions, passkeys, TOTP, settings; prints the setup token while setup is open |
//! | 6 | `ipam` | the IPAM domain over the job engine, its prefix tree and alarms |
//! | 7 | `jobs` | the job runner |
//! | 8 | `api` | the HTTP API, the web UI and server-sent events |
//!
//! The vault needs the store to check its envelopes, so it opens right after the store.
//!
//! Shutdown (Ctrl-C, `SIGTERM`, the service manager, or the end of standard input with
//! `--stop-on-eof`) runs in reverse: the API ends its event streams and lets open requests
//! finish, the job runner stops, the background tasks end, and the store makes its state
//! durable and closes its files.
//!
//! The data directory holds `kek/` (key generations), `store/` (`log.redb`, `sm.redb`,
//! `snapshots/`), `tls/ca-root.pem` (the public root of the internal CA) and `logs/`
//! (the service log).

mod imports;
mod maintenance;
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
use tenko_core::{Coded, Role, RoleSet};
use tenko_ipam::{IpamConfig, IpamService};
use tenko_jobs::{EngineConfig, JobEngine, RunnerHandle};
use tenko_store::{
    Store,
    raft::{RaftStore, RaftStoreConfig, SmDurability, SnapshotPolicy},
};
use tenko_vault::{KekInit, KekRing, StoreVault};
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
pub const START_ORDER: [(&str, &str); 9] = [
    ("kek", "key-encryption keys"),
    ("store", "replicated store (openraft over redb)"),
    ("vault", "envelope encryption of secrets"),
    ("tls", "TLS mode and certificate"),
    ("auth", "users, sessions, passkeys and TOTP"),
    ("ipam", "IPAM domain and job engine"),
    ("jobs", "job runner"),
    ("connectors", "connector plugins and their supervisor"),
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
    if let Err(error) = logging::init_server(
        &resolved.config.log,
        resolved.config.log.file.as_deref(),
        logging::Sink::Console,
    ) {
        let _ = writeln!(err, "tenko serve: {error}");
        return exit::FAILURE;
    }
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
    match run(resolved, shutdown, crate::platform::notify_hooks()) {
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

/// Reports roles that Phase 1 does not implement. Returns the exit status when the node
/// has nothing to run.
pub fn check_roles(roles: RoleSet, err: &mut impl Write) -> Option<u8> {
    let missing: Vec<&str> = roles
        .roles()
        .filter(|role| *role != Role::Controller)
        .map(Role::as_str)
        .collect();
    if missing.is_empty() {
        return None;
    }
    let list = missing.join(", ");
    if roles.contains(Role::Controller) {
        let _ = writeln!(
            err,
            "tenko serve: role(s) {list}: not implemented in Phase 1; this node runs the \
             controller role only"
        );
        None
    } else {
        let _ = writeln!(
            err,
            "tenko serve: role(s) {list}: not implemented in Phase 1"
        );
        Some(exit::USAGE)
    }
}

/// Runs the server on a runtime of its own until `shutdown` resolves.
///
/// `shutdown` is called once, inside the runtime, to build the shutdown future (signals
/// need a runtime to register).
///
/// # Errors
///
/// [`ServeError::Start`] when a step fails, [`ServeError::Runtime`] when the runtime
/// cannot be built or the API stops with an error.
pub fn run(
    resolved: Resolved,
    shutdown: impl FnOnce() -> Shutdown + Send + 'static,
    hooks: Hooks,
) -> Result<(), ServeError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(resolved.config.runtime.workers)
        .thread_name("tenko-core")
        .enable_all()
        .build()
        .map_err(|error| ServeError::Runtime(format!("core runtime: {error}")))?;
    let result = runtime.block_on(async move { serve(resolved, shutdown(), hooks).await });
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
            runner: None,
            stop,
            tasks: Vec::new(),
            watchers: Vec::new(),
        }
    }

    /// Stops the runner and the background tasks, then closes the store.
    async fn stop(mut self) {
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
        version()
    );
    let mut running = Running::new();
    let restart = crate::upgrade::restart::Restart::new();
    // A newly installed version is on probation (OPS-24): read before anything else, so a
    // switched-back previous version restores its store before the format check.
    let probation = probation_at_start(&resolved, &restart)?;
    let started = start(&resolved, &mut running, &restart, probation.as_ref()).await;
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
    let ring: KekRing = steps
        .run("kek", async {
            let kek = resolved.kek.clone();
            let init = if fresh {
                KekInit::CreateIfMissing
            } else {
                KekInit::Require
            };
            let ring = tokio::task::spawn_blocking(move || kek.load(init))
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
            let finished =
                crate::upgrade::datadir::finish(&store, &layout.store(), plan, registry, version())
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

    let vault = steps
        .run("vault", async {
            let vault = StoreVault::open(Arc::clone(&store_dyn), ring)
                .await
                .map_err(|error| StartError::coded("vault", &error))?;
            let summary = format!("{} key(s) loaded", vault.ring().ids().count());
            Ok((Arc::new(vault), summary))
        })
        .await?;

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
            let token = auth
                .prepare_setup()
                .await
                .map_err(|error| StartError::coded("auth", &error))?;
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
            let ipam = IpamService::new(
                Arc::clone(&store_dyn),
                Arc::new(engine.clone()),
                IpamConfig::default(),
            )
            .map_err(|error| StartError::coded("ipam", &error))?;
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
        let mut stop = running.stop.subscribe();
        running
            .tasks
            .push(tokio::spawn(Arc::clone(reconciler).run(async move {
                let _ = stop.wait_for(|stopped| *stopped).await;
            })));
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
            let runner = engine
                .start()
                .map_err(|error| StartError::coded("jobs", &error))?;
            let summary = format!(
                "runner of node {} with {} workers",
                resolved.node_id, config.jobs.workers
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
            ),
        )
        .await?;
    running.tasks.push(connectors.task());

    let lab_plain_http = tls.lab_plain_http;
    let https = tls.https;
    let server = steps
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
            if let Some(ipam) = &ipam {
                server.extensions.insert(Arc::clone(ipam));
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
            if let Some(reconciler) = &reconciler {
                server.extensions.insert(Arc::clone(reconciler));
            }
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
                "listening on {}",
                running
                    .local_addrs()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok((running, summary))
        })
        .await?;

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
    tracing::info!(url = %url, "tenko {} ready", version());
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "tenko {} ready at {url}", version());
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
        // The setup token is the one secret this binary prints, by design (API-10): it is
        // single-use, changes at every start and only works until setup completes.
        tracing::warn!(
            setup_token = token.expose(),
            "first-run setup is open; complete it in the web UI or with `tenko setup`"
        );
        let rule = "=".repeat(72);
        let _ = writeln!(out, "{rule}");
        let _ = writeln!(out, "First-run setup is open.");
        let _ = writeln!(out, "Setup token: {}", token.expose());
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
                "vault",
                "tls",
                "auth",
                "ipam",
                "jobs",
                "connectors",
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
    fn roles_with_the_controller_run_it_alone() {
        let mut err = Vec::new();
        assert_eq!(check_roles(RoleSet::ALL, &mut err), None);
        let text = String::from_utf8(err).expect("UTF-8");
        assert!(text.contains("runs the controller role only"), "{text}");
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
