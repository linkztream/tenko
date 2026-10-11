//! The scanner supervisor of the probe role (OPS-28, SCAN-09): it runs the scanner on the
//! configuration the controllers hold for the probe once there is one, else on the `[scan]`
//! section of `tenko.toml`; it swaps the scanner atomically when a new configuration
//! arrives, keeping the running one when the new one does not build; it carries out the
//! commands of the controllers (scans on demand, their cancellation and the remote kill
//! switch); and it reports the scope it applies after every change.
//!
//! The same supervisor serves a probe node (the configuration from the agent's sync, the
//! reports through the agent) and the probe role in process on a controller (the
//! configuration and the reports straight from and to the store).

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use tenko_cluster::{
    node_sync::{
        commands::{
            CommandHandler, CommandReporter, IncomingCommand, SCAN_CANCEL, SCAN_RESUME, SCAN_RUN,
            SCAN_STOP,
        },
        payload::{CancelArgs, ScanRunArgs, StopArgs, decode_args},
    },
    probe::{ConfigOrigin, timestamp_to_proto},
    proto::v1,
};
use tenko_core::Timestamp;
use tenko_scan::{
    ScanError,
    config::ScanConfig,
    method::MethodKind,
    scanner::{RunRequest, Scanner},
    status::{RunOutcome, ScanPaths},
};
use tokio::{sync::watch, task::JoinHandle};
use uuid::Uuid;

/// How long a scanner may take to stop when it is replaced or the process stops.
pub const SWAP_TIMEOUT: Duration = Duration::from_secs(10);

/// The configuration the supervisor should apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    /// The configuration; `None` when the newest one received does not decode, so the
    /// running one stays and `error` says why.
    pub config: Option<ScanConfig>,
    /// Where it came from.
    pub origin: ConfigOrigin,
    /// Its revision; 0 for the node's own file.
    pub revision: u64,
    /// Why the newest configuration does not apply.
    pub error: Option<String>,
}

impl Desired {
    /// The node's own `[scan]` section.
    pub fn local(config: ScanConfig) -> Self {
        Self {
            config: Some(config),
            origin: ConfigOrigin::Local,
            revision: 0,
            error: None,
        }
    }

    /// A configuration from the controllers at `revision`.
    pub fn synced(config: ScanConfig, revision: u64) -> Self {
        Self {
            config: Some(config),
            origin: ConfigOrigin::Synced,
            revision,
            error: None,
        }
    }

    /// A configuration from the controllers that cannot apply.
    pub fn refused(revision: u64, error: impl Into<String>) -> Self {
        Self {
            config: None,
            origin: ConfigOrigin::Synced,
            revision,
            error: Some(error.into()),
        }
    }
}

/// Where the supervisor's reports of the scope it applies go: the agent's `Config.Report`
/// on a probe node, the store on a controller.
pub trait ScopeReports: Send + Sync {
    /// Takes the newest report; an older one not sent yet is replaced.
    fn report(&self, report: v1::ConfigReport);
}

/// Builds a scanner for a configuration: [`Scanner::new`] over the host in production.
pub type Build = Arc<dyn Fn(&ScanConfig) -> Result<Arc<Scanner>, ScanError> + Send + Sync>;

struct Running {
    scanner: Arc<Scanner>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

#[derive(Debug, Clone)]
struct Applied {
    origin: ConfigOrigin,
    revision: u64,
    error: Option<String>,
    at: Timestamp,
    /// The configuration in force, also when the scanner is switched off.
    config: Option<ScanConfig>,
}

/// The scanner supervisor.
pub struct Supervisor {
    paths: ScanPaths,
    build: Build,
    reports: Arc<dyn ScopeReports>,
    running: tokio::sync::Mutex<Option<Running>>,
    /// The scanner of the moment, for the commands (a cheap read without the swap lock).
    current: Mutex<Option<Arc<Scanner>>>,
    applied: Mutex<Applied>,
    /// The `scan.run` commands in progress, with the scanner that runs each.
    commands: Mutex<HashMap<Uuid, Arc<Scanner>>>,
    /// The `scan.run` commands the controllers cancelled.
    cancelled: Mutex<HashSet<Uuid>>,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Supervisor {
    /// A supervisor for the data directory `data_dir` that builds its scanners with
    /// `build` and reports into `reports`.
    pub fn new(data_dir: &Path, build: Build, reports: Arc<dyn ScopeReports>) -> Arc<Self> {
        Arc::new(Self {
            paths: ScanPaths::new(data_dir),
            build,
            reports,
            running: tokio::sync::Mutex::new(None),
            current: Mutex::new(None),
            applied: Mutex::new(Applied {
                origin: ConfigOrigin::Local,
                revision: 0,
                error: None,
                at: Timestamp::now(),
                config: None,
            }),
            commands: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(HashSet::new()),
        })
    }

    /// The scanner that runs now, if any.
    pub fn scanner(&self) -> Option<Arc<Scanner>> {
        lock(&self.current).clone()
    }

    /// Applies each configuration `desired` publishes until `stop` turns true, then stops
    /// the scanner.
    pub async fn run(
        self: Arc<Self>,
        mut desired: watch::Receiver<Desired>,
        mut stop: watch::Receiver<bool>,
    ) {
        loop {
            let wanted = desired.borrow_and_update().clone();
            self.apply(wanted).await;
            let closed = tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => break,
                changed = desired.changed() => changed.is_err(),
            };
            if closed {
                // Nothing publishes configurations any more: keep the one in force.
                let _ = stop.wait_for(|stopped| *stopped).await;
                break;
            }
        }
        let previous = self.running.lock().await.take();
        *lock(&self.current) = None;
        if let Some(previous) = previous {
            stop_scanner(previous).await;
        }
    }

    /// Applies one configuration: a new scanner when the configuration differs from the
    /// one in force, the old one kept when the new one does not build.
    pub async fn apply(&self, wanted: Desired) {
        let mut running = self.running.lock().await;
        let Some(config) = wanted.config else {
            let error = wanted.error.unwrap_or_default();
            tracing::warn!(
                revision = wanted.revision,
                "the scan configuration from the controllers does not apply; the scanner keeps the one in force: {error}"
            );
            lock(&self.applied).error = Some(error);
            drop(running);
            self.report_now();
            return;
        };
        let same = lock(&self.applied)
            .config
            .as_ref()
            .is_some_and(|current| *current == config);
        if same {
            let mut applied = lock(&self.applied);
            applied.origin = wanted.origin;
            applied.revision = wanted.revision;
            applied.error = None;
            drop(applied);
            drop(running);
            self.report_now();
            return;
        }
        let next = if config.enabled {
            match (self.build)(&config) {
                Ok(scanner) => Some(scanner),
                Err(error) => {
                    tracing::warn!(
                        code = error.code(),
                        revision = wanted.revision,
                        "the new scan configuration does not build; the scanner keeps the one in force: {}",
                        error.detail()
                    );
                    lock(&self.applied).error = Some(error.detail().to_owned());
                    drop(running);
                    self.report_now();
                    return;
                }
            }
        } else {
            None
        };
        if let Some(previous) = running.take() {
            *lock(&self.current) = None;
            stop_scanner(previous).await;
        }
        match next {
            Some(scanner) => {
                if scanner.scope().is_empty() {
                    tracing::warn!(
                        "the scan configuration has no prefixes: the scanner scans nothing until prefixes are configured"
                    );
                }
                let (stop, stopped) = watch::channel(false);
                let task = tokio::spawn(Arc::clone(&scanner).run(stopped));
                tracing::info!(
                    origin = wanted.origin.as_str(),
                    revision = wanted.revision,
                    scope = %scanner.scope().describe(),
                    "scan configuration applied"
                );
                *lock(&self.current) = Some(Arc::clone(&scanner));
                *running = Some(Running {
                    scanner,
                    stop,
                    task,
                });
            }
            None => {
                tracing::info!(
                    origin = wanted.origin.as_str(),
                    revision = wanted.revision,
                    "the scanner is switched off (enabled = false)"
                );
            }
        }
        *lock(&self.applied) = Applied {
            origin: wanted.origin,
            revision: wanted.revision,
            error: None,
            at: Timestamp::now(),
            config: Some(config),
        };
        drop(running);
        self.report_now();
    }

    /// What the probe applies, as `Config.Report` carries it.
    pub fn report(&self) -> v1::ConfigReport {
        let applied = lock(&self.applied).clone();
        let probe = if let Some(scanner) = self.scanner() {
            scanner.scope_report()
        } else {
            {
                let stop_reason = self.kill_reason();
                v1::ProbeScopeReport {
                    prefixes: Vec::new(),
                    exclude: Vec::new(),
                    methods: Vec::new(),
                    vrf: None,
                    active: applied.config.as_ref().is_some_and(|config| config.active),
                    stopped: stop_reason.is_some(),
                    stop_reason: stop_reason.unwrap_or_default(),
                }
            }
        };
        v1::ConfigReport {
            revision: if applied.origin == ConfigOrigin::Synced {
                applied.revision
            } else {
                0
            },
            source: applied.origin.as_str().to_owned(),
            error: applied.error.unwrap_or_default(),
            probe: Some(probe),
            at: Some(timestamp_to_proto(applied.at)),
        }
    }

    fn report_now(&self) {
        self.reports.report(self.report());
    }

    /// The reason recorded with the kill switch file, when it is on.
    fn kill_reason(&self) -> Option<String> {
        if !self.paths.killed() {
            return None;
        }
        let text = std::fs::read_to_string(self.paths.kill_switch()).unwrap_or_default();
        Some(
            text.trim()
                .split_once(' ')
                .map_or("", |(_, reason)| reason)
                .trim()
                .to_owned(),
        )
    }

    /// Switches the kill switch on or off: through the running scanner, which stops its
    /// scans at once, else in the file that a scanner reads when it starts.
    fn kill(&self, on: bool, reason: &str) -> Result<(), ScanError> {
        match self.scanner() {
            Some(scanner) => scanner.set_kill(on, reason)?,
            None if on => self.paths.kill(reason)?,
            None => {
                self.paths.resume()?;
            }
        }
        self.report_now();
        Ok(())
    }

    async fn run_command(
        self: Arc<Self>,
        scanner: Arc<Scanner>,
        id: Uuid,
        args: ScanRunArgs,
        reporter: CommandReporter,
    ) {
        lock(&self.commands).insert(id, Arc::clone(&scanner));
        let deadline = args.deadline_secs.map(|secs| {
            let scanner = Arc::clone(&scanner);
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(u64::from(secs))).await;
                lock(&this.cancelled).insert(id);
                scanner.cancel_run(id);
            })
        });
        let mut methods = Vec::new();
        let mut notes = Vec::new();
        for name in &args.methods {
            match MethodKind::parse(name) {
                Some(kind) => methods.push(kind),
                None => notes.push(format!("{name}: not a scan method")),
            }
        }
        let total = methods.len().max(1);
        let mut batches = 0u32;
        let mut ran = 0usize;
        for (index, kind) in methods.iter().enumerate() {
            if lock(&self.cancelled).contains(&id) {
                notes.push("cancelled by the controllers".to_owned());
                break;
            }
            let percent = u8::try_from(index.saturating_mul(100) / total).unwrap_or(99);
            reporter.running(percent, Some(kind.name().to_owned()));
            let request = RunRequest {
                target: args.target.clone(),
                ignore_blackout: args.ignore_blackout,
                run: Some(id),
            };
            match scanner.run_now(*kind, &request).await {
                Ok(record) => {
                    batches = batches.saturating_add(record.batches);
                    if record.outcome != RunOutcome::Failed {
                        ran += 1;
                    }
                    if let Some(error) = record.error {
                        notes.push(format!("{kind}: {error}"));
                    }
                    if let Some(error) = record.delivery_error {
                        notes.push(format!("{kind}: {error}"));
                    }
                }
                Err(error) => notes.push(format!("{kind}: {}", error.detail())),
            }
        }
        if let Some(deadline) = deadline {
            deadline.abort();
        }
        lock(&self.commands).remove(&id);
        let cancelled = lock(&self.cancelled).remove(&id);
        let detail = (!notes.is_empty()).then(|| notes.join("; "));
        if ran == 0 && batches == 0 {
            reporter.failed(detail.unwrap_or_else(|| "no method ran".to_owned()));
        } else if cancelled && batches == 0 {
            reporter.failed(detail.unwrap_or_else(|| "cancelled".to_owned()));
        } else {
            reporter.done(batches, detail);
        }
    }
}

async fn stop_scanner(previous: Running) {
    let Running {
        scanner,
        stop,
        task,
    } = previous;
    let _ = stop.send(true);
    if tokio::time::timeout(SWAP_TIMEOUT, task).await.is_err() {
        tracing::warn!("the scanner did not stop in time");
    }
    drop(scanner);
}

/// Carries out the commands of the controllers with the supervisor's scanner.
#[derive(Debug, Clone)]
pub struct ScanCommands(pub Arc<Supervisor>);

#[async_trait]
impl CommandHandler for ScanCommands {
    async fn handle(&self, command: IncomingCommand, reporter: CommandReporter) {
        let supervisor = &self.0;
        match command.kind.as_str() {
            SCAN_RUN => {
                let args = match decode_args::<ScanRunArgs>(&command.encoding, &command.payload) {
                    Ok(args) => args,
                    Err(error) => return reporter.rejected(error.detail().to_owned()),
                };
                let Some(scanner) = supervisor.scanner() else {
                    return reporter.rejected("the scanner is switched off on this probe");
                };
                reporter.accepted();
                tracing::info!(command = %command.id, methods = %args.methods.join(","), target = args.target.as_deref().unwrap_or("the scope"), "scan on demand from the controllers");
                tokio::spawn(
                    Arc::clone(supervisor).run_command(scanner, command.id, args, reporter),
                );
            }
            SCAN_CANCEL => {
                let args = match decode_args::<CancelArgs>(&command.encoding, &command.payload) {
                    Ok(args) => args,
                    Err(error) => return reporter.rejected(error.detail().to_owned()),
                };
                let scanner = lock(&supervisor.commands).get(&args.command).cloned();
                let detail = match scanner {
                    Some(scanner) => {
                        lock(&supervisor.cancelled).insert(args.command);
                        scanner.cancel_run(args.command);
                        "cancelled"
                    }
                    None => "the scan was not running",
                };
                reporter.done(0, Some(detail.to_owned()));
            }
            SCAN_STOP => {
                let args = match decode_args::<StopArgs>(&command.encoding, &command.payload) {
                    Ok(args) => args,
                    Err(error) => return reporter.rejected(error.detail().to_owned()),
                };
                match supervisor.kill(true, &args.reason) {
                    Ok(()) => reporter.done(0, None),
                    Err(error) => reporter.failed(error.detail().to_owned()),
                }
            }
            SCAN_RESUME => match supervisor.kill(false, "") {
                Ok(()) => reporter.done(0, None),
                Err(error) => reporter.failed(error.detail().to_owned()),
            },
            other => reporter.rejected(format!(
                "this probe does not know the command `{}`",
                other.chars().take(40).collect::<String>()
            )),
        }
    }
}

#[cfg(test)]
mod tests;
