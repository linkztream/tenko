//! The scheduler of a probe (SCAN-06, SCAN-09): runs every method on its own schedule and
//! on demand, inside the rate limits, outside the blackout windows and never while the
//! kill switch is on, and hands one batch per run to a [`BatchSink`].
//!
//! A batch is complete only when the method covered everything it was asked to cover over
//! the whole configured scope and nothing stopped it; then the controller expires what the
//! method reported before and no longer reports. A narrower on-demand run, a run a device
//! did not fully answer, and a run the kill switch, a blackout window, the deadline or the
//! shutdown stopped all send what they saw as a batch that is not complete.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use tenko_cluster::{
    probe::{MAX_SIGHTINGS, ProbeBatch, Sighting},
    proto::v1,
};
use tenko_core::{Timestamp, VrfId};
use tokio::{
    sync::watch,
    time::{Instant, sleep, sleep_until},
};
use uuid::Uuid;

use crate::{
    blackout::Blackout,
    capability::Capabilities,
    config::ScanConfig,
    error::ScanError,
    known::KnownAddresses,
    limit::Pacer,
    method::{Availability, Cancel, Method, MethodKind, MethodOutput, RunContext},
    methods::{
        icmp::{IcmpSweep, pinger_for},
        names::NameQuery,
        neighbours::NeighbourTable,
        raw,
        rdns::ReverseDns,
        snmp::SnmpPoll,
        tcp::TcpConnect,
    },
    scope::Scope,
    secrets::SecretSource,
    status::{MethodState, MethodStatus, RunOutcome, RunRecord, ScanPaths, ScanStatus},
    sys::System,
};

/// Where batches go: the agent's buffer on a probe node, the reconciler on a controller,
/// the `incoming/` directory for a one-shot run.
#[async_trait]
pub trait BatchSink: Send + Sync {
    /// Takes one batch. `run` is the command the batch answers (a scan on demand from the
    /// controllers), which the batch carries to the controller. Returns how many batches
    /// were queued: a sink may split a batch that is too large.
    ///
    /// # Errors
    ///
    /// A [`ScanError`] when the batch cannot be queued (the buffer is full, the disk
    /// fails).
    async fn deliver(&self, batch: ProbeBatch, run: Option<Uuid>) -> Result<u32, ScanError>;
}

/// A sink that keeps the batches in memory (diagnostics and tests).
#[derive(Debug, Default)]
pub struct MemorySink {
    batches: Mutex<Vec<(ProbeBatch, Option<Uuid>)>>,
}

impl MemorySink {
    /// The batches so far.
    pub fn batches(&self) -> Vec<ProbeBatch> {
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(batch, _)| batch.clone())
            .collect()
    }

    /// The batches so far, with the command each answers.
    pub fn tagged(&self) -> Vec<(ProbeBatch, Option<Uuid>)> {
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl BatchSink for MemorySink {
    async fn deliver(&self, batch: ProbeBatch, run: Option<Uuid>) -> Result<u32, ScanError> {
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((batch, run));
        Ok(1)
    }
}

/// The delays of the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Delay of the first run after the start, per method (the passive methods first).
    pub first_run: [(MethodKind, Duration); 8],
    /// Longest the methods that work on known addresses wait for the others to report.
    pub addresses_wait: Duration,
    /// How often the kill switch file is checked.
    pub kill_poll: Duration,
    /// How long a stopped run may take to hand back what it saw.
    pub grace: Duration,
    /// How often the status file is written while nothing changes.
    pub status_refresh: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            first_run: [
                (MethodKind::Arp, Duration::from_secs(2)),
                (MethodKind::Nd, Duration::from_secs(3)),
                (MethodKind::Mdns, Duration::from_secs(10)),
                (MethodKind::Snmp, Duration::from_secs(15)),
                (MethodKind::Icmp, Duration::from_secs(20)),
                (MethodKind::Llmnr, Duration::from_secs(40)),
                (MethodKind::TcpConnect, Duration::from_secs(90)),
                (MethodKind::ReverseDns, Duration::from_secs(120)),
            ],
            addresses_wait: Duration::from_secs(600),
            kill_poll: Duration::from_secs(1),
            grace: Duration::from_secs(5),
            status_refresh: Duration::from_secs(60),
        }
    }
}

impl Timing {
    /// Delays for tests: every first run after `first`, short waits.
    pub fn immediate(first: Duration) -> Self {
        let mut timing = Self::default();
        for entry in &mut timing.first_run {
            entry.1 = first;
        }
        timing.addresses_wait = first * 4;
        timing.kill_poll = Duration::from_millis(50);
        timing.grace = Duration::from_secs(2);
        timing
    }

    fn first_run(&self, kind: MethodKind) -> Duration {
        self.first_run
            .iter()
            .find(|(method, _)| *method == kind)
            .map_or(Duration::from_secs(60), |(_, delay)| *delay)
    }
}

/// What the scanner gets from its host.
#[derive(Debug, Clone)]
pub struct Environment {
    /// Commands and files.
    pub system: Arc<dyn System>,
    /// Raw sockets and ICMP.
    pub capabilities: Capabilities,
    /// Where vault secrets of SNMP devices come from: the controllers, through the node
    /// agent; `None` on a host without a controller connection.
    pub secrets: Option<Arc<dyn SecretSource>>,
}

impl Environment {
    /// The real host.
    pub fn host() -> Self {
        let system: Arc<dyn System> = Arc::new(crate::sys::HostSystem);
        let capabilities = Capabilities::detect(system.as_ref());
        Self {
            system,
            capabilities,
            secrets: None,
        }
    }

    /// With the source of vault secrets.
    #[must_use]
    pub fn with_secrets(mut self, secrets: Arc<dyn SecretSource>) -> Self {
        self.secrets = Some(secrets);
        self
    }
}

/// How the scanner runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The scheduler of a node: writes the status and the known addresses.
    Service,
    /// A one-shot run from the command line: reads the known addresses, writes nothing of
    /// the running scheduler's.
    OneShot,
}

/// Builds the methods of a configuration.
///
/// # Errors
///
/// `scan.config` for a configuration that does not validate.
pub fn build_methods(
    config: &ScanConfig,
    environment: &Environment,
) -> Result<Vec<Arc<dyn Method>>, ScanError> {
    let system = Arc::clone(&environment.system);
    let ms = Duration::from_millis;
    let methods: Vec<Arc<dyn Method>> = MethodKind::ALL
        .into_iter()
        .map(|kind| -> Result<Arc<dyn Method>, ScanError> {
            Ok(match kind {
                MethodKind::Arp => Arc::new(NeighbourTable::new(false, Arc::clone(&system))),
                MethodKind::Nd => Arc::new(NeighbourTable::new(true, Arc::clone(&system))),
                MethodKind::Icmp => Arc::new(IcmpSweep::new(
                    pinger_for(environment.capabilities.icmp, Arc::clone(&system)),
                    ms(config.icmp.timeout_ms),
                )),
                MethodKind::TcpConnect => Arc::new(TcpConnect::new(
                    config.tcp_connect.ports.clone(),
                    ms(config.tcp_connect.timeout_ms),
                    config.tcp_connect.tls_hint,
                    config.tcp_connect.targets,
                )),
                MethodKind::ReverseDns => Arc::new(ReverseDns::new(
                    config.dns_servers()?,
                    ms(config.reverse_dns.timeout_ms),
                    Arc::clone(&system),
                )),
                MethodKind::Mdns => Arc::new(NameQuery::mdns(
                    config.mdns_group()?,
                    config.mdns.unicast_port,
                    Duration::from_secs(config.mdns.listen_secs),
                    config.mdns.passive,
                )),
                MethodKind::Llmnr => Arc::new(NameQuery::llmnr(
                    config.llmnr.port,
                    ms(config.llmnr.timeout_ms),
                )),
                MethodKind::Snmp => Arc::new(
                    SnmpPoll::new(
                        config.snmp.devices.clone(),
                        ms(config.snmp.timeout_ms),
                        config.snmp.retries,
                        config.snmp.attach_on_lldp_ports,
                    )
                    .with_secrets(environment.secrets.clone()),
                ),
                // WP3.14: the raw-socket methods, from their config sections.
                MethodKind::ArpSweep => Arc::new(raw::ArpSweep::new(
                    raw::RawSupport::detect(&environment.capabilities),
                    &config.arp_sweep,
                )),
                MethodKind::TcpSyn => Arc::new(raw::TcpSynScan::new(
                    raw::RawSupport::detect(&environment.capabilities),
                    &config.tcp_syn,
                )),
                MethodKind::OsFingerprint => Arc::new(raw::OsFingerprintScan::new(
                    raw::RawSupport::detect(&environment.capabilities),
                    &config.os_fingerprint,
                )),
                MethodKind::Lldp => Arc::new(raw::LldpListen::new(
                    raw::RawSupport::detect(&environment.capabilities),
                    &config.lldp,
                )),
                MethodKind::DhcpSnoop => Arc::new(raw::DhcpSnoop::new(
                    raw::RawSupport::detect(&environment.capabilities),
                    &config.dhcp_snoop,
                )),
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(methods)
}

/// The runtime state of the scheduler.
#[derive(Debug, Default)]
struct Inner {
    known: KnownAddresses,
    states: BTreeMap<MethodKind, MethodState>,
    next: BTreeMap<MethodKind, Timestamp>,
    last: BTreeMap<MethodKind, RunRecord>,
    reported: BTreeSet<MethodKind>,
    running: BTreeSet<MethodKind>,
    /// The cancel switches of runs on demand, by the command they answer.
    cancels: BTreeMap<Uuid, watch::Sender<bool>>,
}

/// The scanner of a probe.
pub struct Scanner {
    config: ScanConfig,
    scope: Arc<Scope>,
    pacer: Arc<Pacer>,
    blackout: Blackout,
    vrf: Option<VrfId>,
    capabilities: Capabilities,
    methods: Vec<Arc<dyn Method>>,
    sink: Arc<dyn BatchSink>,
    paths: ScanPaths,
    mode: Mode,
    timing: Timing,
    started: Instant,
    inner: Mutex<Inner>,
    kill: watch::Sender<bool>,
    /// Fires when a run ends, for the methods that wait for known addresses.
    reported: tokio::sync::Notify,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("scope", &self.scope)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// Why a run was stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopReason {
    Shutdown,
    KillSwitch,
    Blackout,
    Deadline,
    Cancelled,
}

impl StopReason {
    const fn text(self) -> &'static str {
        match self {
            StopReason::Shutdown => "stopped by the shutdown of the process",
            StopReason::KillSwitch => "stopped by the kill switch",
            StopReason::Blackout => "stopped by a blackout window",
            StopReason::Deadline => "stopped at its deadline",
            StopReason::Cancelled => "cancelled by the controllers",
        }
    }
}

/// A run's options.
#[derive(Debug, Clone, Default)]
pub struct RunRequest {
    /// A target inside the scope (`192.0.2.10`, `192.0.2.0/28`); the batch is then never
    /// complete.
    pub target: Option<String>,
    /// Runs inside a blackout window too.
    pub ignore_blackout: bool,
    /// The command the run answers (a scan on demand from the controllers): its batch
    /// carries the id, and [`Scanner::cancel_run`] stops it.
    pub run: Option<Uuid>,
}

impl Scanner {
    /// A scanner for `config` with the methods of [`build_methods`].
    ///
    /// # Errors
    ///
    /// `scan.config` for a configuration that does not validate.
    pub fn new(
        config: ScanConfig,
        paths: ScanPaths,
        sink: Arc<dyn BatchSink>,
        environment: &Environment,
        mode: Mode,
    ) -> Result<Arc<Self>, ScanError> {
        config.validate()?;
        let methods = build_methods(&config, environment)?;
        Self::with_methods(
            config,
            paths,
            sink,
            environment.capabilities.clone(),
            methods,
            mode,
            Timing::default(),
        )
    }

    /// A scanner with the given methods and timing (tests, and methods built elsewhere).
    ///
    /// # Errors
    ///
    /// `scan.config` for a configuration that does not validate.
    pub fn with_methods(
        config: ScanConfig,
        paths: ScanPaths,
        sink: Arc<dyn BatchSink>,
        capabilities: Capabilities,
        methods: Vec<Arc<dyn Method>>,
        mode: Mode,
        timing: Timing,
    ) -> Result<Arc<Self>, ScanError> {
        config.validate()?;
        let scope = Arc::new(config.scope()?);
        let blackout = config.blackout()?;
        let vrf = config.vrf()?;
        let pacer = Arc::new(Pacer::new(config.pace_limits()));
        let mut known = KnownAddresses::load(&paths.known());
        known.prune(Timestamp::now());
        let (kill, _) = watch::channel(paths.killed());
        Ok(Arc::new(Self {
            config,
            scope,
            pacer,
            blackout,
            vrf,
            capabilities,
            methods,
            sink,
            paths,
            mode,
            timing,
            started: Instant::now(),
            inner: Mutex::new(Inner {
                known,
                ..Inner::default()
            }),
            kill,
            reported: tokio::sync::Notify::new(),
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The scope.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The method of `kind`.
    pub fn method(&self, kind: MethodKind) -> Option<Arc<dyn Method>> {
        self.methods
            .iter()
            .find(|method| method.kind() == kind)
            .cloned()
    }

    /// Why `kind` does not run on schedule; `None` when it does.
    fn hold(&self, kind: MethodKind, method: &dyn Method) -> Option<(MethodState, String)> {
        if let Availability::Unavailable(reason) = method.availability() {
            return Some((MethodState::Unavailable, reason));
        }
        if !self.config.schedule(kind).enabled {
            return Some((MethodState::Disabled, "switched off in [scan]".to_owned()));
        }
        if kind.is_active() && !self.config.active {
            return Some((
                MethodState::Disabled,
                "active probing is off (scan.active = false)".to_owned(),
            ));
        }
        if self.scope.is_empty() && kind != MethodKind::Snmp {
            return Some((
                MethodState::Unavailable,
                "no prefixes in [scan]; scans never leave the configured prefixes".to_owned(),
            ));
        }
        None
    }

    /// Whether `kind` may run on demand: the same rules as on schedule.
    fn may_run(&self, kind: MethodKind, method: &dyn Method) -> Result<(), ScanError> {
        match self.hold(kind, method) {
            None => Ok(()),
            Some((MethodState::Disabled, reason)) => {
                Err(ScanError::new("scan.disabled", format!("{kind}: {reason}")))
            }
            Some((_, reason)) => Err(ScanError::unavailable(format!("{kind}: {reason}"))),
        }
    }

    /// The addresses that count now, inside the scope.
    pub fn known(&self) -> Vec<std::net::IpAddr> {
        self.lock()
            .known
            .current(Timestamp::now())
            .into_iter()
            .filter(|ip| self.scope.contains(*ip))
            .collect()
    }

    /// Runs `kind` once now, outside its schedule (SCAN-09).
    ///
    /// # Errors
    ///
    /// `scan.stopped` while the kill switch is on, `scan.blackout` inside a blackout window
    /// (unless the request ignores them), `scan.disabled` for a method switched off in
    /// `[scan]` or for active probing when it is off, `scan.unavailable`,
    /// `scan.out_of_scope` for a target outside the scope.
    pub async fn run_now(
        &self,
        kind: MethodKind,
        request: &RunRequest,
    ) -> Result<RunRecord, ScanError> {
        let method = self
            .method(kind)
            .ok_or_else(|| ScanError::unavailable(format!("{kind} is not built in")))?;
        self.may_run(kind, method.as_ref())?;
        if self.paths.killed() || *self.kill.borrow() {
            return Err(ScanError::new(
                "scan.stopped",
                "the kill switch is on; `tenko node scan resume` switches it off",
            ));
        }
        if kind.sends_packets()
            && !request.ignore_blackout
            && let Some(until) = self.blackout.active_until(SystemTime::now())
        {
            return Err(ScanError::new(
                "scan.blackout",
                format!(
                    "a blackout window is in force until {}; --ignore-blackout runs anyway",
                    Timestamp::from(time::OffsetDateTime::from(until))
                ),
            ));
        }
        let target = match &request.target {
            Some(text) => Some(self.scope.narrow(text)?),
            None => None,
        };
        let (_stop, stop) = watch::channel(false);
        let (cancel_tx, cancel) = watch::channel(false);
        if let Some(run) = request.run {
            self.lock().cancels.insert(run, cancel_tx);
        }
        let run = self.execute(
            method.as_ref(),
            Request {
                target,
                target_text: request.target.clone(),
                on_demand: true,
                respect_blackout: !request.ignore_blackout,
                run: request.run,
            },
            stop,
            Some(cancel),
        );
        tokio::pin!(run);
        // The kill switch file stops an on-demand run too, also in a process of its own
        // where no scheduler follows the file.
        let watch_file = async {
            loop {
                sleep(self.timing.kill_poll).await;
                if self.paths.killed() {
                    self.kill.send_replace(true);
                    break;
                }
            }
            std::future::pending::<std::convert::Infallible>().await
        };
        tokio::pin!(watch_file);
        let record = tokio::select! {
            record = &mut run => record,
            never = &mut watch_file => match never {},
        };
        if let Some(run) = request.run {
            self.lock().cancels.remove(&run);
        }
        Ok(record)
    }

    /// Cancels the run on demand that answers `run`; whether one was running.
    pub fn cancel_run(&self, run: Uuid) -> bool {
        self.lock()
            .cancels
            .get(&run)
            .is_some_and(|cancel| cancel.send(true).is_ok())
    }

    /// Switches the kill switch on (with `reason`) or off, at once: every running scan
    /// stops and no scan starts until it is off. The file in `<data_dir>/scan/` keeps the
    /// state across restarts.
    ///
    /// # Errors
    ///
    /// `scan.io` when the file cannot be written or removed.
    pub fn set_kill(&self, on: bool, reason: &str) -> Result<(), ScanError> {
        if on {
            self.paths.kill(reason)?;
            tracing::warn!(%reason, "kill switch on: every scan stops");
        } else if self.paths.resume()? {
            tracing::info!("kill switch off: scans resume");
        }
        self.kill.send_replace(on);
        self.write_status();
        Ok(())
    }

    /// The reason recorded with the kill switch, when it is on.
    pub fn kill_reason(&self) -> Option<String> {
        if !self.paths.killed() {
            return None;
        }
        let text = std::fs::read_to_string(self.paths.kill_switch()).unwrap_or_default();
        // The file holds the time, a space and the reason.
        let reason = text
            .trim()
            .split_once(' ')
            .map_or("", |(_, reason)| reason)
            .trim()
            .to_owned();
        Some(reason)
    }

    /// The scope the scanner applies, as the probe reports it to the controllers.
    pub fn scope_report(&self) -> v1::ProbeScopeReport {
        let methods = self
            .methods
            .iter()
            .filter(|method| self.hold(method.kind(), method.as_ref()).is_none())
            .map(|method| method.kind().name().to_owned())
            .collect();
        let stop_reason = self.kill_reason();
        v1::ProbeScopeReport {
            prefixes: self
                .scope
                .prefixes()
                .iter()
                .map(ToString::to_string)
                .collect(),
            exclude: self
                .scope
                .exclusions()
                .iter()
                .map(ToString::to_string)
                .collect(),
            methods,
            vrf: self.vrf.map(|vrf| vrf.to_string()),
            active: self.config.active,
            stopped: stop_reason.is_some() || *self.kill.borrow(),
            stop_reason: stop_reason.unwrap_or_default(),
        }
    }

    /// Runs the schedule until `stop` turns true.
    pub async fn run(self: Arc<Self>, stop: watch::Receiver<bool>) {
        let mut tasks = Vec::new();
        for method in &self.methods {
            let kind = method.kind();
            if let Some((state, reason)) = self.hold(kind, method.as_ref()) {
                tracing::debug!(method = %kind, %reason, "scan method held");
                self.lock().states.insert(kind, state);
                continue;
            }
            self.lock().states.insert(kind, MethodState::Idle);
            tasks.push(tokio::spawn(
                Arc::clone(&self).method_loop(Arc::clone(method), stop.clone()),
            ));
        }
        tracing::info!(
            prefixes = %self.scope.describe(),
            methods = tasks.len(),
            "scanner started"
        );
        self.write_status();
        let watcher = tokio::spawn(Arc::clone(&self).watch_kill_switch(stop.clone()));
        let mut stop = stop;
        let _ = stop.wait_for(|stopped| *stopped).await;
        for task in tasks {
            let _ = task.await;
        }
        let _ = watcher.await;
        self.write_status();
        tracing::info!("scanner stopped");
    }

    /// Follows the kill switch file and refreshes the status now and then.
    async fn watch_kill_switch(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut refreshed = Instant::now();
        loop {
            tokio::select! {
                () = sleep(self.timing.kill_poll) => {}
                _ = stop.wait_for(|stopped| *stopped) => return,
            }
            let killed = self.paths.killed();
            if killed != *self.kill.borrow() {
                if killed {
                    tracing::warn!("kill switch on: every scan stops");
                } else {
                    tracing::info!("kill switch off: scans resume");
                }
                self.kill.send_replace(killed);
                self.write_status();
                refreshed = Instant::now();
            } else if refreshed.elapsed() >= self.timing.status_refresh {
                self.write_status();
                refreshed = Instant::now();
            }
        }
    }

    /// Whether the methods that work on known addresses may start: every presence method
    /// that runs here has reported once, or the wait is over.
    fn addresses_ready(&self) -> bool {
        if self.started.elapsed() >= self.timing.addresses_wait {
            return true;
        }
        let inner = self.lock();
        self.methods
            .iter()
            .map(|method| method.kind())
            .filter(|kind| !kind.uses_known_addresses())
            .filter(|kind| {
                inner.states.get(kind).is_some_and(|state| {
                    !matches!(state, MethodState::Disabled | MethodState::Unavailable)
                })
            })
            .all(|kind| inner.reported.contains(&kind))
    }

    fn set_state(&self, kind: MethodKind, state: MethodState) {
        let changed = self.lock().states.insert(kind, state) != Some(state);
        if changed {
            self.write_status();
        }
    }

    fn set_next(&self, kind: MethodKind, at: Instant) {
        let wait = at.saturating_duration_since(Instant::now());
        if let Some(next) = Timestamp::now().checked_add(wait) {
            self.lock().next.insert(kind, next);
        }
    }

    async fn method_loop(
        self: Arc<Self>,
        method: Arc<dyn Method>,
        mut stop: watch::Receiver<bool>,
    ) {
        let kind = method.kind();
        let schedule = self.config.schedule(kind);
        let mut next = Instant::now() + self.timing.first_run(kind);
        let mut kill = self.kill.subscribe();
        // A run the kill switch stopped runs again as soon as the switch is off.
        let mut rerun = false;
        loop {
            self.set_next(kind, next);
            self.write_status();
            tokio::select! {
                () = sleep_until(next) => {}
                _ = kill.wait_for(|killed| *killed) => {}
                _ = stop.wait_for(|stopped| *stopped) => return,
            }
            if *kill.borrow_and_update() {
                self.set_state(kind, MethodState::Stopped);
                tokio::select! {
                    _ = kill.wait_for(|killed| !*killed) => {}
                    _ = stop.wait_for(|stopped| *stopped) => return,
                }
                self.set_state(kind, MethodState::Idle);
                if rerun {
                    next = Instant::now();
                    rerun = false;
                }
                continue;
            }
            if Instant::now() < next {
                continue;
            }
            if kind.uses_known_addresses() && !self.addresses_ready() {
                self.set_state(kind, MethodState::WaitingForAddresses);
                tokio::select! {
                    () = self.reported.notified() => {}
                    () = sleep(Duration::from_secs(1)) => {}
                    _ = stop.wait_for(|stopped| *stopped) => return,
                }
                next = Instant::now();
                continue;
            }
            if kind.sends_packets()
                && let Some(until) = self.blackout.active_until(SystemTime::now())
            {
                self.set_state(kind, MethodState::Blackout);
                let wait = until
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO);
                next = Instant::now() + wait + Duration::from_secs(1);
                continue;
            }
            let record = self
                .execute(
                    method.as_ref(),
                    Request {
                        target: None,
                        target_text: None,
                        on_demand: false,
                        respect_blackout: true,
                        run: None,
                    },
                    stop.clone(),
                    None,
                )
                .await;
            if *stop.borrow() {
                return;
            }
            rerun = record.outcome == RunOutcome::Cancelled && *self.kill.borrow();
            next = Instant::now() + jitter(schedule.interval);
        }
    }

    /// Runs `method` once and hands its batch to the sink.
    async fn execute(
        &self,
        method: &dyn Method,
        request: Request,
        mut stop: watch::Receiver<bool>,
        cancel: Option<watch::Receiver<bool>>,
    ) -> RunRecord {
        let Request {
            target,
            target_text,
            on_demand,
            respect_blackout,
            run,
        } = request;
        let kind = method.kind();
        let started_at = Timestamp::now();
        let (narrowed, scope) = match target {
            Some(scope) => (true, Arc::new(scope)),
            None => (false, Arc::clone(&self.scope)),
        };
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let ctx = RunContext {
            known: self
                .known()
                .into_iter()
                .filter(|ip| scope.contains(*ip))
                .collect(),
            scope,
            narrowed,
            pacer: Arc::clone(&self.pacer),
            cancel: Cancel::new(cancel_rx),
        };
        {
            let mut inner = self.lock();
            inner.running.insert(kind);
            inner.states.insert(kind, MethodState::Running);
        }
        self.write_status();
        let (result, stopped) = self
            .drive(
                method,
                &ctx,
                &cancel_tx,
                &mut stop,
                cancel,
                respect_blackout,
            )
            .await;
        let finished_at = Timestamp::now();
        let mut record = RunRecord {
            started_at,
            finished_at,
            outcome: RunOutcome::Failed,
            sightings: 0,
            probes: 0,
            queued: false,
            on_demand,
            target: target_text,
            error: None,
            delivery_error: None,
            notes: Vec::new(),
            batches: 0,
        };
        match result {
            None => {
                record.outcome = RunOutcome::Cancelled;
                record.error = stopped.map(|reason| reason.text().to_owned());
            }
            Some(Err(error)) => {
                tracing::warn!(method = %kind, code = error.code(), "{}", error.detail());
                record.error = Some(error.to_string());
            }
            Some(Ok(output)) => {
                let covered = output.covered_all && !narrowed && stopped.is_none();
                let complete = covered && method.completes();
                record.outcome = if stopped.is_some() {
                    RunOutcome::Cancelled
                } else if covered {
                    RunOutcome::Complete
                } else {
                    RunOutcome::Partial
                };
                if let Some(reason) = stopped {
                    record.error = Some(reason.text().to_owned());
                }
                record.probes = output.probes;
                record.notes.clone_from(&output.notes);
                self.deliver(kind, output, complete, &mut record, run).await;
            }
        }
        {
            let mut inner = self.lock();
            inner.running.remove(&kind);
            inner.reported.insert(kind);
            inner.states.insert(kind, MethodState::Idle);
            inner.last.insert(kind, record.clone());
        }
        self.reported.notify_waiters();
        self.write_status();
        record
    }

    /// Runs `method` until it ends, or until the shutdown, the kill switch, a blackout
    /// window or its deadline stops it; a stopped method gets the grace time to hand back
    /// what it saw. `None` when it did not.
    async fn drive(
        &self,
        method: &dyn Method,
        ctx: &RunContext,
        cancel: &watch::Sender<bool>,
        stop: &mut watch::Receiver<bool>,
        mut cancelled: Option<watch::Receiver<bool>>,
        respect_blackout: bool,
    ) -> (Option<Result<MethodOutput, ScanError>>, Option<StopReason>) {
        let kind = method.kind();
        let deadline = Instant::now() + method.deadline();
        let blackout_at = if respect_blackout && kind.sends_packets() {
            self.blackout.next_start(SystemTime::now()).map(|start| {
                Instant::now()
                    + start
                        .duration_since(SystemTime::now())
                        .unwrap_or(Duration::ZERO)
            })
        } else {
            None
        };
        let mut kill = self.kill.subscribe();
        let run = method.run(ctx);
        tokio::pin!(run);
        let mut stopped: Option<StopReason> = None;
        let mut grace = Instant::now();
        let result = loop {
            tokio::select! {
                result = &mut run => break Some(result),
                reason = stop_reason(stop, &mut kill, cancelled.as_mut(), deadline, blackout_at), if stopped.is_none() => {
                    tracing::info!(method = %kind, "{}", reason.text());
                    stopped = Some(reason);
                    let _ = cancel.send(true);
                    grace = Instant::now() + self.timing.grace;
                }
                () = sleep_until(grace), if stopped.is_some() => break None,
            }
        };
        (result, stopped)
    }

    /// Builds the batch of a run, queues it and records the presence sightings.
    async fn deliver(
        &self,
        kind: MethodKind,
        output: MethodOutput,
        complete: bool,
        record: &mut RunRecord,
        run: Option<Uuid>,
    ) {
        let ttl = self.config.schedule(kind).ttl;
        let (batch, truncated) = build_batch(kind, output, complete, self.vrf, ttl);
        let complete = batch.complete;
        if truncated {
            record.outcome = RunOutcome::Partial;
            record
                .notes
                .push(format!("the batch was cut to {MAX_SIGHTINGS} sightings"));
        }
        record.sightings = batch.sightings.len();
        if batch.sightings.is_empty() && !complete {
            // Nothing seen and nothing to expire.
            return;
        }
        let until = Timestamp::now()
            .checked_add(ttl)
            .unwrap_or_else(Timestamp::now);
        let subjects: Vec<_> = batch.sightings.iter().map(|s| s.subject.clone()).collect();
        match self.sink.deliver(batch, run).await {
            Ok(batches) => record.batches = batches,
            Err(error) => {
                tracing::warn!(method = %kind, code = error.code(), "the batch could not be queued: {}", error.detail());
                record.delivery_error = Some(error.to_string());
                return;
            }
        }
        record.queued = true;
        let snapshot = {
            let mut inner = self.lock();
            inner.known.record(kind, &subjects, complete, until);
            inner.known.prune(Timestamp::now());
            inner.known.clone()
        };
        if self.mode == Mode::Service
            && let Err(error) = snapshot.save(&self.paths.known())
        {
            tracing::debug!(%error, "the known addresses could not be saved");
        }
    }

    /// The status as `tenko node scan status` shows it.
    pub fn status(&self) -> ScanStatus {
        let now = SystemTime::now();
        let inner = self.lock();
        let methods = self
            .methods
            .iter()
            .map(|method| {
                let kind = method.kind();
                let schedule = self.config.schedule(kind);
                let held = self.hold(kind, method.as_ref());
                let state = inner
                    .states
                    .get(&kind)
                    .copied()
                    .or_else(|| held.as_ref().map(|(state, _)| *state))
                    .unwrap_or(MethodState::Idle);
                MethodStatus {
                    method: kind,
                    enabled: schedule.enabled,
                    availability: method.availability(),
                    state,
                    interval_secs: schedule.interval.as_secs(),
                    ttl_secs: schedule.ttl.as_secs(),
                    next_run: if held.is_none() {
                        inner.next.get(&kind).copied()
                    } else {
                        None
                    },
                    last_run: inner.last.get(&kind).cloned(),
                }
            })
            .collect();
        ScanStatus {
            updated_at: Timestamp::now(),
            pid: std::process::id(),
            kill_switch: *self.kill.borrow() || self.paths.killed(),
            prefixes: self
                .scope
                .prefixes()
                .iter()
                .map(ToString::to_string)
                .collect(),
            exclude: self
                .scope
                .exclusions()
                .iter()
                .map(ToString::to_string)
                .collect(),
            active: self.config.active,
            per_second: self.pacer.limits().per_second,
            blackout: self.blackout.windows().to_vec(),
            timezone: self.blackout.zone_name(),
            blackout_until: self
                .blackout
                .active_until(now)
                .map(|until| Timestamp::from(time::OffsetDateTime::from(until))),
            capabilities: self.capabilities.clone(),
            known_addresses: inner.known.current(Timestamp::now()).len(),
            methods,
        }
    }

    fn write_status(&self) {
        if self.mode != Mode::Service {
            return;
        }
        let status = self.status();
        match serde_json::to_vec_pretty(&status) {
            Ok(bytes) => {
                if let Err(error) = crate::status::write_atomically(&self.paths.status(), &bytes) {
                    tracing::debug!(%error, "the scan status could not be written");
                }
            }
            Err(error) => tracing::debug!(%error, "the scan status could not be encoded"),
        }
    }
}

async fn stop_reason(
    stop: &mut watch::Receiver<bool>,
    kill: &mut watch::Receiver<bool>,
    cancelled: Option<&mut watch::Receiver<bool>>,
    deadline: Instant,
    blackout_at: Option<Instant>,
) -> StopReason {
    let cancel = async {
        match cancelled {
            Some(cancelled) => {
                if cancelled.wait_for(|cancelled| *cancelled).await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending::<()>().await,
        }
    };
    let blackout = async {
        match blackout_at {
            Some(at) => sleep_until(at).await,
            None => std::future::pending::<()>().await,
        }
    };
    let killed = async {
        if kill.wait_for(|killed| *killed).await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    let stopped = async {
        if stop.wait_for(|stopped| *stopped).await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        () = stopped => StopReason::Shutdown,
        () = killed => StopReason::KillSwitch,
        () = blackout => StopReason::Blackout,
        () = sleep_until(deadline) => StopReason::Deadline,
        () = cancel => StopReason::Cancelled,
    }
}

/// How one run is asked for.
#[derive(Debug, Clone)]
struct Request {
    target: Option<Scope>,
    target_text: Option<String>,
    on_demand: bool,
    respect_blackout: bool,
    run: Option<Uuid>,
}

/// `interval` moved by up to a tenth either way, so that probes started together drift
/// apart.
fn jitter(interval: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(0);
    let random = hasher.finish() % 2001;
    // A factor from 0.9 to 1.1 in steps of 0.0001.
    let factor = 0.9 + f64::from(u32::try_from(random).unwrap_or(1000)) / 10_000.0;
    interval.mul_f64(factor)
}

/// The batch of a run: sightings without duplicates, each living `ttl`, at most
/// [`MAX_SIGHTINGS`] of them; and whether it had to be cut (then it is not complete).
pub fn build_batch(
    kind: MethodKind,
    output: MethodOutput,
    complete: bool,
    vrf: Option<VrfId>,
    ttl: Duration,
) -> (ProbeBatch, bool) {
    let ttl_secs = u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX);
    let mut seen = HashSet::new();
    let mut sightings = Vec::new();
    let mut found = output.found;
    // The latest sighting of a subject wins.
    found.sort_by_key(|item| std::cmp::Reverse(item.at));
    for item in found {
        let key = serde_json::to_string(&item.subject).unwrap_or_default();
        if !seen.insert(key) {
            continue;
        }
        sightings.push(Sighting {
            observed_at: item.at,
            ttl_secs: Some(ttl_secs),
            subject: item.subject,
        });
    }
    sightings.reverse();
    let truncated = sightings.len() > MAX_SIGHTINGS;
    sightings.truncate(MAX_SIGHTINGS);
    (
        ProbeBatch {
            method: kind.probe_method(),
            vrf,
            complete: complete && !truncated,
            collected_at: Timestamp::now(),
            sightings,
        },
        truncated,
    )
}
