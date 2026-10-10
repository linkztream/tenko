//! The scheduler with scripted methods: schedules, complete and partial batches, the time a
//! sighting lives, known addresses, on-demand runs, the kill switch, blackout windows,
//! TGL-18 and deadlines. No method here touches a network.

use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tenko_cluster::probe::{ProbeBatch, SightingSubject};
use tenko_core::observe::ProbeMethod;
use tenko_scan::{
    ScanError,
    capability::{Capabilities, IcmpSupport},
    config::ScanConfig,
    method::{Availability, Found, Method, MethodKind, MethodOutput, RunContext},
    scanner::{MemorySink, Mode, RunRequest, Scanner, Timing, build_batch},
    status::{MethodState, RunOutcome, ScanPaths},
};
use tokio::sync::watch;

/// A method that reports a fixed set of sightings after a delay, or what it has when it
/// is stopped.
#[derive(Debug)]
struct Scripted {
    kind: MethodKind,
    found: Vec<SightingSubject>,
    delay: Duration,
    deadline: Duration,
    completes: bool,
    runs: AtomicUsize,
    known: Mutex<Vec<Vec<IpAddr>>>,
}

impl Scripted {
    fn new(kind: MethodKind, found: Vec<SightingSubject>) -> Arc<Self> {
        Self::slow(kind, found, Duration::ZERO)
    }

    fn slow(kind: MethodKind, found: Vec<SightingSubject>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            kind,
            found,
            delay,
            deadline: Duration::from_secs(3600),
            completes: true,
            runs: AtomicUsize::new(0),
            known: Mutex::new(Vec::new()),
        })
    }

    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Method for Scripted {
    fn kind(&self) -> MethodKind {
        self.kind
    }

    fn availability(&self) -> Availability {
        Availability::Ready
    }

    fn deadline(&self) -> Duration {
        self.deadline
    }

    fn completes(&self) -> bool {
        self.completes
    }

    async fn run(&self, ctx: &RunContext) -> Result<MethodOutput, ScanError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        self.known.lock().expect("lock").push(ctx.known.clone());
        let found: Vec<Found> = self
            .found
            .iter()
            .filter(|subject| match subject {
                SightingSubject::Address { ip, .. } | SightingSubject::Services { ip, .. } => {
                    ctx.scope.contains(*ip)
                }
                _ => true,
            })
            .cloned()
            .map(Found::now)
            .collect();
        tokio::select! {
            () = tokio::time::sleep(self.delay) => Ok(MethodOutput {
                found,
                covered_all: true,
                probes: 1,
                notes: Vec::new(),
            }),
            () = ctx.cancel.cancelled() => Ok(MethodOutput {
                found: found.into_iter().take(1).collect(),
                covered_all: false,
                probes: 1,
                notes: vec!["stopped early".to_owned()],
            }),
        }
    }
}

fn address(ip: &str, mac: &str) -> SightingSubject {
    SightingSubject::Address {
        ip: ip.parse().expect("ip"),
        mac: Some(mac.parse().expect("mac")),
    }
}

fn config() -> ScanConfig {
    ScanConfig {
        prefixes: vec!["192.0.2.0/24".to_owned(), "2001:db8::/64".to_owned()],
        ..ScanConfig::default()
    }
}

fn capabilities() -> Capabilities {
    Capabilities {
        raw_sockets: false,
        raw_detail: "CAP_NET_RAW is missing".to_owned(),
        icmp: IcmpSupport::PingCommand,
    }
}

struct Rig {
    scanner: Arc<Scanner>,
    sink: Arc<MemorySink>,
    paths: ScanPaths,
    _dir: tempfile::TempDir,
}

fn rig(config: ScanConfig, methods: Vec<Arc<dyn Method>>, timing: Timing) -> Rig {
    let dir = tempfile::tempdir().expect("dir");
    let paths = ScanPaths::new(dir.path());
    let sink = Arc::new(MemorySink::default());
    let scanner = Scanner::with_methods(
        config,
        paths.clone(),
        sink.clone(),
        capabilities(),
        methods,
        Mode::Service,
        timing,
    )
    .expect("scanner");
    Rig {
        scanner,
        sink,
        paths,
        _dir: dir,
    }
}

/// Waits until `check` holds, at most five seconds.
async fn until(what: &str, check: impl Fn() -> bool) {
    for _ in 0..500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn batches_of(sink: &MemorySink, method: ProbeMethod) -> Vec<ProbeBatch> {
    sink.batches()
        .into_iter()
        .filter(|batch| batch.method == method)
        .collect()
}

#[tokio::test]
async fn scheduled_runs_hand_complete_batches_that_live_three_intervals() {
    let arp = Scripted::new(
        MethodKind::Arp,
        vec![
            address("192.0.2.10", "00:00:5e:00:53:10"),
            address("198.51.100.10", "00:00:5e:00:53:11"),
        ],
    );
    let rig = rig(
        config(),
        vec![arp.clone()],
        Timing::immediate(Duration::from_millis(10)),
    );
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&rig.scanner).run(stopped));
    until("an ARP batch", || {
        !batches_of(&rig.sink, ProbeMethod::Arp).is_empty()
    })
    .await;
    let batch = batches_of(&rig.sink, ProbeMethod::Arp).remove(0);
    assert!(batch.complete);
    assert_eq!(
        batch.vrf, None,
        "the controller chooses the VRF of the enrolment"
    );
    assert_eq!(
        batch.sightings.len(),
        1,
        "198.51.100.10 is outside the scope"
    );
    assert_eq!(batch.sightings[0].ttl_secs, Some(900));
    until("the status file", || {
        rig.paths
            .read_status()
            .and_then(|status| {
                status
                    .method(MethodKind::Arp)
                    .and_then(|m| m.last_run.clone())
            })
            .is_some()
    })
    .await;
    let status = rig.paths.read_status().expect("status");
    assert_eq!(status.prefixes, ["192.0.2.0/24", "2001:db8::/64"]);
    assert_eq!(
        status
            .method(MethodKind::Arp)
            .and_then(|m| m.last_run.as_ref())
            .map(|r| r.outcome),
        Some(RunOutcome::Complete)
    );
    assert_eq!(status.known_addresses, 1);
    stop.send(true).expect("stop");
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stops")
        .expect("joins");
    assert_eq!(arp.runs(), 1, "the next run is five minutes away");
}

#[tokio::test]
async fn methods_on_known_addresses_wait_for_the_others() {
    let arp = Scripted::slow(
        MethodKind::Arp,
        vec![address("192.0.2.10", "00:00:5e:00:53:10")],
        Duration::from_millis(200),
    );
    let tcp = Scripted::new(
        MethodKind::TcpConnect,
        vec![SightingSubject::Services {
            ip: "192.0.2.10".parse().expect("ip"),
            open_tcp: vec![22],
            tls_tcp: Vec::new(),
        }],
    );
    let mut timing = Timing::immediate(Duration::from_millis(10));
    timing.addresses_wait = Duration::from_secs(30);
    let rig = rig(config(), vec![arp.clone(), tcp.clone()], timing);
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&rig.scanner).run(stopped));
    until("a TCP batch", || {
        !batches_of(&rig.sink, ProbeMethod::TcpConnect).is_empty()
    })
    .await;
    let seen = tcp.known.lock().expect("lock").clone();
    assert_eq!(seen[0], ["192.0.2.10".parse::<IpAddr>().expect("ip")]);
    stop.send(true).expect("stop");
    task.await.expect("joins");
    let known = std::fs::read_to_string(rig.paths.known()).expect("known addresses on disk");
    assert!(known.contains("192.0.2.10"), "{known}");
}

#[tokio::test]
async fn on_demand_runs_on_a_target_are_never_complete() {
    let arp = Scripted::new(
        MethodKind::Arp,
        vec![
            address("192.0.2.10", "00:00:5e:00:53:10"),
            address("192.0.2.20", "00:00:5e:00:53:20"),
        ],
    );
    let rig = rig(config(), vec![arp], Timing::default());
    let record = rig
        .scanner
        .run_now(
            MethodKind::Arp,
            &RunRequest {
                target: Some("192.0.2.10".to_owned()),
                ignore_blackout: false,
                run: None,
            },
        )
        .await
        .expect("run");
    assert_eq!(record.outcome, RunOutcome::Partial);
    assert!(record.on_demand);
    let batch = rig.sink.batches().remove(0);
    assert!(!batch.complete);
    assert_eq!(batch.sightings.len(), 1);
    let error = rig
        .scanner
        .run_now(
            MethodKind::Arp,
            &RunRequest {
                target: Some("198.51.100.0/24".to_owned()),
                ignore_blackout: false,
                run: None,
            },
        )
        .await
        .expect_err("outside");
    assert_eq!(error.code(), "scan.out_of_scope");
    let full = rig
        .scanner
        .run_now(MethodKind::Arp, &RunRequest::default())
        .await
        .expect("run");
    assert_eq!(full.outcome, RunOutcome::Complete);
    assert!(rig.sink.batches()[1].complete);
}

#[tokio::test]
async fn the_kill_switch_stops_a_running_scan_and_holds_the_next() {
    let icmp = Scripted::slow(
        MethodKind::Icmp,
        vec![
            address("192.0.2.10", "00:00:5e:00:53:10"),
            address("192.0.2.11", "00:00:5e:00:53:11"),
        ],
        Duration::from_secs(60),
    );
    let rig = rig(
        config(),
        vec![icmp.clone()],
        Timing::immediate(Duration::from_millis(10)),
    );
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&rig.scanner).run(stopped));
    until("the sweep to start", || icmp.runs() == 1).await;
    rig.paths.kill("test").expect("kill");
    until("the partial batch", || !rig.sink.batches().is_empty()).await;
    let batch = rig.sink.batches().remove(0);
    assert!(!batch.complete, "a stopped run is not complete");
    assert_eq!(batch.sightings.len(), 1, "what it saw before the stop");
    until("the stopped state", || {
        rig.paths
            .read_status()
            .and_then(|status| status.method(MethodKind::Icmp).map(|m| m.state))
            == Some(MethodState::Stopped)
    })
    .await;
    let status = rig.paths.read_status().expect("status");
    assert!(status.kill_switch);
    let last = status
        .method(MethodKind::Icmp)
        .and_then(|m| m.last_run.clone())
        .expect("last run");
    assert_eq!(last.outcome, RunOutcome::Cancelled);
    let refused = rig
        .scanner
        .run_now(MethodKind::Icmp, &RunRequest::default())
        .await
        .expect_err("killed");
    assert_eq!(refused.code(), "scan.stopped");
    assert_eq!(icmp.runs(), 1);
    rig.paths.resume().expect("resume");
    until("the next sweep", || icmp.runs() == 2).await;
    stop.send(true).expect("stop");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("stops")
        .expect("joins");
}

#[tokio::test]
async fn blackout_windows_hold_every_method_that_sends_packets() {
    let arp = Scripted::new(
        MethodKind::Arp,
        vec![address("192.0.2.10", "00:00:5e:00:53:10")],
    );
    let icmp = Scripted::new(
        MethodKind::Icmp,
        vec![address("192.0.2.10", "00:00:5e:00:53:10")],
    );
    let config = ScanConfig {
        blackout: vec!["daily 00:00-24:00".to_owned()],
        timezone: Some("UTC".to_owned()),
        ..config()
    };
    let rig = rig(
        config,
        vec![arp.clone(), icmp.clone()],
        Timing::immediate(Duration::from_millis(10)),
    );
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&rig.scanner).run(stopped));
    until("the ARP table read", || arp.runs() == 1).await;
    until("the blackout state", || {
        rig.paths
            .read_status()
            .and_then(|status| status.method(MethodKind::Icmp).map(|m| m.state))
            == Some(MethodState::Blackout)
    })
    .await;
    assert_eq!(icmp.runs(), 0);
    let status = rig.paths.read_status().expect("status");
    assert!(status.blackout_until.is_some());
    assert_eq!(status.timezone, "UTC");
    let refused = rig
        .scanner
        .run_now(MethodKind::Icmp, &RunRequest::default())
        .await
        .expect_err("blackout");
    assert_eq!(refused.code(), "scan.blackout");
    let forced = rig
        .scanner
        .run_now(
            MethodKind::Icmp,
            &RunRequest {
                target: None,
                ignore_blackout: true,
                run: None,
            },
        )
        .await
        .expect("forced");
    assert_eq!(forced.outcome, RunOutcome::Complete);
    stop.send(true).expect("stop");
    task.await.expect("joins");
}

#[tokio::test]
async fn active_probing_off_keeps_the_probe_passive() {
    let icmp = Scripted::new(MethodKind::Icmp, Vec::new());
    let snmp = Scripted::new(MethodKind::Snmp, Vec::new());
    let config = ScanConfig {
        active: false,
        ..config()
    };
    let rig = rig(config, vec![icmp.clone(), snmp], Timing::default());
    let refused = rig
        .scanner
        .run_now(MethodKind::Icmp, &RunRequest::default())
        .await
        .expect_err("passive");
    assert_eq!(refused.code(), "scan.disabled");
    let status = rig.scanner.status();
    assert_eq!(
        status.method(MethodKind::Icmp).map(|m| m.state),
        Some(MethodState::Disabled)
    );
    assert_eq!(
        status.method(MethodKind::Snmp).map(|m| m.state),
        Some(MethodState::Idle)
    );
    assert!(!status.active);
    assert_eq!(icmp.runs(), 0);
}

#[tokio::test]
async fn a_run_that_overstays_its_deadline_is_stopped() {
    let slow = Arc::new(Scripted {
        deadline: Duration::from_millis(100),
        ..Arc::try_unwrap(Scripted::slow(
            MethodKind::Mdns,
            vec![address("192.0.2.10", "00:00:5e:00:53:10")],
            Duration::from_secs(60),
        ))
        .expect("unique")
    });
    let rig = rig(config(), vec![slow], Timing::default());
    let record = rig
        .scanner
        .run_now(MethodKind::Mdns, &RunRequest::default())
        .await
        .expect("run");
    assert_eq!(record.outcome, RunOutcome::Cancelled);
    assert_eq!(record.error.as_deref(), Some("stopped at its deadline"));
    assert!(!rig.sink.batches()[0].complete);
}

#[test]
fn batches_drop_duplicate_subjects() {
    let at = |text: &str| text.parse().expect("time");
    let output = MethodOutput {
        found: vec![
            Found {
                at: at("2026-10-10T08:00:01Z"),
                subject: address("192.0.2.10", "00:00:5e:00:53:10"),
            },
            Found {
                at: at("2026-10-10T08:00:05Z"),
                subject: address("192.0.2.10", "00:00:5e:00:53:10"),
            },
            Found {
                at: at("2026-10-10T08:00:02Z"),
                subject: address("192.0.2.11", "00:00:5e:00:53:11"),
            },
        ],
        covered_all: true,
        probes: 3,
        notes: Vec::new(),
    };
    let (batch, truncated) = build_batch(
        MethodKind::Arp,
        output,
        true,
        None,
        Duration::from_secs(900),
    );
    assert!(!truncated);
    assert!(batch.complete);
    assert_eq!(batch.method, ProbeMethod::Arp);
    assert_eq!(batch.sightings.len(), 2);
    let latest = batch
        .sightings
        .iter()
        .find(|s| s.subject == address("192.0.2.10", "00:00:5e:00:53:10"))
        .expect("kept");
    assert_eq!(
        latest.observed_at,
        at("2026-10-10T08:00:05Z"),
        "the latest sighting wins"
    );
}

#[tokio::test]
async fn best_effort_methods_never_send_complete_batches() {
    let mdns = Arc::new(Scripted {
        completes: false,
        ..Arc::try_unwrap(Scripted::new(
            MethodKind::Mdns,
            vec![address("192.0.2.10", "00:00:5e:00:53:10")],
        ))
        .expect("unique")
    });
    let rig = rig(config(), vec![mdns], Timing::default());
    let record = rig
        .scanner
        .run_now(MethodKind::Mdns, &RunRequest::default())
        .await
        .expect("run");
    assert_eq!(
        record.outcome,
        RunOutcome::Complete,
        "it covered everything"
    );
    let batch = rig.sink.batches().remove(0);
    assert!(!batch.complete, "but its facts expire by their lifetime");
}

#[tokio::test]
async fn the_kill_switch_file_stops_an_on_demand_run_without_a_scheduler() {
    let slow = Scripted::slow(
        MethodKind::Arp,
        vec![address("192.0.2.10", "00:00:5e:00:53:10")],
        Duration::from_secs(60),
    );
    let dir = tempfile::tempdir().expect("dir");
    let paths = ScanPaths::new(dir.path());
    let sink = Arc::new(MemorySink::default());
    let scanner = Scanner::with_methods(
        config(),
        paths.clone(),
        sink.clone(),
        capabilities(),
        vec![slow.clone()],
        Mode::OneShot,
        Timing::immediate(Duration::from_millis(10)),
    )
    .expect("scanner");
    let killer = {
        let paths = paths.clone();
        let slow = Arc::clone(&slow);
        tokio::spawn(async move {
            until("the run to start", || slow.runs() == 1).await;
            paths.kill("test").expect("kill");
        })
    };
    let record = tokio::time::timeout(
        Duration::from_secs(10),
        scanner.run_now(MethodKind::Arp, &RunRequest::default()),
    )
    .await
    .expect("the run stops")
    .expect("run");
    killer.await.expect("killer");
    assert_eq!(record.outcome, RunOutcome::Cancelled);
    assert_eq!(record.error.as_deref(), Some("stopped by the kill switch"));
    assert!(record.queued, "what it saw went out, not complete");
    assert!(!sink.batches()[0].complete);
}

/// A sink whose buffer is full.
#[derive(Debug, Default)]
struct FullSink;

#[async_trait]
impl tenko_scan::scanner::BatchSink for FullSink {
    async fn deliver(
        &self,
        _batch: ProbeBatch,
        _run: Option<uuid::Uuid>,
    ) -> Result<u32, ScanError> {
        Err(ScanError::io("the buffer is full"))
    }
}

#[tokio::test]
async fn a_batch_that_cannot_be_queued_is_recorded() {
    let arp = Scripted::new(
        MethodKind::Arp,
        vec![address("192.0.2.10", "00:00:5e:00:53:10")],
    );
    let dir = tempfile::tempdir().expect("dir");
    let scanner = Scanner::with_methods(
        config(),
        ScanPaths::new(dir.path()),
        Arc::new(FullSink),
        capabilities(),
        vec![arp],
        Mode::OneShot,
        Timing::default(),
    )
    .expect("scanner");
    let record = scanner
        .run_now(MethodKind::Arp, &RunRequest::default())
        .await
        .expect("run");
    assert!(!record.queued);
    assert_eq!(
        record.delivery_error.as_deref(),
        Some("[scan.io] the buffer is full")
    );
    assert_eq!(
        scanner.known(),
        Vec::<IpAddr>::new(),
        "nothing was recorded as seen"
    );
}
