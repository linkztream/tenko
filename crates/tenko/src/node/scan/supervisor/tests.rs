//! Tests of the scanner supervisor with a scripted method: configuration swaps, refused
//! configurations, and the commands of the controllers through the store as the probe role
//! in process receives them, the kill switch among them. Test data stays in the
//! documentation ranges.

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tenko_cluster::{
    node_sync::{
        commands::{self, CommandRecord, CommandState},
        payload::{CancelArgs, encode_args},
    },
    probe::SightingSubject,
};
use tenko_core::{NodeId, RequestCtx, SystemComponent};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_scan::{
    capability::{Capabilities, IcmpSupport},
    control::ScanControl,
    method::{Availability, Found, Method, MethodOutput, RunContext},
    scanner::{MemorySink, Timing},
};
use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

use super::*;

const NODE: NodeId = NodeId(1);

/// An ARP method that runs until it is cancelled or a minute passed, and reports one
/// address.
#[derive(Debug)]
struct Slow;

#[async_trait]
impl Method for Slow {
    fn kind(&self) -> MethodKind {
        MethodKind::Arp
    }

    fn availability(&self) -> Availability {
        Availability::Ready
    }

    fn deadline(&self) -> Duration {
        Duration::from_secs(120)
    }

    async fn run(&self, ctx: &RunContext) -> Result<tenko_scan::method::MethodOutput, ScanError> {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
            () = ctx.cancel.cancelled() => {}
        }
        Ok(MethodOutput {
            found: vec![Found::now(SightingSubject::Address {
                ip: "192.0.2.7".parse().expect("ip"),
                mac: None,
            })],
            covered_all: false,
            probes: 1,
            notes: Vec::new(),
        })
    }
}

#[derive(Default)]
struct Reports(Mutex<Vec<v1::ConfigReport>>);

impl ScopeReports for Reports {
    fn report(&self, report: v1::ConfigReport) {
        self.0.lock().expect("lock").push(report);
    }
}

impl Reports {
    fn last(&self) -> v1::ConfigReport {
        self.0
            .lock()
            .expect("lock")
            .last()
            .cloned()
            .expect("a report")
    }
}

fn config(prefix: &str) -> ScanConfig {
    ScanConfig {
        prefixes: vec![prefix.to_owned()],
        ..ScanConfig::default()
    }
}

fn supervisor(dir: &Path, sink: Arc<MemorySink>) -> (Arc<Supervisor>, Arc<Reports>) {
    let paths = ScanPaths::new(dir);
    let build: Build = Arc::new(move |config: &ScanConfig| {
        Scanner::with_methods(
            config.clone(),
            paths.clone(),
            Arc::clone(&sink) as Arc<dyn tenko_scan::scanner::BatchSink>,
            Capabilities {
                raw_sockets: false,
                raw_detail: "not needed".to_owned(),
                icmp: IcmpSupport::Unavailable,
            },
            vec![Arc::new(Slow) as Arc<dyn Method>],
            tenko_scan::scanner::Mode::Service,
            // No scheduled run within the test: only runs on demand.
            Timing::immediate(Duration::from_secs(3600)),
        )
    });
    let reports = Arc::new(Reports::default());
    let supervisor = Supervisor::new(dir, build, Arc::clone(&reports) as Arc<dyn ScopeReports>);
    (supervisor, reports)
}

#[tokio::test]
async fn a_new_configuration_replaces_the_scanner_and_a_bad_one_keeps_it() {
    let dir = tempfile::tempdir().expect("dir");
    let (supervisor, reports) = supervisor(dir.path(), Arc::new(MemorySink::default()));
    supervisor
        .apply(Desired::local(config("192.0.2.0/24")))
        .await;
    let first = supervisor.scanner().expect("a scanner");
    let report = reports.last();
    assert_eq!(report.source, "local");
    assert_eq!(report.revision, 0);
    assert_eq!(
        report.probe.as_ref().expect("scope").prefixes,
        ["192.0.2.0/24"]
    );

    // The same configuration from the controllers keeps the scanner and moves the revision.
    supervisor
        .apply(Desired::synced(config("192.0.2.0/24"), 7))
        .await;
    assert!(Arc::ptr_eq(&first, &supervisor.scanner().expect("scanner")));
    assert_eq!(
        (reports.last().source.as_str(), reports.last().revision),
        ("synced", 7)
    );

    // One that does not build keeps the running scanner and reports why.
    supervisor
        .apply(Desired::synced(config("not a prefix"), 8))
        .await;
    assert!(Arc::ptr_eq(&first, &supervisor.scanner().expect("scanner")));
    let report = reports.last();
    assert_eq!(report.revision, 7, "the revision in force stays");
    assert!(!report.error.is_empty(), "{report:?}");

    // One that cannot be read either.
    supervisor
        .apply(Desired::refused(
            9,
            "the scan configuration does not decode",
        ))
        .await;
    assert!(reports.last().error.contains("does not decode"));

    // A good one swaps the scanner.
    supervisor
        .apply(Desired::synced(config("198.51.100.0/24"), 10))
        .await;
    let second = supervisor.scanner().expect("scanner");
    assert!(!Arc::ptr_eq(&first, &second));
    let report = reports.last();
    assert_eq!(report.revision, 10);
    assert_eq!(report.error, "");
    assert_eq!(report.probe.expect("scope").prefixes, ["198.51.100.0/24"]);

    // Switched off: no scanner, the scope is empty.
    supervisor
        .apply(Desired::synced(
            ScanConfig {
                enabled: false,
                ..config("198.51.100.0/24")
            },
            11,
        ))
        .await;
    assert!(supervisor.scanner().is_none());
    assert_eq!(
        reports.last().probe.expect("scope").prefixes,
        Vec::<String>::new()
    );
}

/// The in-process probe of a controller over a store, with its commands followed.
struct Probe {
    store: Arc<dyn Store>,
    control: Arc<ScanControl>,
    supervisor: Arc<Supervisor>,
    sink: Arc<MemorySink>,
    stop: watch::Sender<bool>,
    dir: tempfile::TempDir,
}

impl Probe {
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
        let control = ScanControl::new(Arc::clone(&store), &engine, None, Some(NODE));
        let sink = Arc::new(MemorySink::default());
        let (supervisor, _) = supervisor(dir.path(), Arc::clone(&sink));
        supervisor
            .apply(Desired::local(config("192.0.2.0/24")))
            .await;
        let (stop, stopped) = watch::channel(false);
        tokio::spawn(commands::follow_local(
            Arc::clone(&store),
            NODE,
            Arc::new(ScanCommands(Arc::clone(&supervisor))),
            stopped,
        ));
        Self {
            store,
            control,
            supervisor,
            sink,
            stop,
            dir,
        }
    }

    async fn issue(&self, kind: &str, payload: Vec<u8>) -> Uuid {
        let record = CommandRecord::new(NODE, kind, payload, tenko_core::Timestamp::now());
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Scan));
        commands::stage_issue(&mut batch, &record).expect("staged");
        self.store.propose(batch).await.expect("issued");
        record.id
    }

    async fn state(&self, command: Uuid) -> CommandRecord {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        commands::get(view.as_ref(), NODE, command)
            .expect("read")
            .expect("the command")
            .0
    }

    async fn wait_for(
        &self,
        command: Uuid,
        done: impl Fn(&CommandRecord) -> bool,
    ) -> CommandRecord {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let record = self.state(command).await;
                if done(&record) {
                    return record;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the command moves on")
    }

    async fn run_arp(&self) -> Uuid {
        let args = ScanRunArgs {
            methods: vec!["arp".to_owned()],
            target: Some("192.0.2.0/28".to_owned()),
            ignore_blackout: false,
            deadline_secs: None,
        };
        let id = self
            .issue(SCAN_RUN, encode_args(&args).expect("args"))
            .await;
        self.wait_for(id, |record| record.state == CommandState::Running)
            .await;
        id
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

#[tokio::test]
async fn the_kill_switch_from_the_controllers_stops_a_running_scan_within_two_seconds() {
    let probe = Probe::start().await;
    let run = probe.run_arp().await;
    let cx = RequestCtx::system(SystemComponent::Api);
    let started = Instant::now();
    let switched = probe
        .control
        .stop(&cx, Some(NODE), Some("maintenance window"))
        .await
        .expect("stop");
    let finished = probe.wait_for(run, |record| record.state.is_final()).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "the scan stopped after {elapsed:?}"
    );
    assert_eq!(finished.state, CommandState::Done, "{finished:?}");
    assert_eq!(finished.batches, Some(1), "what it saw went out as a batch");
    assert!(
        finished
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("kill switch")),
        "{finished:?}"
    );
    let tagged = probe.sink.tagged();
    assert_eq!(tagged.len(), 1);
    assert_eq!(tagged[0].1, Some(run), "the batch carries the command id");
    let stop = probe
        .wait_for(switched.commands[0].command, |record| {
            record.state.is_final()
        })
        .await;
    assert_eq!(stop.state, CommandState::Done);
    assert!(ScanPaths::new(probe.dir.path()).killed());
    let view = probe.control.config(NODE).await.expect("config");
    assert!(
        view.kill_switch.stopped && view.kill_switch.confirmed,
        "{view:?}"
    );
    let report = probe.supervisor.report();
    let scope = report.probe.expect("scope");
    assert!(scope.stopped);
    assert_eq!(scope.stop_reason, "maintenance window");

    // While it is on, a scan on demand does not run.
    let refused = probe.run_arp_or_final().await;
    assert_eq!(refused.state, CommandState::Failed, "{refused:?}");

    let resumed = probe.control.resume(&cx, Some(NODE)).await.expect("resume");
    probe
        .wait_for(resumed.commands[0].command, |record| {
            record.state.is_final()
        })
        .await;
    assert!(!ScanPaths::new(probe.dir.path()).killed());
}

impl Probe {
    /// Issues an ARP run and waits until it is final (it may never run).
    async fn run_arp_or_final(&self) -> CommandRecord {
        let args = ScanRunArgs {
            methods: vec!["arp".to_owned()],
            target: None,
            ignore_blackout: false,
            deadline_secs: None,
        };
        let id = self
            .issue(SCAN_RUN, encode_args(&args).expect("args"))
            .await;
        self.wait_for(id, |record| record.state.is_final()).await
    }
}

#[tokio::test]
async fn a_cancelled_run_stops_and_unknown_commands_are_rejected() {
    let probe = Probe::start().await;
    let run = probe.run_arp().await;
    let cancel = probe
        .issue(
            SCAN_CANCEL,
            encode_args(&CancelArgs { command: run }).expect("args"),
        )
        .await;
    let cancelled = probe
        .wait_for(cancel, |record| record.state.is_final())
        .await;
    assert_eq!(cancelled.state, CommandState::Done);
    assert_eq!(cancelled.detail.as_deref(), Some("cancelled"));
    let finished = probe.wait_for(run, |record| record.state.is_final()).await;
    assert!(
        finished
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("cancelled")),
        "{finished:?}"
    );

    let unknown = probe.issue("scan.reboot", Vec::new()).await;
    let unknown = probe
        .wait_for(unknown, |record| record.state.is_final())
        .await;
    assert_eq!(unknown.state, CommandState::Rejected);
    let garbage = probe.issue(SCAN_RUN, vec![0xff]).await;
    let garbage = probe
        .wait_for(garbage, |record| record.state.is_final())
        .await;
    assert_eq!(garbage.state, CommandState::Rejected);

    // Switched off: a scan on demand is rejected.
    probe
        .supervisor
        .apply(Desired::local(ScanConfig {
            enabled: false,
            ..config("192.0.2.0/24")
        }))
        .await;
    let off = probe.run_arp_or_final().await;
    assert_eq!(off.state, CommandState::Rejected, "{off:?}");
}
