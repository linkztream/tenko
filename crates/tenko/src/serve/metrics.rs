//! Metrics of the controller (OPS-05, OPS-20, OPS-21): the gauges read from status
//! interfaces on a timer, and the optional loopback listener of `[metrics] listen`.
//!
//! Every `[metrics] gauge_interval_secs` (default 30 s, first at start) the timer sets the
//! gauges of the API state (`tenko_api::routes::metrics::refresh_gauges`: the event hub,
//! the store revision, journal and data, the certificate expiry) and those of this module
//! from the status interfaces of the services: the store files, the state file ratio and
//! the coalescer queue, the Raft role, term and lag per member, the jobs that are not
//! finished, the connector health, the connected nodes and their buffers, the leader
//! services, the KEK protection, the audit export lag and the backup age. A scrape reads
//! the values the timer left; it computes nothing again but the uptime.
//!
//! Label values known only at run time (member and node ids, connector instance ids, sink
//! names, service names) take slots of bounded families; a value that is not seen in a
//! round frees its slot. A source that cannot be read in a round keeps its last values.
//!
//! `[metrics] listen` (a loopback address, checked by the configuration) serves the same
//! text in plain HTTP without authentication; it starts in the `api` step and stops with
//! the server.
//!
//! The publisher of the `metrics` topic of the event stream
//! ([`tenko_api::sse::metrics::MetricsPublisher`]) starts next to the timer. While a client
//! listens it takes a sample every second, and before each one it refreshes the gauges that
//! read memory only ([`refresh_live`]: the event hub and the store status, Raft, the store
//! files, the jobs and the connected nodes); the other gauges keep the timer's values.

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use futures::future::BoxFuture;
use tenko_api::{
    dto::system::{LeaderServiceState, LeaderStatus},
    routes::{backup::BackupService, system::LeaderSource},
    sse::metrics::{MetricsPublisher, PeerLayer, PeerSamples, SampleSources, Sampler},
    state::AppState,
};
use tenko_cluster::{peers::Peers, registry::NodeRegistry, session::Sessions};
use tenko_connect::{Health, host::ConnectorHost};
use tenko_core::{
    NodeId, Timestamp,
    metrics::{Collect, Desc, Gauge, GaugeVec, Registry},
};
use tenko_jobs::{JobEngine, JobQuery, JobState};
use tenko_store::{ReadConsistency, ReadViewExt as _, Store, StoreRole, StoreStatus, tables};
use tenko_vault::distribution::KekAdmin;
use tokio::{sync::watch, task::JoinHandle};

/// Members of the controller cluster with a lag series (Raft allows at most nine voters
/// in this product's sizing).
const MEMBER_SLOTS: u16 = 9;
/// Connector instances with health series (four series each).
const INSTANCE_SLOTS: u16 = 64;
/// Audit export sinks with a lag series.
const SINK_SLOTS: u16 = 8;
/// Leader services with state series (four series each).
const SERVICE_SLOTS: u16 = 32;
/// Connected nodes with a buffer series.
const NODE_SLOTS: u16 = 256;
/// Key-encryption key providers (one at a time).
const PROVIDER_SLOTS: u16 = 4;

/// The values of `tenko_connector_health{health}`.
const HEALTH_LABELS: [&str; 4] = ["healthy", "degraded", "unreachable", "unknown"];
/// The values of `tenko_leader_service{state}`.
const SERVICE_STATES: [&str; 4] = ["idle", "running", "restarting", "finished"];
/// The job states that are gauged: those of jobs that are not finished.
const JOB_STATES: [JobState; 4] = [
    JobState::Queued,
    JobState::Running,
    JobState::Waiting,
    JobState::RollingBack,
];

static STORE_FILE_BYTES: GaugeVec = GaugeVec::fixed(
    Desc::gauge(
        "tenko_store_file_bytes",
        "Bytes on disk of the store by file: the Raft log, the state file and the snapshots.",
    )
    .labels(&["file"])
    .unit("bytes"),
    &[&["log"], &["state"], &["snapshots"]],
);
static STORE_STATE_RATIO: Gauge = Gauge::new(
    Desc::gauge(
        "tenko_store_state_file_ratio",
        "The state file over the live data; a re-seed is due when it stays above about 2 (ADR 0002).",
    )
    .unit("ratio"),
);
static STORE_COALESCER: Gauge = Gauge::new(Desc::gauge(
    "tenko_store_coalescer_queue_batches",
    "Write batches waiting in the coalescer for a Raft entry.",
));
static RAFT_ROLE: GaugeVec = GaugeVec::fixed(
    Desc::gauge(
        "tenko_raft_role",
        "The Raft role of this member: 1 for the current role, 0 for the others.",
    )
    .labels(&["role"]),
    &[
        &["leader"],
        &["follower"],
        &["learner"],
        &["candidate"],
        &["shutdown"],
        &["memory"],
    ],
);
static RAFT_TERM: Gauge = Gauge::new(Desc::gauge(
    "tenko_raft_term",
    "The Raft term this member knows.",
));
static RAFT_LAG: GaugeVec = GaugeVec::new(
    Desc::gauge(
        "tenko_raft_lag_entries",
        "Log entries a member is behind the leader: every member on the leader, this member on a follower.",
    )
    .labels(&["node"]),
);
static JOBS: GaugeVec = GaugeVec::fixed(
    Desc::gauge("tenko_jobs", "Jobs that are not finished, by state.").labels(&["state"]),
    &[&["queued"], &["running"], &["waiting"], &["rolling_back"]],
);
static CONNECTOR_HEALTH: GaugeVec = GaugeVec::new(
    Desc::gauge(
        "tenko_connector_health",
        "The health of the remote system of each connector instance: 1 for the current health, 0 for the others.",
    )
    .labels(&["instance", "health"]),
);
static NODES_CONNECTED: Gauge = Gauge::new(Desc::gauge(
    "tenko_nodes_connected",
    "Nodes connected to this controller.",
));
static NODE_BUFFER: GaugeVec = GaugeVec::new(
    Desc::gauge(
        "tenko_node_buffer_batches",
        "Observation batches waiting in the disk buffer of each connected node.",
    )
    .labels(&["node"]),
);
static LEADER_SERVICE: GaugeVec = GaugeVec::new(
    Desc::gauge(
        "tenko_leader_service",
        "The leader-only services of this controller: 1 for the current state, 0 for the others.",
    )
    .labels(&["service", "state"]),
);
static KEK_PROTECTION: GaugeVec = GaugeVec::new(
    Desc::gauge(
        "tenko_kek_protection",
        "The protection of the active key-encryption key: 0 memory, 1 a plain file, 2 DPAPI machine scope or systemd-creds with the host key, 3 DPAPI user scope or systemd-creds with a TPM2.",
    )
    .labels(&["provider"]),
);
static AUDIT_EXPORT_LAG: GaugeVec = GaugeVec::new(
    Desc::gauge(
        "tenko_audit_export_lag_seconds",
        "Age of the oldest audit record an enabled sink has not received; 0 when it is current.",
    )
    .labels(&["sink"])
    .unit("seconds"),
);
static BACKUP_AGE: Gauge = Gauge::new(
    Desc::gauge(
        "tenko_backup_age_seconds",
        "Seconds since the last good backup.",
    )
    .unit("seconds"),
);

/// The status interfaces the timer reads. Only the API state is required; a missing
/// source leaves its gauges out.
#[derive(Clone)]
pub(crate) struct Sources {
    /// The API state: its registry, store, event hub and listener.
    pub(crate) state: AppState,
    /// The Raft store: file sizes and the coalescer queue.
    pub(crate) store: Option<tenko_store::raft::RaftStore>,
    /// The job engine.
    pub(crate) engine: Option<JobEngine>,
    /// The connector host.
    pub(crate) connectors: Option<Arc<ConnectorHost>>,
    /// The node sessions of this controller.
    pub(crate) sessions: Option<Arc<Sessions>>,
    /// The leader supervisor's view.
    pub(crate) leader: Option<LeaderSource>,
    /// The key-encryption key service.
    pub(crate) kek: Option<Arc<KekAdmin>>,
    /// The backup service.
    pub(crate) backups: Option<Arc<dyn BackupService>>,
    /// The peer layer: the other controllers whose samples the `metrics` topic shows.
    pub(crate) peers: Option<Peers>,
    /// The node registry, which answers `Metrics.Snapshot` from this controller's samples.
    pub(crate) node_registry: Option<Arc<NodeRegistry>>,
}

impl Sources {
    /// Sources with the API state only.
    pub(crate) fn of(state: AppState) -> Self {
        Self {
            state,
            store: None,
            engine: None,
            connectors: None,
            sessions: None,
            leader: None,
            kek: None,
            backups: None,
            peers: None,
            node_registry: None,
        }
    }
}

/// Seals the gauge families of this module and registers them with `registry`.
pub(crate) fn register(registry: &Registry) {
    RAFT_LAG.seal_slots(MEMBER_SLOTS);
    CONNECTOR_HEALTH.seal_slots(INSTANCE_SLOTS * 4);
    NODE_BUFFER.seal_slots(NODE_SLOTS);
    LEADER_SERVICE.seal_slots(SERVICE_SLOTS * 4);
    KEK_PROTECTION.seal_slots(PROVIDER_SLOTS);
    AUDIT_EXPORT_LAG.seal_slots(SINK_SLOTS);
    for family in [
        &STORE_FILE_BYTES as &'static dyn Collect,
        &STORE_STATE_RATIO,
        &STORE_COALESCER,
        &RAFT_ROLE,
        &RAFT_TERM,
        &RAFT_LAG,
        &JOBS,
        &CONNECTOR_HEALTH,
        &NODES_CONNECTED,
        &NODE_BUFFER,
        &LEADER_SERVICE,
        &KEK_PROTECTION,
        &AUDIT_EXPORT_LAG,
        &BACKUP_AGE,
        // Observed by the store and the reconciler (the samples of the `metrics` topic).
        &tenko_store::raft::COMMIT_DURATION,
        &tenko_ipam::reconcile::INGEST_BATCHES,
        &tenko_ipam::reconcile::INGEST_FACTS,
    ] {
        registry.register(family);
    }
}

/// The sources of the samples of the `metrics` topic: the gauges that read memory only, and
/// the drops the node sessions report.
struct LiveSources(Sources);

impl SampleSources for LiveSources {
    fn refresh(&self) -> BoxFuture<'_, ()> {
        Box::pin(refresh_live(&self.0))
    }

    fn node_drops(&self) -> BTreeMap<NodeId, u64> {
        self.0
            .sessions
            .as_ref()
            .map(|sessions| {
                sessions
                    .connected()
                    .into_iter()
                    .map(|(node, view)| (node, view.dropped_batches))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Registers the gauges, starts the timer, the publisher of the `metrics` topic and, when
/// `listen` is set, the loopback listener. Returns the tasks (they end when `stop` turns
/// true) and a summary for the start log.
///
/// # Errors
///
/// The listener's bind error.
pub(crate) async fn start(
    sources: Sources,
    interval: Duration,
    listen: Option<SocketAddr>,
    stop: &watch::Receiver<bool>,
) -> std::io::Result<(Vec<JoinHandle<()>>, String)> {
    register(sources.state.metrics());
    let state = sources.state.clone();
    let sampler = Sampler::new(state.clone(), Arc::new(LiveSources(sources.clone())));
    if let Some(registry) = &sources.node_registry {
        registry.set_metrics_source(Arc::new(sampler.clone()));
    }
    let peers = sources
        .peers
        .clone()
        .map(|peers| Arc::new(PeerLayer(peers)) as Arc<dyn PeerSamples>);
    let publisher = Arc::new(MetricsPublisher::new(&state, sampler, peers));
    let mut tasks = vec![
        spawn_timer(sources, interval, stop.clone()),
        publisher.spawn(stop.clone()),
    ];
    let summary = match listen {
        Some(addr) => {
            let (local, task) = listen_plain(addr, state, stop.clone()).await?;
            tasks.push(task);
            format!(
                "gauges every {} s, metrics listener on http://{local}/metrics",
                interval.as_secs()
            )
        }
        None => format!("gauges every {} s", interval.as_secs()),
    };
    Ok((tasks, summary))
}

/// The timer: refreshes the gauges at once and then every `interval` until `stop`.
fn spawn_timer(
    sources: Sources,
    interval: Duration,
    mut stop: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return;
                    }
                    continue;
                }
                _ = tick.tick() => {}
            }
            refresh(&sources, Timestamp::now()).await;
        }
    })
}

/// Binds `addr` and serves the metrics text there without authentication until `stop`
/// turns true. Logs one line with the bound address.
///
/// # Errors
///
/// The bind error.
pub(crate) async fn listen_plain(
    addr: SocketAddr,
    state: AppState,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{addr} is not a loopback address; the metrics listener has no authentication"),
        ));
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tracing::info!(
        %local,
        "metrics listener on http://{local}/metrics: plain HTTP without authentication, loopback only"
    );
    let task = tokio::spawn(async move {
        let shutdown = async move {
            while !*stop.borrow() {
                if stop.changed().await.is_err() {
                    break;
                }
            }
        };
        if let Err(error) = tenko_api::routes::metrics::serve_plain(listener, state, shutdown).await
        {
            tracing::warn!(%error, "the metrics listener stopped");
        }
    });
    Ok((local, task))
}

/// Sets every gauge from its source once.
pub(crate) async fn refresh(sources: &Sources, now: Timestamp) {
    let state = &sources.state;
    tenko_api::routes::metrics::refresh_gauges(state, now);
    refresh_sources(sources).await;
    if let Some(host) = &sources.connectors {
        connectors(host).await;
    }
    if let Some(leader) = &sources.leader {
        leader_services(&leader.current());
    }
    if let Some(kek) = &sources.kek {
        kek_protection(kek).await;
    }
    audit_export(state.store.as_ref(), now).await;
    if let Some(backups) = &sources.backups {
        backup_age(backups.as_ref()).await;
    }
}

/// Sets the gauges that read memory only (and the jobs from their state index): those the
/// samples of the `metrics` topic read.
pub(crate) async fn refresh_live(sources: &Sources) {
    tenko_api::routes::metrics::refresh_live_gauges(&sources.state);
    refresh_sources(sources).await;
}

/// One round of the slot families at a time: the timer and the publisher of the `metrics`
/// topic both set them, and a sweep between another round's sets would drop a series.
static ROUND: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The Raft status, the store files, the jobs and the connected nodes.
async fn refresh_sources(sources: &Sources) {
    let _round = ROUND.lock().await;
    raft(&sources.state.store.status());
    if let Some(store) = &sources.store {
        store_files(store);
    }
    if let Some(engine) = &sources.engine {
        jobs(engine).await;
    }
    if let Some(sessions) = &sources.sessions {
        nodes(sessions);
    }
}

/// A count or size as a gauge value.
#[allow(clippy::cast_precision_loss)]
fn value(count: u64) -> f64 {
    count as f64
}

fn usize_value(count: usize) -> f64 {
    value(u64::try_from(count).unwrap_or(u64::MAX))
}

fn raft(status: &StoreStatus) {
    let role = match status.role {
        StoreRole::Leader => 0,
        StoreRole::Follower => 1,
        StoreRole::Learner => 2,
        StoreRole::Candidate => 3,
        StoreRole::Shutdown => 4,
        StoreRole::Memory => 5,
    };
    RAFT_ROLE.set_one_of(0..6, role);
    RAFT_TERM.set(value(status.term));
    if status.members.is_empty() {
        if let (Some(node), Some(lag)) = (status.node, status.lag) {
            RAFT_LAG.set_labels(&[&node.to_string()], value(lag));
        }
    } else {
        for member in &status.members {
            if let Some(lag) = member.lag_entries {
                RAFT_LAG.set_labels(&[&member.node.to_string()], value(lag));
            }
        }
    }
    RAFT_LAG.sweep();
}

fn store_files(store: &tenko_store::raft::RaftStore) {
    let usage = store.disk_usage();
    STORE_FILE_BYTES.set(0, value(usage.log_bytes));
    STORE_FILE_BYTES.set(1, value(usage.state_bytes));
    STORE_FILE_BYTES.set(2, value(usage.snapshot_bytes));
    match usage.state_ratio {
        Some(ratio) => STORE_STATE_RATIO.set(ratio),
        None => STORE_STATE_RATIO.unset(),
    }
    STORE_COALESCER.set(usize_value(store.coalescer_queue_depth()));
}

async fn jobs(engine: &JobEngine) {
    for (series, state) in (0_u16..).zip(JOB_STATES) {
        let mut count = 0_usize;
        let mut cursor = None;
        loop {
            let query = JobQuery {
                states: vec![state],
                limit: tenko_jobs::query::MAX_LIMIT,
                cursor,
                ..JobQuery::default()
            };
            let Ok(page) = engine.list(&query).await else {
                return;
            };
            count += page.items.len();
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        JOBS.set(series, usize_value(count));
    }
}

async fn connectors(host: &ConnectorHost) {
    let Ok(views) = host.list(None).await else {
        return;
    };
    for view in views.iter().take(usize::from(INSTANCE_SLOTS)) {
        let id = view.instance.id.to_string();
        let current = match view.health.remote.as_ref().map(|report| report.health) {
            Some(Health::Healthy) => 0,
            Some(Health::Degraded) => 1,
            Some(Health::Unreachable) => 2,
            None => 3,
        };
        for (index, health) in HEALTH_LABELS.iter().enumerate() {
            let on = if index == current { 1.0 } else { 0.0 };
            CONNECTOR_HEALTH.set_labels(&[&id, health], on);
        }
    }
    CONNECTOR_HEALTH.sweep();
}

fn nodes(sessions: &Sessions) {
    let connected = sessions.connected();
    NODES_CONNECTED.set(usize_value(connected.len()));
    for (node, connection) in &connected {
        NODE_BUFFER.set_labels(&[&node.to_string()], value(connection.buffered_batches));
    }
    NODE_BUFFER.sweep();
}

fn leader_services(status: &LeaderStatus) {
    for service in status.services.iter().take(usize::from(SERVICE_SLOTS)) {
        let current = match service.state {
            LeaderServiceState::Idle => 0,
            LeaderServiceState::Running => 1,
            LeaderServiceState::Restarting => 2,
            LeaderServiceState::Finished => 3,
        };
        for (index, state) in SERVICE_STATES.iter().enumerate() {
            let on = if index == current { 1.0 } else { 0.0 };
            LEADER_SERVICE.set_labels(&[&service.name, state], on);
        }
    }
    LEADER_SERVICE.sweep();
}

async fn kek_protection(kek: &KekAdmin) {
    if kek.summary().is_none() {
        // The first status read fills the summary that later rounds read without I/O.
        let _ = kek.status().await;
    }
    if let Some(summary) = kek.summary() {
        KEK_PROTECTION.set_labels(&[&summary.provider], f64::from(summary.protection.rank()));
        KEK_PROTECTION.sweep();
    }
}

async fn audit_export(store: &dyn Store, now: Timestamp) {
    let Ok(view) = store.read(ReadConsistency::Local).await else {
        return;
    };
    let Ok(export) = tenko_auth::audit_export::status::read_view(view.as_ref(), now) else {
        return;
    };
    for sink in export
        .sinks
        .iter()
        .filter(|sink| sink.sink.enabled)
        .take(usize::from(SINK_SLOTS))
    {
        let seconds = if sink.status.lag == 0 {
            Some(0)
        } else {
            let oldest = sink.status.delivered.seq.next();
            match view.get_typed(&tables::AUDIT, &oldest) {
                Ok(Some((record, _))) => Some((now.0 - record.at.0).whole_seconds().max(0)),
                _ => None,
            }
        };
        if let Some(seconds) = seconds {
            AUDIT_EXPORT_LAG.set_labels(
                &[&sink.sink.name],
                value(u64::try_from(seconds).unwrap_or_default()),
            );
        }
    }
    AUDIT_EXPORT_LAG.sweep();
}

async fn backup_age(backups: &dyn BackupService) {
    let (summary, _) = backups.summary().await;
    match summary.and_then(|summary| summary.age_seconds) {
        Some(age) => BACKUP_AGE.set(value(age)),
        None => BACKUP_AGE.unset(),
    }
}

#[cfg(test)]
mod tests {
    use tenko_api::dto::system::LeaderServiceStatus;

    use super::*;

    fn render(state: &AppState) -> String {
        tenko_api::routes::metrics::render_metrics(state)
    }

    #[tokio::test]
    async fn a_refresh_sets_the_gauges_of_the_sources_it_has() {
        let state = AppState::default();
        register(state.metrics());
        let mut sources = Sources::of(state.clone());
        sources.leader = Some(LeaderSource::new(|| LeaderStatus {
            leads: true,
            epoch: Some(3),
            since: None,
            services: vec![LeaderServiceStatus {
                name: "jobs.runner".to_owned(),
                state: LeaderServiceState::Running,
                restarts: 0,
                last_error: None,
                since: None,
            }],
            clock_skew_ms: None,
        }));
        let before = render(&state);
        assert!(!before.contains("\ntenko_raft_term "), "{before}");
        refresh(&sources, Timestamp::now()).await;
        let text = render(&state);
        tenko_core::metrics::check(&text).unwrap_or_else(|error| panic!("{error}\n{text}"));
        for line in [
            "tenko_raft_role{role=\"memory\"} 1\n",
            "tenko_raft_role{role=\"leader\"} 0\n",
            "\ntenko_raft_term 1\n",
            "\ntenko_store_revision 0\n",
            "\ntenko_sse_subscribers 0\n",
            "tenko_leader_service{service=\"jobs.runner\",state=\"running\"} 1\n",
            "tenko_leader_service{service=\"jobs.runner\",state=\"idle\"} 0\n",
            "# TYPE tenko_backup_age_seconds gauge\n",
            "# UNIT tenko_audit_export_lag_seconds seconds\n",
        ] {
            assert!(text.contains(line), "missing {line:?} in\n{text}");
        }
        // No backup service, no store files, no nodes: no samples, only the metadata.
        assert!(!text.contains("\ntenko_backup_age_seconds "));
        assert!(!text.contains("\ntenko_store_file_bytes{"));
        assert!(text.ends_with("# EOF\n"));
    }

    #[tokio::test]
    async fn a_raft_store_reports_its_role_files_and_coalescer_queue() {
        let store = tenko_store::raft::RaftStore::open_temp(
            tenko_store::raft::RaftStoreConfig::new(std::env::temp_dir()),
        )
        .await
        .expect("a store");
        let state = AppState::new(Arc::new(store.clone()));
        register(state.metrics());
        let mut sources = Sources::of(state.clone());
        sources.store = Some(store.clone());
        refresh(&sources, Timestamp::now()).await;
        let text = render(&state);
        tenko_core::metrics::check(&text).unwrap_or_else(|error| panic!("{error}\n{text}"));
        for line in [
            "tenko_raft_role{role=\"leader\"} 1\n",
            "tenko_raft_role{role=\"memory\"} 0\n",
            "\ntenko_store_coalescer_queue_batches 0\n",
            "\ntenko_store_file_bytes{file=\"log\"} ",
            "\ntenko_store_file_bytes{file=\"state\"} ",
            "# UNIT tenko_store_state_file_ratio ratio\n",
        ] {
            assert!(text.contains(line), "missing {line:?} in\n{text}");
        }
        assert_eq!(store.coalescer_queue_depth(), 0);
        store.shutdown().await.expect("closed");
        assert_eq!(store.coalescer_queue_depth(), 0);
    }

    #[tokio::test]
    async fn a_sample_refreshes_and_reads_the_live_gauges_of_the_store() {
        let store = tenko_store::raft::RaftStore::open_temp(
            tenko_store::raft::RaftStoreConfig::new(std::env::temp_dir()),
        )
        .await
        .expect("a store");
        let state = AppState::new(Arc::new(store.clone()));
        register(state.metrics());
        let mut sources = Sources::of(state.clone());
        sources.store = Some(store.clone());
        let sampler = Sampler::new(state.clone(), Arc::new(LiveSources(sources)));
        // No timer ran: the sample's own refresh sets the gauges it reads.
        let local = sampler.take().await;
        assert_eq!(local.sample.raft.role.as_deref(), Some("leader"));
        assert!(local.sample.raft.term >= 1);
        assert!(local.sample.store.file_bytes.is_some_and(|bytes| bytes > 0));
        let text = render(&state);
        for line in [
            "# TYPE tenko_store_commit_duration_seconds histogram\n",
            "# TYPE tenko_ipam_ingest_batches counter\n",
            "# TYPE tenko_ipam_ingest_facts counter\n",
        ] {
            assert!(text.contains(line), "missing {line:?} in\n{text}");
        }
        tenko_core::metrics::check(&text).unwrap_or_else(|error| panic!("{error}\n{text}"));
        store.shutdown().await.expect("closed");
    }

    #[tokio::test]
    async fn a_sample_has_the_dns_part_once_the_role_registers_its_families() {
        let state = AppState::default();
        register(state.metrics());
        let sampler = Sampler::new(
            state.clone(),
            Arc::new(LiveSources(Sources::of(state.clone()))),
        );
        assert_eq!(
            sampler.take().await.sample.dns,
            None,
            "no role, no DNS part"
        );

        // What the role's start step registers (crates/tenko/src/serve/dns.rs).
        tenko_dns::tls::register(state.metrics());
        tenko_dns::metrics::register(state.metrics());
        tenko_dns::querylog::register_metrics(state.metrics());
        let first = sampler.take().await;
        let dns = first.sample.dns.clone().expect("the role's families");
        assert_eq!(
            dns.connections,
            Some(tenko_api::dto::events::MetricsDnsConnections { dot: 0, doh: 0 })
        );
        tenko_dns::metrics::QUERY_COUNTER.add(
            tenko_dns::metrics::query_index(tenko_core::dns::QueryTransport::Dot, false, 3),
            5,
        );
        tenko_dns::metrics::CACHE_HIT_COUNTER.add(0, 3);
        tenko_dns::metrics::CACHE_MISS_COUNTER.add(0, 1);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let dns = sampler.take().await.sample.dns.clone().expect("dns");
        assert!(dns.queries_per_second > 0.0, "{dns:?}");
        assert!(
            dns.transports.dot > 0.0 && dns.rcodes.nxdomain > 0.0,
            "{dns:?}"
        );
        assert!((dns.queries_per_second - dns.transports.dot).abs() < 1e-6);
        assert_eq!(dns.cache.hit_ratio, Some(0.75));
    }

    #[tokio::test]
    async fn the_loopback_listener_serves_the_text_without_authentication() {
        let state = AppState::default();
        register(state.metrics());
        let (stop_tx, stop) = watch::channel(false);
        let (addr, task) = listen_plain("127.0.0.1:0".parse().expect("addr"), state, stop)
            .await
            .expect("bound");
        assert!(addr.ip().is_loopback());
        let response = reqwest::get(format!("http://{addr}/metrics"))
            .await
            .expect("an answer");
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some(tenko_api::routes::metrics::OPENMETRICS)
        );
        let text = response.text().await.expect("text");
        tenko_core::metrics::check(&text).unwrap_or_else(|error| panic!("{error}\n{text}"));
        assert!(text.contains("# TYPE tenko_http_requests counter\n"));
        assert!(text.contains("\ntenko_build_info 1\n"));
        assert!(text.ends_with("# EOF\n"));
        let other = reqwest::get(format!("http://{addr}/api/v1/metrics"))
            .await
            .expect("an answer");
        assert_eq!(other.status(), 404);
        stop_tx.send(true).expect("stop");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the listener stops")
            .expect("no panic");
    }

    #[tokio::test]
    async fn start_runs_the_timer_and_names_the_listener() {
        let state = AppState::default();
        let (stop_tx, stop) = watch::channel(false);
        let (tasks, summary) = start(
            Sources::of(state.clone()),
            Duration::from_secs(30),
            Some("127.0.0.1:0".parse().expect("addr")),
            &stop,
        )
        .await
        .expect("started");
        assert_eq!(tasks.len(), 3, "timer, publisher and listener");
        assert!(summary.starts_with("gauges every 30 s, metrics listener on http://127.0.0.1:"));
        // The first tick runs at once.
        tokio::time::timeout(Duration::from_secs(10), async {
            while !render(&state).contains("\ntenko_raft_term 1\n") {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the first refresh");
        stop_tx.send(true).expect("stop");
        for task in tasks {
            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("stops")
                .expect("no panic");
        }
    }
}
