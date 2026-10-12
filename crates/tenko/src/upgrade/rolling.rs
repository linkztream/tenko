//! Rolling upgrades of a controller cluster (OPS-08, OPS-24, R26): the leader-gated format
//! migration and the format status every controller reports.
//!
//! A controller cluster is upgraded one member at a time (`docs/upgrades.md`, rolling
//! order). A member that starts with a binary of a newer data format does not migrate the
//! replicated data at start ([`super::datadir::finish_with`] with `defer`): the other
//! voters may still run a binary that cannot read the newer format. Instead
//!
//! * every member reports its binary in its member record after each start (version,
//!   protocol majors, Raft wire version, the formats it knows; `Peers::announce`);
//! * the leader runs the leader service [`SERVICE_NAME`] ([`Migrator`]): every
//!   [`CHECK_INTERVAL`] it compares the stored format with the newest format of its own
//!   binary and runs the migrations once every voter's binary knows that format, each
//!   batch fenced with the leader epoch, so a deposed leader cannot migrate twice;
//! * every member runs [`Follower`]: it moves its local format marker after a migration
//!   the leader committed and keeps the [`DataFormatStatus`] that `GET /system/status`
//!   shows, with the voters that block a pending migration.
//!
//! A voter without a member record, or one whose record names no formats and an older
//! data format, blocks the migration: the gate errs on the side of keeping the old format.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tenko_api::{
    dto::system::{DataFormatStatus, FormatBlocker, PendingMigration},
    routes::system::DataFormatSource,
};
use tenko_cluster::model::{MemberRecord, tables};
use tenko_core::{NodeId, Revision, cluster::LeaderService};
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt as _, Store, StoreError,
    format::{self, Marker},
};
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use super::{datadir, migrations::Registry};

/// The name of the leader service that runs pending format migrations.
pub const SERVICE_NAME: &str = "upgrade.migrate";

/// How often the leader looks for a migration it may run, and how often every member
/// refreshes its format status and its marker.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// The voters of the Raft group, read when needed (they change with membership changes).
pub type Voters = Arc<dyn Fn() -> BTreeSet<NodeId> + Send + Sync>;

/// The stored format record and the member records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterFormats {
    /// The format of the replicated data and the revision of its record; `None` before the
    /// first start wrote the record.
    pub stored: Option<(u32, Revision)>,
    /// The member records by node.
    pub members: BTreeMap<NodeId, MemberRecord>,
}

/// Reads the stored format and the member records.
///
/// # Errors
///
/// The store's error.
pub async fn read(
    store: &dyn Store,
    consistency: ReadConsistency,
) -> Result<ClusterFormats, StoreError> {
    let view = store.read(consistency).await?;
    let stored =
        format::read_stored(view.as_ref())?.map(|(record, revision)| (record.version, revision));
    let members = view
        .scan_typed(&tables::MEMBERS, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .map(|(node, record, _)| (NodeId(node), record))
        .collect();
    Ok(ClusterFormats { stored, members })
}

/// The format status of the cluster for a binary that knows formats up to `binary`: a
/// pending migration when the stored data is older, with every voter whose binary does not
/// know `binary` yet.
pub fn gate(
    stored: u32,
    binary: u32,
    voters: &BTreeSet<NodeId>,
    members: &BTreeMap<NodeId, MemberRecord>,
) -> DataFormatStatus {
    let pending = (stored < binary).then(|| PendingMigration {
        target: binary,
        blocked_by: voters
            .iter()
            .filter_map(|node| match members.get(node) {
                Some(record) if record.known_formats().contains(&binary) => None,
                Some(record) => Some(FormatBlocker {
                    node: *node,
                    version: Some(record.version.clone()),
                    data_format: Some(record.data_format),
                }),
                None => Some(FormatBlocker {
                    node: *node,
                    version: None,
                    data_format: None,
                }),
            })
            .collect(),
    });
    DataFormatStatus {
        stored,
        binary,
        pending,
    }
}

/// What one look of the leader found or did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The stored data is at the newest format of this binary (or has no record yet).
    Current,
    /// Voters with older binaries keep the migration from running.
    Blocked(Vec<FormatBlocker>),
    /// The migrations ran; the formats migrated to.
    Migrated(Vec<u32>),
}

/// One look of the leader: runs the migrations to the newest format of `registry` when
/// every voter knows it, each batch fenced with `epoch`.
///
/// # Errors
///
/// The store's error, or the migration's ([`datadir::UpgradeError`]) as text.
pub async fn step(
    store: &dyn Store,
    voters: &BTreeSet<NodeId>,
    registry: Registry<'_>,
    written_by: &str,
    epoch: u64,
) -> Result<Step, String> {
    let formats = read(store, ReadConsistency::Linearizable)
        .await
        .map_err(|error| error.to_string())?;
    let Some((stored, revision)) = formats.stored else {
        return Ok(Step::Current);
    };
    let status = gate(stored, registry.current, voters, &formats.members);
    let Some(pending) = status.pending else {
        return Ok(Step::Current);
    };
    if !pending.blocked_by.is_empty() {
        return Ok(Step::Blocked(pending.blocked_by));
    }
    datadir::migrate(
        store,
        None,
        (stored, Some(revision)),
        registry,
        written_by,
        Some(tenko_store::fence(epoch)),
    )
    .await
    .map(Step::Migrated)
    .map_err(|error| format!("{}: {error}", error.code()))
}

/// The leader service [`SERVICE_NAME`].
pub struct Migrator {
    store: Arc<dyn Store>,
    voters: Voters,
    registry: Registry<'static>,
    written_by: String,
    interval: Duration,
}

impl std::fmt::Debug for Migrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Migrator")
            .field("registry", &self.registry)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl Migrator {
    /// The service for `store`, migrating to the newest format of `registry`.
    pub fn new(
        store: Arc<dyn Store>,
        voters: Voters,
        registry: Registry<'static>,
        written_by: impl Into<String>,
    ) -> Self {
        Self {
            store,
            voters,
            registry,
            written_by: written_by.into(),
            interval: CHECK_INTERVAL,
        }
    }

    /// Looks every `interval` instead of every [`CHECK_INTERVAL`] (tests).
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

#[async_trait::async_trait]
impl LeaderService for Migrator {
    fn name(&self) -> &'static str {
        SERVICE_NAME
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut reported: Option<Vec<FormatBlocker>> = None;
        loop {
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                _ = tick.tick() => {}
            }
            let voters = (self.voters)();
            match step(
                self.store.as_ref(),
                &voters,
                self.registry,
                &self.written_by,
                epoch,
            )
            .await?
            {
                Step::Current => reported = None,
                Step::Blocked(blockers) => {
                    if reported.as_ref() != Some(&blockers) {
                        tracing::info!(
                            target = self.registry.current,
                            blocked_by = %blocker_list(&blockers),
                            "the data format migration waits until every voter runs a binary \
                             that knows the format"
                        );
                        reported = Some(blockers);
                    }
                }
                Step::Migrated(formats) => {
                    tracing::info!(
                        ?formats,
                        "every voter knows the new data format; the leader migrated the data"
                    );
                    reported = None;
                }
            }
        }
    }
}

/// `1002 (0.1.0, format 2), 1003 (unknown)`.
fn blocker_list(blockers: &[FormatBlocker]) -> String {
    blockers
        .iter()
        .map(|blocker| match (&blocker.version, blocker.data_format) {
            (Some(version), Some(format)) => {
                format!("{} ({version}, format {format})", blocker.node)
            }
            _ => format!("{} (unknown)", blocker.node),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The local part on every member: keeps the format status for `GET /system/status` and
/// moves the format marker of the store directory after a migration the leader
/// committed, so that an older binary refuses the directory before it opens the store.
#[derive(Clone)]
pub struct Follower {
    store: Arc<dyn Store>,
    store_dir: PathBuf,
    voters: Voters,
    registry: Registry<'static>,
    written_by: String,
    status: Arc<Mutex<Option<DataFormatStatus>>>,
}

impl std::fmt::Debug for Follower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Follower")
            .field("store_dir", &self.store_dir)
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl Follower {
    /// The follower of the store in `store_dir`.
    pub fn new(
        store: Arc<dyn Store>,
        store_dir: PathBuf,
        voters: Voters,
        registry: Registry<'static>,
        written_by: impl Into<String>,
    ) -> Self {
        Self {
            store,
            store_dir,
            voters,
            registry,
            written_by: written_by.into(),
            status: Arc::new(Mutex::new(None)),
        }
    }

    /// The request extension of `GET /system/status`.
    pub fn source(&self) -> DataFormatSource {
        let status = Arc::clone(&self.status);
        DataFormatSource::new(move || {
            status
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        })
    }

    /// The status the last refresh found.
    pub fn status(&self) -> Option<DataFormatStatus> {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Reads the store once: refreshes the status and moves the marker when the stored
    /// format is ahead of it.
    ///
    /// # Errors
    ///
    /// The store's or the file system's error, as text.
    pub async fn refresh(&self) -> Result<(), String> {
        let formats = read(self.store.as_ref(), ReadConsistency::Local)
            .await
            .map_err(|error| error.to_string())?;
        let Some((stored, _)) = formats.stored else {
            return Ok(());
        };
        let voters = (self.voters)();
        let status = gate(stored, self.registry.current, &voters, &formats.members);
        *self.status.lock().unwrap_or_else(PoisonError::into_inner) = Some(status);
        let marker = format::read_marker(&self.store_dir)
            .map_err(|error| error.to_string())?
            .map(|marker| marker.version);
        if marker.is_some_and(|marker| marker < stored) && stored <= self.registry.current {
            format::write_marker(&self.store_dir, &Marker::new(stored, &self.written_by))
                .map_err(|error| error.to_string())?;
            tracing::info!(
                format = stored,
                "the cluster migrated the data; the format marker of this member follows"
            );
        }
        Ok(())
    }

    /// Refreshes at once and then every [`CHECK_INTERVAL`] until `stop` turns true.
    pub fn spawn(self, mut stop: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CHECK_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stop.wait_for(|stopped| *stopped) => return,
                    _ = tick.tick() => {}
                }
                if let Err(error) = self.refresh().await {
                    tracing::debug!(%error, "cannot refresh the data format status");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{Principal, SystemComponent, TableName, Timestamp, cluster::LEADER_EPOCH};
    use tenko_store::{
        Mutation, ReadView, WriteBatch, format::StoredFormat, raft::fixture::InProcessCluster,
        testing::ConformanceConfig,
    };

    use super::*;
    use crate::upgrade::migrations::{Migration, MigrationError};

    const TABLE: TableName = TableName::from_static("ipam.rolling_test_items");

    /// Format 3 of the tests: adds a row.
    struct AddRow;

    impl Migration for AddRow {
        fn to(&self) -> u32 {
            3
        }
        fn summary(&self) -> &'static str {
            "adds the test row"
        }
        fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
            Ok(vec![Mutation::Put {
                table: TABLE,
                key: b"migrated".to_vec().into(),
                value: b"1".to_vec().into(),
            }])
        }
    }

    /// A no-op step to format 2, then [`AddRow`].
    struct Empty;

    impl Migration for Empty {
        fn to(&self) -> u32 {
            2
        }
        fn summary(&self) -> &'static str {
            "nothing"
        }
        fn plan(&self, _view: &dyn ReadView) -> Result<Vec<Mutation>, MigrationError> {
            Ok(Vec::new())
        }
    }

    static MIGRATIONS: &[&dyn Migration] = &[&Empty, &AddRow];

    fn registry() -> Registry<'static> {
        Registry {
            current: 3,
            migrations: MIGRATIONS,
        }
    }

    fn record(node: u64, version: &str, data_format: u32) -> MemberRecord {
        MemberRecord {
            node: NodeId(node),
            address: format!("controller-{node}.example.test:8444"),
            version: version.to_owned(),
            data_format,
            joined_at: Timestamp::now(),
            protocol_majors: vec![1],
            raft_wire: Some("openraft-0.9/cbor-1".to_owned()),
            formats: (1..=data_format).collect(),
        }
    }

    fn batch() -> WriteBatch {
        WriteBatch::new(Principal::system(SystemComponent::Store), Timestamp::now())
    }

    async fn write_records(store: &dyn Store, records: &[MemberRecord]) {
        let mut batch = batch();
        for record in records {
            batch
                .put_typed(&tables::MEMBERS, &record.node.0, record)
                .expect("record");
        }
        store.propose(batch).await.expect("records");
    }

    async fn stored_format(store: &dyn Store) -> u32 {
        read(store, ReadConsistency::Local)
            .await
            .expect("read")
            .stored
            .expect("stored")
            .0
    }

    async fn epoch(store: &dyn Store) -> u64 {
        let view = store.read(ReadConsistency::Local).await.expect("read");
        view.counter(&LEADER_EPOCH).expect("counter")
    }

    #[test]
    fn the_gate_names_every_voter_that_does_not_know_the_format() {
        let voters: BTreeSet<NodeId> = [1, 1001, 1002, 1003].into_iter().map(NodeId).collect();
        let mut members: BTreeMap<NodeId, MemberRecord> = [
            record(1, "0.2.0", 3),
            record(1001, "0.2.0", 3),
            record(1002, "0.1.0", 2),
            // A learner with an old binary does not vote and does not block.
            record(1004, "0.1.0", 2),
        ]
        .into_iter()
        .map(|record| (record.node, record))
        .collect();
        let status = gate(2, 3, &voters, &members);
        let pending = status.pending.expect("pending");
        assert_eq!(pending.target, 3);
        assert_eq!(
            pending.blocked_by,
            vec![
                FormatBlocker {
                    node: NodeId(1002),
                    version: Some("0.1.0".to_owned()),
                    data_format: Some(2),
                },
                FormatBlocker {
                    node: NodeId(1003),
                    version: None,
                    data_format: None,
                },
            ]
        );
        // A record of an older build without the list counts every format up to its own.
        let mut old = record(1003, "0.2.0", 3);
        old.formats.clear();
        members.insert(NodeId(1003), old);
        members.insert(NodeId(1002), record(1002, "0.2.0", 3));
        assert_eq!(
            gate(2, 3, &voters, &members).pending.map(|p| p.blocked_by),
            Some(Vec::new())
        );
        assert_eq!(gate(3, 3, &voters, &members).pending, None);
        // A leader whose binary is older than the data never has anything pending.
        assert_eq!(gate(3, 2, &voters, &members).pending, None);
    }

    #[test]
    fn blockers_are_listed_for_the_log() {
        let blockers = vec![
            FormatBlocker {
                node: NodeId(1002),
                version: Some("0.1.0".to_owned()),
                data_format: Some(2),
            },
            FormatBlocker {
                node: NodeId(1003),
                version: None,
                data_format: None,
            },
        ];
        assert_eq!(
            blocker_list(&blockers),
            "1002 (0.1.0, format 2), 1003 (unknown)"
        );
    }

    /// The mixed-version case on three in-process Raft members: the data stays in the old
    /// format while one voter runs an older binary, writes keep flowing on every member,
    /// and the leader migrates once the last voter reports the newer binary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_leader_migrates_only_after_the_last_voter_is_upgraded() {
        let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
        let leader = cluster.wait_for_leader().await;
        let leader_dyn: Arc<dyn Store> = Arc::new(leader.clone());
        // The cluster's data is at format 1; members 1 and 2 run the new binary, 3 the old.
        let mut start = batch();
        format::stage_stored(
            &mut start,
            None,
            &StoredFormat {
                version: 1,
                written_by: "0.1.0".to_owned(),
            },
        )
        .expect("stored");
        leader.propose(start).await.expect("format 1");
        write_records(
            leader_dyn.as_ref(),
            &[
                record(1, "0.3.0", 3),
                record(2, "0.3.0", 3),
                record(3, "0.1.0", 1),
            ],
        )
        .await;
        let voters = leader.membership().voters;
        assert_eq!(voters.len(), 3);
        let fence = epoch(leader_dyn.as_ref()).await;

        let step_once = || step(leader_dyn.as_ref(), &voters, registry(), "0.3.0", fence);
        match step_once().await.expect("step") {
            Step::Blocked(blockers) => {
                assert_eq!(
                    blockers.iter().map(|b| b.node).collect::<Vec<_>>(),
                    vec![NodeId(3)]
                );
            }
            other => panic!("expected a blocked migration, got {other:?}"),
        }
        assert_eq!(stored_format(leader_dyn.as_ref()).await, 1);

        // Writes keep flowing through every member while the migration waits.
        for member in cluster.members() {
            let mut write = batch();
            write.put(
                TABLE,
                format!("write-{}", member.node_id()).into_bytes(),
                b"x".to_vec(),
            );
            member.propose(write).await.expect("write on a member");
        }

        // A follower shows the pending migration and names the blocking voter.
        let follower = cluster.a_follower().await;
        let dir = tempfile::tempdir().expect("tempdir");
        format::write_marker(dir.path(), &Marker::new(1, "0.3.0")).expect("marker");
        let watcher = Follower::new(
            Arc::new(follower.clone()),
            dir.path().to_owned(),
            {
                let voters = voters.clone();
                Arc::new(move || voters.clone())
            },
            registry(),
            "0.3.0",
        );
        watcher.refresh().await.expect("refresh");
        let status = watcher.status().expect("status");
        assert_eq!(status.stored, 1);
        assert_eq!(
            status.pending.expect("pending").blocked_by[0].node,
            NodeId(3)
        );

        // A stale epoch cannot migrate even when nothing blocks it.
        write_records(leader_dyn.as_ref(), &[record(3, "0.3.0", 3)]).await;
        let stale = step(leader_dyn.as_ref(), &voters, registry(), "0.3.0", fence + 1)
            .await
            .expect_err("fenced");
        assert!(stale.contains("upgrade."), "{stale}");
        assert_eq!(stored_format(leader_dyn.as_ref()).await, 1);

        // The last voter is upgraded: the leader migrates.
        assert_eq!(step_once().await.expect("step"), Step::Migrated(vec![2, 3]));
        assert_eq!(stored_format(leader_dyn.as_ref()).await, 3);
        assert_eq!(step_once().await.expect("step"), Step::Current);
        let view = leader
            .read(ReadConsistency::Linearizable)
            .await
            .expect("read");
        assert!(view.get(&TABLE, b"migrated").expect("get").is_some());
        drop(view);

        // The follower's marker follows once it has applied the migration.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            watcher.refresh().await.expect("refresh");
            let marker = format::read_marker(dir.path()).expect("marker");
            if marker.map(|marker| marker.version) == Some(3) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the marker did not follow"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(watcher.status().expect("status").pending, None);
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_service_stops_when_asked() {
        let store: Arc<dyn Store> = Arc::new(tenko_store::MemStore::default());
        let service = Migrator::new(
            Arc::clone(&store),
            Arc::new(|| [NodeId(1)].into_iter().collect()),
            registry(),
            "0.3.0",
        )
        .with_interval(Duration::from_millis(10));
        assert_eq!(service.name(), SERVICE_NAME);
        let stop = CancellationToken::new();
        let task = tokio::spawn({
            let stop = stop.clone();
            async move { service.run(0, stop).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.cancel();
        assert_eq!(task.await.expect("join"), Ok(()));
    }
}
