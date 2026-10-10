//! The leader service `scan.housekeeping`: prunes finished node commands, their results
//! and old scan runs, and the commands and scopes of nodes that left. Every delete carries
//! the leader's epoch, so a deposed leader deletes nothing.

use std::time::Duration;

use tenko_cluster::{
    model::tables::NODES,
    node_sync::{
        commands::CommandRecord,
        tables::{NODE_COMMANDS, RUN_RESULTS},
    },
    probe::tables::SCOPES,
};
use tenko_core::{
    NodeId, RequestCtx, SystemComponent, Timestamp, cluster::LeaderService, codec::key::encode_key,
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt, WriteBatch};
use tokio_util::sync::CancellationToken;

use super::{
    Shared,
    model::tables::{BASELINES, PROBE_CONFIG, RUNS},
};

/// How often the service prunes.
pub const INTERVAL: Duration = Duration::from_secs(3600);
/// How long a finished command and its results are kept.
pub const COMMAND_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long a scan run is kept.
pub const RUN_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
/// How long the commands of a node that left are kept.
pub const DEPARTED_RETENTION: Duration = Duration::from_secs(24 * 3600);
/// Most keys removed in one write.
const PAGE: usize = 500;

pub(crate) struct Housekeeping {
    shared: Shared,
}

impl Housekeeping {
    pub(crate) fn new(shared: Shared) -> Self {
        Self { shared }
    }
}

/// Rows to delete, each as its table and key.
type Deletes = Vec<(tenko_core::TableName, Vec<u8>)>;

/// What one pass removes, as writes of at most [`PAGE`] deletes each.
pub(crate) fn plan(
    view: &dyn ReadView,
    local: Option<NodeId>,
    now: Timestamp,
) -> Result<Vec<Deletes>, tenko_store::StoreError> {
    let mut deletes: Deletes = Vec::new();
    let known = |node: NodeId| -> Result<bool, tenko_store::StoreError> {
        Ok(Some(node) == local || view.get_typed(&NODES, &node.0)?.is_some())
    };
    let older = |at: Timestamp, keep: Duration| now.saturating_since(at) > keep;
    for (_, command, _) in view.scan_typed(&NODE_COMMANDS, KeyRange::all(), usize::MAX, false)? {
        let command: CommandRecord = command;
        let gone = !known(command.node)? && older(command.issued_at, DEPARTED_RETENTION);
        let done = command.state.is_final() && older(command.updated_at, COMMAND_RETENTION);
        if gone || done {
            deletes.push((
                NODE_COMMANDS.name().clone(),
                NODE_COMMANDS.key(&(command.node.0, command.id)).to_vec(),
            ));
            for (key, _, _) in view.scan_typed(
                &RUN_RESULTS,
                KeyRange::prefix(encode_key(&(command.id,))),
                usize::MAX,
                false,
            )? {
                deletes.push((RUN_RESULTS.name().clone(), RUN_RESULTS.key(&key).to_vec()));
            }
        }
    }
    for (id, run, _) in view.scan_typed(&RUNS, KeyRange::all(), usize::MAX, false)? {
        if older(run.created_at, RUN_RETENTION) {
            deletes.push((RUNS.name().clone(), RUNS.key(&id).to_vec()));
            deletes.push((BASELINES.name().clone(), BASELINES.key(&id).to_vec()));
        }
    }
    for (node, scope, _) in view.scan_typed(&SCOPES, KeyRange::all(), usize::MAX, false)? {
        if !known(NodeId(node))? && older(scope.reported_at, DEPARTED_RETENTION) {
            deletes.push((SCOPES.name().clone(), SCOPES.key(&node).to_vec()));
            deletes.push((
                PROBE_CONFIG.name().clone(),
                PROBE_CONFIG.key(&node).to_vec(),
            ));
        }
    }
    Ok(deletes.chunks(PAGE).map(<[_]>::to_vec).collect())
}

impl Housekeeping {
    async fn pass(&self, epoch: u64) -> Result<usize, tenko_store::StoreError> {
        let view = self.shared.store.read(ReadConsistency::Local).await?;
        let pages = plan(view.as_ref(), self.shared.local, Timestamp::now())?;
        drop(view);
        let mut removed = 0;
        for page in pages {
            let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Scan));
            batch.expect_counter(tenko_core::cluster::LEADER_EPOCH, epoch);
            for (table, key) in &page {
                batch.delete(table.clone(), key.clone());
            }
            self.shared.store.propose(batch).await?;
            removed += page.len();
        }
        Ok(removed)
    }
}

#[async_trait::async_trait]
impl LeaderService for Housekeeping {
    fn name(&self) -> &'static str {
        "scan.housekeeping"
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut tick = tokio::time::interval(INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                _ = tick.tick() => {}
            }
            match self.pass(epoch).await {
                Ok(0) => {}
                Ok(count) => tracing::info!(count, "old scan commands, results and runs removed"),
                Err(tenko_store::StoreError::PreconditionFailed(_)) => {
                    return Err(
                        "the leader epoch moved on; another controller took office".to_owned()
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "scan housekeeping failed; it runs again later");
                }
            }
        }
    }
}
