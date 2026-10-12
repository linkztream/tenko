//! The local queue of a controller and its drain (OPS-26, ADR 0013, `docs/partitions.md`).
//!
//! While the IPAM module runs, every controller keeps its own queue of changes made while
//! it was cut off from its cluster, under `<data_dir>/queue/`, and drains it itself: not a
//! leader service, because only the controller that holds the files can settle them. The
//! drain runs
//!
//! - when the quorum state turns to one that accepts writes (the heal),
//! - at start, for items queued before a restart,
//! - every [`RETRY_INTERVAL`] while items wait and the store accepts writes, so an item
//!   stopped by a transient error is settled without another state change.
//!
//! The drain itself ([`tenko_ipam::queue::Drainer`]) reads linearizably before it plans,
//! so it never settles an item against a copy that has not caught up.

use std::{sync::Arc, time::Duration};

use tenko_core::{Authorizer, NodeId};
use tenko_ipam::{
    IpamService,
    queue::{DrainReport, Drainer, LocalQueue},
    scope::ScopeIndex,
};
use tenko_store::QuorumState;
use tokio::{sync::watch, task::JoinHandle};

/// How often a waiting queue is retried while the store accepts writes.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// The directory of the queue under the data directory.
pub const DIR: &str = "queue";

/// What the queue needs.
pub struct Parts {
    /// The data directory.
    pub data_dir: std::path::PathBuf,
    /// This controller.
    pub node: NodeId,
    /// The IPAM service the drain plans and applies with.
    pub ipam: Arc<IpamService>,
    /// The authorizer that checks the authors' current rights.
    pub authorizer: Option<Arc<dyn Authorizer>>,
    /// The anchors of scoped rights.
    pub scope: Option<Arc<ScopeIndex>>,
    /// The quorum state of the store; `None` for a store that never loses it.
    pub quorum: Option<watch::Receiver<QuorumState>>,
    /// Fires at shutdown.
    pub stop: watch::Receiver<bool>,
}

/// The queue of a running controller.
pub struct Queue {
    /// The queue, for the API (`Arc<LocalQueue>` request extension).
    pub queue: Arc<LocalQueue>,
    /// The drainer.
    pub drainer: Arc<Drainer>,
    /// The drain task.
    pub task: JoinHandle<()>,
}

/// Opens the queue under `<data_dir>/queue/` and starts its drain task.
///
/// # Errors
///
/// The directory cannot be created or read.
pub fn start(parts: Parts) -> std::io::Result<Queue> {
    let queue = Arc::new(LocalQueue::open(parts.data_dir.join(DIR), parts.node)?);
    let waiting = queue.len().unwrap_or_default();
    if waiting > 0 {
        tracing::info!(
            waiting,
            dir = %parts.data_dir.join(DIR).display(),
            "changes queued while this controller was cut off from its cluster wait to be settled"
        );
    }
    let drainer = Arc::new(Drainer::new(
        parts.ipam,
        parts.authorizer,
        parts.scope,
        Arc::clone(&queue),
    ));
    let task = tokio::spawn(run(Arc::clone(&drainer), parts.quorum, parts.stop));
    Ok(Queue {
        queue,
        drainer,
        task,
    })
}

/// The drain loop.
async fn run(
    drainer: Arc<Drainer>,
    mut quorum: Option<watch::Receiver<QuorumState>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(RETRY_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // The first tick fires at once: items from before a restart are settled at start.
        tokio::select! {
            () = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return,
            _ = tick.tick() => {}
            open = async {
                match quorum.as_mut() {
                    Some(quorum) => quorum.changed().await.is_ok(),
                    None => std::future::pending().await,
                }
            } => {
                if !open {
                    quorum = None;
                }
            }
        }
        let accepts = quorum
            .as_ref()
            .is_none_or(|quorum| quorum.borrow().accepts_writes());
        if !accepts || drainer.queue().is_empty().unwrap_or(true) {
            continue;
        }
        match drainer.drain().await {
            Ok(report) => log(&report),
            Err(error) => tracing::warn!(%error, "the queue of changes could not be read"),
        }
    }
}

fn log(report: &DrainReport) {
    if report.is_empty() {
        return;
    }
    tracing::info!(
        applied = report.applied.len(),
        conflicts = report.conflicts.len(),
        expired = report.expired.len(),
        dropped = report.dropped.len(),
        interrupted = report.interrupted,
        "changes queued while the controller was cut off were settled; their authors find them \
         in GET /api/v1/queue/conflicts"
    );
}
