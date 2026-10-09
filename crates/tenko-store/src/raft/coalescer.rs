//! The write coalescer (ADR 0002 decision 4).
//!
//! openraft 0.9 waits for each log flush before it takes the next client request, so one
//! Raft entry per write would cap the store at one write per fsync (about 120 writes per
//! second in Spike A). Proposers therefore queue their encoded batch here; one task drains
//! the queue and packs whatever has arrived into one entry, up to
//! [`CoalescerConfig::max_batches_per_entry`] batches and
//! [`CoalescerConfig::max_entry_bytes`] bytes (a single larger batch travels alone), and
//! keeps at most [`CoalescerConfig::max_inflight_entries`] entries in flight. Entries are
//! handed to openraft in queue order (`client_write_ff`), and the state machine applies the
//! batches of an entry in order, each against its own preconditions; the answer for each
//! batch goes back to its own proposer.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

use openraft::raft::ClientWriteResult;

use super::types::{BatchOutcome, Proposal, ProposedBatch, Raft, TypeConfig};
use crate::api::{CoalescerConfig, Committed, StoreError};

/// A batch waiting for an entry, with the channel its proposer waits on.
pub(crate) struct Queued {
    pub(crate) batch: ProposedBatch,
    pub(crate) reply: oneshot::Sender<Result<Committed, StoreError>>,
}

/// Counters of the coalescer.
#[derive(Debug, Default)]
pub(crate) struct CoalescerStats {
    pub(crate) entries: std::sync::atomic::AtomicU64,
    pub(crate) batches: std::sync::atomic::AtomicU64,
}

/// Starts the coalescer task; it ends when every sender of `queue` is dropped.
pub(crate) fn spawn(
    raft: Raft,
    config: CoalescerConfig,
    journal_retention: u64,
    queue: mpsc::Receiver<Queued>,
    stats: Arc<CoalescerStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(raft, config, journal_retention, queue, stats))
}

async fn run(
    raft: Raft,
    config: CoalescerConfig,
    journal_retention: u64,
    mut queue: mpsc::Receiver<Queued>,
    stats: Arc<CoalescerStats>,
) {
    let inflight = Arc::new(Semaphore::new(config.max_inflight_entries.max(1)));
    let max_batches = config.max_batches_per_entry.max(1);
    let mut carried: Option<Queued> = None;
    loop {
        let first = match carried.take() {
            Some(first) => first,
            None => match queue.recv().await {
                Some(first) => first,
                None => return,
            },
        };
        let Ok(permit) = Arc::clone(&inflight).acquire_owned().await else {
            fail(vec![first], &StoreError::ShuttingDown);
            return;
        };
        // Whatever arrived while the permit was awaited joins this entry.
        let mut bytes = first.batch.batch.len();
        let mut entry = vec![first];
        while entry.len() < max_batches {
            match queue.try_recv() {
                Ok(next) => {
                    if bytes + next.batch.batch.len() > config.max_entry_bytes {
                        carried = Some(next);
                        break;
                    }
                    bytes += next.batch.batch.len();
                    entry.push(next);
                }
                Err(_) => break,
            }
        }
        stats
            .entries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        stats.batches.fetch_add(
            u64::try_from(entry.len()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        let (batches, replies): (Vec<ProposedBatch>, Vec<_>) = entry
            .into_iter()
            .map(|queued| (queued.batch, queued.reply))
            .unzip();
        let proposal = Proposal {
            journal_retention,
            batches,
        };
        let Ok(response) = raft.client_write_ff(proposal).await else {
            for reply in replies {
                let _ = reply.send(Err(StoreError::ShuttingDown));
            }
            return;
        };
        tokio::spawn(answer(response, replies, permit));
    }
}

/// Waits for an entry's response and answers each proposer.
async fn answer<E>(
    response: impl Future<Output = Result<ClientWriteResult<TypeConfig>, E>>,
    replies: Vec<oneshot::Sender<Result<Committed, StoreError>>>,
    permit: OwnedSemaphorePermit,
) {
    let result = response.await;
    drop(permit);
    let outcomes = match result {
        Ok(Ok(written)) => written.data.outcomes,
        Ok(Err(error)) => {
            let error = map_write_error(&error);
            for reply in replies {
                let _ = reply.send(Err(error.clone()));
            }
            return;
        }
        Err(_) => {
            for reply in replies {
                let _ = reply.send(Err(StoreError::ShuttingDown));
            }
            return;
        }
    };
    if outcomes.len() != replies.len() {
        let error = StoreError::Storage(format!(
            "the state machine answered {} of {} batches",
            outcomes.len(),
            replies.len()
        ));
        for reply in replies {
            let _ = reply.send(Err(error.clone()));
        }
        return;
    }
    for (outcome, reply) in outcomes.into_iter().zip(replies) {
        let _ = reply.send(BatchOutcome::into_result(outcome));
    }
}

/// Maps a client write error. Without write forwarding (Slice 3) a follower cannot accept
/// writes, which callers see as no quorum on this node.
fn map_write_error(
    error: &openraft::error::ClientWriteError<u64, openraft::BasicNode>,
) -> StoreError {
    match error {
        openraft::error::ClientWriteError::ForwardToLeader(_) => StoreError::NoQuorum,
        openraft::error::ClientWriteError::ChangeMembershipError(error) => {
            StoreError::Storage(error.to_string())
        }
    }
}

fn fail(queued: Vec<Queued>, error: &StoreError) {
    for queued in queued {
        let _ = queued.reply.send(Err(error.clone()));
    }
}
