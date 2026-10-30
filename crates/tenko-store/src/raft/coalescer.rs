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
//!
//! WP9.6 (ADR 0030): a batch is foreground (the default) or background (the DHCP role's
//! writer of the lease history and facts, [`crate::Store::propose_background`]). The
//! foreground batches waiting are packed first, in their order; an entry that carries any
//! takes at most one background batch beside them, and only one of at most
//! [`BACKGROUND_SHARE`] bytes, so a lease commit never waits behind more than that share
//! of background rows in the append and the apply. An entry without foreground batches
//! carries background batches up to the entry bound, and a background batch that has
//! waited [`BACKGROUND_MAX_WAIT`] is packed as if no foreground batch waited, so the
//! background class is never starved. The two classes keep no order between them.
//!
//! When openraft refuses an entry because this node no longer leads, every proposer of the
//! entry learns it as [`Refused::NotLeader`]: nothing was appended, so the store forwards
//! the batch to the new leader. A hand-over of leadership holds the coalescer
//! ([`Hold`]) so that no entry refreshes the followers' leader lease meanwhile.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

use openraft::raft::ClientWriteResult;

use super::types::{BatchOutcome, Proposal, ProposedBatch, Raft, TypeConfig};
use crate::api::{CoalescerConfig, Committed, StoreError};

/// Why the coalescer did not commit a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    /// This node does not lead: the batch was not appended.
    NotLeader,
    /// The batch failed (preconditions, idempotency, ...) or the store stopped.
    Store(StoreError),
}

/// A batch waiting for an entry, with the channel its proposer waits on.
pub(crate) struct Queued {
    pub(crate) batch: ProposedBatch,
    pub(crate) reply: oneshot::Sender<Result<Committed, Refused>>,
    /// WP9.6: a background batch (ADR 0030).
    pub(crate) background: bool,
}

/// The encoded bytes of background batches an entry with foreground batches may carry: one
/// background batch of at most this size.
pub const BACKGROUND_SHARE: usize = 24 * 1024;

/// The longest a background batch waits while foreground batches keep coming.
pub const BACKGROUND_MAX_WAIT: Duration = Duration::from_millis(250);

/// The batches waiting for an entry, by class.
#[derive(Default)]
pub(crate) struct Waiting {
    foreground: VecDeque<Queued>,
    background: VecDeque<(std::time::Instant, Queued)>,
}

impl Waiting {
    pub(crate) fn push(&mut self, queued: Queued) {
        if queued.background {
            self.background
                .push_back((std::time::Instant::now(), queued));
        } else {
            self.foreground.push_back(queued);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.foreground.is_empty() && self.background.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.foreground.len() + self.background.len()
    }

    /// The batches of the next entry (at least one when any waits): the foreground ones in
    /// order within the bound, then the background share.
    pub(crate) fn next_entry(&mut self, config: &CoalescerConfig) -> Vec<Queued> {
        let max_batches = config.max_batches_per_entry.max(1);
        let mut entry: Vec<Queued> = Vec::new();
        let mut bytes = 0;
        while entry.len() < max_batches {
            let Some(next) = self.foreground.front() else {
                break;
            };
            let len = next.batch.batch.len();
            if !entry.is_empty() && bytes + len > config.max_entry_bytes {
                break;
            }
            bytes += len;
            entry.extend(self.foreground.pop_front());
        }
        let overdue = self
            .background
            .front()
            .is_some_and(|(at, _)| at.elapsed() >= BACKGROUND_MAX_WAIT);
        if !entry.is_empty() && !overdue {
            // The share beside the foreground batches: one small background batch.
            if entry.len() < max_batches
                && self
                    .background
                    .front()
                    .is_some_and(|(_, next)| next.batch.batch.len() <= BACKGROUND_SHARE)
            {
                entry.extend(self.background.pop_front().map(|(_, queued)| queued));
            }
            return entry;
        }
        // No foreground batch waits, or the oldest background batch waited long enough:
        // background batches up to the entry bound.
        while entry.len() < max_batches {
            let Some((_, next)) = self.background.front() else {
                break;
            };
            let len = next.batch.batch.len();
            if !entry.is_empty() && bytes + len > config.max_entry_bytes {
                break;
            }
            bytes += len;
            entry.extend(self.background.pop_front().map(|(_, queued)| queued));
        }
        entry
    }

    fn drain(&mut self) -> Vec<Queued> {
        self.foreground
            .drain(..)
            .chain(self.background.drain(..).map(|(_, queued)| queued))
            .collect()
    }
}

/// Holds the coalescer: while a writer holds it, no entry goes to openraft.
pub(crate) type Hold = Arc<tokio::sync::RwLock<()>>;

/// Counters of the coalescer.
#[derive(Debug, Default)]
pub(crate) struct CoalescerStats {
    pub(crate) entries: std::sync::atomic::AtomicU64,
    pub(crate) batches: std::sync::atomic::AtomicU64,
    /// WP9.6: batches taken from the channel and waiting for an entry by class.
    pub(crate) waiting: std::sync::atomic::AtomicUsize,
}

/// Starts the coalescer task; it ends when every sender of `queue` is dropped.
pub(crate) fn spawn(
    raft: Raft,
    config: CoalescerConfig,
    journal: (u64, u64),
    queue: mpsc::Receiver<Queued>,
    stats: Arc<CoalescerStats>,
    hold: Hold,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(raft, config, journal, queue, stats, hold))
}

async fn run(
    raft: Raft,
    config: CoalescerConfig,
    (journal_retention, journal_max_bytes): (u64, u64),
    mut queue: mpsc::Receiver<Queued>,
    stats: Arc<CoalescerStats>,
    hold: Hold,
) {
    let inflight = Arc::new(Semaphore::new(config.max_inflight_entries.max(1)));
    let mut waiting = Waiting::default();
    loop {
        if waiting.is_empty() {
            match queue.recv().await {
                Some(first) => waiting.push(first),
                None => return,
            }
        }
        let Ok(permit) = Arc::clone(&inflight).acquire_owned().await else {
            fail(waiting.drain(), &Refused::Store(StoreError::ShuttingDown));
            return;
        };
        let not_held = hold.read().await;
        // Whatever arrived while the permit was awaited joins the choice of this entry, up
        // to two entries' worth: the rest waits in the channel, which bounds the queue.
        let look_ahead = config.max_batches_per_entry.max(1).saturating_mul(2);
        while waiting.len() < look_ahead {
            match queue.try_recv() {
                Ok(next) => waiting.push(next),
                Err(_) => break,
            }
        }
        let entry = waiting.next_entry(&config);
        stats
            .waiting
            .store(waiting.len(), std::sync::atomic::Ordering::Relaxed);

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
            journal_max_bytes,
            batches,
        };
        let Ok(response) = raft.client_write_ff(proposal).await else {
            for reply in replies {
                let _ = reply.send(Err(Refused::Store(StoreError::ShuttingDown)));
            }
            return;
        };
        drop(not_held);
        tokio::spawn(answer(response, replies, permit));
    }
}

/// Waits for an entry's response and answers each proposer.
async fn answer<E>(
    response: impl Future<Output = Result<ClientWriteResult<TypeConfig>, E>>,
    replies: Vec<oneshot::Sender<Result<Committed, Refused>>>,
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
                let _ = reply.send(Err(Refused::Store(StoreError::ShuttingDown)));
            }
            return;
        }
    };
    if outcomes.len() != replies.len() {
        let error = Refused::Store(StoreError::Storage(format!(
            "the state machine answered {} of {} batches",
            outcomes.len(),
            replies.len()
        )));
        for reply in replies {
            let _ = reply.send(Err(error.clone()));
        }
        return;
    }
    for (outcome, reply) in outcomes.into_iter().zip(replies) {
        let _ = reply.send(BatchOutcome::into_result(outcome).map_err(Refused::Store));
    }
}

/// Maps a client write error: a refusal because another node leads proves that nothing was
/// appended (the store forwards the batch).
fn map_write_error(error: &openraft::error::ClientWriteError<u64, openraft::BasicNode>) -> Refused {
    match error {
        openraft::error::ClientWriteError::ForwardToLeader(_) => Refused::NotLeader,
        openraft::error::ClientWriteError::ChangeMembershipError(error) => {
            Refused::Store(StoreError::Storage(error.to_string()))
        }
    }
}

fn fail(queued: Vec<Queued>, error: &Refused) {
    for queued in queued {
        let _ = queued.reply.send(Err(error.clone()));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bytes::Bytes;

    use super::*;
    use crate::raft::ENTRY_BOUND;

    /// A queued batch of `len` encoded bytes; its tag is its first byte.
    fn queued(len: usize, tag: u8, background: bool) -> Queued {
        let mut bytes = vec![0_u8; len.max(1)];
        bytes[0] = tag;
        Queued {
            batch: ProposedBatch {
                batch: Bytes::from(bytes),
                fingerprint: None,
            },
            reply: oneshot::channel().0,
            background,
        }
    }

    fn tags(entry: &[Queued]) -> Vec<(u8, bool)> {
        entry
            .iter()
            .map(|queued| (queued.batch.batch[0], queued.background))
            .collect()
    }

    fn bytes(entry: &[Queued]) -> usize {
        entry.iter().map(|queued| queued.batch.batch.len()).sum()
    }

    #[test]
    fn foreground_batches_go_first_with_one_small_background_batch_beside_them() {
        let mut waiting = Waiting::default();
        waiting.push(queued(16 * 1024, 1, true));
        waiting.push(queued(16 * 1024, 2, true));
        for tag in 10..14 {
            waiting.push(queued(1_000, tag, false));
        }
        let entry = waiting.next_entry(&ENTRY_BOUND);
        assert_eq!(
            tags(&entry),
            [
                (10, false),
                (11, false),
                (12, false),
                (13, false),
                (1, true)
            ],
            "every foreground batch, then one background batch"
        );
        // Nothing in the foreground any more: the background batches fill an entry.
        let entry = waiting.next_entry(&ENTRY_BOUND);
        assert_eq!(tags(&entry), [(2, true)]);
    }

    #[test]
    fn a_background_batch_never_delays_a_foreground_one_past_the_entry_bound() {
        let mut waiting = Waiting::default();
        waiting.push(queued(BACKGROUND_SHARE, 1, true));
        waiting.push(queued(BACKGROUND_SHARE + 1, 2, true));
        // Foreground batches enough for two entries.
        for tag in 10..30 {
            waiting.push(queued(6 * 1024, tag, false));
        }
        let first = waiting.next_entry(&ENTRY_BOUND);
        let foreground = first.iter().filter(|queued| !queued.background).count();
        assert_eq!(
            foreground, 10,
            "the foreground batches fill the entry bound"
        );
        assert!(bytes(&first) <= ENTRY_BOUND.max_entry_bytes + BACKGROUND_SHARE);
        assert_eq!(tags(&first).last(), Some(&(1, true)), "one share, last");
        // A background batch above the share never rides beside foreground batches.
        let second = waiting.next_entry(&ENTRY_BOUND);
        assert!(
            second.iter().all(|queued| !queued.background),
            "{:?}",
            tags(&second)
        );
        let third = waiting.next_entry(&ENTRY_BOUND);
        assert_eq!(
            tags(&third),
            [(2, true)],
            "alone once the foreground is empty"
        );
    }

    #[test]
    fn a_background_batch_that_waited_its_cap_goes_whatever_waits_in_the_foreground() {
        let mut waiting = Waiting::default();
        let long_ago = Instant::now()
            .checked_sub(BACKGROUND_MAX_WAIT)
            .expect("a past instant");
        for tag in 1..4 {
            waiting
                .background
                .push_back((long_ago, queued(20 * 1024, tag, true)));
        }
        for tag in 10..12 {
            waiting.push(queued(1_000, tag, false));
        }
        let entry = waiting.next_entry(&ENTRY_BOUND);
        assert_eq!(
            tags(&entry),
            [(10, false), (11, false), (1, true), (2, true), (3, true)],
            "overdue: the background batches up to the bound"
        );
        assert!(bytes(&entry) <= ENTRY_BOUND.max_entry_bytes);
    }
}
