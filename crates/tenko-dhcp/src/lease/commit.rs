//! The production [`LeaseStore`]: lease changes committed through the store's coalescer
//! before the role answers (plan section 2.1, P3-Q1, ADR 0019 points 3 and 4).
//!
//! [`StoreLeases::submit`] is the hand-off of the DORA path: it copies the change into a
//! queue allocated up front and wakes the [`Committer`], without allocating or waiting
//! (`tests/lease_alloc.rs`). The committer, a task of the role:
//!
//! 1. takes the queued changes in order and builds each into one batch
//!    ([`batch::build`]: the lease row, the client index rows it moves, the history row,
//!    the observation fact) from the row the role's table holds for the address;
//! 2. proposes the batches concurrently, up to [`CommitSettings::max_in_flight`], so the
//!    store's coalescer folds the waiting ones into one Raft entry and one fsync. Changes
//!    that touch the same address or the same client (as new or as previous holder) are
//!    proposed one after another, each built from the table after the one before it
//!    applied, so the rows and the index never depend on the order commits finish in;
//! 3. when a batch commits (durable on this node: the store answers after its log entry is
//!    on disk and applied), applies the row to the role's table at the commit's revision
//!    and only then reports the ticket committed with that revision: the ACK the worker
//!    sends for it is released by the durable commit and the table holds what it promised;
//! 4. reports a ticket failed when its commit is refused, or when it has not committed
//!    within [`CommitSettings::commit_wait`] of its hand-off (the worker drops the request
//!    as the DNS update path answers SERVFAIL past its index wait; a commit that lands
//!    later still reaches the table, and the client's retry finds the lease).
//!
//! A refusal of the store closes the [`RefusalGate`] (P3-Q14): the hand-off refuses until
//! the gate's trial interval passes, and the worker answers from
//! [`RefusalGate::decide`].

use std::{
    collections::{HashSet, VecDeque},
    hash::{BuildHasher, Hash, RandomState},
    pin::pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tenko_core::{NodeId, Revision, Timestamp, dhcp::lease::MAX_IDENTITY};
use tenko_store::{Store, StoreError};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::{
    LeaseTable, PendingChange,
    batch::{self, BuildError, NoObservations, ObservationHook},
    metrics,
    refusal::RefusalGate,
    table::SharedLeases,
};
use crate::store::{CommitError, Completion, LeaseStore, SubmitError, Ticket};

/// The committer's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitSettings {
    /// Changes the hand-off queue holds; a full queue drops the request (`queue`).
    pub queue: usize,
    /// Batches proposed at once.
    pub max_in_flight: usize,
    /// How long after its hand-off a change may take to commit before its request is
    /// dropped.
    pub commit_wait: Duration,
    /// How long after a refusal the gate stays closed before a trial.
    pub retry_after: Duration,
}

impl Default for CommitSettings {
    fn default() -> Self {
        Self {
            queue: 4_096,
            max_in_flight: 512,
            commit_wait: Duration::from_secs(2),
            retry_after: Duration::from_secs(1),
        }
    }
}

/// What the committer has done since it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitStats {
    /// Changes handed off.
    pub submitted: u64,
    /// Changes committed.
    pub committed: u64,
    /// Changes whose commit the store refused.
    pub refused: u64,
    /// Changes reported failed because their commit took longer than the wait.
    pub timed_out: u64,
    /// Changes refused because another client holds the address.
    pub held_by_other: u64,
}

#[derive(Debug, Default)]
struct Counters {
    submitted: AtomicU64,
    committed: AtomicU64,
    refused: AtomicU64,
    timed_out: AtomicU64,
    held_by_other: AtomicU64,
}

#[derive(Debug)]
struct Queued {
    change: PendingChange,
    ticket: Ticket,
    at: Instant,
}

struct Shared {
    node: NodeId,
    capacity: usize,
    queue: Mutex<VecDeque<Queued>>,
    wake: Notify,
    completions: Mutex<Vec<Completion>>,
    done: Notify,
    gate: RefusalGate,
    leases: SharedLeases,
    counters: Counters,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("node", &self.node)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn complete(&self, ticket: Ticket, outcome: Result<Revision, CommitError>) {
        self.completions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Completion { ticket, outcome });
        self.done.notify_one();
    }
}

/// The lease store on the replicated store: the hand-off side, shared by the workers.
#[derive(Debug, Clone)]
pub struct StoreLeases {
    shared: Arc<Shared>,
}

/// The committer task of a [`StoreLeases`]; run it with [`Committer::run`].
pub struct Committer {
    shared: Arc<Shared>,
    store: Arc<dyn Store>,
    hook: Arc<dyn ObservationHook>,
    settings: CommitSettings,
    hasher: RandomState,
}

impl std::fmt::Debug for Committer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Committer")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl StoreLeases {
    /// A lease store for `node` that commits to `store` and applies its commits to
    /// `leases`, without observation facts; and its committer.
    pub fn new(
        store: Arc<dyn Store>,
        leases: SharedLeases,
        node: NodeId,
        settings: CommitSettings,
    ) -> (Self, Committer) {
        Self::with_hook(store, leases, node, settings, Arc::new(NoObservations))
    }

    /// As [`StoreLeases::new`], with the hook that adds the observation facts (WP8.1).
    pub fn with_hook(
        store: Arc<dyn Store>,
        leases: SharedLeases,
        node: NodeId,
        settings: CommitSettings,
        hook: Arc<dyn ObservationHook>,
    ) -> (Self, Committer) {
        let capacity = settings.queue.max(1);
        let shared = Arc::new(Shared {
            node,
            capacity,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            wake: Notify::new(),
            completions: Mutex::new(Vec::with_capacity(capacity)),
            done: Notify::new(),
            gate: RefusalGate::new(settings.retry_after),
            leases,
            counters: Counters::default(),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            Committer {
                shared,
                store,
                hook,
                settings,
                hasher: RandomState::new(),
            },
        )
    }

    /// The refusal state (P3-Q14).
    pub fn gate(&self) -> &RefusalGate {
        &self.shared.gate
    }

    /// The table the committer applies its commits to.
    pub fn leases(&self) -> &SharedLeases {
        &self.shared.leases
    }

    /// Waits until a completion is ready (one waiter: the role's completion loop).
    pub async fn completed(&self) {
        self.shared.done.notified().await;
    }

    /// The counts since the start.
    pub fn stats(&self) -> CommitStats {
        let counters = &self.shared.counters;
        CommitStats {
            submitted: counters.submitted.load(Ordering::Relaxed),
            committed: counters.committed.load(Ordering::Relaxed),
            refused: counters.refused.load(Ordering::Relaxed),
            timed_out: counters.timed_out.load(Ordering::Relaxed),
            held_by_other: counters.held_by_other.load(Ordering::Relaxed),
        }
    }

    /// Changes waiting in the hand-off queue.
    pub fn queued(&self) -> usize {
        self.shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl LeaseStore for StoreLeases {
    fn submit(&self, change: &PendingChange, ticket: Ticket) -> Result<(), SubmitError> {
        if !self.shared.gate.accepting() {
            return Err(SubmitError::Refused);
        }
        {
            let mut queue = self
                .shared
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if queue.len() >= self.shared.capacity {
                return Err(SubmitError::Full);
            }
            queue.push_back(Queued {
                change: change.clone(),
                ticket,
                at: Instant::now(),
            });
        }
        self.shared
            .counters
            .submitted
            .fetch_add(1, Ordering::Relaxed);
        self.shared.wake.notify_one();
        Ok(())
    }

    fn completions(&self, out: &mut Vec<Completion>) {
        out.append(
            &mut self
                .shared
                .completions
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    fn accepting(&self) -> bool {
        self.shared.gate.accepting()
    }
}

/// Whether a store error means the store cannot commit now (P3-Q14), rather than a fault
/// of the batch.
fn is_refusal(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::NoQuorum
            | StoreError::Timeout
            | StoreError::ShuttingDown
            | StoreError::Storage(_)
    )
}

type InFlight = FuturesUnordered<BoxFuture<'static, [u64; 3]>>;

impl Committer {
    fn key_of(&self, value: impl Hash) -> u64 {
        self.hasher.hash_one(value)
    }

    /// The keys a change touches: its address, its client, and the client that holds the
    /// address now.
    fn keys(&self, change: &PendingChange) -> [u64; 3] {
        let mut identity = [0u8; MAX_IDENTITY];
        let len = change.identity(&mut identity);
        let address = self.key_of((0u8, change.vrf, change.addr));
        let client = self.key_of((1u8, change.scope, &identity[..len]));
        let holder = self
            .shared
            .leases
            .read()
            .get(change.vrf, change.addr)
            .map_or(client, |held| {
                self.key_of((1u8, held.scope, held.client.identity().as_slice()))
            });
        [address, client, holder]
    }

    /// Runs until `stop` fires; then waits for the batches in flight, and fails the
    /// changes still queued.
    pub async fn run(self, stop: CancellationToken) {
        let mut inflight: InFlight = FuturesUnordered::new();
        let mut busy: HashSet<u64> = HashSet::new();
        let mut deferred: VecDeque<Queued> = VecDeque::new();
        loop {
            if stop.is_cancelled() {
                break;
            }
            self.schedule(&mut inflight, &mut busy, &mut deferred);
            tokio::select! {
                biased;
                () = stop.cancelled() => break,
                Some(keys) = inflight.next(), if !inflight.is_empty() => {
                    for key in keys {
                        busy.remove(&key);
                    }
                }
                () = self.shared.wake.notified() => {}
            }
        }
        while inflight.next().await.is_some() {}
        let queued: Vec<Queued> = {
            let mut queue = self
                .shared
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            deferred.drain(..).chain(queue.drain(..)).collect()
        };
        for queued in queued {
            self.shared.complete(
                queued.ticket,
                Err(CommitError::Refused(
                    "the lease committer stopped".to_owned(),
                )),
            );
        }
    }

    /// Starts what may start: the deferred changes first, in order, then the queue's, while
    /// the in-flight limit allows; a change whose keys are busy, or touched by an earlier
    /// waiting change, waits its turn.
    fn schedule(
        &self,
        inflight: &mut InFlight,
        busy: &mut HashSet<u64>,
        deferred: &mut VecDeque<Queued>,
    ) {
        let max = self.settings.max_in_flight.max(1);
        let mut blocked: HashSet<u64> = busy.clone();
        let mut waiting = std::mem::take(deferred);
        loop {
            let queued = if let Some(queued) = waiting.pop_front() {
                queued
            } else {
                if inflight.len() >= max || deferred.len() >= max {
                    break;
                }
                let next = self
                    .shared
                    .queue
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pop_front();
                match next {
                    Some(queued) => queued,
                    None => break,
                }
            };
            // The holder of the address may have changed while the change waited.
            let keys = self.keys(&queued.change);
            let free = keys.iter().all(|key| !blocked.contains(key));
            blocked.extend(keys);
            if free && inflight.len() < max {
                if let Some(future) = self.start(&queued, keys) {
                    busy.extend(keys);
                    inflight.push(future);
                }
            } else {
                deferred.push_back(queued);
            }
        }
    }

    /// Builds the batch of a change and returns the future that commits it, or completes
    /// the ticket at once when the change cannot be built.
    fn start(&self, queued: &Queued, keys: [u64; 3]) -> Option<BoxFuture<'static, [u64; 3]>> {
        let now = Timestamp::now();
        let built = {
            let table = self.shared.leases.read();
            let previous = table.get(queued.change.vrf, queued.change.addr).cloned();
            batch::build(
                &queued.change,
                self.shared.node,
                previous.as_ref(),
                |lease| table.index_after(lease),
                self.hook.as_ref(),
                now,
            )
        };
        let built = match built {
            Ok(built) => built,
            Err(error) => {
                if error == BuildError::HeldByOther {
                    self.shared
                        .counters
                        .held_by_other
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.shared
                    .complete(queued.ticket, Err(CommitError::Refused(error.to_string())));
                return None;
            }
        };
        let shared = Arc::clone(&self.shared);
        let store = Arc::clone(&self.store);
        let deadline = tokio::time::Instant::from_std(queued.at + self.settings.commit_wait);
        let wait = self.settings.commit_wait;
        let (ticket, at) = (queued.ticket, queued.at);
        Some(Box::pin(async move {
            let mut propose = pin!(store.propose(built.batch));
            let mut late = false;
            let result = tokio::select! {
                result = &mut propose => result,
                () = tokio::time::sleep_until(deadline) => {
                    late = true;
                    shared.counters.timed_out.fetch_add(1, Ordering::Relaxed);
                    shared.complete(
                        ticket,
                        Err(CommitError::Refused(format!(
                            "the lease change did not commit within {} ms",
                            wait.as_millis()
                        ))),
                    );
                    propose.await
                }
            };
            match result {
                Ok(committed) => {
                    shared.leases.apply_at(built.lease, committed.revision);
                    shared.gate.committed();
                    shared.counters.committed.fetch_add(1, Ordering::Relaxed);
                    metrics::COMMIT_DURATION
                        .observe(u64::try_from(at.elapsed().as_micros()).unwrap_or(u64::MAX));
                    metrics::HISTORY_WRITTEN.fetch_add(1, Ordering::Relaxed);
                    if !late {
                        shared.complete(ticket, Ok(committed.revision));
                    }
                }
                Err(error) => {
                    shared.counters.refused.fetch_add(1, Ordering::Relaxed);
                    if is_refusal(&error) {
                        shared.gate.refused(&error.to_string());
                    } else {
                        tracing::warn!(%error, "a lease change was not committed");
                    }
                    if !late {
                        shared.complete(ticket, Err(CommitError::Refused(error.to_string())));
                    }
                }
            }
            keys
        }))
    }
}
