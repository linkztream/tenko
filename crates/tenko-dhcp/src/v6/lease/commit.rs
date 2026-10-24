//! The production [`Lease6Store`]: DHCPv6 lease changes committed through the store's
//! coalescer before the REPLY leaves (plan section 2.1, P3-Q1, ADR 0019), as
//! [`crate::lease::StoreLeases`] commits DHCPv4 changes.
//!
//! [`StoreLeases6::submit6`] copies the change into a queue allocated up front and wakes
//! the [`Committer6`]. The committer builds each change into one batch ([`build`]: a
//! `dhcp.leases6` row and a `dhcp.history6` row per binding, and the IPAM facts of the
//! source `dhcp:<node>` through the [`Observation6Hook`]), proposes the batches
//! concurrently with the changes that touch the same address or client one after another,
//! applies a committed batch's rows to the role's [`SharedLeases6`] and only then reports
//! the ticket committed. It shares the [`RefusalGate`] of the role's DHCPv4 lease store, so
//! one refusal of the store closes both families' hand-offs and one commit opens them.

use std::{
    collections::{HashSet, VecDeque},
    hash::{BuildHasher, Hash, RandomState},
    pin::pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tenko_core::{
    NodeId, Principal, Revision, SystemComponent, Timestamp,
    dhcp::{Lease6, lease::MAX_IDENTITY6, tables},
};
use tenko_store::{Store, StoreError, WriteBatch};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::{
    Lease6Table, PendingChange6, SharedLeases6,
    store::{Lease6Store, held_by_other6},
};
use crate::{
    lease::{CommitSettings, CommitStats, metrics, refusal::RefusalGate},
    store::{CommitError, Completion, SubmitError, Ticket},
};

/// Adds the IPAM facts of a DHCPv6 lease change to its batch (plan section 2.8).
pub trait Observation6Hook: Send + Sync {
    /// Adds the facts of `lease` (the row after the change) to `batch` when they are due,
    /// and returns the time to record as the row's `observed_at`.
    ///
    /// # Errors
    ///
    /// A store error when a fact does not encode; the change then fails.
    fn observe6(
        &self,
        lease: &Lease6,
        previous: Option<&Lease6>,
        batch: &mut WriteBatch,
    ) -> Result<Option<Timestamp>, StoreError>;
}

/// No observation facts.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObservations6;

impl Observation6Hook for NoObservations6 {
    fn observe6(
        &self,
        _lease: &Lease6,
        _previous: Option<&Lease6>,
        _batch: &mut WriteBatch,
    ) -> Result<Option<Timestamp>, StoreError> {
        Ok(None)
    }
}

/// Why a change was not turned into a batch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Build6Error {
    /// Another client holds an address of the change (`dhcp.lease.state`).
    #[error("an address is held by another client")]
    HeldByOther,
    /// A row did not encode.
    #[error("the lease change did not encode: {0}")]
    Encode(String),
}

/// Builds the batch of one change: per binding the row (completed from the row held
/// before) and its history row, and the observation facts. `previous` gives the row the
/// table holds at an address.
///
/// # Errors
///
/// [`Build6Error::HeldByOther`] for an address another client holds,
/// [`Build6Error::Encode`] when a row does not encode.
pub fn build<'t>(
    change: &PendingChange6,
    node: NodeId,
    previous: impl Fn(&super::Binding6) -> Option<&'t Lease6>,
    hook: &dyn Observation6Hook,
    now: Timestamp,
) -> Result<(WriteBatch, Vec<Lease6>), Build6Error> {
    if change
        .bindings()
        .iter()
        .any(|binding| held_by_other6(change, binding, previous(binding), now))
    {
        return Err(Build6Error::HeldByOther);
    }
    let encode = |error: StoreError| Build6Error::Encode(error.to_string());
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
    let mut rows = Vec::with_capacity(change.bindings().len());
    for binding in change.bindings() {
        let held = previous(binding);
        let mut lease = change.to_lease(binding, node, held);
        // A row never moves back in client time (the table's rule and the store agree).
        if let Some(held) = held
            && held.cltt > lease.cltt
        {
            lease.cltt = held.cltt;
        }
        if let Some(observed) = hook.observe6(&lease, held, &mut batch).map_err(encode)? {
            lease.observed_at = Some(observed);
        }
        let key = (lease.vrf, lease.addr6());
        batch
            .put_typed(&tables::LEASES6, &key, &lease)
            .map_err(encode)?;
        let mut event = change.to_event(binding, node);
        event.at = lease.cltt;
        batch
            .put_typed(
                &tables::HISTORY6,
                &(event.at, event.vrf, event.addr),
                &event,
            )
            .map_err(encode)?;
        rows.push(lease);
    }
    Ok((batch, rows))
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
    change: PendingChange6,
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
    gate: Arc<RefusalGate>,
    leases: SharedLeases6,
    counters: Counters,
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

/// The DHCPv6 lease store on the replicated store: the hand-off side.
#[derive(Clone)]
pub struct StoreLeases6 {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for StoreLeases6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreLeases6")
            .field("node", &self.shared.node)
            .finish_non_exhaustive()
    }
}

/// The committer task of a [`StoreLeases6`]; run it with [`Committer6::run`].
pub struct Committer6 {
    shared: Arc<Shared>,
    store: Arc<dyn Store>,
    hook: Arc<dyn Observation6Hook>,
    settings: CommitSettings,
    hasher: RandomState,
}

impl std::fmt::Debug for Committer6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Committer6")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl StoreLeases6 {
    /// A DHCPv6 lease store for `node` that commits to `store`, applies its commits to
    /// `leases`, adds the facts of `hook` and shares `gate` with the DHCPv4 store; and its
    /// committer.
    pub fn new(
        store: Arc<dyn Store>,
        leases: SharedLeases6,
        node: NodeId,
        settings: CommitSettings,
        hook: Arc<dyn Observation6Hook>,
        gate: Arc<RefusalGate>,
    ) -> (Self, Committer6) {
        let capacity = settings.queue.max(1);
        let shared = Arc::new(Shared {
            node,
            capacity,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            wake: Notify::new(),
            completions: Mutex::new(Vec::with_capacity(capacity)),
            done: Notify::new(),
            gate,
            leases,
            counters: Counters::default(),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            Committer6 {
                shared,
                store,
                hook,
                settings,
                hasher: RandomState::new(),
            },
        )
    }

    /// The table the committer applies its commits to.
    pub fn leases(&self) -> &SharedLeases6 {
        &self.shared.leases
    }

    /// The refusal state, shared with the DHCPv4 store.
    pub fn gate(&self) -> &RefusalGate {
        &self.shared.gate
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

impl Lease6Store for StoreLeases6 {
    fn submit6(&self, change: &PendingChange6, ticket: Ticket) -> Result<(), SubmitError> {
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

    fn completions6(&self, out: &mut Vec<Completion>) {
        out.append(
            &mut self
                .shared
                .completions
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    fn accepting6(&self) -> bool {
        self.shared.gate.accepting()
    }
}

fn is_refusal(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::NoQuorum
            | StoreError::Timeout
            | StoreError::ShuttingDown
            | StoreError::Storage(_)
    )
}

type InFlight = FuturesUnordered<BoxFuture<'static, Vec<u64>>>;

impl Committer6 {
    fn key_of(&self, value: impl Hash) -> u64 {
        self.hasher.hash_one(value)
    }

    /// The keys a change touches: each address, each client identity, and the client that
    /// holds each address now.
    fn keys(&self, change: &PendingChange6) -> Vec<u64> {
        let table = self.shared.leases.read();
        let mut keys = Vec::with_capacity(change.bindings().len() * 3);
        for binding in change.bindings() {
            let mut identity = [0u8; MAX_IDENTITY6];
            let len = change.identity(binding.iaid, &mut identity);
            keys.push(self.key_of((0u8, binding.vrf, binding.addr)));
            keys.push(self.key_of((1u8, binding.scope, &identity[..len])));
            if let Some(held) = table.get(binding.vrf, binding.addr) {
                keys.push(self.key_of((1u8, held.scope, held.identity().as_slice())));
            }
        }
        keys
    }

    /// Runs until `stop` fires; then waits for the batches in flight and fails the changes
    /// still queued.
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
            let keys = self.keys(&queued.change);
            let free = keys.iter().all(|key| !blocked.contains(key));
            blocked.extend(keys.iter().copied());
            if free && inflight.len() < max {
                if let Some(future) = self.start(&queued, keys.clone()) {
                    busy.extend(keys);
                    inflight.push(future);
                }
            } else {
                deferred.push_back(queued);
            }
        }
    }

    fn start(&self, queued: &Queued, keys: Vec<u64>) -> Option<BoxFuture<'static, Vec<u64>>> {
        let now = Timestamp::now();
        let built = {
            let table = self.shared.leases.read();
            build(
                &queued.change,
                self.shared.node,
                |binding| table.get(binding.vrf, binding.addr),
                self.hook.as_ref(),
                now,
            )
        };
        let (batch, rows) = match built {
            Ok(built) => built,
            Err(error) => {
                if error == Build6Error::HeldByOther {
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
            let mut propose = pin!(store.propose(batch));
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
                    let count = u64::try_from(rows.len()).unwrap_or(u64::MAX);
                    {
                        let mut table = shared.leases.write();
                        for row in rows {
                            table.apply_at(row, committed.revision);
                        }
                    }
                    shared.leases.changed();
                    shared.gate.committed();
                    shared.counters.committed.fetch_add(1, Ordering::Relaxed);
                    metrics::COMMIT_DURATION
                        .observe(u64::try_from(at.elapsed().as_micros()).unwrap_or(u64::MAX));
                    metrics::HISTORY_WRITTEN.fetch_add(count, Ordering::Relaxed);
                    if !late {
                        shared.complete(ticket, Ok(committed.revision));
                    }
                }
                Err(error) => {
                    shared.counters.refused.fetch_add(1, Ordering::Relaxed);
                    if is_refusal(&error) {
                        shared.gate.refused(&error.to_string());
                    } else {
                        tracing::warn!(%error, "a DHCPv6 lease change was not committed");
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
