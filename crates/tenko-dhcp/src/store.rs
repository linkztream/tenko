//! The lease store (plan section 2.1, ADR 0019 points 3 and 4): where the DORA path commits
//! a lease change before it answers.
//!
//! [`LeaseStore::submit`] is the hand-off: the worker copies its [`PendingChange`] into
//! the committer's queue and returns without blocking on the disk and without allocating
//! (the end of the no-allocation window of the DORA path, `tests/alloc.rs`). The committer
//! turns each change into one batch (the lease row, its client index row, the history row
//! and, from WP8.1, the IPAM observation fact) and reports each [`Ticket`] as committed or
//! refused through [`LeaseStore::completions`]; the worker side sends the ACK only for a
//! committed ticket. The production implementation is the store through the coalescer
//! (WP7.2); the asynchronous fallback of P3-Q1 would be a second implementation, not a
//! second engine. [`MemLeaseStore`] is the in-memory reference: its rows are the oracle of
//! the lease table and of the crash test.
//!
//! While the store refuses writes ([`LeaseStore::accepting`] is false, P3-Q14), the role
//! promises nothing it has not committed: it answers a renewal of an unexpired lease with
//! the time the lease still has and writes nothing, and drops new requests.

use std::{
    collections::{BTreeMap, VecDeque},
    net::Ipv4Addr,
    sync::{Mutex, PoisonError},
};

use tenko_core::{
    NodeId, PrefixId, Revision, VrfId,
    dhcp::{Lease, LeaseEvent, LeaseRef, lease::MAX_IDENTITY},
};

use crate::lease::PendingChange;

/// The caller's handle on a submitted change: the worker keeps its pending reply under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket(pub u64);

/// Why a change was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SubmitError {
    /// The committer's queue is full; the request is dropped and counted
    /// (`tenko_dhcp_dropped_total{reason="queue"}`), the client retries.
    #[error("the lease commit queue is full")]
    Full,
    /// The store refuses writes (P3-Q14).
    #[error("the store refuses lease writes")]
    Refused,
}

/// Why a submitted change did not commit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    /// The store refused the batch (`dhcp.store_refused`).
    #[error("the store refused the lease write: {0}")]
    Refused(String),
}

/// The result of one submitted change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    /// The ticket of the submission.
    pub ticket: Ticket,
    /// The revision of the commit, or why it failed.
    pub outcome: Result<Revision, CommitError>,
}

/// Commits lease changes before the role answers.
pub trait LeaseStore: Send + Sync {
    /// Hands a change to the committer and returns at once. Implementations neither
    /// allocate nor wait for I/O here; a bounded queue copies the change into a slot.
    ///
    /// # Errors
    ///
    /// [`SubmitError::Full`] when the queue has no slot, [`SubmitError::Refused`] while
    /// the store refuses writes.
    fn submit(&self, change: &PendingChange, ticket: Ticket) -> Result<(), SubmitError>;

    /// Appends the completions since the last call to `out`, in commit order.
    fn completions(&self, out: &mut Vec<Completion>);

    /// Whether the store accepts lease writes now (P3-Q14).
    fn accepting(&self) -> bool;
}

#[derive(Debug)]
struct MemInner {
    queue: VecDeque<(PendingChange, Ticket)>,
    capacity: usize,
    rows: BTreeMap<(VrfId, Ipv4Addr), Lease>,
    by_client: BTreeMap<(PrefixId, Vec<u8>), LeaseRef>,
    history: Vec<LeaseEvent>,
    completions: Vec<Completion>,
    revision: Revision,
    refusing: bool,
}

impl MemInner {
    fn reindex(&mut self, scope: PrefixId, identity: Vec<u8>) {
        match crate::lease::latest_row(&self.rows, scope, &identity) {
            Some((vrf, addr)) => {
                self.by_client
                    .insert((scope, identity), LeaseRef { vrf, addr });
            }
            None => {
                self.by_client.remove(&(scope, identity));
            }
        }
    }
}

/// The in-memory reference lease store: a bounded queue that [`MemLeaseStore::commit`]
/// drains into rows as the production committer would, one revision per change.
#[derive(Debug)]
pub struct MemLeaseStore {
    node: NodeId,
    inner: Mutex<MemInner>,
}

impl MemLeaseStore {
    /// A store for `node` whose queue holds `capacity` changes; the queue and the
    /// completion list are allocated now, so [`LeaseStore::submit`] never allocates.
    pub fn with_capacity(node: NodeId, capacity: usize) -> Self {
        Self {
            node,
            inner: Mutex::new(MemInner {
                queue: VecDeque::with_capacity(capacity),
                capacity,
                rows: BTreeMap::new(),
                by_client: BTreeMap::new(),
                history: Vec::new(),
                completions: Vec::with_capacity(capacity),
                revision: Revision::ZERO,
                refusing: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes the store refuse (or accept again), as the store's test hook does (WP6.2).
    /// Changes already queued fail when committed while it refuses.
    pub fn set_refusing(&self, refusing: bool) {
        self.lock().refusing = refusing;
    }

    /// Commits every queued change in order, one revision each, and returns how many it
    /// took. The rows follow the rules of the production batch: the lease row, the client
    /// index (moved when a client changes address, removed when another client takes the
    /// address) and a history row.
    pub fn commit(&self) -> usize {
        let mut inner = self.lock();
        let mut count = 0;
        while let Some((change, ticket)) = inner.queue.pop_front() {
            count += 1;
            if inner.refusing {
                inner.completions.push(Completion {
                    ticket,
                    outcome: Err(CommitError::Refused("the store refuses writes".to_owned())),
                });
                continue;
            }
            let key = (change.vrf, change.addr);
            let previous = inner.rows.get(&key).cloned();
            let lease = change.to_lease(self.node, previous.as_ref());
            let mut identity = [0u8; MAX_IDENTITY];
            let len = change.identity(&mut identity);
            let identity = identity[..len].to_vec();
            let scope = lease.scope;
            inner.history.push(change.to_event(self.node));
            inner.rows.insert(key, lease);
            // The index points at each client's latest row in a scope: the changed client's,
            // and the previous holder's, which may hold another row or none.
            if let Some(previous) = &previous {
                inner.reindex(previous.scope, previous.client.identity());
            }
            inner.reindex(scope, identity);
            inner.revision = inner.revision.next();
            let revision = inner.revision;
            inner.completions.push(Completion {
                ticket,
                outcome: Ok(revision),
            });
        }
        count
    }

    /// The committed lease rows.
    pub fn leases(&self) -> BTreeMap<(VrfId, Ipv4Addr), Lease> {
        self.lock().rows.clone()
    }

    /// The committed client index.
    pub fn client_index(&self) -> BTreeMap<(PrefixId, Vec<u8>), LeaseRef> {
        self.lock().by_client.clone()
    }

    /// The committed history rows, in commit order.
    pub fn history(&self) -> Vec<LeaseEvent> {
        self.lock().history.clone()
    }

    /// The revision of the last commit.
    pub fn revision(&self) -> Revision {
        self.lock().revision
    }

    /// The number of queued changes.
    pub fn queued(&self) -> usize {
        self.lock().queue.len()
    }
}

impl LeaseStore for MemLeaseStore {
    fn submit(&self, change: &PendingChange, ticket: Ticket) -> Result<(), SubmitError> {
        let mut inner = self.lock();
        if inner.refusing {
            return Err(SubmitError::Refused);
        }
        if inner.queue.len() >= inner.capacity {
            return Err(SubmitError::Full);
        }
        inner.queue.push_back((change.clone(), ticket));
        Ok(())
    }

    fn completions(&self, out: &mut Vec<Completion>) {
        out.append(&mut self.lock().completions);
    }

    fn accepting(&self) -> bool {
        !self.lock().refusing
    }
}
