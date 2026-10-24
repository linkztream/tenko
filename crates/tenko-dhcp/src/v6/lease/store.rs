//! The DHCPv6 lease store (plan section 2.1): where the engine's change is committed before
//! the REPLY leaves. [`Lease6Store`] is the contract of [`crate::store::LeaseStore`] for a
//! [`PendingChange6`]; the tickets, completions and errors are the DHCPv4 ones.
//! [`MemLease6Store`] is the in-memory reference and the oracle of the engine's tests.

use std::{
    collections::{BTreeMap, VecDeque},
    net::Ipv6Addr,
    sync::{Mutex, PoisonError},
};

use tenko_core::{
    NodeId, Revision, Timestamp, VrfId,
    dhcp::{Lease6, Lease6Event, LeaseEventKind, lease::MAX_IDENTITY6},
};

use super::{Binding6, PendingChange6};
use crate::store::{CommitError, Completion, SubmitError, Ticket};

/// Commits DHCPv6 lease changes before the role answers.
pub trait Lease6Store: Send + Sync {
    /// Hands a change to the committer and returns at once, without allocating or waiting.
    ///
    /// # Errors
    ///
    /// [`SubmitError::Full`] when the queue has no slot, [`SubmitError::Refused`] while
    /// the store refuses writes.
    fn submit6(&self, change: &PendingChange6, ticket: Ticket) -> Result<(), SubmitError>;

    /// Appends the completions since the last call to `out`, in commit order.
    fn completions6(&self, out: &mut Vec<Completion>);

    /// Whether the store accepts lease writes now (P3-Q14).
    fn accepting6(&self) -> bool;
}

/// Whether `previous` stops `binding` of `change`: another client's binding, or an
/// abandoned address, that has not ended at `now`. A RELEASE or DECLINE of the holder and
/// an operator's reclaim may end it.
pub fn held_by_other6(
    change: &PendingChange6,
    binding: &Binding6,
    previous: Option<&Lease6>,
    now: Timestamp,
) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    if binding.event == LeaseEventKind::Reclaimed || !previous.blocks(now) {
        return false;
    }
    let mut identity = [0u8; MAX_IDENTITY6];
    let len = change.identity(binding.iaid, &mut identity);
    if previous.state == tenko_core::dhcp::BindingState::Abandoned {
        // A declined address is held for nobody until its hold ends.
        return true;
    }
    previous.identity() != identity[..len]
}

#[derive(Debug)]
struct MemInner {
    queue: VecDeque<(PendingChange6, Ticket)>,
    capacity: usize,
    rows: BTreeMap<(VrfId, Ipv6Addr), Lease6>,
    history: Vec<Lease6Event>,
    completions: Vec<Completion>,
    revision: Revision,
    refusing: bool,
}

/// The in-memory reference DHCPv6 lease store: a bounded queue that
/// [`MemLease6Store::commit`] drains into rows, one revision per change.
#[derive(Debug)]
pub struct MemLease6Store {
    node: NodeId,
    inner: Mutex<MemInner>,
}

impl MemLease6Store {
    /// A store for `node` whose queue holds `capacity` changes, allocated now.
    pub fn with_capacity(node: NodeId, capacity: usize) -> Self {
        Self {
            node,
            inner: Mutex::new(MemInner {
                queue: VecDeque::with_capacity(capacity),
                capacity,
                rows: BTreeMap::new(),
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

    /// Makes the store refuse (or accept again).
    pub fn set_refusing(&self, refusing: bool) {
        self.lock().refusing = refusing;
    }

    /// Commits every queued change at `now`, in order, and returns the rows written. A
    /// change with a binding another client holds is refused whole.
    pub fn commit(&self, now: Timestamp) -> Vec<Lease6> {
        let mut inner = self.lock();
        let mut written = Vec::new();
        while let Some((change, ticket)) = inner.queue.pop_front() {
            if inner.refusing {
                inner.completions.push(Completion {
                    ticket,
                    outcome: Err(CommitError::Refused("the store refuses".to_owned())),
                });
                continue;
            }
            let held = change.bindings().iter().any(|binding| {
                held_by_other6(
                    &change,
                    binding,
                    inner.rows.get(&(binding.vrf, binding.addr)),
                    now,
                )
            });
            if held {
                inner.completions.push(Completion {
                    ticket,
                    outcome: Err(CommitError::Refused(
                        "the address is held by another client".to_owned(),
                    )),
                });
                continue;
            }
            inner.revision = inner.revision.next();
            for binding in change.bindings() {
                let key = (binding.vrf, binding.addr);
                let lease = change.to_lease(binding, self.node, inner.rows.get(&key));
                let event = change.to_event(binding, self.node);
                inner.rows.insert(key, lease.clone());
                inner.history.push(event);
                written.push(lease);
            }
            let revision = inner.revision;
            inner.completions.push(Completion {
                ticket,
                outcome: Ok(revision),
            });
        }
        written
    }

    /// The committed rows.
    pub fn rows(&self) -> BTreeMap<(VrfId, Ipv6Addr), Lease6> {
        self.lock().rows.clone()
    }

    /// The history rows, in commit order.
    pub fn history(&self) -> Vec<Lease6Event> {
        self.lock().history.clone()
    }

    /// Changes waiting.
    pub fn queued(&self) -> usize {
        self.lock().queue.len()
    }
}

impl Lease6Store for MemLease6Store {
    fn submit6(&self, change: &PendingChange6, ticket: Ticket) -> Result<(), SubmitError> {
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

    fn completions6(&self, out: &mut Vec<Completion>) {
        out.append(&mut self.lock().completions);
    }

    fn accepting6(&self) -> bool {
        !self.lock().refusing
    }
}
