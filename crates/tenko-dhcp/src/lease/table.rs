//! The role's lease table (plan section 2.2): every row of `dhcp.leases` in memory, indexed
//! by address and by client, so that the DORA path never reads the store.
//!
//! [`LeaseIndex`] is the production [`LeaseTable`]: hash maps by VRF and address, and per
//! scope by client identity, with the rows of each client kept beside the index entry so
//! that moving the entry to a client's latest row never scans the table. It follows the
//! rules of the reference [`MemLeaseTable`](super::MemLeaseTable) (`tests/lease_table.rs`
//! checks the two against each other on random sequences):
//!
//! - a row replaces the held one unless the held one is newer: written at a later revision
//!   when both revisions are known ([`LeaseIndex::apply_at`]), else with a later client
//!   transaction time (`cltt`). So the role's own commit and the feed's copy of it give one
//!   row whatever order they arrive in, and an older copy never overwrites a newer row;
//! - the client index points at the client's row with the latest `cltt` in a scope, then
//!   the highest address, as `dhcp.leases.by_client` does.
//!
//! [`SharedLeases`] is the handle the workers read through (a read lock per lookup, which
//! does not allocate) and the committer and the feed write through; it also tells waiters
//! when the table reaches a revision.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use tenko_core::{
    PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease, LeaseRef, lease::MAX_IDENTITY, write_identity},
};
use tokio::sync::Notify;

use super::LeaseTable;

/// A held row and the revision that wrote it (`Revision::ZERO` when unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    lease: Lease,
    revision: Revision,
}

/// The rows of one client in one scope, and the index entry among them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ClientRows {
    rows: Vec<(VrfId, Ipv4Addr)>,
    best: Option<(VrfId, Ipv4Addr)>,
}

/// One entry of the client index that a lease change moves: the client of `scope` and
/// `identity` now points at `target`, or has no row left in the scope (`None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexUpdate {
    /// The scope.
    pub scope: PrefixId,
    /// The client identity ([`tenko_core::dhcp::ClientKey::identity`]).
    pub identity: Vec<u8>,
    /// Where the index entry points after the change.
    pub target: Option<LeaseRef>,
}

/// The production lease table.
#[derive(Debug, Clone, Default)]
pub struct LeaseIndex {
    rows: HashMap<(VrfId, Ipv4Addr), Held>,
    clients: HashMap<PrefixId, HashMap<Vec<u8>, ClientRows>>,
    revision: Revision,
}

/// The identity of a lease's client, written into a stack buffer.
fn identity_of(lease: &Lease, out: &mut [u8; MAX_IDENTITY]) -> usize {
    write_identity(
        lease.client.htype,
        &lease.client.chaddr.0,
        lease.client.client_id.as_ref().map(|id| id.0.as_slice()),
        out,
    )
}

impl LeaseIndex {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// A table with room for `capacity` rows.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            rows: HashMap::with_capacity(capacity),
            clients: HashMap::new(),
            revision: Revision::ZERO,
        }
    }

    /// A table holding `rows`, each written at the given revision, at the table revision
    /// `revision`.
    pub fn from_rows(
        rows: impl IntoIterator<Item = (Lease, Revision)>,
        revision: Revision,
    ) -> Self {
        let rows = rows.into_iter();
        let mut table = Self::with_capacity(rows.size_hint().0);
        for (lease, at) in rows {
            table.apply_at(lease, at);
        }
        table.revision = revision;
        table
    }

    /// The highest revision the table has applied (its own commits and the feed's).
    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// Records that the table holds every change up to `revision` (a feed delta's end).
    pub fn advance(&mut self, revision: Revision) {
        if revision > self.revision {
            self.revision = revision;
        }
    }

    /// The revision that wrote the row of an address, when known.
    pub fn row_revision(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<Revision> {
        self.rows.get(&(vrf, addr)).map(|held| held.revision)
    }

    /// The rows written at a revision after `revision`, with their revisions.
    pub fn rows_after(&self, revision: Revision) -> Vec<(Lease, Revision)> {
        self.rows
            .values()
            .filter(|held| held.revision > revision)
            .map(|held| (held.lease.clone(), held.revision))
            .collect()
    }

    /// Every row, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Lease> {
        self.rows.values().map(|held| &held.lease)
    }

    /// The rows by VRF and address, ordered: for comparisons with the store and the
    /// reference table.
    pub fn sorted_rows(&self) -> std::collections::BTreeMap<(VrfId, Ipv4Addr), Lease> {
        self.rows
            .iter()
            .map(|(key, held)| (*key, held.lease.clone()))
            .collect()
    }

    /// The client index, ordered as `dhcp.leases.by_client` is keyed.
    pub fn client_index(&self) -> std::collections::BTreeMap<(PrefixId, Vec<u8>), LeaseRef> {
        let mut out = std::collections::BTreeMap::new();
        for (scope, clients) in &self.clients {
            for (identity, rows) in clients {
                if let Some((vrf, addr)) = rows.best {
                    out.insert((*scope, identity.clone()), LeaseRef { vrf, addr });
                }
            }
        }
        out
    }

    /// The rows in each binding state, for the lazy gauge `tenko_dhcp_leases{state}`.
    pub fn counts_by_state(&self) -> [(BindingState, usize); 7] {
        let mut counts = [
            (BindingState::Free, 0),
            (BindingState::Active, 0),
            (BindingState::Expired, 0),
            (BindingState::Released, 0),
            (BindingState::Abandoned, 0),
            (BindingState::Reset, 0),
            (BindingState::Backup, 0),
        ];
        for held in self.rows.values() {
            if let Some(slot) = counts
                .iter_mut()
                .find(|(state, _)| *state == held.lease.state)
            {
                slot.1 += 1;
            }
        }
        counts
    }

    /// The rows whose state ends at or before `now` and that expiry moves on: active
    /// bindings past their end, abandoned addresses past their hold.
    pub fn due(&self, now: Timestamp) -> Vec<(VrfId, Ipv4Addr)> {
        let mut due: Vec<_> = self
            .rows
            .iter()
            .filter(|(_, held)| {
                matches!(
                    held.lease.state,
                    BindingState::Active | BindingState::Abandoned
                ) && held.lease.ends <= now
            })
            .map(|(key, _)| *key)
            .collect();
        due.sort_unstable();
        due
    }

    /// Takes a committed row written at `revision` (`Revision::ZERO` when unknown) and
    /// returns whether it replaced or added a row. The held row stays when it was written
    /// at a later revision (both known), or when its `cltt` is later.
    pub fn apply_at(&mut self, lease: Lease, revision: Revision) -> bool {
        let key = (lease.vrf, lease.addr);
        if let Some(held) = self.rows.get(&key) {
            let newer_held = if held.revision != Revision::ZERO && revision != Revision::ZERO {
                held.revision > revision
            } else {
                held.lease.cltt > lease.cltt
            };
            if newer_held {
                return false;
            }
        }
        let scope = lease.scope;
        let mut identity = [0u8; MAX_IDENTITY];
        let len = identity_of(&lease, &mut identity);
        let previous = self.rows.insert(key, Held { lease, revision });
        if revision > self.revision {
            self.revision = revision;
        }
        if let Some(previous) = previous {
            let mut held_identity = [0u8; MAX_IDENTITY];
            let held_len = identity_of(&previous.lease, &mut held_identity);
            if previous.lease.scope != scope || held_identity[..held_len] != identity[..len] {
                self.detach(previous.lease.scope, &held_identity[..held_len], key);
            }
        }
        self.attach(scope, &identity[..len], key);
        true
    }

    /// Removes the row of an address; returns it.
    pub fn take(&mut self, vrf: VrfId, addr: Ipv4Addr) -> Option<Lease> {
        let held = self.rows.remove(&(vrf, addr))?;
        let mut identity = [0u8; MAX_IDENTITY];
        let len = identity_of(&held.lease, &mut identity);
        self.detach(held.lease.scope, &identity[..len], (vrf, addr));
        Some(held.lease)
    }

    fn attach(&mut self, scope: PrefixId, identity: &[u8], key: (VrfId, Ipv4Addr)) {
        let clients = self.clients.entry(scope).or_default();
        if !clients.contains_key(identity) {
            clients.insert(identity.to_vec(), ClientRows::default());
        }
        if let Some(entry) = clients.get_mut(identity) {
            if !entry.rows.contains(&key) {
                entry.rows.push(key);
            }
            entry.best = best_of(&self.rows, &entry.rows, None, None);
        }
    }

    fn detach(&mut self, scope: PrefixId, identity: &[u8], key: (VrfId, Ipv4Addr)) {
        let Some(clients) = self.clients.get_mut(&scope) else {
            return;
        };
        let Some(entry) = clients.get_mut(identity) else {
            return;
        };
        entry.rows.retain(|held| *held != key);
        if entry.rows.is_empty() {
            clients.remove(identity);
            if clients.is_empty() {
                self.clients.remove(&scope);
            }
        } else {
            entry.best = best_of(&self.rows, &entry.rows, None, None);
        }
    }

    /// The entries of the client index that applying `lease` in place of the row held at
    /// its address would change: the new client's entry when it moves, and the previous
    /// holder's when another client held the address. The batch of a lease change writes
    /// exactly these (`dhcp.leases.by_client`).
    pub fn index_after(&self, lease: &Lease) -> Vec<IndexUpdate> {
        let key = (lease.vrf, lease.addr);
        let mut out = Vec::new();
        let identity = lease.client.identity();
        let rows = self
            .clients
            .get(&lease.scope)
            .and_then(|clients| clients.get(identity.as_slice()));
        let current = rows.and_then(|rows| rows.best);
        let candidates: &[(VrfId, Ipv4Addr)] = rows.map_or(&[], |rows| rows.rows.as_slice());
        let best = best_of(&self.rows, candidates, Some(key), Some(lease));
        if best != current {
            out.push(IndexUpdate {
                scope: lease.scope,
                identity: identity.clone(),
                target: best.map(|(vrf, addr)| LeaseRef { vrf, addr }),
            });
        }
        if let Some(previous) = self.rows.get(&key).map(|held| &held.lease) {
            let held_identity = previous.client.identity();
            if previous.scope != lease.scope || held_identity != identity {
                let rows = self
                    .clients
                    .get(&previous.scope)
                    .and_then(|clients| clients.get(held_identity.as_slice()));
                let current = rows.and_then(|rows| rows.best);
                let candidates: &[(VrfId, Ipv4Addr)] =
                    rows.map_or(&[], |rows| rows.rows.as_slice());
                let remaining: Vec<(VrfId, Ipv4Addr)> = candidates
                    .iter()
                    .copied()
                    .filter(|held| *held != key)
                    .collect();
                let best = best_of(&self.rows, &remaining, None, None);
                if best != current {
                    out.push(IndexUpdate {
                        scope: previous.scope,
                        identity: held_identity,
                        target: best.map(|(vrf, addr)| LeaseRef { vrf, addr }),
                    });
                }
            }
        }
        out
    }
}

/// The client's row with the latest `cltt`, then the highest address, among `keys`; with
/// `replace`, the row at that key is `lease` (added when absent from `keys`).
fn best_of(
    rows: &HashMap<(VrfId, Ipv4Addr), Held>,
    keys: &[(VrfId, Ipv4Addr)],
    replace: Option<(VrfId, Ipv4Addr)>,
    lease: Option<&Lease>,
) -> Option<(VrfId, Ipv4Addr)> {
    let mut best: Option<(Timestamp, Ipv4Addr, (VrfId, Ipv4Addr))> = None;
    let mut consider = |key: (VrfId, Ipv4Addr), cltt: Timestamp| {
        let rank = (cltt, key.1);
        if best.is_none_or(|(best_cltt, best_addr, _)| rank > (best_cltt, best_addr)) {
            best = Some((cltt, key.1, key));
        }
    };
    for key in keys {
        if Some(*key) == replace {
            continue;
        }
        if let Some(held) = rows.get(key) {
            consider(*key, held.lease.cltt);
        }
    }
    if let (Some(key), Some(lease)) = (replace, lease) {
        consider(key, lease.cltt);
    }
    best.map(|(_, _, key)| key)
}

impl LeaseTable for LeaseIndex {
    fn get(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<&Lease> {
        self.rows.get(&(vrf, addr)).map(|held| &held.lease)
    }

    fn by_client(&self, scope: PrefixId, identity: &[u8]) -> Option<&Lease> {
        let key = self.clients.get(&scope)?.get(identity)?.best?;
        self.get(key.0, key.1)
    }

    fn apply(&mut self, lease: Lease) {
        self.apply_at(lease, Revision::ZERO);
    }

    fn remove(&mut self, vrf: VrfId, addr: Ipv4Addr) {
        self.take(vrf, addr);
    }

    fn len(&self) -> usize {
        self.rows.len()
    }
}

#[derive(Debug, Default)]
struct SharedInner {
    table: RwLock<LeaseIndex>,
    advanced: Notify,
}

/// The lease table shared by the workers (readers), the committer and the feed (writers).
#[derive(Debug, Clone, Default)]
pub struct SharedLeases(Arc<SharedInner>);

impl SharedLeases {
    /// A handle on `table`.
    pub fn new(table: LeaseIndex) -> Self {
        Self(Arc::new(SharedInner {
            table: RwLock::new(table),
            advanced: Notify::new(),
        }))
    }

    /// A read guard: the DORA path's lookups. Does not allocate.
    pub fn read(&self) -> RwLockReadGuard<'_, LeaseIndex> {
        self.0.table.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// A write guard. Waiters on a revision are told when it is dropped through
    /// [`SharedLeases::changed`]; writers call it after a commit or a delta.
    pub fn write(&self) -> RwLockWriteGuard<'_, LeaseIndex> {
        self.0.table.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes the waiters of [`SharedLeases::wait_for`].
    pub fn changed(&self) {
        self.0.advanced.notify_waiters();
    }

    /// Applies a committed row at its revision and wakes the waiters.
    pub fn apply_at(&self, lease: Lease, revision: Revision) -> bool {
        let applied = self.write().apply_at(lease, revision);
        self.changed();
        applied
    }

    /// Replaces the whole table, as a reset of the feed does: the new one is built aside.
    pub fn install(&self, table: LeaseIndex) {
        *self.write() = table;
        self.changed();
    }

    /// The table's revision.
    pub fn revision(&self) -> Revision {
        self.read().revision()
    }

    /// Waits until the table holds `revision`, at most `bound`; returns whether it does.
    pub async fn wait_for(&self, revision: Revision, bound: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + bound;
        loop {
            let notified = self.0.advanced.notified();
            if self.revision() >= revision {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.revision() >= revision;
            }
        }
    }
}
