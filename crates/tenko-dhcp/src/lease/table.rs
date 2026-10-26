//! The role's lease table (plan section 2.2): every row of `dhcp.leases` in memory, indexed
//! by address and by client, so that the DORA path never reads the store.
//!
//! [`LeaseIndex`] is the production [`LeaseTable`]: a hash map by VRF and address of
//! compact rows ([`super::row`]: the fields the DORA path reads inline, the client and the
//! rest in one boxed byte string), and a client index by a keyed hash of the scope and the
//! client identity whose entries list the addresses of that client's rows, so that moving
//! the index to a client's latest row never scans the table. Two clients whose hashes
//! collide share an entry and each lookup keeps only the rows of the client asked for, so
//! a collision costs a comparison, never a wrong answer. It follows the rules of the
//! reference [`MemLeaseTable`](super::MemLeaseTable) (`tests/lease_table.rs` checks the
//! two against each other on random sequences):
//!
//! - a row replaces the held one unless the held one is newer: written at a later revision
//!   when both revisions are known ([`LeaseIndex::apply_at`]), else with a later client
//!   transaction time (`cltt`). So the role's own commit and the feed's copy of it give one
//!   row whatever order they arrive in, and an older copy never overwrites a newer row;
//! - the client index points at the client's row with the latest `cltt` in a scope, then
//!   the highest address, as `dhcp.leases.by_client` does.
//!
//! A row costs about 148 octets in the map (with its key and its share of the spare
//! buckets) and 43 in the client index, plus its byte string: about 214 octets a lease all
//! in for the rows of M30, against about 1 KiB when the whole `Lease` sat in the map
//! (`bench/phase3-dhcp/results/2026-10-26-e32-after-memory.md`).
//!
//! [`SharedLeases`] is the handle the workers read through (a read lock per lookup, which
//! does not allocate) and the committer and the feed write through; it also tells waiters
//! when the table reaches a revision.

use std::{
    collections::{BTreeMap, HashMap},
    hash::{BuildHasher, RandomState},
    net::Ipv4Addr,
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use tenko_core::{
    PrefixId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, Lease, LeaseRef, lease::MAX_IDENTITY, write_identity},
};
use tokio::sync::Notify;

use super::{
    LeaseTable,
    row::{LeaseView, Row},
};

/// The key of a row: its VRF and address.
type Key = (VrfId, Ipv4Addr);

/// The rows of one entry of the client index: usually one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Keys {
    One(Key),
    Many(Box<[Key]>),
}

impl Keys {
    fn as_slice(&self) -> &[Key] {
        match self {
            Self::One(key) => std::slice::from_ref(key),
            Self::Many(keys) => keys,
        }
    }
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
    rows: HashMap<Key, Row>,
    /// The keyed hash of a scope and a client identity, to the rows of that client there.
    clients: HashMap<u64, Keys>,
    hasher: RandomState,
    revision: Revision,
    /// The encoder's buffer, so that a row costs one allocation of its own size.
    scratch: Vec<u8>,
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
            clients: HashMap::with_capacity(capacity),
            ..Self::default()
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
        self.rows.get(&(vrf, addr)).map(|row| row.revision)
    }

    /// The rows written at a revision after `revision`, with their revisions.
    pub fn rows_after(&self, revision: Revision) -> Vec<(Lease, Revision)> {
        self.rows
            .iter()
            .filter(|(_, row)| row.revision > revision)
            .map(|(key, row)| (row.to_lease(key.0, key.1), row.revision))
            .collect()
    }

    /// Every row as the DORA path reads it, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = LeaseView<'_>> {
        self.rows.iter().map(|(key, row)| row.view(key.0, key.1))
    }

    /// Every row whole, in no particular order (allocates per row).
    pub fn leases(&self) -> impl Iterator<Item = Lease> + '_ {
        self.rows
            .iter()
            .map(|(key, row)| row.to_lease(key.0, key.1))
    }

    /// The rows by VRF and address, ordered: for comparisons with the store and the
    /// reference table.
    pub fn sorted_rows(&self) -> BTreeMap<(VrfId, Ipv4Addr), Lease> {
        self.rows
            .iter()
            .map(|(key, row)| (*key, row.to_lease(key.0, key.1)))
            .collect()
    }

    /// The client index, ordered as `dhcp.leases.by_client` is keyed.
    pub fn client_index(&self) -> BTreeMap<(PrefixId, Vec<u8>), LeaseRef> {
        let mut out = BTreeMap::new();
        let mut identity = [0u8; MAX_IDENTITY];
        for row in self.rows.values() {
            let len = row.client().identity(&mut identity);
            let entry = (row.scope, identity[..len].to_vec());
            if out.contains_key(&entry) {
                continue;
            }
            if let Some((vrf, addr)) = self.best(row.scope, &identity[..len], None, None) {
                out.insert(entry, LeaseRef { vrf, addr });
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
        for row in self.rows.values() {
            if let Some(slot) = counts.iter_mut().find(|(state, _)| *state == row.state) {
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
            .filter(|(_, row)| {
                matches!(row.state, BindingState::Active | BindingState::Abandoned)
                    && row.ends <= now
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
                held.cltt > lease.cltt
            };
            if newer_held {
                return false;
            }
        }
        let scope = lease.scope;
        let mut identity = [0u8; MAX_IDENTITY];
        let len = identity_of(&lease, &mut identity);
        let row = Row::new(&lease, revision, &mut self.scratch);
        drop(lease);
        let previous = self.rows.insert(key, row);
        if revision > self.revision {
            self.revision = revision;
        }
        if let Some(previous) = previous {
            let mut held_identity = [0u8; MAX_IDENTITY];
            let held_len = previous.client().identity(&mut held_identity);
            if previous.scope != scope || held_identity[..held_len] != identity[..len] {
                self.detach(previous.scope, &held_identity[..held_len], key);
            }
        }
        self.attach(scope, &identity[..len], key);
        true
    }

    /// Removes the row of an address; returns it.
    pub fn take(&mut self, vrf: VrfId, addr: Ipv4Addr) -> Option<Lease> {
        let row = self.rows.remove(&(vrf, addr))?;
        let mut identity = [0u8; MAX_IDENTITY];
        let len = row.client().identity(&mut identity);
        self.detach(row.scope, &identity[..len], (vrf, addr));
        Some(row.to_lease(vrf, addr))
    }

    fn client_hash(&self, scope: PrefixId, identity: &[u8]) -> u64 {
        self.hasher.hash_one((scope, identity))
    }

    fn attach(&mut self, scope: PrefixId, identity: &[u8], key: Key) {
        let hash = self.client_hash(scope, identity);
        match self.clients.get_mut(&hash) {
            None => {
                self.clients.insert(hash, Keys::One(key));
            }
            Some(keys) if keys.as_slice().contains(&key) => {}
            Some(keys) => {
                let grown: Box<[Key]> = keys
                    .as_slice()
                    .iter()
                    .copied()
                    .chain(std::iter::once(key))
                    .collect();
                *keys = Keys::Many(grown);
            }
        }
    }

    fn detach(&mut self, scope: PrefixId, identity: &[u8], key: Key) {
        let hash = self.client_hash(scope, identity);
        let Some(keys) = self.clients.get_mut(&hash) else {
            return;
        };
        let left: Vec<Key> = keys
            .as_slice()
            .iter()
            .copied()
            .filter(|held| *held != key)
            .collect();
        match left.as_slice() {
            [] => {
                self.clients.remove(&hash);
            }
            [one] => *keys = Keys::One(*one),
            _ => *keys = Keys::Many(left.into_boxed_slice()),
        }
    }

    /// The client's row with the latest `cltt`, then the highest address, among its rows
    /// in `scope` other than `skip`, and `extra` (a key and the `cltt` of a row about to be
    /// written there). Does not allocate.
    fn best(
        &self,
        scope: PrefixId,
        identity: &[u8],
        skip: Option<Key>,
        extra: Option<(Key, Timestamp)>,
    ) -> Option<Key> {
        let mut best: Option<(Timestamp, Ipv4Addr, Key)> = None;
        let mut consider = |key: Key, cltt: Timestamp| {
            let rank = (cltt, key.1);
            if best.is_none_or(|(best_cltt, best_addr, _)| rank > (best_cltt, best_addr)) {
                best = Some((cltt, key.1, key));
            }
        };
        let keys = self
            .clients
            .get(&self.client_hash(scope, identity))
            .map_or(&[][..], Keys::as_slice);
        for key in keys {
            if Some(*key) == skip {
                continue;
            }
            if let Some(row) = self.rows.get(key)
                && row.scope == scope
                && row.client().is(identity)
            {
                consider(*key, row.cltt);
            }
        }
        if let Some((key, cltt)) = extra {
            consider(key, cltt);
        }
        best.map(|(_, _, key)| key)
    }

    /// The entries of the client index that applying `lease` in place of the row held at
    /// its address would change: the new client's entry when it moves, and the previous
    /// holder's when another client held the address. The batch of a lease change writes
    /// exactly these (`dhcp.leases.by_client`).
    pub fn index_after(&self, lease: &Lease) -> Vec<IndexUpdate> {
        let key = (lease.vrf, lease.addr);
        let mut out = Vec::new();
        let identity = lease.client.identity();
        let current = self.best(lease.scope, &identity, None, None);
        let best = self.best(lease.scope, &identity, Some(key), Some((key, lease.cltt)));
        if best != current {
            out.push(IndexUpdate {
                scope: lease.scope,
                identity: identity.clone(),
                target: best.map(|(vrf, addr)| LeaseRef { vrf, addr }),
            });
        }
        if let Some(previous) = self.rows.get(&key) {
            let mut held = [0u8; MAX_IDENTITY];
            let held_len = previous.client().identity(&mut held);
            let held_identity = &held[..held_len];
            if previous.scope != lease.scope || held_identity != identity.as_slice() {
                let current = self.best(previous.scope, held_identity, None, None);
                let best = self.best(previous.scope, held_identity, Some(key), None);
                if best != current {
                    out.push(IndexUpdate {
                        scope: previous.scope,
                        identity: held_identity.to_vec(),
                        target: best.map(|(vrf, addr)| LeaseRef { vrf, addr }),
                    });
                }
            }
        }
        out
    }
}

impl LeaseTable for LeaseIndex {
    fn get(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<LeaseView<'_>> {
        self.rows.get(&(vrf, addr)).map(|row| row.view(vrf, addr))
    }

    fn by_client(&self, scope: PrefixId, identity: &[u8]) -> Option<LeaseView<'_>> {
        let (vrf, addr) = self.best(scope, identity, None, None)?;
        self.get(vrf, addr)
    }

    fn lease(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<Lease> {
        self.rows
            .get(&(vrf, addr))
            .map(|row| row.to_lease(vrf, addr))
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
