//! The DHCPv6 lease path (plan sections 2.1 and 2.2, WP9.1): the role's table of
//! `dhcp.leases6` in memory, the lease change the engine builds, and its commit before the
//! REPLY.
//!
//! It mirrors the DHCPv4 path of [`crate::lease`]:
//!
//! | Item | What | DHCPv4 counterpart |
//! |---|---|---|
//! | [`Lease6Table`], [`Lease6Index`], [`SharedLeases6`] | the rows by VRF and address, and per scope by client identity (IAID and DUID) | `LeaseTable`, `LeaseIndex`, `SharedLeases` |
//! | [`PendingChange6`] | the change of one message: up to [`MAX_BINDINGS`] bindings of one client, every field inline | `PendingChange` |
//! | [`store::Lease6Store`], [`store::MemLease6Store`] | the hand-off and its reference | `LeaseStore`, `MemLeaseStore` |
//! | [`commit::StoreLeases6`] | the lease store on the replicated store and its committer, sharing the refusal gate of the DHCPv4 store | `StoreLeases` |
//! | [`expiry::Expiry6Service`] | expiry as the leader service `dhcp.expiry6` | `ExpiryService` |
//!
//! One message is one change and one store batch: a REQUEST with two `IA_NA`s commits both
//! bindings, their history rows and their IPAM facts together, and the REPLY leaves after
//! that commit. There is no `by_client` table: the role derives its client index from the
//! rows (the rows are the truth, the index a view of them).

pub mod commit;
pub mod expiry;
pub mod store;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use tenko_core::{
    NodeId, PrefixId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, Lease6, Lease6Event, Lease6Kind, LeaseEventKind, Relay6Info,
        lease::{MAX_DUID, MAX_IDENTITY6, write_identity6},
    },
    net::Duid,
    serde_util::HexBytes,
};
use tokio::sync::Notify;

use crate::{
    feed::DhcpData,
    lease::{InlineBytes, TextBytes},
};

/// The most bindings one message changes: its `IA_NA`s and `IA_PD`s (WP9.2) together up
/// to this many; the engine answers the others with a status.
pub const MAX_BINDINGS: usize = 8;

/// The longest link-layer address kept (RFC 6939 allows any; Ethernet has six octets).
pub const MAX_LINK_LAYER: usize = 20;

/// The role's in-memory DHCPv6 leases. Lookups never allocate.
pub trait Lease6Table {
    /// The lease of an address.
    fn get(&self, vrf: VrfId, addr: Ipv6Addr) -> Option<&Lease6>;

    /// The latest lease of a client identity ([`Lease6::identity`]: IAID and DUID) in a
    /// scope, of one kind: an `IA_NA` and an `IA_PD` of one client may share an IAID (RFC
    /// 8415 section 12: the IAID is unique among the IAs of one type), so the kind is part
    /// of the key (WP9.2).
    fn by_client(&self, scope: PrefixId, kind: Lease6Kind, identity: &[u8]) -> Option<&Lease6>;

    /// The number of rows.
    fn len(&self) -> usize;

    /// Whether the table is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A held row and the revision that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    lease: Lease6,
    revision: Revision,
}

/// The rows of each client identity of a scope.
type ClientIndex = HashMap<Vec<u8>, Vec<(VrfId, Ipv6Addr)>>;

/// The production DHCPv6 lease table: the rules of the DHCPv4 [`crate::lease::LeaseIndex`]
/// (a row replaces the held one unless the held one is newer, by revision when both are
/// known, else by `cltt`; the client index points at the client's latest row in a scope).
#[derive(Debug, Clone, Default)]
pub struct Lease6Index {
    rows: HashMap<(VrfId, Ipv6Addr), Held>,
    clients: HashMap<(PrefixId, Lease6Kind), ClientIndex>,
    revision: Revision,
}

impl Lease6Index {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// A table holding `rows` at the table revision `revision`.
    pub fn from_rows(
        rows: impl IntoIterator<Item = (Lease6, Revision)>,
        revision: Revision,
    ) -> Self {
        let mut table = Self::new();
        for (lease, at) in rows {
            table.apply_at(lease, at);
        }
        table.revision = revision;
        table
    }

    /// The highest revision the table has applied.
    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// Records that the table holds every change up to `revision`.
    pub fn advance(&mut self, revision: Revision) {
        if revision > self.revision {
            self.revision = revision;
        }
    }

    /// The revision that wrote the row of an address.
    pub fn row_revision(&self, vrf: VrfId, addr: Ipv6Addr) -> Option<Revision> {
        self.rows.get(&(vrf, addr)).map(|held| held.revision)
    }

    /// The rows written at a revision after `revision`.
    pub fn rows_after(&self, revision: Revision) -> Vec<(Lease6, Revision)> {
        self.rows
            .values()
            .filter(|held| held.revision > revision)
            .map(|held| (held.lease.clone(), held.revision))
            .collect()
    }

    /// Every row, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Lease6> {
        self.rows.values().map(|held| &held.lease)
    }

    /// The rows by VRF and address, ordered.
    pub fn sorted_rows(&self) -> std::collections::BTreeMap<(VrfId, Ipv6Addr), Lease6> {
        self.rows
            .iter()
            .map(|(key, held)| (*key, held.lease.clone()))
            .collect()
    }

    /// The rows in each binding state.
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

    /// The rows expiry moves on at `now`: active bindings past their end, abandoned
    /// addresses past their hold.
    pub fn due(&self, now: Timestamp) -> Vec<(VrfId, Ipv6Addr)> {
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

    /// Takes a committed row written at `revision` (`Revision::ZERO` when unknown);
    /// whether it replaced or added a row.
    pub fn apply_at(&mut self, lease: Lease6, revision: Revision) -> bool {
        let key = (lease.vrf, lease.addr6());
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
        let scope = (lease.scope, lease.kind);
        let identity = lease.identity();
        let previous = self.rows.insert(key, Held { lease, revision });
        if revision > self.revision {
            self.revision = revision;
        }
        if let Some(previous) = previous {
            let held_identity = previous.lease.identity();
            let held_scope = (previous.lease.scope, previous.lease.kind);
            if held_scope != scope || held_identity != identity {
                self.detach(held_scope, &held_identity, key);
            }
        }
        let rows = self
            .clients
            .entry(scope)
            .or_default()
            .entry(identity)
            .or_default();
        if !rows.contains(&key) {
            rows.push(key);
        }
        true
    }

    /// Removes the row of an address; returns it.
    pub fn take(&mut self, vrf: VrfId, addr: Ipv6Addr) -> Option<Lease6> {
        let held = self.rows.remove(&(vrf, addr))?;
        self.detach(
            (held.lease.scope, held.lease.kind),
            &held.lease.identity(),
            (vrf, addr),
        );
        Some(held.lease)
    }

    fn detach(&mut self, scope: (PrefixId, Lease6Kind), identity: &[u8], key: (VrfId, Ipv6Addr)) {
        let Some(clients) = self.clients.get_mut(&scope) else {
            return;
        };
        let Some(rows) = clients.get_mut(identity) else {
            return;
        };
        rows.retain(|held| *held != key);
        if rows.is_empty() {
            clients.remove(identity);
            if clients.is_empty() {
                self.clients.remove(&scope);
            }
        }
    }
}

impl Lease6Table for Lease6Index {
    fn get(&self, vrf: VrfId, addr: Ipv6Addr) -> Option<&Lease6> {
        self.rows.get(&(vrf, addr)).map(|held| &held.lease)
    }

    fn by_client(&self, scope: PrefixId, kind: Lease6Kind, identity: &[u8]) -> Option<&Lease6> {
        let rows = self.clients.get(&(scope, kind))?.get(identity)?;
        rows.iter()
            .filter_map(|key| self.rows.get(key).map(|held| (key, &held.lease)))
            .max_by_key(|(key, lease)| (lease.cltt, key.1))
            .map(|(_, lease)| lease)
    }

    fn len(&self) -> usize {
        self.rows.len()
    }
}

#[derive(Debug, Default)]
struct SharedInner {
    table: RwLock<Lease6Index>,
    advanced: Notify,
}

/// The DHCPv6 lease table shared by the workers, the committer and the feed.
#[derive(Debug, Clone, Default)]
pub struct SharedLeases6(Arc<SharedInner>);

impl SharedLeases6 {
    /// A handle on `table`.
    pub fn new(table: Lease6Index) -> Self {
        Self(Arc::new(SharedInner {
            table: RwLock::new(table),
            advanced: Notify::new(),
        }))
    }

    /// A read guard.
    pub fn read(&self) -> RwLockReadGuard<'_, Lease6Index> {
        self.0.table.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// A write guard.
    pub fn write(&self) -> RwLockWriteGuard<'_, Lease6Index> {
        self.0.table.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes the waiters.
    pub fn changed(&self) {
        self.0.advanced.notify_waiters();
    }

    /// Applies a committed row at its revision.
    pub fn apply_at(&self, lease: Lease6, revision: Revision) -> bool {
        let applied = self.write().apply_at(lease, revision);
        self.changed();
        applied
    }

    /// Replaces the whole table.
    pub fn install(&self, table: Lease6Index) {
        *self.write() = table;
        self.changed();
    }

    /// The table's revision.
    pub fn revision(&self) -> Revision {
        self.read().revision()
    }
}

/// A table built from an image of the feed.
pub fn index_from_data6(data: &DhcpData) -> Lease6Index {
    Lease6Index::from_rows(
        data.leases6
            .values()
            .map(|lease| (lease.clone(), data.revision)),
        data.revision,
    )
}

/// One binding of a [`PendingChange6`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding6 {
    /// What happened to it.
    pub event: LeaseEventKind,
    /// Address or prefix.
    pub kind: Lease6Kind,
    /// The VRF of its scope.
    pub vrf: VrfId,
    /// Its scope (a sibling of the selected one in a shared network).
    pub scope: PrefixId,
    /// The identity association.
    pub iaid: u32,
    /// The address, or the prefix's first address.
    pub addr: Ipv6Addr,
    /// 128 for an address, the delegated length for a prefix.
    pub prefix_len: u8,
    /// The state after the change.
    pub state: BindingState,
    /// The end of the preferred lifetime.
    pub preferred_ends: Timestamp,
    /// The end of the state (the valid lifetime of an active binding).
    pub ends: Timestamp,
}

/// What the relay closest to the client said, inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRelay6 {
    /// The link address of the closest relay.
    pub link_address: Ipv6Addr,
    /// The client's address as that relay saw it.
    pub peer_address: Ipv6Addr,
    /// The relays the request passed.
    pub hops: u8,
    /// The Interface-Id of the closest relay that sent one.
    pub interface_id: InlineBytes<64>,
    /// The Remote-Id of the closest relay that sent one.
    pub remote_id: InlineBytes<64>,
}

/// The lease change of one DHCPv6 message: no field on the heap, so that building it and
/// handing it off allocates nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChange6 {
    /// The client's DUID.
    pub duid: InlineBytes<MAX_DUID>,
    /// The client's link-layer address (RFC 6939, else from its DUID) and its type.
    pub link_layer: Option<(u16, InlineBytes<MAX_LINK_LAYER>)>,
    /// The client's transaction time.
    pub cltt: Timestamp,
    /// The name of option 39, as text.
    pub fqdn: TextBytes,
    /// The flags of option 39 in the layout of option 81.
    pub fqdn_flags: Option<u8>,
    /// The relay.
    pub relay: Option<PendingRelay6>,
    bindings: [Binding6; MAX_BINDINGS],
    count: usize,
}

impl PendingChange6 {
    /// A change for the client of `duid` at `cltt`, without bindings yet.
    pub fn new(duid: &[u8], cltt: Timestamp) -> Self {
        let empty = Binding6 {
            event: LeaseEventKind::Granted,
            kind: Lease6Kind::Na,
            vrf: VrfId::from_uuid(uuid::Uuid::nil()),
            scope: PrefixId::from_uuid(uuid::Uuid::nil()),
            iaid: 0,
            addr: Ipv6Addr::UNSPECIFIED,
            prefix_len: 128,
            state: BindingState::Free,
            preferred_ends: cltt,
            ends: cltt,
        };
        Self {
            duid: InlineBytes::new(duid).0,
            link_layer: None,
            cltt,
            fqdn: TextBytes::default(),
            fqdn_flags: None,
            relay: None,
            bindings: [empty; MAX_BINDINGS],
            count: 0,
        }
    }

    /// Clears the bindings and sets the client, keeping the storage.
    pub fn reset(&mut self, duid: &[u8], cltt: Timestamp) {
        self.duid.set(duid);
        self.link_layer = None;
        self.cltt = cltt;
        self.fqdn = TextBytes::default();
        self.fqdn_flags = None;
        self.relay = None;
        self.count = 0;
    }

    /// Adds a binding; false when the change holds [`MAX_BINDINGS`] already.
    pub fn push(&mut self, binding: Binding6) -> bool {
        if self.count == MAX_BINDINGS {
            return false;
        }
        self.bindings[self.count] = binding;
        self.count += 1;
        true
    }

    /// The bindings.
    pub fn bindings(&self) -> &[Binding6] {
        &self.bindings[..self.count]
    }

    /// Whether the change binds nothing.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The identity of a binding's client: its IAID and the DUID, written into `out`.
    pub fn identity(&self, iaid: u32, out: &mut [u8; MAX_IDENTITY6]) -> usize {
        write_identity6(iaid, self.duid.as_slice(), out)
    }

    /// The lease row of `binding` after the change. Fields the change does not carry (the
    /// DDNS outcome, the observation time, the name and the relay of a change that has
    /// none) come from the row held before, for the same client.
    pub fn to_lease(&self, binding: &Binding6, node: NodeId, previous: Option<&Lease6>) -> Lease6 {
        let duid = duid_of(self.duid.as_slice());
        let same_client =
            previous.is_some_and(|held| held.duid == duid && held.iaid == binding.iaid);
        let relay = self.relay.map(|relay| Relay6Info {
            link_address: relay.link_address,
            peer_address: relay.peer_address,
            hops: relay.hops,
            interface_id: (!relay.interface_id.is_empty())
                .then(|| HexBytes(relay.interface_id.as_slice().to_vec())),
            remote_id: (!relay.remote_id.is_empty())
                .then(|| HexBytes(relay.remote_id.as_slice().to_vec())),
        });
        let kept = previous.filter(|_| same_client);
        Lease6 {
            addr: IpAddr::V6(binding.addr),
            prefix_len: binding.prefix_len,
            kind: binding.kind,
            vrf: binding.vrf,
            scope: binding.scope,
            iaid: binding.iaid,
            duid,
            link_layer: self
                .link_layer
                .map(|(_, octets)| HexBytes(octets.as_slice().to_vec()))
                .or_else(|| kept.and_then(|held| held.link_layer.clone())),
            link_layer_type: self
                .link_layer
                .map(|(kind, _)| kind)
                .or_else(|| kept.and_then(|held| held.link_layer_type)),
            state: binding.state,
            cltt: self.cltt,
            ends: binding.ends,
            preferred_ends: binding.preferred_ends,
            node,
            fqdn: self
                .fqdn
                .to_text()
                .or_else(|| kept.and_then(|held| held.fqdn.clone())),
            fqdn_flags: self
                .fqdn_flags
                .or_else(|| kept.and_then(|held| held.fqdn_flags)),
            relay: relay.or_else(|| kept.and_then(|held| held.relay.clone())),
            observed_at: kept.and_then(|held| held.observed_at),
            ddns: kept.map(|held| held.ddns.clone()).unwrap_or_default(),
        }
    }

    /// The history row of `binding`.
    pub fn to_event(&self, binding: &Binding6, node: NodeId) -> Lease6Event {
        Lease6Event {
            at: self.cltt,
            kind: binding.event,
            addr: binding.addr,
            prefix_len: binding.prefix_len,
            vrf: binding.vrf,
            scope: binding.scope,
            iaid: binding.iaid,
            duid: duid_of(self.duid.as_slice()),
            state: binding.state,
            ends: binding.ends,
            node,
            link_layer: self
                .link_layer
                .map(|(_, octets)| HexBytes(octets.as_slice().to_vec())),
            link_layer_type: self.link_layer.map(|(kind, _)| kind),
        }
    }
}

/// The DUID of a change. The engine takes it from the codec, whose bounds (3 to 130
/// octets) lie inside the model's (2 to 130), so it always validates; a change built by
/// hand with a shorter one gets the two-octet DUID of type 0.
fn duid_of(octets: &[u8]) -> Duid {
    Duid::new(octets.to_vec())
        .unwrap_or_else(|_| Duid::new(vec![0, 0]).expect("two octets are a valid DUID"))
}
