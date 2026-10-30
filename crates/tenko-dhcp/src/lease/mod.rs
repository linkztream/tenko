//! The lease table and the lease change (plan sections 2.1 and 2.2, ADR 0019 point 3), and
//! the lease path on the store (WP7.2).
//!
//! The role keeps its leases in memory, indexed by address and by client, and never reads
//! the store on the DORA path. [`LeaseTable`] is the contract; [`MemLeaseTable`] is the
//! reference implementation (ordered maps) and [`LeaseIndex`] the production one. The table
//! takes the role's own committed rows at once and the feed's copy of the same rows again:
//! [`LeaseTable::apply`] keeps the row with the later client transaction time (and
//! [`LeaseIndex::apply_at`] the row of the later revision), so applying a row twice, or an
//! older copy after a newer one, changes nothing and the table equals the store's rows.
//!
//! A [`PendingChange`] is what the DORA path hands to the [`LeaseStore`](crate::store::LeaseStore):
//! every field in fixed-capacity storage, so building and handing it off allocates nothing
//! (the counting-allocator test, `tests/alloc.rs`). The committer turns it into the rows
//! of the batch ([`PendingChange::to_lease`], [`PendingChange::to_event`]) off the DORA
//! path.
//!
//! The lease path of WP7.2 (`docs/dhcp.md` section 7):
//!
//! | Module | What |
//! |---|---|
//! | [`table`] | [`LeaseIndex`], the production table, and [`SharedLeases`], its shared handle |
//! | [`batch`] | the lease change as one batch: row, client index, history, observation hook |
//! | [`commit`] | [`StoreLeases`], the [`LeaseStore`](crate::store::LeaseStore) on the replicated store, and its [`Committer`] |
//! | [`follow`] | the table from the feed ([`LeaseFollower`]) and from a store view ([`rebuild_from_view`]) |
//! | [`observe`] | the IPAM facts of the lease batch ([`observe::IpamObservations`], WP8.1) |
//! | [`offer`] | [`OfferTable`], the offer hold |
//! | [`expiry`] | [`ExpiryService`], expiry as a leader service |
//! | [`history`] | [`PurgeService`], history retention per profile (P3-Q13) |
//! | [`refusal`] | [`RefusalGate`], the behaviour while the store refuses (P3-Q14) |
//! | [`metrics`] | the series the lease path counts |
//! | [`row`] | the table's compact row and [`LeaseView`], what the DORA path reads of a lease (E32) |

pub mod batch;
pub mod commit;
// WP9.6: the asynchronous writer of the history rows and the facts (ADR 0030).
pub mod derived;
pub mod expiry;
pub mod follow;
pub mod history;
pub mod metrics;
// WP8.1: the observation hook over the lease facts of IPAM.
pub mod observe;
pub mod offer;
pub mod refusal;
// E32: the compact row of the table and the view the DORA path reads.
pub mod row;
pub mod table;

pub use commit::{CommitSettings, CommitStats, Committer, StoreLeases};
pub use expiry::{ExpiryService, ExpirySettings};
pub use follow::{LeaseFollower, rebuild_from_view};
pub use history::{HistoryProfile, HistoryRetention, PurgeService, PurgeSettings};
pub use offer::OfferTable;
pub use refusal::{RefusalGate, WhileRefused};
pub use row::{ClientView, LeaseView};
pub use table::{LeaseIndex, SharedLeases};

use std::{collections::BTreeMap, net::Ipv4Addr};

use tenko_core::{
    NodeId, PrefixId, Timestamp, VrfId,
    dhcp::{
        BindingState, ClientKey, Fingerprint, Lease, LeaseEvent, LeaseEventKind, RelayInfo,
        lease::{MAX_CHADDR, MAX_CLIENT_ID, MAX_IDENTITY, write_identity},
    },
    serde_util::HexBytes,
};

use crate::v4::RelayAgentInfo;

/// The role's in-memory leases. Lookups never allocate.
///
/// E32: the lookups of the DORA path return a [`LeaseView`], the fields it reads borrowed
/// from the table, so that the production table can keep a compact row instead of a whole
/// [`Lease`]; [`LeaseTable::lease`] gives the whole row off the DORA path.
pub trait LeaseTable {
    /// The lease of an address.
    fn get(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<LeaseView<'_>>;

    /// The lease of a client identity in a scope ([`ClientKey::identity`]).
    fn by_client(&self, scope: PrefixId, identity: &[u8]) -> Option<LeaseView<'_>>;

    /// The whole row of an address, as the store holds it. Allocates; not for the DORA
    /// path.
    fn lease(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<Lease>;

    /// The whole row of a client identity in a scope ([`LeaseTable::by_client`], then
    /// [`LeaseTable::lease`]). Allocates; not for the DORA path.
    fn client_lease(&self, scope: PrefixId, identity: &[u8]) -> Option<Lease> {
        let found = self.by_client(scope, identity)?;
        self.lease(found.vrf, found.addr)
    }

    /// Takes a committed row: inserted when the address has none, replaced when its
    /// `cltt` is not older than the row held, ignored otherwise. The client index follows.
    fn apply(&mut self, lease: Lease);

    /// Removes the row of an address (a row deleted from the store).
    fn remove(&mut self, vrf: VrfId, addr: Ipv4Addr);

    /// The number of rows.
    fn len(&self) -> usize;

    /// Whether the table is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The reference lease table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemLeaseTable {
    rows: BTreeMap<(VrfId, Ipv4Addr), Lease>,
    by_client: BTreeMap<PrefixId, BTreeMap<Vec<u8>, (VrfId, Ipv4Addr)>>,
}

impl MemLeaseTable {
    /// A table holding `leases`.
    pub fn from_rows(leases: impl IntoIterator<Item = Lease>) -> Self {
        let mut table = Self::default();
        for lease in leases {
            table.apply(lease);
        }
        table
    }

    /// The rows, by VRF and address.
    pub fn rows(&self) -> &BTreeMap<(VrfId, Ipv4Addr), Lease> {
        &self.rows
    }

    /// Points the client's index entry of a scope at its row with the latest `cltt` (then
    /// the highest address), or removes it when the client holds no row there, so that the
    /// index does not depend on the order rows arrive in.
    fn reindex(&mut self, scope: PrefixId, identity: &[u8]) {
        let best = latest_row(&self.rows, scope, identity);
        let index = self.by_client.entry(scope).or_default();
        match best {
            Some(key) => {
                index.insert(identity.to_vec(), key);
            }
            None => {
                index.remove(identity);
            }
        }
    }
}

/// The key of the client's row in a scope with the latest `cltt`, then the highest address.
pub(crate) fn latest_row(
    rows: &BTreeMap<(VrfId, Ipv4Addr), Lease>,
    scope: PrefixId,
    identity: &[u8],
) -> Option<(VrfId, Ipv4Addr)> {
    rows.iter()
        .filter(|(_, lease)| lease.scope == scope && lease.client.identity() == identity)
        .max_by_key(|(key, lease)| (lease.cltt, key.1))
        .map(|(key, _)| *key)
}

impl LeaseTable for MemLeaseTable {
    fn get(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<LeaseView<'_>> {
        self.rows.get(&(vrf, addr)).map(LeaseView::of)
    }

    fn by_client(&self, scope: PrefixId, identity: &[u8]) -> Option<LeaseView<'_>> {
        let key = self.by_client.get(&scope)?.get(identity)?;
        self.rows.get(key).map(LeaseView::of)
    }

    fn lease(&self, vrf: VrfId, addr: Ipv4Addr) -> Option<Lease> {
        self.rows.get(&(vrf, addr)).cloned()
    }

    fn apply(&mut self, lease: Lease) {
        let key = (lease.vrf, lease.addr);
        if self
            .rows
            .get(&key)
            .is_some_and(|held| held.cltt > lease.cltt)
        {
            return;
        }
        let (scope, identity) = (lease.scope, lease.client.identity());
        if let Some(held) = self.rows.insert(key, lease) {
            self.reindex(held.scope, &held.client.identity());
        }
        self.reindex(scope, &identity);
    }

    fn remove(&mut self, vrf: VrfId, addr: Ipv4Addr) {
        if let Some(held) = self.rows.remove(&(vrf, addr)) {
            self.reindex(held.scope, &held.client.identity());
        }
    }

    fn len(&self) -> usize {
        self.rows.len()
    }
}

/// Up to `N` octets stored inline, for the fields of a [`PendingChange`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InlineBytes<const N: usize> {
    len: u16,
    data: [u8; N],
}

impl<const N: usize> Default for InlineBytes<N> {
    fn default() -> Self {
        Self {
            len: 0,
            data: [0; N],
        }
    }
}

impl<const N: usize> std::fmt::Debug for InlineBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InlineBytes({:02x?})", self.as_slice())
    }
}

impl<const N: usize> InlineBytes<N> {
    /// Octets copied from `bytes`, cut to `N`; the flag says whether it was cut.
    pub fn new(bytes: &[u8]) -> (Self, bool) {
        let mut out = Self::default();
        let cut = out.set(bytes);
        (out, cut)
    }

    /// Replaces the content with `bytes`, cut to `N`; returns whether it was cut.
    pub fn set(&mut self, bytes: &[u8]) -> bool {
        let len = bytes.len().min(N);
        self.data[..len].copy_from_slice(&bytes[..len]);
        // N is at most a few hundred octets, so the length fits.
        self.len = u16::try_from(len).unwrap_or(u16::MAX);
        len < bytes.len()
    }

    /// The octets.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The octets as text, when they are UTF-8 and not empty.
    pub fn to_text(&self) -> Option<String> {
        if self.is_empty() {
            None
        } else {
            std::str::from_utf8(self.as_slice()).ok().map(str::to_owned)
        }
    }
}

/// Text of option 12, 81 and 60: at most 255 octets.
pub type TextBytes = InlineBytes<255>;

/// The client's fingerprint in fixed-capacity form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingFingerprint {
    /// Option 55.
    pub parameters: InlineBytes<255>,
    /// Option 60.
    pub vendor_class: TextBytes,
    /// Option 77 present.
    pub user_class: bool,
    /// Option 81 present.
    pub client_fqdn: bool,
    /// The first architecture of option 93.
    pub architecture: Option<u16>,
}

/// What the relay said, in fixed-capacity form: `giaddr` and option 82 as received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRelay {
    /// `giaddr`.
    pub giaddr: Ipv4Addr,
    /// Option 82's data.
    pub raw: InlineBytes<255>,
}

/// A lease change as the DORA path builds it: no field on the heap. The committer
/// completes it into the rows of one batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChange {
    /// What happened.
    pub kind: LeaseEventKind,
    /// The VRF of the scope.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// The address.
    pub addr: Ipv4Addr,
    /// The hardware type.
    pub htype: u8,
    /// `chaddr`, `hlen` octets.
    pub chaddr: InlineBytes<MAX_CHADDR>,
    /// Option 61, when the client sent it.
    pub client_id: Option<InlineBytes<MAX_CLIENT_ID>>,
    /// The state after the change.
    pub state: BindingState,
    /// The client's transaction time.
    pub cltt: Timestamp,
    /// The end of the state.
    pub ends: Timestamp,
    /// Option 12.
    pub hostname: TextBytes,
    /// The name of option 81, as text.
    pub fqdn: TextBytes,
    // WP8.3: the flags of option 81, for the DDNS worker.
    /// The flags of option 81 as the client sent them.
    pub fqdn_flags: Option<u8>,
    // Slice 8 follow-ups: the matcher's DDNS decision, for the DDNS worker.
    /// The DDNS settings of the first matching policy that sets them; none: the scope's.
    pub ddns_policy: Option<tenko_core::dhcp::DdnsPolicy>,
    /// The relay.
    pub relay: Option<PendingRelay>,
    /// The fingerprint.
    pub fingerprint: Option<PendingFingerprint>,
}

impl PendingChange {
    /// A change for a client, with no host name, relay or fingerprint yet.
    #[allow(
        clippy::too_many_arguments,
        reason = "the identity of a lease change; the optional parts are set as fields"
    )]
    pub fn new(
        kind: LeaseEventKind,
        vrf: VrfId,
        scope: PrefixId,
        addr: Ipv4Addr,
        htype: u8,
        chaddr: &[u8],
        client_id: Option<&[u8]>,
        state: BindingState,
        cltt: Timestamp,
        ends: Timestamp,
    ) -> Self {
        Self {
            kind,
            vrf,
            scope,
            addr,
            htype,
            chaddr: InlineBytes::new(chaddr).0,
            client_id: client_id.map(|id| InlineBytes::new(id).0),
            state,
            cltt,
            ends,
            hostname: TextBytes::default(),
            fqdn: TextBytes::default(),
            // WP8.3: no option 81 flags until the engine sets them.
            fqdn_flags: None,
            // Slice 8 follow-ups: the scope's DDNS settings until the engine decides.
            ddns_policy: None,
            relay: None,
            fingerprint: None,
        }
    }

    /// The client identity, written into `out`; its length.
    pub fn identity(&self, out: &mut [u8; MAX_IDENTITY]) -> usize {
        write_identity(
            self.htype,
            self.chaddr.as_slice(),
            self.client_id.as_ref().map(InlineBytes::as_slice),
            out,
        )
    }

    /// The client key.
    pub fn client(&self) -> ClientKey {
        ClientKey {
            htype: self.htype,
            chaddr: HexBytes(self.chaddr.as_slice().to_vec()),
            client_id: self
                .client_id
                .as_ref()
                .map(|id| HexBytes(id.as_slice().to_vec())),
        }
    }

    /// The lease row after the change. Fields the change does not carry (the DDNS outcome,
    /// the partner times, the observation time) come from the row held before, if any.
    pub fn to_lease(&self, node: NodeId, previous: Option<&Lease>) -> Lease {
        let relay = self.relay.map(|relay| {
            let parsed = RelayAgentInfo::parse(relay.raw.as_slice()).ok();
            RelayInfo {
                giaddr: relay.giaddr,
                circuit_id: parsed
                    .as_ref()
                    .and_then(RelayAgentInfo::circuit_id)
                    .map(|id| HexBytes(id.to_vec())),
                remote_id: parsed
                    .as_ref()
                    .and_then(RelayAgentInfo::remote_id)
                    .map(|id| HexBytes(id.to_vec())),
                link_selection: parsed.as_ref().and_then(RelayAgentInfo::link_selection),
                server_id_override: parsed.as_ref().and_then(RelayAgentInfo::server_id_override),
                raw: HexBytes(relay.raw.as_slice().to_vec()),
            }
        });
        let fingerprint = self.fingerprint.map(|fp| Fingerprint {
            parameters: HexBytes(fp.parameters.as_slice().to_vec()),
            vendor_class: fp.vendor_class.to_text(),
            user_class: fp.user_class,
            client_fqdn: fp.client_fqdn,
            architecture: fp.architecture,
        });
        let same_client = previous.is_some_and(|held| held.client == self.client());
        Lease {
            addr: self.addr,
            vrf: self.vrf,
            scope: self.scope,
            client: self.client(),
            state: self.state,
            cltt: self.cltt,
            ends: self.ends,
            tstp: previous.and_then(|held| held.tstp),
            tsfp: previous.and_then(|held| held.tsfp),
            atsfp: previous.and_then(|held| held.atsfp),
            node,
            share: previous.and_then(|held| held.share),
            hostname: self.hostname.to_text().or_else(|| {
                previous
                    .filter(|_| same_client)
                    .and_then(|held| held.hostname.clone())
            }),
            fqdn: self.fqdn.to_text().or_else(|| {
                previous
                    .filter(|_| same_client)
                    .and_then(|held| held.fqdn.clone())
            }),
            // WP8.3: the flags go with the name they came with.
            fqdn_flags: self.fqdn_flags.or_else(|| {
                previous
                    .filter(|_| same_client)
                    .and_then(|held| held.fqdn_flags)
            }),
            // Slice 8 follow-ups: the decision of this request; a change without one (a
            // release, an expiry, a decline) keeps the held row's for the same client.
            ddns_policy: if self.state == BindingState::Active {
                self.ddns_policy.clone()
            } else {
                previous
                    .filter(|_| same_client)
                    .and_then(|held| held.ddns_policy.clone())
            },
            ddns: previous
                .filter(|_| same_client)
                .map(|held| held.ddns.clone())
                .unwrap_or_default(),
            fingerprint: fingerprint.or_else(|| {
                previous
                    .filter(|_| same_client)
                    .and_then(|held| held.fingerprint.clone())
            }),
            relay: relay.or_else(|| {
                previous
                    .filter(|_| same_client)
                    .and_then(|held| held.relay.clone())
            }),
            observed_at: previous
                .filter(|_| same_client)
                .and_then(|held| held.observed_at),
        }
    }

    /// The history row of the change.
    pub fn to_event(&self, node: NodeId) -> LeaseEvent {
        LeaseEvent {
            at: self.cltt,
            kind: self.kind,
            addr: self.addr,
            vrf: self.vrf,
            scope: self.scope,
            client: self.client(),
            state: self.state,
            ends: self.ends,
            hostname: self.hostname.to_text(),
            node,
        }
    }
}
