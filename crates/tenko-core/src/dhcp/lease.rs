//! Leases (plan sections 2.1 and 2.12, ADR 0019): the rows of `dhcp.leases`, their client
//! index and their history.
//!
//! A lease row carries the fields that ISC's failover draft (`draft-ietf-dhc-failover-12`)
//! keeps per binding, so that pairing two nodes in Phase 5 adds a protocol, not a column:
//! the binding state, the client's end time (`ends`), the client's last transaction time
//! (`cltt`), the times told to and acknowledged by the partner (`tstp`, `tsfp`, `atsfp`),
//! the node that wrote the row and the pool share the address came from. On one node the
//! partner fields stay empty.
//!
//! The client is identified as RFC 4361 and RFC 6842 say: by its client identifier (option
//! 61) when it sends one, else by hardware type and `chaddr`. [`ClientKey::identity`] is
//! that identity as octets, the second part of the key of `dhcp.leases.by_client`, and
//! [`write_identity`] writes it into a caller's buffer without allocating.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    dns::DnsName,
    id::{NodeId, PrefixId, VrfId},
    net::Duid,
    serde_util::HexBytes,
    timestamp::Timestamp,
};

/// The longest `chaddr` (RFC 2131).
pub const MAX_CHADDR: usize = 16;

/// The longest client identifier: the data of one option 61.
pub const MAX_CLIENT_ID: usize = 255;

/// The longest client identity: one tag octet and a client identifier.
pub const MAX_IDENTITY: usize = 1 + MAX_CLIENT_ID;

/// How a DHCPv4 client is known (RFC 4361, RFC 6842).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema)]
pub struct ClientKey {
    /// The hardware type (1 for Ethernet).
    pub htype: u8,
    /// The hardware address, `hlen` octets of `chaddr`.
    pub chaddr: HexBytes,
    /// The client identifier (option 61), when the client sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<HexBytes>,
}

impl ClientKey {
    /// The client's identity as octets: `1` and the client identifier when there is one,
    /// else `0`, the hardware type and the hardware address.
    pub fn identity(&self) -> Vec<u8> {
        let mut out = [0u8; MAX_IDENTITY];
        let len = write_identity(
            self.htype,
            &self.chaddr.0,
            self.client_id.as_ref().map(|id| id.0.as_slice()),
            &mut out,
        );
        out[..len].to_vec()
    }

    /// The Ethernet address, when the hardware type is Ethernet and `chaddr` six octets.
    pub fn mac(&self) -> Option<[u8; 6]> {
        if self.htype == 1 {
            <[u8; 6]>::try_from(self.chaddr.0.as_slice()).ok()
        } else {
            None
        }
    }
}

/// Writes a client identity into `out` and returns its length; see [`ClientKey::identity`].
/// A client identifier or `chaddr` longer than its maximum is cut to it.
pub fn write_identity(
    htype: u8,
    chaddr: &[u8],
    client_id: Option<&[u8]>,
    out: &mut [u8; MAX_IDENTITY],
) -> usize {
    if let Some(id) = client_id {
        let len = id.len().min(MAX_CLIENT_ID);
        out[0] = 1;
        out[1..=len].copy_from_slice(&id[..len]);
        1 + len
    } else {
        let len = chaddr.len().min(MAX_CHADDR);
        out[0] = 0;
        out[1] = htype;
        out[2..2 + len].copy_from_slice(&chaddr[..len]);
        2 + len
    }
}

/// The state of a binding (the failover draft's binding states).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BindingState {
    /// Available for allocation.
    Free,
    /// Leased to the client until `ends`.
    Active,
    /// The lease ran out; the address returns to the pool after its grace.
    Expired,
    /// The client released it.
    Released,
    /// Not usable until `ends`: the client declined it (a conflict) or a probe found it in
    /// use.
    Abandoned,
    /// An operator reclaimed it (`dhcp.lease.release` through the API).
    Reset,
    /// Free and held for the failover partner (Phase 5).
    Backup,
}

impl BindingState {
    /// Whether the address is held for its client (`active`) or blocked (`abandoned`) and
    /// may not be offered to another client before `ends`.
    pub const fn holds_address(self) -> bool {
        matches!(self, Self::Active | Self::Abandoned)
    }
}

/// The half of a pool an address belongs to when two nodes share it (Phase 5: the RFC 3074
/// buckets in load balance, the backup share in hot standby). None on one node.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PoolShare {
    /// The primary's share.
    Primary,
    /// The secondary's share.
    Secondary,
}

/// What a relay agent said about the client (RFC 3046, RFC 3527, RFC 5107), kept on the
/// lease and echoed in replies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct RelayInfo {
    /// The relay's address (`giaddr`).
    #[schema(value_type = String, example = "192.0.2.1")]
    pub giaddr: Ipv4Addr,
    /// Sub-option 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_id: Option<HexBytes>,
    /// Sub-option 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<HexBytes>,
    /// The link selection sub-option (RFC 3527).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub link_selection: Option<Ipv4Addr>,
    /// The server identifier override sub-option (RFC 5107).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub server_id_override: Option<Ipv4Addr>,
    /// The whole option 82 as received, for the echo.
    #[serde(default)]
    pub raw: HexBytes,
}

/// What a request says about the client's system (DHCP-14, plan section 2.8): the parameter
/// request list in the client's order, the vendor class and which identifying options it
/// sent. WP8.2 maps it to an OS guess.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct Fingerprint {
    /// Option 55, in order.
    #[serde(default)]
    pub parameters: HexBytes,
    /// Option 60.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_class: Option<String>,
    /// Whether the client sent option 77.
    #[serde(default)]
    pub user_class: bool,
    /// Whether the client sent option 81.
    #[serde(default)]
    pub client_fqdn: bool,
    /// The first architecture of option 93.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<u16>,
}

/// The outcome of DDNS for a lease (ADR 0020, point 5): what was written and the last
/// error. Empty until the DDNS worker of WP8.3 has run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct DdnsState {
    /// The forward name written (A or AAAA and DHCID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward: Option<DnsName>,
    /// The reverse name written (PTR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse: Option<DnsName>,
    /// The DHCID data (RFC 4701) at the forward name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcid: Option<HexBytes>,
    /// The last failure, in English (a refused name, a store that refused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the worker last ran for the lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Timestamp>,
}

/// A DHCPv4 lease (`dhcp.leases`, key VRF and address).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Lease {
    /// The address.
    #[schema(value_type = String, example = "192.0.2.50")]
    pub addr: Ipv4Addr,
    /// The VRF of the scope's prefix.
    pub vrf: VrfId,
    /// The scope, by its prefix.
    pub scope: PrefixId,
    /// The client.
    pub client: ClientKey,
    /// The binding state.
    pub state: BindingState,
    /// The client's last transaction time.
    pub cltt: Timestamp,
    /// When the state ends: the lease end of an active binding, the end of the hold of an
    /// abandoned one, the end of the grace of an expired or released one.
    pub ends: Timestamp,
    /// The lease end told to the partner (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tstp: Option<Timestamp>,
    /// The lease end the partner told this node (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsfp: Option<Timestamp>,
    /// The lease end the partner acknowledged (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atsfp: Option<Timestamp>,
    /// The node that wrote the row.
    pub node: NodeId,
    /// The pool share the address came from (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<PoolShare>,
    /// The host name the client sent (option 12), as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The name the client sent in option 81, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    // WP8.3: the flags of option 81, so that the DDNS worker knows who writes the A record.
    /// The flags of option 81 as the client sent them (S, O, E, N; RFC 4702).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn_flags: Option<u8>,
    // Slice 8 follow-ups: the DDNS settings the class and policy matcher decided.
    /// The DDNS settings of the first matching policy that sets them, as the matcher
    /// decided them for the client's last REQUEST (the settings its reply's option 81
    /// used); none: the scope's apply. The DDNS worker writes the names by them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ddns_policy: Option<super::DdnsPolicy>,
    /// The DDNS outcome.
    #[serde(default)]
    pub ddns: DdnsState,
    /// The client's fingerprint, from its last REQUEST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Fingerprint>,
    /// What the relay said, for a relayed client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayInfo>,
    /// When the IPAM observation fact of the lease was last written (plan section 2.8), so
    /// that a renewal adds a fact only when its refresh is due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Timestamp>,
}

impl Lease {
    /// Whether the lease holds its address for the client at `now`.
    pub fn is_bound(&self, now: Timestamp) -> bool {
        self.state == BindingState::Active && self.ends > now
    }

    /// Whether the address may not be given to another client at `now`.
    pub fn blocks(&self, now: Timestamp) -> bool {
        self.state.holds_address() && self.ends > now
    }
}

/// The value of `dhcp.leases.by_client`: where the client's lease in a scope is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct LeaseRef {
    /// The VRF.
    pub vrf: VrfId,
    /// The address.
    #[schema(value_type = String)]
    pub addr: Ipv4Addr,
}

/// What happened to a lease (`dhcp.history`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LeaseEventKind {
    /// A new binding (REQUEST in SELECTING or INIT-REBOOT).
    Granted,
    /// A renewal (RENEWING).
    Renewed,
    /// A rebind (REBINDING).
    Rebound,
    /// The client released the address.
    Released,
    /// The client declined the address.
    Declined,
    /// The binding ran out.
    Expired,
    /// An operator reclaimed the address.
    Reclaimed,
    /// A probe found the address in use before an offer.
    Conflict,
}

/// One row of `dhcp.history` (key: time, VRF, address), written in the batch of the lease
/// change; bounded by the retention of P3-Q13.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LeaseEvent {
    /// When.
    pub at: Timestamp,
    /// What.
    pub kind: LeaseEventKind,
    /// The address.
    #[schema(value_type = String)]
    pub addr: Ipv4Addr,
    /// The VRF.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// The client.
    pub client: ClientKey,
    /// The state after the event.
    pub state: BindingState,
    /// The end of that state.
    pub ends: Timestamp,
    /// The host name the client sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The node that wrote it.
    pub node: NodeId,
}

impl LeaseEvent {
    /// The history row of a lease after `kind`.
    pub fn of(lease: &Lease, kind: LeaseEventKind, at: Timestamp) -> Self {
        Self {
            at,
            kind,
            addr: lease.addr,
            vrf: lease.vrf,
            scope: lease.scope,
            client: lease.client.clone(),
            state: lease.state,
            ends: lease.ends,
            hostname: lease.hostname.clone(),
            node: lease.node,
        }
    }
}

/// What a DHCPv6 lease binds (Slice 9).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Lease6Kind {
    /// A non-temporary address (`IA_NA`).
    Na,
    /// A delegated prefix (`IA_PD`).
    Pd,
}

/// A DHCPv6 lease (Slice 9, `dhcp.leases6` then). Declared now so that the format of this
/// phase holds its values; no table stores it yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Lease6 {
    /// The address, or the prefix's first address.
    #[schema(value_type = String, example = "2001:db8::50")]
    pub addr: IpAddr,
    /// The prefix length: 128 for an address.
    pub prefix_len: u8,
    /// Address or prefix.
    pub kind: Lease6Kind,
    /// The VRF.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// The identity association.
    pub iaid: u32,
    /// The client's DUID.
    pub duid: Duid,
    /// The client's link-layer address (RFC 6939), for the correlation of DHCP-11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_layer: Option<HexBytes>,
    /// The binding state.
    pub state: BindingState,
    /// The client's last transaction time.
    pub cltt: Timestamp,
    /// The valid lifetime's end.
    pub ends: Timestamp,
    /// The preferred lifetime's end.
    pub preferred_ends: Timestamp,
    /// The node that wrote the row.
    pub node: NodeId,
    /// The name of RFC 4704.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    /// The DDNS outcome.
    #[serde(default)]
    pub ddns: DdnsState,
}
