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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    dns::DnsName,
    id::{JobId, NodeId, PrefixId, VrfId},
    net::{Duid, MacAddr},
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

/// A client a move job is moving to another network (`docs/moves.md` section 4, ADR
/// 0027): the row of `dhcp.moving`, keyed by the job. The move job writes it in its first
/// step and removes it when it ends; the `dhcp` role serves it in its configuration image.
///
/// While the row is active (before `until`), a REQUEST of the client for the address of
/// `lease` gets a lease of `short_secs` instead of the pool's time, so that the client
/// comes back soon after the move changes its network, and the role notes every DHCP
/// message of the client's MAC address, so that the job sees the client's exchange (the
/// deadline's extension, the reconnection on the target scope). The role acts on no row
/// past `until`; the leader's lease expiry removes the rows of jobs that ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MovingClient {
    /// The move job.
    pub job: JobId,
    /// The client's MAC address.
    #[schema(value_type = String, example = "00:00:5e:00:53:31")]
    pub mac: MacAddr,
    /// The lease of the client on its old network that a renewal answers with the short
    /// lease; none when Tenko does not serve the old network or the move does not shorten
    /// the lease ("move now").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<MovingLease>,
    /// The time of the short lease in seconds (`[dhcp.moves] short_lease_secs`).
    pub short_secs: u32,
    /// The Tenko scope of the target network, where a message of the client counts as its
    /// reconnection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PrefixId>,
    /// When the row stops counting: the job's own deadline.
    pub until: Timestamp,
    /// Whether the job extended its observation deadline once already.
    #[serde(default)]
    pub extended: bool,
}

impl MovingClient {
    /// Whether the row counts at `now`.
    pub fn is_active(&self, now: Timestamp) -> bool {
        now < self.until
    }
}

/// The old lease of a [`MovingClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MovingLease {
    /// The VRF of the old scope.
    pub vrf: VrfId,
    /// The address the client holds.
    #[schema(value_type = String, example = "192.0.2.50")]
    pub addr: Ipv4Addr,
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

/// What the relay agent closest to a DHCPv6 client said about it (RFC 8415 section 9,
/// RFC 4649, RFC 6221), kept on the lease (WP9.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct Relay6Info {
    /// The link address of the relay closest to the client (zero for a lightweight relay
    /// of RFC 6221).
    #[schema(value_type = String, example = "2001:db8:1::1")]
    pub link_address: Ipv6Addr,
    /// The client's address as the relay saw it (its link-local address).
    #[schema(value_type = String, example = "fe80::200:5eff:fe00:5301")]
    pub peer_address: Ipv6Addr,
    /// The relays the request passed, one for a single relay.
    pub hops: u8,
    /// The Interface-Id of the closest relay that sent one (option 18).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<HexBytes>,
    /// The Remote-Id of the closest relay that sent one (option 37, RFC 4649): the
    /// enterprise number and the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<HexBytes>,
}

/// A DHCPv6 lease (`dhcp.leases6`, key VRF and address; WP9.1). An `IA_NA` binding is one
/// address of one identity association of a client; an `IA_PD` binding (WP9.2) a delegated
/// prefix keyed by its first address.
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
    /// The client's link-layer address, for the correlation of DHCP-11: from the Client
    /// Link-Layer Address option a relay added (RFC 6939), else from a DUID-LLT or DUID-LL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_layer: Option<HexBytes>,
    // WP9.1: the link-layer type, the option 39 flags, the relay and the observation time.
    /// The hardware type of `link_layer` (1 for Ethernet), when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_layer_type: Option<u16>,
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
    /// The name of RFC 4704, as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    /// The flags of the client's option 39, in the layout of RFC 4702 (S 0x01, O 0x02, N
    /// 0x08), so that the DDNS rules read them as they read the flags of option 81.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn_flags: Option<u8>,
    /// What the relay closest to the client said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Relay6Info>,
    /// When the IPAM observation facts of the lease were last written (plan section 2.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Timestamp>,
    /// The DDNS outcome.
    #[serde(default)]
    pub ddns: DdnsState,
}

impl Lease6 {
    /// The address as IPv6 (a row always holds one; an IPv4 value reads as its mapped
    /// form).
    pub fn addr6(&self) -> Ipv6Addr {
        match self.addr {
            IpAddr::V6(addr) => addr,
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
        }
    }

    /// Whether the lease holds its address for the client at `now`.
    pub fn is_bound(&self, now: Timestamp) -> bool {
        self.state == BindingState::Active && self.ends > now
    }

    /// Whether the address may not be given to another client at `now`.
    pub fn blocks(&self, now: Timestamp) -> bool {
        self.state.holds_address() && self.ends > now
    }

    /// The client identity of the row: the IAID (four octets) and the DUID; the key of the
    /// role's client index ([`write_identity6`]).
    pub fn identity(&self) -> Vec<u8> {
        let mut out = [0u8; MAX_IDENTITY6];
        let len = write_identity6(self.iaid, self.duid.as_bytes(), &mut out);
        out[..len].to_vec()
    }

    /// The client's Ethernet address, when its link-layer address is one.
    pub fn mac(&self) -> Option<[u8; 6]> {
        if self.link_layer_type.is_some_and(|kind| kind != 1) {
            return None;
        }
        self.link_layer
            .as_ref()
            .and_then(|octets| <[u8; 6]>::try_from(octets.0.as_slice()).ok())
    }

    /// The client as the DDNS rules know a client: the RFC 4361 form of a client
    /// identifier (type 255, the IAID, the DUID), so that the DHCID of the lease is of
    /// identifier type 2 over the DUID (RFC 4701 section 3.3), the same as that of a
    /// DHCPv4 client that sends its DUID.
    pub fn client_key(&self) -> ClientKey {
        let mut id = Vec::with_capacity(5 + self.duid.as_bytes().len());
        id.push(255);
        id.extend_from_slice(&self.iaid.to_be_bytes());
        id.extend_from_slice(self.duid.as_bytes());
        ClientKey {
            htype: 0,
            chaddr: HexBytes(Vec::new()),
            client_id: Some(HexBytes(id)),
        }
    }
}

/// The longest DUID (RFC 8415 section 11.1: a type and at most 128 octets).
pub const MAX_DUID: usize = 130;

/// The longest DHCPv6 client identity: an IAID and a DUID.
pub const MAX_IDENTITY6: usize = 4 + MAX_DUID;

/// Writes the identity of a DHCPv6 binding (the IAID, big-endian, and the DUID) into `out`
/// and returns its length; a DUID longer than [`MAX_DUID`] is cut to it.
pub fn write_identity6(iaid: u32, duid: &[u8], out: &mut [u8; MAX_IDENTITY6]) -> usize {
    let len = duid.len().min(MAX_DUID);
    out[..4].copy_from_slice(&iaid.to_be_bytes());
    out[4..4 + len].copy_from_slice(&duid[..len]);
    4 + len
}

/// What happened to a DHCPv6 lease (`dhcp.history6`, key time, VRF, address; WP9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Lease6Event {
    /// When.
    pub at: Timestamp,
    /// What.
    pub kind: LeaseEventKind,
    /// The address, or the prefix's first address.
    #[schema(value_type = String)]
    pub addr: Ipv6Addr,
    /// The prefix length: 128 for an address.
    pub prefix_len: u8,
    /// The VRF.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// The identity association.
    pub iaid: u32,
    /// The client's DUID.
    pub duid: Duid,
    /// The state after the event.
    pub state: BindingState,
    /// The end of that state.
    pub ends: Timestamp,
    /// The node that wrote it.
    pub node: NodeId,
    // WP9.4: the client's link-layer address, so that the history's MAC filter finds a
    // client with a DUID-EN or DUID-UUID behind an RFC 6939 relay. A row written before
    // reads as none.
    /// The client's link-layer address as the lease had it (RFC 6939, else a DUID-LLT or
    /// DUID-LL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_layer: Option<HexBytes>,
    /// The hardware type of `link_layer` (1 for Ethernet), when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_layer_type: Option<u16>,
}

impl Lease6Event {
    /// The client's Ethernet address, when the row's link-layer address is one.
    pub fn mac(&self) -> Option<[u8; 6]> {
        if self.link_layer_type.is_some_and(|kind| kind != 1) {
            return None;
        }
        self.link_layer
            .as_ref()
            .and_then(|octets| <[u8; 6]>::try_from(octets.0.as_slice()).ok())
    }

    /// The history row of a lease after `kind`.
    pub fn of(lease: &Lease6, kind: LeaseEventKind, at: Timestamp) -> Self {
        Self {
            at,
            kind,
            addr: lease.addr6(),
            prefix_len: lease.prefix_len,
            vrf: lease.vrf,
            scope: lease.scope,
            iaid: lease.iaid,
            duid: lease.duid.clone(),
            state: lease.state,
            ends: lease.ends,
            node: lease.node,
            link_layer: lease.link_layer.clone(),
            link_layer_type: lease.link_layer_type,
        }
    }
}
