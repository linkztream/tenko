//! Request and response bodies of the DHCP routes (WP7.0 contracts; WP7.4, WP7.5, WP8.x and
//! WP9.3 implement them). The stored model is `tenko_core::dhcp`; these types add the
//! revision of a read and the values derived for display (the network of a scope, the
//! typed view of an option), and shape writes.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, Class, ClassId, ClientKey, Condition, DdnsPolicy, DdnsState, DhcpSettings,
        ExclusionRange, Filter, FilterKind, Fingerprint, Lease, Lease6Kind, LeaseEventKind,
        LeaseTimes, MacPattern, Match, OptionData, OptionDef, OptionKind, OptionLevel, OptionOwner,
        OptionSpace, OptionValue, Policy, PolicyAction, PolicyId, PoolSettings, PoolShare,
        Relay6Info, RelayInfo, ReservationWarning, Scope, SharedNetwork, SharedNetworkId,
    },
    ipam::{RangeRole, Stamp},
    net::{Duid, HostName, MacAddr},
    serde_util::HexBytes,
};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ---------------------------------------------------------------------------------------
// Settings

/// The server settings as the API reads them.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpSettingsItem {
    /// The settings.
    #[serde(flatten)]
    pub settings: DhcpSettings,
    /// What the security profile makes of the unset values: conflict detection (TGL-16).
    pub effective_conflict_detection: bool,
    /// The same for the lease history retention in days (P3-Q13).
    pub effective_history_days: u32,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// `PUT /dhcp/settings`: the whole server settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpSettingsUpdate {
    /// Lease times of scopes that set none.
    #[serde(default)]
    pub lease: Option<LeaseTimes>,
    /// Whether scopes are authoritative unless they say otherwise.
    #[serde(default)]
    pub authoritative: Option<bool>,
    /// DDNS settings new scopes start from.
    #[serde(default)]
    pub ddns: Option<DdnsPolicy>,
    /// Conflict detection; none follows the profile.
    #[serde(default)]
    pub conflict_detection: Option<bool>,
    /// History retention in days; none follows the profile.
    #[serde(default)]
    pub history_days: Option<u32>,
}

// ---------------------------------------------------------------------------------------
// Scopes

/// A scope as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpScopeItem {
    /// The scope.
    #[serde(flatten)]
    pub scope: Scope,
    /// The prefix's network.
    #[schema(value_type = String, example = "192.0.2.0/24")]
    pub cidr: ipnet::IpNet,
    // WP9.1: the address family, so that a client tells DHCPv4 and DHCPv6 scopes apart.
    /// `v4` for a scope on an IPv4 prefix (DHCPv4), `v6` on an IPv6 prefix (DHCPv6).
    #[schema(example = "v4")]
    pub family: String,
    /// The prefix's VRF.
    pub vrf: VrfId,
    /// The number of pools (IPAM ranges of role `dhcp_pool`).
    pub pools: u32,
    /// The active leases on the node.
    pub leases: u64,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// `POST /dhcp/scopes`: a scope for an IPAM network.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpScopeCreate {
    /// The prefix to serve (a network without a scope).
    pub prefix: PrefixId,
    /// Whether the scope serves clients; true when absent.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Lease times; the server's when absent.
    #[serde(default)]
    pub lease: Option<LeaseTimes>,
    /// Authoritative; the server's setting when absent.
    #[serde(default)]
    pub authoritative: Option<bool>,
    /// The server identifier.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub server_id: Option<IpAddr>,
    /// DDNS; the server's DDNS settings when absent.
    #[serde(default)]
    pub ddns: Option<DdnsPolicy>,
    /// The shared network.
    #[serde(default)]
    pub shared_network: Option<SharedNetworkId>,
    /// Only allowed clients are served.
    #[serde(default)]
    pub restricted: Option<bool>,
    /// The classes the scope admits.
    #[serde(default)]
    pub classes: Vec<ClassId>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
    // WP9.1: the DHCPv6 settings of a scope on an IPv6 prefix.
    /// The DHCPv6 settings (preferred lifetime, rapid commit, the relay's Interface-Id);
    /// only on an IPv6 prefix; the defaults when absent.
    #[serde(default)]
    pub v6: Option<tenko_core::dhcp::Scope6Settings>,
}

/// `PATCH /dhcp/scopes/{prefix}`: the fields to change; the prefix does not change.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpScopePatch {
    /// Whether the scope serves clients.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Lease times; `null` keeps them, see `clear_lease`.
    #[serde(default)]
    pub lease: Option<LeaseTimes>,
    /// Drop the scope's lease times and use the server's.
    #[serde(default)]
    pub clear_lease: bool,
    /// Authoritative.
    #[serde(default)]
    pub authoritative: Option<bool>,
    /// The server identifier.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub server_id: Option<IpAddr>,
    /// DDNS.
    #[serde(default)]
    pub ddns: Option<DdnsPolicy>,
    /// The shared network; the nil UUID leaves the shared network.
    #[serde(default)]
    pub shared_network: Option<SharedNetworkId>,
    /// Only allowed clients are served.
    #[serde(default)]
    pub restricted: Option<bool>,
    /// The classes the scope admits.
    #[serde(default)]
    pub classes: Option<Vec<ClassId>>,
    /// Free text; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
    // WP9.1: the DHCPv6 settings of a scope on an IPv6 prefix.
    /// The DHCPv6 settings, replaced whole; `null` keeps them, see `clear_v6`.
    #[serde(default)]
    pub v6: Option<tenko_core::dhcp::Scope6Settings>,
    /// Drop the DHCPv6 settings (the defaults apply).
    #[serde(default)]
    pub clear_v6: bool,
}

/// How full a scope is (`GET /dhcp/scopes/{prefix}/utilization`, IPAM-10).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpScopeUtilization {
    /// The scope.
    pub prefix: PrefixId,
    /// Addresses in the pools, exclusions taken out.
    pub pool_size: u64,
    /// Pool addresses with an active lease.
    pub leased: u64,
    /// Pool addresses held by a reservation.
    pub reserved: u64,
    /// Pool addresses abandoned after a DECLINE or a conflict.
    pub abandoned: u64,
    /// Pool addresses free now.
    pub free: u64,
    /// `(leased + reserved + abandoned) / pool_size`, 0 to 1.
    pub utilization: f64,
    /// When the role's table was read.
    pub at: Timestamp,
    // WP9.4: a DHCPv6 scope counts its DHCPv6 leases.
    /// `v4` for a DHCPv4 scope, `v6` for a DHCPv6 one, whose pools may hold more addresses
    /// than `pool_size` can say (it stops at 2^64 - 1; `pool_bits` gives the size).
    #[schema(example = "v4")]
    pub family: String,
    /// The pool size as a power of two, rounded down, when it is at least 2^32 (a DHCPv6
    /// pool of a /64 has 64); absent for a smaller pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_bits: Option<u8>,
    // WP9.4: the delegation pools of a DHCPv6 scope.
    /// A DHCPv6 scope with delegation pools: how full they are, in prefixes. The address
    /// figures above leave the delegated prefixes out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pd: Option<DhcpPdUtilization>,
}

/// How full the delegation pools of a DHCPv6 scope are (`pd` of the utilization).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpPdUtilization {
    /// The delegation pools of the scope.
    pub pools: u32,
    /// The prefixes they may delegate, those an exclusion touches taken out; stops at
    /// 2^64 - 1.
    pub pool_size: u64,
    /// The prefixes bound now.
    pub leased: u64,
    /// The prefixes free now; stops at 2^64 - 1.
    pub free: u64,
    /// `leased / pool_size`, 0 to 1.
    pub utilization: f64,
}

/// The client of `GET /dhcp/scopes/{prefix}/effective-options`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EffectiveOptionsParams {
    /// The client's MAC address.
    #[param(value_type = Option<String>, example = "00:00:5e:00:53:01")]
    pub mac: Option<MacAddr>,
    /// The client identifier (option 61) in hexadecimal.
    pub client_id: Option<String>,
    /// The vendor class the client sends (option 60).
    pub vendor_class: Option<String>,
    /// The user class the client sends (option 77).
    pub user_class: Option<String>,
    // WP8.6: the other facts the matcher tests, for the "why this value" view of the UI.
    /// The client system architecture (option 93, RFC 4578): 0 BIOS, 7 and 9 UEFI x64, 16 UEFI
    /// HTTP boot x64.
    #[param(minimum = 0, maximum = 65535)]
    pub architecture: Option<u32>,
    /// The host name the client sends (option 12).
    pub host_name: Option<String>,
}

/// One option of a client's effective set, with where it came from.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveOption {
    /// The value.
    pub value: OptionValue,
    /// The option's name in the catalog or its definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The typed view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<OptionData>,
    /// The level that set it.
    pub level: OptionLevel,
    /// The owner of the set that set it.
    pub owner: OptionOwner,
}

/// The options a client gets in a scope and why (plan section 2.4).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveOptions {
    /// The scope.
    pub prefix: PrefixId,
    /// The reservation the client has, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation: Option<InterfaceId>,
    /// The policies that matched, in order.
    #[serde(default)]
    pub policies: Vec<PolicyId>,
    /// The classes the client is in.
    #[serde(default)]
    pub classes: Vec<ClassId>,
    /// The effective options, in reply order.
    pub options: Vec<EffectiveOption>,
}

// ---------------------------------------------------------------------------------------
// Shared networks

/// A shared network as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SharedNetworkItem {
    /// The shared network.
    #[serde(flatten)]
    pub shared_network: SharedNetwork,
    /// Its scopes.
    pub scopes: Vec<PrefixId>,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// `POST /dhcp/shared-networks`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SharedNetworkCreate {
    /// The name.
    pub name: String,
    /// The listener interface of a directly attached link.
    #[serde(default)]
    pub interface: Option<String>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dhcp/shared-networks/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SharedNetworkPatch {
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// The interface; an empty string clears it.
    #[serde(default)]
    pub interface: Option<String>,
    /// Free text; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------------------
// Pools and exclusions

/// A pool: an IPAM range of role `dhcp_pool` (addresses) or `dhcp_pd_pool` (delegated
/// prefixes of a DHCPv6 scope) with its DHCP settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpPoolItem {
    /// The range.
    pub range: RangeId,
    // WP9.4: the delegation pools beside the address pools.
    /// The range's role: `dhcp_pool` or `dhcp_pd_pool`.
    #[schema(example = "dhcp_pool")]
    pub role: RangeRole,
    /// A delegation pool's delegated length: the length of the prefixes it hands out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_len: Option<u8>,
    /// The scope.
    pub prefix: PrefixId,
    /// The first address.
    #[schema(value_type = String)]
    pub first: IpAddr,
    /// The last address.
    #[schema(value_type = String)]
    pub last: IpAddr,
    /// The range's lease time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u32>,
    /// The DHCP settings, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<PoolSettings>,
    /// Addresses in the pool, exclusions taken out; for a delegation pool the prefixes it
    /// may delegate (a prefix an exclusion touches taken out). Stops at 2^64 - 1.
    pub size: u64,
    /// Addresses with an active lease; for a delegation pool the prefixes bound.
    pub leased: u64,
    /// The store revision of the settings row (the `ETag`); 0 without settings.
    pub revision: Revision,
}

/// The filter of the pool and exclusion lists.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DhcpScopeFilter {
    /// Only this scope.
    pub scope: Option<PrefixId>,
}

/// `PUT /dhcp/pools/{range}`: the pool's DHCP settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpPoolSet {
    /// The classes the pool admits.
    #[serde(default)]
    pub classes: Vec<ClassId>,
    /// Lease times.
    #[serde(default)]
    pub lease: Option<LeaseTimes>,
}

/// `POST /dhcp/scopes/{prefix}/exclusions`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExclusionCreate {
    /// The first address excluded.
    #[schema(value_type = String, example = "192.0.2.10")]
    pub first: IpAddr,
    /// The last address excluded.
    #[schema(value_type = String, example = "192.0.2.19")]
    pub last: IpAddr,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// An exclusion range as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExclusionItem {
    /// The range.
    #[serde(flatten)]
    pub exclusion: ExclusionRange,
    /// The store revision of the row.
    pub revision: Revision,
}

// ---------------------------------------------------------------------------------------
// Options

/// A custom option definition as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OptionDefItem {
    /// The definition.
    #[serde(flatten)]
    pub def: OptionDef,
    /// The option sets that use it.
    pub used_by: u32,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// `POST /dhcp/option-defs`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OptionDefCreate {
    /// The space; `dhcp4` when absent.
    #[serde(default)]
    pub space: Option<OptionSpace>,
    /// The code.
    pub code: u16,
    /// The name.
    pub name: String,
    /// The type.
    pub kind: OptionKind,
    /// Whether the option holds a list.
    #[serde(default)]
    pub array: bool,
    /// The vendor class of a vendor space.
    #[serde(default)]
    pub vendor_class: Option<String>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dhcp/option-defs/{id}`: the name, the vendor class and the description; the
/// space, the code and the type do not change while option sets use them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct OptionDefPatch {
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// The type (refused while an option set uses the definition).
    #[serde(default)]
    pub kind: Option<OptionKind>,
    /// Whether the option holds a list (refused while used).
    #[serde(default)]
    pub array: Option<bool>,
    /// The vendor class; an empty string clears it.
    #[serde(default)]
    pub vendor_class: Option<String>,
    /// Free text; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
}

/// One entry of the built-in catalog (`GET /dhcp/option-catalog`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OptionCatalogItem {
    /// The space.
    pub space: OptionSpace,
    /// The code.
    pub code: u16,
    /// The name.
    pub name: String,
    /// The type.
    pub kind: OptionKind,
    /// Whether it holds a list.
    pub array: bool,
    /// Whether the server sets it itself (never in an option set).
    pub server_managed: bool,
}

// WP9.4: the DHCPv6 catalog beside the DHCPv4 one.
/// The filter of `GET /dhcp/option-catalog`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OptionCatalogParams {
    /// Only this space: `dhcp4` (RFC 2132 and its successors) or `dhcp6` (RFC 8415 and the
    /// option RFCs); both when absent, `dhcp4` first.
    pub space: Option<String>,
}

/// One option of a set as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OptionValueItem {
    /// The value in wire form.
    #[serde(flatten)]
    pub value: OptionValue,
    /// The option's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The typed view, when the option has a definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<OptionData>,
}

/// An option set as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OptionSetItem {
    /// The owner.
    pub owner: OptionOwner,
    /// The owner in the path form (`server`, `scope:<prefix>`, `host:<interface>`).
    pub path: String,
    /// The level.
    pub level: OptionLevel,
    /// The values.
    pub values: Vec<OptionValueItem>,
    /// Last change.
    pub updated: Stamp,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// One option to set: in wire form (`data`) or typed (`typed`), exactly one of them.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OptionValueInput {
    /// The space; `dhcp4` when absent.
    #[serde(default)]
    pub space: Option<OptionSpace>,
    /// The code.
    pub code: u16,
    /// The data in wire form, hexadecimal.
    #[serde(default)]
    pub data: Option<HexBytes>,
    /// The data typed.
    #[serde(default)]
    pub typed: Option<OptionData>,
}

/// `PUT /dhcp/option-sets/{owner}`: the whole set.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct OptionSetPut {
    /// The values, at most one per space and code.
    #[serde(default)]
    pub values: Vec<OptionValueInput>,
}

/// The filter of `GET /dhcp/option-sets`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OptionSetFilter {
    /// Only sets of this level.
    pub level: Option<OptionLevel>,
}

// ---------------------------------------------------------------------------------------
// Classes, policies, filters

/// A class as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpClassItem {
    /// The class.
    #[serde(flatten)]
    pub class: Class,
    /// The scopes, pools and policies that name it.
    pub used_by: u32,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// `POST /dhcp/classes`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpClassCreate {
    /// The name.
    pub name: String,
    /// The matches, joined by OR.
    pub matches: Vec<Match>,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dhcp/classes/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpClassPatch {
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// The matches.
    #[serde(default)]
    pub matches: Option<Vec<Match>>,
    /// Free text; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
}

/// A policy as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpPolicyItem {
    /// The policy.
    #[serde(flatten)]
    pub policy: Policy,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// `POST /dhcp/policies`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpPolicyCreate {
    /// The name.
    pub name: String,
    /// The scope; none for a server-level policy.
    #[serde(default)]
    pub scope: Option<PrefixId>,
    /// The order; after the last one when absent.
    #[serde(default)]
    pub order: Option<u32>,
    /// Whether it applies; true when absent.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// When it applies.
    pub condition: Condition,
    /// What it does.
    #[serde(default)]
    pub action: PolicyAction,
    /// Free text.
    #[serde(default)]
    pub description: Option<String>,
}

/// `PATCH /dhcp/policies/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpPolicyPatch {
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// The order.
    #[serde(default)]
    pub order: Option<u32>,
    /// Whether it applies.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// When it applies.
    #[serde(default)]
    pub condition: Option<Condition>,
    /// What it does.
    #[serde(default)]
    pub action: Option<PolicyAction>,
    /// Free text; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
}

/// The filter of `GET /dhcp/policies`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DhcpPolicyFilter {
    /// Only the policies of this scope.
    pub scope: Option<PrefixId>,
    /// Only the server-level policies.
    pub server: Option<bool>,
}

/// A MAC filter entry as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpFilterItem {
    /// The entry.
    #[serde(flatten)]
    pub filter: Filter,
    /// The store revision of the row (the `ETag`).
    pub revision: Revision,
}

/// `POST /dhcp/filters`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpFilterCreate {
    /// The addresses.
    pub mac: MacPattern,
    /// Allow or deny.
    pub kind: FilterKind,
    /// Why.
    #[serde(default)]
    pub note: Option<String>,
}

/// `PATCH /dhcp/filters/{id}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpFilterPatch {
    /// The addresses.
    #[serde(default)]
    pub mac: Option<MacPattern>,
    /// Allow or deny.
    #[serde(default)]
    pub kind: Option<FilterKind>,
    /// Why; an empty string clears it.
    #[serde(default)]
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------------------
// Reservations

/// A reservation: an IPAM host of mode `reserved` with an interface and an address in a
/// served prefix (a read view; writes go to the IPAM host routes and the host's option
/// set).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpReservationItem {
    /// The host.
    pub host: HostId,
    /// The host's name.
    pub host_name: HostName,
    /// The interface.
    pub interface: InterfaceId,
    /// The interface's MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    /// The interface's client identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<HexBytes>,
    /// The address.
    #[schema(value_type = String)]
    pub address: IpAddr,
    /// The scope.
    pub scope: PrefixId,
    /// Whether the address lies in a pool (allowed; the reservation wins).
    pub in_pool: bool,
    /// The reservation's options (the interface's option set).
    #[serde(default)]
    pub options: Vec<OptionValueItem>,
    /// The client's current lease, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    /// What the reservation check found (IPAM-18, IPAM-23).
    #[serde(default)]
    pub warnings: Vec<ReservationWarning>,
}

// ---------------------------------------------------------------------------------------
// Leases and history

// WP9.4: the leases of both families in one shape.
/// The address family of a lease or a history row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DhcpFamily {
    /// DHCPv4.
    V4,
    /// DHCPv6.
    V6,
}

/// The lease of the other family whose client has the same MAC address (DHCP-11): an
/// active one when there is one, else the one that ends last.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpLeasePeer {
    /// Its family.
    pub family: DhcpFamily,
    /// Its VRF.
    pub vrf: VrfId,
    /// Its address.
    #[schema(value_type = String, example = "2001:db8::50")]
    pub addr: IpAddr,
    /// Its binding state.
    pub state: BindingState,
    /// When that state ends.
    pub ends: Timestamp,
}

/// A lease as the API reads it: a DHCPv4 lease (`family` `v4`, the fields of
/// `dhcp.leases`) or a DHCPv6 lease (`family` `v6`, the fields of `dhcp.leases6`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpLeaseItem {
    /// The family.
    pub family: DhcpFamily,
    /// The address (a delegated prefix's first address for a DHCPv6 `pd` lease).
    #[schema(value_type = String, example = "192.0.2.50")]
    pub addr: IpAddr,
    /// The VRF of the scope's prefix.
    pub vrf: VrfId,
    /// The scope, by its prefix.
    pub scope: PrefixId,
    /// The binding state.
    pub state: BindingState,
    /// The client's last transaction time.
    pub cltt: Timestamp,
    /// When the state ends (the valid lifetime's end of a DHCPv6 binding).
    pub ends: Timestamp,
    /// The node that wrote the row.
    pub node: NodeId,
    /// DHCPv6: what the lease binds, `na` (an address) or `pd` (a delegated prefix).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<Lease6Kind>,
    /// DHCPv6: the prefix length, 128 for an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    /// DHCPv4: the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientKey>,
    /// The client's MAC address, where it is known: the Ethernet hardware address of a
    /// DHCPv4 client, the link-layer address of a DHCPv6 client (RFC 6939, or its DUID-LLT
    /// or DUID-LL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "00:00:5e:00:53:01")]
    pub mac: Option<MacAddr>,
    /// DHCPv6: the identity association.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iaid: Option<u32>,
    /// DHCPv6: the client's DUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duid: Option<Duid>,
    /// DHCPv6: the client's link-layer address as it came.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_layer: Option<HexBytes>,
    /// DHCPv6: the hardware type of `link_layer` (1 for Ethernet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_layer_type: Option<u16>,
    /// DHCPv6: the preferred lifetime's end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_ends: Option<Timestamp>,
    /// DHCPv4: the lease end told to the partner (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tstp: Option<Timestamp>,
    /// DHCPv4: the lease end the partner told this node (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsfp: Option<Timestamp>,
    /// DHCPv4: the lease end the partner acknowledged (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atsfp: Option<Timestamp>,
    /// DHCPv4: the pool share the address came from (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<PoolShare>,
    /// DHCPv4: the host name the client sent (option 12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The name the client sent: option 81 of DHCPv4, option 39 of DHCPv6 (RFC 4704).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    /// The flags of that option, in the layout of option 81 (S, O, E, N; RFC 4702).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn_flags: Option<u8>,
    /// DHCPv4: the DDNS settings of the policy that decided the names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ddns_policy: Option<DdnsPolicy>,
    /// The DDNS outcome.
    #[serde(default)]
    pub ddns: DdnsState,
    /// DHCPv4: the client's fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Fingerprint>,
    /// DHCPv4: what the relay said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayInfo>,
    /// DHCPv6: what the relay closest to the client said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay6: Option<Relay6Info>,
    /// When the IPAM observation fact of the lease was last written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Timestamp>,
    /// The host IPAM knows for the client, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// Whether the address is the client's reservation.
    pub reserved: bool,
    /// The store revision of the row.
    pub revision: Revision,
    /// The client's lease of the other family with the same MAC address (DHCP-11), when the
    /// node holds one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<DhcpLeasePeer>,
    // WP9.4: a delegated prefix and its router's address.
    /// A delegated prefix (`pd`): the lease of an address (`na`) of the same client, by its
    /// DUID in the same VRF, when the node holds one (an active one first, else the one
    /// that ends last).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_lease: Option<DhcpLeasePeer>,
}

/// The filters of `GET /dhcp/leases`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DhcpLeaseFilters {
    /// Only this scope.
    pub scope: Option<PrefixId>,
    /// Addresses starting with this text (`192.0.2.`). An IPv6 address or prefix
    /// (`2001:db8:180::/48`) also matches the DHCPv6 leases whose address or delegated
    /// prefix it holds and the delegated prefixes that hold it.
    pub addr: Option<String>,
    /// The client's MAC address.
    #[param(value_type = Option<String>)]
    pub mac: Option<MacAddr>,
    /// Host names or FQDNs containing this text.
    pub name: Option<String>,
    /// One binding state.
    pub state: Option<BindingState>,
    /// The cursor of the next page.
    pub cursor: Option<String>,
    /// Items per page, 1 to 1000; 100 by default.
    pub limit: Option<u32>,
    // WP9.4: the family and the DUID.
    /// Only this family (`v4`, `v6`); both when absent, the DHCPv4 leases first.
    pub family: Option<DhcpFamily>,
    /// Only DHCPv6 leases of this client DUID (hexadecimal, separators allowed).
    pub duid: Option<String>,
    // WP9.4: addresses or delegated prefixes.
    /// Only DHCPv6 leases of this kind: `na` (addresses) or `pd` (delegated prefixes).
    pub kind: Option<Lease6Kind>,
}

/// The VRF of an address in the path; the default VRF when absent.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DhcpLeaseParams {
    /// The VRF.
    pub vrf: Option<VrfId>,
}

/// `POST /dhcp/leases/{addr}/release`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpLeaseRelease {
    /// The VRF; the default VRF when absent.
    #[serde(default)]
    pub vrf: Option<VrfId>,
    /// Why, for the audit record.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One row of the lease history: an event of `dhcp.history` (`family` `v4`) or of
/// `dhcp.history6` (`family` `v6`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpHistoryItem {
    /// The family.
    pub family: DhcpFamily,
    /// When.
    pub at: Timestamp,
    /// What.
    pub kind: LeaseEventKind,
    /// The address.
    #[schema(value_type = String, example = "192.0.2.50")]
    pub addr: IpAddr,
    /// DHCPv6: the prefix length, 128 for an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    /// The VRF.
    pub vrf: VrfId,
    /// The scope.
    pub scope: PrefixId,
    /// DHCPv4: the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientKey>,
    /// The client's MAC address where the row says it: the Ethernet hardware address of a
    /// DHCPv4 client; the link-layer address of a DHCPv6 client (RFC 6939, else its
    /// DUID-LLT or DUID-LL; rows written before WP9.4 only the DUID's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "00:00:5e:00:53:01")]
    pub mac: Option<MacAddr>,
    /// DHCPv6: the identity association.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iaid: Option<u32>,
    /// DHCPv6: the client's DUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duid: Option<Duid>,
    /// The state after the event.
    pub state: BindingState,
    /// The end of that state.
    pub ends: Timestamp,
    /// DHCPv4: the host name the client sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The node that wrote it.
    pub node: NodeId,
}

/// The filters of `GET /dhcp/history`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DhcpHistoryFilters {
    /// Only this address.
    pub addr: Option<String>,
    /// Only this MAC address.
    #[param(value_type = Option<String>)]
    pub mac: Option<MacAddr>,
    /// Only this scope.
    pub scope: Option<PrefixId>,
    /// Only this kind of event.
    pub kind: Option<LeaseEventKind>,
    /// From this time, RFC 3339.
    pub from: Option<String>,
    /// Until this time, RFC 3339.
    pub to: Option<String>,
    /// The cursor of the next page.
    pub cursor: Option<String>,
    /// Items per page, 1 to 1000; 100 by default.
    pub limit: Option<u32>,
    // WP9.4: the family and the DUID.
    /// Only this family (`v4`, `v6`); both when absent, merged newest first.
    pub family: Option<DhcpFamily>,
    /// Only DHCPv6 events of this client DUID (hexadecimal, separators allowed).
    pub duid: Option<String>,
}

// ---------------------------------------------------------------------------------------
// Export (Slice 9)

/// The parameters of `GET /dhcp/export`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DhcpExportParams {
    /// The format; `kea` (MIG-16) is the only one.
    pub format: Option<String>,
    /// Whether the leases are included as memfile CSV; true when absent.
    pub leases: Option<bool>,
}

// ---------------------------------------------------------------------------------------
// The role of a node

/// How a listener receives traffic (plan section 2.5).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DhcpListenMode {
    /// The unicast address: relayed traffic only.
    Relay,
    /// The interface: broadcasts from the link as well.
    Direct,
    // Slice 8 follow-ups: the proxy DHCP listeners of WP8.4.
    /// A proxy DHCP listener (`[dhcp] proxy`, port 4011): boot information for PXE clients,
    /// no address.
    Proxy,
}

/// One listener of the role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpListenerItem {
    /// The address.
    #[schema(value_type = String, example = "198.51.100.10")]
    pub address: IpAddr,
    /// The port (67, 547 for DHCPv6, 4011 for a proxy DHCP listener).
    pub port: u16,
    /// The mode.
    pub mode: DhcpListenMode,
    /// The interface of a direct listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// The worker threads.
    pub workers: u16,
}

/// The number of leases in one state.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpLeaseCount {
    /// The state.
    pub state: BindingState,
    /// The leases.
    pub count: u64,
}

/// `GET /nodes/{id}/dhcp`: the state of a node's `dhcp` role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpNodeStatus {
    /// The node.
    pub node: NodeId,
    /// Whether the role serves.
    pub serving: bool,
    /// Whether the store accepts lease writes (P3-Q14).
    pub accepting: bool,
    /// Whether conflict detection runs (a `probe` role in the process).
    pub probe: bool,
    /// The listeners.
    pub listeners: Vec<DhcpListenerItem>,
    /// The scopes served.
    pub scopes: u32,
    /// The leases by state.
    pub leases: Vec<DhcpLeaseCount>,
    /// The last commit's duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_commit_ms: Option<f64>,
    /// The revision of the configuration image served.
    pub revision: Revision,
    // WP9.4: the DHCPv6 side of the report.
    /// The DHCPv6 listeners (port 547).
    #[serde(default)]
    pub listeners6: Vec<DhcpListenerItem>,
    /// The DHCPv6 scopes served.
    #[serde(default)]
    pub scopes6: u32,
    /// The DHCPv6 leases by state.
    #[serde(default)]
    pub leases6: Vec<DhcpLeaseCount>,
    // WP9.4: the router advertisement check and the server DUID (WP9.2).
    /// The router advertisement check of DHCP-10 (`docs/dhcp.md` section 19.12).
    #[serde(default)]
    pub ra: DhcpRaReport,
    /// The DHCPv6 server's DUID in hexadecimal, when the role serves DHCPv6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "000400000000000000000000000000000001")]
    pub server_duid: Option<String>,
}

/// Whether the router advertisement check runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DhcpRaCheck {
    /// No `probe` role runs in the process.
    #[default]
    Off,
    /// The raw socket for ICMP version 6 could not be opened (`reason` says why).
    Unavailable,
    /// The links are heard.
    Watching,
}

/// The router advertisement check of a node's `dhcp` role.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DhcpRaReport {
    /// Whether it runs.
    pub check: DhcpRaCheck,
    /// Why it is unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The links heard in the last hour, by interface.
    #[serde(default)]
    pub links: Vec<DhcpRaLink>,
    /// The findings, which are also health rows of `GET /system/status`.
    #[serde(default)]
    pub findings: Vec<DhcpRaFinding>,
}

/// One link as the router advertisement check hears it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpRaLink {
    /// The interface.
    #[schema(example = "eth0")]
    pub interface: String,
    /// The routers heard, by link-local address.
    #[schema(value_type = Vec<String>, example = json!(["fe80::1"]))]
    pub routers: Vec<std::net::Ipv6Addr>,
    /// Whether a router sets M (managed address configuration).
    pub managed: bool,
    /// Whether a router sets O (other configuration).
    pub other: bool,
    /// The prefixes the routers advertise.
    #[schema(example = json!(["2001:db8:100::/64"]))]
    pub prefixes: Vec<String>,
    /// The networks of the enabled DHCPv6 scopes of the link.
    #[schema(example = json!(["2001:db8:100::/64"]))]
    pub scopes: Vec<String>,
    /// When the last advertisement was heard.
    pub seen: Timestamp,
}

/// One finding of the router advertisement check.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpRaFinding {
    /// The health row's code: `dhcp.ra.flags_off`, `dhcp.ra.other_only`,
    /// `dhcp.ra.managed_without_scope` or `dhcp.ra.unchecked`.
    #[schema(example = "dhcp.ra.flags_off")]
    pub code: String,
    /// The interface (empty for `dhcp.ra.unchecked`).
    pub interface: String,
    /// What it means and what to do, in English.
    pub detail: String,
    /// The parameters: `interface`, `routers`, and `scopes` or `prefixes`; `reason` for
    /// `dhcp.ra.unchecked`.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
}

/// A node command was accepted; its outcome follows on the node command's record.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpCommandAccepted {
    /// The command.
    pub command_id: Uuid,
}

// ---------------------------------------------------------------------------------------
// The reconciliation view (IPAM-21, WP8.2): the rows are `tenko_ipam`'s.

pub use tenko_ipam::reconcile::view::{HostTruths, ReconcileKind, ReconcileRow, Truth};

/// The filters of `GET /ipam/reconcile`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ReconcileFilters {
    /// Only rows of addresses inside this prefix, in its VRF.
    pub prefix: Option<PrefixId>,
    /// Only rows of this host (its addresses, its MAC addresses and the rows it is named
    /// in); the answer then carries the host's truths (`host`).
    pub host: Option<HostId>,
    /// Only this kind.
    pub kind: Option<ReconcileKind>,
    /// The cursor of the next page.
    pub cursor: Option<String>,
    /// Items per page, 1 to 1000; 100 by default.
    pub limit: Option<u32>,
    /// Read at least this store revision (read your writes).
    pub at_least: Option<u64>,
}

/// A page of the reconciliation view.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReconcilePage {
    /// The rows of this page, ordered by address, then kind.
    pub items: Vec<ReconcileRow>,
    /// Cursor of the next page; `null` on the last page.
    pub next_cursor: Option<String>,
    /// Store revision the page was read at.
    #[schema(value_type = u64)]
    pub revision: Revision,
    /// With the `host` filter: the host's truths (the OS field by precedence, every OS
    /// guess, the vendors).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostTruths>,
}
