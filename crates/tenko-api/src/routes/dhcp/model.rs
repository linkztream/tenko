//! Request and response bodies of the DHCP routes (WP7.0 contracts; WP7.4, WP7.5, WP8.x and
//! WP9.3 implement them). The stored model is `tenko_core::dhcp`; these types add the
//! revision of a read and the values derived for display (the network of a scope, the
//! typed view of an option), and shape writes.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, Class, ClassId, Condition, DdnsPolicy, DhcpSettings, ExclusionRange, Filter,
        FilterKind, Lease, LeaseEvent, LeaseEventKind, LeaseTimes, MacPattern, Match, OptionData,
        OptionDef, OptionKind, OptionLevel, OptionOwner, OptionSpace, OptionValue, Policy,
        PolicyAction, PolicyId, PoolSettings, ReservationWarning, Scope, SharedNetwork,
        SharedNetworkId,
    },
    ipam::Stamp,
    ir::LossEntry,
    net::{HostName, MacAddr},
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

/// A pool: an IPAM range of role `dhcp_pool` with its DHCP settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpPoolItem {
    /// The range.
    pub range: RangeId,
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
    /// Addresses in the pool, exclusions taken out.
    pub size: u64,
    /// Addresses with an active lease.
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

/// A lease as the API reads it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpLeaseItem {
    /// The lease.
    #[serde(flatten)]
    pub lease: Lease,
    /// The host IPAM knows for the client, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostId>,
    /// Whether the address is the client's reservation.
    pub reserved: bool,
    /// The store revision of the row.
    pub revision: Revision,
}

/// The filters of `GET /dhcp/leases`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DhcpLeaseFilters {
    /// Only this scope.
    pub scope: Option<PrefixId>,
    /// Addresses starting with this text (`192.0.2.`).
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

/// One row of the lease history.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpHistoryItem {
    /// The event.
    #[serde(flatten)]
    pub event: LeaseEvent,
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

/// The Kea export (P3-Q17): the configurations, the leases and what did not map.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DhcpExport {
    /// The `Dhcp4` configuration.
    #[schema(value_type = Object)]
    pub dhcp4: serde_json::Value,
    /// The `Dhcp6` configuration (Slice 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub dhcp6: Option<serde_json::Value>,
    /// The DHCPv4 leases as Kea memfile CSV.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leases4_csv: Option<String>,
    /// What did not map.
    #[serde(default)]
    pub losses: Vec<LossEntry>,
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
