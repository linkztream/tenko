//! The `ipam.*` tables and counters.
//!
//! Primary tables hold one object per 16-byte identifier. Secondary tables hold
//! uniqueness keys (only for objects that are not soft-deleted) and memberships (for
//! deleted objects too, so a restore finds them). Values of secondary tables are the
//! identifier or the unit value `()`.
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `ipam.tenants` .. `ipam.interfaces` | identifier | the object |
//! | `ipam.custom_fields` | `CustomFieldId` | [`CustomFieldDef`] |
//! | `ipam.custom_field_keys` | key text | `CustomFieldId` |
//! | `ipam.tenant_names` | lowercase name | `TenantId` |
//! | `ipam.vrf_names` | (tenant, lowercase name) | `VrfId` |
//! | `ipam.site_names` | lowercase name | `SiteId` |
//! | `ipam.vlan_vids` | (site or none, VLAN id) | `VlanId` |
//! | `ipam.prefix_cidrs` | (VRF, network) | `PrefixId` |
//! | `ipam.address_ips` | (VRF, address) | `AddressId` |
//! | `ipam.host_names` | (tenant, host name) | `HostId` |
//! | `ipam.host_interfaces` | (host, interface) | `()` |
//! | `ipam.interface_addresses` | (interface, address) | `()` |
//! | `ipam.interface_macs` | (MAC, interface) | `()` |
//! | `ipam.prefix_ranges` | (prefix, range) | `()` |
//! | `ipam.tag_usage` | (tag, object) | `()` |
//! | `ipam.field_usage` | (field key, object) | `()` |
//! | `ipam.history` | (object, time, request, base revision, index) | [`HistoryEntry`] |
//! | `ipam.alarms` | `PrefixId` | [`AlarmEvent`] |
//! | `ipam.receipts` | (principal subject, idempotency key) | [`Receipt`] |
//! | `ipam.move_receipts` | (principal subject, idempotency key) | `MoveReceipt` |
//!
//! Counters (checked by preconditions, bumped by mutations):
//!
//! - [`tree_counter`] `ipam.tree/<vrf>`: the prefix set of a VRF changed (create, delete,
//!   restore, CIDR change). Every plan that reads the prefix set of a VRF expects it.
//! - [`alloc_counter`] `ipam.alloc/<prefix>`: the addresses or ranges whose most specific
//!   prefix is this one changed. Plans that read that set expect it; next free relies on
//!   it.
//! - [`refs_counter`] `ipam.refs/<object>`: something started to reference the object.
//!   A delete that found no references expects it, so a concurrent new reference makes the
//!   delete retry instead of leaving a dangling reference.
//!
//! [`CustomFieldDef`]: tenko_core::ipam::CustomFieldDef
//! [`HistoryEntry`]: crate::history::HistoryEntry
//! [`AlarmEvent`]: crate::alarm::AlarmEvent
//! [`Receipt`]: crate::plan::Receipt

use std::net::IpAddr;

use ipnet::IpNet;
use tenko_core::{
    AddressId, CounterKey, CustomFieldId, HostId, InterfaceId, MacAddr, ObjectRef, PrefixId,
    RangeId, RequestId, Revision, SiteId, TenantId, Timestamp, VlanId, VrfId,
    ipam::{Address, CustomFieldDef, Host, Interface, Prefix, Range, Site, Tenant, Vlan, Vrf},
    net::HostName,
    table::TableDef,
};

use crate::{alarm::AlarmEvent, history::HistoryEntry, plan::Receipt};

/// Tenants.
pub static TENANTS: TableDef<TenantId, Tenant> = TableDef::new("ipam.tenants");
/// VRFs.
pub static VRFS: TableDef<VrfId, Vrf> = TableDef::new("ipam.vrfs");
/// Sites.
pub static SITES: TableDef<SiteId, Site> = TableDef::new("ipam.sites");
/// VLANs.
pub static VLANS: TableDef<VlanId, Vlan> = TableDef::new("ipam.vlans");
/// Prefixes.
pub static PREFIXES: TableDef<PrefixId, Prefix> = TableDef::new("ipam.prefixes");
/// Ranges.
pub static RANGES: TableDef<RangeId, Range> = TableDef::new("ipam.ranges");
/// Addresses.
pub static ADDRESSES: TableDef<AddressId, Address> = TableDef::new("ipam.addresses");
/// Hosts.
pub static HOSTS: TableDef<HostId, Host> = TableDef::new("ipam.hosts");
/// Interfaces.
pub static INTERFACES: TableDef<InterfaceId, Interface> = TableDef::new("ipam.interfaces");
/// Custom field definitions.
pub static CUSTOM_FIELDS: TableDef<CustomFieldId, CustomFieldDef> =
    TableDef::new("ipam.custom_fields");

/// Custom field key to definition.
pub static CUSTOM_FIELD_KEYS: TableDef<String, CustomFieldId> =
    TableDef::new("ipam.custom_field_keys");
/// Tenant names (lowercase) of live tenants.
pub static TENANT_NAMES: TableDef<String, TenantId> = TableDef::new("ipam.tenant_names");
/// VRF names (lowercase) per tenant of live VRFs.
pub static VRF_NAMES: TableDef<(TenantId, String), VrfId> = TableDef::new("ipam.vrf_names");
/// Site names (lowercase) of live sites.
pub static SITE_NAMES: TableDef<String, SiteId> = TableDef::new("ipam.site_names");
/// VLAN ids per site (or global) of live VLANs.
pub static VLAN_VIDS: TableDef<(Option<SiteId>, u16), VlanId> = TableDef::new("ipam.vlan_vids");
/// Networks per VRF of live prefixes.
pub static PREFIX_CIDRS: TableDef<(VrfId, IpNet), PrefixId> = TableDef::new("ipam.prefix_cidrs");
/// Addresses per VRF of live address objects.
pub static ADDRESS_IPS: TableDef<(VrfId, IpAddr), AddressId> = TableDef::new("ipam.address_ips");
/// Host names per tenant of live hosts.
pub static HOST_NAMES: TableDef<(TenantId, HostName), HostId> = TableDef::new("ipam.host_names");
/// Interfaces of a host (deleted ones included).
pub static HOST_INTERFACES: TableDef<(HostId, InterfaceId), ()> =
    TableDef::new("ipam.host_interfaces");
/// Addresses of an interface (deleted ones included).
pub static INTERFACE_ADDRESSES: TableDef<(InterfaceId, AddressId), ()> =
    TableDef::new("ipam.interface_addresses");
/// Interfaces by MAC address (live interfaces).
pub static INTERFACE_MACS: TableDef<(MacAddr, InterfaceId), ()> =
    TableDef::new("ipam.interface_macs");
/// Ranges of a prefix (deleted ones included).
pub static PREFIX_RANGES: TableDef<(PrefixId, RangeId), ()> = TableDef::new("ipam.prefix_ranges");
/// Objects carrying a tag (live objects).
pub static TAG_USAGE: TableDef<(String, ObjectRef), ()> = TableDef::new("ipam.tag_usage");
/// Objects carrying a custom field value (live objects).
pub static FIELD_USAGE: TableDef<(String, ObjectRef), ()> = TableDef::new("ipam.field_usage");
/// Change history (IPAM-09).
pub static HISTORY: TableDef<(ObjectRef, Timestamp, RequestId, Revision, u32), HistoryEntry> =
    TableDef::new("ipam.history");
/// Current utilization alarm level per prefix (IPAM-10); each write is a `system` event.
pub static ALARMS: TableDef<PrefixId, AlarmEvent> = TableDef::new("ipam.alarms");
/// Results of requests that carried an idempotency key (API-04).
pub static RECEIPTS: TableDef<(String, String), Receipt> = TableDef::new("ipam.receipts");
/// Answers of moves submitted with an idempotency key (API-04, IPAM-19).
pub static MOVE_RECEIPTS: TableDef<(String, String), crate::moves::MoveReceipt> =
    TableDef::new("ipam.move_receipts");

/// The prefix-set version of a VRF.
pub fn tree_counter(vrf: VrfId) -> CounterKey {
    CounterKey::with("ipam.tree", &vrf)
}

/// The address and range set version of a prefix.
pub fn alloc_counter(prefix: PrefixId) -> CounterKey {
    CounterKey::with("ipam.alloc", &prefix)
}

/// The reference version of an object.
pub fn refs_counter(object: ObjectRef) -> CounterKey {
    CounterKey::with("ipam.refs", &object)
}

/// Every table of the IPAM domain, for watch filters.
pub fn all_tables() -> Vec<tenko_core::TableName> {
    [
        TENANTS.name(),
        VRFS.name(),
        SITES.name(),
        VLANS.name(),
        PREFIXES.name(),
        RANGES.name(),
        ADDRESSES.name(),
        HOSTS.name(),
        INTERFACES.name(),
        CUSTOM_FIELDS.name(),
        ALARMS.name(),
    ]
    .into_iter()
    .cloned()
    .collect()
}
