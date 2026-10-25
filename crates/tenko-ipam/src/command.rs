//! Commands: what a caller wants to change (IPAM-01 to IPAM-18).
//!
//! A command is intent, not a write: [`crate::plan()`] turns a list of commands into an
//! [`IpamPlan`](crate::plan::IpamPlan) against a read view, and the service applies the
//! plan as one write batch. Every list of commands is a bulk change (API-04): it applies
//! completely or not at all.
//!
//! Inputs carry optional client-chosen identifiers, so later commands of the same list can
//! refer to objects created by earlier ones (an import creates a host, its interface and
//! its address in one plan). Patches follow JSON merge-patch rules: an absent field stays,
//! `null` clears an optional field, a value replaces it.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use tenko_core::{
    AddressId, CustomFieldId, HostId, InterfaceId, MacAddr, ObjectKind, ObjectRef, PrefixId,
    RangeId, Revision, SiteId, TenantId, VlanId, VrfId,
    ipam::{
        AllocPolicy, AssignmentMode, CustomKind, CustomValue, DnsReverse, FieldKey, PrefixRole,
        RangeRole, Status, Tag, UtilizationAlarm,
    },
    net::{Duid, Fqdn, HostName},
    serde_util::HexBytes,
};
use utoipa::ToSchema;

/// Deserializes a field of a patch: absent stays `None` (through `#[serde(default)]`),
/// `null` becomes `Some(None)`, a value becomes `Some(Some(value))`.
///
/// # Errors
///
/// Returns the deserializer's error for a value of the wrong type.
pub fn nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

macro_rules! meta_input_fields {
    ($(#[$meta:meta])* pub struct $name:ident { $($(#[$fmeta:meta])* pub $field:ident : $ty:ty,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
            /// Tags (IPAM-08).
            #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
            pub tags: BTreeSet<Tag>,
            /// Custom field values (IPAM-08).
            #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
            pub custom: BTreeMap<FieldKey, CustomValue>,
            /// Free text.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub description: Option<String>,
        }
    };
}

macro_rules! meta_patch_fields {
    ($(#[$meta:meta])* pub struct $name:ident { $($(#[$fmeta:meta])* pub $field:ident : $ty:ty,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
            /// Replaces the tags.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub tags: Option<BTreeSet<Tag>>,
            /// Sets custom field values; `null` removes a value.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[schema(value_type = Option<BTreeMap<String, CustomValue>>)]
            pub custom: Option<BTreeMap<FieldKey, Option<CustomValue>>>,
            /// Replaces the description; `null` clears it.
            #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
            #[schema(value_type = Option<String>, nullable)]
            pub description: Option<Option<String>>,
        }
    };
}

meta_input_fields! {
    /// A new tenant.
    pub struct TenantInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<TenantId>,
        /// Unique name.
        pub name: String,
    }
}

meta_patch_fields! {
    /// Changes to a tenant.
    pub struct TenantPatch {
        /// New name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        // Backlog: the tenant's default zone.
        /// The DNS settings, replaced as a whole: `{"default_zone": "<zone id>"}` sets the
        /// default zone of the tenant's reverse zones, `{}` clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns: Option<tenko_core::dns::TenantDns>,
    }
}

meta_input_fields! {
    /// A new VRF.
    pub struct VrfInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<VrfId>,
        /// Owning tenant; the default tenant when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tenant: Option<TenantId>,
        /// Name, unique within the tenant.
        pub name: String,
        /// Route distinguisher.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rd: Option<String>,
    }
}

meta_patch_fields! {
    /// Changes to a VRF. The tenant cannot change.
    pub struct VrfPatch {
        /// New name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// New route distinguisher; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub rd: Option<Option<String>>,
    }
}

meta_input_fields! {
    /// A new site.
    pub struct SiteInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<SiteId>,
        /// Unique name.
        pub name: String,
        /// Parent site.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parent: Option<SiteId>,
        /// Matching Active Directory site.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ad_site: Option<String>,
    }
}

meta_patch_fields! {
    /// Changes to a site.
    pub struct SitePatch {
        /// New name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// New parent; `null` makes it a top-level site.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub parent: Option<Option<SiteId>>,
        /// New Active Directory site; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub ad_site: Option<Option<String>>,
    }
}

meta_input_fields! {
    /// A new VLAN.
    pub struct VlanInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<VlanId>,
        /// VLAN id, 1 to 4094, unique per site.
        pub vid: u16,
        /// VXLAN network identifier, up to 16,777,215.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vni: Option<u32>,
        /// Name.
        pub name: String,
        /// Site; global when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub site: Option<SiteId>,
        /// Status; `active` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
    }
}

meta_patch_fields! {
    /// Changes to a VLAN.
    pub struct VlanPatch {
        /// New VLAN id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vid: Option<u16>,
        /// New VNI; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u32>, nullable)]
        pub vni: Option<Option<u32>>,
        /// New name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// New site; `null` makes it global.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub site: Option<Option<SiteId>>,
        /// New status (IPAM-05 transitions apply).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
    }
}

meta_input_fields! {
    /// A new prefix.
    pub struct PrefixInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<PrefixId>,
        /// VRF; the default VRF when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vrf: Option<VrfId>,
        /// The network, without host bits.
        #[schema(value_type = String, example = "192.0.2.0/24")]
        pub cidr: IpNet,
        /// Role; a supernet when the prefix would contain existing prefixes, else a
        /// network.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<PrefixRole>,
        /// Status; `active` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
        /// VLAN.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vlan: Option<VlanId>,
        /// Site.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub site: Option<SiteId>,
        /// Utilization alarm thresholds (IPAM-10).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alarm: Option<UtilizationAlarm>,
        /// Next-free policy (IPAM-07); lowest first when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alloc: Option<AllocPolicy>,
    }
}

meta_patch_fields! {
    /// Changes to a prefix. The VRF cannot change.
    pub struct PrefixPatch {
        /// New network (resize or renumber); children, addresses and ranges must still fit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, example = "192.0.2.0/23")]
        pub cidr: Option<IpNet>,
        /// New role.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<PrefixRole>,
        /// New status (IPAM-05 transitions apply).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
        /// New VLAN; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub vlan: Option<Option<VlanId>>,
        /// New site; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub site: Option<Option<SiteId>>,
        /// New alarm thresholds; `null` removes the alarm.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<UtilizationAlarm>, nullable)]
        pub alarm: Option<Option<UtilizationAlarm>>,
        /// New next-free policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alloc: Option<AllocPolicy>,
        /// Whether Tenko keeps the reverse zone (plan section 2.6); `null` returns to the
        /// automatic default.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<DnsReverse>, nullable)]
        pub dns_reverse: Option<Option<DnsReverse>>,
    }
}

meta_input_fields! {
    /// A new range inside a network prefix.
    pub struct RangeInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<RangeId>,
        /// The network prefix.
        pub prefix: PrefixId,
        /// First address, inclusive.
        #[schema(value_type = String, example = "192.0.2.100")]
        pub first: IpAddr,
        /// Last address, inclusive.
        #[schema(value_type = String, example = "192.0.2.199")]
        pub last: IpAddr,
        /// What the range is for.
        pub role: RangeRole,
        /// Status; `active` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
        /// DHCP lease time in seconds, 60 to 31,536,000 (`dhcp_pool` ranges only); half of it
        /// is the default timeout of moves into the prefix (IPAM-19).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lease_secs: Option<u32>,
        /// The length of the delegated prefixes, `dhcp_pd_pool` ranges only (required
        /// there): between the network's length and 64, with the range on its boundaries.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegated_len: Option<u8>,
    }
}

meta_patch_fields! {
    /// Changes to a range. The prefix cannot change.
    pub struct RangePatch {
        /// New first address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>)]
        pub first: Option<IpAddr>,
        /// New last address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>)]
        pub last: Option<IpAddr>,
        /// New role.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<RangeRole>,
        /// New status (IPAM-05 transitions apply).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
        /// New DHCP lease time in seconds (`dhcp_pool` ranges only); `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u32>, nullable)]
        pub lease_secs: Option<Option<u32>>,
        /// New length of the delegated prefixes (`dhcp_pd_pool` ranges only); `null`
        /// clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u8>, nullable)]
        pub delegated_len: Option<Option<u8>>,
    }
}

meta_input_fields! {
    /// A new address.
    pub struct AddressInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<AddressId>,
        /// VRF; the default VRF when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vrf: Option<VrfId>,
        /// The address; its most specific prefix in the VRF becomes its prefix.
        #[schema(value_type = String, example = "192.0.2.10")]
        pub ip: IpAddr,
        /// Status; `active` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
        /// Interface the address is assigned to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub interface: Option<InterfaceId>,
        /// Intended DNS name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns_name: Option<Fqdn>,
    }
}

meta_patch_fields! {
    /// Changes to an address. The VRF cannot change.
    pub struct AddressPatch {
        /// New address (renumber); the prefix is recomputed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>)]
        pub ip: Option<IpAddr>,
        /// New status (IPAM-05 transitions apply).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Status>,
        /// New interface; `null` unassigns the address.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub interface: Option<Option<InterfaceId>>,
        /// New DNS name; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub dns_name: Option<Option<Fqdn>>,
    }
}

meta_input_fields! {
    /// A new interface.
    pub struct InterfaceInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<InterfaceId>,
        /// Owning host; may be left out inside [`HostInput::interfaces`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<HostId>,
        /// Name, unique per host (`eth0`).
        pub name: String,
        /// MAC address (DHCPv4 reservations).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mac: Option<MacAddr>,
        /// DUID (DHCPv6 reservations).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub duid: Option<Duid>,
        /// DHCPv4 client identifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<HexBytes>,
    }
}

meta_patch_fields! {
    /// Changes to an interface. The host cannot change.
    pub struct InterfacePatch {
        /// New name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// New MAC address; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub mac: Option<Option<MacAddr>>,
        /// New DUID; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub duid: Option<Option<Duid>>,
        /// New client identifier; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub client_id: Option<Option<HexBytes>>,
    }
}

meta_input_fields! {
    /// A new host, optionally with its interfaces.
    pub struct HostInput {
        /// Client-chosen identifier; generated when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<HostId>,
        /// Owning tenant; the default tenant when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tenant: Option<TenantId>,
        /// Name, unique within the tenant.
        #[schema(value_type = String, example = "nas01")]
        pub name: HostName,
        /// Assignment mode (IPAM-14); `static` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<AssignmentMode>,
        /// Lock against automation (IPAM-16).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lock: Option<bool>,
        /// Site.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub site: Option<SiteId>,
        /// Interfaces created with the host.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub interfaces: Vec<InterfaceInput>,
    }
}

meta_patch_fields! {
    /// Changes to a host. The tenant cannot change.
    pub struct HostPatch {
        /// New name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>)]
        pub name: Option<HostName>,
        /// New assignment mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<AssignmentMode>,
        /// Lock or unlock (people only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lock: Option<bool>,
        /// New site; `null` clears it.
        #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<String>, nullable)]
        pub site: Option<Option<SiteId>>,
    }
}

/// A new custom field definition (IPAM-08).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CustomFieldInput {
    /// Client-chosen identifier; generated when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<CustomFieldId>,
    /// The key, `[a-z][a-z0-9_]{0,63}`.
    pub key: FieldKey,
    /// Value type.
    pub kind: CustomKind,
    /// Object kinds the field applies to.
    pub applies_to: Vec<ObjectKind>,
    /// Whether every object of those kinds must have a value.
    #[serde(default)]
    pub required: bool,
}

/// Changes to a custom field definition. The key cannot change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CustomFieldPatch {
    /// New value type (a select may only gain options).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CustomKind>,
    /// New object kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<Vec<ObjectKind>>,
    /// New required flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

macro_rules! update_command {
    ($(#[$meta:meta])* $name:ident, $id:ty, $patch:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
        pub struct $name {
            /// The object.
            pub id: $id,
            /// The revision the caller read (`If-Match`); the plan fails when it differs.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[schema(value_type = Option<u64>)]
            pub expected: Option<Revision>,
            /// The changes.
            pub patch: $patch,
        }
    };
}

update_command!(
    /// Updates a tenant.
    UpdateTenant, TenantId, TenantPatch
);
update_command!(
    /// Updates a VRF.
    UpdateVrf, VrfId, VrfPatch
);
update_command!(
    /// Updates a site.
    UpdateSite, SiteId, SitePatch
);
update_command!(
    /// Updates a VLAN.
    UpdateVlan, VlanId, VlanPatch
);
update_command!(
    /// Updates a prefix.
    UpdatePrefix, PrefixId, PrefixPatch
);
update_command!(
    /// Updates a range.
    UpdateRange, RangeId, RangePatch
);
update_command!(
    /// Updates an address.
    UpdateAddress, AddressId, AddressPatch
);
update_command!(
    /// Updates a host.
    UpdateHost, HostId, HostPatch
);
update_command!(
    /// Updates an interface.
    UpdateInterface, InterfaceId, InterfacePatch
);

/// Updates a custom field definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateCustomField {
    /// The key.
    pub key: FieldKey,
    /// The revision of the definition the caller read (`If-Match`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<u64>)]
    pub expected: Option<Revision>,
    /// The changes.
    pub patch: CustomFieldPatch,
}

/// Allocates the next free address of a prefix (IPAM-07) and creates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AllocateAddress {
    /// The prefix to allocate from.
    pub prefix: PrefixId,
    /// Allocation end; the prefix's policy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<AllocPolicy>,
    /// Allocate inside this range of the prefix; outside every range when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<RangeId>,
    /// Client-chosen identifier of the new address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<AddressId>,
    /// Status of the new address; `active` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Interface of the new address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceId>,
    /// DNS name of the new address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<Fqdn>,
    /// Tags of the new address.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<Tag>,
    /// Custom field values of the new address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<FieldKey, CustomValue>,
    /// Description of the new address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// A candidate from the prefix tree. The plan uses it when it is free in the read
    /// view and searches the view otherwise; callers normally leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub hint: Option<IpAddr>,
}

/// Allocates the next free child prefix of a given length (IPAM-07) and creates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AllocatePrefix {
    /// The supernet to allocate from.
    pub parent: PrefixId,
    /// Prefix length of the new prefix.
    pub length: u8,
    /// Allocation end; the parent's policy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<AllocPolicy>,
    /// Client-chosen identifier of the new prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<PrefixId>,
    /// Role of the new prefix; `network` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<PrefixRole>,
    /// Status of the new prefix; `active` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// VLAN of the new prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VlanId>,
    /// Site of the new prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<SiteId>,
    /// Alarm thresholds of the new prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarm: Option<UtilizationAlarm>,
    /// Tags of the new prefix.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<Tag>,
    /// Custom field values of the new prefix.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<FieldKey, CustomValue>,
    /// Description of the new prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// A candidate from the prefix tree, verified against the read view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub hint: Option<IpNet>,
}

/// Decommissions a host: its addresses are released (unassigned, and their DNS names
/// removed unless `keep_dns`), its facts raise no proposals and the default lists leave it
/// out. A reinstatement binds the addresses again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DecommissionHost {
    /// The host.
    pub host: HostId,
    /// Why, for the list of decommissioned hosts (at most 1,024 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Keep the DNS names of the released addresses, so their records stay. By default the
    /// names are removed and the DNS actuator removes the records.
    #[serde(default)]
    pub keep_dns: bool,
    /// The revision the caller read (`If-Match`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<u64>)]
    pub expected: Option<Revision>,
}

/// One change, as part of a plan.
///
/// Adjacently tagged (`{"op": "create_prefix", "args": {...}}`) because arguments carry
/// IP addresses (see the encoding rules in `tenko_core::codec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op", content = "args", rename_all = "snake_case")]
pub enum IpamCommand {
    /// Creates a tenant.
    CreateTenant(TenantInput),
    /// Updates a tenant.
    UpdateTenant(UpdateTenant),
    /// Creates a VRF.
    CreateVrf(VrfInput),
    /// Updates a VRF.
    UpdateVrf(UpdateVrf),
    /// Creates a site.
    CreateSite(SiteInput),
    /// Updates a site.
    UpdateSite(UpdateSite),
    /// Creates a VLAN.
    CreateVlan(VlanInput),
    /// Updates a VLAN.
    UpdateVlan(UpdateVlan),
    /// Creates a prefix.
    CreatePrefix(PrefixInput),
    /// Updates a prefix.
    UpdatePrefix(UpdatePrefix),
    /// Creates a range.
    CreateRange(RangeInput),
    /// Updates a range.
    UpdateRange(UpdateRange),
    /// Creates an address.
    CreateAddress(AddressInput),
    /// Updates an address.
    UpdateAddress(UpdateAddress),
    /// Creates a host.
    CreateHost(HostInput),
    /// Updates a host.
    UpdateHost(UpdateHost),
    /// Creates an interface.
    CreateInterface(InterfaceInput),
    /// Updates an interface.
    UpdateInterface(UpdateInterface),
    /// Soft-deletes an object (IPAM-09).
    Delete {
        /// The object.
        object: ObjectRef,
        /// The revision the caller read (`If-Match`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u64>)]
        expected: Option<Revision>,
        /// Also delete what would otherwise block the delete: the addresses and ranges of
        /// a prefix, the addresses of a host or an interface.
        #[serde(default)]
        cascade: bool,
    },
    /// Restores a soft-deleted object (IPAM-09).
    Restore {
        /// The object.
        object: ObjectRef,
        /// The revision the caller read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u64>)]
        expected: Option<Revision>,
    },
    /// Locks or unlocks a host against automation (IPAM-16).
    SetLock {
        /// The host.
        host: HostId,
        /// Whether the host is locked.
        lock: bool,
        /// The revision the caller read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u64>)]
        expected: Option<Revision>,
    },
    /// Changes the assignment mode of a host (IPAM-14).
    SetMode {
        /// The host.
        host: HostId,
        /// The new mode.
        mode: AssignmentMode,
        /// The revision the caller read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u64>)]
        expected: Option<Revision>,
    },
    /// Decommissions a host (its lifecycle state).
    DecommissionHost(DecommissionHost),
    /// Reinstates a decommissioned host: the addresses it released and that are still free
    /// are bound again, with the DNS names they lost.
    ReinstateHost {
        /// The host.
        host: HostId,
        /// The revision the caller read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u64>)]
        expected: Option<Revision>,
    },
    /// Allocates and creates the next free address (IPAM-07).
    AllocateAddress(AllocateAddress),
    /// Allocates and creates the next free child prefix (IPAM-07).
    AllocatePrefix(AllocatePrefix),
    /// Creates a custom field definition (IPAM-08).
    CreateCustomField(CustomFieldInput),
    /// Updates a custom field definition.
    UpdateCustomField(UpdateCustomField),
    /// Removes a custom field definition that no object uses.
    DeleteCustomField {
        /// The key.
        key: FieldKey,
        /// The revision of the definition the caller read (`If-Match`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<u64>)]
        expected: Option<Revision>,
    },
}

impl IpamCommand {
    /// The kind of object the command creates or changes.
    pub fn kind(&self) -> ObjectKind {
        match self {
            IpamCommand::CreateTenant(_) | IpamCommand::UpdateTenant(_) => ObjectKind::Tenant,
            IpamCommand::CreateVrf(_) | IpamCommand::UpdateVrf(_) => ObjectKind::Vrf,
            IpamCommand::CreateSite(_) | IpamCommand::UpdateSite(_) => ObjectKind::Site,
            IpamCommand::CreateVlan(_) | IpamCommand::UpdateVlan(_) => ObjectKind::Vlan,
            IpamCommand::CreatePrefix(_)
            | IpamCommand::UpdatePrefix(_)
            | IpamCommand::AllocatePrefix(_) => ObjectKind::Prefix,
            IpamCommand::CreateRange(_) | IpamCommand::UpdateRange(_) => ObjectKind::Range,
            IpamCommand::CreateAddress(_)
            | IpamCommand::UpdateAddress(_)
            | IpamCommand::AllocateAddress(_) => ObjectKind::Address,
            IpamCommand::CreateHost(_)
            | IpamCommand::UpdateHost(_)
            | IpamCommand::SetLock { .. }
            | IpamCommand::SetMode { .. }
            | IpamCommand::DecommissionHost(_)
            | IpamCommand::ReinstateHost { .. } => ObjectKind::Host,
            IpamCommand::CreateInterface(_) | IpamCommand::UpdateInterface(_) => {
                ObjectKind::Interface
            }
            IpamCommand::Delete { object, .. } | IpamCommand::Restore { object, .. } => object.kind,
            IpamCommand::CreateCustomField(_)
            | IpamCommand::UpdateCustomField(_)
            | IpamCommand::DeleteCustomField { .. } => ObjectKind::CustomField,
        }
    }

    /// The prefixes an allocation command allocates from (the service serializes local
    /// allocators per prefix).
    pub fn allocation_prefix(&self) -> Option<PrefixId> {
        match self {
            IpamCommand::AllocateAddress(alloc) => Some(alloc.prefix),
            IpamCommand::AllocatePrefix(alloc) => Some(alloc.parent),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::codec::{from_cbor, to_cbor};

    use super::*;

    #[test]
    fn patches_distinguish_absent_null_and_value() {
        let patch: PrefixPatch = serde_json::from_str(r#"{"vlan": null}"#).expect("json");
        assert_eq!(patch.vlan, Some(None));
        assert_eq!(patch.site, None);
        let patch: PrefixPatch =
            serde_json::from_str(r#"{"description": "lab", "cidr": "192.0.2.0/25"}"#)
                .expect("json");
        assert_eq!(patch.description, Some(Some("lab".to_owned())));
        assert_eq!(patch.cidr, Some("192.0.2.0/25".parse().expect("cidr")));
        let back: PrefixPatch = from_cbor(&to_cbor(&patch).expect("cbor")).expect("cbor");
        assert_eq!(back, patch);
        let cleared = PrefixPatch {
            vlan: Some(None),
            ..PrefixPatch::default()
        };
        let back: PrefixPatch = from_cbor(&to_cbor(&cleared).expect("cbor")).expect("cbor");
        assert_eq!(back, cleared);
    }

    #[test]
    fn commands_round_trip_in_json_and_cbor() {
        let commands = vec![
            IpamCommand::CreatePrefix(PrefixInput {
                id: None,
                vrf: None,
                cidr: "192.0.2.0/24".parse().expect("cidr"),
                role: None,
                status: None,
                vlan: None,
                site: None,
                alarm: None,
                alloc: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: Some("lab".to_owned()),
            }),
            IpamCommand::Delete {
                object: ObjectRef::from(PrefixId::generate()),
                expected: Some(Revision(4)),
                cascade: false,
            },
            IpamCommand::AllocateAddress(AllocateAddress {
                prefix: PrefixId::generate(),
                policy: None,
                range: None,
                id: None,
                status: None,
                interface: None,
                dns_name: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
                hint: Some("192.0.2.9".parse().expect("ip")),
            }),
        ];
        let json = serde_json::to_value(&commands).expect("json");
        assert_eq!(json[0]["op"], "create_prefix");
        assert_eq!(json[0]["args"]["cidr"], "192.0.2.0/24");
        let back: Vec<IpamCommand> = serde_json::from_value(json).expect("json");
        assert_eq!(back, commands);
        let back: Vec<IpamCommand> = from_cbor(&to_cbor(&commands).expect("cbor")).expect("cbor");
        assert_eq!(back, commands);
        assert_eq!(commands[2].kind(), ObjectKind::Address);
    }
}
