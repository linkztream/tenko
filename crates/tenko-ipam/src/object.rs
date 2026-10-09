//! IPAM objects as one sum type, and the [`Entity`] trait that ties each model type to
//! its table.

use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tenko_core::{
    AddressId, HostId, InterfaceId, ObjectKind, ObjectRef, PrefixId, RangeId, SiteId, TenantId,
    VlanId, VrfId,
    codec::KeyCodec,
    ipam::{
        Address, CustomFieldDef, Host, Interface, Meta, Prefix, Range, Site, Tenant, Vlan, Vrf,
    },
    table::TableDef,
};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::tables;

/// Any IPAM object, tagged by kind.
///
/// Adjacently tagged (`{"kind": "prefix", "data": {...}}`) because several variants
/// carry IP addresses (see the encoding rules in `tenko_core::codec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum IpamObject {
    /// A tenant.
    Tenant(Tenant),
    /// A VRF.
    Vrf(Vrf),
    /// A site.
    Site(Site),
    /// A VLAN.
    Vlan(Vlan),
    /// A prefix.
    Prefix(Prefix),
    /// A range.
    Range(Range),
    /// An address.
    Address(Address),
    /// A host.
    Host(Host),
    /// An interface.
    Interface(Interface),
    /// A custom field definition.
    CustomField(CustomFieldDef),
}

impl IpamObject {
    /// The reference of the object.
    pub fn object_ref(&self) -> ObjectRef {
        match self {
            IpamObject::Tenant(o) => o.id.into(),
            IpamObject::Vrf(o) => o.id.into(),
            IpamObject::Site(o) => o.id.into(),
            IpamObject::Vlan(o) => o.id.into(),
            IpamObject::Prefix(o) => o.id.into(),
            IpamObject::Range(o) => o.id.into(),
            IpamObject::Address(o) => o.id.into(),
            IpamObject::Host(o) => o.id.into(),
            IpamObject::Interface(o) => o.id.into(),
            IpamObject::CustomField(o) => o.id.into(),
        }
    }

    /// The metadata, for every kind but custom field definitions.
    pub fn meta(&self) -> Option<&Meta> {
        match self {
            IpamObject::Tenant(o) => Some(&o.meta),
            IpamObject::Vrf(o) => Some(&o.meta),
            IpamObject::Site(o) => Some(&o.meta),
            IpamObject::Vlan(o) => Some(&o.meta),
            IpamObject::Prefix(o) => Some(&o.meta),
            IpamObject::Range(o) => Some(&o.meta),
            IpamObject::Address(o) => Some(&o.meta),
            IpamObject::Host(o) => Some(&o.meta),
            IpamObject::Interface(o) => Some(&o.meta),
            IpamObject::CustomField(_) => None,
        }
    }

    /// A short human label: the name, CIDR, address or key.
    pub fn label(&self) -> String {
        match self {
            IpamObject::Tenant(o) => o.name.clone(),
            IpamObject::Vrf(o) => o.name.clone(),
            IpamObject::Site(o) => o.name.clone(),
            IpamObject::Vlan(o) => format!("{} ({})", o.vid, o.name),
            IpamObject::Prefix(o) => o.cidr.to_string(),
            IpamObject::Range(o) => format!("{}-{}", o.first, o.last),
            IpamObject::Address(o) => o.ip.to_string(),
            IpamObject::Host(o) => o.name.to_string(),
            IpamObject::Interface(o) => o.name.clone(),
            IpamObject::CustomField(o) => o.key.to_string(),
        }
    }
}

/// A model type stored in its own `ipam.*` table under its identifier.
pub trait Entity:
    Clone + fmt::Debug + PartialEq + Serialize + DeserializeOwned + Send + Sync + 'static
{
    /// The identifier type.
    type Id: KeyCodec
        + Copy
        + Ord
        + fmt::Display
        + fmt::Debug
        + Into<ObjectRef>
        + From<Uuid>
        + Send
        + Sync
        + 'static;

    /// The object kind.
    const KIND: ObjectKind;

    /// The collection name in the API (`prefixes`).
    const COLLECTION: &'static str;

    /// The table.
    fn table() -> &'static TableDef<Self::Id, Self>;

    /// The identifier.
    fn id(&self) -> Self::Id;

    /// The metadata.
    fn meta(&self) -> &Meta;

    /// The metadata, mutable.
    fn meta_mut(&mut self) -> &mut Meta;

    /// Wraps the object.
    fn into_object(self) -> IpamObject;

    /// Unwraps an object of this kind.
    fn from_object(object: IpamObject) -> Option<Self>;

    /// The object reference.
    fn object_ref(&self) -> ObjectRef {
        self.id().into()
    }
}

macro_rules! entity {
    ($ty:ident, $id:ident, $kind:ident, $collection:literal, $table:ident) => {
        impl Entity for $ty {
            type Id = $id;
            const KIND: ObjectKind = ObjectKind::$kind;
            const COLLECTION: &'static str = $collection;

            fn table() -> &'static TableDef<$id, $ty> {
                &tables::$table
            }

            fn id(&self) -> $id {
                self.id
            }

            fn meta(&self) -> &Meta {
                &self.meta
            }

            fn meta_mut(&mut self) -> &mut Meta {
                &mut self.meta
            }

            fn into_object(self) -> IpamObject {
                IpamObject::$ty(self)
            }

            fn from_object(object: IpamObject) -> Option<Self> {
                match object {
                    IpamObject::$ty(inner) => Some(inner),
                    _ => None,
                }
            }
        }
    };
}

entity!(Tenant, TenantId, Tenant, "tenants", TENANTS);
entity!(Vrf, VrfId, Vrf, "vrfs", VRFS);
entity!(Site, SiteId, Site, "sites", SITES);
entity!(Vlan, VlanId, Vlan, "vlans", VLANS);
entity!(Prefix, PrefixId, Prefix, "prefixes", PREFIXES);
entity!(Range, RangeId, Range, "ranges", RANGES);
entity!(Address, AddressId, Address, "addresses", ADDRESSES);
entity!(Host, HostId, Host, "hosts", HOSTS);
entity!(Interface, InterfaceId, Interface, "interfaces", INTERFACES);

/// The API collection name of an IPAM kind (`prefix` is `prefixes`).
pub fn collection_of(kind: ObjectKind) -> Option<&'static str> {
    Some(match kind {
        ObjectKind::Tenant => Tenant::COLLECTION,
        ObjectKind::Vrf => Vrf::COLLECTION,
        ObjectKind::Site => Site::COLLECTION,
        ObjectKind::Vlan => Vlan::COLLECTION,
        ObjectKind::Prefix => Prefix::COLLECTION,
        ObjectKind::Range => Range::COLLECTION,
        ObjectKind::Address => Address::COLLECTION,
        ObjectKind::Host => Host::COLLECTION,
        ObjectKind::Interface => Interface::COLLECTION,
        ObjectKind::CustomField => "custom-fields",
        _ => return None,
    })
}

/// The IPAM kind of an API collection name.
pub fn kind_of_collection(collection: &str) -> Option<ObjectKind> {
    IPAM_KINDS
        .iter()
        .copied()
        .find(|kind| collection_of(*kind) == Some(collection))
}

/// The kinds of IPAM objects that carry [`Meta`] (and so tags, custom fields and soft
/// delete).
pub const IPAM_KINDS: [ObjectKind; 9] = [
    ObjectKind::Tenant,
    ObjectKind::Vrf,
    ObjectKind::Site,
    ObjectKind::Vlan,
    ObjectKind::Prefix,
    ObjectKind::Range,
    ObjectKind::Address,
    ObjectKind::Host,
    ObjectKind::Interface,
];

#[cfg(test)]
mod tests {
    use tenko_core::codec::{from_cbor, to_cbor};

    use super::*;
    use crate::testutil::{prefix, stamp};

    #[test]
    fn objects_round_trip_in_cbor_and_json() {
        let object = IpamObject::Prefix(prefix("192.0.2.0/24"));
        let back: IpamObject = from_cbor(&to_cbor(&object).expect("cbor")).expect("cbor");
        assert_eq!(back, object);
        let json = serde_json::to_value(&object).expect("json");
        assert_eq!(json["kind"], "prefix");
        assert_eq!(json["data"]["cidr"], "192.0.2.0/24");
        assert_eq!(object.label(), "192.0.2.0/24");
        let _ = stamp();
    }

    #[test]
    fn collections_map_both_ways() {
        for kind in IPAM_KINDS {
            let collection = collection_of(kind).expect("collection");
            assert_eq!(kind_of_collection(collection), Some(kind));
        }
        assert_eq!(collection_of(ObjectKind::User), None);
    }
}
