//! Identifiers (plan section 2.1).
//!
//! Every entity has a transparent newtype over a UUIDv7, created by the proposer so that a
//! write batch is complete before it reaches the store. UUIDv7 values sort by creation
//! time, which keeps keys of new objects close together in the store.
//!
//! [`NodeId`], [`Revision`] and [`AuditSeq`] are integers.

use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::codec::key::{KeyCodec, KeyError};

/// Defines identifier newtypes over [`uuid::Uuid`] (UUIDv7).
///
/// Each type gets `generate()` (a fresh UUIDv7), conversions from and to `Uuid`,
/// `Display` and `FromStr` in the hyphenated form, serde (a string in JSON, 16 bytes in
/// CBOR), an OpenAPI schema (`string`, format `uuid`) and an order-preserving key encoding.
/// Packages may use the macro for identifiers that stay inside their crate; identifiers that
/// cross crates are added to `tenko-core` by the lead builder.
///
/// ```
/// tenko_core::id_type! {
///     /// Identifier of a widget.
///     WidgetId,
/// }
/// let id = WidgetId::generate();
/// assert_eq!(id.to_string().parse::<WidgetId>().unwrap(), id);
/// ```
#[macro_export]
macro_rules! id_type {
    ($($(#[$meta:meta])* $name:ident),+ $(,)?) => {
        $($crate::__id_type_one!($(#[$meta])* $name);)+
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __id_type_one {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $crate::__private::uuid::Uuid);

        impl $name {
            /// Creates a new identifier from a fresh, time-ordered UUIDv7.
            pub fn generate() -> Self {
                Self($crate::__private::uuid::Uuid::now_v7())
            }

            /// Wraps an existing UUID.
            pub const fn from_uuid(uuid: $crate::__private::uuid::Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID.
            pub const fn uuid(self) -> $crate::__private::uuid::Uuid {
                self.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::error::InvalidValue;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                $crate::__private::uuid::Uuid::parse_str(s.trim())
                    .map(Self)
                    .map_err(|_| $crate::error::InvalidValue::new(
                        stringify!($name), s, "not a UUID"))
            }
        }

        impl ::core::convert::From<$crate::__private::uuid::Uuid> for $name {
            fn from(uuid: $crate::__private::uuid::Uuid) -> Self {
                Self(uuid)
            }
        }

        impl ::core::convert::From<$name> for $crate::__private::uuid::Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl $crate::__private::serde::Serialize for $name {
            fn serialize<S: $crate::__private::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                $crate::__private::serde::Serialize::serialize(&self.0, serializer)
            }
        }

        impl<'de> $crate::__private::serde::Deserialize<'de> for $name {
            fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                <$crate::__private::uuid::Uuid as $crate::__private::serde::Deserialize>
                    ::deserialize(deserializer).map(Self)
            }
        }

        impl $crate::__private::utoipa::PartialSchema for $name {
            fn schema() -> $crate::__private::utoipa::openapi::RefOr<
                $crate::__private::utoipa::openapi::schema::Schema,
            > {
                $crate::id::uuid_schema()
            }
        }

        impl $crate::__private::utoipa::ToSchema for $name {}

        impl $crate::codec::key::KeyCodec for $name {
            fn encode_key(&self, out: &mut ::std::vec::Vec<u8>) {
                $crate::codec::key::KeyCodec::encode_key(&self.0, out);
            }
            fn decode_key(
                input: &mut &[u8],
            ) -> ::core::result::Result<Self, $crate::codec::key::KeyError> {
                <$crate::__private::uuid::Uuid as $crate::codec::key::KeyCodec>::decode_key(input)
                    .map(Self)
            }
        }
    };
}

/// OpenAPI schema of every UUID identifier: `string`, format `uuid`.
#[doc(hidden)]
pub fn uuid_schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::{KnownFormat, ObjectBuilder, RefOr, Schema, SchemaFormat, Type};
    RefOr::T(Schema::Object(
        ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uuid)))
            .build(),
    ))
}

id_type! {
    /// Identifier of a tenant (IPAM-01).
    TenantId,
    /// Identifier of a VRF (IPAM-01).
    VrfId,
    /// Identifier of a site (IPAM-04).
    SiteId,
    /// Identifier of a VLAN (IPAM-03).
    VlanId,
    /// Identifier of a prefix (supernet or network, IPAM-02).
    PrefixId,
    /// Identifier of an address range inside a prefix.
    RangeId,
    /// Identifier of an IP address object.
    AddressId,
    /// Identifier of a host (the unit of intent, IPAM-12).
    HostId,
    /// Identifier of a host interface (MAC, DUID, client id).
    InterfaceId,
    /// Identifier of a custom field definition (IPAM-08).
    CustomFieldId,
    /// Identifier of a local user.
    UserId,
    /// Identifier of a login session.
    SessionId,
    /// Identifier of a personal API token (IAM-10).
    ApiTokenId,
    /// Identifier of a job (IPAM-17).
    JobId,
    /// Identifier of an observation (IPAM-12).
    ObservationId,
    /// Identifier of a proposal (IPAM-15).
    ProposalId,
    /// Identifier of an import session (IPAM-11).
    ImportId,
    /// Identifier of a configured connector instance (CONN-01).
    ConnectorId,
    /// Identifier of a vault secret (IAM-15, IAM-16).
    SecretId,
    /// Identifier of one API request, carried into write batches and audit records.
    RequestId,
}

/// Raft node identifier, assigned at enrolment.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(transparent)]
pub struct NodeId(pub u64);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Store revision: incremented by exactly one per applied write batch, store-wide. It is
/// also the SSE event id (ADR 0008, ADR 0011).
///
/// `Revision(0)` is the empty store; the first batch commits as `Revision(1)`.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(transparent)]
pub struct Revision(pub u64);

impl Revision {
    /// The revision of an empty store.
    pub const ZERO: Revision = Revision(0);

    /// The next revision.
    #[must_use]
    pub const fn next(self) -> Revision {
        Revision(self.0 + 1)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Position in the audit chain: gap-free, starting at 1 (IAM-18).
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(transparent)]
pub struct AuditSeq(pub u64);

impl AuditSeq {
    /// "No record yet": the chain position before the first record.
    pub const NONE: AuditSeq = AuditSeq(0);

    /// The next position.
    #[must_use]
    pub const fn next(self) -> AuditSeq {
        AuditSeq(self.0 + 1)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AuditSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

macro_rules! u64_key {
    ($($name:ident),+) => {$(
        impl KeyCodec for $name {
            fn encode_key(&self, out: &mut Vec<u8>) {
                self.0.encode_key(out);
            }
            fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
                u64::decode_key(input).map($name)
            }
        }
    )+};
}

u64_key!(NodeId, Revision, AuditSeq);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_key, encode_key, from_cbor, to_cbor};

    #[test]
    fn generated_ids_are_v7_and_increase() {
        let first = HostId::generate();
        let second = HostId::generate();
        assert_eq!(first.uuid().get_version_num(), 7);
        assert!(first < second);
        assert!(encode_key(&first) < encode_key(&second));
    }

    #[test]
    fn ids_round_trip_through_text_json_cbor_and_keys() {
        let id = PrefixId::generate();
        assert_eq!(id.to_string().parse::<PrefixId>(), Ok(id));
        let json = serde_json::to_string(&id).expect("json");
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<PrefixId>(&json).expect("json"), id);
        let cbor = to_cbor(&id).expect("cbor");
        assert_eq!(cbor.len(), 17, "a 16-byte byte string");
        assert_eq!(from_cbor::<PrefixId>(&cbor).expect("cbor"), id);
        assert_eq!(decode_key::<PrefixId>(&encode_key(&id)), Ok(id));
        assert!(format!("{id:?}").starts_with("PrefixId("));
    }

    #[test]
    fn invalid_id_text_is_rejected() {
        let error = "not-a-uuid".parse::<UserId>().expect_err("invalid");
        assert_eq!(error.kind, "UserId");
    }

    #[test]
    fn revisions_count_up() {
        assert_eq!(Revision::ZERO.next(), Revision(1));
        assert_eq!(AuditSeq::NONE.next().get(), 1);
        assert_eq!(
            serde_json::to_string(&Revision(4712)).expect("json"),
            "4712"
        );
    }
}
