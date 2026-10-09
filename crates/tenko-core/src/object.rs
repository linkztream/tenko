//! References to objects of any kind, used by audit records, events, jobs and
//! authorization.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    codec::key::{KeyCodec, KeyError, encode_str},
    error::InvalidValue,
    id::{
        AddressId, ApiTokenId, ConnectorId, CustomFieldId, HostId, ImportId, InterfaceId, JobId,
        NodeId, ObservationId, PrefixId, ProposalId, RangeId, SecretId, SessionId, SiteId,
        TenantId, UserId, VlanId, VrfId,
    },
};

macro_rules! object_kinds {
    ($($(#[$meta:meta])* $variant:ident => $name:literal),+ $(,)?) => {
        /// The kind of an object: one variant per entity.
        ///
        /// Serialized and key-encoded as its `snake_case` name, which is stable. Ordering
        /// follows the name, so it matches the key encoding.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
        #[serde(rename_all = "snake_case")]
        pub enum ObjectKind {
            $($(#[$meta])* $variant,)+
        }

        impl ObjectKind {
            /// Every kind, in declaration order.
            pub const ALL: &'static [ObjectKind] = &[$(ObjectKind::$variant,)+];

            /// The stable `snake_case` name.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(ObjectKind::$variant => $name,)+
                }
            }
        }

        impl FromStr for ObjectKind {
            type Err = InvalidValue;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($name => Ok(ObjectKind::$variant),)+
                    _ => Err(InvalidValue::new("object kind", s, "unknown object kind")),
                }
            }
        }
    };
}

object_kinds! {
    /// A tenant.
    Tenant => "tenant",
    /// A VRF.
    Vrf => "vrf",
    /// A site.
    Site => "site",
    /// A VLAN.
    Vlan => "vlan",
    /// A prefix.
    Prefix => "prefix",
    /// An address range.
    Range => "range",
    /// An IP address.
    Address => "address",
    /// A host.
    Host => "host",
    /// A host interface.
    Interface => "interface",
    /// A custom field definition.
    CustomField => "custom_field",
    /// A local user.
    User => "user",
    /// A login session.
    Session => "session",
    /// A personal API token.
    ApiToken => "api_token",
    /// A job.
    Job => "job",
    /// An observation.
    Observation => "observation",
    /// A proposal.
    Proposal => "proposal",
    /// An import session.
    Import => "import",
    /// A connector instance.
    Connector => "connector",
    /// A vault secret.
    Secret => "secret",
    /// A cluster node; the id is [`ObjectRef::node`].
    Node => "node",
    /// The security settings singleton; the id is nil.
    Settings => "settings",
    /// The system as a whole (setup, break-glass); the id is nil.
    System => "system",
}

impl PartialOrd for ObjectKind {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectKind {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl KeyCodec for ObjectKind {
    fn encode_key(&self, out: &mut Vec<u8>) {
        encode_str(self.as_str(), out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        String::decode_key(input)?
            .parse()
            .map_err(|_| KeyError::Invalid("unknown object kind"))
    }
}

/// A typed reference to one object.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
pub struct ObjectRef {
    /// The kind of object.
    pub kind: ObjectKind,
    /// The object's identifier (nil for singletons).
    #[schema(value_type = String, format = Uuid)]
    pub id: Uuid,
}

impl ObjectRef {
    /// Creates a reference.
    pub const fn new(kind: ObjectKind, id: Uuid) -> Self {
        Self { kind, id }
    }

    /// A reference to a singleton such as [`ObjectKind::Settings`] (nil identifier).
    pub const fn singleton(kind: ObjectKind) -> Self {
        Self {
            kind,
            id: Uuid::nil(),
        }
    }

    /// A reference to a cluster node: the node id in the low 64 bits.
    pub const fn node(id: NodeId) -> Self {
        Self {
            kind: ObjectKind::Node,
            id: Uuid::from_u64_pair(0, id.0),
        }
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.id)
    }
}

impl KeyCodec for ObjectRef {
    fn encode_key(&self, out: &mut Vec<u8>) {
        self.kind.encode_key(out);
        self.id.encode_key(out);
    }
    fn decode_key(input: &mut &[u8]) -> Result<Self, KeyError> {
        Ok(Self {
            kind: ObjectKind::decode_key(input)?,
            id: Uuid::decode_key(input)?,
        })
    }
}

macro_rules! object_ref_from {
    ($($id:ident => $kind:ident),+ $(,)?) => {$(
        impl From<$id> for ObjectRef {
            fn from(id: $id) -> Self {
                ObjectRef::new(ObjectKind::$kind, id.0)
            }
        }
    )+};
}

object_ref_from! {
    TenantId => Tenant,
    VrfId => Vrf,
    SiteId => Site,
    VlanId => Vlan,
    PrefixId => Prefix,
    RangeId => Range,
    AddressId => Address,
    HostId => Host,
    InterfaceId => Interface,
    CustomFieldId => CustomField,
    UserId => User,
    SessionId => Session,
    ApiTokenId => ApiToken,
    JobId => Job,
    ObservationId => Observation,
    ProposalId => Proposal,
    ImportId => Import,
    ConnectorId => Connector,
    SecretId => Secret,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_key, encode_key};

    #[test]
    fn kinds_round_trip_by_name() {
        for &kind in ObjectKind::ALL {
            assert_eq!(kind.as_str().parse::<ObjectKind>(), Ok(kind));
            let json = serde_json::to_string(&kind).expect("json");
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
            assert_eq!(decode_key::<ObjectKind>(&encode_key(&kind)), Ok(kind));
        }
        assert!("zone".parse::<ObjectKind>().is_err());
    }

    #[test]
    fn refs_from_ids_carry_the_kind() {
        let host = HostId::generate();
        let reference = ObjectRef::from(host);
        assert_eq!(reference.kind, ObjectKind::Host);
        assert_eq!(reference.id, host.0);
        assert_eq!(reference.to_string(), format!("host/{host}"));
        assert_eq!(
            decode_key::<ObjectRef>(&encode_key(&reference)),
            Ok(reference)
        );
        let json = serde_json::to_value(reference).expect("json");
        assert_eq!(json["kind"], "host");
    }

    #[test]
    fn node_and_singleton_refs() {
        assert_eq!(ObjectRef::node(NodeId(3)).id.as_u64_pair(), (0, 3));
        assert!(ObjectRef::singleton(ObjectKind::Settings).id.is_nil());
    }
}
