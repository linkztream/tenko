//! Shared contracts of Tenko DDI (plan `docs/plans/phase-1-execution.md`, section 2):
//! identifiers, principals and authorization, the IPAM model, observations and proposals,
//! audit records and the hash chain, stable error codes, order-preserving keys and CBOR
//! values, namespaced names, secret references and the IPAM part of the migration IR.
//!
//! # Ownership
//!
//! This crate is the contract between the Phase 1 work packages and is owned by the lead
//! builder (WP1.0). Other packages never edit this crate; contract changes go through the
//! lead as a small pull request reviewed by every package that uses the changed item
//! (plan rule 2.8). Error codes are stable once merged (API-08).
//!
//! # Map
//!
//! | Module | Contents |
//! |---|---|
//! | [`id`] | `id_type!`, entity identifiers (UUIDv7), [`NodeId`], [`Revision`], [`AuditSeq`] |
//! | [`timestamp`] | [`Timestamp`] (UTC, RFC 3339) |
//! | [`object`] | [`ObjectKind`], [`ObjectRef`] |
//! | [`principal`] | [`Principal`], [`RequestCtx`], [`Authorizer`], [`Action`], [`Denied`] |
//! | [`names`] | namespaces, [`TableName`], [`CounterKey`], [`MessageKey`], [`IdempotencyKey`] |
//! | [`error`] | [`Coded`], [`CodedError`], [`FieldError`], [`InvalidValue`] |
//! | [`codec`] | order-preserving keys, CBOR values, canonical CBOR for hashing |
//! | [`table`] | [`TableDef`](table::TableDef): typed keys and values of one table |
//! | [`net`] | [`MacAddr`], [`Fqdn`](net::Fqdn), [`HostName`](net::HostName), [`Duid`](net::Duid) |
//! | [`ipam`] | the IPAM model |
//! | [`ir`] | migration IR and loss reports |
//! | [`observe`] | observations and proposals |
//! | [`audit`] | audit drafts, records, the hash chain and its verifier |
//! | [`secret`] | [`SecretRef`](secret::SecretRef) and the vault envelope marker |
//! | [`role`] | node roles |

/// Re-exports used by the exported macros (`id_type!`, `namespaced_name!`). Not part of
/// the contract.
#[doc(hidden)]
pub mod __private {
    pub use serde;
    pub use utoipa;
    pub use uuid;
}

pub mod audit;
pub mod codec;
pub mod error;
pub mod id;
pub mod ipam;
pub mod ir;
pub mod names;
pub mod net;
pub mod object;
pub mod observe;
pub mod principal;
pub mod role;
pub mod secret;
pub mod serde_util;
pub mod table;
pub mod timestamp;

pub use error::{Coded, CodedError, FieldError, InvalidValue};
pub use id::{
    AddressId, ApiTokenId, AuditSeq, ConnectorId, CustomFieldId, HostId, ImportId, InterfaceId,
    JobId, NodeId, ObservationId, PrefixId, ProposalId, RangeId, RequestId, Revision, SecretId,
    SessionId, SiteId, TenantId, UserId, VlanId, VrfId,
};
pub use names::{CounterKey, IdempotencyKey, MessageKey, TableName};
pub use net::MacAddr;
pub use object::{ObjectKind, ObjectRef};
pub use principal::{
    Action, AuthStrength, Authorizer, Denied, DenyReason, Principal, RequestCtx, ScopeFilter,
    SystemComponent,
};
pub use role::{ParseRoleError, Role, RoleSet};
pub use timestamp::Timestamp;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-core";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }
}
