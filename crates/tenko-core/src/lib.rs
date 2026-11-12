//! Shared contracts of Tenko DDI (plan `docs/plans/phase-1-execution.md`, section 2):
//! identifiers, principals and authorization, the IPAM model, observations and proposals,
//! audit records and the hash chain, stable error codes, order-preserving keys and CBOR
//! values, namespaced names, secret references and the IPAM part of the migration IR.
//!
//! # A home of shared code
//!
//! This crate is a home of shared code (`CONTRIBUTING.md`, "Where shared code lives"):
//!
//! - **In:** contracts between crates: identifiers, principals and authorization, the stored
//!   models, the error trait and code lists, the codecs (CBOR, keys, byte text forms), the
//!   metrics registry, secret references, roles, test support.
//! - **Never:** a helper that no type of this crate needs (it goes to the lowest crate that
//!   every caller already depends on), input or output outside test support, policy in a free
//!   helper (a setting's bound or default lives on the setting's own type, which may be a
//!   stored model here).
//! - **Who depends on it:** any crate. Every crate rebuilds when it changes, so an addition
//!   inside this charter needs no permission but is announced in the first line of its pull
//!   request and merged ahead of other open changes; a change to what an existing item does
//!   goes through the maintainers. Error codes are stable once merged (API-08).
//!
//! # Map
//!
//! | Module | Contents |
//! |---|---|
//! | [`id`] | `id_type!`, entity identifiers (UUIDv7), [`NodeId`], [`Revision`], [`AuditSeq`] |
//! | [`timestamp`] | [`Timestamp`] (UTC, RFC 3339) |
//! | [`object`] | [`ObjectKind`], [`ObjectRef`] |
//! | [`principal`] | [`Principal`], [`RequestCtx`], [`Authorizer`], [`Action`], [`Denied`], scopes: [`ScopeFilter`], [`ScopeRule`], [`Anchors`], [`AnchorMode`] |
//! | [`cluster`] | leader-only work: [`cluster::LeaderService`], the epoch counter [`cluster::LEADER_EPOCH`] |
//! | [`i18n`] | language packs in the store: [`i18n::PACKS`], the built-in languages |
//! | [`auth`] | [`Credentials`], [`Authenticated`], [`Authenticator`], [`AuthFailure`] |
//! | [`names`] | namespaces, [`TableName`], [`CounterKey`], [`MessageKey`], [`IdempotencyKey`] |
//! | [`error`] | [`Coded`], [`CodedError`], [`FieldError`], [`InvalidValue`] |
//! | [`codec`] | order-preserving keys, CBOR values, canonical CBOR for hashing |
//! | [`table`] | [`TableDef`](table::TableDef): typed keys and values of one table |
//! | [`net`] | [`MacAddr`], [`Fqdn`](net::Fqdn), [`HostName`](net::HostName), [`Duid`](net::Duid) |
//! | [`ipam`] | the IPAM model |
//! | [`dns`] | the DNS model: zones, RRsets, record data, views, forwarders, keys, lists, tables, scopes, codes |
//! | [`dhcp`] | the DHCP model: scopes, pools, options, classes, policies, filters, leases, tables, scopes, codes |
//! | [`ir`] | migration IR and loss reports; the mirror envelope [`ir::MirrorSnapshot`] (WP14.0) |
//! | [`migrate`] | mirrored sources, their snapshots, takeovers and loss acknowledgments (WP14.0) |
//! | [`metrics`] | counters, histograms and gauges on striped atomics, the registry, the `OpenMetrics` encoder |
//! | [`observe`] | observations and proposals |
//! | [`audit`] | audit drafts, records, the hash chain and its verifier |
//! | [`secret`] | [`SecretRef`](secret::SecretRef) and the vault envelope marker |
//! | [`role`] | node roles |
//! | `testing` | test support (feature `testing`): the shared wait, free ports, temporary directories |

/// Re-exports used by the exported macros (`id_type!`, `namespaced_name!`). Not part of
/// the contract.
#[doc(hidden)]
pub mod __private {
    pub use serde;
    pub use utoipa;
    pub use uuid;
}

pub mod audit;
pub mod auth;
pub mod cluster;
pub mod codec;
// WP7.0: the DHCP model (Phase 3).
pub mod dhcp;
pub mod dns;
pub mod egress;
pub mod error;
pub mod i18n;
pub mod id;
pub mod ipam;
pub mod ir;
pub mod metrics;
// WP14.0: mirrored sources and takeovers (Phase 4).
pub mod migrate;
pub mod names;
pub mod net;
pub mod object;
pub mod observe;
pub mod principal;
pub mod role;
pub mod secret;
pub mod serde_util;
pub mod table;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod timestamp;

pub use auth::{AuthFailure, AuthFlags, Authenticated, Authenticator, Credentials};
pub use error::{Coded, CodedError, FieldError, InvalidValue};
pub use id::{
    AddressId, ApiTokenId, AuditSeq, ConnectorId, CustomFieldId, HostId, ImportId, InterfaceId,
    JobId, MirrorId, NodeId, ObservationId, PrefixId, ProposalId, RangeId, RequestId, Revision,
    SecretId, SessionId, SiteId, TakeoverId, TenantId, UserId, VlanId, VrfId,
};
pub use names::{CounterKey, IdempotencyKey, MessageKey, TableName};
pub use net::MacAddr;
pub use object::{ObjectKind, ObjectRef};
pub use principal::{
    Action, AnchorMode, Anchors, AuthStrength, Authorizer, Denied, DenyReason, Principal,
    RequestCtx, ScopeFilter, ScopeRule, SystemComponent,
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
