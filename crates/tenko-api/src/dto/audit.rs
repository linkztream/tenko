//! Audit endpoints (IAM-18): the query of `GET /audit` and the report of
//! `GET /audit/verify`. Records themselves are `tenko_core::audit::AuditRecord`.

use serde::{Deserialize, Serialize};
use tenko_core::{AuditSeq, Revision, Timestamp, audit::ChainHead};
use utoipa::{IntoParams, ToSchema};

use super::SortOrder;

/// Query of `GET /audit`: pagination plus filters. Every filter is optional; filters
/// combine with AND.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Page size, 1 to 1,000 (default 100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Opaque cursor from the previous page's `next_cursor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Read at least this store revision (read-your-writes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_least: Option<u64>,
    /// Principal subject, for example `user:<uuid>`, `token:<uuid>` or `system:api`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Audit action, exact (`ipam.prefix.create`) or a namespace prefix ending with a dot
    /// (`ipam.` or `ipam.prefix.`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Object reference `kind:<uuid>`, or a bare kind such as `prefix`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Outcome: `success`, `denied` or `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Records at or after this time (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Timestamp>,
    /// Records before this time (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Timestamp>,
    /// `desc` (newest first, the default) or `asc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<SortOrder>,
}

/// Result of `GET /audit/verify`: the hash chain walked from the first record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditVerifyReport {
    /// Whether every record links to its predecessor and matches its hash.
    pub intact: bool,
    /// Number of records verified before the first break, or all of them.
    pub checked: u64,
    /// The last record that verified (sequence number and hash); sequence 0 when none did.
    pub head: ChainHead,
    /// The audit head the store reports at `revision`.
    pub store_head: AuditSeq,
    /// The first break of the chain, if any.
    pub first_break: Option<AuditBreak>,
    /// Store revision the chain was read at.
    pub revision: Revision,
}

/// The first break found in the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditBreak {
    /// Sequence number of the record where the chain breaks.
    pub seq: AuditSeq,
    /// Stable code: `sys.audit.gap`, `sys.audit.broken_link`, `sys.audit.bad_hash` or a
    /// codec error.
    pub code: String,
    /// English explanation.
    pub detail: String,
}
