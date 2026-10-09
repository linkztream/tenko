//! What the import endpoints answer: the upload with its analysis and mapping
//! ([`ImportView`]), the preview ([`ImportPreview`]) and the apply request.
//!
//! The UI (WP1.10) builds the import wizard from these: sheets and columns with shapes
//! and samples for the mapping step, then the preview with counts per entity and action,
//! the first rows, the loss report by sheet, row and column, the proposals to accept or
//! reject, the plain-words statement about credentials, and whether apply is possible.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{ImportId, JobId, Timestamp, ir::SourceLocation};
use utoipa::ToSchema;

use super::{
    codes::Severity,
    mapping::{Mapping, SheetAnalysis},
    read::{SourceFormat, TextInfo},
    reconcile::ItemAction,
    translate::{ItemKey, Proposal, RowStatus, SheetOutcome},
    vocab::Target,
};
use crate::plan::{PlanSummary, PlanWarning};

/// Where an import stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImportState {
    /// Uploaded; the suggested mapping applies.
    Uploaded,
    /// The user set a mapping.
    Mapped,
    /// An apply job runs.
    Applying,
    /// The last apply job succeeded.
    Applied,
    /// The last apply job failed and was rolled back (see the job).
    Failed,
}

/// An uploaded file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FileView {
    /// The name as uploaded.
    pub name: String,
    /// The detected format.
    pub format: SourceFormat,
    /// Size in bytes.
    pub size: u64,
    /// How a CSV file was decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<TextInfo>,
}

/// A target the mapping step offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TargetInfo {
    /// The target.
    pub target: Target,
    /// English label (the UI translates by `target`).
    pub label: String,
    /// Whether values become operator secrets in the vault instead of IPAM fields.
    pub credential: bool,
}

/// An upload with its analysis and mapping (`GET /imports/{id}`, the answer of
/// `POST /imports` and `PUT /imports/{id}/mapping`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ImportView {
    /// The import.
    #[schema(value_type = String)]
    pub id: ImportId,
    /// Where it stands.
    pub state: ImportState,
    /// Upload time.
    #[schema(value_type = String)]
    pub created: Timestamp,
    /// When the staged upload is discarded.
    #[schema(value_type = String)]
    pub expires: Timestamp,
    /// The uploaded files.
    pub files: Vec<FileView>,
    /// Every sheet with its columns, shapes, samples and suggestion.
    pub sheets: Vec<SheetAnalysis>,
    /// The mapping in force: the user's, else the suggested one.
    pub mapping: Mapping,
    /// Whether `mapping` is the user's (`true`) or the suggestion.
    pub mapped: bool,
    /// The targets the mapping step offers (custom fields included).
    pub targets: Vec<TargetInfo>,
    /// The latest apply job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub job_id: Option<JobId>,
}

/// How many items of a kind get one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ActionCount {
    /// The item kind: `tenant`, `vrf`, `site`, `vlan`, `prefix`, `host`, `interface`,
    /// `address` or `credential`.
    pub kind: String,
    /// The action.
    pub action: ItemAction,
    /// How many.
    pub count: usize,
}

/// Rows of the source by outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RowCounts {
    /// Rows with data.
    pub total: usize,
    /// Address-only rows of pre-filled lists (free addresses).
    pub free: usize,
    /// Rows that produced something.
    pub imported: usize,
    /// Rows left out.
    pub skipped: usize,
}

/// Loss report entries by severity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LossCounts {
    /// Information.
    pub info: usize,
    /// Warnings.
    pub warning: usize,
    /// Errors (values or rows not imported).
    pub error: usize,
}

/// The counts of a preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreviewSummary {
    /// Items per kind and action, ordered by kind and action.
    pub counts: Vec<ActionCount>,
    /// English lines such as `21 hosts created`.
    pub lines: Vec<String>,
    /// Source rows by outcome.
    pub rows: RowCounts,
    /// Loss report entries by severity.
    pub loss: LossCounts,
    /// The IPAM plan's own summary (objects per kind and change, physical writes); absent
    /// when the plan failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanSummary>,
    /// Chunks the apply job will write.
    pub chunks: usize,
}

/// One item of a preview row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RowItem {
    /// The item.
    pub key: ItemKey,
    /// What happens to it.
    pub action: ItemAction,
}

/// One source row of the preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreviewRow {
    /// Sheet and row.
    pub location: SourceLocation,
    /// What became of the row.
    pub status: RowStatus,
    /// What it creates, updates or leaves unchanged.
    pub items: Vec<RowItem>,
}

/// One loss report entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LossItem {
    /// Row number (1-based), when the entry is about a row or cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<u32>,
    /// Column letter, when the entry is about a column or cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    /// Stable code (`import.address.unparsable`).
    pub code: String,
    /// How serious it is.
    pub severity: Severity,
    /// English explanation with the offending value.
    pub detail: String,
}

/// The loss report entries of one sheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SheetLoss {
    /// The sheet; `None` for entries about the whole import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sheet: Option<String>,
    /// Entries in source order.
    pub entries: Vec<LossItem>,
}

/// What happens to the credential columns, in plain words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CredentialNotice {
    /// Hosts with a login or password in the source.
    pub hosts: usize,
    /// Secrets that would be created.
    pub new: usize,
    /// Secrets that would be replaced because the value changed.
    pub changed: usize,
    /// Secrets that are already stored with the same value.
    pub unchanged: usize,
    /// The statement shown to the user (English; the UI translates by the counts).
    pub statement: String,
    /// Whether this account may store them now.
    pub allowed: bool,
    /// Why not, when not allowed, as a code the UI translates: `forbidden`,
    /// `step_up_required`, `unauthenticated` or `vault_unavailable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The same in English, for logs and clients without translations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A problem that stops the plan, as in problem details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlanProblem {
    /// Stable code (`ipam.prefix.overlap`).
    pub code: String,
    /// HTTP status the code maps to.
    pub status: u16,
    /// English explanation.
    pub detail: String,
    /// Named parameters for the translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

/// The preview of an import (`GET /imports/{id}/preview`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ImportPreview {
    /// The import.
    #[schema(value_type = String)]
    pub id: ImportId,
    /// The store revision the preview was computed from.
    pub base_revision: u64,
    /// Counts.
    pub summary: PreviewSummary,
    /// Per sheet: what it was read as and its row counts.
    pub sheets: Vec<SheetOutcome>,
    /// The first rows (see `total_rows`).
    pub rows: Vec<PreviewRow>,
    /// Rows with data in the whole import.
    pub total_rows: usize,
    /// The loss report by sheet, row and column.
    pub loss: Vec<SheetLoss>,
    /// Proposed prefixes for addresses outside every known network.
    pub proposals: Vec<Proposal>,
    /// The credential statement.
    pub credentials: CredentialNotice,
    /// Warnings of the IPAM plan; those with `requires_ack` must be acknowledged.
    pub warnings: Vec<PlanWarning>,
    /// The error that stops the plan, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_error: Option<PlanProblem>,
    /// Whether apply would be accepted now.
    pub can_apply: bool,
    /// Codes of what stops apply (`import.credentials.vault_required`,
    /// `ipam.plan.unacknowledged`, `import.conflict.kept`, a plan error code).
    pub blockers: Vec<String>,
}

/// The body of `POST /imports/{id}/apply`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApplyRequest {
    /// Plan warning codes acknowledged in addition to the mapping options.
    #[serde(default)]
    pub acknowledge: Vec<String>,
}

/// The answer of `POST /imports/{id}/apply`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApplyAccepted {
    /// The job that applies the import; follow it at `/jobs/{id}`.
    #[schema(value_type = String)]
    pub job_id: JobId,
}
