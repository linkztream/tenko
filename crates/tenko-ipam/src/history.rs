//! Immutable change history of IPAM objects (IPAM-09).
//!
//! Every planned change writes one [`HistoryEntry`] into `ipam.history`, keyed by the
//! object, the request time, the request id and the position in the plan, in the same
//! batch as the change. Entries are never rewritten. The revision of an entry is the
//! revision of the batch that wrote it, filled in when the entry is read.

use serde::{Deserialize, Serialize};
use tenko_core::{
    ObjectRef, Principal, RequestId, Revision, Timestamp, audit::FieldChange, codec::encode_key,
};
use tenko_jobs::JobKind;
use tenko_store::{KeyRange, ReadView, ReadViewExt};
use utoipa::ToSchema;

use crate::{error::IpamResult, object::IpamObject, tables::HISTORY};

/// What happened to an object.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ChangeAction {
    /// Created.
    Create,
    /// Fields changed.
    Update,
    /// Soft-deleted.
    Delete,
    /// Restored after a soft delete.
    Restore,
    /// Locked against automation (hosts).
    Lock,
    /// Unlocked (hosts).
    Unlock,
    /// Removed for good (custom field definitions, which have no soft delete).
    Remove,
}

impl ChangeAction {
    /// The verb used in audit actions (`ipam.prefix.create`).
    pub const fn as_str(self) -> &'static str {
        match self {
            ChangeAction::Create => "create",
            ChangeAction::Update => "update",
            ChangeAction::Delete => "delete",
            ChangeAction::Restore => "restore",
            ChangeAction::Lock => "lock",
            ChangeAction::Unlock => "unlock",
            ChangeAction::Remove => "remove",
        }
    }

    /// The past participle for summaries (`created`).
    pub const fn past(self) -> &'static str {
        match self {
            ChangeAction::Create => "created",
            ChangeAction::Update => "updated",
            ChangeAction::Delete => "deleted",
            ChangeAction::Restore => "restored",
            ChangeAction::Lock => "locked",
            ChangeAction::Unlock => "unlocked",
            ChangeAction::Remove => "removed",
        }
    }
}

/// One change of one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HistoryEntry {
    /// The object.
    pub object: ObjectRef,
    /// What happened.
    pub action: ChangeAction,
    /// When (the request time).
    pub at: Timestamp,
    /// Who.
    pub by: Principal,
    /// The request.
    pub request: RequestId,
    /// The kind of job that carried the change.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub job_kind: Option<JobKind>,
    /// The object before the change (`None` on create).
    #[serde(default)]
    pub before: Option<IpamObject>,
    /// The object after the change.
    #[serde(default)]
    pub after: Option<IpamObject>,
    /// Changed fields, rendered as text.
    #[serde(default)]
    pub changes: Vec<FieldChange>,
    /// The revision of the batch that wrote the entry (filled when read).
    #[serde(default)]
    pub revision: Revision,
}

/// Reads the history of one object, oldest first, up to `limit` entries after the
/// position `after` (an encoded key from a previous page).
///
/// # Errors
///
/// Returns store or decoding errors.
pub fn read_history(
    view: &dyn ReadView,
    object: ObjectRef,
    after: Option<&[u8]>,
    limit: usize,
    newest_first: bool,
) -> IpamResult<Vec<(Vec<u8>, HistoryEntry)>> {
    let mut range = KeyRange::prefix(encode_key(&object));
    if let Some(after) = after {
        range = if newest_first {
            range.before(after.to_vec())
        } else {
            range.after(after.to_vec())
        };
    }
    let rows = view.scan(HISTORY.name(), range, limit, newest_first)?;
    rows.into_iter()
        .map(|(key, versioned)| {
            let mut entry = HISTORY.decode(&versioned.value)?;
            entry.revision = versioned.revision;
            Ok((key.to_vec(), entry))
        })
        .collect()
}

/// The newest history entry of an object, if any.
///
/// # Errors
///
/// Returns store or decoding errors.
pub fn last_entry(view: &dyn ReadView, object: ObjectRef) -> IpamResult<Option<HistoryEntry>> {
    let rows = view.scan_typed(&HISTORY, KeyRange::prefix(encode_key(&object)), 1, true)?;
    Ok(rows.into_iter().next().map(|(_, mut entry, revision)| {
        entry.revision = revision;
        entry
    }))
}
