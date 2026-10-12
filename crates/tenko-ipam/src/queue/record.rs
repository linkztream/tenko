//! What became of a queued change after the heal: a record in `ipam.queued_changes` per
//! settled item, listed to its author (`GET /queue/conflicts`).
//!
//! A record is `applied` (the unchanged plan was applied on the author's behalf; the record
//! committed in the same batch as the change, so its revision is the change's), `conflict`
//! (the plan changed, the author's rights no longer allow it, or planning failed) or
//! `expired` (it waited longer than [`super::EXPIRY`]). The author re-applies a conflict or
//! an expired change through the API, or discards the record; an applied record is
//! discarded once seen. Records replicate like every IPAM table, so the author sees them
//! on any controller.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, CodedError, NodeId, Principal, Revision, SessionId, Timestamp, UserId, table::TableDef,
};
use tenko_store::{KeyRange, ReadView, ReadViewExt as _, StoreError};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ChangeSummary, QueueItem, QueuedRequest};
use crate::{IpamCommand, PlanOptions, PlanView};

/// The records of settled queued changes, by item identifier.
pub static QUEUED_CHANGES: TableDef<Uuid, QueuedChange> = TableDef::new("ipam.queued_changes");

/// What became of a queued change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeState {
    /// Applied unchanged on the author's behalf.
    Applied,
    /// Not applied: see the conflict.
    Conflict,
    /// Not applied: it waited too long.
    Expired,
}

/// Why a queued change was not applied, as problem details carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Conflict {
    /// Stable code, for example `queue.plan_changed`, `ipam.address.duplicate` or
    /// `auth.forbidden`.
    pub code: String,
    /// The HTTP status the code has in an answer.
    pub status: u16,
    /// English title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// English detail.
    pub detail: String,
    /// Named parameters for the translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
}

impl Conflict {
    /// The conflict of an error.
    pub fn of(error: &dyn Coded) -> Self {
        Self::from_coded(&error.to_coded_error())
    }

    /// The conflict of a captured error.
    pub fn from_coded(error: &CodedError) -> Self {
        Self {
            code: error.code.to_string(),
            status: error.status,
            title: Some(error.title.to_string()).filter(|title| !title.is_empty()),
            detail: error.detail.clone(),
            params: error.params.clone(),
        }
    }
}

/// A settled queued change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct QueuedChange {
    /// The identifier of the queued item.
    pub id: Uuid,
    /// The user who queued it.
    pub author: UserId,
    /// The principal it was queued with.
    pub principal: Principal,
    /// The session it was queued in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_session: Option<SessionId>,
    /// When it was queued.
    pub queued_at: Timestamp,
    /// The controller that queued it.
    pub queued_on: NodeId,
    /// When the controller settled it.
    pub settled_at: Timestamp,
    /// What became of it.
    pub state: ChangeState,
    /// The request.
    pub request: QueuedRequest,
    /// The one-line summary.
    pub summary: ChangeSummary,
    /// The planner commands, for a re-apply.
    #[schema(value_type = Vec<Object>)]
    pub commands: Vec<IpamCommand>,
    /// The acknowledged warnings of the request.
    #[serde(default)]
    pub options: PlanOptions,
    /// The plan made when the change was queued.
    pub queued_plan: PlanView,
    /// The plan after the heal, when planning succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_plan: Option<PlanView>,
    /// Why it was not applied; absent for `applied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<Conflict>,
}

impl QueuedChange {
    /// The record of `item`, settled at `now`.
    pub fn of(
        item: &QueueItem,
        author: UserId,
        now: Timestamp,
        state: ChangeState,
        current_plan: Option<PlanView>,
        conflict: Option<Conflict>,
    ) -> Self {
        Self {
            id: item.id,
            author,
            principal: item.principal.clone(),
            original_session: item.original_session(),
            queued_at: item.queued_at,
            queued_on: item.queued_on,
            settled_at: now,
            state,
            request: item.request.clone(),
            summary: item.summary.clone(),
            commands: item.commands.clone(),
            options: item.options.clone(),
            queued_plan: item.plan.clone(),
            current_plan,
            conflict,
        }
    }
}

/// The records of `author`, oldest first, each with the revision that wrote it.
///
/// # Errors
///
/// A store error.
pub fn of_author(
    view: &dyn ReadView,
    author: UserId,
) -> Result<Vec<(QueuedChange, Revision)>, StoreError> {
    let mut records: Vec<(QueuedChange, Revision)> = view
        .scan_typed(&QUEUED_CHANGES, KeyRange::all(), usize::MAX, false)?
        .into_iter()
        .filter(|(_, record, _)| record.author == author)
        .map(|(_, record, revision)| (record, revision))
        .collect();
    records.sort_by_key(|(record, _)| record.id);
    Ok(records)
}

/// One record with its revision.
///
/// # Errors
///
/// A store error.
pub fn get(view: &dyn ReadView, id: Uuid) -> Result<Option<(QueuedChange, Revision)>, StoreError> {
    view.get_typed(&QUEUED_CHANGES, &id)
}
