//! Changes queued on a controller cut off from its cluster, and what becomes of them after
//! the partition heals (OPS-26, ADR 0013, `docs/partitions.md`).
//!
//! # The queue
//!
//! A controller in the isolated mode refuses writes. A person can keep an IPAM intent
//! write instead: the API translates the request into planner commands, plans them against
//! the local copy and stores a [`QueueItem`] in the controller's [`LocalQueue`], one file
//! per item under `<data_dir>/queue/`. The queue is local (a cut-off controller cannot
//! replicate anything), durable across restarts, bounded ([`local::MAX_ITEMS`],
//! [`local::MAX_ITEM_BYTES`]) and expires items after [`EXPIRY`].
//!
//! # The drain
//!
//! When the controller accepts writes again, [`drain::Drainer`] settles every item once:
//! it plans the commands again against the current state (after a linearizable read, so
//! the controller has caught up), checks the plan with the author's current rights, and
//!
//! - applies an item whose plan is unchanged ([`fingerprint::Fingerprint`]) as an inline
//!   job of `System { component: Ipam, on_behalf_of: author }`, with the audit context
//!   `queued_at`, `queued_on` and `original_session` and an idempotency key derived from
//!   the item, so that a drain interrupted after the commit replays instead of applying
//!   twice;
//! - turns every other item into a [`record::QueuedChange`] in `ipam.queued_changes` with
//!   its conflict, for the author to re-apply or discard.
//!
//! Applied items are recorded there too ([`record::ChangeState::Applied`]), so every
//! applied item is listed to its author and nothing applies silently.

pub mod drain;
pub mod fingerprint;
pub mod local;
pub mod record;

#[cfg(test)]
mod tests;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tenko_core::{NodeId, ObjectKind, Principal, Revision, SessionId, Timestamp, UserId};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{IpamCommand, PlanOptions, PlanView};

pub use drain::{DrainReport, Drainer};
pub use fingerprint::Fingerprint;
pub use local::LocalQueue;
pub use record::{ChangeState, Conflict, QUEUED_CHANGES, QueuedChange};

/// How long an item waits in the queue before it expires: 7 days (plan, WP3.9).
pub const EXPIRY: Duration = Duration::from_secs(7 * 24 * 3600);

/// Error codes of the queue.
pub mod codes {
    /// The queue is not configured on this server (503).
    pub const UNAVAILABLE: &str = "queue.unavailable";
    /// The controller accepts writes: make the change directly (409).
    pub const NOT_ISOLATED: &str = "queue.not_isolated";
    /// The request is not one the queue takes (422).
    pub const NOT_QUEUEABLE: &str = "queue.not_queueable";
    /// The queue of this controller is full (507).
    pub const FULL: &str = "queue.full";
    /// The request is too large for the queue (413).
    pub const TOO_LARGE: &str = "queue.too_large";
    /// No such item or record of the caller (404).
    pub const NOT_FOUND: &str = "queue.not_found";
    /// Only people (sessions and personal or scoped tokens) queue changes (403).
    pub const NOT_A_PERSON: &str = "queue.not_a_person";
    /// The plan after the heal differs from the queued plan (the conflict of a record).
    pub const PLAN_CHANGED: &str = "queue.plan_changed";
    /// The item expired before the controller could apply it (the conflict of a record).
    pub const EXPIRED: &str = "queue.expired";
    /// The queue directory could not be read or written (500).
    pub const IO: &str = "queue.io";
    /// The record changed meanwhile; read it again (409).
    pub const CHANGED: &str = "queue.changed";
}

/// The request as the client would have sent it, relative to the API base.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct QueuedRequest {
    /// `POST`, `PATCH` or `DELETE`.
    pub method: String,
    /// The path, for example `/addresses/0192…`; `/api/v1` in front is accepted.
    pub path: String,
    /// The query string without `?`, for example `acknowledge=ipam.address.in_supernet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// The JSON body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub body: Option<serde_json::Value>,
    /// The `If-Match` value (`"12"` or `12`), for changes, deletes and restores.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "if_match_text"
    )]
    pub if_match: Option<String>,
}

/// `if_match` as a string or a number.
fn if_match_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Text {
        Text(String),
        Number(u64),
    }
    Ok(
        Option::<Text>::deserialize(deserializer)?.map(|text| match text {
            Text::Text(text) => text,
            Text::Number(number) => number.to_string(),
        }),
    )
}

/// What a queued change does, in words a list can show.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAction {
    /// Creates an object.
    Create,
    /// Changes an object.
    Update,
    /// Deletes an object.
    Delete,
    /// Restores a deleted object.
    Restore,
    /// Several changes of one collection at once.
    Bulk,
}

/// The one-line summary of a queued change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ChangeSummary {
    /// What the change does.
    pub action: SummaryAction,
    /// The kind of object.
    pub kind: ObjectKind,
    /// A human key of the object (its name, CIDR or address), when the plan shows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// The state of an item in the local queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// Waiting for the controller to accept writes.
    Queued,
    /// The controller is settling it (or was, when it stopped).
    Applying,
    /// Older than [`EXPIRY`]: it will not apply, and becomes an `expired` record after the
    /// heal.
    Expired,
}

/// One queued change: a file in the local queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueItem {
    /// Identifier (UUID v7, so the order of identifiers is the order of queueing).
    pub id: Uuid,
    /// When it was queued.
    pub queued_at: Timestamp,
    /// The controller whose queue holds it.
    pub queued_on: NodeId,
    /// When it expires.
    pub expires_at: Timestamp,
    /// Who queued it, as authenticated then.
    pub principal: Principal,
    /// The request.
    pub request: QueuedRequest,
    /// The planner commands of the request; creates carry the identifiers chosen at
    /// queue time.
    pub commands: Vec<IpamCommand>,
    /// The acknowledged warnings of the request.
    #[serde(default)]
    pub options: PlanOptions,
    /// The revision of the local copy the plan was made from.
    pub base: Revision,
    /// The plan against the local copy.
    pub plan: PlanView,
    /// What the plan does, for the comparison after the heal.
    pub fingerprint: Fingerprint,
    /// The one-line summary.
    pub summary: ChangeSummary,
    /// Set while the drain settles the item.
    #[serde(default)]
    pub applying: bool,
}

impl QueueItem {
    /// The state at `now`.
    pub fn state(&self, now: Timestamp) -> ItemState {
        if self.applying {
            ItemState::Applying
        } else if now >= self.expires_at {
            ItemState::Expired
        } else {
            ItemState::Queued
        }
    }

    /// The user behind the item.
    pub fn author(&self) -> Option<UserId> {
        self.principal.user()
    }

    /// The session the item was queued in, for the audit context.
    pub fn original_session(&self) -> Option<SessionId> {
        match &self.principal {
            Principal::User { session, .. } => Some(*session),
            _ => None,
        }
    }
}

/// The summary of a plan for a request: the action, and the kind and key of the primary
/// object of the first command.
pub fn summarize(action: SummaryAction, plan: &PlanView) -> Option<ChangeSummary> {
    let primary = plan.results.first()?;
    let key = plan
        .changes
        .iter()
        .find(|change| change.object == *primary)
        .and_then(|change| change.after.as_ref().or(change.before.as_ref()))
        .map(crate::object::IpamObject::label);
    Some(ChangeSummary {
        action,
        kind: primary.kind,
        key,
    })
}
