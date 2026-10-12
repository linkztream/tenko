//! The administration of the controller cluster behind `/cluster/*` and `tenko cluster`
//! (OPS-03): the views of the members and the membership changes.
//!
//! [`ClusterAdmin`] is what the API routes call; the peer layer of `tenko serve`
//! implements it and the server adds it to the request extensions as
//! `Arc<dyn ClusterAdmin>`. Membership changes run on the leader: a controller that does not
//! lead hands them to the leader over the cluster port, so any controller serves them.
//!
//! | Code | Status | When |
//! |---|---|---|
//! | `cluster.member.not_found` | 404 | the node is not a member |
//! | `cluster.member.even_voters` | 409 | a promotion would leave an even number of voters; pass `force` |
//! | `cluster.member.not_caught_up` | 409 | the learner is too far behind or out of contact; pass `force` |
//! | `cluster.member.last_voter` | 409 | the change would remove the last voter |
//! | `cluster.member.no_successor` | 409 | a step-down without another caught-up voter |
//! | `cluster.member.changing` | 409 | another membership change is in progress |
//! | `cluster.member.not_leader` | 503 | no leader is known to take the change; retry |
//! | `cluster.member.starting` | 503 | the controller is still starting |
//! | `cluster.single` | 409 | the controller is not part of a cluster |

use serde::{Deserialize, Serialize};
use tenko_core::{JobId, NodeId, RequestCtx, Revision, Timestamp};
use tenko_store::QuorumState;
use utoipa::ToSchema;

use crate::error::ClusterError;

/// The cluster as one controller sees it (`GET /cluster/members`). The API serves it as
/// `tenko_api::routes::cluster::ClusterView`, with the quorum state of the API's own
/// schema, so this type has none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterView {
    /// The controller that answered.
    pub node: NodeId,
    /// The leader it knows, if any.
    pub leader: Option<NodeId>,
    /// The Raft term it knows.
    pub term: u64,
    /// Whether it is in contact with a quorum.
    pub quorum: QuorumView,
    /// Whether a membership change is in progress (joint consensus).
    pub changing: bool,
    /// The members by node id. Replication figures (`matched`, `lag_entries`,
    /// `last_contact_ms`) come from the leader; a follower forwards the question.
    pub members: Vec<MemberView>,
    /// The inline job `cluster.edit` of a promotion or removal; absent on a plain view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<JobId>,
}

/// The kind of quorum state (the API's schema is `tenko_api::dto::system::QuorumKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumKind {
    /// The only voter.
    Single,
    /// In contact with a quorum.
    Healthy,
    /// No leader known; an election runs.
    Electing,
    /// Out of contact with a quorum: reads serve the local copy, writes are refused.
    Isolated,
}

/// The quorum state of a controller (OPS-26; the API's schema is
/// `tenko_api::dto::system::QuorumView`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumView {
    /// The state.
    pub state: QuorumKind,
    /// When an election started (`electing`) or the controller became isolated
    /// (`isolated`).
    pub since: Option<Timestamp>,
    /// The last contact with a quorum while isolated.
    pub last_contact: Option<Timestamp>,
    /// The revision the controller applied last, while isolated: the age of its copy.
    pub applied: Option<Revision>,
}

impl Default for QuorumView {
    /// A single controller.
    fn default() -> Self {
        Self::from(QuorumState::Single)
    }
}

impl From<QuorumState> for QuorumView {
    fn from(state: QuorumState) -> Self {
        match state {
            QuorumState::Single => Self {
                state: QuorumKind::Single,
                since: None,
                last_contact: None,
                applied: None,
            },
            QuorumState::Healthy => Self {
                state: QuorumKind::Healthy,
                since: None,
                last_contact: None,
                applied: None,
            },
            QuorumState::Electing { since } => Self {
                state: QuorumKind::Electing,
                since: Some(since),
                last_contact: None,
                applied: None,
            },
            QuorumState::Isolated {
                since,
                last_contact,
                applied,
            } => Self {
                state: QuorumKind::Isolated,
                since: Some(since),
                last_contact,
                applied: Some(applied),
            },
        }
    }
}

/// Whether a member votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// Votes in elections and counts for the quorum.
    Voter,
    /// Replicates without voting (catching up, or kept for reads).
    Learner,
}

/// One member of the controller cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MemberView {
    /// The node id (also its Raft id).
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// Its name in the node registry.
    pub name: Option<String>,
    /// Its cluster port as `host:port`.
    pub address: Option<String>,
    /// Voter or learner.
    pub role: MemberRole,
    /// Whether it leads.
    pub leader: bool,
    /// The last log index known to match the leader's log.
    pub matched: Option<u64>,
    /// Log entries it is behind the leader.
    pub lag_entries: Option<u64>,
    /// Milliseconds since the leader last heard from it.
    pub last_contact_ms: Option<u64>,
    /// The software version it reported when it joined or last started.
    pub version: Option<String>,
    /// The data format its binary knows.
    pub data_format: Option<u32>,
    /// When it joined.
    pub joined_at: Option<Timestamp>,
    /// The protocol majors its binary speaks with nodes; empty when it has not reported
    /// them (a member that has not restarted since it joined with an older build).
    #[serde(default)]
    pub protocol_majors: Vec<u32>,
    /// The wire version of its Raft messages, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raft_wire: Option<String>,
    /// The data formats its binary can open, oldest first; empty when not reported.
    #[serde(default)]
    pub formats: Vec<u32>,
}

/// Body of `POST /cluster/members/{id}/promote`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PromoteRequest {
    /// Promote although the result has an even number of voters or the learner is not
    /// caught up.
    #[serde(default)]
    pub force: bool,
    /// A voter to remove in the same change: replaces a dead voter without passing
    /// through an even number of voters.
    #[serde(default)]
    #[schema(value_type = Option<u64>)]
    pub replace: Option<NodeId>,
}

/// Answer of `POST /cluster/step-down`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StepDown {
    /// The controller that led before.
    #[schema(value_type = u64)]
    pub previous: NodeId,
    /// The controller that leads now.
    #[schema(value_type = u64)]
    pub leader: NodeId,
    /// The term of the new leadership.
    pub term: u64,
}

/// The state digest of one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MemberDigest {
    /// The member.
    #[schema(value_type = u64)]
    pub node: NodeId,
    /// The revision the digest covers.
    #[schema(value_type = Option<u64>)]
    pub revision: Option<Revision>,
    /// The SHA-256 over every table at that revision, lower-case hex.
    pub sha256: Option<String>,
    /// Non-empty tables in the digest.
    pub tables: Option<u64>,
    /// Rows in the digest.
    pub entries: Option<u64>,
    /// Why the member gave no digest (an error code), if it did not.
    pub error: Option<String>,
}

/// Answer of `GET /cluster/digests`: the digests of every member at one revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DigestReport {
    /// The revision every member was asked for (the newest one the answering controller
    /// knows, unless the request named one).
    #[schema(value_type = u64)]
    pub revision: Revision,
    /// Whether every member answered with the same digest at the same revision.
    pub agree: bool,
    /// The digests by node id.
    pub members: Vec<MemberDigest>,
}

/// The cluster operations behind `/cluster/*`.
#[async_trait::async_trait]
pub trait ClusterAdmin: Send + Sync + 'static {
    /// The members with their replication state.
    ///
    /// # Errors
    ///
    /// A store error.
    async fn view(&self) -> Result<ClusterView, ClusterError>;

    /// Promotes a learner to a voter, optionally replacing a voter in the same joint
    /// change; an inline job `cluster.edit` audited as `cluster.member.promote`.
    ///
    /// # Errors
    ///
    /// The codes of the module table.
    async fn promote(
        &self,
        cx: &RequestCtx,
        node: NodeId,
        request: PromoteRequest,
    ) -> Result<ClusterView, ClusterError>;

    /// Removes a member and revokes its certificates; audited as `cluster.member.remove`.
    ///
    /// # Errors
    ///
    /// The codes of the module table.
    async fn remove(&self, cx: &RequestCtx, node: NodeId) -> Result<ClusterView, ClusterError>;

    /// Hands leadership to the most caught-up voter and waits until it leads.
    ///
    /// # Errors
    ///
    /// The codes of the module table.
    async fn step_down(&self, cx: &RequestCtx) -> Result<StepDown, ClusterError>;

    /// The state digests of every member at `revision` (default: the newest revision the
    /// answering controller applied).
    ///
    /// # Errors
    ///
    /// A store error.
    async fn digests(&self, revision: Option<Revision>) -> Result<DigestReport, ClusterError>;
}

/// `cluster.member.not_found` (404).
pub fn member_not_found(node: NodeId) -> ClusterError {
    ClusterError::new(
        "cluster.member.not_found",
        404,
        format!("node {node} is not a member of the controller cluster"),
    )
    .with_param("node", node.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_states_map_onto_views() {
        let at: Timestamp = "2026-10-10T08:00:00Z".parse().expect("time");
        assert_eq!(
            QuorumView::from(QuorumState::Single).state,
            QuorumKind::Single
        );
        let isolated = QuorumView::from(QuorumState::Isolated {
            since: at,
            last_contact: None,
            applied: Revision(7),
        });
        assert_eq!(isolated.state, QuorumKind::Isolated);
        assert_eq!(isolated.since, Some(at));
        assert_eq!(isolated.applied, Some(Revision(7)));
        let json = serde_json::to_value(QuorumView::from(QuorumState::Electing { since: at }))
            .expect("json");
        assert_eq!(json["state"], "electing");
    }
}
