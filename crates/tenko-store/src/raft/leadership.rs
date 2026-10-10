//! Leadership, quorum state and member replication from openraft's metrics (plan section
//! 2.2): what [`Store::leadership`](crate::api::Store::leadership) and the Slice 3 fields of
//! [`StoreStatus`](crate::api::StoreStatus) report.
//!
//! A member counts as the leader for leader-only work (`is_self`) once it is the leader
//! and has applied an entry of its own term: openraft commits a blank entry at the start
//! of every term, so the state machine then holds everything committed before. With one
//! voter the quorum state is `Single`; with more it is `Healthy` while a leader is known
//! and `Electing` from the moment the leader was lost. Isolation (no contact with a
//! quorum for `[cluster] isolation_after_ms`) needs the peer transport's contact times
//! and arrives with it (WP3.1a).

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use openraft::{RaftMetrics, ServerState};
use tenko_core::{NodeId, Timestamp};
use tokio::sync::watch;

use super::types::RaftNodeId;
use crate::api::{Leadership, MemberStatus, QuorumState};

type Metrics = RaftMetrics<RaftNodeId, openraft::BasicNode>;

/// What the metrics follower publishes.
pub(super) struct LeadershipState {
    sender: watch::Sender<Option<Leadership>>,
    /// When this member last saw no leader, while it sees none.
    leaderless_since: Mutex<Option<Timestamp>>,
}

impl LeadershipState {
    pub(super) fn new() -> Self {
        let (sender, _) = watch::channel(None);
        Self {
            sender,
            leaderless_since: Mutex::new(None),
        }
    }

    /// A receiver of the leadership as this member sees it.
    pub(super) fn subscribe(&self) -> watch::Receiver<Option<Leadership>> {
        self.sender.subscribe()
    }

    /// Records one metrics snapshot.
    fn publish(&self, metrics: &Metrics) {
        let leadership = leadership_of(metrics);
        {
            let mut since = self
                .leaderless_since
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match (leadership, *since) {
                (None, None) => *since = Some(Timestamp::now()),
                (Some(_), Some(_)) => *since = None,
                _ => {}
            }
        }
        self.sender.send_if_modified(|current| {
            if *current == leadership {
                false
            } else {
                *current = leadership;
                true
            }
        });
    }

    /// Ends leadership for good (the store stops).
    pub(super) fn close(&self) {
        self.sender.send_replace(None);
    }

    /// The quorum state for a metrics snapshot.
    pub(super) fn quorum(&self, metrics: &Metrics) -> QuorumState {
        let voters = metrics.membership_config.membership().voter_ids().count();
        if voters <= 1 {
            return QuorumState::Single;
        }
        if metrics.current_leader.is_some() {
            return QuorumState::Healthy;
        }
        let since = self
            .leaderless_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or_else(Timestamp::now);
        QuorumState::Electing { since }
    }
}

/// The leadership a metrics snapshot shows.
fn leadership_of(metrics: &Metrics) -> Option<Leadership> {
    let leader = metrics.current_leader?;
    let applied_own_term = metrics
        .last_applied
        .is_some_and(|applied| applied.leader_id.get_term() == metrics.current_term);
    Some(Leadership {
        leader: NodeId(leader),
        term: metrics.current_term,
        is_self: leader == metrics.id && metrics.state == ServerState::Leader && applied_own_term,
    })
}

/// The members with their replication state; filled on the leader only.
pub(super) fn members(metrics: &Metrics) -> Vec<MemberStatus> {
    let Some(replication) = &metrics.replication else {
        return Vec::new();
    };
    let membership = metrics.membership_config.membership();
    let voters: Vec<RaftNodeId> = membership.voter_ids().collect();
    let last = metrics.last_log_index;
    membership
        .nodes()
        .map(|(id, _)| {
            let matched = if *id == metrics.id {
                last
            } else {
                replication
                    .get(id)
                    .and_then(|matched| matched.map(|log_id| log_id.index))
            };
            MemberStatus {
                node: NodeId(*id),
                voter: voters.contains(id),
                matched,
                lag_entries: last.map(|last| last.saturating_sub(matched.unwrap_or(0))),
                last_contact_ms: None,
            }
        })
        .collect()
}

/// Follows the metrics until the store shuts down, then reports no leader.
pub(super) async fn follow(
    mut metrics: watch::Receiver<Metrics>,
    state: Arc<LeadershipState>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        state.publish(&metrics.borrow_and_update());
        if metrics.changed().await.is_err() {
            break;
        }
    }
    state.close();
}
