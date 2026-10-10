//! Leadership, quorum state and member replication from openraft's metrics (plan section
//! 2.2): what [`Store::leadership`](crate::api::Store::leadership) and the Slice 3 fields of
//! [`StoreStatus`](crate::api::StoreStatus) report.
//!
//! A member counts as the leader for leader-only work (`is_self`) once it is the leader
//! and has applied an entry of its own term: openraft commits a blank entry at the start
//! of every term, so the state machine then holds everything committed before.
//!
//! # Quorum state
//!
//! The sole voter is `Single`. Any other member is `Healthy` while it is in contact with a
//! quorum: a leader whose last acknowledgement by a quorum (`millis_since_quorum_ack`) is
//! younger than the isolation threshold (`[cluster] isolation_after_ms`), a follower or
//! learner whose last message from the leader is younger than it. A member without a leader
//! is `Electing` from the moment it lost the leader. A member that stays out of contact
//! longer than the threshold is `Isolated` from the moment the threshold passed, with the
//! time of its last contact and the revision it last applied.

use std::{
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use openraft::{RaftMetrics, ServerState};
use tenko_core::{NodeId, Revision, Timestamp};
use tokio::sync::watch;

use super::{network::ContactBook, types::RaftNodeId};
use crate::api::{Leadership, MemberStatus, QuorumState};

type Metrics = RaftMetrics<RaftNodeId, openraft::BasicNode>;

/// How often the quorum state is evaluated again without a metrics change (contact ages).
const QUORUM_TICK: Duration = Duration::from_millis(250);

/// A moment as both a monotonic instant (for ages) and a wall-clock time (for reports).
#[derive(Debug, Clone, Copy)]
struct Moment {
    at: Instant,
    wall: Timestamp,
}

impl Moment {
    fn now() -> Self {
        Self {
            at: Instant::now(),
            wall: Timestamp::now(),
        }
    }

    /// The wall-clock time `offset` after this moment.
    fn plus(self, offset: Duration) -> Timestamp {
        self.wall.checked_add(offset).unwrap_or(self.wall)
    }
}

/// Moments the quorum state is judged on.
#[derive(Debug, Default)]
struct Clock {
    /// When this member last saw no leader, while it sees none.
    leaderless_since: Option<Moment>,
    /// When this member last heard from its leader (`handle_append_entries`, a snapshot).
    leader_contact: Option<Moment>,
    /// When this member started to lead or to follow the current leader.
    leader_since: Option<(RaftNodeId, u64, Moment)>,
}

/// What the metrics follower publishes.
pub(super) struct LeadershipState {
    sender: watch::Sender<Option<Leadership>>,
    quorum: watch::Sender<QuorumState>,
    clock: Mutex<Clock>,
    /// The isolation threshold in milliseconds.
    isolation_after: AtomicU64,
}

impl LeadershipState {
    pub(super) fn new(isolation_after: Duration) -> Self {
        let (sender, _) = watch::channel(None);
        let (quorum, _) = watch::channel(QuorumState::Single);
        Self {
            sender,
            quorum,
            clock: Mutex::new(Clock::default()),
            isolation_after: AtomicU64::new(
                u64::try_from(isolation_after.as_millis()).unwrap_or(u64::MAX),
            ),
        }
    }

    /// Changes the isolation threshold.
    pub(super) fn set_isolation_after(&self, threshold: Duration) {
        self.isolation_after.store(
            u64::try_from(threshold.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn clock(&self) -> std::sync::MutexGuard<'_, Clock> {
        self.clock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A receiver of the leadership as this member sees it.
    pub(super) fn subscribe(&self) -> watch::Receiver<Option<Leadership>> {
        self.sender.subscribe()
    }

    /// A receiver of the quorum state, re-evaluated on every metrics change and every
    /// quarter second.
    pub(super) fn subscribe_quorum(&self) -> watch::Receiver<QuorumState> {
        self.quorum.subscribe()
    }

    /// Records a message from the leader (append entries, heartbeat, snapshot).
    pub(super) fn heard_from_leader(&self) {
        self.clock().leader_contact = Some(Moment::now());
    }

    /// Records one metrics snapshot.
    fn publish(&self, metrics: &Metrics, applied: Revision) {
        let leadership = leadership_of(metrics);
        {
            let mut clock = self.clock();
            match (metrics.current_leader, clock.leaderless_since) {
                (None, None) => clock.leaderless_since = Some(Moment::now()),
                (Some(_), Some(_)) => clock.leaderless_since = None,
                _ => {}
            }
            match (metrics.current_leader, clock.leader_since) {
                (Some(leader), Some((known, term, _)))
                    if known == leader && term == metrics.current_term => {}
                (Some(leader), _) => {
                    clock.leader_since = Some((leader, metrics.current_term, Moment::now()));
                }
                (None, _) => clock.leader_since = None,
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
        self.refresh_quorum(metrics, applied);
    }

    fn refresh_quorum(&self, metrics: &Metrics, applied: Revision) {
        let quorum = self.quorum(metrics, applied);
        self.quorum.send_if_modified(|current| {
            if *current == quorum {
                false
            } else {
                *current = quorum;
                true
            }
        });
    }

    /// Ends leadership for good (the store stops).
    pub(super) fn close(&self) {
        self.sender.send_replace(None);
    }

    /// The quorum state for a metrics snapshot.
    pub(super) fn quorum(&self, metrics: &Metrics, applied: Revision) -> QuorumState {
        let membership = metrics.membership_config.membership();
        let voters: Vec<RaftNodeId> = membership.voter_ids().collect();
        if voters == [metrics.id] {
            return QuorumState::Single;
        }
        let clock = self.clock();
        let threshold = Duration::from_millis(self.isolation_after.load(Ordering::Relaxed));
        let isolated = |contact: Option<Moment>, since: Timestamp| QuorumState::Isolated {
            since,
            last_contact: contact.map(|moment| moment.wall),
            applied,
        };
        if metrics.state == ServerState::Leader {
            let became = clock
                .leader_since
                .filter(|(leader, _, _)| *leader == metrics.id)
                .map_or_else(Moment::now, |(_, _, moment)| moment);
            return match metrics.millis_since_quorum_ack {
                Some(millis) => {
                    let age = Duration::from_millis(millis);
                    if age <= threshold {
                        QuorumState::Healthy
                    } else {
                        let ack = Moment {
                            at: Instant::now().checked_sub(age).unwrap_or_else(Instant::now),
                            wall: Timestamp(Timestamp::now().0 - age),
                        };
                        isolated(Some(ack), ack.plus(threshold))
                    }
                }
                None if became.at.elapsed() <= threshold => QuorumState::Healthy,
                None => isolated(None, became.plus(threshold)),
            };
        }
        if metrics.current_leader.is_some() {
            // Contact counts from the last message, or from the moment the leader became
            // known (a restarted member before the first heartbeat).
            let since = clock.leader_since.map(|(_, _, moment)| moment);
            let contact = match (clock.leader_contact, since) {
                (Some(contact), Some(since)) if since.at > contact.at => Some(since),
                (Some(contact), _) => Some(contact),
                (None, since) => since,
            };
            return match contact {
                Some(contact) if contact.at.elapsed() <= threshold => QuorumState::Healthy,
                Some(contact) => isolated(clock.leader_contact, contact.plus(threshold)),
                None => QuorumState::Healthy,
            };
        }
        let since = clock.leaderless_since.unwrap_or_else(Moment::now);
        if since.at.elapsed() <= threshold {
            QuorumState::Electing { since: since.wall }
        } else {
            isolated(clock.leader_contact, since.plus(threshold))
        }
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
pub(super) fn members(metrics: &Metrics, contacts: &ContactBook) -> Vec<MemberStatus> {
    let Some(replication) = &metrics.replication else {
        return Vec::new();
    };
    let membership = metrics.membership_config.membership();
    let voters: Vec<RaftNodeId> = membership.voter_ids().collect();
    let last = metrics.last_log_index;
    membership
        .nodes()
        .map(|(id, _)| {
            let (matched, last_contact_ms) = if *id == metrics.id {
                (last, Some(0))
            } else {
                (
                    replication
                        .get(id)
                        .and_then(|matched| matched.map(|log_id| log_id.index)),
                    contacts.millis_since(*id),
                )
            };
            MemberStatus {
                node: NodeId(*id),
                voter: voters.contains(id),
                matched,
                lag_entries: last.map(|last| last.saturating_sub(matched.unwrap_or(0))),
                last_contact_ms,
            }
        })
        .collect()
}

/// Follows the metrics until the store shuts down, then reports no leader. `applied`
/// reports the revision the state machine has applied.
pub(super) async fn follow(
    mut metrics: watch::Receiver<Metrics>,
    state: Arc<LeadershipState>,
    shutdown: Arc<AtomicBool>,
    applied: impl Fn() -> Revision + Send + 'static,
) {
    let mut tick = tokio::time::interval(QUORUM_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        state.publish(&metrics.borrow_and_update(), applied());
        tokio::select! {
            changed = metrics.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            _ = tick.tick() => {}
        }
    }
    state.close();
}
