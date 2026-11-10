//! The leader's confirmation of its leadership for linearizable reads (the read index),
//! one round at a time for every read that waits for one.
//!
//! openraft confirms leadership for a read with one round of heartbeats to the voters,
//! each abandoned after the heartbeat interval, and fails the read when a quorum did not
//! answer within it. A round per read multiplies those heartbeats by the read rate: under
//! load they queue behind replication on the followers, a whole wave of rounds misses the
//! interval together, and with one voter of three down every read of the wave fails,
//! because the only follower left has no slack. Here one round runs at a time; a read that
//! arrives while a round runs joins the next one, which starts when the running one ends.
//! A read never takes the outcome of a round that started before it arrived: the
//! heartbeats must leave after the read did, or a newer leader could have committed in
//! between (the read index of the Raft thesis, section 6.4).
//!
//! A round is one call of openraft's `Raft::get_read_log_id`: it takes the read index (the
//! leader's committed index, at least the first entry of its term) when it is called, then
//! sends an empty append with the leader's current vote to every voter and answers only
//! once a quorum of voters accepted that vote; a voter that knows a newer term answers with
//! it, and the round ends as `NotLeader`. Every read a round answers joined before the
//! call, so its confirmation always comes from heartbeats sent after the read arrived. A
//! round that fails confirms nothing: the store may start another one for the same read,
//! but a read is answered only by a round that ended in a quorum's acknowledgment.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures::future::BoxFuture;
use openraft::error::{CheckIsLeaderError, RaftError};
use tokio::sync::watch;

use super::types::{Raft, RaftNodeId};

/// The outcome of one confirmation round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Confirmation {
    /// A quorum confirmed this node's leadership: a read must see the log up to `index`.
    Leader { index: Option<u64> },
    /// Another node leads, as far as this node knows.
    NotLeader { leader: Option<RaftNodeId> },
    /// Fewer than a quorum answered the round in time.
    NoQuorum,
    /// The round did not end within the read wait.
    Timeout,
    /// The Raft node stopped.
    ShuttingDown,
}

type Outcome = watch::Sender<Option<Confirmation>>;

/// One confirmation round, started when called.
type Round = Arc<dyn Fn() -> BoxFuture<'static, Confirmation> + Send + Sync>;

/// The rounds of one store.
pub(super) struct Confirmer {
    round: Round,
    state: Mutex<State>,
}

impl std::fmt::Debug for Confirmer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Confirmer").finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct State {
    /// A round is running.
    running: bool,
    /// The round that starts when the running one ends, with its readers.
    next: Option<Outcome>,
}

impl Confirmer {
    /// Rounds of `round`.
    fn new(round: Round) -> Self {
        Self {
            round,
            state: Mutex::default(),
        }
    }

    /// Rounds of openraft's leadership check on `raft`, each ended after `limit`.
    pub(super) fn of_raft(raft: Raft, limit: Duration) -> Self {
        Self::new(Arc::new(move || {
            let raft = raft.clone();
            Box::pin(async move { confirm(&raft, limit).await })
        }))
    }

    /// The outcome of a round that starts no earlier than this call: a new round when none
    /// runs, else the one after the running round.
    pub(super) fn join(self: &Arc<Self>) -> watch::Receiver<Option<Confirmation>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.running {
            return state
                .next
                .get_or_insert_with(|| watch::channel(None).0)
                .subscribe();
        }
        state.running = true;
        drop(state);
        let (outcome, receiver) = watch::channel(None);
        tokio::spawn(Arc::clone(self).run(outcome));
        receiver
    }

    /// Runs rounds while readers wait for one.
    async fn run(self: Arc<Self>, mut outcome: Outcome) {
        let mut running = Running {
            confirmer: Arc::clone(&self),
            ended: false,
        };
        loop {
            let confirmation = (self.round)().await;
            outcome.send_replace(Some(confirmation));
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(next) = state.next.take() else {
                state.running = false;
                running.ended = true;
                return;
            };
            outcome = next;
        }
    }
}

/// The task of the running rounds. A task dropped before it ended (its runtime shut down)
/// leaves no round running: its readers see the rounds' senders go and ask again, and the
/// next read starts a round of its own instead of waiting for one that never comes.
struct Running {
    confirmer: Arc<Confirmer>,
    ended: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.ended {
            let mut state = self
                .confirmer
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.running = false;
            state.next = None;
        }
    }
}

/// One round of openraft's leadership check.
async fn confirm(raft: &Raft, limit: Duration) -> Confirmation {
    match tokio::time::timeout(limit, raft.get_read_log_id()).await {
        Err(_) => Confirmation::Timeout,
        Ok(Ok((read, _))) => Confirmation::Leader {
            index: read.map(|log_id| log_id.index),
        },
        Ok(Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(forward)))) => {
            Confirmation::NotLeader {
                leader: forward.leader_id,
            }
        }
        Ok(Err(RaftError::APIError(CheckIsLeaderError::QuorumNotEnough(_)))) => {
            Confirmation::NoQuorum
        }
        Ok(Err(RaftError::Fatal(_))) => Confirmation::ShuttingDown,
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::{mpsc, oneshot};

    use super::*;

    type Gates = mpsc::UnboundedReceiver<oneshot::Sender<Confirmation>>;

    /// A confirmer whose rounds report their start, and end with what the test sends.
    fn gated() -> (Arc<Confirmer>, Gates) {
        let (started, gates) = mpsc::unbounded_channel();
        let round: Round = Arc::new(move || {
            let (gate, ended) = oneshot::channel();
            let _ = started.send(gate);
            Box::pin(async move { ended.await.unwrap_or(Confirmation::ShuttingDown) })
        });
        (Arc::new(Confirmer::new(round)), gates)
    }

    async fn outcome(mut receiver: watch::Receiver<Option<Confirmation>>) -> Confirmation {
        receiver
            .wait_for(Option::is_some)
            .await
            .map_or(Confirmation::ShuttingDown, |outcome| {
                outcome.unwrap_or(Confirmation::ShuttingDown)
            })
    }

    /// A read that arrives while a round runs is never answered by it: a leader deposed
    /// after that round started confirmed nothing for the read, and the next round, which
    /// starts after the read arrived, decides.
    #[tokio::test]
    async fn a_read_that_arrives_during_a_round_is_answered_by_the_next_one() {
        let (confirmer, mut gates) = gated();
        let first = confirmer.join();
        let round_one = gates.recv().await.expect("the first round starts");
        // Two reads arrive while the first round runs.
        let second = confirmer.join();
        let third = confirmer.join();
        assert!(gates.try_recv().is_err(), "rounds never overlap");
        let _ = round_one.send(Confirmation::Leader { index: Some(1) });
        assert_eq!(
            outcome(first).await,
            Confirmation::Leader { index: Some(1) }
        );
        // The next round starts for them; the leader was deposed meanwhile.
        let round_two = gates.recv().await.expect("the second round starts");
        assert_eq!(*second.borrow(), None, "not answered by the first round");
        let _ = round_two.send(Confirmation::NotLeader { leader: Some(9) });
        assert_eq!(
            outcome(second).await,
            Confirmation::NotLeader { leader: Some(9) }
        );
        assert_eq!(
            outcome(third).await,
            Confirmation::NotLeader { leader: Some(9) }
        );
        // Nobody waits: no third round runs, and the next read starts one at once.
        tokio::task::yield_now().await;
        assert!(gates.try_recv().is_err(), "no round without a reader");
        let fourth = confirmer.join();
        let round_three = gates.recv().await.expect("a round for the next read");
        let _ = round_three.send(Confirmation::Leader { index: Some(4) });
        assert_eq!(
            outcome(fourth).await,
            Confirmation::Leader { index: Some(4) }
        );
    }

    /// A round whose task is dropped before it ends (its runtime shut down) leaves no round
    /// running: its readers see the round go, and the next read starts a new round.
    #[test]
    fn a_dropped_round_leaves_no_round_running() {
        let (confirmer, mut gates) = gated();
        let first = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let (read, queued, gate) = first.block_on(async {
            let read = confirmer.join();
            let gate = gates.recv().await.expect("a round starts");
            let queued = confirmer.join();
            (read, queued, gate)
        });
        // The round is still running when its runtime goes.
        drop(first);
        drop(gate);
        let second = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        second.block_on(async {
            assert_eq!(
                outcome(read).await,
                Confirmation::ShuttingDown,
                "the round went"
            );
            assert_eq!(outcome(queued).await, Confirmation::ShuttingDown);
            let again = confirmer.join();
            let round = gates.recv().await.expect("a new round for the next read");
            let _ = round.send(Confirmation::Leader { index: Some(3) });
            assert_eq!(
                outcome(again).await,
                Confirmation::Leader { index: Some(3) }
            );
        });
    }

    /// A round that a quorum missed answers its readers with `NoQuorum`; it confirms
    /// nothing, and a read that asks again joins a new round.
    #[tokio::test]
    async fn a_failed_round_confirms_nothing_and_a_new_read_gets_a_new_round() {
        let (confirmer, mut gates) = gated();
        let read = confirmer.join();
        let round = gates.recv().await.expect("a round starts");
        let _ = round.send(Confirmation::NoQuorum);
        assert_eq!(outcome(read).await, Confirmation::NoQuorum);
        let again = confirmer.join();
        let round = gates
            .recv()
            .await
            .expect("a new round for the read that asks again");
        let _ = round.send(Confirmation::Leader { index: Some(2) });
        assert_eq!(
            outcome(again).await,
            Confirmation::Leader { index: Some(2) }
        );
    }
}
