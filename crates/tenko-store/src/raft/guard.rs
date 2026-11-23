//! What a leader may send to this store. Every leader whose vote openraft accepts holds the
//! entries this store holds as committed under the same log ids (Leader Completeness), so a
//! request that contradicts them comes from another history; and while this store is its own
//! only voter, no other node can lead above its vote unless the store went back to an older
//! copy. The store judges each request with these functions before openraft sees it.

use super::types::{LogId, RaftNodeId, Vote};
use crate::api::FenceReason;

/// What this store holds as committed when a request arrives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Held {
    /// The greater of the applied and the last saved committed log id.
    pub(super) bound: Option<LogId>,
    /// The last saved committed log id. Records above it are not compared: after a snapshot
    /// install they may be a deposed leader's tail that the purge has not dropped yet.
    pub(super) committed: Option<LogId>,
    /// The last purged log id.
    pub(super) purged: Option<LogId>,
}

/// The committed log id this store holds at `index`, if it knows one; `record` reads the log
/// id of the local record there (none once purged).
pub(super) fn local(
    held: &Held,
    index: u64,
    record: impl Fn(u64) -> Option<LogId>,
) -> Option<LogId> {
    match held.purged {
        Some(purged) if purged.index == index => Some(purged),
        _ if held
            .committed
            .is_some_and(|committed| index <= committed.index) =>
        {
            record(index)
        }
        _ => None,
    }
}

/// Whether `position` contradicts what `held` holds as committed, `local` being its
/// [`local`] id. In one log, leader ids never fall as the index rises, so a position above
/// the bound under a leader below the bound's, or one without a local id under a leader
/// above it, comes from another history.
pub(super) fn contradicts(held: &Held, position: LogId, local: Option<LogId>) -> bool {
    let Some(bound) = held.bound else {
        return false;
    };
    match local {
        _ if position.index > bound.index => position.leader_id < bound.leader_id,
        Some(local) => local != position,
        None => position.leader_id > bound.leader_id,
    }
}

/// Why a request stops this store, if it does. `stored` is the vote the log store holds,
/// read after `held`; `sole` says whether this store is its own only voter.
pub(super) fn verdict(
    me: RaftNodeId,
    sole: bool,
    request: &Vote,
    stored: Option<&Vote>,
    contradicts: bool,
) -> Option<FenceReason> {
    let other = request.leader_id().voted_for() != Some(me);
    if sole && other && stored.is_none_or(|stored| request > stored) {
        Some(FenceReason::Reverted)
    } else if contradicts && stored.is_none_or(|stored| request >= stored) {
        // The test openraft applies first (`vote_handler::update_vote`).
        Some(FenceReason::Diverged)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use openraft::CommittedLeaderId;

    use super::*;

    fn id(term: u64, node: u64, index: u64) -> LogId {
        LogId::new(CommittedLeaderId::new(term, node), index)
    }

    fn vote(term: u64, node: u64, committed: bool) -> Vote {
        if committed {
            Vote::new_committed(term, node)
        } else {
            Vote::new(term, node)
        }
    }

    /// The fixtures of the design note: `H` in steady state, `I` while a snapshot install
    /// has purged and not applied, `B` with a record above the saved committed, `L` with a
    /// bound from a snapshot alone, `N` with nothing purged.
    fn held(name: char) -> Held {
        match name {
            'H' => Held {
                bound: Some(id(3, 1, 10)),
                committed: Some(id(3, 1, 10)),
                purged: Some(id(2, 1, 4)),
            },
            'I' => Held {
                bound: Some(id(3, 1, 10)),
                committed: Some(id(3, 1, 10)),
                purged: Some(id(4, 2, 12)),
            },
            'B' => Held {
                bound: Some(id(3, 1, 10)),
                committed: Some(id(3, 1, 7)),
                purged: Some(id(2, 1, 4)),
            },
            'L' => Held {
                bound: Some(id(3, 1, 10)),
                ..Held::default()
            },
            'N' => Held {
                bound: Some(id(3, 1, 10)),
                committed: Some(id(3, 1, 10)),
                purged: None,
            },
            _ => Held::default(),
        }
    }

    fn record(held: char, index: u64) -> Option<LogId> {
        match (held, index) {
            ('H', 8) => None,
            ('B', 9) => Some(id(2, 2, 9)),
            (_, 5..=10) => Some(id(3, 1, index)),
            _ => None,
        }
    }

    /// A row of the position table: (row, fixture, position as term, leader, index,
    /// contradicts).
    type PositionRow = (&'static str, char, (u64, u64, u64), bool);

    /// The position table of the design note.
    const POSITIONS: [PositionRow; 22] = [
        ("P1", 'H', (3, 1, 12), false),
        ("P2", 'H', (5, 5, 12), false),
        ("P3", 'I', (3, 1, 11), false),
        ("P4", 'H', (3, 1, 10), false),
        ("P5", 'H', (3, 2, 10), true),
        ("P6", 'I', (3, 1, 10), false),
        ("P7", 'I', (4, 2, 10), true),
        ("P8", 'H', (3, 1, 7), false),
        ("P9", 'H', (3, 2, 7), true),
        ("P10", 'H', (2, 1, 4), false),
        ("P11", 'H', (2, 2, 4), true),
        ("P12", 'H', (1, 1, 3), false),
        ("P13", 'H', (4, 1, 3), true),
        ("P14", 'H', (3, 1, 8), false),
        ("P15", 'H', (4, 1, 8), true),
        ("P16", 'B', (3, 1, 9), false),
        ("P17", '-', (9, 9, 1), false),
        ("P18", 'H', (2, 1, 12), true),
        ("P19", 'B', (4, 1, 9), true),
        ("P20", 'L', (3, 1, 7), false),
        ("P21", 'L', (4, 1, 7), true),
        ("P22", 'N', (3, 2, 7), true),
    ];

    /// The vote table of the design note: (row, request, stored, accepted, and whether it
    /// finds node 1 reverted when node 1 is its own only voter).
    fn votes() -> [(&'static str, Vote, Option<Vote>, bool, bool); 8] {
        let stored = Some(vote(3, 1, true));
        [
            ("V1", vote(2, 1, true), stored, false, false),
            ("V2", vote(3, 0, true), stored, false, false),
            ("V3", vote(3, 1, false), stored, false, false),
            ("V4", vote(3, 1, true), stored, true, false),
            ("V5", vote(3, 2, true), stored, true, true),
            ("V6", vote(4, 2, true), stored, true, true),
            ("V7", vote(4, 2, false), stored, true, true),
            ("V8", vote(2, 1, true), None, true, false),
        ]
    }

    #[test]
    fn a_request_stops_the_store_only_where_the_table_says() {
        for (row, fixture, (term, node, index), contradicting) in POSITIONS {
            let (held, position) = (held(fixture), id(term, node, index));
            let found = contradicts(
                &held,
                position,
                local(&held, index, |at| record(fixture, at)),
            );
            assert_eq!(found, contradicting, "{row}");
            for (vote_row, request, stored, accepted, _) in votes() {
                // Node 7 is not the sender of any row and is not its own only voter here.
                let stops = verdict(7, false, &request, stored.as_ref(), found);
                let expected = (contradicting && accepted).then_some(FenceReason::Diverged);
                assert_eq!(stops, expected, "{row} {vote_row}");
            }
        }
    }

    #[test]
    fn only_another_leader_above_a_sole_voter_finds_it_reverted() {
        for (row, request, stored, _, reverts) in votes() {
            let expected = reverts.then_some(FenceReason::Reverted);
            assert_eq!(
                verdict(1, true, &request, stored.as_ref(), false),
                expected,
                "{row}"
            );
            assert_eq!(
                verdict(1, false, &request, stored.as_ref(), false),
                None,
                "{row}"
            );
        }
        // A sole voter that holds no vote yet.
        assert_eq!(
            verdict(1, true, &vote(2, 2, true), None, false),
            Some(FenceReason::Reverted)
        );
        // A leader that removed itself sends under the vote the store holds.
        let held = vote(3, 2, true);
        assert_eq!(verdict(1, true, &held, Some(&held), false), None);
        // The sole voter's own vote, and the older-copy verdict before the diverged one.
        assert_eq!(
            verdict(1, true, &vote(4, 1, true), Some(&held), true),
            Some(FenceReason::Diverged)
        );
        assert_eq!(
            verdict(1, true, &vote(4, 2, true), Some(&held), true),
            Some(FenceReason::Reverted)
        );
    }
}
