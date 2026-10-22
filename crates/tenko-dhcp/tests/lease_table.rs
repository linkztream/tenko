//! The production lease table and its feed (WP7.2 content 2): `LeaseIndex` agrees with the
//! reference `MemLeaseTable` on every lookup after random sequences; the index moves it
//! predicts are the ones the table makes; the follower installs an image, applies deltas in
//! order, refuses a gap, takes a reset, and never loses a newer row of the role's own
//! commits to an older copy from the feed.

mod lease_support;

use std::time::Duration;

use lease_support::{NODE, addr, at, change, identity_of};
use proptest::prelude::*;
use tenko_core::{
    PrefixId, Revision, VrfId,
    dhcp::{BindingState, Lease, LeaseEventKind},
};
use tenko_dhcp::{
    feed::{Change, Delta, DhcpData, FeedError, FeedEvent, MemFeed},
    lease::{
        LeaseFollower, LeaseIndex, LeaseTable, MemLeaseTable, SharedLeases, follow::index_from_data,
    },
};

#[derive(Debug, Clone)]
enum Op {
    Apply {
        addr: u8,
        scope: usize,
        client: u32,
        cltt: u64,
        state: BindingState,
    },
    Remove {
        addr: u8,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0u8..6, 0usize..2, 0u32..5, 0u64..8, prop::sample::select(vec![
            BindingState::Active, BindingState::Expired, BindingState::Released, BindingState::Abandoned,
        ])).prop_map(|(addr, scope, client, cltt, state)| Op::Apply { addr, scope, client, cltt, state }),
        1 => (0u8..6).prop_map(|addr| Op::Remove { addr }),
    ]
}

fn lease(
    vrf: VrfId,
    scopes: [PrefixId; 2],
    addr_last: u8,
    scope: usize,
    client: u32,
    cltt: u64,
    state: BindingState,
) -> Lease {
    change(
        LeaseEventKind::Granted,
        vrf,
        scopes[scope],
        addr(10 + addr_last),
        client,
        state,
        at(cltt),
        at(cltt + 600),
    )
    .to_lease(NODE, None)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn the_index_agrees_with_the_reference_table(ops in prop::collection::vec(op(), 1..60)) {
        let vrf = VrfId::generate();
        let scopes = [PrefixId::generate(), PrefixId::generate()];
        let mut reference = MemLeaseTable::default();
        let mut index = LeaseIndex::new();
        for op in &ops {
            match op {
                Op::Apply { addr: a, scope, client, cltt, state } => {
                    let row = lease(vrf, scopes, *a, *scope, *client, *cltt, *state);
                    // The moves the index predicts before the row is applied are the moves
                    // the table makes, for the rows the reference keeps.
                    let kept = reference.get(vrf, row.addr).is_none_or(|held| held.cltt <= row.cltt);
                    let predicted = index.index_after(&row);
                    let before = index.client_index();
                    reference.apply(row.clone());
                    index.apply(row);
                    let after = index.client_index();
                    if kept {
                        for update in &predicted {
                            let key = (update.scope, update.identity.clone());
                            prop_assert_eq!(after.get(&key).copied(), update.target);
                        }
                        for (key, value) in &after {
                            if before.get(key) != Some(value) {
                                prop_assert!(predicted.iter().any(|update| update.scope == key.0 && update.identity == key.1));
                            }
                        }
                    }
                }
                Op::Remove { addr: a } => {
                    reference.remove(vrf, addr(10 + a));
                    index.remove(vrf, addr(10 + a));
                }
            }
            prop_assert_eq!(index.len(), reference.len());
            prop_assert_eq!(&index.sorted_rows(), reference.rows());
            for client in 0..5 {
                for scope in scopes {
                    let identity = identity_of(client);
                    prop_assert_eq!(index.by_client(scope, &identity), reference.by_client(scope, &identity));
                }
            }
        }
    }
}

#[test]
fn a_later_revision_wins_over_client_time() {
    let vrf = VrfId::generate();
    let scopes = [PrefixId::generate(), PrefixId::generate()];
    let mut index = LeaseIndex::new();
    let active = lease(vrf, scopes, 1, 0, 1, 5, BindingState::Active);
    let expired = Lease {
        state: BindingState::Expired,
        ..active.clone()
    };
    assert!(index.apply_at(expired.clone(), Revision(9)));
    // The feed's older copy of the same client time is ignored.
    assert!(!index.apply_at(active.clone(), Revision(4)));
    assert_eq!(index.get(vrf, active.addr), Some(&expired));
    assert_eq!(index.row_revision(vrf, active.addr), Some(Revision(9)));
    assert_eq!(index.revision(), Revision(9));
    // Without revisions, the client time decides.
    let mut plain = LeaseIndex::new();
    plain.apply(lease(vrf, scopes, 1, 0, 1, 6, BindingState::Active));
    plain.apply(lease(vrf, scopes, 1, 0, 1, 5, BindingState::Released));
    assert_eq!(
        plain.get(vrf, active.addr).map(|lease| lease.state),
        Some(BindingState::Active)
    );
}

fn data_with(revision: Revision, leases: &[Lease]) -> DhcpData {
    let mut data = DhcpData::at(revision);
    for lease in leases {
        data.leases.insert((lease.vrf, lease.addr), lease.clone());
    }
    data
}

#[tokio::test]
async fn the_follower_holds_the_rows_of_the_feed() {
    let vrf = VrfId::generate();
    let scopes = [PrefixId::generate(), PrefixId::generate()];
    let first = lease(vrf, scopes, 1, 0, 1, 1, BindingState::Active);
    let (mut feed, handle) = MemFeed::new(data_with(Revision(3), std::slice::from_ref(&first)));
    let leases = SharedLeases::default();
    let mut follower = LeaseFollower::new(leases.clone());
    let task_leases = leases.clone();
    let task = tokio::spawn(async move {
        let mut follower = LeaseFollower::new(task_leases);
        follower.follow(&mut feed).await
    });
    assert!(leases.wait_for(Revision(3), Duration::from_secs(5)).await);
    assert_eq!(leases.read().get(vrf, first.addr), Some(&first));

    let second = lease(vrf, scopes, 2, 1, 2, 2, BindingState::Active);
    let renewed = Lease {
        cltt: at(3),
        ..first.clone()
    };
    let revision = handle.publish(vec![
        Change::Lease((vrf, second.addr), Some(second.clone())),
        Change::Lease((vrf, first.addr), Some(renewed.clone())),
    ]);
    assert!(leases.wait_for(revision, Duration::from_secs(5)).await);
    assert_eq!(leases.read().get(vrf, first.addr), Some(&renewed));
    assert_eq!(
        leases.read().by_client(scopes[1], &identity_of(2)),
        Some(&second)
    );

    // A removed row leaves; a reset replaces everything.
    let revision = handle.publish(vec![Change::Lease((vrf, second.addr), None)]);
    assert!(leases.wait_for(revision, Duration::from_secs(5)).await);
    assert!(leases.read().get(vrf, second.addr).is_none());
    let third = lease(vrf, scopes, 3, 0, 3, 4, BindingState::Active);
    handle.reset(data_with(Revision(20), std::slice::from_ref(&third)));
    assert!(leases.wait_for(Revision(20), Duration::from_secs(5)).await);
    {
        let table = leases.read();
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(vrf, third.addr), Some(&third));
    }
    drop(handle);
    assert_eq!(task.await.expect("the task"), Err(FeedError::Closed));

    // A delta that does not follow the revision held is a gap.
    follower.install(&data_with(Revision(5), &[]));
    let gap = Delta {
        from: Revision(7),
        to: Revision(8),
        changes: Vec::new(),
    };
    assert!(matches!(follower.apply(&gap), Err(FeedError::Gap { .. })));
    assert!(
        follower
            .on_event(&FeedEvent::Reset(Box::new(data_with(Revision(9), &[]))))
            .is_ok()
    );
    assert_eq!(follower.held(), Revision(9));
}

#[test]
fn own_commits_survive_an_older_image_and_older_deltas() {
    let vrf = VrfId::generate();
    let scopes = [PrefixId::generate(), PrefixId::generate()];
    let leases = SharedLeases::new(LeaseIndex::new());
    let mut follower = LeaseFollower::new(leases.clone());
    let old = lease(vrf, scopes, 1, 0, 1, 1, BindingState::Active);
    follower.install(&data_with(Revision(10), std::slice::from_ref(&old)));

    // The committer applies its commit at revision 12 before the feed delivers 11 and 12.
    let renewed = Lease {
        cltt: at(2),
        ends: at(9_000),
        ..old.clone()
    };
    leases.apply_at(renewed.clone(), Revision(12));
    let other = lease(vrf, scopes, 2, 0, 2, 1, BindingState::Active);
    follower
        .apply(&Delta {
            from: Revision(10),
            to: Revision(11),
            changes: vec![
                Change::Lease((vrf, other.addr), Some(other.clone())),
                // A stale copy of the renewed row, as it was at 11.
                Change::Lease((vrf, old.addr), Some(old.clone())),
            ],
        })
        .expect("follows");
    assert_eq!(leases.read().get(vrf, old.addr), Some(&renewed));

    // An image older than the commit does not drop it either.
    follower.install(&data_with(Revision(11), &[old.clone(), other.clone()]));
    assert_eq!(leases.read().get(vrf, old.addr), Some(&renewed));
    assert_eq!(leases.read().get(vrf, other.addr), Some(&other));
    follower
        .apply(&Delta {
            from: Revision(11),
            to: Revision(12),
            changes: vec![Change::Lease((vrf, old.addr), Some(renewed.clone()))],
        })
        .expect("follows");
    let table = leases.read();
    assert_eq!(table.get(vrf, old.addr), Some(&renewed));
    assert_eq!(table.revision(), Revision(12));
    assert_eq!(
        index_from_data(&data_with(Revision(12), &[renewed.clone(), other.clone()])).sorted_rows(),
        table.sorted_rows()
    );
}
