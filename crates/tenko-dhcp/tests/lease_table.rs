//! The production lease table and its feed (WP7.2 content 2): `LeaseIndex` agrees with the
//! reference `MemLeaseTable` on every lookup after random sequences; the index moves it
//! predicts are the ones the table makes; the follower installs an image, applies deltas in
//! order, refuses a gap, takes a reset, and never loses a newer row of the role's own
//! commits to an older copy from the feed. E32: the table's compact rows give back every
//! field of the store's rows, rebuilt from the store or applied in memory.

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
    assert_eq!(index.lease(vrf, active.addr), Some(expired.clone()));
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
    assert_eq!(leases.read().lease(vrf, first.addr), Some(first.clone()));

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
    assert_eq!(leases.read().lease(vrf, first.addr), Some(renewed.clone()));
    assert_eq!(
        leases.read().client_lease(scopes[1], &identity_of(2)),
        Some(second.clone())
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
        assert_eq!(table.lease(vrf, third.addr), Some(third.clone()));
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
    assert_eq!(leases.read().lease(vrf, old.addr), Some(renewed.clone()));

    // An image older than the commit does not drop it either.
    follower.install(&data_with(Revision(11), &[old.clone(), other.clone()]));
    assert_eq!(leases.read().lease(vrf, old.addr), Some(renewed.clone()));
    assert_eq!(leases.read().lease(vrf, other.addr), Some(other.clone()));
    follower
        .apply(&Delta {
            from: Revision(11),
            to: Revision(12),
            changes: vec![Change::Lease((vrf, old.addr), Some(renewed.clone()))],
        })
        .expect("follows");
    let table = leases.read();
    assert_eq!(table.lease(vrf, old.addr), Some(renewed.clone()));
    assert_eq!(table.revision(), Revision(12));
    assert_eq!(
        index_from_data(&data_with(Revision(12), &[renewed.clone(), other.clone()])).sorted_rows(),
        table.sorted_rows()
    );
}

// E32 (M30): the compact row of the table gives back every field of the store's row.

/// A host name, a name of option 81 and its flags.
type Names = (Option<String>, Option<String>, Option<u8>);
/// The DDNS outcome: forward and reverse names, the DHCID, the last error, when.
type Ddns = (
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<u64>,
);
/// A fingerprint: option 55, the vendor class, options 77 and 81, the architecture.
type Print = (Vec<u8>, Option<String>, bool, bool, Option<u16>);
/// A relay: `giaddr`, circuit and remote id, link selection, server override, option 82.
type Relay = (
    u8,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<u8>,
    Option<u8>,
    Vec<u8>,
);

/// The parts of a lease the table keeps outside the hot fields, as a test draws them.
#[derive(Debug, Clone)]
struct Cold {
    chaddr: Vec<u8>,
    client_id: Option<Vec<u8>>,
    times: [Option<u64>; 5],
    share: Option<bool>,
    names: Names,
    policy: Option<(bool, Option<u32>)>,
    ddns: Ddns,
    fingerprint: Option<Print>,
    relay: Option<Relay>,
    state: BindingState,
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

fn text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 .é-]{0,24}"
}

fn name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,7}(\\.[a-z][a-z0-9-]{0,7}){0,3}"
}

fn cold() -> impl Strategy<Value = Cold> {
    (
        (bytes(20), prop::option::of(bytes(300))),
        prop::array::uniform5(prop::option::of(0u64..4_000_000_000)),
        prop::option::of(any::<bool>()),
        (
            prop::option::of(text()),
            prop::option::of(text()),
            prop::option::of(any::<u8>()),
        ),
        prop::option::of((any::<bool>(), prop::option::of(any::<u32>()))),
        (
            prop::option::of(name()),
            prop::option::of(name()),
            prop::option::of(bytes(40)),
            prop::option::of(text()),
            prop::option::of(0u64..4_000_000_000),
        ),
        prop::option::of((
            bytes(40),
            prop::option::of(text()),
            any::<bool>(),
            any::<bool>(),
            prop::option::of(any::<u16>()),
        )),
        prop::option::of((
            any::<u8>(),
            prop::option::of(bytes(20)),
            prop::option::of(bytes(20)),
            prop::option::of(any::<u8>()),
            prop::option::of(any::<u8>()),
            bytes(60),
        )),
        prop::sample::select(vec![
            BindingState::Free,
            BindingState::Active,
            BindingState::Expired,
            BindingState::Released,
            BindingState::Abandoned,
            BindingState::Reset,
            BindingState::Backup,
        ]),
    )
        .prop_map(
            |(
                (chaddr, client_id),
                times,
                share,
                names,
                policy,
                ddns,
                fingerprint,
                relay,
                state,
            )| Cold {
                chaddr,
                client_id,
                times,
                share,
                names,
                policy,
                ddns,
                fingerprint,
                relay,
                state,
            },
        )
}

fn whole(vrf: VrfId, scope: PrefixId, last: u8, cold: Cold) -> Lease {
    use std::net::Ipv4Addr;
    use tenko_core::{
        dhcp::{ClientKey, DdnsPolicy, DdnsState, Fingerprint, PoolShare, RelayInfo},
        dns::DnsName,
        serde_util::HexBytes,
    };
    let time = |secs: Option<u64>| secs.map(at);
    let doc = |octet: u8| Ipv4Addr::new(192, 0, 2, octet);
    let [
        partner_told,
        partner_said,
        partner_acked,
        observed_at,
        granted,
    ] = cold.times;
    let (hostname, fqdn, fqdn_flags) = cold.names;
    let (forward, reverse, dhcid, last_error, updated) = cold.ddns;
    Lease {
        addr: addr(last),
        vrf,
        scope,
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(cold.chaddr),
            client_id: cold.client_id.map(HexBytes),
        },
        state: cold.state,
        cltt: at(u64::from(last)),
        ends: at(u64::from(last) + 3_600),
        tstp: time(partner_told),
        tsfp: time(partner_said),
        atsfp: time(partner_acked),
        node: NODE,
        share: cold.share.map(|primary| {
            if primary {
                PoolShare::Primary
            } else {
                PoolShare::Secondary
            }
        }),
        hostname,
        fqdn,
        fqdn_flags,
        ddns_policy: cold.policy.map(|(enabled, ttl)| DdnsPolicy {
            enabled,
            ttl,
            ..DdnsPolicy::default()
        }),
        ddns: DdnsState {
            forward: forward.map(|name| DnsName::new(&name).expect("a name")),
            reverse: reverse.map(|name| DnsName::new(&name).expect("a name")),
            dhcid: dhcid.map(HexBytes),
            last_error,
            updated: time(updated),
        },
        fingerprint: cold.fingerprint.map(
            |(parameters, vendor_class, user_class, client_fqdn, architecture)| Fingerprint {
                parameters: HexBytes(parameters),
                vendor_class,
                user_class,
                client_fqdn,
                architecture,
            },
        ),
        relay: cold
            .relay
            .map(|(giaddr, circuit, remote, link, server, raw)| RelayInfo {
                giaddr: doc(giaddr),
                circuit_id: circuit.map(HexBytes),
                remote_id: remote.map(HexBytes),
                link_selection: link.map(doc),
                server_id_override: server.map(doc),
                raw: HexBytes(raw),
            }),
        observed_at: time(observed_at),
        granted: time(granted),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn e32_ops_15_the_compact_rows_give_back_the_stores_rows(colds in prop::collection::vec(cold(), 1..24)) {
        use tenko_core::{
            Principal, SystemComponent, Timestamp,
            dhcp::{LeaseRef, tables},
        };
        use tenko_dhcp::lease::rebuild_from_view;
        use tenko_store::{ReadConsistency, WriteBatch};

        let vrf = VrfId::generate();
        let scope = PrefixId::generate();
        let leases: Vec<Lease> = colds
            .into_iter()
            .zip(1u8..)
            .map(|(cold, last)| whole(vrf, scope, last, cold))
            .collect();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let (stored, rebuilt) = runtime.block_on(async {
            let store = lease_support::mem_store();
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
            for lease in &leases {
                batch.put_typed(&tables::LEASES, &(lease.vrf, lease.addr), lease).expect("encodes");
                batch
                    .put_typed(
                        &tables::LEASES_BY_CLIENT,
                        &(lease.scope, lease.client.identity()),
                        &LeaseRef { vrf: lease.vrf, addr: lease.addr },
                    )
                    .expect("encodes");
            }
            store.propose(batch).await.expect("written");
            let stored = lease_support::rows(store.as_ref()).await;
            let view = store.read(ReadConsistency::Local).await.expect("a view");
            (stored, rebuild_from_view(view.as_ref()).expect("rebuilt"))
        });
        // The table rebuilt from the store's rows holds them field for field.
        prop_assert_eq!(&rebuilt.sorted_rows(), &stored.leases);
        // So does a table the rows were applied to in memory, as the committer does.
        let applied = LeaseIndex::from_rows(leases.iter().cloned().map(|lease| (lease, Revision(3))), Revision(3));
        for lease in &leases {
            prop_assert_eq!(applied.lease(lease.vrf, lease.addr), Some(lease.clone()));
            let view = applied.get(lease.vrf, lease.addr).expect("a row");
            prop_assert!(view.client.is(&lease.client.identity()));
            prop_assert_eq!(view.client.to_key(), lease.client.clone());
        }
        // And the client index points where the reference's does.
        let reference = MemLeaseTable::from_rows(leases.iter().cloned());
        for lease in &leases {
            let identity = lease.client.identity();
            prop_assert_eq!(applied.by_client(scope, &identity), reference.by_client(scope, &identity));
        }
    }
}

// ADR 0031: the grant time of a binding, kept in the lease row.

/// The row `kind` writes for client `client` at `second` seconds, over `previous`.
fn written(
    kind: LeaseEventKind,
    client: u32,
    state: BindingState,
    second: u64,
    previous: Option<&Lease>,
) -> Lease {
    let (vrf, scope) = previous.map_or_else(
        || (VrfId::generate(), PrefixId::generate()),
        |held| (held.vrf, held.scope),
    );
    change(
        kind,
        vrf,
        scope,
        addr(10),
        client,
        state,
        at(second),
        at(second + 600),
    )
    .to_lease(NODE, previous)
}

#[test]
fn a_new_grant_sets_the_grant_time_and_a_renewal_keeps_it() {
    let grant = written(LeaseEventKind::Granted, 1, BindingState::Active, 100, None);
    assert_eq!(grant.granted, Some(at(100)));
    assert_eq!(
        grant.observed_at, None,
        "the fact time is no longer written"
    );
    let renewal = written(
        LeaseEventKind::Renewed,
        1,
        BindingState::Active,
        400,
        Some(&grant),
    );
    assert_eq!(renewal.granted, Some(at(100)));
    assert_eq!(renewal.cltt, at(400));
    let rebind = written(
        LeaseEventKind::Rebound,
        1,
        BindingState::Active,
        700,
        Some(&renewal),
    );
    assert_eq!(rebind.granted, Some(at(100)));
    assert_eq!(rebind.granted_at(), at(100));
    // The release of the same client keeps it too.
    let release = written(
        LeaseEventKind::Released,
        1,
        BindingState::Released,
        800,
        Some(&rebind),
    );
    assert_eq!(release.granted, Some(at(100)));
}

#[test]
fn a_grant_after_the_binding_ended_sets_the_grant_time_again() {
    let grant = written(LeaseEventKind::Granted, 1, BindingState::Active, 100, None);
    // The binding ran out at 700; the same client asks again at 5,000.
    let again = written(
        LeaseEventKind::Granted,
        1,
        BindingState::Active,
        5_000,
        Some(&grant),
    );
    assert_eq!(again.granted, Some(at(5_000)));
    // After a release the next grant of the same client is a new grant as well.
    let release = written(
        LeaseEventKind::Released,
        1,
        BindingState::Released,
        200,
        Some(&grant),
    );
    let after_release = written(
        LeaseEventKind::Granted,
        1,
        BindingState::Active,
        300,
        Some(&release),
    );
    assert_eq!(after_release.granted, Some(at(300)));
    // And after an expiry: the expired row keeps the grant time, the next grant sets a new one.
    let expired = written(
        LeaseEventKind::Expired,
        1,
        BindingState::Expired,
        800,
        Some(&grant),
    );
    assert_eq!(expired.granted, Some(at(100)));
    let after_expiry = written(
        LeaseEventKind::Granted,
        1,
        BindingState::Active,
        900,
        Some(&expired),
    );
    assert_eq!(after_expiry.granted, Some(at(900)));
}

#[test]
fn a_grant_to_another_client_sets_the_grant_time() {
    let grant = written(LeaseEventKind::Granted, 1, BindingState::Active, 100, None);
    let other = written(
        LeaseEventKind::Granted,
        2,
        BindingState::Active,
        200,
        Some(&grant),
    );
    assert_eq!(other.granted, Some(at(200)));
    assert_ne!(other.client, grant.client);
}

#[test]
fn the_grant_time_round_trips_through_the_table() {
    let grant = written(LeaseEventKind::Granted, 1, BindingState::Active, 100, None);
    let renewal = written(
        LeaseEventKind::Renewed,
        1,
        BindingState::Active,
        400,
        Some(&grant),
    );
    let mut table = MemLeaseTable::default();
    let mut index = LeaseIndex::new();
    table.apply(renewal.clone());
    index.apply(renewal.clone());
    assert_eq!(
        table
            .rows()
            .get(&(renewal.vrf, renewal.addr))
            .and_then(|row| row.granted),
        Some(at(100))
    );
    assert_eq!(
        index.lease(renewal.vrf, renewal.addr),
        Some(renewal.clone())
    );
    // A row of an earlier version has none; it reads as granted at its client time.
    let old = Lease {
        granted: None,
        ..renewal
    };
    index.apply(Lease {
        cltt: at(500),
        ..old.clone()
    });
    let held = index.lease(old.vrf, old.addr).expect("the row");
    assert_eq!(held.granted, None);
    assert_eq!(held.granted_at(), at(500));
}
