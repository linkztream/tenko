//! The leader service `ipam.reconcile` on a three-member in-process Raft cluster, one IPAM
//! service and reconciler per member over that member's store, each member with a small
//! supervisor that runs the service while the member leads (as `tenko serve` does):
//!
//! - only the leader runs the reconciler; followers ingest but never run it;
//! - an ingest on a follower reaches the leader as a write to `ipam.obs.facts` and starts a
//!   debounced run there;
//! - a setting changed through a follower applies at the leader's next run, without a
//!   restart;
//! - after `hand_over()` the new leader runs it and the old one no longer does.

mod common;
mod reconcile_support;

use std::{future::Future, sync::Arc, time::Duration};

use common::*;
use reconcile_support::*;
use tenko_core::{
    ObjectRef, ObservationId, RequestCtx, SystemComponent, Timestamp,
    cluster::{LEADER_EPOCH, LeaderService},
    ipam::AssignmentMode,
    observe::{Observation, ObservationSource, Observed, ProbeMethod},
};
use tenko_ipam::{
    IpamCommand, IpamService,
    observe::{IngestBatch, IntentSighting, tables::LAST_SEEN},
    proposals::IntentProposalKind,
    reconcile::{LEADER_SERVICE, ReconcilerConfig, settings},
};
use tenko_store::{
    ReadConsistency, Store, WriteBatch,
    raft::{RaftStore, fixture::InProcessCluster},
    testing::ConformanceConfig,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// How long a test waits for the cluster to reach a state before it fails.
const LIMIT: Duration = Duration::from_secs(60);

async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, future)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within {LIMIT:?}"))
}

/// What `take_office` of `tenko serve` does: bumps the leader epoch against its value.
async fn take_office(member: &RaftStore) -> Option<u64> {
    let view = member.read(ReadConsistency::Linearizable).await.ok()?;
    let current = view.counter(&LEADER_EPOCH).ok()?;
    let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Cluster));
    batch.preconditions.push(tenko_store::fence(current));
    batch.bump(LEADER_EPOCH);
    member.propose(batch).await.ok()?;
    Some(current + 1)
}

/// Runs `service` while `member` leads, as the supervisor of `tenko serve` does, until
/// `shutdown` fires.
fn supervise(
    member: RaftStore,
    service: Arc<dyn LeaderService>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut leadership = member.leadership();
        loop {
            let leads = leadership
                .borrow_and_update()
                .is_some_and(|seen| seen.is_self);
            if leads && let Some(epoch) = take_office(&member).await {
                let stop = CancellationToken::new();
                let task = tokio::spawn({
                    let service = Arc::clone(&service);
                    let stop = stop.clone();
                    async move { service.run(epoch, stop).await }
                });
                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        changed = leadership.changed() => {
                            if changed.is_err()
                                || !leadership.borrow_and_update().is_some_and(|seen| seen.is_self)
                            {
                                break;
                            }
                        }
                    }
                }
                stop.cancel();
                let _ = task.await;
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                changed = leadership.changed() => if changed.is_err() { return; },
            }
        }
    })
}

/// The time of the last run on a member, if it ran.
fn last_run(world: &World) -> Option<Timestamp> {
    world.reconciler.last_report().map(|report| report.at)
}

/// Waits until the member ran after `after` (or at all).
async fn runs_after(world: &World, after: Option<Timestamp>, what: &str) {
    within(what, async {
        loop {
            if last_run(world).is_some_and(|at| after.is_none_or(|after| at > after)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// One probe sighting of an address without a MAC address, ingested on `world`.
async fn sighting(world: &World, ip: &str) {
    let source = ObservationSource::Probe {
        node: tenko_core::NodeId(7),
        method: ProbeMethod::Arp,
    };
    let now = Timestamp::now();
    let vrf = world.default_vrf().await;
    world
        .reconciler
        .ingest(IngestBatch {
            source: source.clone(),
            observations: vec![Observation {
                id: ObservationId::generate(),
                source,
                subject: Observed::Address {
                    vrf,
                    ip: ip.parse().expect("ip"),
                    mac: None,
                },
                observed_at: now,
                received_at: now,
                expires_at: now.checked_add(Duration::from_secs(900)),
            }],
            complete: false,
            received_at: now,
        })
        .await
        .expect("ingest");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario from the first leader to the hand-over"
)]
async fn the_reconciler_runs_on_the_leader_only_follows_a_hand_over_and_reads_its_settings() {
    let cluster = InProcessCluster::start(3, &ConformanceConfig::default()).await;
    let shutdown = CancellationToken::new();
    let mut worlds = Vec::new();
    let mut supervisors = Vec::new();
    for member in cluster.members() {
        let store: Arc<dyn Store> = Arc::new(member.clone());
        let service = IpamService::with_direct_jobs(Arc::clone(&store)).expect("service");
        let world = World::over(store, service, ReconcilerConfig::default());
        let leader_service = world.reconciler.leader_service();
        assert_eq!(leader_service.name(), LEADER_SERVICE);
        supervisors.push(supervise(member.clone(), leader_service, shutdown.clone()));
        worlds.push(world);
    }
    let index_of = |member: &RaftStore| {
        cluster
            .members()
            .iter()
            .position(|candidate| candidate.node_id() == member.node_id())
            .expect("a member")
    };
    let leader = index_of(&cluster.wait_for_leader().await);
    let follower = index_of(&cluster.a_follower().await);
    assert!(
        settings::seed(
            worlds[follower].store.as_ref(),
            settings::ReconcilerSettings::default()
        )
        .await
        .expect("seed")
    );

    // The leader runs right after taking office; no follower ever runs.
    runs_after(&worlds[leader], None, "the first run on the leader").await;

    // Intent, written through a follower: an address last seen two hours ago.
    let (input, interface) = host("nas01", AssignmentMode::Static, Some("00:00:5e:00:53:01"));
    let mut assigned = address(None, "192.0.2.10");
    assigned.interface = Some(interface);
    let address_id = assigned.id.expect("id");
    run(
        &worlds[follower].service,
        vec![
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            IpamCommand::CreateHost(input),
            IpamCommand::CreateAddress(assigned),
        ],
    )
    .await;
    let two_hours_ago = Timestamp::from_unix_nanos(
        Timestamp::now().unix_nanos() - i128::from(2 * 3600) * 1_000_000_000,
    )
    .expect("time");
    let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Reconciler));
    batch
        .put_typed(
            &LAST_SEEN,
            &ObjectRef::from(address_id),
            &IntentSighting {
                at: two_hours_ago,
                source: "probe:7:arp".to_owned(),
                observation: ObservationId::generate(),
            },
        )
        .expect("sighting");
    worlds[follower]
        .store
        .propose(batch)
        .await
        .expect("write the sighting");

    // An ingest on the follower starts a run on the leader; under the default orphan age
    // of seven days nothing is orphaned.
    let before = last_run(&worlds[leader]);
    sighting(&worlds[follower], "192.0.2.50").await;
    runs_after(&worlds[leader], before, "a run after a follower's ingest").await;
    assert_eq!(
        worlds[leader]
            .open(IntentProposalKind::OrphanedIntent)
            .await
            .len(),
        0
    );

    // A shorter orphan age, set through the follower, applies at the next run.
    let (current, revision) = settings::read(worlds[follower].store.as_ref())
        .await
        .expect("settings");
    settings::update(
        worlds[follower].store.as_ref(),
        &person(),
        settings::ReconcilerSettings {
            orphan_after_secs: 3600,
            ..current
        },
        revision,
    )
    .await
    .expect("update");
    sighting(&worlds[follower], "192.0.2.51").await;
    within("the orphan proposal under the new setting", async {
        loop {
            if worlds[follower]
                .open(IntentProposalKind::OrphanedIntent)
                .await
                .len()
                == 1
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    for (index, world) in worlds.iter().enumerate() {
        if index != leader {
            assert_eq!(last_run(world), None, "member {index} ran while following");
        }
    }

    // Hand-over: the new leader runs, the old one stops.
    let next = index_of(&cluster.hand_over().await);
    assert_ne!(next, leader);
    runs_after(&worlds[next], None, "the first run on the new leader").await;
    let old_last = last_run(&worlds[leader]);
    let next_last = last_run(&worlds[next]);
    let ingest_on = (0..3).find(|index| *index != next).expect("a follower");
    sighting(&worlds[ingest_on], "192.0.2.52").await;
    runs_after(&worlds[next], next_last, "a run on the new leader").await;
    assert_eq!(
        last_run(&worlds[leader]),
        old_last,
        "the old leader ran after the hand-over"
    );

    shutdown.cancel();
    for supervisor in supervisors {
        within("the supervisor stops", supervisor)
            .await
            .expect("supervisor");
    }
    cluster.shutdown().await;
}
