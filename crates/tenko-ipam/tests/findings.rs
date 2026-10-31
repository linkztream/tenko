//! The findings model over a real reconciler (IPAM-21, IPAM-23): the guard rail (a sighting of a network's
//! edge address is a scan artifact, never a conflict) for IPv4 and IPv6, an open conflict on
//! such an address closed by the next run with its reason in the audit record, the
//! findings of the view (ghost ageing), and the index kept current from change sets.

mod common;
mod reconcile_support;

use std::collections::BTreeMap;

use common::*;
use reconcile_support::*;
use tenko_core::{
    Principal, ProposalId, Revision, SystemComponent,
    audit::{AuditRecord, Digest},
    ipam::AssignmentMode,
};
use tenko_ipam::{
    IpamCommand,
    findings::{
        Finding, FindingAction, FindingKind, FindingLevel, FindingQuery, FindingSource,
        FindingsConfig, FindingsIndex,
    },
    proposals::{
        IntentProposal, IntentProposalKind, IntentProposalState, ProposalSeverity, ProposalSubject,
        actions,
        model::{OPEN_KEYS, PROPOSALS},
    },
    reconcile::{rule, view::lease_conflicts},
};
use tenko_store::{
    Change, ChangeSet, KeyRange, ReadConsistency, ReadViewExt, WriteBatch, tables::AUDIT,
};

/// A world with the networks `192.0.2.0/24` and `2001:db8::/64` in the default VRF.
async fn lab() -> World {
    let world = World::new();
    run(
        &world.service,
        vec![
            IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24")),
            IpamCommand::CreatePrefix(prefix(None, "2001:db8::/64")),
        ],
    )
    .await;
    world
}

/// An index loaded from the world's store at `now`, the view's findings included.
async fn index_of(world: &World, now: tenko_core::Timestamp) -> FindingsIndex {
    let index = FindingsIndex::new(FindingsConfig::default());
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    index.load(view.as_ref(), now, true).expect("load");
    index
}

fn all(index: &FindingsIndex) -> Vec<Finding> {
    index
        .list(
            &FindingQuery {
                limit: Some(1_000),
                ..FindingQuery::default()
            },
            &|_| true,
        )
        .expect("list")
        .items
}

#[tokio::test]
async fn a_scan_hit_on_an_ipv4_network_or_broadcast_address_is_an_artifact_not_a_conflict() {
    let world = lab().await;
    let vrf = world.default_vrf().await;
    // Two sources see two devices on each edge address: an inventory and a probe.
    world
        .poll(
            vec![
                vm("101", Some("a"), Some("00:00:5e:00:53:01"), &["192.0.2.0"]),
                vm(
                    "102",
                    Some("b"),
                    Some("00:00:5e:00:53:03"),
                    &["192.0.2.255"],
                ),
            ],
            at("08:00"),
        )
        .await;
    world
        .probe(
            vrf,
            &[
                ("192.0.2.0", Some("00:00:5e:00:53:02")),
                ("192.0.2.255", Some("00:00:5e:00:53:04")),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    assert_eq!(
        world.proposals(Some(IntentProposalState::Open)).await,
        Vec::<IntentProposal>::new(),
        "no conflict and no discovered host on an edge address"
    );
    let view = world.service.view(None).await.expect("view");
    assert_eq!(
        lease_conflicts(view.as_ref(), Some(world.service.leases()), at("08:01"))
            .expect("conflicts"),
        Vec::new(),
        "the view lists no conflict row either"
    );

    let index = index_of(&world, at("08:02")).await;
    let findings = all(&index);
    let artifacts: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::ScanArtifact)
        .collect();
    assert_eq!(artifacts.len(), 2, "{findings:#?}");
    for artifact in &artifacts {
        assert_eq!(artifact.severity, FindingLevel::Info);
        assert_eq!(artifact.action, FindingAction::None);
        assert_eq!(artifact.source, FindingSource::Reconcile);
    }
    let edges: Vec<&str> = artifacts
        .iter()
        .map(|artifact| artifact.params["edge"].as_str())
        .collect();
    assert!(
        edges.contains(&"network") && edges.contains(&"broadcast"),
        "{edges:?}"
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.kind != FindingKind::Conflict),
        "{findings:#?}"
    );
    let counts = index.counts();
    assert_eq!(
        counts.problems, 0,
        "artifacts are never counted: {counts:?}"
    );
    assert_eq!(counts.total.info, 2);
}

#[tokio::test]
async fn ipv6_has_no_broadcast_but_its_subnet_router_anycast_address_is_an_artifact() {
    let world = lab().await;
    let vrf = world.default_vrf().await;
    world
        .poll(
            vec![vm(
                "201",
                Some("c"),
                Some("00:00:5e:00:53:11"),
                &["2001:db8::", "2001:db8::ffff:ffff:ffff:ffff"],
            )],
            at("08:00"),
        )
        .await;
    world
        .probe(
            vrf,
            &[
                ("2001:db8::", Some("00:00:5e:00:53:12")),
                ("2001:db8::ffff:ffff:ffff:ffff", Some("00:00:5e:00:53:13")),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let conflicts = world.open(IntentProposalKind::Conflict).await;
    assert_eq!(conflicts.len(), 1, "{conflicts:#?}");
    assert_eq!(
        conflicts[0].subject.ip,
        Some(ip("2001:db8::ffff:ffff:ffff:ffff")),
        "the last address of an IPv6 network is an ordinary address"
    );
    assert_eq!(conflicts[0].rule, rule::CONFLICT_SHARED_ADDRESS);

    let index = index_of(&world, at("08:02")).await;
    let findings = all(&index);
    let artifact = findings
        .iter()
        .find(|finding| finding.kind == FindingKind::ScanArtifact)
        .expect("artifact");
    assert_eq!(artifact.subject.ip, Some(ip("2001:db8::")));
    assert_eq!(artifact.params["edge"], "subnet_router_anycast");
    // The conflict is listed once: as the proposal, not again as the view's row.
    let listed: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::Conflict)
        .collect();
    assert_eq!(listed.len(), 1, "{listed:#?}");
    assert_eq!(listed[0].source, FindingSource::Proposal);
    assert_eq!(listed[0].severity, FindingLevel::Act);
    assert_eq!(index.counts().total.act, 1);
}

#[tokio::test]
async fn an_open_conflict_on_a_network_address_is_closed_by_the_next_run_with_its_reason() {
    let world = lab().await;
    let vrf = world.default_vrf().await;
    // A conflict an earlier version opened on the network address.
    let created = at("07:00");
    let proposal = IntentProposal {
        id: ProposalId::generate(),
        kind: IntentProposalKind::Conflict,
        rule: rule::CONFLICT_SHARED_ADDRESS.to_owned(),
        key: format!("conflict/shared:{vrf}/192.0.2.0"),
        subject: ProposalSubject {
            ip: Some(ip("192.0.2.0")),
            vrf: Some(vrf),
            ..ProposalSubject::default()
        },
        severity: ProposalSeverity::Critical,
        state: IntentProposalState::Open,
        summary: "192.0.2.0 is used by 2 devices".to_owned(),
        params: BTreeMap::new(),
        evidence: Vec::new(),
        commands: Vec::new(),
        choices: Vec::new(),
        fingerprint: Digest([1; 32]),
        created,
        updated: created,
        decided: None,
        reason: None,
        adopted_by: None,
        results: Vec::new(),
        superseded_by: None,
        adoption_error: None,
        revision: Revision::ZERO,
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Reconciler), created);
    batch
        .put_typed(&PROPOSALS, &proposal.id, &proposal)
        .expect("put");
    batch
        .put_typed(&OPEN_KEYS, &proposal.key, &proposal.id)
        .expect("put");
    world.store.propose(batch).await.expect("write");
    world
        .probe(
            vrf,
            &[
                ("192.0.2.0", Some("00:00:5e:00:53:01")),
                ("192.0.2.0", Some("00:00:5e:00:53:02")),
            ],
            at("08:00"),
        )
        .await;

    world.reconcile(at("08:01")).await;
    let expired: Vec<IntentProposal> = world
        .proposals(Some(IntentProposalState::Expired))
        .await
        .into_iter()
        .filter(|expired| expired.id == proposal.id)
        .collect();
    assert_eq!(expired.len(), 1, "the conflict is closed");
    let reason = expired[0].reason.clone().expect("reason");
    assert!(
        reason.starts_with("the network address of its network is never the subject of a conflict"),
        "{reason}"
    );
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    let records: Vec<AuditRecord> = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .filter(|record: &AuditRecord| record.draft.action.as_str() == actions::EXPIRE)
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].draft.details.context.get("reason"),
        Some(&reason),
        "the audit record carries the reason"
    );
    assert!(
        world.open(IntentProposalKind::Conflict).await.is_empty(),
        "and no new conflict opens"
    );
}

#[tokio::test]
async fn a_ghost_is_information_until_it_has_been_unseen_for_the_review_age() {
    let world = lab().await;
    let (input, interface) = host(
        "printer",
        AssignmentMode::Reserved,
        Some("00:00:5e:00:53:21"),
    );
    let mut assigned = address(None, "192.0.2.21");
    assigned.interface = Some(interface);
    run(
        &world.service,
        vec![
            IpamCommand::CreateHost(input),
            IpamCommand::CreateAddress(assigned),
        ],
    )
    .await;
    let vrf = world.default_vrf().await;
    // Seen once by the probe, so the address is scanned; then never again.
    world
        .probe(
            vrf,
            &[("192.0.2.21", Some("00:00:5e:00:53:21"))],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;

    let config = FindingsConfig::default();
    let ghost = |index: &FindingsIndex| {
        all(index)
            .into_iter()
            .find(|finding| finding.kind == FindingKind::Ghost)
    };
    // Ten days later the address is a ghost: listed, not counted.
    let ten_days = days_after(at("08:00"), 10);
    let index = index_of(&world, ten_days).await;
    let young = ghost(&index).expect("a ghost after ten days");
    assert_eq!(young.severity, FindingLevel::Info);
    assert_eq!(young.action, FindingAction::None);
    assert_eq!(young.since, at("08:00"), "unseen since its last sighting");
    assert_eq!(index.counts().problems, 0);

    // Past the review age it is to review, with the action "Decommission".
    let later = days_after(at("08:00"), config.ghost_review_after_secs / 86_400 + 1);
    let index = index_of(&world, later).await;
    let old = ghost(&index).expect("still a ghost");
    assert_eq!(old.id, young.id, "the identifier is stable");
    assert_eq!(old.severity, FindingLevel::Review);
    assert_eq!(old.action, FindingAction::Decommission);
    assert_eq!(old.subject.label, "printer");
    assert_eq!(index.counts().areas.ipam.review, 1);
}

#[tokio::test]
async fn the_index_follows_the_proposals_of_change_sets() {
    let world = lab().await;
    let index = index_of(&world, at("08:00")).await;
    assert!(index.is_empty());
    world
        .poll(
            vec![vm(
                "101",
                Some("web01"),
                Some("00:00:5e:00:53:31"),
                &["192.0.2.31"],
            )],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let open = world.proposals(Some(IntentProposalState::Open)).await;
    assert_eq!(open.len(), 1);
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    let changes = ChangeSet {
        revision: view.revision(),
        principal: Principal::system(SystemComponent::Reconciler),
        at: at("08:01"),
        changes: vec![Change {
            table: PROPOSALS.name().clone(),
            key: PROPOSALS.key(&open[0].id),
            deleted: false,
        }],
    };
    let applied = index.apply(view.as_ref(), &changes).expect("apply");
    assert_eq!(
        applied.changed,
        vec![tenko_core::ObjectRef::from(open[0].id)]
    );
    assert!(applied.view_inputs, "a proposal is an input of the view");
    let finding = index
        .get(&format!("proposal:{}", open[0].id))
        .expect("finding");
    assert_eq!(finding.kind, FindingKind::UnknownDevice);
    assert_eq!(finding.severity, FindingLevel::Review);
    assert_eq!(finding.action, FindingAction::Adopt);
    assert_eq!(index.counts().sources.proposal, 1);

    // Rejected: the finding goes, applied from the next change set alone.
    let rejected = world.reject(&open[0]).await;
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    let changes = ChangeSet {
        revision: view.revision(),
        changes: changes.changes.clone(),
        ..changes
    };
    let applied = index.apply(view.as_ref(), &changes).expect("apply");
    assert_eq!(applied.changed.len(), 1, "{rejected:?}");
    assert!(index.get(&format!("proposal:{}", open[0].id)).is_none());
    assert_eq!(index.counts().sources.proposal, 0);
}
