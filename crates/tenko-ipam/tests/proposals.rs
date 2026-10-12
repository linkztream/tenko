//! Decisions on proposals: approval, rejection and its memory, revision checks, and the
//! adoption policies with their inheritance and constraints.

mod common;
mod reconcile_support;

use common::*;
use reconcile_support::*;
use tenko_core::{
    ObjectRef,
    ipam::{AssignmentMode, Host, RangeRole},
};
use tenko_ipam::{
    IpamCommand, PlanOptions,
    proposals::{
        self, AdoptionMode, AdoptionPolicy, IntentProposalKind, IntentProposalState, codes,
    },
    query,
    reconcile::ReconcilerConfig,
};

/// A supernet 192.0.2.0/24 with the network 192.0.2.0/25 inside, whose DHCP pool is
/// .64 to .126.
async fn lab(world: &World) -> (tenko_core::PrefixId, tenko_core::PrefixId) {
    let outer = supernet(None, "192.0.2.0/24");
    let inner = prefix(None, "192.0.2.0/25");
    let (outer_id, inner_id) = (outer.id.expect("id"), inner.id.expect("id"));
    run(
        &world.service,
        vec![
            IpamCommand::CreatePrefix(outer),
            IpamCommand::CreatePrefix(inner),
            IpamCommand::CreateRange(range(
                inner_id,
                "192.0.2.64",
                "192.0.2.126",
                RangeRole::DhcpPool,
            )),
        ],
    )
    .await;
    (outer_id, inner_id)
}

fn adopt(mode: AdoptionMode) -> AdoptionPolicy {
    AdoptionPolicy {
        mode,
        ..AdoptionPolicy::default()
    }
}

#[tokio::test]
async fn a_rejection_is_remembered_until_the_evidence_changes() {
    let world = World::new();
    lab(&world).await;
    world
        .poll(
            vec![vm(
                "1",
                Some("tv"),
                Some("00:00:5e:00:53:01"),
                &["192.0.2.10"],
            )],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let proposal = world
        .open(IntentProposalKind::DiscoveredHost)
        .await
        .remove(0);

    let stale = proposals::reject(
        &world.service,
        proposal.id,
        Some("guest device".to_owned()),
        &person(),
        Some(tenko_core::Revision(proposal.revision.0 + 100)),
    )
    .await
    .expect_err("stale If-Match");
    assert_eq!(stale.code_str(), codes::REVISION_MISMATCH);

    let decision = proposals::reject(
        &world.service,
        proposal.id,
        Some("guest device".to_owned()),
        &person(),
        Some(proposal.revision),
    )
    .await
    .expect("reject");
    assert_eq!(decision.proposal.state, IntentProposalState::Rejected);
    assert_eq!(decision.proposal.reason.as_deref(), Some("guest device"));
    assert!(decision.job_id.is_some(), "a decision is a job");

    // The same evidence does not open the subject again.
    world
        .poll(
            vec![vm(
                "1",
                Some("tv"),
                Some("00:00:5e:00:53:01"),
                &["192.0.2.10"],
            )],
            at("08:20"),
        )
        .await;
    let report = world.reconcile(at("08:21")).await;
    assert_eq!((report.opened, report.suppressed), (0, 1), "{report:?}");

    // Other evidence (a new address) does.
    world
        .poll(
            vec![vm(
                "1",
                Some("tv"),
                Some("00:00:5e:00:53:01"),
                &["192.0.2.11"],
            )],
            at("08:30"),
        )
        .await;
    let report = world.reconcile(at("08:31")).await;
    assert_eq!(report.opened, 1, "{report:?}");

    let again = proposals::approve(
        &world.service,
        proposal.id,
        &person(),
        &PlanOptions::default(),
        false,
        None,
    )
    .await
    .expect_err("decided");
    assert_eq!(again.code_str(), codes::NOT_OPEN);
}

#[tokio::test]
async fn a_dry_run_writes_nothing_and_conflicts_have_nothing_to_apply() {
    let world = World::new();
    lab(&world).await;
    world
        .poll(
            vec![
                vm("1", None, Some("00:00:5e:00:53:01"), &["192.0.2.20"]),
                vm("2", None, Some("00:00:5e:00:53:02"), &["192.0.2.20"]),
                vm("3", None, Some("00:00:5e:00:53:03"), &["192.0.2.30"]),
            ],
            at("09:00"),
        )
        .await;
    world.reconcile(at("09:01")).await;
    let conflict = world.open(IntentProposalKind::Conflict).await.remove(0);
    let error = proposals::approve(
        &world.service,
        conflict.id,
        &person(),
        &PlanOptions::default(),
        false,
        None,
    )
    .await
    .expect_err("conflict");
    assert_eq!(error.code_str(), codes::NOTHING_TO_APPLY);

    let discovered = world
        .open(IntentProposalKind::DiscoveredHost)
        .await
        .into_iter()
        .find(|proposal| proposal.subject.mac == Some(mac("00:00:5e:00:53:03")))
        .expect("discovered");
    let preview = proposals::approve(
        &world.service,
        discovered.id,
        &person(),
        &PlanOptions::default(),
        true,
        None,
    )
    .await
    .expect("dry run");
    assert!(preview.dry_run);
    assert_eq!(preview.revision, None);
    let plan = preview.plan.expect("plan");
    assert!(
        plan.summary
            .lines
            .iter()
            .any(|line| line == "1 host created"),
        "{:?}",
        plan.summary.lines
    );
    assert_eq!(preview.proposal.state, IntentProposalState::Open);
    let still = world.open(IntentProposalKind::DiscoveredHost).await;
    assert!(still.iter().any(|proposal| proposal.id == discovered.id));
}

#[tokio::test]
async fn an_inherited_policy_adopts_discovered_hosts_within_its_constraints() {
    let world = World::new();
    let (outer, inner) = lab(&world).await;
    let none = proposals::policy_view(
        world.service.view(None).await.expect("view").as_ref(),
        inner,
    )
    .expect("view");
    assert_eq!(none.policy, None);
    assert_eq!(none.effective.mode, AdoptionMode::Manual);
    assert_eq!(none.source, None);

    let policy = AdoptionPolicy {
        only_dhcp_pools: true,
        min_sightings: 2,
        vendors: vec!["00-00-5E".to_owned()],
        ..adopt(AdoptionMode::AdoptHosts)
    };
    let set = proposals::set_policy(
        &world.service,
        outer,
        Some(policy.clone()),
        &person(),
        Some(tenko_core::Revision::ZERO),
    )
    .await
    .expect("set");
    assert_eq!(set.policy.as_ref(), Some(&policy));
    let child = proposals::policy_view(
        world.service.view(None).await.expect("view").as_ref(),
        inner,
    )
    .expect("view");
    assert_eq!(child.source, Some(outer), "inherited from the supernet");
    assert_eq!(child.effective, policy);

    // Inside the pool, but only one sighting so far: not adopted yet.
    let devices = || {
        vec![
            vm(
                "pool",
                Some("phone"),
                Some("00:00:5e:00:53:70"),
                &["192.0.2.70"],
            ),
            vm(
                "fixed",
                Some("desk"),
                Some("00:00:5e:00:53:05"),
                &["192.0.2.5"],
            ),
            vm("nomac", Some("sensor"), None, &["192.0.2.71"]),
        ]
    };
    world.poll(devices(), at("10:00")).await;
    let first = world.reconcile(at("10:01")).await;
    assert_eq!(first.adopted, 0, "{first:?}");
    // A sighting at least a refresh interval later counts as the second one.
    world.poll(devices(), at("10:20")).await;
    let second = world.reconcile(at("10:21")).await;
    assert_eq!(
        second.adopted, 1,
        "only the pool device with a MAC: {second:?}"
    );

    let accepted = world.proposals(Some(IntentProposalState::Accepted)).await;
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].adopted_by, Some(outer));
    assert_eq!(accepted[0].subject.mac, Some(mac("00:00:5e:00:53:70")));
    let decided = accepted[0].decided.as_ref().expect("decided");
    assert_eq!(decided.by.to_string(), "system:reconciler");
    let host_ref: ObjectRef = accepted[0].results[0];
    let view = world.service.view(None).await.expect("view");
    let host = query::get::<Host>(view.as_ref(), host_ref.id.into()).expect("host");
    assert_eq!(host.mode, AssignmentMode::Dynamic);
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(open.len(), 2, "outside the pool and without MAC stay open");

    // A policy of the network itself wins over the inherited one.
    proposals::set_policy(
        &world.service,
        inner,
        Some(adopt(AdoptionMode::AdoptAll)),
        &person(),
        None,
    )
    .await
    .expect("set inner");
    let third = world.reconcile(at("10:30")).await;
    assert_eq!(third.adopted, 2, "{third:?}");
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new()
    );

    let cleared = proposals::set_policy(&world.service, inner, None, &person(), None)
        .await
        .expect("clear");
    assert_eq!(cleared.policy, None);
    assert_eq!(cleared.source, Some(outer));
}

#[tokio::test]
async fn adoption_never_touches_locked_hosts_and_records_refusals() {
    let world = World::new();
    let (outer, _) = lab(&world).await;
    let (laptop, interface) = host("laptop", AssignmentMode::Dynamic, Some("00:00:5e:00:53:02"));
    let laptop_id = laptop.id.expect("id");
    let mut assigned = address(None, "192.0.2.11");
    assigned.interface = Some(interface);
    run(
        &world.service,
        vec![
            IpamCommand::CreateHost(laptop),
            IpamCommand::CreateAddress(assigned),
        ],
    )
    .await;
    run(
        &world.service,
        vec![IpamCommand::SetLock {
            host: laptop_id,
            lock: true,
            expected: None,
        }],
    )
    .await;
    // Another device already holds the name an inventory gives the new one.
    run(
        &world.service,
        vec![IpamCommand::CreateHost(
            host("camera", AssignmentMode::Static, None).0,
        )],
    )
    .await;
    proposals::set_policy(
        &world.service,
        outer,
        Some(adopt(AdoptionMode::AdoptAll)),
        &person(),
        None,
    )
    .await
    .expect("policy");
    world
        .poll(
            vec![
                vm("laptop", None, Some("00:00:5e:00:53:02"), &["192.0.2.12"]),
                vm(
                    "cam",
                    Some("camera"),
                    Some("00:00:5e:00:53:06"),
                    &["192.0.2.6"],
                ),
            ],
            at("11:00"),
        )
        .await;
    let report = world.reconcile(at("11:01")).await;
    assert_eq!(
        world.open(IntentProposalKind::AddressMismatch).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new(),
        "locked: no proposal"
    );
    assert_eq!(
        report.adopted, 1,
        "the camera, under a free name: {report:?}"
    );
    let accepted = world.proposals(Some(IntentProposalState::Accepted)).await;
    assert!(
        matches!(&accepted[0].commands[0], IpamCommand::CreateHost(input) if input.name.as_str() == "camera-2")
    );
    let view = world.service.view(None).await.expect("view");
    let laptop = query::get::<Host>(view.as_ref(), laptop_id).expect("laptop");
    assert!(laptop.lock);
}

#[tokio::test]
async fn a_refused_adoption_is_recorded_and_not_retried() {
    let world = World::new();
    let (outer, _) = lab(&world).await;
    // A reservation inside the DHCP pool is refused by the planner (IPAM-23).
    proposals::set_policy(
        &world.service,
        outer,
        Some(AdoptionPolicy {
            host_mode: AssignmentMode::Reserved,
            ..adopt(AdoptionMode::AdoptAll)
        }),
        &person(),
        None,
    )
    .await
    .expect("reserved policy");
    world
        .poll(
            vec![vm(
                "phone",
                Some("phone"),
                Some("00:00:5e:00:53:08"),
                &["192.0.2.80"],
            )],
            at("11:05"),
        )
        .await;
    let report = world.reconcile(at("11:06")).await;
    assert_eq!(
        (report.adopted, report.adoption_failures),
        (0, 1),
        "{report:?}"
    );
    let refused = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(refused.len(), 1);
    assert_eq!(
        refused[0].adoption_error.as_deref(),
        Some(tenko_ipam::codes::ADDRESS_IN_DHCP_POOL)
    );
    let report = world.reconcile(at("11:07")).await;
    assert_eq!(
        (report.adopted, report.adoption_failures),
        (0, 0),
        "not retried: {report:?}"
    );
}

#[tokio::test]
async fn a_name_taken_in_the_meantime_supersedes_the_proposal() {
    let world = World::new();
    lab(&world).await;
    world
        .poll(
            vec![vm(
                "tv",
                Some("tv"),
                Some("00:00:5e:00:53:07"),
                &["192.0.2.7"],
            )],
            at("11:10"),
        )
        .await;
    world.reconcile(at("11:11")).await;
    run(
        &world.service,
        vec![IpamCommand::CreateHost(
            host("tv", AssignmentMode::Static, None).0,
        )],
    )
    .await;
    let pending = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(pending.len(), 1);
    let error = proposals::approve(
        &world.service,
        pending[0].id,
        &person(),
        &PlanOptions::default(),
        true,
        None,
    )
    .await
    .expect_err("name taken");
    assert_eq!(error.code_str(), tenko_ipam::codes::NAME_TAKEN);
    // The next run sees the taken name and supersedes the proposal with a free one.
    let report = world.reconcile(at("11:12")).await;
    assert_eq!(report.superseded, 1, "{report:?}");
}

#[tokio::test]
async fn adoption_can_be_switched_off() {
    let world = World::with_config(ReconcilerConfig {
        adopt: false,
        ..ReconcilerConfig::default()
    });
    let (outer, _) = lab(&world).await;
    proposals::set_policy(
        &world.service,
        outer,
        Some(adopt(AdoptionMode::AdoptAll)),
        &person(),
        None,
    )
    .await
    .expect("policy");
    world
        .poll(
            vec![vm("1", None, Some("00:00:5e:00:53:01"), &["192.0.2.70"])],
            at("12:00"),
        )
        .await;
    let report = world.reconcile(at("12:01")).await;
    assert_eq!((report.opened, report.adopted), (1, 0), "{report:?}");
}

#[tokio::test]
async fn invalid_policies_and_missing_prefixes_are_refused() {
    let world = World::new();
    let (outer, _) = lab(&world).await;
    let error = proposals::set_policy(
        &world.service,
        outer,
        Some(AdoptionPolicy {
            min_sightings: 0,
            ..AdoptionPolicy::default()
        }),
        &person(),
        None,
    )
    .await
    .expect_err("invalid");
    assert_eq!(error.code_str(), codes::POLICY_INVALID);
    let error = proposals::set_policy(
        &world.service,
        tenko_core::PrefixId::generate(),
        Some(AdoptionPolicy::default()),
        &person(),
        None,
    )
    .await
    .expect_err("missing");
    assert_eq!(error.code_str(), tenko_ipam::codes::NOT_FOUND);
    let error = proposals::set_policy(
        &world.service,
        outer,
        Some(AdoptionPolicy::default()),
        &person(),
        Some(tenko_core::Revision(9_999)),
    )
    .await
    .expect_err("stale");
    assert_eq!(error.code_str(), tenko_ipam::codes::REVISION_MISMATCH);
}

#[tokio::test]
async fn the_list_filters_sorts_and_pages() {
    use tenko_ipam::proposals::{ProposalQuery, ProposalSeverity, query};
    let world = World::new();
    let (_, inner) = lab(&world).await;
    world
        .poll(
            vec![
                vm("1", None, Some("00:00:5e:00:53:01"), &["192.0.2.10"]),
                vm("2", None, Some("00:00:5e:00:53:02"), &["192.0.2.10"]),
                vm(
                    "3",
                    Some("printer"),
                    Some("00:00:5e:00:53:03"),
                    &["192.0.2.30"],
                ),
                vm("4", None, Some("00:00:5e:00:53:04"), &["198.51.100.4"]),
            ],
            at("13:00"),
        )
        .await;
    world.reconcile(at("13:01")).await;
    let view = world.service.view(None).await.expect("view");
    let list = |query: ProposalQuery| query::list(view.as_ref(), &query).expect("list");

    let all = list(ProposalQuery::default());
    assert_eq!(
        all.items.len(),
        3,
        "a conflict, a printer, a network: {:#?}",
        all.items
    );
    let conflicts = list(ProposalQuery {
        kinds: vec![IntentProposalKind::Conflict],
        ..ProposalQuery::default()
    });
    assert_eq!(conflicts.items.len(), 1);
    let critical = list(ProposalQuery {
        severities: vec![ProposalSeverity::Critical],
        ..ProposalQuery::default()
    });
    assert_eq!(critical.items[0].id, conflicts.items[0].id);
    let in_network = list(ProposalQuery {
        prefix: Some(inner),
        ..ProposalQuery::default()
    });
    assert_eq!(in_network.items.len(), 2, "the conflict and the printer");
    let by_mac = list(ProposalQuery {
        subject: Some("00-00-5E-00-53-03".to_owned()),
        ..ProposalQuery::default()
    });
    assert_eq!(by_mac.items.len(), 1);
    let by_ip = list(ProposalQuery {
        subject: Some("192.0.2.10".to_owned()),
        ..ProposalQuery::default()
    });
    assert_eq!(by_ip.items.len(), 1);
    let by_name = list(ProposalQuery {
        subject: Some("PRINT".to_owned()),
        ..ProposalQuery::default()
    });
    assert_eq!(by_name.items.len(), 1);

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = list(ProposalQuery {
            sort: vec!["severity,-created".to_owned()],
            limit: Some(1),
            cursor,
            ..ProposalQuery::default()
        });
        seen.extend(page.items.iter().map(|proposal| proposal.id));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen.len(), 3);
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 3);

    let error = query::list(
        view.as_ref(),
        &ProposalQuery {
            sort: vec!["colour".to_owned()],
            ..ProposalQuery::default()
        },
    )
    .expect_err("sort");
    assert_eq!(error.code_str(), tenko_ipam::codes::INVALID_FILTER);
    let error = query::list(
        view.as_ref(),
        &ProposalQuery {
            cursor: Some("zz".to_owned()),
            ..ProposalQuery::default()
        },
    )
    .expect_err("cursor");
    assert_eq!(error.code_str(), tenko_ipam::codes::INVALID_CURSOR);
}

/// Vendor facts for MAC addresses from `source` at `when`.
async fn vendors(
    world: &World,
    source: tenko_core::observe::ObservationSource,
    pairs: &[(&str, &str)],
    when: tenko_core::Timestamp,
) {
    let observations = pairs
        .iter()
        .map(|(device, vendor)| tenko_core::observe::Observation {
            id: tenko_core::ObservationId::generate(),
            source: source.clone(),
            subject: tenko_core::observe::Observed::Vendor {
                mac: mac(device),
                vendor: (*vendor).to_owned(),
            },
            observed_at: when,
            received_at: when,
            expires_at: when.checked_add(std::time::Duration::from_secs(3600)),
        })
        .collect();
    world
        .reconciler
        .ingest(tenko_ipam::observe::IngestBatch {
            source,
            observations,
            complete: false,
            received_at: when,
        })
        .await
        .expect("vendor ingest");
}

#[tokio::test]
async fn the_vendors_constraint_reads_the_vendors_that_sources_report() {
    let world = World::new();
    let (outer, _) = lab(&world).await;
    let policy = AdoptionPolicy {
        vendors: vec!["Example Devices".to_owned()],
        ..adopt(AdoptionMode::AdoptHosts)
    };
    proposals::set_policy(
        &world.service,
        outer,
        Some(policy),
        &person(),
        Some(tenko_core::Revision::ZERO),
    )
    .await
    .expect("set");
    world
        .poll(
            vec![
                vm(
                    "probe",
                    Some("camera"),
                    Some("02:00:5e:00:53:70"),
                    &["192.0.2.70"],
                ),
                vm(
                    "hass",
                    Some("plug"),
                    Some("02:00:5e:00:53:72"),
                    &["192.0.2.72"],
                ),
                vm(
                    "other",
                    Some("tv"),
                    Some("02:00:5e:00:53:71"),
                    &["192.0.2.71"],
                ),
            ],
            at("10:00"),
        )
        .await;
    // A probe's OUI lookup names one device; an inventory (Home Assistant) the second; the
    // third has a vendor that does not match. None of the MAC addresses has a listed OUI.
    vendors(
        &world,
        tenko_core::observe::ObservationSource::Probe {
            node: tenko_core::NodeId(7),
            method: tenko_core::observe::ProbeMethod::Arp,
        },
        &[
            ("02:00:5e:00:53:70", "Example Devices Inc."),
            ("02:00:5e:00:53:71", "Other Corp"),
        ],
        at("10:00"),
    )
    .await;
    vendors(
        &world,
        tenko_core::observe::ObservationSource::Inventory {
            connector: tenko_core::ConnectorId::generate(),
        },
        &[("02:00:5e:00:53:72", "EXAMPLE DEVICES")],
        at("10:00"),
    )
    .await;
    let report = world.reconcile(at("10:01")).await;
    assert_eq!(report.adopted, 2, "{report:?}");
    let accepted: Vec<_> = world
        .proposals(Some(IntentProposalState::Accepted))
        .await
        .into_iter()
        .filter_map(|proposal| proposal.subject.mac)
        .collect();
    assert!(accepted.contains(&mac("02:00:5e:00:53:70")));
    assert!(accepted.contains(&mac("02:00:5e:00:53:72")));
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        1
    );
}
