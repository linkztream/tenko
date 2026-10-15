//! The reconciler's rules against synthetic observations: discovered hosts, address
//! mismatches, conflicts, addresses outside known networks and orphaned intent; locked
//! and unmanaged hosts; the life of a proposal (open, refreshed, superseded, expired).

mod common;
mod reconcile_support;

use common::*;
use reconcile_support::*;
use tenko_core::{
    ObjectKind,
    ipam::{Address, AssignmentMode, Host, Status},
};
use tenko_ipam::{
    IpamCommand,
    proposals::{IntentProposalKind, IntentProposalState, ProposalSeverity},
    query,
    reconcile::{rule, scopes},
};

/// A world with the network 192.0.2.0/24 in the default VRF.
async fn lab() -> World {
    let world = World::new();
    run(
        &world.service,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    world
}

/// A host with one interface (MAC) and one address.
async fn intended(world: &World, name: &str, mode: AssignmentMode, mac: &str, ip: &str) -> Host {
    let (input, interface) = host(name, mode, Some(mac));
    let id = input.id.expect("id");
    let mut assigned = address(None, ip);
    assigned.interface = Some(interface);
    run(
        &world.service,
        vec![
            IpamCommand::CreateHost(input),
            IpamCommand::CreateAddress(assigned),
        ],
    )
    .await;
    let view = world.service.view(None).await.expect("view");
    query::get::<Host>(view.as_ref(), id).expect("host")
}

#[tokio::test]
async fn every_ingest_counts_its_batch_and_its_facts() {
    use tenko_ipam::reconcile::{INGEST_BATCHES, INGEST_FACTS};
    let world = lab().await;
    let (batches, facts) = (INGEST_BATCHES.get(), INGEST_FACTS.get());
    world
        .poll(
            vec![
                vm("qemu/101", None, Some("00:00:5e:00:53:01"), &["192.0.2.10"]),
                vm("qemu/102", None, Some("00:00:5e:00:53:02"), &["192.0.2.11"]),
            ],
            at("08:00"),
        )
        .await;
    // Other tests of this binary may ingest at the same time, so at least.
    assert!(INGEST_BATCHES.get() > batches);
    assert!(INGEST_FACTS.get() >= facts + 2);
}

#[tokio::test]
async fn an_unknown_mac_becomes_a_discovered_host_and_approval_makes_it_intent() {
    let world = lab().await;
    world
        .poll(
            vec![vm(
                "qemu/101",
                Some("Web 01"),
                Some("00:00:5e:00:53:01"),
                &["192.0.2.10"],
            )],
            at("08:00"),
        )
        .await;
    let report = world.reconcile(at("08:01")).await;
    assert_eq!(report.opened, 1, "{report:?}");
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(open.len(), 1);
    let proposal = &open[0];
    assert_eq!(proposal.rule, rule::DISCOVERED_MAC);
    assert_eq!(proposal.key, "discovered_host/mac:00:00:5e:00:53:01");
    assert_eq!(proposal.severity, ProposalSeverity::Info);
    assert_eq!(proposal.subject.mac, Some(mac("00:00:5e:00:53:01")));
    assert_eq!(
        proposal.subject.ip.map(|ip| ip.to_string()).as_deref(),
        Some("192.0.2.10")
    );
    assert!(proposal.subject.prefix.is_some());
    assert_eq!(proposal.evidence.len(), 1);
    assert_eq!(proposal.evidence[0].name.as_deref(), Some("Web 01"));
    assert!(
        matches!(&proposal.commands[0], IpamCommand::CreateHost(host) if host.name.as_str() == "web-01")
    );
    assert!(
        matches!(&proposal.commands[1], IpamCommand::CreateAddress(address) if address.ip.to_string() == "192.0.2.10")
    );

    // A second run with nothing new keeps the proposal as it is.
    let again = world.reconcile(at("08:02")).await;
    assert_eq!((again.opened, again.unchanged), (0, 1), "{again:?}");

    let decision = world.approve(proposal).await;
    assert_eq!(decision.proposal.state, IntentProposalState::Accepted);
    assert!(decision.job_id.is_some());
    assert_eq!(decision.results.len(), 2);
    let view = world.service.view(decision.revision).await.expect("view");
    let host = query::get::<Host>(view.as_ref(), decision.results[0].id.into()).expect("host");
    assert_eq!(host.name.as_str(), "web-01");
    assert_eq!(host.mode, AssignmentMode::Dynamic);
    assert!(
        host.meta
            .tags
            .iter()
            .any(|tag| tag.as_str() == "discovered")
    );

    // The device is intent now: nothing is open, and the accepted proposal stays.
    let after = world.reconcile(at("08:05")).await;
    assert_eq!((after.opened, after.expired), (0, 0), "{after:?}");
    assert_eq!(
        world.proposals(Some(IntentProposalState::Open)).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new()
    );
    assert_eq!(
        world
            .proposals(Some(IntentProposalState::Accepted))
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn names_are_unique_and_unknown_addresses_without_mac_are_discovered_too() {
    let world = lab().await;
    intended(
        &world,
        "printer",
        AssignmentMode::Static,
        "00:00:5e:00:53:20",
        "192.0.2.20",
    )
    .await;
    world
        .poll(
            vec![
                vm(
                    "1",
                    Some("printer"),
                    Some("00:00:5e:00:53:21"),
                    &["192.0.2.21"],
                ),
                vm("2", None, None, &["192.0.2.22"]),
                vm("3", None, Some("00:00:5e:00:53:23"), &[]),
            ],
            at("09:00"),
        )
        .await;
    world.reconcile(at("09:01")).await;
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    let names: Vec<String> = open
        .iter()
        .filter_map(|proposal| match &proposal.commands[0] {
            IpamCommand::CreateHost(host) => Some(host.name.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(open.len(), 3, "{open:#?}");
    assert!(names.contains(&"printer-2".to_owned()), "{names:?}");
    assert!(names.contains(&"host-192-0-2-22".to_owned()), "{names:?}");
    assert!(names.contains(&"host-00005e005323".to_owned()), "{names:?}");
    let by_ip = open
        .iter()
        .find(|proposal| proposal.rule == rule::DISCOVERED_ADDRESS)
        .expect("address proposal");
    assert_eq!(by_ip.subject.mac, None);
    let mac_only = open
        .iter()
        .find(|proposal| proposal.subject.mac == Some(mac("00:00:5e:00:53:23")))
        .expect("mac only");
    assert_eq!(mac_only.commands.len(), 1, "a host without addresses");
    assert_eq!(mac_only.subject.prefix, None);
}

#[tokio::test]
async fn a_host_seen_elsewhere_gets_a_mismatch_unless_locked_and_unmanaged_hosts_get_nothing() {
    let world = lab().await;
    let nas = intended(
        &world,
        "nas01",
        AssignmentMode::Static,
        "00:00:5e:00:53:01",
        "192.0.2.10",
    )
    .await;
    let laptop = intended(
        &world,
        "laptop",
        AssignmentMode::Dynamic,
        "00:00:5e:00:53:02",
        "192.0.2.11",
    )
    .await;
    intended(
        &world,
        "wild",
        AssignmentMode::Unmanaged,
        "00:00:5e:00:53:03",
        "192.0.2.12",
    )
    .await;
    world
        .poll(
            vec![
                vm(
                    "nas",
                    Some("nas01"),
                    Some("00:00:5e:00:53:01"),
                    &["192.0.2.50"],
                ),
                vm(
                    "laptop",
                    Some("laptop"),
                    Some("00:00:5e:00:53:02"),
                    &["192.0.2.51"],
                ),
                vm(
                    "wild",
                    Some("wild"),
                    Some("00:00:5e:00:53:03"),
                    &["192.0.2.52"],
                ),
                // Uses the address intended for the unmanaged host: nothing either.
                vm("other", None, Some("00:00:5e:00:53:04"), &["192.0.2.12"]),
            ],
            at("10:00"),
        )
        .await;
    world.reconcile(at("10:01")).await;
    let mismatches = world.open(IntentProposalKind::AddressMismatch).await;
    assert_eq!(mismatches.len(), 2, "{mismatches:#?}");
    let nas_mismatch = mismatches
        .iter()
        .find(|proposal| proposal.subject.objects.contains(&nas.id.into()))
        .expect("nas");
    assert_eq!(
        nas_mismatch.severity,
        ProposalSeverity::Warning,
        "intent wins: static"
    );
    assert_eq!(nas_mismatch.rule, rule::ADDRESS_MISMATCH);
    assert!(
        matches!(&nas_mismatch.commands[0], IpamCommand::UpdateAddress(update) if update.patch.ip.map(|ip| ip.to_string()).as_deref() == Some("192.0.2.50"))
    );
    let laptop_mismatch = mismatches
        .iter()
        .find(|proposal| proposal.subject.objects.contains(&laptop.id.into()))
        .expect("laptop");
    assert_eq!(laptop_mismatch.severity, ProposalSeverity::Info, "dynamic");
    assert_eq!(
        world.open(IntentProposalKind::Conflict).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new()
    );
    assert!(
        world
            .proposals(None)
            .await
            .iter()
            .all(|proposal| !proposal.key.contains("00:00:5e:00:53:03")),
        "the unmanaged host produces nothing"
    );

    // Locking the NAS expires its mismatch: no proposal changes a locked host.
    run(
        &world.service,
        vec![IpamCommand::SetLock {
            host: nas.id,
            lock: true,
            expected: None,
        }],
    )
    .await;
    let report = world.reconcile(at("10:02")).await;
    assert_eq!(report.expired, 1, "{report:?}");
    let open = world.open(IntentProposalKind::AddressMismatch).await;
    assert_eq!(open.len(), 1);
    assert!(open[0].subject.objects.contains(&laptop.id.into()));
}

#[tokio::test]
async fn two_devices_on_one_address_and_an_address_held_by_another_device_are_conflicts() {
    let world = lab().await;
    intended(
        &world,
        "camera",
        AssignmentMode::Reserved,
        "00:00:5e:00:53:30",
        "192.0.2.30",
    )
    .await;
    let vrf = world.default_vrf().await;
    world
        .probe(
            vrf,
            &[
                ("192.0.2.40", Some("00:00:5e:00:53:41")),
                ("192.0.2.40", Some("00:00:5e:00:53:42")),
                ("192.0.2.30", Some("00:00:5e:00:53:43")),
            ],
            at("11:00"),
        )
        .await;
    // The probe reports one address per fact: the second sighting of .40 replaces the
    // first. A second source sees the other device on it.
    world
        .poll(
            vec![vm("x", None, Some("00:00:5e:00:53:41"), &["192.0.2.40"])],
            at("11:00"),
        )
        .await;
    world.reconcile(at("11:01")).await;
    let conflicts = world.open(IntentProposalKind::Conflict).await;
    let shared = conflicts
        .iter()
        .find(|proposal| proposal.rule == rule::CONFLICT_SHARED_ADDRESS)
        .expect("shared");
    assert_eq!(shared.severity, ProposalSeverity::Critical);
    assert_eq!(shared.commands, Vec::<IpamCommand>::new());
    assert_eq!(shared.evidence.len(), 2);
    let taken = conflicts
        .iter()
        .find(|proposal| proposal.rule == rule::CONFLICT_ADDRESS_TAKEN)
        .expect("taken");
    assert_eq!(taken.subject.mac, Some(mac("00:00:5e:00:53:43")));
    assert!(taken.summary.contains("camera"), "{}", taken.summary);
}

#[tokio::test]
async fn addresses_outside_known_networks_suggest_a_prefix_and_then_a_host() {
    let world = lab().await;
    world
        .poll(
            vec![
                vm("a", Some("a"), Some("00:00:5e:00:53:51"), &["198.51.100.7"]),
                vm("b", Some("b"), Some("00:00:5e:00:53:52"), &["198.51.100.9"]),
                vm("c", Some("c"), None, &["127.0.0.1", "fe80::1"]),
            ],
            at("12:00"),
        )
        .await;
    world.reconcile(at("12:01")).await;
    let outside = world.open(IntentProposalKind::OutsidePrefixes).await;
    assert_eq!(outside.len(), 1, "{outside:#?}");
    let proposal = &outside[0];
    assert_eq!(
        proposal
            .subject
            .cidr
            .map(|cidr| cidr.to_string())
            .as_deref(),
        Some("198.51.100.0/24")
    );
    assert_eq!(proposal.params["count"], "2");
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new(),
        "the network first"
    );
    world.approve(proposal).await;
    world.reconcile(at("12:02")).await;
    assert_eq!(
        world.open(IntentProposalKind::OutsidePrefixes).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new()
    );
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        2
    );
}

#[tokio::test]
async fn proposals_are_superseded_when_evidence_changes_and_expire_when_it_goes() {
    let world = lab().await;
    world
        .poll(
            vec![vm(
                "1",
                Some("tv"),
                Some("00:00:5e:00:53:61"),
                &["192.0.2.61"],
            )],
            at("13:00"),
        )
        .await;
    world.reconcile(at("13:01")).await;
    let first = world
        .open(IntentProposalKind::DiscoveredHost)
        .await
        .remove(0);

    world
        .poll(
            vec![vm(
                "1",
                Some("tv"),
                Some("00:00:5e:00:53:61"),
                &["192.0.2.62"],
            )],
            at("13:05"),
        )
        .await;
    let report = world.reconcile(at("13:06")).await;
    assert_eq!((report.superseded, report.opened), (1, 1), "{report:?}");
    let all = world.proposals(None).await;
    let old = all
        .iter()
        .find(|proposal| proposal.id == first.id)
        .expect("old");
    assert_eq!(old.state, IntentProposalState::Superseded);
    let second = world
        .open(IntentProposalKind::DiscoveredHost)
        .await
        .remove(0);
    assert_eq!(old.superseded_by, Some(second.id));
    assert_eq!(
        second.subject.ip.map(|ip| ip.to_string()).as_deref(),
        Some("192.0.2.62")
    );

    // The complete poll without the device expires its fact, and the proposal with it.
    world.poll(Vec::new(), at("13:10")).await;
    let report = world.reconcile(at("13:11")).await;
    assert_eq!(report.expired, 1, "{report:?}");
    let expired = world
        .proposals(Some(IntentProposalState::Expired))
        .await
        .remove(0);
    assert_eq!(expired.id, second.id);
    assert!(expired.reason.is_some());
}

#[tokio::test]
async fn an_address_unseen_for_the_orphan_age_is_proposed_for_deprecation() {
    let world = lab().await;
    let nas = intended(
        &world,
        "nas01",
        AssignmentMode::Static,
        "00:00:5e:00:53:01",
        "192.0.2.10",
    )
    .await;
    let start = at("08:00");
    world
        .poll(
            vec![vm("nas", None, Some("00:00:5e:00:53:01"), &["192.0.2.10"])],
            start,
        )
        .await;
    let report = world.reconcile(start).await;
    assert!(
        report.sightings >= 2,
        "address and interface sightings: {report:?}"
    );
    // Gone from the source, and a week and a day later still unseen.
    world.poll(Vec::new(), at("08:30")).await;
    world.reconcile(at("08:31")).await;
    assert_eq!(
        world.open(IntentProposalKind::OrphanedIntent).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new()
    );
    world.reconcile(days_after(start, 8)).await;
    let orphans = world.open(IntentProposalKind::OrphanedIntent).await;
    assert_eq!(orphans.len(), 1, "{orphans:#?}");
    assert_eq!(orphans[0].rule, rule::ORPHANED_ADDRESS);
    assert!(orphans[0].subject.objects.contains(&nas.id.into()));
    let decision = world.approve(&orphans[0]).await;
    let view = world.service.view(decision.revision).await.expect("view");
    let address =
        query::get::<Address>(view.as_ref(), decision.results[0].id.into()).expect("address");
    assert_eq!(address.status, Status::Deprecated);
    assert_eq!(decision.results[0].kind, ObjectKind::Address);
}

#[tokio::test]
async fn an_unmanaged_host_seen_outside_known_networks_suggests_nothing() {
    let world = lab().await;
    intended(
        &world,
        "wild",
        AssignmentMode::Unmanaged,
        "00:00:5e:00:53:03",
        "192.0.2.12",
    )
    .await;
    world
        .poll(
            vec![vm(
                "wild",
                None,
                Some("00:00:5e:00:53:03"),
                &["203.0.113.12"],
            )],
            at("14:00"),
        )
        .await;
    let report = world.reconcile(at("14:01")).await;
    assert_eq!(report.opened, 0, "{report:?}");
    assert_eq!(
        world.proposals(None).await,
        Vec::<tenko_ipam::proposals::IntentProposal>::new()
    );
}

#[tokio::test]
async fn a_name_from_a_probe_names_a_discovered_host_but_is_no_sighting() {
    use tenko_store::ReadViewExt as _;
    let world = lab().await;
    let vrf = world.default_vrf().await;
    let nas = intended(
        &world,
        "nas01",
        AssignmentMode::Static,
        "00:00:5e:00:53:10",
        "192.0.2.10",
    )
    .await;
    // A name alone: not a sighting of the address, so nothing is discovered, no network is
    // suggested and the intended address gets no last sighting.
    world
        .names(
            &[
                ("192.0.2.10", "nas01.example.test"),
                ("192.0.2.77", "ghost.example.test"),
                ("203.0.113.9", "elsewhere.example.test"),
            ],
            at("09:00"),
        )
        .await;
    let report = world.reconcile(at("09:01")).await;
    assert_eq!(report.sightings, 0, "{report:?}");
    assert_eq!(report.opened, 0, "{report:?}");
    let view = world.service.view(None).await.expect("view");
    let last = view
        .get_typed(
            &tenko_ipam::observe::tables::LAST_SEEN,
            &tenko_core::ObjectRef::from(nas.id),
        )
        .expect("read");
    assert!(last.is_none(), "a name never refreshes the last sighting");
    drop(view);

    // A device seen at an address without intent takes its name from the probe.
    world
        .probe(
            vrf,
            &[("192.0.2.40", Some("00:00:5e:00:53:40"))],
            at("09:02"),
        )
        .await;
    world
        .names(&[("192.0.2.40", "printer.example.test")], at("09:02"))
        .await;
    world.reconcile(at("09:03")).await;
    let open = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(open.len(), 1, "{open:#?}");
    let IpamCommand::CreateHost(host) = &open[0].commands[0] else {
        panic!("not a host: {:?}", open[0].commands[0]);
    };
    assert_eq!(host.name.to_string(), "printer.example.test");
    assert_eq!(
        open[0].subject.name.as_deref(),
        Some("printer.example.test")
    );
}

#[tokio::test]
async fn with_probe_scopes_only_a_scanned_address_is_orphaned() {
    let world = lab().await;
    let scanned = intended(
        &world,
        "nas01",
        AssignmentMode::Static,
        "00:00:5e:00:53:01",
        "192.0.2.10",
    )
    .await;
    let unscanned = intended(
        &world,
        "nas02",
        AssignmentMode::Static,
        "00:00:5e:00:53:02",
        "192.0.2.200",
    )
    .await;
    let start = at("08:00");
    world
        .poll(
            vec![
                vm("a", None, Some("00:00:5e:00:53:01"), &["192.0.2.10"]),
                vm("b", None, Some("00:00:5e:00:53:02"), &["192.0.2.200"]),
            ],
            start,
        )
        .await;
    world.reconcile(start).await;
    world.poll(Vec::new(), at("08:30")).await;
    // A probe scans the lower half of the network only.
    let mut batch = tenko_store::WriteBatch::for_request(&tenko_core::RequestCtx::system(
        tenko_core::SystemComponent::Cluster,
    ));
    batch
        .put_typed(
            &scopes::SCOPES,
            &7,
            &scopes::ScanScope {
                prefixes: vec!["192.0.2.0/25".parse().expect("net")],
                ..scopes::ScanScope::default()
            },
        )
        .expect("scope");
    world.store.propose(batch).await.expect("write the scope");

    world.reconcile(days_after(start, 8)).await;
    let orphans = world.open(IntentProposalKind::OrphanedIntent).await;
    assert_eq!(orphans.len(), 1, "{orphans:#?}");
    assert!(orphans[0].subject.objects.contains(&scanned.id.into()));
    assert!(
        !orphans
            .iter()
            .any(|orphan| orphan.subject.objects.contains(&unscanned.id.into())),
        "an address outside every probe scope is not scanned, not gone"
    );
}
