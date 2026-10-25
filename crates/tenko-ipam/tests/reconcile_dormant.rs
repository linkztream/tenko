//! Dormant claims and "keep both": a stopped guest's configured address is no sighting, so
//! it raises no address conflict against a running guest; a decommissioned host's facts
//! raise nothing; and a person can keep an address conflict as intended, which stays quiet
//! until another device joins the address.

mod common;
mod reconcile_support;

use std::collections::BTreeSet;

use common::*;
use reconcile_support::*;
use tenko_core::{
    ObjectRef,
    audit::AuditRecord,
    ipam::{AssignmentMode, Host},
    observe::{ObservedHost, PowerState},
};
use tenko_ipam::{
    IpamCommand,
    command::DecommissionHost,
    proposals::{
        self, IntentProposal, IntentProposalKind, IntentProposalState, actions, codes,
        model::REJECTIONS,
    },
    query,
    reconcile::{
        rule,
        view::{ReconcileKind, ReconcileQuery, lease_conflicts, reconcile},
    },
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, tables::AUDIT};

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
async fn intended(world: &World, name: &str, mac_text: &str, ip: &str) -> Host {
    let (input, interface) = host(name, AssignmentMode::Reserved, Some(mac_text));
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

/// The MAC address `00:00:5e:00:53:<low>`.
fn mac_of(low: u8) -> String {
    format!("00:00:5e:00:53:{low:02x}")
}

/// An inventory guest with the MAC `00:00:5e:00:53:<low>` at `ip`, in a power state.
fn guest(id: &str, low: u8, ip: &str, power: PowerState) -> ObservedHost {
    let mut host = vm(id, Some(id), Some(&mac_of(low)), &[ip]);
    host.power = Some(power);
    host
}

/// The open conflicts of one rule.
async fn conflicts(world: &World, rule: &str) -> Vec<IntentProposal> {
    world
        .open(IntentProposalKind::Conflict)
        .await
        .into_iter()
        .filter(|proposal| proposal.rule == rule)
        .collect()
}

/// The MAC addresses a proposal's evidence names.
fn evidence_macs(proposal: &IntentProposal) -> BTreeSet<String> {
    proposal
        .evidence
        .iter()
        .filter_map(|evidence| evidence.mac.map(|mac| mac.to_string()))
        .collect()
}

/// The ids of a `hosts` parameter.
fn host_ids(text: &str) -> Vec<String> {
    text.split(", ")
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn a_stopped_and_a_running_guest_on_one_address_raise_no_conflict() {
    let world = lab().await;
    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Running),
                guest("102", 0x42, "192.0.2.40", PowerState::Stopped),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    assert_eq!(
        world.open(IntentProposalKind::Conflict).await,
        Vec::<IntentProposal>::new()
    );

    // The discovered host is the running device; the stopped guest's claim is dormant.
    let discovered = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(discovered.len(), 1, "{discovered:#?}");
    assert_eq!(discovered[0].subject.mac, Some(mac(&mac_of(0x41))));
    assert_eq!(
        discovered[0].subject.ip.map(|ip| ip.to_string()).as_deref(),
        Some("192.0.2.40")
    );
    assert_eq!(
        evidence_macs(&discovered[0]),
        BTreeSet::from([mac_of(0x41)]),
        "the stopped guest is no evidence"
    );
    assert!(
        matches!(&discovered[0].commands[1], IpamCommand::CreateAddress(created) if created.ip.to_string() == "192.0.2.40")
    );
    let all = world.proposals(None).await;
    assert!(
        all.iter()
            .all(|proposal| proposal.subject.mac != Some(mac(&mac_of(0x42)))),
        "nothing is proposed for the stopped guest: {all:#?}"
    );
}

#[tokio::test]
async fn two_running_guests_on_one_address_are_a_shared_address_conflict() {
    let world = lab().await;
    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Running),
                guest("102", 0x42, "192.0.2.40", PowerState::Running),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let shared = conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await;
    assert_eq!(shared.len(), 1, "{shared:#?}");
    let conflict = &shared[0];
    assert_eq!(
        evidence_macs(conflict),
        BTreeSet::from([mac_of(0x41), mac_of(0x42)])
    );
    assert_eq!(conflict.params["ip"], "192.0.2.40");
    assert_eq!(conflict.params["count"], "2");
    assert_eq!(
        conflict.params["hosts"], "",
        "neither device is a host of intent"
    );
}

#[tokio::test]
async fn a_shared_address_conflict_names_the_hosts_of_intent() {
    let world = lab().await;
    let first = intended(&world, "first", &mac_of(0x41), "192.0.2.21").await;
    let second = intended(&world, "second", &mac_of(0x42), "192.0.2.22").await;
    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Running),
                guest("102", 0x42, "192.0.2.40", PowerState::Running),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let shared = conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await;
    assert_eq!(shared.len(), 1, "{shared:#?}");
    let hosts = host_ids(&shared[0].params["hosts"]);
    assert_eq!(hosts.len(), 2, "{hosts:?}");
    assert!(
        shared[0].params["hosts"].contains(", "),
        "comma and space between the ids"
    );
    assert_eq!(
        hosts.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([first.id.to_string(), second.id.to_string()])
    );
}

#[tokio::test]
async fn two_stopped_guests_on_one_address_raise_no_conflict() {
    let world = lab().await;
    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Stopped),
                guest("102", 0x42, "192.0.2.40", PowerState::Stopped),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    assert_eq!(
        world.open(IntentProposalKind::Conflict).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn a_running_guest_with_no_power_state_counts_as_live() {
    let world = lab().await;
    // A source that does not report the power state: its claims are live.
    world
        .poll(
            vec![
                vm("101", None, Some(&mac_of(0x41)), &["192.0.2.40"]),
                guest("102", 0x42, "192.0.2.40", PowerState::Running),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    assert_eq!(
        conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await.len(),
        1
    );
}

#[tokio::test]
async fn a_stopped_guest_does_not_take_an_address_intended_for_another_device() {
    let world = lab().await;
    intended(&world, "camera", &mac_of(0x30), "192.0.2.30").await;
    world
        .poll(
            vec![guest("201", 0x43, "192.0.2.30", PowerState::Stopped)],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    assert_eq!(
        conflicts(&world, rule::CONFLICT_ADDRESS_TAKEN).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn a_running_guest_on_an_address_intended_for_another_device_is_a_taken_address() {
    let world = lab().await;
    let camera = intended(&world, "camera", &mac_of(0x30), "192.0.2.30").await;
    let intruder = intended(&world, "intruder", &mac_of(0x43), "192.0.2.43").await;
    world
        .poll(
            vec![guest("201", 0x43, "192.0.2.30", PowerState::Running)],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let taken = conflicts(&world, rule::CONFLICT_ADDRESS_TAKEN).await;
    assert_eq!(taken.len(), 1, "{taken:#?}");
    let conflict = &taken[0];
    assert_eq!(conflict.params["host"], "camera");
    assert_eq!(conflict.params["macs"], mac_of(0x43));
    assert_eq!(
        host_ids(&conflict.params["hosts"]),
        [camera.id.to_string(), intruder.id.to_string()],
        "the intended host first"
    );
    assert_eq!(
        conflict.params["dormant_hosts"], "",
        "nobody's claim is dormant"
    );
}

#[tokio::test]
async fn a_taken_address_names_the_intended_host_whose_own_claim_is_only_dormant() {
    let world = lab().await;
    let camera = intended(&world, "camera", &mac_of(0x30), "192.0.2.30").await;
    // The intended guest is stopped, another device runs on its address.
    world
        .poll(
            vec![
                guest("200", 0x30, "192.0.2.30", PowerState::Stopped),
                guest("201", 0x43, "192.0.2.30", PowerState::Running),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let taken = conflicts(&world, rule::CONFLICT_ADDRESS_TAKEN).await;
    assert_eq!(taken.len(), 1, "{taken:#?}");
    let conflict = &taken[0];
    assert_eq!(conflict.params["dormant_hosts"], camera.id.to_string());
    assert_eq!(conflict.params["hosts"], camera.id.to_string());
    assert_eq!(conflict.params["macs"], mac_of(0x43));
    assert_eq!(
        evidence_macs(conflict),
        BTreeSet::from([mac_of(0x43)]),
        "only the device that took the address is evidence"
    );
    // Neither side is a shared-address conflict: only one of them runs.
    assert_eq!(
        conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn a_taken_address_does_not_name_the_intended_host_when_its_guest_runs_too() {
    let world = lab().await;
    intended(&world, "camera", &mac_of(0x30), "192.0.2.30").await;
    world
        .poll(
            vec![
                guest("200", 0x30, "192.0.2.30", PowerState::Running),
                guest("201", 0x43, "192.0.2.30", PowerState::Running),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let taken = conflicts(&world, rule::CONFLICT_ADDRESS_TAKEN).await;
    assert_eq!(taken.len(), 1, "{taken:#?}");
    assert_eq!(taken[0].params["dormant_hosts"], "");
    assert_eq!(
        conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await.len(),
        1,
        "both devices run on one address"
    );
}

#[tokio::test]
async fn the_facts_of_a_decommissioned_host_raise_nothing() {
    let world = lab().await;
    let old = intended(&world, "old", &mac_of(0x50), "192.0.2.50").await;
    // The old guest and its replacement run on the address of the old one.
    let guests = || {
        vec![
            guest("100", 0x50, "192.0.2.60", PowerState::Running),
            guest("101", 0x51, "192.0.2.60", PowerState::Running),
        ]
    };
    world.poll(guests(), at("08:00")).await;
    world.reconcile(at("08:01")).await;
    assert_eq!(
        conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await.len(),
        1,
        "the control: an active host's MAC takes part in the conflict"
    );
    assert_eq!(
        world.open(IntentProposalKind::AddressMismatch).await.len(),
        1,
        "the control: an active host seen elsewhere is a mismatch"
    );

    run(
        &world.service,
        vec![IpamCommand::DecommissionHost(DecommissionHost {
            host: old.id,
            reason: Some("replaced".to_owned()),
            keep_dns: false,
            expected: None,
        })],
    )
    .await;
    world.poll(guests(), at("08:02")).await;
    let report = world.reconcile(at("08:03")).await;
    assert!(report.expired >= 2, "{report:?}");
    assert_eq!(
        world.open(IntentProposalKind::Conflict).await,
        Vec::<IntentProposal>::new()
    );
    assert_eq!(
        world.open(IntentProposalKind::AddressMismatch).await,
        Vec::<IntentProposal>::new()
    );
    let open = world.proposals(Some(IntentProposalState::Open)).await;
    assert!(
        open.iter()
            .all(|proposal| proposal.subject.mac != Some(mac(&mac_of(0x50)))
                && !proposal.subject.objects.contains(&ObjectRef::from(old.id))),
        "nothing about the decommissioned host: {open:#?}"
    );
    // The replacement is still a device the reconciler does not know.
    let discovered = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(discovered.len(), 1, "{discovered:#?}");
    assert_eq!(discovered[0].subject.mac, Some(mac(&mac_of(0x51))));
}

#[tokio::test]
async fn the_reconciliation_view_shows_no_conflict_for_a_stopped_and_a_running_guest() {
    let world = lab().await;
    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Running),
                guest("102", 0x42, "192.0.2.40", PowerState::Stopped),
                guest("103", 0x43, "192.0.2.41", PowerState::Running),
                guest("104", 0x44, "192.0.2.41", PowerState::Running),
            ],
            at("08:00"),
        )
        .await;
    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    let rows = lease_conflicts(view.as_ref(), at("08:01")).expect("conflicts");
    let addresses: Vec<String> = rows.iter().map(|row| row.address.to_string()).collect();
    assert_eq!(
        addresses,
        ["192.0.2.41"],
        "the running pair conflicts, the stopped and running pair does not"
    );
    assert_eq!(rows[0].kind, ReconcileKind::Conflict);

    let page = reconcile(view.as_ref(), &ReconcileQuery::default(), at("08:01")).expect("page");
    let conflicting: Vec<String> = page
        .items
        .iter()
        .filter(|row| row.kind == ReconcileKind::Conflict)
        .map(|row| row.address.to_string())
        .collect();
    assert_eq!(conflicting, ["192.0.2.41"]);
    // The stopped guest's address is no sighting: the running guest alone is a rogue there.
    let rogue = page
        .items
        .iter()
        .find(|row| row.address.to_string() == "192.0.2.40")
        .expect("a row at the shared address");
    assert_eq!(rogue.kind, ReconcileKind::Rogue);
    assert_eq!(
        rogue.scan.as_ref().map(|scan| scan.macs.clone()),
        Some(vec![mac(&mac_of(0x41))])
    );
}

// ----- keep both ------------------------------------------------------------------------

/// A world with two running guests on 192.0.2.40 and the shared-address conflict open.
async fn shared_conflict() -> (World, IntentProposal) {
    let world = lab().await;
    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Running),
                guest("102", 0x42, "192.0.2.40", PowerState::Running),
            ],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let mut open = conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await;
    assert_eq!(open.len(), 1, "{open:#?}");
    let proposal = open.remove(0);
    (world, proposal)
}

/// Keeps a conflict as a person.
async fn keep(world: &World, proposal: &IntentProposal) -> proposals::Decision {
    proposals::keep(
        &world.service,
        proposal.id,
        Some("fallback guest".to_owned()),
        &person(),
        None,
    )
    .await
    .expect("keep")
}

/// A probe sighting of `low` at the shared address: a second source for a device.
async fn second_source(world: &World, low: u8, when: &str) {
    let vrf = world.default_vrf().await;
    world
        .probe(vrf, &[("192.0.2.40", Some(&mac_of(low)))], at(when))
        .await;
}

#[tokio::test]
async fn a_kept_conflict_is_closed_as_rejected_and_remembered_with_its_devices() {
    let (world, proposal) = shared_conflict().await;
    let decision = keep(&world, &proposal).await;
    assert_eq!(decision.proposal.state, IntentProposalState::Rejected);
    assert!(!decision.dry_run);
    assert!(decision.revision.is_some() && decision.job_id.is_some());
    assert_eq!(decision.proposal.reason.as_deref(), Some("fallback guest"));
    assert_eq!(decision.proposal.id, proposal.id);

    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    let (rejection, _) = view
        .get_typed(&REJECTIONS, &proposal.key)
        .expect("read")
        .expect("the rejection row");
    assert_eq!(rejection.proposal, proposal.id);
    assert_eq!(rejection.fingerprint, proposal.fingerprint);
    let kept = rejection.kept.expect("the kept devices");
    assert_eq!(
        kept.macs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        [mac_of(0x41), mac_of(0x42)]
    );

    // Audited as a keep, not as a rejection.
    let records: Vec<AuditRecord> = view
        .scan_typed(&AUDIT, KeyRange::all(), usize::MAX, false)
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect();
    let kept_records: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| record.draft.action.as_str() == actions::KEEP)
        .collect();
    assert_eq!(kept_records.len(), 1);
    assert_eq!(kept_records[0].draft.action.as_str(), "ipam.proposal.keep");
    assert_eq!(
        kept_records[0].draft.objects,
        [ObjectRef::from(proposal.id)]
    );
    assert!(
        records
            .iter()
            .all(|record| record.draft.action.as_str() != actions::REJECT)
    );
}

#[tokio::test]
async fn a_kept_conflict_stays_quiet_when_the_same_devices_keep_sharing_the_address() {
    let (world, proposal) = shared_conflict().await;
    keep(&world, &proposal).await;

    let report = world.reconcile(at("08:02")).await;
    assert_eq!((report.opened, report.suppressed), (0, 1), "{report:?}");
    assert_eq!(
        world.open(IntentProposalKind::Conflict).await,
        Vec::<IntentProposal>::new()
    );

    // Another source starts to report the same two devices: the fingerprint changes, the
    // devices do not.
    second_source(&world, 0x41, "08:03").await;
    let report = world.reconcile(at("08:04")).await;
    assert_eq!((report.opened, report.suppressed), (0, 1), "{report:?}");
    assert_eq!(
        world.open(IntentProposalKind::Conflict).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn a_plainly_rejected_conflict_opens_again_when_another_source_reports_the_devices() {
    let (world, proposal) = shared_conflict().await;
    world.reject(&proposal).await;
    let report = world.reconcile(at("08:02")).await;
    assert_eq!((report.opened, report.suppressed), (0, 1), "{report:?}");

    second_source(&world, 0x41, "08:03").await;
    let report = world.reconcile(at("08:04")).await;
    assert_eq!((report.opened, report.suppressed), (1, 0), "{report:?}");
    let reopened = conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await;
    assert_eq!(reopened.len(), 1);
    assert_ne!(reopened[0].id, proposal.id);
    assert_ne!(reopened[0].fingerprint, proposal.fingerprint);
}

#[tokio::test]
async fn a_third_device_on_a_kept_address_opens_the_conflict_again_and_forgets_the_exception() {
    let (world, proposal) = shared_conflict().await;
    keep(&world, &proposal).await;
    world.reconcile(at("08:02")).await;

    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Running),
                guest("102", 0x42, "192.0.2.40", PowerState::Running),
                guest("103", 0x43, "192.0.2.40", PowerState::Running),
            ],
            at("08:03"),
        )
        .await;
    let report = world.reconcile(at("08:04")).await;
    assert_eq!((report.opened, report.suppressed), (1, 0), "{report:?}");
    let reopened = conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await;
    assert_eq!(reopened.len(), 1, "{reopened:#?}");
    assert_eq!(reopened[0].params["count"], "3");
    assert_ne!(reopened[0].id, proposal.id);

    let view = world
        .store
        .read(ReadConsistency::Linearizable)
        .await
        .expect("view");
    assert!(
        view.get_typed(&REJECTIONS, &proposal.key)
            .expect("read")
            .is_none(),
        "the exception is forgotten"
    );
}

#[tokio::test]
async fn a_kept_conflict_with_a_stopped_third_device_stays_quiet() {
    let (world, proposal) = shared_conflict().await;
    keep(&world, &proposal).await;
    // A stopped fallback guest on the address is a dormant claim: not evidence at all.
    world
        .poll(
            vec![
                guest("101", 0x41, "192.0.2.40", PowerState::Running),
                guest("102", 0x42, "192.0.2.40", PowerState::Running),
                guest("103", 0x43, "192.0.2.40", PowerState::Stopped),
            ],
            at("08:03"),
        )
        .await;
    let report = world.reconcile(at("08:04")).await;
    assert_eq!((report.opened, report.suppressed), (0, 1), "{report:?}");
}

#[tokio::test]
async fn a_taken_address_conflict_can_be_kept_too() {
    let world = lab().await;
    intended(&world, "camera", &mac_of(0x30), "192.0.2.30").await;
    world
        .poll(
            vec![guest("201", 0x43, "192.0.2.30", PowerState::Running)],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let mut taken = conflicts(&world, rule::CONFLICT_ADDRESS_TAKEN).await;
    assert_eq!(taken.len(), 1);
    let proposal = taken.remove(0);
    let decision = keep(&world, &proposal).await;
    assert_eq!(decision.proposal.state, IntentProposalState::Rejected);

    let report = world.reconcile(at("08:02")).await;
    assert_eq!(report.suppressed, 1, "{report:?}");
    assert_eq!(
        conflicts(&world, rule::CONFLICT_ADDRESS_TAKEN).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn only_an_address_conflict_can_be_kept() {
    let world = lab().await;
    world
        .poll(
            vec![guest("101", 0x41, "192.0.2.40", PowerState::Running)],
            at("08:00"),
        )
        .await;
    world.reconcile(at("08:01")).await;
    let mut discovered = world.open(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(discovered.len(), 1);
    let proposal = discovered.remove(0);

    let error = proposals::keep(&world.service, proposal.id, None, &person(), None)
        .await
        .expect_err("a discovered host cannot be kept");
    assert_eq!(error.code_str(), codes::NOT_KEEPABLE);
    assert_eq!(error.code_str(), "ipam.proposal.not_keepable");
    assert_eq!(status_of(&error), 409);
    assert!(!proposals::keep::keepable(&proposal));
    assert_eq!(
        world.open(IntentProposalKind::DiscoveredHost).await.len(),
        1,
        "the proposal stays open"
    );
}

#[tokio::test]
async fn a_conflict_that_is_not_open_cannot_be_kept() {
    let (world, proposal) = shared_conflict().await;
    keep(&world, &proposal).await;
    let error = proposals::keep(&world.service, proposal.id, None, &person(), None)
        .await
        .expect_err("already closed");
    assert_eq!(error.code_str(), codes::NOT_OPEN);
    assert_eq!(status_of(&error), 409);

    let unknown = proposals::keep(
        &world.service,
        tenko_core::ProposalId::generate(),
        None,
        &person(),
        None,
    )
    .await
    .expect_err("unknown");
    assert_eq!(unknown.code_str(), codes::NOT_FOUND);
    assert_eq!(status_of(&unknown), 404);
}

#[tokio::test]
async fn the_reason_of_a_kept_conflict_is_bounded() {
    let (world, proposal) = shared_conflict().await;
    let error = proposals::keep(
        &world.service,
        proposal.id,
        Some("x".repeat(1_025)),
        &person(),
        None,
    )
    .await
    .expect_err("too long");
    assert_eq!(error.code_str(), "ipam.validation");
    assert_eq!(status_of(&error), 400);
    assert_eq!(
        conflicts(&world, rule::CONFLICT_SHARED_ADDRESS).await.len(),
        1,
        "still open"
    );
}
