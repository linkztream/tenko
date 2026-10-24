//! The reconciler against the networks a controller reports: a VLAN IPAM does not know, a
//! prefix whose range equals a network's subnet without the network's VLAN, approval in
//! either order, rejection, the untagged default network, and VLANs of a site.

use std::collections::{BTreeMap, BTreeSet};

mod common;
mod reconcile_support;

use common::*;
use reconcile_support::*;
use tenko_core::{
    PrefixId, SiteId, VlanId,
    ipam::{Prefix, Vlan},
};
use tenko_ipam::{
    IpamCommand,
    command::{SiteInput, VlanInput},
    proposals::{IntentProposal, IntentProposalKind, IntentProposalState, ProposalSeverity},
    query,
    reconcile::rule,
};

/// A world with the network 198.51.100.0/24 in the default VRF, optionally at `site`.
async fn lab(site: Option<SiteId>) -> (World, PrefixId) {
    let world = World::new();
    let mut input = prefix(None, "198.51.100.0/24");
    input.site = site;
    let id = input.id.expect("id");
    run(&world.service, vec![IpamCommand::CreatePrefix(input)]).await;
    (world, id)
}

fn vlan_input(vid: u16, name: &str, site: Option<SiteId>) -> VlanInput {
    VlanInput {
        id: Some(VlanId::generate()),
        vid,
        vni: None,
        name: name.to_owned(),
        site,
        status: None,
        tags: BTreeSet::default(),
        custom: BTreeMap::default(),
        description: None,
    }
}

async fn create_vlan(world: &World, vid: u16, name: &str, site: Option<SiteId>) -> VlanId {
    let input = vlan_input(vid, name, site);
    let id = input.id.expect("id");
    run(&world.service, vec![IpamCommand::CreateVlan(input)]).await;
    id
}

async fn create_site(world: &World, name: &str) -> SiteId {
    let id = SiteId::generate();
    run(
        &world.service,
        vec![IpamCommand::CreateSite(SiteInput {
            id: Some(id),
            name: name.to_owned(),
            parent: None,
            ad_site: None,
            tags: BTreeSet::default(),
            custom: BTreeMap::default(),
            description: None,
        })],
    )
    .await;
    id
}

async fn get_prefix(world: &World, id: PrefixId) -> Prefix {
    let view = world.service.view(None).await.expect("view");
    query::get::<Prefix>(view.as_ref(), id).expect("prefix")
}

async fn vlans(world: &World) -> Vec<Vlan> {
    let view = world.service.view(None).await.expect("view");
    query::list::<Vlan>(view.as_ref(), &query::ListQuery::default())
        .expect("vlans")
        .items
}

const IOT: (&str, &str, Option<u16>, Option<&str>) =
    ("net-iot", "IoT", Some(30), Some("198.51.100.1/24"));

#[tokio::test]
async fn a_tagged_network_suggests_its_vlan_and_the_link_and_approval_settles_both() {
    let (world, prefix_id) = lab(None).await;
    world.networks(&[IOT], at("08:00")).await;
    let report = world.reconcile(at("08:01")).await;
    assert_eq!(report.opened, 2, "{report:?}");

    let discovered = world.open(IntentProposalKind::VlanDiscovered).await;
    assert_eq!(discovered.len(), 1);
    let vlan = &discovered[0];
    assert_eq!(vlan.rule, rule::VLAN_DISCOVERED);
    assert_eq!(vlan.key, "vlan_discovered/global/30");
    assert_eq!(vlan.severity, ProposalSeverity::Info);
    assert_eq!(vlan.subject.prefix, Some(prefix_id));
    assert_eq!(vlan.params["vid"], "30");
    assert_eq!(vlan.params["name"], "IoT");
    assert_eq!(vlan.params["cidr"], "198.51.100.0/24");
    assert_eq!(vlan.evidence.len(), 1);
    assert_eq!(vlan.evidence[0].subject_key, "network:net-iot");
    assert!(matches!(
        &vlan.commands[..],
        [IpamCommand::CreateVlan(input)] if input.vid == 30 && input.name == "IoT" && input.site.is_none()
    ));

    let mismatch = world.open(IntentProposalKind::PrefixVlanMismatch).await;
    assert_eq!(mismatch.len(), 1);
    let link = &mismatch[0];
    assert_eq!(link.rule, rule::PREFIX_VLAN_UNSET);
    assert_eq!(link.key, format!("prefix_vlan_mismatch/{prefix_id}"));
    assert_eq!(link.subject.prefix, Some(prefix_id));
    // The link proposal creates the same VLAN when approved first.
    let IpamCommand::CreateVlan(planned) = &vlan.commands[0] else {
        panic!("a VLAN");
    };
    assert!(matches!(
        &link.commands[..],
        [IpamCommand::CreateVlan(same), IpamCommand::UpdatePrefix(update)]
            if same.id == planned.id && update.id == prefix_id && update.patch.vlan == Some(planned.id)
    ));

    // The VLAN first, then the link: the link does not create the VLAN a second time.
    let created = world.approve(vlan).await;
    assert_eq!(created.proposal.state, IntentProposalState::Accepted);
    let linked = world.approve(link).await;
    assert_eq!(linked.proposal.state, IntentProposalState::Accepted);
    let all = vlans(&world).await;
    assert_eq!(all.len(), 1);
    assert_eq!(
        (all[0].vid, all[0].name.as_str(), all[0].site),
        (30, "IoT", None)
    );
    assert!(
        all[0]
            .meta
            .tags
            .iter()
            .any(|tag| tag.as_str() == "discovered")
    );
    assert_eq!(get_prefix(&world, prefix_id).await.vlan, Some(all[0].id));

    // Intent caught up: a second run opens nothing and nothing stays open.
    world.networks(&[IOT], at("08:20")).await;
    let after = world.reconcile(at("08:21")).await;
    assert_eq!((after.opened, after.expired), (0, 0), "{after:?}");
    assert_eq!(
        world.proposals(Some(IntentProposalState::Open)).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn approving_the_link_alone_creates_the_vlan_and_the_vlan_proposal_expires() {
    let (world, prefix_id) = lab(None).await;
    world.networks(&[IOT], at("08:00")).await;
    world.reconcile(at("08:01")).await;
    let link = world.open(IntentProposalKind::PrefixVlanMismatch).await;
    let decision = world.approve(&link[0]).await;
    assert_eq!(decision.results.len(), 2, "{decision:?}");
    let all = vlans(&world).await;
    assert_eq!(all.len(), 1);
    assert_eq!(get_prefix(&world, prefix_id).await.vlan, Some(all[0].id));

    let after = world.reconcile(at("08:02")).await;
    assert_eq!((after.opened, after.expired), (0, 1), "{after:?}");
    assert_eq!(
        world.proposals(Some(IntentProposalState::Open)).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn a_vlan_that_exists_already_yields_only_the_link() {
    let (world, prefix_id) = lab(None).await;
    let existing = create_vlan(&world, 30, "Things", None).await;
    world.networks(&[IOT], at("08:00")).await;
    let report = world.reconcile(at("08:01")).await;
    assert_eq!(report.opened, 1, "{report:?}");
    assert_eq!(
        world.open(IntentProposalKind::VlanDiscovered).await,
        Vec::<IntentProposal>::new()
    );
    let link = world.open(IntentProposalKind::PrefixVlanMismatch).await;
    assert!(matches!(
        &link[0].commands[..],
        [IpamCommand::UpdatePrefix(update)] if update.patch.vlan == Some(Some(existing))
    ));
    world.approve(&link[0]).await;
    assert_eq!(get_prefix(&world, prefix_id).await.vlan, Some(existing));
    assert_eq!(vlans(&world).await.len(), 1);
}

#[tokio::test]
async fn a_prefix_on_another_vlan_gets_a_warning() {
    let (world, prefix_id) = lab(None).await;
    let other = create_vlan(&world, 20, "Home", None).await;
    let thirty = create_vlan(&world, 30, "IoT", None).await;
    run(
        &world.service,
        vec![IpamCommand::UpdatePrefix(
            tenko_ipam::command::UpdatePrefix {
                id: prefix_id,
                expected: None,
                patch: tenko_ipam::command::PrefixPatch {
                    vlan: Some(Some(other)),
                    ..tenko_ipam::command::PrefixPatch::default()
                },
            },
        )],
    )
    .await;
    world.networks(&[IOT], at("08:00")).await;
    world.reconcile(at("08:01")).await;
    let link = world.open(IntentProposalKind::PrefixVlanMismatch).await;
    assert_eq!(link.len(), 1);
    assert_eq!(link[0].rule, rule::PREFIX_VLAN_DIFFERS);
    assert_eq!(link[0].severity, ProposalSeverity::Warning);
    assert_eq!(link[0].params["current"], "20");
    world.approve(&link[0]).await;
    assert_eq!(get_prefix(&world, prefix_id).await.vlan, Some(thirty));
}

#[tokio::test]
async fn the_untagged_default_network_and_a_network_without_a_prefix_suggest_no_link() {
    let (world, _) = lab(None).await;
    world
        .networks(
            &[
                ("net-default", "Default", None, Some("198.51.100.1/24")),
                ("net-cams", "Cameras", Some(40), None),
            ],
            at("08:00"),
        )
        .await;
    let report = world.reconcile(at("08:01")).await;
    // Only the VLAN of the subnet-less network, global.
    assert_eq!(report.opened, 1, "{report:?}");
    let discovered = world.open(IntentProposalKind::VlanDiscovered).await;
    assert_eq!(discovered[0].key, "vlan_discovered/global/40");
    assert_eq!(discovered[0].subject.prefix, None);
    assert_eq!(
        world.open(IntentProposalKind::PrefixVlanMismatch).await,
        Vec::<IntentProposal>::new()
    );
}

#[tokio::test]
async fn a_rejected_vlan_stays_closed_until_its_evidence_changes() {
    let (world, _) = lab(None).await;
    world.networks(&[IOT], at("08:00")).await;
    world.reconcile(at("08:01")).await;
    let vlan = world.open(IntentProposalKind::VlanDiscovered).await;
    world.reject(&vlan[0]).await;
    let again = world.reconcile(at("08:02")).await;
    assert_eq!((again.opened, again.suppressed), (0, 1), "{again:?}");
    assert_eq!(
        world.open(IntentProposalKind::VlanDiscovered).await,
        Vec::<IntentProposal>::new()
    );
    // The link proposal is a subject of its own and stays open.
    assert_eq!(
        world
            .open(IntentProposalKind::PrefixVlanMismatch)
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn the_vlan_of_a_site_prefix_belongs_to_the_site_and_a_global_vlan_counts() {
    let world = World::new();
    let site = create_site(&world, "lab").await;
    let mut input = prefix(None, "198.51.100.0/24");
    input.site = Some(site);
    run(&world.service, vec![IpamCommand::CreatePrefix(input)]).await;
    world.networks(&[IOT], at("08:00")).await;
    world.reconcile(at("08:01")).await;
    let discovered = world.open(IntentProposalKind::VlanDiscovered).await;
    assert_eq!(discovered[0].key, format!("vlan_discovered/{site}/30"));
    assert!(matches!(
        &discovered[0].commands[..],
        [IpamCommand::CreateVlan(input)] if input.site == Some(site)
    ));

    // A global VLAN 30 serves the site too: the VLAN proposal expires, the link names it.
    let global = create_vlan(&world, 30, "IoT", None).await;
    let after = world.reconcile(at("08:02")).await;
    assert_eq!(after.expired, 1, "{after:?}");
    assert_eq!(
        world.open(IntentProposalKind::VlanDiscovered).await,
        Vec::<IntentProposal>::new()
    );
    let link = world.open(IntentProposalKind::PrefixVlanMismatch).await;
    assert!(matches!(
        &link[0].commands[..],
        [IpamCommand::UpdatePrefix(update)] if update.patch.vlan == Some(Some(global))
    ));
}
