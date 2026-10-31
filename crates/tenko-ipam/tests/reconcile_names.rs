//! The reconciler and the names of devices: a placeholder name never names a host or
//! conflicts with a real one, the name authority decides between real names (by default,
//! globally and per site), the operator's choice on approval with what it remembers, the
//! one-time cleanup of hosts that carry a placeholder, and the hosts no rule touches.
//! Requirements: IPAM-13, IPAM-15, IPAM-16; the UniFi placeholder pattern CONN-05.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

mod common;
mod reconcile_support;

use common::*;
use reconcile_support::*;
use serde::{Deserialize, Serialize};
use tenko_core::{
    ConnectorId, ObservationId, SiteId, Timestamp,
    ipam::{AssignmentMode, Host},
    observe::{Observation, ObservationSource, Observed, ObservedHost},
    table::TableDef,
};
use tenko_ipam::{
    IpamCommand, PlanOptions,
    command::{DecommissionHost, HostPatch, SiteInput, UpdateHost},
    observe::IngestBatch,
    proposals::{
        self, ApproveRequest, IntentProposal, IntentProposalKind, IntentProposalState, Remember,
    },
    reconcile::names::{self, NameSource, rule},
};
use tenko_store::{ReadConsistency, WriteBatch};

const MAC: &str = "00:00:5e:00:53:0a";
const IP: &str = "192.0.2.10";

/// The one field of a connector instance the reconciler reads.
#[derive(Serialize, Deserialize)]
struct Instance {
    plugin: String,
}

const INSTANCES: TableDef<ConnectorId, Instance> = TableDef::new("connect.instances");

/// A world with the network 192.0.2.0/24 (at `site`, if any), a Proxmox VE connector and a
/// UniFi connector.
struct Lab {
    world: World,
    proxmox: ConnectorId,
    unifi: ConnectorId,
}

/// The lab, its network at a new site `site` when one is named.
async fn lab_at(site: Option<&str>) -> (Lab, Option<SiteId>) {
    let world = World::new();
    let site = match site {
        Some(name) => Some(create_site(&world, name).await),
        None => None,
    };
    let mut network = prefix(None, "192.0.2.0/24");
    network.site = site;
    run(&world.service, vec![IpamCommand::CreatePrefix(network)]).await;
    let proxmox = ConnectorId::generate();
    let unifi = ConnectorId::generate();
    let mut batch = WriteBatch::for_request(&person());
    for (id, plugin) in [(proxmox, "proxmox"), (unifi, "unifi")] {
        batch
            .put_typed(
                &INSTANCES,
                &id,
                &Instance {
                    plugin: plugin.to_owned(),
                },
            )
            .expect("instance");
    }
    world.store.propose(batch).await.expect("instances");
    (
        Lab {
            world,
            proxmox,
            unifi,
        },
        site,
    )
}

async fn lab() -> Lab {
    lab_at(None).await.0
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

/// A device as an inventory reports it: MAC, address and a name, marked a placeholder or
/// not.
fn device(id: &str, name: &str, placeholder: bool) -> ObservedHost {
    ObservedHost {
        name_placeholder: placeholder,
        ..vm(id, Some(name), Some(MAC), &[IP])
    }
}

impl Lab {
    /// One complete inventory poll of `connector` at `when`.
    async fn poll(&self, connector: ConnectorId, hosts: Vec<ObservedHost>, when: Timestamp) {
        let source = ObservationSource::Inventory { connector };
        let observations = hosts
            .into_iter()
            .map(|host| Observation {
                id: ObservationId::generate(),
                source: source.clone(),
                subject: Observed::Host(host),
                observed_at: when,
                received_at: when,
                expires_at: when.checked_add(Duration::from_secs(900)),
            })
            .collect();
        self.world
            .reconciler
            .ingest(IngestBatch {
                source,
                observations,
                complete: true,
                received_at: when,
            })
            .await
            .expect("ingest");
    }

    /// Proxmox VE names the device `name`.
    async fn proxmox(&self, name: &str, when: Timestamp) {
        self.poll(self.proxmox, vec![device("qemu/101", name, false)], when)
            .await;
    }

    /// UniFi names the device `name` (`placeholder` as the connector marks it).
    async fn unifi(&self, name: &str, placeholder: bool, when: Timestamp) {
        self.poll(
            self.unifi,
            vec![device(&format!("client:{MAC}"), name, placeholder)],
            when,
        )
        .await;
    }

    async fn reconcile(&self, when: Timestamp) {
        self.world.reconcile(when).await;
    }

    async fn open(&self, kind: IntentProposalKind) -> Vec<IntentProposal> {
        self.world.open(kind).await
    }

    async fn assert_none(&self, kind: IntentProposalKind) {
        assert_eq!(self.open(kind).await, Vec::<IntentProposal>::new());
    }

    async fn only(&self, kind: IntentProposalKind) -> IntentProposal {
        let open = self.open(kind).await;
        assert_eq!(open.len(), 1, "{open:#?}");
        open.into_iter().next().expect("one")
    }

    async fn approve(&self, proposal: &IntentProposal, request: ApproveRequest) {
        proposals::approve_with(
            &self.world.service,
            proposal.id,
            &person(),
            &PlanOptions::default(),
            false,
            None,
            &request,
        )
        .await
        .expect("approve");
    }

    async fn hosts(&self) -> Vec<Host> {
        all_of::<Host>(&self.world.service).await
    }

    async fn authority(&self) -> names::NameAuthorityView {
        let view = self
            .world
            .store
            .read(ReadConsistency::Linearizable)
            .await
            .expect("view");
        names::view_of(view.as_ref()).expect("authority")
    }

    /// An existing host `name` with the device's MAC address and address.
    async fn intended(&self, name: &str, mode: AssignmentMode, lock: bool) -> Host {
        let (mut input, interface) = host(name, mode, Some(MAC));
        input.lock = lock.then_some(true);
        let id = input.id.expect("id");
        let mut assigned = address(None, IP);
        assigned.interface = Some(interface);
        run(
            &self.world.service,
            vec![
                IpamCommand::CreateHost(input),
                IpamCommand::CreateAddress(assigned),
            ],
        )
        .await;
        fetch::<Host>(&self.world.service, id).await
    }
}

fn host_name_of(proposal: &IntentProposal) -> String {
    match &proposal.commands[0] {
        IpamCommand::CreateHost(input) => input.name.to_string(),
        IpamCommand::UpdateHost(update) => update.patch.name.as_ref().expect("name").to_string(),
        other => panic!("not a naming command: {other:?}"),
    }
}

fn choice_names(proposal: &IntentProposal) -> Vec<(String, bool, NameSource)> {
    proposal
        .choices
        .iter()
        .map(|choice| {
            (
                choice.name.clone(),
                choice.proposed,
                choice.sources[0].source,
            )
        })
        .collect()
}

#[tokio::test]
async fn a_placeholder_never_names_a_discovered_host() {
    let lab = lab().await;
    // UniFi's placeholder alone: the device takes Tenko's fallback, not the placeholder,
    // whether the connector marked it or the rule recognises it.
    for marked in [true, false] {
        lab.unifi("host-192-0-2-10", marked, at("09:00")).await;
        lab.reconcile(at("09:01")).await;
        let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;
        assert_eq!(host_name_of(&proposal), "host-00005e00530a");
        assert!(proposal.choices.is_empty(), "{:?}", proposal.choices);
        assert_eq!(proposal.subject.name, None);
        let evidence = &proposal.evidence[0];
        assert_eq!(evidence.name, None, "a placeholder is no name");
    }

    // The real name of Proxmox VE wins without a conflict: one name, nothing to choose.
    lab.proxmox("postgresql", at("09:02")).await;
    lab.reconcile(at("09:03")).await;
    let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(host_name_of(&proposal), "postgresql");
    assert!(proposal.choices.is_empty(), "{:?}", proposal.choices);
    assert_eq!(
        proposal.params.get("name_source").map(String::as_str),
        Some("proxmox")
    );
    lab.assert_none(IntentProposalKind::HostName).await;

    // The fact keeps the name with its mark, for the facts view.
    let view = lab.world.service.view(None).await.expect("view");
    let facts = tenko_ipam::observe::view::list_facts(
        view.as_ref(),
        Some(lab.world.service.leases()),
        &tenko_ipam::observe::view::FactQuery {
            source: Some(format!("inventory:{}", lab.unifi)),
            ..Default::default()
        },
        at("09:03"),
    )
    .expect("facts");
    let Observed::Host(unifi) = &facts.items[0].observed else {
        panic!("not a host fact");
    };
    assert_eq!(unifi.name.as_deref(), Some("host-192-0-2-10"));
    assert!(unifi.name_placeholder, "the rule marks it at ingest");
}

#[tokio::test]
async fn the_name_authority_decides_between_real_names() {
    let lab = lab().await;
    lab.proxmox("postgresql", at("09:00")).await;
    lab.unifi("DB", false, at("09:00")).await;
    lab.reconcile(at("09:01")).await;
    let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(host_name_of(&proposal), "postgresql");
    assert_eq!(
        choice_names(&proposal),
        [
            ("postgresql".to_owned(), true, NameSource::Proxmox),
            ("db".to_owned(), false, NameSource::Unifi),
        ]
    );
    assert_eq!(proposal.choices[1].sources[0].given, "DB");
    assert_eq!(
        proposal.params.get("name_rule").map(String::as_str),
        Some("default")
    );
    assert_eq!(
        proposal.params.get("other_names").map(String::as_str),
        Some("db")
    );
    assert!(
        proposal.summary.contains("also named db (UniFi)"),
        "{}",
        proposal.summary
    );

    // The global rule trusts UniFi first: the proposal is superseded with the other name.
    names::set_rule(
        lab.world.store.as_ref(),
        &person(),
        None,
        vec![NameSource::Unifi],
    )
    .await
    .expect("rule");
    lab.reconcile(at("09:02")).await;
    let superseded = lab
        .world
        .proposals(Some(IntentProposalState::Superseded))
        .await;
    assert_eq!(superseded.len(), 1);
    let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(host_name_of(&proposal), "db");
    assert_eq!(
        proposal.params.get("name_rule").map(String::as_str),
        Some("global")
    );

    // Rules are validated.
    let error = names::set_rule(lab.world.store.as_ref(), &person(), None, Vec::new())
        .await
        .expect_err("empty");
    assert_eq!(error.code_str(), names::codes::AUTHORITY_INVALID);
}

#[tokio::test]
async fn a_site_rule_decides_in_the_networks_of_its_site() {
    let (lab, site) = lab_at(Some("lab")).await;
    let site_id = site.expect("site");
    names::set_rule(
        lab.world.store.as_ref(),
        &person(),
        Some(site_id),
        vec![NameSource::Unifi, NameSource::Proxmox],
    )
    .await
    .expect("site rule");
    lab.proxmox("postgresql", at("09:00")).await;
    lab.unifi("db", false, at("09:00")).await;
    lab.reconcile(at("09:01")).await;
    let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;
    assert_eq!(host_name_of(&proposal), "db");
    assert_eq!(
        proposal.params.get("name_rule"),
        Some(&format!("site:{site_id}"))
    );
    assert_eq!(proposal.params.get("rule_site"), Some(&site_id.to_string()));
    let authority = lab.authority().await;
    assert_eq!(authority.sites.len(), 1);
    assert_eq!(authority.sites[0].site_name, "lab");

    // An unknown site is refused.
    let error = names::set_rule(
        lab.world.store.as_ref(),
        &person(),
        Some(SiteId::generate()),
        vec![NameSource::Dns],
    )
    .await
    .expect_err("unknown site");
    assert_eq!(error.code_str(), "ipam.not_found");
}

#[tokio::test]
async fn approving_with_a_choice_names_the_host_and_settles_the_same_names() {
    let lab = lab().await;
    lab.proxmox("postgresql", at("09:00")).await;
    lab.unifi("db", false, at("09:00")).await;
    lab.reconcile(at("09:01")).await;
    let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;

    // A name the proposal does not offer is refused.
    let error = proposals::approve_with(
        &lab.world.service,
        proposal.id,
        &person(),
        &PlanOptions::default(),
        false,
        None,
        &ApproveRequest {
            choice: Some("mail".to_owned()),
            remember: None,
        },
    )
    .await
    .expect_err("not offered");
    assert_eq!(error.code_str(), proposals::codes::CHOICE_INVALID);

    lab.approve(
        &proposal,
        ApproveRequest {
            choice: Some("DB".to_owned()),
            remember: None,
        },
    )
    .await;
    let hosts = lab.hosts().await;
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].name.as_str(), "db");

    // The same names do not open a proposal again although the authority prefers the
    // other one.
    lab.reconcile(at("09:02")).await;
    lab.assert_none(IntentProposalKind::HostName).await;
    lab.assert_none(IntentProposalKind::DiscoveredHost).await;

    // A name no source gave before does: the sources disagree and the authority decides.
    lab.world
        .names(&[(IP, "pg-main.example.test")], at("09:03"))
        .await;
    lab.reconcile(at("09:04")).await;
    let conflict = lab.only(IntentProposalKind::HostName).await;
    assert_eq!(conflict.rule, rule::NAME_CONFLICT);
    assert_eq!(host_name_of(&conflict), "postgresql");
    assert_eq!(conflict.choices.len(), 3, "{:?}", conflict.choices);

    // Keeping the host's own name changes no intent and closes the proposal.
    lab.approve(
        &conflict,
        ApproveRequest {
            choice: Some("db".to_owned()),
            remember: None,
        },
    )
    .await;
    assert_eq!(lab.hosts().await[0].name.as_str(), "db");
    let accepted = lab
        .world
        .proposals(Some(IntentProposalState::Accepted))
        .await;
    assert_eq!(accepted.len(), 2);
    lab.reconcile(at("09:05")).await;
    lab.assert_none(IntentProposalKind::HostName).await;
}

#[tokio::test]
async fn remember_host_makes_the_host_follow_its_source() {
    let lab = lab().await;
    lab.proxmox("postgresql", at("09:00")).await;
    lab.unifi("db", false, at("09:00")).await;
    lab.reconcile(at("09:01")).await;
    let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;
    lab.approve(
        &proposal,
        ApproveRequest {
            choice: Some("db".to_owned()),
            remember: Some(Remember::Host),
        },
    )
    .await;
    let host = lab.hosts().await.remove(0);
    let authority = lab.authority().await;
    assert_eq!(authority.preferences.len(), 1);
    assert_eq!(authority.preferences[0].host, host.id);
    assert_eq!(authority.preferences[0].source, NameSource::Unifi);

    // UniFi renames the client: the host follows it.
    lab.unifi("db-primary", false, at("09:02")).await;
    lab.reconcile(at("09:03")).await;
    let follow = lab.only(IntentProposalKind::HostName).await;
    assert_eq!(follow.rule, rule::PREFERRED_NAME);
    assert_eq!(host_name_of(&follow), "db-primary");
    assert_eq!(
        follow.params.get("name_rule").map(String::as_str),
        Some("host")
    );

    // Forgetting the preference: the same names stay settled, the rule decides again.
    names::clear_preference(lab.world.store.as_ref(), &person(), host.id)
        .await
        .expect("clear");
    assert_eq!(lab.authority().await.preferences, []);
    lab.reconcile(at("09:04")).await;
    let conflict = lab.only(IntentProposalKind::HostName).await;
    assert_eq!(conflict.rule, rule::NAME_CONFLICT);
    assert_eq!(host_name_of(&conflict), "postgresql");
}

#[tokio::test]
async fn remember_source_puts_the_source_first_in_the_rule() {
    let lab = lab().await;
    lab.proxmox("postgresql", at("09:00")).await;
    lab.unifi("db", false, at("09:00")).await;
    lab.reconcile(at("09:01")).await;
    let proposal = lab.only(IntentProposalKind::DiscoveredHost).await;
    lab.approve(
        &proposal,
        ApproveRequest {
            choice: Some("db".to_owned()),
            remember: Some(Remember::Source),
        },
    )
    .await;
    let authority = lab.authority().await;
    let global = authority.global.expect("global rule");
    assert_eq!(global.order[0], NameSource::Unifi);
    assert_eq!(global.order[1], NameSource::Proxmox);
    assert_eq!(global.order.len(), NameSource::DEFAULT_ORDER.len());
    assert_eq!(authority.preferences, []);
}

#[tokio::test]
async fn a_host_with_a_placeholder_name_is_offered_its_real_name_once() {
    let lab = lab().await;
    // Adopted earlier with UniFi's placeholder; now Proxmox VE names it.
    let host = lab
        .intended("host-192-0-2-10", AssignmentMode::Dynamic, false)
        .await;
    lab.unifi("host-192-0-2-10", true, at("09:00")).await;
    lab.reconcile(at("09:01")).await;
    lab.assert_none(IntentProposalKind::HostName).await;
    lab.proxmox("postgresql", at("09:02")).await;
    lab.reconcile(at("09:03")).await;
    let cleanup = lab.only(IntentProposalKind::HostName).await;
    assert_eq!(cleanup.rule, rule::PLACEHOLDER_NAME);
    assert_eq!(cleanup.key, format!("host_name/host:{}", host.id));
    assert_eq!(
        cleanup.commands,
        [IpamCommand::UpdateHost(UpdateHost {
            id: host.id,
            expected: None,
            patch: HostPatch {
                name: Some("postgresql".parse().expect("name")),
                ..HostPatch::default()
            },
        })]
    );
    assert_eq!(
        choice_names(&cleanup),
        [("postgresql".to_owned(), true, NameSource::Proxmox)]
    );

    // Rejected, it stays closed while the names stay the same.
    lab.world.reject(&cleanup).await;
    lab.reconcile(at("09:04")).await;
    lab.assert_none(IntentProposalKind::HostName).await;

    // Approved (after the evidence changed), the host is renamed and nothing follows.
    lab.unifi("pg", false, at("09:05")).await;
    lab.reconcile(at("09:06")).await;
    let again = lab.only(IntentProposalKind::HostName).await;
    assert_eq!(host_name_of(&again), "postgresql");
    lab.world.approve(&again).await;
    assert_eq!(
        fetch::<Host>(&lab.world.service, host.id)
            .await
            .name
            .as_str(),
        "postgresql"
    );
    lab.reconcile(at("09:07")).await;
    lab.assert_none(IntentProposalKind::HostName).await;
}

#[tokio::test]
async fn locked_unmanaged_and_decommissioned_hosts_and_single_names_get_no_name_proposal() {
    for (mode, lock) in [
        (AssignmentMode::Dynamic, true),
        (AssignmentMode::Unmanaged, false),
    ] {
        let lab = lab().await;
        lab.intended("host-192-0-2-10", mode, lock).await;
        lab.proxmox("postgresql", at("09:00")).await;
        lab.reconcile(at("09:01")).await;
        lab.assert_none(IntentProposalKind::HostName).await;
    }
    // A decommissioned host is not renamed.
    let retired_lab = lab().await;
    let retired = retired_lab
        .intended("host-192-0-2-10", AssignmentMode::Dynamic, false)
        .await;
    run(
        &retired_lab.world.service,
        vec![IpamCommand::DecommissionHost(DecommissionHost {
            host: retired.id,
            reason: None,
            keep_dns: false,
            expected: None,
        })],
    )
    .await;
    retired_lab.proxmox("postgresql", at("09:00")).await;
    retired_lab.reconcile(at("09:01")).await;
    retired_lab.assert_none(IntentProposalKind::HostName).await;
    // A host named by its operator and one source naming it otherwise: intent wins.
    let lab = lab().await;
    lab.intended("db", AssignmentMode::Static, false).await;
    lab.proxmox("postgresql", at("09:00")).await;
    lab.reconcile(at("09:01")).await;
    lab.assert_none(IntentProposalKind::HostName).await;
    // A second source with the host's own name: the sources disagree, the rule decides.
    lab.unifi("db", false, at("09:02")).await;
    lab.reconcile(at("09:03")).await;
    let conflict = lab.only(IntentProposalKind::HostName).await;
    assert_eq!(conflict.rule, rule::NAME_CONFLICT);
    assert_eq!(host_name_of(&conflict), "postgresql");
    // A placeholder of a third source changes nothing.
    lab.world.names(&[(IP, "192-0-2-10")], at("09:04")).await;
    lab.reconcile(at("09:05")).await;
    let same = lab.only(IntentProposalKind::HostName).await;
    assert_eq!(same.id, conflict.id, "a placeholder is no new evidence");
}
