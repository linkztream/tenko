//! The link from IPAM to DNS (WP4.4): the planner over a store with IPAM intent and zones,
//! and the actuator writing through the zone service.

mod common;

use std::sync::Arc;

use common::{address, person, prefix, run, supernet};
use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{
        DnsName, Origin, RecordData, Rtype, ScopeName, SerialPolicy, SoaDefaults, ZoneId, ZoneKind,
    },
    ipam::{DnsReverse, Status},
    net::Fqdn,
};
use tenko_dns::zone::{
    NewZone, ZoneConfig, ZoneService,
    records::{Change, Op},
};
use tenko_ipam::{
    IpamCommand, IpamService,
    command::{AddressPatch, PrefixPatch, UpdateAddress, UpdatePrefix},
    dns::{
        DnsActuator, DnsFinding, DnsPlan, OrphanRule, PlanOptions, RecordChange,
        plan::{self, chunks},
    },
};
use tenko_store::{MemStore, ReadConsistency, Store};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn fqdn(text: &str) -> Fqdn {
    Fqdn::new(text).expect("fqdn")
}

struct Lab {
    ipam: Arc<IpamService>,
    zones: Arc<ZoneService>,
    actuator: DnsActuator,
    store: MemStore,
}

async fn lab() -> Lab {
    let store = MemStore::default();
    let dyn_store = Arc::new(store.clone()) as Arc<dyn Store>;
    let ipam = IpamService::with_direct_jobs(Arc::clone(&dyn_store)).expect("ipam");
    ipam.ensure_defaults(&RequestCtx::system(SystemComponent::Ipam))
        .await
        .expect("defaults");
    let zones = ZoneService::with_direct_jobs(dyn_store, None, ZoneConfig::default());
    let actuator = DnsActuator::new(Arc::clone(&zones));
    Lab {
        ipam,
        zones,
        actuator,
        store,
    }
}

fn zone(apex: &str, servers: &str) -> NewZone {
    NewZone {
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: Vec::new(),
        serial: SerialPolicy::Counter,
        soa: SoaDefaults::new(name(servers), name("hostmaster.example.test")),
        name_servers: vec![name(servers)],
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        description: None,
        reverse_of: None,
        catalog: false,
    }
}

impl Lab {
    async fn zone(&self, apex: &str) -> ZoneId {
        self.zones
            .create(&person(), zone(apex, "ns1.example.test"))
            .await
            .expect("zone")
            .zone
            .id
    }

    async fn plan(&self) -> DnsPlan {
        self.plan_with(&PlanOptions::default()).await
    }

    async fn plan_with(&self, options: &PlanOptions) -> DnsPlan {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        plan::plan(view.as_ref(), options).expect("plan")
    }

    async fn named(&self, ip: &str, dns: &str) -> tenko_core::AddressId {
        let mut input = address(None, ip);
        input.dns_name = Some(fqdn(dns));
        let id = input.id.expect("id");
        run(&self.ipam, vec![IpamCommand::CreateAddress(input)]).await;
        id
    }

    async fn network(&self, cidr: &str) -> tenko_core::PrefixId {
        let input = prefix(None, cidr);
        let id = input.id.expect("id");
        run(&self.ipam, vec![IpamCommand::CreatePrefix(input)]).await;
        id
    }

    async fn rrsets(&self, apex: &str) -> Vec<(String, Rtype, Origin, Vec<RecordData>)> {
        let view = self.zones.view(None).await.expect("view");
        let row = ZoneService::zone_by_name(view.as_ref(), &name(apex))
            .expect("zones")
            .expect("zone");
        ZoneService::rrsets(
            view.as_ref(),
            &row.zone,
            &tenko_dns::zone::RrSetFilter::scope(ScopeName::DEFAULT),
            None,
            usize::MAX,
        )
        .expect("rrsets")
        .0
        .into_iter()
        .map(|(rrset, _)| rrset)
        .filter(|rrset| {
            !matches!(rrset.rtype, Rtype::SOA | Rtype::NS) || rrset.name != row.zone.name
        })
        .map(|rrset| {
            let records = rrset.records().expect("records");
            (rrset.name.to_string(), rrset.rtype, rrset.origin, records)
        })
        .collect()
    }
}

fn change_names(plan: &DnsPlan, apex: &str) -> Vec<(String, Rtype, usize)> {
    plan.batches
        .iter()
        .filter(|batch| batch.name == name(apex))
        .flat_map(|batch| &batch.changes)
        .map(|change| (change.name.to_string(), change.rtype, change.after.len()))
        .collect()
}

#[tokio::test]
async fn names_get_records_and_the_prefix_its_reverse_zone() {
    let lab = lab().await;
    lab.zone("example.test").await;
    let net = lab.network("192.0.2.0/24").await;
    lab.named("192.0.2.10", "host-a.example.test").await;
    lab.named("192.0.2.11", "host-a.example.test").await;
    lab.named("192.0.2.12", "printer.elsewhere.test").await;
    let mut planned_input = address(None, "192.0.2.13");
    planned_input.dns_name = Some(fqdn("later.example.test"));
    planned_input.status = Some(Status::Planned);
    run(&lab.ipam, vec![IpamCommand::CreateAddress(planned_input)]).await;

    let plan = lab.plan().await;
    assert_eq!(plan.create.len(), 1);
    assert_eq!(plan.create[0].name, name("2.0.192.in-addr.arpa"));
    assert_eq!(plan.create[0].prefix, net);
    assert_eq!(plan.create[0].source, name("example.test"));
    assert_eq!(plan.create[0].name_servers, [name("ns1.example.test")]);
    // Two addresses with one name are one RRset; a planned address gets nothing.
    assert_eq!(
        change_names(&plan, "example.test"),
        [("host-a.example.test".to_owned(), Rtype::A, 2)]
    );
    let no_zone = plan.findings.iter().find_map(|finding| match finding {
        DnsFinding::NoZone { names } => Some(names.keys().cloned().collect::<Vec<_>>()),
        _ => None,
    });
    assert_eq!(no_zone, Some(vec![fqdn("printer.elsewhere.test")]));

    // Once the reverse zone exists (made here by hand), the PTRs go there, the name
    // without a zone included, and the zone is adopted for the prefix.
    let reverse = lab.zone("2.0.192.in-addr.arpa").await;
    let plan = lab.plan().await;
    assert_eq!(plan.create.len(), 0);
    assert_eq!(plan.adopt.len(), 1);
    assert_eq!(plan.adopt[0].zone, reverse);
    assert_eq!(
        change_names(&plan, "2.0.192.in-addr.arpa"),
        [
            ("10.2.0.192.in-addr.arpa".to_owned(), Rtype::PTR, 1),
            ("11.2.0.192.in-addr.arpa".to_owned(), Rtype::PTR, 1),
            ("12.2.0.192.in-addr.arpa".to_owned(), Rtype::PTR, 1),
        ]
    );
}

#[tokio::test]
async fn the_reverse_setting_decides_and_ipv6_prefixes_use_nibbles() {
    let lab = lab().await;
    // Without a forward zone, a prefix gets no reverse zone by default.
    let v4 = lab.network("198.51.100.0/24").await;
    lab.network("2001:db8:1::/48").await;
    assert_eq!(lab.plan().await.create.len(), 0);

    lab.zone("example.test").await;
    let names: Vec<String> = lab
        .plan()
        .await
        .create
        .iter()
        .map(|create| create.name.to_string())
        .collect();
    assert_eq!(
        names,
        [
            "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            "100.51.198.in-addr.arpa"
        ]
    );

    // `off` on the IPv4 prefix leaves only the IPv6 zone.
    run(
        &lab.ipam,
        vec![IpamCommand::UpdatePrefix(UpdatePrefix {
            id: v4,
            expected: None,
            patch: PrefixPatch {
                dns_reverse: Some(Some(DnsReverse::Off)),
                ..PrefixPatch::default()
            },
        })],
    )
    .await;
    let names: Vec<String> = lab
        .plan()
        .await
        .create
        .iter()
        .map(|create| create.name.to_string())
        .collect();
    assert_eq!(names, ["1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"]);
}

#[tokio::test]
async fn a_small_network_in_a_served_parent_gets_the_rfc_2317_glue() {
    let lab = lab().await;
    lab.zone("example.test").await;
    run(
        &lab.ipam,
        vec![IpamCommand::CreatePrefix(supernet(None, "192.0.2.0/24"))],
    )
    .await;
    lab.network("192.0.2.64/26").await;
    lab.named("192.0.2.70", "cam.example.test").await;
    lab.zone("2.0.192.in-addr.arpa").await;

    let plan = lab.plan().await;
    assert_eq!(
        plan.create
            .iter()
            .map(|c| c.name.to_string())
            .collect::<Vec<_>>(),
        ["64/26.2.0.192.in-addr.arpa"]
    );
    // The glue is planned with the zone's name servers already, the PTR once it exists.
    lab.zone("64/26.2.0.192.in-addr.arpa").await;
    let plan = lab.plan().await;
    let parent = change_names(&plan, "2.0.192.in-addr.arpa");
    assert_eq!(parent.len(), 65, "one NS set and 64 CNAMEs");
    assert!(parent.contains(&("64/26.2.0.192.in-addr.arpa".to_owned(), Rtype::NS, 1)));
    assert!(parent.contains(&("64.2.0.192.in-addr.arpa".to_owned(), Rtype::CNAME, 1)));
    assert!(parent.contains(&("127.2.0.192.in-addr.arpa".to_owned(), Rtype::CNAME, 1)));
    assert_eq!(
        change_names(&plan, "64/26.2.0.192.in-addr.arpa"),
        [("70.64/26.2.0.192.in-addr.arpa".to_owned(), Rtype::PTR, 1)]
    );
    let cname = plan
        .batches
        .iter()
        .flat_map(|batch| &batch.changes)
        .find(|change| change.name == name("70.2.0.192.in-addr.arpa"))
        .expect("cname");
    assert_eq!(
        cname.after,
        [RecordData::Cname {
            target: name("70.64/26.2.0.192.in-addr.arpa")
        }]
    );
}

#[tokio::test]
async fn a_small_network_without_its_parent_lists_the_delegation() {
    let lab = lab().await;
    lab.zone("example.test").await;
    let net = lab.network("198.51.100.128/25").await;
    lab.zone("128/25.100.51.198.in-addr.arpa").await;
    let plan = lab.plan().await;
    let lines = plan.findings.iter().find_map(|finding| match finding {
        DnsFinding::Delegation {
            prefix,
            parent,
            lines,
            ..
        } => {
            assert_eq!(*prefix, net);
            assert_eq!(parent, &name("100.51.198.in-addr.arpa"));
            Some(lines.clone())
        }
        _ => None,
    });
    assert_eq!(
        lines.expect("delegation"),
        [
            "128/25.100.51.198.in-addr.arpa. IN NS ns1.example.test.",
            "$GENERATE 128-255 $.100.51.198.in-addr.arpa. IN CNAME $.128/25.100.51.198.in-addr.arpa."
        ]
    );
}

#[tokio::test]
async fn another_origin_keeps_its_rrset_and_a_delegated_name_has_no_zone() {
    let lab = lab().await;
    let forward = lab.zone("example.test").await;
    lab.network("192.0.2.0/24").await;
    lab.named("192.0.2.10", "host-a.example.test").await;
    lab.named("192.0.2.20", "a.lab.example.test").await;
    let change = |name_: &str, rtype, records| Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(name_),
        rtype,
        ttl: Some(300),
        records,
        take_over: false,
        origin: Origin::Manual,
    };
    lab.zones
        .change_records(
            &person(),
            forward,
            &[
                change(
                    "host-a.example.test",
                    Rtype::A,
                    vec![RecordData::A {
                        address: "192.0.2.99".parse().expect("ip"),
                    }],
                ),
                change(
                    "lab.example.test",
                    Rtype::NS,
                    vec![RecordData::Ns {
                        host: name("ns.lab.example.test"),
                    }],
                ),
            ],
            false,
        )
        .await
        .expect("manual records");
    let plan = lab.plan().await;
    assert_eq!(change_names(&plan, "example.test").len(), 0);
    assert!(plan.findings.iter().any(|finding| matches!(
        finding,
        DnsFinding::Held { name: owner, origin: Origin::Manual, .. } if owner == &name("host-a.example.test")
    )));
    assert!(plan.findings.iter().any(|finding| matches!(
        finding,
        DnsFinding::NoZone { names } if names.contains_key(&fqdn("a.lab.example.test"))
    )));
}

#[tokio::test]
async fn the_actuator_writes_ipam_records_once_and_removes_orphans() {
    let lab = lab().await;
    lab.zone("example.test").await;
    lab.network("192.0.2.0/24").await;
    let a = lab.named("192.0.2.10", "host-a.example.test").await;
    lab.named("192.0.2.11", "host-b.example.test").await;
    let cx = RequestCtx::system(SystemComponent::Reconciler);

    // The dry run writes nothing.
    let dry = lab
        .actuator
        .dry_run(&PlanOptions::default())
        .await
        .expect("dry run");
    assert!(!dry.is_empty());
    assert_eq!(lab.rrsets("example.test").await.len(), 0);

    let report = lab
        .actuator
        .run(&cx, &PlanOptions::default())
        .await
        .expect("run");
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.zones_created, 1);
    assert_eq!(report.rrsets_changed, 4);
    let forward = lab.rrsets("example.test").await;
    assert_eq!(forward.len(), 2);
    assert!(
        forward
            .iter()
            .all(|(_, _, origin, _)| *origin == Origin::Ipam)
    );
    let reverse = lab.rrsets("2.0.192.in-addr.arpa").await;
    assert_eq!(
        reverse
            .iter()
            .map(|(owner, rtype, _, records)| (owner.clone(), *rtype, records.clone()))
            .collect::<Vec<_>>(),
        [
            (
                "10.2.0.192.in-addr.arpa".to_owned(),
                Rtype::PTR,
                vec![RecordData::Ptr {
                    target: name("host-a.example.test")
                }]
            ),
            (
                "11.2.0.192.in-addr.arpa".to_owned(),
                Rtype::PTR,
                vec![RecordData::Ptr {
                    target: name("host-b.example.test")
                }]
            ),
        ]
    );

    // Idempotent: a second run plans and writes nothing.
    assert!(lab.plan().await.is_empty(), "a second run plans nothing");
    let again = lab
        .actuator
        .run(&cx, &PlanOptions::default())
        .await
        .expect("again");
    assert_eq!(again.rrsets_changed, 0);
    assert_eq!(again.batches, 0);

    // The name goes: with `propose` the records stay and are listed, with `remove` they go.
    run(
        &lab.ipam,
        vec![IpamCommand::UpdateAddress(UpdateAddress {
            id: a,
            expected: None,
            patch: AddressPatch {
                dns_name: Some(None),
                ..AddressPatch::default()
            },
        })],
    )
    .await;
    let propose = PlanOptions {
        orphans: OrphanRule::Propose,
        ..PlanOptions::default()
    };
    let plan = lab.plan_with(&propose).await;
    assert_eq!(plan.batches.len(), 0);
    assert_eq!(
        plan.findings
            .iter()
            .filter(|finding| matches!(finding, DnsFinding::Orphaned { .. }))
            .count(),
        2
    );
    let report = lab
        .actuator
        .run(&cx, &PlanOptions::default())
        .await
        .expect("orphans");
    assert_eq!(report.rrsets_changed, 2);
    assert_eq!(lab.rrsets("example.test").await.len(), 1);
    assert_eq!(lab.rrsets("2.0.192.in-addr.arpa").await.len(), 1);
}

#[test]
fn chunks_keep_the_changes_of_one_owner_together() {
    let change = |owner: &str, delete: bool| RecordChange {
        name: name(owner),
        rtype: Rtype::A,
        before: Vec::new(),
        after: if delete {
            Vec::new()
        } else {
            vec![RecordData::A {
                address: "192.0.2.1".parse().expect("ip"),
            }]
        },
        addresses: Vec::new(),
    };
    let mut changes: Vec<RecordChange> = (0..plan::MAX_CHANGES - 1)
        .map(|index| change(&format!("h{index}.example.test"), false))
        .collect();
    changes.push(change("last.example.test", true));
    changes.push(change("last.example.test", false));
    changes.push(change("z.example.test", false));
    let parts = chunks(&changes);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].len(), plan::MAX_CHANGES - 1);
    assert_eq!(parts[1].len(), 3);
    assert_eq!(chunks(&[]).len(), 0);
}
