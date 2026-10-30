//! The reconciler and DHCP's names (M31): a change set of `dhcp` RRsets alone makes no run
//! read the zones again, a record of another origin in the same change set does, and the
//! zones' facts and the DNS findings stay those of the full pass.

mod common;

use std::sync::Arc;

use common::{address, person, prefix, run};
use tenko_core::{
    ObservationId, RequestCtx, SystemComponent, Timestamp,
    dns::{DnsName, Origin, RecordData, Rtype, ScopeName, SerialPolicy, SoaDefaults, ZoneKind},
    net::Fqdn,
    observe::{Observation, ObservationSource, Observed},
};
use tenko_dns::zone::{
    NewZone, ZoneConfig, ZoneService,
    records::{Change, Op},
};
use tenko_ipam::{
    IpamCommand, IpamService,
    dns::DnsActuator,
    observe::{IngestBatch, ObservedFact, tables::FACTS},
    reconcile::{Reconciler, ReconcilerConfig},
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

struct Lab {
    ipam: Arc<IpamService>,
    zones: Arc<ZoneService>,
    reconciler: Arc<Reconciler>,
    store: MemStore,
    forward: tenko_core::dns::ZoneId,
}

async fn lab() -> Lab {
    let store = MemStore::default();
    let dyn_store = Arc::new(store.clone()) as Arc<dyn Store>;
    let ipam = IpamService::with_direct_jobs(Arc::clone(&dyn_store)).expect("ipam");
    ipam.ensure_defaults(&RequestCtx::system(SystemComponent::Ipam))
        .await
        .expect("defaults");
    let zones = ZoneService::with_direct_jobs(dyn_store, None, ZoneConfig::default());
    let reconciler =
        Reconciler::new(Arc::clone(&ipam), ReconcilerConfig::default()).expect("reconciler");
    reconciler.set_dns(Arc::new(DnsActuator::new(Arc::clone(&zones))));
    let forward = zones
        .create(
            &person(),
            NewZone {
                name: name("example.test"),
                kind: ZoneKind::Primary,
                tenant: None,
                scopes: Vec::new(),
                serial: SerialPolicy::Counter,
                soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
                name_servers: vec![name("ns1.example.test")],
                transfer: tenko_core::dns::TransferPolicy::default(),
                update: tenko_core::dns::UpdatePolicy::default(),
                dnssec: tenko_core::dns::DnssecPolicy::default(),
                source: None,
                description: None,
                reverse_of: None,
                catalog: false,
            },
        )
        .await
        .expect("zone")
        .zone
        .id;
    run(
        &ipam,
        vec![IpamCommand::CreatePrefix(prefix(None, "192.0.2.0/24"))],
    )
    .await;
    Lab {
        ipam,
        zones,
        reconciler,
        store,
        forward,
    }
}

fn a_set(owner: &str, ip: &str, origin: Origin, op: Op) -> Change {
    Change {
        op,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: Rtype::A,
        ttl: Some(300),
        records: if op == Op::Delete {
            Vec::new()
        } else {
            vec![RecordData::A {
                address: ip.parse().expect("ip"),
            }]
        },
        take_over: false,
        origin,
    }
}

fn dhcp() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dhcp)
}

impl Lab {
    async fn write(&self, cx: &RequestCtx, changes: &[Change]) {
        self.zones
            .change_records(cx, self.forward, changes, false)
            .await
            .expect("records");
    }

    /// The names of the current facts of the forward zone's source.
    async fn zone_names(&self) -> Vec<String> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        let now = Timestamp::now();
        let mut names: Vec<String> = view
            .scan_typed(&FACTS, KeyRange::all(), usize::MAX, false)
            .expect("facts")
            .into_iter()
            .map(|(_, fact, _)| fact)
            .filter(|fact: &ObservedFact| fact.is_current(now))
            .filter_map(|fact| match (&fact.source, &fact.observed) {
                (ObservationSource::DnsRecord { .. }, Observed::Name { name, .. }) => {
                    Some(name.clone())
                }
                _ => None,
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }

    async fn changed_run(&self) -> tenko_ipam::reconcile::ReconcileReport {
        self.reconciler
            .reconcile_changed(Timestamp::now())
            .await
            .expect("run")
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one sequence of change sets, read top to bottom"
)]
async fn dhcp_names_alone_are_not_read_again_and_other_origins_are() {
    let lab = lab().await;
    lab.write(
        &person(),
        &[a_set(
            "printer.example.test",
            "192.0.2.5",
            Origin::Manual,
            Op::Set,
        )],
    )
    .await;
    let report = lab
        .reconciler
        .reconcile(Timestamp::now())
        .await
        .expect("full run");
    assert!(report.dns.is_some());
    assert_eq!(lab.reconciler.dns_passes(), 1);
    // The full run created the network's reverse zone; the run after it reads that once.
    lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 2);
    lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 2);
    assert_eq!(lab.zone_names().await, ["printer.example.test"]);

    // DHCP's names (the DDNS worker's principal and origin) schedule no run; a run after
    // them evaluates nothing and reads no zone, and a DHCP record is no DNS fact (the
    // lease's own name fact carries it).
    let rules = lab.reconciler.rule_passes();
    lab.write(
        &dhcp(),
        &[
            a_set("laptop.example.test", "192.0.2.50", Origin::Dhcp, Op::Set),
            a_set("phone.example.test", "192.0.2.51", Origin::Dhcp, Op::Set),
        ],
    )
    .await;
    let report = lab.changed_run().await;
    assert_eq!(report.dns, None);
    assert_eq!(lab.reconciler.rule_passes(), rules);
    assert_eq!(lab.reconciler.dns_passes(), 2);
    assert_eq!(lab.zone_names().await, ["printer.example.test"]);

    // A fact alone (a probe's sighting) runs the rules, not the DNS steps: the actuator
    // writes nothing.
    lab.reconciler
        .ingest(probe_batch("192.0.2.77"))
        .await
        .expect("ingest");
    let report = lab.changed_run().await;
    assert_eq!(report.dns, Some(tenko_ipam::dns::DnsActuation::default()));
    assert_eq!(lab.reconciler.rule_passes(), rules + 1);
    assert_eq!(lab.reconciler.dns_passes(), 2);

    // DHCP's release deletes its record: still nothing to read.
    lab.write(
        &dhcp(),
        &[a_set("phone.example.test", "", Origin::Dhcp, Op::Delete)],
    )
    .await;
    lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 2);

    // A hand-written record in the same change set as DHCP's: the full pass, and its fact.
    lab.write(
        &dhcp(),
        &[
            a_set("tablet.example.test", "192.0.2.52", Origin::Dhcp, Op::Set),
            a_set("nas.example.test", "192.0.2.6", Origin::Manual, Op::Set),
        ],
    )
    .await;
    lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 3);
    assert_eq!(
        lab.zone_names().await,
        ["nas.example.test", "printer.example.test"]
    );

    // A person deletes a record: read again, and its fact goes.
    lab.write(
        &person(),
        &[a_set(
            "printer.example.test",
            "",
            Origin::Manual,
            Op::Delete,
        )],
    )
    .await;
    lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 4);
    assert_eq!(lab.zone_names().await, ["nas.example.test"]);

    // An intent change plans again, and the actuator writes the `ipam` record.
    let mut named = address(None, "192.0.2.10");
    named.dns_name = Some(Fqdn::new("server.example.test").expect("fqdn"));
    run(&lab.ipam, vec![IpamCommand::CreateAddress(named)]).await;
    let report = lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 5);
    assert!(
        report
            .dns
            .as_ref()
            .is_some_and(|dns| dns.rrsets_changed >= 1),
        "{report:?}"
    );

    // The actuator's own write is read once more, then all is quiet.
    lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 6);
    assert_eq!(
        lab.zone_names().await,
        ["nas.example.test", "server.example.test"]
    );
    lab.changed_run().await;
    assert_eq!(lab.reconciler.dns_passes(), 6);

    // The run on demand is always the full pass.
    lab.reconciler
        .reconcile(Timestamp::now())
        .await
        .expect("full run");
    assert_eq!(lab.reconciler.dns_passes(), 7);
}

/// A probe's sighting at an address.
fn probe_batch(ip: &str) -> IngestBatch {
    let source = ObservationSource::Probe {
        node: tenko_core::NodeId(1),
        method: tenko_core::observe::ProbeMethod::Arp,
    };
    IngestBatch {
        source: source.clone(),
        observations: vec![Observation {
            id: ObservationId::generate(),
            source,
            subject: Observed::Address {
                vrf: tenko_core::VrfId::generate(),
                ip: ip.parse().expect("ip"),
                mac: None,
            },
            observed_at: Timestamp::now(),
            received_at: Timestamp::now(),
            expires_at: None,
        }],
        complete: false,
        received_at: Timestamp::now(),
    }
}

/// The lease facts the `dhcp` role writes with every lease change make a light run: the
/// waiting moves are confirmed, the rules wait for the periodic run; another source's
/// facts run the rules.
#[tokio::test]
async fn lease_facts_alone_make_a_light_run() {
    use std::time::Duration;

    use tenko_core::{
        NodeId, PrefixId, Principal, VrfId,
        dhcp::{BindingState, ClientKey, DdnsState, Lease},
        serde_util::HexBytes,
    };
    use tenko_ipam::observe::{ObserveConfig, dhcp::LeaseFacts};
    use tenko_store::WriteBatch;

    let lab = lab().await;
    lab.reconciler
        .reconcile(Timestamp::now())
        .await
        .expect("full run");
    lab.changed_run().await;
    let (rules, dns) = (lab.reconciler.rule_passes(), lab.reconciler.dns_passes());

    let store = Arc::new(lab.store.clone()) as Arc<dyn Store>;
    let facts = LeaseFacts::new(NodeId(1), ObserveConfig::default());
    facts.register(store.as_ref()).expect("register");
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    for last in 50..60u8 {
        let now = Timestamp::now();
        let lease = Lease {
            addr: std::net::Ipv4Addr::new(192, 0, 2, last),
            vrf,
            scope,
            client: ClientKey {
                htype: 1,
                chaddr: HexBytes(vec![0, 0, 0x5e, 0, 0x53, last]),
                client_id: None,
            },
            state: BindingState::Active,
            cltt: now,
            ends: now.checked_add(Duration::from_secs(3_600)).expect("end"),
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: Some(format!("client{last}")),
            fqdn: None,
            fqdn_flags: None,
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
        };
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        facts.observe(&lease, now, &mut batch).expect("observe");
        store.propose(batch).await.expect("commit");
    }
    lab.changed_run().await;
    assert_eq!(lab.reconciler.rule_passes(), rules, "a light run");
    assert_eq!(lab.reconciler.dns_passes(), dns);

    // A probe's fact runs the rules (and reads no zone).
    lab.reconciler
        .ingest(probe_batch("192.0.2.77"))
        .await
        .expect("ingest");
    lab.changed_run().await;
    assert_eq!(lab.reconciler.rule_passes(), rules + 1);
    assert_eq!(lab.reconciler.dns_passes(), dns);

    // The periodic run (as the run on demand) evaluates the rules over the lease facts too.
    lab.reconciler
        .reconcile(Timestamp::now())
        .await
        .expect("full run");
    assert_eq!(lab.reconciler.rule_passes(), rules + 2);
}

/// ADR 0030: the `dhcp` role's asynchronous writer flushes the facts of many lease changes
/// in one batch of its own, without the lease rows; that batch is a change set of lease
/// facts like the per-lease ones before it: it makes a light run, and the waiting moves are
/// confirmed by it.
#[tokio::test]
async fn the_writers_batch_of_lease_facts_makes_a_light_run() {
    use std::time::Duration;

    use tenko_core::{
        NodeId, PrefixId, Principal, VrfId,
        dhcp::{BindingState, ClientKey, DdnsState, Lease},
        serde_util::HexBytes,
    };
    use tenko_ipam::observe::{ObserveConfig, dhcp::LeaseFacts};
    use tenko_store::WriteBatch;

    let lab = lab().await;
    lab.reconciler
        .reconcile(Timestamp::now())
        .await
        .expect("full run");
    lab.changed_run().await;
    let (rules, dns) = (lab.reconciler.rule_passes(), lab.reconciler.dns_passes());

    let store = Arc::new(lab.store.clone()) as Arc<dyn Store>;
    let facts = LeaseFacts::new(NodeId(1), ObserveConfig::default());
    facts.register(store.as_ref()).expect("register");
    let (vrf, scope) = (VrfId::generate(), PrefixId::generate());
    let now = Timestamp::now();
    let mut flush = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
    for last in 60..90u8 {
        let lease = Lease {
            addr: std::net::Ipv4Addr::new(192, 0, 2, last),
            vrf,
            scope,
            client: ClientKey {
                htype: 1,
                chaddr: HexBytes(vec![0, 0, 0x5e, 0, 0x53, last]),
                client_id: None,
            },
            state: BindingState::Active,
            cltt: now,
            ends: now.checked_add(Duration::from_secs(3_600)).expect("end"),
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: Some(format!("client{last}")),
            fqdn: None,
            fqdn_flags: None,
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
        };
        let mut derived = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        facts.observe(&lease, now, &mut derived).expect("observe");
        // The committer hands the facts to the index at once, the writer's flush follows.
        facts.note_written(&derived);
        flush.mutations.extend(derived.mutations);
    }
    assert!(
        flush.mutations.len() >= 30,
        "the facts of thirty leases in one batch"
    );
    store.propose(flush).await.expect("the writer's flush");
    assert_eq!(
        facts.len(),
        60,
        "the address and name facts of thirty leases"
    );
    lab.changed_run().await;
    assert_eq!(lab.reconciler.rule_passes(), rules, "a light run");
    assert_eq!(lab.reconciler.dns_passes(), dns);
}
