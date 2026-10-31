//! Ingest and retention of observations: one write per poll at most, idempotent repeats,
//! refresh and sighting counts, expiry by complete batches (empty ones too), several
//! sources side by side, and the purge of old facts and stale sightings.

use std::{sync::Arc, time::Duration};

use tenko_core::{
    ConnectorId, MacAddr, NodeId, ObjectRef, ObservationId, PrefixId, Principal, SystemComponent,
    Timestamp, VrfId,
    dhcp::{BindingState, ClientKey, DdnsState, Lease, tables as lease_tables},
    observe::{Observation, ObservationSource, Observed, ObservedHost, ProbeMethod},
    serde_util::HexBytes,
};
use tenko_ipam::observe::{
    self, FactSubject, IngestBatch, IntentSighting, ObserveConfig, ObservedFact,
    dhcp::{LeaseFacts, Naming},
    source::{FactSource, Observations, StoredFacts},
    tables::{BY_IP, BY_MAC, BY_NAME, FACTS, LAST_SEEN},
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, WriteBatch};

fn at(clock: &str) -> Timestamp {
    format!("2026-10-10T{clock}:00Z").parse().expect("time")
}

fn host(id: &str, ip: &str, when: Timestamp, connector: ConnectorId) -> Observation {
    Observation {
        id: ObservationId::generate(),
        source: ObservationSource::Inventory { connector },
        subject: Observed::Host(ObservedHost {
            external_id: id.to_owned(),
            name: Some(format!("VM-{id}.example.test")),
            macs: vec!["00:00:5e:00:53:01".parse().expect("mac")],
            ips: vec![ip.parse().expect("ip")],
            ..ObservedHost::default()
        }),
        observed_at: when,
        received_at: when,
        expires_at: when.checked_add(Duration::from_secs(900)),
    }
}

fn batch(connector: ConnectorId, observations: Vec<Observation>, when: Timestamp) -> IngestBatch {
    IngestBatch {
        source: ObservationSource::Inventory { connector },
        observations,
        complete: true,
        received_at: when,
    }
}

async fn facts(store: &Arc<dyn Store>) -> Vec<observe::ObservedFact> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&FACTS, KeyRange::all(), usize::MAX, false)
        .expect("scan")
        .into_iter()
        .map(|(_, fact, _)| fact)
        .collect()
}

async fn rows(store: &Arc<dyn Store>) -> (usize, usize, usize) {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    (
        view.scan(BY_MAC.name(), KeyRange::all(), usize::MAX, false)
            .expect("mac")
            .len(),
        view.scan(BY_IP.name(), KeyRange::all(), usize::MAX, false)
            .expect("ip")
            .len(),
        view.scan(BY_NAME.name(), KeyRange::all(), usize::MAX, false)
            .expect("name")
            .len(),
    )
}

#[tokio::test]
async fn sightings_count_once_per_refresh_and_lifetimes_never_lapse_between_polls() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let config = ObserveConfig::default();
    let connector = ConnectorId::generate();
    // Polled every minute for 40 minutes: the fact lives 15 minutes from each write.
    let mut writes = 0;
    for minute in 0..40u64 {
        let when = at("08:00")
            .checked_add(Duration::from_secs(minute * 60))
            .expect("time");
        let report = observe::ingest(
            &store,
            &batch(
                connector,
                vec![host("101", "192.0.2.10", when, connector)],
                when,
            ),
            &config,
        )
        .await
        .expect("ingest");
        if report.wrote() {
            writes += 1;
        }
        let fact = facts(&store).await.remove(0);
        assert!(fact.is_current(when), "minute {minute}");
        assert!(
            fact.expires_at
                .is_some_and(|expires| expires.saturating_since(when) >= Duration::from_secs(420)),
            "minute {minute}: at least half a lifetime left"
        );
    }
    assert!((5..=8).contains(&writes), "{writes} writes in 40 polls");
    let fact = facts(&store).await.remove(0);
    assert_eq!(fact.sightings, 3, "08:00, 08:15, 08:30");
    assert_eq!(fact.first_seen, at("08:00"));
    assert_eq!(rows(&store).await, (1, 1, 1));
}

#[tokio::test]
async fn an_empty_complete_batch_expires_only_its_own_source() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let config = ObserveConfig::default();
    let (one, two) = (ConnectorId::generate(), ConnectorId::generate());
    for connector in [one, two] {
        observe::ingest(
            &store,
            &batch(
                connector,
                vec![host("101", "192.0.2.10", at("09:00"), connector)],
                at("09:00"),
            ),
            &config,
        )
        .await
        .expect("ingest");
    }
    let report = observe::ingest(&store, &batch(one, Vec::new(), at("09:05")), &config)
        .await
        .expect("empty");
    assert_eq!(report.gone, 1);
    let current: Vec<_> = facts(&store)
        .await
        .into_iter()
        .filter(|fact| fact.is_current(at("09:05")))
        .map(|fact| fact.source_key)
        .collect();
    assert_eq!(current, vec![format!("inventory:{two}")]);
    // Repeating it changes nothing.
    let again = observe::ingest(&store, &batch(one, Vec::new(), at("09:06")), &config)
        .await
        .expect("again");
    assert!(!again.wrote());
    // The host comes back: the fact revives with a counted sighting.
    let back = observe::ingest(
        &store,
        &batch(
            one,
            vec![host("101", "192.0.2.10", at("09:07"), one)],
            at("09:07"),
        ),
        &config,
    )
    .await
    .expect("back");
    assert_eq!(back.refreshed, 1);
}

#[tokio::test]
async fn malformed_and_duplicate_observations_are_handled() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let connector = ConnectorId::generate();
    let early = host("101", "192.0.2.10", at("10:00"), connector);
    let late = host("101", "192.0.2.11", at("10:01"), connector);
    let empty = host(" ", "192.0.2.12", at("10:00"), connector);
    let report = observe::ingest(
        &store,
        &batch(connector, vec![late, early, empty], at("10:02")),
        &ObserveConfig::default(),
    )
    .await
    .expect("ingest");
    assert_eq!((report.new, report.skipped), (1, 1));
    let fact = facts(&store).await.remove(0);
    assert_eq!(
        fact.ips(),
        vec!["192.0.2.11".parse::<std::net::IpAddr>().expect("ip")]
    );
}

#[tokio::test]
async fn probe_addresses_and_services_are_facts_of_their_own() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    let probe = ObservationSource::Probe {
        node: NodeId(3),
        method: ProbeMethod::Icmp,
    };
    let observations = vec![
        Observation {
            id: ObservationId::generate(),
            source: probe.clone(),
            subject: Observed::Address {
                vrf,
                ip: "2001:db8::10".parse().expect("ip"),
                mac: None,
            },
            observed_at: at("11:00"),
            received_at: at("11:00"),
            expires_at: None,
        },
        Observation {
            id: ObservationId::generate(),
            source: probe.clone(),
            subject: Observed::Services {
                ip: "2001:db8::10".parse().expect("ip"),
                open_tcp: vec![22, 443],
                tls_tcp: vec![443],
            },
            observed_at: at("11:00"),
            received_at: at("11:00"),
            expires_at: None,
        },
    ];
    let report = observe::ingest(
        &store,
        &IngestBatch {
            source: probe,
            observations,
            complete: false,
            received_at: at("11:00"),
        },
        &ObserveConfig::default(),
    )
    .await
    .expect("ingest");
    assert_eq!(report.new, 2);
    let keys: Vec<String> = facts(&store)
        .await
        .into_iter()
        .map(|fact| fact.subject_key)
        .collect();
    assert!(
        keys.contains(&format!("address:{vrf}/2001:db8::10")),
        "{keys:?}"
    );
    assert!(
        keys.contains(&"services:2001:db8::10".to_owned()),
        "{keys:?}"
    );
    assert_eq!(rows(&store).await, (0, 2, 0));
}

#[tokio::test]
async fn retention_purges_old_facts_with_their_index_rows_and_stale_sightings() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let config = ObserveConfig {
        retention: Duration::from_secs(24 * 3600),
        ..ObserveConfig::default()
    };
    let connector = ConnectorId::generate();
    observe::ingest(
        &store,
        &batch(
            connector,
            vec![host("101", "192.0.2.10", at("08:00"), connector)],
            at("08:00"),
        ),
        &config,
    )
    .await
    .expect("ingest");
    // A sighting of an address that does not exist (any more).
    let mut write = WriteBatch::new(Principal::system(SystemComponent::Reconciler), at("08:00"));
    let gone = ObjectRef::from(tenko_core::AddressId::generate());
    write
        .put_typed(
            &LAST_SEEN,
            &gone,
            &IntentSighting {
                at: at("08:00"),
                source: format!("inventory:{connector}"),
                observation: ObservationId::generate(),
            },
        )
        .expect("put");
    store.propose(write).await.expect("propose");

    let kept = observe::retention::purge(&store, &config, at("20:00"))
        .await
        .expect("purge");
    assert_eq!(kept, 0, "younger than a day");
    let later = at("08:00")
        .checked_add(Duration::from_secs(25 * 3600))
        .expect("time");
    let purged = observe::retention::purge(&store, &config, later)
        .await
        .expect("purge");
    assert_eq!(purged, 1);
    assert_eq!(facts(&store).await.len(), 0);
    assert_eq!(rows(&store).await, (0, 0, 0));
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert!(view.get_typed(&LAST_SEEN, &gone).expect("read").is_none());
}

// ADR 0031: the lease tables are the source `dhcp:<node>`; the ingest writes no fact row of
// it, the stored facts of it (written by a version before) are never read.

const DHCP_NODE: NodeId = NodeId(7);

fn dhcp_source() -> ObservationSource {
    ObservationSource::DhcpLease { node: DHCP_NODE }
}

fn lease_mac() -> MacAddr {
    "00:00:5e:00:53:20".parse().expect("mac")
}

fn lease_observation(vrf: VrfId, ip: &str, when: Timestamp) -> Observation {
    Observation {
        id: ObservationId::generate(),
        source: dhcp_source(),
        subject: Observed::Address {
            vrf,
            ip: ip.parse().expect("ip"),
            mac: Some(lease_mac()),
        },
        observed_at: when,
        received_at: when,
        expires_at: when.checked_add(Duration::from_secs(3_600)),
    }
}

/// A fact of the source `dhcp:7` as a version before ADR 0031 stored it, with its index
/// rows, committed to the store.
async fn store_legacy_lease_fact(store: &Arc<dyn Store>, vrf: VrfId, ip: &str, mac: MacAddr) {
    let ip: std::net::IpAddr = ip.parse().expect("ip");
    let when = at("12:00");
    let observed = Observed::Address {
        vrf,
        ip,
        mac: Some(mac),
    };
    let subject = FactSubject::of(&observed);
    let fact = ObservedFact {
        source: dhcp_source(),
        source_key: "dhcp:7".to_owned(),
        subject_key: subject.key(),
        subject,
        observed,
        observation: ObservationId::generate(),
        first_seen: when,
        last_seen: when,
        received_at: when,
        expires_at: when.checked_add(Duration::from_secs(3_600)),
        sightings: 1,
        counted_at: Some(when),
        revision: tenko_core::Revision::ZERO,
    };
    let key = (fact.source_key.clone(), fact.subject_key.clone());
    let mut write = WriteBatch::new(Principal::system(SystemComponent::Dhcp), when);
    write.put_typed(&FACTS, &key, &fact).expect("fact");
    write
        .put_typed(&BY_IP, &(ip, key.0.clone(), key.1.clone()), &())
        .expect("by ip");
    write
        .put_typed(&BY_MAC, &(mac, key.0, key.1), &())
        .expect("by mac");
    store.propose(write).await.expect("commit");
}

#[tokio::test]
async fn an_ingest_of_a_lease_source_writes_no_fact_row_and_counts_the_observations_as_skipped() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    let when = at("12:00");
    let observations = vec![
        lease_observation(vrf, "192.0.2.10", when),
        lease_observation(vrf, "192.0.2.11", when),
        Observation {
            subject: Observed::Vendor {
                mac: lease_mac(),
                vendor: "MSFT 5.0".to_owned(),
            },
            ..lease_observation(vrf, "192.0.2.10", when)
        },
    ];
    let report = observe::ingest(
        &store,
        &IngestBatch {
            source: dhcp_source(),
            observations,
            complete: false,
            received_at: when,
        },
        &ObserveConfig::default(),
    )
    .await
    .expect("ingest");
    assert_eq!(
        (report.new, report.changed, report.refreshed, report.skipped),
        (0, 0, 0, 3)
    );
    assert!(!report.wrote(), "{report:?}");
    assert!(facts(&store).await.is_empty(), "no fact row");
    assert_eq!(rows(&store).await, (0, 0, 0));

    // A lease observation inside the batch of another source is skipped on its own; the
    // other observations of the batch are written.
    let connector = ConnectorId::generate();
    let report = observe::ingest(
        &store,
        &batch(
            connector,
            vec![
                lease_observation(vrf, "192.0.2.12", when),
                host("101", "192.0.2.10", when, connector),
            ],
            when,
        ),
        &ObserveConfig::default(),
    )
    .await
    .expect("ingest");
    assert_eq!((report.new, report.skipped), (1, 1));
    let stored = facts(&store).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].source_key, format!("inventory:{connector}"));
}

#[tokio::test]
async fn a_complete_batch_of_a_lease_source_expires_nothing() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    store_legacy_lease_fact(&store, vrf, "192.0.2.10", lease_mac()).await;
    let before = facts(&store).await;
    assert_eq!(before.len(), 1);
    let revision = store.status().revision;

    // An empty complete batch would have expired every fact of its source.
    let empty = observe::ingest(
        &store,
        &IngestBatch {
            source: dhcp_source(),
            observations: Vec::new(),
            complete: true,
            received_at: at("13:00"),
        },
        &ObserveConfig::default(),
    )
    .await
    .expect("ingest");
    assert_eq!((empty.gone, empty.skipped), (0, 0));
    assert!(!empty.wrote(), "{empty:?}");

    // So would a complete batch that reports another address.
    let other = observe::ingest(
        &store,
        &IngestBatch {
            source: dhcp_source(),
            observations: vec![lease_observation(vrf, "192.0.2.11", at("13:00"))],
            complete: true,
            received_at: at("13:00"),
        },
        &ObserveConfig::default(),
    )
    .await
    .expect("ingest");
    assert_eq!((other.gone, other.skipped), (0, 1));
    assert!(!other.wrote(), "{other:?}");

    assert_eq!(store.status().revision, revision, "nothing was committed");
    assert_eq!(facts(&store).await, before);
    assert!(before[0].is_current(at("12:30")));
}

#[tokio::test]
async fn the_stored_facts_never_return_a_stored_fact_of_a_lease_source() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    store_legacy_lease_fact(&store, vrf, "192.0.2.10", lease_mac()).await;
    // A fact of another source for another address stays visible.
    let connector = ConnectorId::generate();
    observe::ingest(
        &store,
        &batch(
            connector,
            vec![host("101", "192.0.2.50", at("12:00"), connector)],
            at("12:00"),
        ),
        &ObserveConfig::default(),
    )
    .await
    .expect("ingest");
    assert_eq!(facts(&store).await.len(), 2, "both rows are stored");

    let view = store.read(ReadConsistency::Local).await.expect("view");
    let now = at("12:10");
    let sources = |found: Vec<ObservedFact>| {
        found
            .into_iter()
            .map(|fact| fact.source_key)
            .collect::<Vec<_>>()
    };
    let inventory = vec![format!("inventory:{connector}")];

    assert_eq!(
        sources(StoredFacts.facts(view.as_ref(), now).expect("facts")),
        inventory
    );
    // The index rows of the lease fact exist, and are not followed.
    let ip = "192.0.2.10".parse().expect("ip");
    for naming in [Naming::Ip(ip), Naming::Mac(lease_mac())] {
        assert!(
            StoredFacts
                .facts_naming(view.as_ref(), &naming, now)
                .expect("naming")
                .is_empty(),
            "{naming:?}"
        );
    }
    // The host's own names are found.
    assert_eq!(
        sources(
            StoredFacts
                .facts_naming(
                    view.as_ref(),
                    &Naming::Ip("192.0.2.50".parse().expect("ip")),
                    now
                )
                .expect("naming")
        ),
        inventory
    );
    let net = "192.0.2.0/24".parse().expect("net");
    assert_eq!(
        sources(
            StoredFacts
                .facts_within(view.as_ref(), &net, now)
                .expect("within")
        ),
        inventory
    );

    // Through the join of the readers, without a lease view, the lease fact is not seen.
    let observations = Observations::new(view.as_ref(), None);
    assert_eq!(sources(observations.facts(now).expect("facts")), inventory);
    assert!(
        observations
            .current_at(ip, now)
            .expect("current")
            .is_empty(),
        "no current fact"
    );
}

#[tokio::test]
async fn the_lease_view_stands_for_a_stored_fact_of_an_older_version() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    // The stored fact names another MAC address than the lease row does.
    let stale: MacAddr = "00:00:5e:00:53:99".parse().expect("mac");
    store_legacy_lease_fact(&store, vrf, "192.0.2.10", stale).await;
    let granted = at("11:30");
    let lease = Lease {
        addr: "192.0.2.10".parse().expect("addr"),
        vrf,
        scope: PrefixId::generate(),
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20]),
            client_id: None,
        },
        state: BindingState::Active,
        cltt: at("12:00"),
        ends: at("13:00"),
        tstp: None,
        tsfp: None,
        atsfp: None,
        node: DHCP_NODE,
        share: None,
        hostname: None,
        fqdn: None,
        fqdn_flags: None,
        ddns_policy: None,
        ddns: DdnsState::default(),
        fingerprint: None,
        relay: None,
        observed_at: None,
        granted: Some(granted),
    };
    let mut write = WriteBatch::new(Principal::system(SystemComponent::Dhcp), at("12:00"));
    write
        .put_typed(&lease_tables::LEASES, &(vrf, lease.addr), &lease)
        .expect("lease");
    let committed = store.propose(write).await.expect("commit");

    let view = store.read(ReadConsistency::Local).await.expect("view");
    let lease_view = LeaseFacts::new(ObserveConfig::default());
    let observations = Observations::new(view.as_ref(), Some(lease_view.as_ref()));
    let found = observations.facts(at("12:10")).expect("facts");
    let leased: Vec<_> = found
        .iter()
        .filter(|fact| fact.source_key == "dhcp:7")
        .collect();
    assert_eq!(leased.len(), 1, "{found:?}");
    let fact = leased[0];
    assert_eq!(
        fact.observed,
        Observed::Address {
            vrf,
            ip: "192.0.2.10".parse().expect("ip"),
            mac: Some(lease_mac()),
        }
    );
    assert_eq!(
        (fact.first_seen, fact.revision),
        (granted, committed.revision)
    );
    // By name, the stale MAC address finds nothing and the lease's finds the fact.
    assert!(
        observations
            .facts_naming(&Naming::Mac(stale), at("12:10"))
            .expect("naming")
            .is_empty(),
        "the stale MAC address names nothing"
    );
    let by_mac = observations
        .facts_naming(&Naming::Mac(lease_mac()), at("12:10"))
        .expect("naming");
    assert_eq!(by_mac.len(), 1);
    let current = observations
        .current_at("192.0.2.10".parse().expect("ip"), at("12:10"))
        .expect("current");
    assert_eq!(current.len(), 1);
    assert_eq!(lease_view.builds(), 1, "built on the first read");
}
