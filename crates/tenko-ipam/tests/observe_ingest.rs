//! Ingest and retention of observations: one write per poll at most, idempotent repeats,
//! refresh and sighting counts, expiry by complete batches (empty ones too), several
//! sources side by side, and the purge of old facts and stale sightings.

use std::{sync::Arc, time::Duration};

use tenko_core::{
    ConnectorId, NodeId, ObjectRef, ObservationId, Principal, SystemComponent, Timestamp, VrfId,
    observe::{Observation, ObservationSource, Observed, ObservedHost, ProbeMethod},
};
use tenko_ipam::observe::{
    self, IngestBatch, IntentSighting, ObserveConfig,
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
