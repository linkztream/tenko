//! The guesses and the last sightings of the findings view read the facts of an address
//! through an index, not by walking every fact.

use tenko_core::{ConnectorId, ObservationId, observe::ObservedHost};

use super::super::{names::Authorities, snapshot::Intent};
use crate::observe::FactSubject;

use super::{
    super::snapshot::{FactIndex, VISITED},
    *,
};

fn ip(n: usize) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::from(
        0x0a00_0000 + u32::try_from(n).expect("small"),
    ))
}

fn fact(observed: Observed) -> ObservedFact {
    let at: Timestamp = "2026-10-10T12:00:00Z".parse().expect("time");
    let subject = FactSubject::of(&observed);
    ObservedFact {
        source: ObservationSource::Inventory {
            connector: ConnectorId::generate(),
        },
        source_key: "inventory:example".to_owned(),
        subject_key: subject.key(),
        subject,
        observed,
        observation: ObservationId::generate(),
        first_seen: at,
        last_seen: at,
        received_at: at,
        expires_at: None,
        sightings: 1,
        counted_at: None,
        revision: tenko_core::Revision::ZERO,
    }
}

/// A snapshot of `facts` and nothing else.
fn snapshot(facts: Vec<ObservedFact>) -> Snapshot {
    let now: Timestamp = "2026-10-10T12:00:00Z".parse().expect("time");
    Snapshot {
        now,
        intent: Intent::default(),
        os_facts: FactIndex::of(
            facts.iter().enumerate().filter(|(_, fact)| {
                matches!(fact.observed, Observed::Host(_) | Observed::Os { .. })
            }),
        ),
        sighting_facts: FactIndex::of(facts.iter().enumerate()),
        facts,
        seen: Vec::new(),
        name_facts: BTreeMap::new(),
        authorities: Authorities::default(),
        open: BTreeMap::new(),
        rejections: BTreeMap::new(),
        policies: BTreeMap::new(),
        sightings: BTreeMap::new(),
        vendors: BTreeMap::new(),
        scopes: Vec::new(),
        networks: Vec::new(),
        dormant: Vec::new(),
        artifacts: Vec::new(),
    }
}

fn os_facts(n: usize) -> Vec<ObservedFact> {
    (0..n)
        .map(|at| {
            fact(Observed::Os {
                ip: ip(at),
                guess: format!("os {at}"),
                confidence: 50,
            })
        })
        .collect()
}

/// The facts the guesses of every row looked at.
fn visited_for(rows: usize) -> usize {
    let snapshot = snapshot(os_facts(rows));
    VISITED.with(|visited| visited.set(0));
    for at in 0..rows {
        let guesses = os_guesses(&snapshot, &BTreeSet::from([ip(at)]), &BTreeSet::new());
        assert_eq!(guesses.len(), 1);
    }
    VISITED.with(std::cell::Cell::get)
}

#[test]
fn the_facts_the_guesses_look_at_grow_with_the_rows_not_with_rows_times_facts() {
    assert_eq!(visited_for(100), 100);
    assert_eq!(visited_for(400), 400);
}

#[test]
fn a_host_found_by_its_address_and_its_mac_address_counts_once() {
    let mac: MacAddr = "00:00:5e:00:53:01".parse().expect("mac");
    let snapshot = snapshot(vec![fact(Observed::Host(ObservedHost {
        external_id: "h1".to_owned(),
        macs: vec![mac],
        ips: vec![ip(1)],
        os: Some("Debian 12".to_owned()),
        ..ObservedHost::default()
    }))]);
    let guesses = os_guesses(&snapshot, &BTreeSet::from([ip(1)]), &BTreeSet::from([mac]));
    assert_eq!(guesses.len(), 1);
    assert_eq!(guesses[0].guess, "Debian 12");
}
