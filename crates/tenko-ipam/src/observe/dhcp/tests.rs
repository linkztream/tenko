//! The lease view (ADR 0031) against the in-memory store: the facts each kind of lease row
//! stands for, the build from the lease tables, the follower of the store's journal and the
//! rebuild after a stream that ends with `Lagged` or `Compacted`.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tenko_core::{
    AddressId, ObjectRef, ObservationId, PrefixId, Principal, SystemComponent,
    dhcp::{BindingState, ClientKey, DdnsState, Fingerprint},
    net::Duid,
    observe::NetworkDhcp,
    serde_util::HexBytes,
};
use tenko_store::{MemStore, WatchError, WriteBatch};

use super::*;
use crate::observe::{model::IntentSighting, source::FactSource, tables::LAST_SEEN};

const NODE: NodeId = NodeId(7);
const IP4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 15);

fn at(minutes: u64) -> Timestamp {
    "2026-10-22T08:00:00Z"
        .parse::<Timestamp>()
        .expect("time")
        .checked_add(Duration::from_secs(minutes * 60))
        .expect("time")
}

fn mac(last: u8) -> MacAddr {
    format!("00:00:5e:00:53:{last:02x}").parse().expect("mac")
}

/// An active lease of `IP4` held by the Ethernet client `00:00:5e:00:53:<last>` for an
/// hour, named `printer`, granted at its client transaction time.
fn lease(vrf: VrfId, last: u8, cltt: Timestamp, state: BindingState) -> Lease {
    Lease {
        addr: IP4,
        vrf,
        scope: PrefixId::generate(),
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, last]),
            client_id: None,
        },
        state,
        cltt,
        ends: cltt.checked_add(Duration::from_secs(3_600)).expect("end"),
        tstp: None,
        tsfp: None,
        atsfp: None,
        node: NODE,
        share: None,
        hostname: Some("printer".to_owned()),
        fqdn: None,
        fqdn_flags: None,
        ddns_policy: None,
        ddns: DdnsState::default(),
        fingerprint: None,
        relay: None,
        observed_at: None,
        granted: None,
    }
}

/// An `IA_NA` lease of `2001:db8::50` for the client `00:00:5e:00:53:20`.
fn lease6(vrf: VrfId, cltt: Timestamp, state: BindingState) -> Lease6 {
    Lease6 {
        addr: "2001:db8::50".parse::<Ipv6Addr>().expect("addr").into(),
        prefix_len: 128,
        kind: Lease6Kind::Na,
        vrf,
        scope: PrefixId::generate(),
        iaid: 1,
        duid: Duid::new(vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x20]).expect("a DUID"),
        link_layer: Some(HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20])),
        link_layer_type: Some(1),
        state,
        cltt,
        ends: cltt.checked_add(Duration::from_secs(3_600)).expect("end"),
        preferred_ends: cltt.checked_add(Duration::from_secs(1_800)).expect("end"),
        node: NODE,
        fqdn: None,
        fqdn_flags: None,
        relay: None,
        observed_at: None,
        ddns: DdnsState::default(),
        granted: None,
    }
}

/// A delegated prefix `2001:db8:1:100::/56` for the client `00:00:5e:00:53:20`.
fn delegation(vrf: VrfId, cltt: Timestamp, state: BindingState) -> Lease6 {
    Lease6 {
        addr: "2001:db8:1:100::".parse::<Ipv6Addr>().expect("addr").into(),
        prefix_len: 56,
        kind: Lease6Kind::Pd,
        ..lease6(vrf, cltt, state)
    }
}

fn fingerprinted(row: &mut Lease, vendor: &str) {
    row.fingerprint = Some(Fingerprint {
        parameters: HexBytes(vec![
            1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252,
        ]),
        vendor_class: Some(vendor.to_owned()),
        ..Fingerprint::default()
    });
}

/// A classifier that knows one fingerprint: the vendor class of Windows.
struct Windows;

impl LeaseClassifier for Windows {
    fn os(&self, fingerprint: &Fingerprint) -> Option<OsReading> {
        (fingerprint.vendor_class.as_deref().map(str::trim) == Some("MSFT 5.0")).then(|| {
            OsReading {
                guess: "Windows 10 or 11".to_owned(),
                confidence: 85,
            }
        })
    }
}

/// Commits what `fill` puts in a batch and returns the revision.
async fn commit(store: &Arc<dyn Store>, fill: impl FnOnce(&mut WriteBatch)) -> Revision {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), at(0));
    fill(&mut batch);
    store.propose(batch).await.expect("commit").revision
}

async fn put(store: &Arc<dyn Store>, lease: &Lease) -> Revision {
    commit(store, |batch| {
        batch
            .put_typed(&tables::LEASES, &(lease.vrf, lease.addr), lease)
            .expect("put");
    })
    .await
}

async fn put6(store: &Arc<dyn Store>, lease: &Lease6) -> Revision {
    commit(store, |batch| {
        batch
            .put_typed(&tables::LEASES6, &(lease.vrf, lease.addr6()), lease)
            .expect("put");
    })
    .await
}

/// A store and a view of its leases without a follower: every read of the facts builds the
/// view from a view of the store that is newer.
struct World {
    store: Arc<dyn Store>,
    leases: Arc<LeaseFacts>,
}

impl World {
    fn new() -> Self {
        Self {
            store: Arc::new(MemStore::default()),
            leases: LeaseFacts::new(ObserveConfig::default()),
        }
    }

    async fn put(&self, lease: &Lease) -> Revision {
        put(&self.store, lease).await
    }

    async fn put6(&self, lease: &Lease6) -> Revision {
        put6(&self.store, lease).await
    }

    /// The facts at `now`, ordered by source and subject.
    async fn facts(&self, now: Timestamp) -> Vec<ObservedFact> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        self.leases.ensure(view.as_ref()).expect("ensure");
        let mut facts = self.leases.facts(now);
        facts.sort_by(|a, b| (&a.source_key, &a.subject_key).cmp(&(&b.source_key, &b.subject_key)));
        facts
    }
}

/// The fact of one subject.
fn subject<'a>(facts: &'a [ObservedFact], key: &str) -> &'a ObservedFact {
    facts
        .iter()
        .find(|fact| fact.subject_key == key)
        .unwrap_or_else(|| panic!("no fact of {key} in {facts:?}"))
}

fn has(facts: &[ObservedFact], key: &str) -> bool {
    facts.iter().any(|fact| fact.subject_key == key)
}

fn address_key(vrf: VrfId, ip: impl std::fmt::Display) -> String {
    format!("address:{vrf}/{ip}")
}

fn mac_of(fact: &ObservedFact) -> Option<MacAddr> {
    let Observed::Address { mac, .. } = &fact.observed else {
        panic!("an address fact, not {fact:?}");
    };
    *mac
}

// The rules of the view.

#[test]
fn an_empty_view_gives_no_fact() {
    let view = LeaseFacts::new(ObserveConfig::default());
    assert!(view.facts(Timestamp::now()).is_empty(), "an empty view");
    assert!(view.is_empty());
    assert_eq!((view.builds(), view.is_following()), (0, false));
}

#[tokio::test]
async fn an_active_lease_gives_an_address_fact_with_the_mac_and_a_name_fact() {
    let world = World::new();
    let vrf = VrfId::generate();
    let mut row = lease(vrf, 0x20, at(0), BindingState::Active);
    row.hostname = Some("printer".to_owned());
    row.fqdn = Some("printer.example.test.".to_owned());
    let revision = world.put(&row).await;

    let facts = world.facts(at(10)).await;
    assert_eq!(facts.len(), 2, "{facts:?}");
    let address = subject(&facts, &address_key(vrf, IP4));
    assert_eq!(address.source_key, "dhcp:7");
    assert_eq!(address.source, ObservationSource::DhcpLease { node: NODE });
    assert_eq!(mac_of(address), Some(mac(0x20)));
    assert_eq!(address.expires_at, Some(row.ends));
    assert_eq!(address.revision, revision);
    assert!(address.is_current(at(59)));
    assert!(
        !address.is_current(row.ends),
        "current until `ends`, not at it"
    );

    // The FQDN of option 81 wins over the host name of option 12; the trailing dot goes.
    let name = subject(&facts, &format!("name:{IP4}"));
    let Observed::Name { ip, name: text, .. } = &name.observed else {
        panic!("a name fact, not {name:?}");
    };
    assert_eq!(
        (*ip, text.as_str()),
        (IpAddr::V4(IP4), "printer.example.test")
    );
    assert_eq!(name.expires_at, Some(row.ends));
    assert_eq!(name.source_key, "dhcp:7");
}

#[tokio::test]
async fn the_host_name_is_the_name_when_the_client_sent_no_fqdn() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .put(&lease(vrf, 0x20, at(0), BindingState::Active))
        .await;
    let facts = world.facts(at(1)).await;
    let Observed::Name { name, .. } = &subject(&facts, &format!("name:{IP4}")).observed else {
        panic!("a name fact");
    };
    assert_eq!(name, "printer");

    // A client that sent no name has no name fact.
    let mut nameless = lease(vrf, 0x20, at(5), BindingState::Active);
    nameless.hostname = None;
    world.put(&nameless).await;
    let facts = world.facts(at(6)).await;
    assert!(!has(&facts, &format!("name:{IP4}")), "{facts:?}");
    assert!(has(&facts, &address_key(vrf, IP4)));
}

#[tokio::test]
async fn a_renewal_keeps_the_grant_time_and_the_sightings_count_one_per_refresh_interval() {
    let world = World::new();
    let vrf = VrfId::generate();
    let key = address_key(vrf, IP4);
    let renewed = |cltt: Timestamp| {
        let mut row = lease(vrf, 0x20, cltt, BindingState::Active);
        row.granted = Some(at(0));
        row
    };

    let revision = world.put(&renewed(at(0))).await;
    let facts = world.facts(at(59)).await;
    let first = subject(&facts, &key);
    assert_eq!(
        (first.first_seen, first.last_seen, first.sightings),
        (at(0), at(0), 1)
    );
    assert_eq!(first.received_at, at(0));

    // Ten minutes: inside the interval, still one sighting; the grant time stays.
    let later = world.put(&renewed(at(10))).await;
    assert!(later > revision);
    let facts = world.facts(at(59)).await;
    let fact = subject(&facts, &key);
    assert_eq!(
        (fact.first_seen, fact.last_seen, fact.sightings),
        (at(0), at(10), 1)
    );
    assert_eq!(fact.revision, later, "the revision is the row's");
    assert_eq!(
        fact.expires_at,
        Some(at(70)),
        "the end of the renewed binding"
    );

    // One interval: a second sighting.
    world.put(&renewed(at(15))).await;
    let facts = world.facts(at(59)).await;
    let fact = subject(&facts, &key);
    assert_eq!((fact.last_seen, fact.sightings), (at(15), 2));
    assert_eq!(fact.counted_at, Some(at(15)));

    // Fifty minutes: the grant plus three intervals.
    world.put(&renewed(at(50))).await;
    let facts = world.facts(at(59)).await;
    let fact = subject(&facts, &key);
    assert_eq!(
        (fact.first_seen, fact.last_seen, fact.sightings),
        (at(0), at(50), 4)
    );
    assert_eq!(fact.counted_at, Some(at(45)));

    // The name fact counts the same way.
    let name = subject(&facts, &format!("name:{IP4}"));
    assert_eq!((name.first_seen, name.sightings), (at(0), 4));

    // The view never reports a sighting from after the time it is read at.
    let early = world.facts(at(20)).await;
    let fact = subject(&early, &key);
    assert_eq!((fact.last_seen, fact.sightings), (at(20), 2));
}

#[tokio::test]
async fn a_lease_row_without_a_grant_time_reads_as_granted_at_its_cltt() {
    let world = World::new();
    let vrf = VrfId::generate();
    let key = address_key(vrf, IP4);
    let mut row = lease(vrf, 0x20, at(20), BindingState::Active);
    assert_eq!(row.granted, None);
    world.put(&row).await;
    let facts = world.facts(at(30)).await;
    let fact = subject(&facts, &key);
    assert_eq!(
        (fact.first_seen, fact.last_seen, fact.sightings),
        (at(20), at(20), 1)
    );

    // A grant time after the client transaction time is not believed.
    row.granted = Some(at(40));
    world.put(&row).await;
    let facts = world.facts(at(50)).await;
    assert_eq!(subject(&facts, &key).first_seen, at(20));
}

#[tokio::test]
async fn an_abandoned_row_gives_the_answering_mac_until_its_hold_ends_and_no_name() {
    let world = World::new();
    world.leases.set_classifier(Arc::new(Windows));
    let vrf = VrfId::generate();
    // An ARP answer from another device (WP8.5 stores its MAC as the row's chaddr).
    let mut conflict = lease(vrf, 0x2a, at(5), BindingState::Abandoned);
    conflict.ends = at(65);
    fingerprinted(&mut conflict, "MSFT 5.0");
    world.put(&conflict).await;

    let facts = world.facts(at(30)).await;
    assert_eq!(facts.len(), 1, "no name, OS or vendor fact: {facts:?}");
    let fact = subject(&facts, &address_key(vrf, IP4));
    assert_eq!(mac_of(fact), Some(mac(0x2a)));
    assert_eq!(fact.expires_at, Some(at(65)));
    assert!(fact.is_current(at(64)));
    assert!(!fact.is_current(at(65)));

    // An ICMP answer or a DECLINE carries no client: the fact names no MAC.
    let mut icmp = conflict.clone();
    icmp.client = ClientKey {
        htype: 0,
        chaddr: HexBytes(Vec::new()),
        client_id: None,
    };
    icmp.cltt = at(6);
    world.put(&icmp).await;
    let facts = world.facts(at(30)).await;
    assert_eq!(facts.len(), 1, "{facts:?}");
    assert_eq!(mac_of(subject(&facts, &address_key(vrf, IP4))), None);
}

#[tokio::test]
async fn a_released_or_expired_row_gives_facts_that_are_not_current() {
    let world = World::new();
    world.leases.set_classifier(Arc::new(Windows));
    let vrf = VrfId::generate();

    // Released at 5 minutes, the hold would have run to 65: expired at the release.
    let mut released = lease(vrf, 0x20, at(5), BindingState::Released);
    fingerprinted(&mut released, "MSFT 5.0");
    world.put(&released).await;
    // Expired with a transaction time after its end: expired at the end.
    let mut expired = lease(vrf, 0x21, at(100), BindingState::Expired);
    expired.addr = Ipv4Addr::new(198, 51, 100, 16);
    expired.ends = at(60);
    fingerprinted(&mut expired, "MSFT 5.0");
    world.put(&expired).await;

    let facts = world.facts(at(200)).await;
    // Per row: address, name, OS and vendor facts.
    assert_eq!(facts.len(), 8, "{facts:?}");
    for fact in facts
        .iter()
        .filter(|fact| fact.ips().contains(&IpAddr::V4(IP4)))
    {
        assert_eq!(fact.expires_at, Some(at(5)), "{fact:?}");
        assert!(
            fact.is_current(at(4)) && !fact.is_current(at(5)),
            "{fact:?}"
        );
    }
    for fact in facts.iter().filter(|fact| {
        fact.ips()
            .contains(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 16)))
    }) {
        assert_eq!(fact.expires_at, Some(at(60)), "{fact:?}");
        assert!(!fact.is_current(at(100)), "{fact:?}");
    }
    // The vendor fact is keyed by the MAC address and ended with its row.
    let vendor = subject(&facts, &format!("vendor:{}", mac(0x20)));
    assert_eq!(vendor.expires_at, Some(at(5)));
    assert!(facts.iter().all(|fact| !fact.is_current(at(200))));

    // A reclaimed (reset) row is the same.
    let mut reset = lease(vrf, 0x22, at(30), BindingState::Reset);
    reset.addr = Ipv4Addr::new(198, 51, 100, 17);
    world.put(&reset).await;
    let facts = world.facts(at(200)).await;
    let fact = subject(&facts, &address_key(vrf, Ipv4Addr::new(198, 51, 100, 17)));
    assert_eq!(fact.expires_at, Some(at(30)));
}

#[tokio::test]
async fn a_free_or_backup_row_gives_no_fact() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .put(&lease(vrf, 0x20, at(0), BindingState::Free))
        .await;
    let mut backup = lease(vrf, 0x21, at(0), BindingState::Backup);
    backup.addr = Ipv4Addr::new(198, 51, 100, 16);
    world.put(&backup).await;
    assert!(world.facts(at(1)).await.is_empty(), "no fact");
    assert!(world.leases.is_empty(), "the view keeps no entry for them");
}

#[tokio::test]
async fn a_classifier_gives_the_os_fact_and_option_60_the_vendor_fact() {
    let world = World::new();
    assert!(world.leases.set_classifier(Arc::new(Windows)));
    assert!(
        !world.leases.set_classifier(Arc::new(Windows)),
        "the classifier is set once"
    );
    let vrf = VrfId::generate();
    let mut row = lease(vrf, 0x20, at(0), BindingState::Active);
    fingerprinted(&mut row, "  MSFT 5.0 ");
    world.put(&row).await;
    // A client without an Ethernet address: the OS fact stays, there is no vendor fact.
    let mut bare = lease(vrf, 0x21, at(0), BindingState::Active);
    bare.addr = Ipv4Addr::new(198, 51, 100, 16);
    bare.client = ClientKey {
        htype: 0,
        chaddr: HexBytes(Vec::new()),
        client_id: Some(HexBytes(vec![0x01, 0x02, 0x03])),
    };
    fingerprinted(&mut bare, "MSFT 5.0");
    world.put(&bare).await;

    let facts = world.facts(at(10)).await;
    let os = subject(&facts, &format!("os:{IP4}"));
    assert_eq!(
        os.observed,
        Observed::Os {
            ip: IP4.into(),
            guess: "Windows 10 or 11".to_owned(),
            confidence: 85,
        }
    );
    assert_eq!(
        (os.source_key.as_str(), os.expires_at),
        ("dhcp:7", Some(row.ends))
    );
    let vendor = subject(&facts, &format!("vendor:{}", mac(0x20)));
    assert_eq!(
        vendor.observed,
        Observed::Vendor {
            mac: mac(0x20),
            vendor: "MSFT 5.0".to_owned(),
        }
    );
    assert!(has(&facts, "os:198.51.100.16"));
    assert_eq!(
        facts
            .iter()
            .filter(|fact| fact.subject_key.starts_with("vendor:"))
            .count(),
        1,
        "{facts:?}"
    );

    // A vendor class the classifier does not know: a vendor fact, no OS guess.
    let mut other = lease(vrf, 0x20, at(5), BindingState::Active);
    fingerprinted(&mut other, "udhcp 1.35.0");
    world.put(&other).await;
    let facts = world.facts(at(10)).await;
    assert!(!has(&facts, &format!("os:{IP4}")), "{facts:?}");
    let Observed::Vendor { vendor, .. } =
        &subject(&facts, &format!("vendor:{}", mac(0x20))).observed
    else {
        panic!("a vendor fact");
    };
    assert_eq!(vendor, "udhcp 1.35.0");
}

#[tokio::test]
async fn without_a_classifier_there_is_no_os_fact() {
    let world = World::new();
    let vrf = VrfId::generate();
    let mut row = lease(vrf, 0x20, at(0), BindingState::Active);
    fingerprinted(&mut row, "MSFT 5.0");
    world.put(&row).await;
    let facts = world.facts(at(10)).await;
    assert!(
        facts
            .iter()
            .all(|fact| !fact.subject_key.starts_with("os:")),
        "{facts:?}"
    );
    // The vendor class is a fact without any classifier.
    assert!(has(&facts, &format!("vendor:{}", mac(0x20))));
    assert_eq!(lease_vendor(&row).as_deref(), Some("MSFT 5.0"));
}

#[tokio::test]
async fn setting_the_classifier_of_a_view_without_a_follower_gives_the_guess_to_the_next_read() {
    let world = World::new();
    let vrf = VrfId::generate();
    let mut row = lease(vrf, 0x20, at(0), BindingState::Active);
    fingerprinted(&mut row, "MSFT 5.0");
    world.put(&row).await;
    assert!(!has(&world.facts(at(1)).await, &format!("os:{IP4}")));
    world.leases.set_classifier(Arc::new(Windows));
    assert!(has(&world.facts(at(1)).await, &format!("os:{IP4}")));
}

#[tokio::test]
async fn the_source_key_is_dhcp_and_the_node_of_the_row() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .put(&lease(vrf, 0x20, at(0), BindingState::Active))
        .await;
    let mut other = lease(vrf, 0x21, at(0), BindingState::Active);
    other.addr = Ipv4Addr::new(198, 51, 100, 16);
    other.node = NodeId(8);
    other.hostname = None;
    world.put(&other).await;

    let facts = world.facts(at(1)).await;
    let first = subject(&facts, &address_key(vrf, IP4));
    let second = subject(&facts, &address_key(vrf, other.addr));
    assert_eq!(first.source_key, "dhcp:7");
    assert_eq!(
        first.source,
        ObservationSource::DhcpLease { node: NodeId(7) }
    );
    assert_eq!(second.source_key, "dhcp:8");
    assert_eq!(
        second.source,
        ObservationSource::DhcpLease { node: NodeId(8) }
    );
    let mut sources: Vec<_> = facts.iter().map(|fact| fact.source_key.as_str()).collect();
    sources.sort_unstable();
    sources.dedup();
    assert_eq!(sources, ["dhcp:7", "dhcp:8"]);
}

#[tokio::test]
async fn a_dhcpv6_address_lease_gives_the_address_fact_with_the_mac_of_its_link_layer() {
    let world = World::new();
    let vrf = VrfId::generate();
    let mut row = lease6(vrf, at(0), BindingState::Active);
    row.fqdn = Some("host6.example.test.".to_owned());
    let revision = world.put6(&row).await;

    let facts = world.facts(at(10)).await;
    assert_eq!(facts.len(), 2, "{facts:?}");
    let address = subject(&facts, &address_key(vrf, "2001:db8::50"));
    assert_eq!(
        address.observed,
        Observed::Address {
            vrf,
            ip: "2001:db8::50".parse().expect("ip"),
            mac: Some(mac(0x20)),
        }
    );
    assert_eq!(
        (address.source_key.as_str(), address.revision),
        ("dhcp:7", revision)
    );
    assert_eq!(address.expires_at, Some(row.ends));
    // The name of RFC 4704, without the trailing dot.
    let name = subject(&facts, "name:2001:db8::50");
    let Observed::Name { name, .. } = &name.observed else {
        panic!("a name fact");
    };
    assert_eq!(name, "host6.example.test");

    // A link layer that is not Ethernet, or none: the address fact names no MAC.
    let mut other = lease6(vrf, at(0), BindingState::Active);
    other.addr = "2001:db8::51".parse::<Ipv6Addr>().expect("addr").into();
    other.link_layer_type = Some(32);
    world.put6(&other).await;
    let mut bare = lease6(vrf, at(0), BindingState::Active);
    bare.addr = "2001:db8::52".parse::<Ipv6Addr>().expect("addr").into();
    bare.link_layer = None;
    bare.link_layer_type = None;
    world.put6(&bare).await;
    let facts = world.facts(at(10)).await;
    for ip in ["2001:db8::51", "2001:db8::52"] {
        assert_eq!(mac_of(subject(&facts, &address_key(vrf, ip))), None, "{ip}");
    }

    // A DHCPv6 DECLINE (an abandoned row) is a conflict without a MAC address or a name.
    let mut declined = lease6(vrf, at(5), BindingState::Abandoned);
    declined.addr = "2001:db8::53".parse::<Ipv6Addr>().expect("addr").into();
    declined.fqdn = Some("host6.example.test".to_owned());
    world.put6(&declined).await;
    let facts = world.facts(at(10)).await;
    assert_eq!(
        mac_of(subject(&facts, &address_key(vrf, "2001:db8::53"))),
        None
    );
    assert!(!has(&facts, "name:2001:db8::53"));
}

#[tokio::test]
async fn a_delegated_prefix_gives_a_network_fact_and_no_name() {
    let world = World::new();
    let vrf = VrfId::generate();
    // Even with a name the client sent, a delegation gives no address or name fact.
    let mut row = delegation(vrf, at(0), BindingState::Active);
    row.fqdn = Some("router.example.net.".to_owned());
    world.put6(&row).await;

    let facts = world.facts(at(10)).await;
    assert_eq!(facts.len(), 1, "{facts:?}");
    let fact = subject(
        &facts,
        &format!("network:dhcp-pd/{vrf}/2001:db8:1:100::/56"),
    );
    assert_eq!(fact.source_key, "dhcp:7");
    assert_eq!(fact.expires_at, Some(row.ends));
    assert_eq!(
        fact.observed,
        Observed::Network {
            controller: format!("dhcp-pd/{vrf}/2001:db8:1:100::/56"),
            name: "delegated to 00:00:5e:00:53:20".to_owned(),
            subnet: Some("2001:db8:1:100::/56".parse().expect("prefix")),
            vlan: None,
            dhcp: NetworkDhcp::Server,
            management: false,
        }
    );

    // A client without a MAC address is named by its DUID.
    let mut bare = delegation(vrf, at(0), BindingState::Active);
    bare.addr = "2001:db8:2:100::".parse::<Ipv6Addr>().expect("addr").into();
    bare.link_layer = None;
    bare.link_layer_type = None;
    world.put6(&bare).await;
    let facts = world.facts(at(10)).await;
    let Observed::Network { name, .. } = &subject(
        &facts,
        &format!("network:dhcp-pd/{vrf}/2001:db8:2:100::/56"),
    )
    .observed
    else {
        panic!("a network fact");
    };
    assert_eq!(name, "delegated to DUID 0003000100005e005320");

    // A released delegation stands for an expired fact.
    let mut released = delegation(vrf, at(5), BindingState::Released);
    released.ends = at(5);
    world.put6(&released).await;
    let facts = world.facts(at(10)).await;
    let fact = subject(
        &facts,
        &format!("network:dhcp-pd/{vrf}/2001:db8:1:100::/56"),
    );
    assert!(!fact.is_current(at(5)));
}

#[tokio::test]
async fn the_observation_id_is_stable_for_a_binding_and_changes_with_a_new_grant_or_another_mac() {
    let key_of = |vrf| address_key(vrf, IP4);
    let vrf = VrfId::generate();
    let row = |last: u8, cltt: Timestamp, granted: Timestamp| {
        let mut row = lease(vrf, last, cltt, BindingState::Active);
        row.granted = Some(granted);
        row
    };
    let world = World::new();
    world.put(&row(0x20, at(0), at(0))).await;
    let facts = world.facts(at(59)).await;
    let first = subject(&facts, &key_of(vrf)).observation;
    let first_name = subject(&facts, &format!("name:{IP4}")).observation;
    assert_ne!(first, first_name, "one id per fact");

    // The same facts read again, and read from a view built again, carry the same ids.
    let again = world.facts(at(59)).await;
    assert_eq!(subject(&again, &key_of(vrf)).observation, first);
    let rebuilt = LeaseFacts::new(ObserveConfig::default());
    let view = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    rebuilt.build(view.as_ref()).expect("build");
    let facts = rebuilt.facts(at(59));
    assert_eq!(subject(&facts, &key_of(vrf)).observation, first);

    // A renewal of the same binding keeps the id.
    world.put(&row(0x20, at(20), at(0))).await;
    let facts = world.facts(at(59)).await;
    assert_eq!(subject(&facts, &key_of(vrf)).observation, first);

    // A new grant changes it, and so does another client.
    world.put(&row(0x20, at(30), at(30))).await;
    let facts = world.facts(at(59)).await;
    let regranted = subject(&facts, &key_of(vrf)).observation;
    assert_ne!(regranted, first);
    world.put(&row(0x21, at(30), at(30))).await;
    let facts = world.facts(at(59)).await;
    let other = subject(&facts, &key_of(vrf)).observation;
    assert_ne!(other, regranted);
    assert_ne!(other, first);
    // The name did not change with the MAC address.
    assert_eq!(
        subject(&facts, &format!("name:{IP4}")).observation,
        subject(&world.facts(at(59)).await, &format!("name:{IP4}")).observation
    );
}

#[tokio::test]
async fn two_rows_giving_the_same_subject_give_one_fact_the_current_one() {
    let world = World::new();
    world.leases.set_classifier(Arc::new(Windows));
    let vrf = VrfId::generate();
    // The vendor of one MAC address on two leases: the first is bound, the second more
    // recent but released.
    let mut bound = lease(vrf, 0x20, at(0), BindingState::Active);
    fingerprinted(&mut bound, "MSFT 5.0");
    world.put(&bound).await;
    let mut released = lease(vrf, 0x20, at(20), BindingState::Released);
    released.addr = Ipv4Addr::new(198, 51, 100, 16);
    fingerprinted(&mut released, "udhcp 1.35.0");
    world.put(&released).await;

    let vendor_key = format!("vendor:{}", mac(0x20));
    let facts = world.facts(at(25)).await;
    let vendors: Vec<_> = facts
        .iter()
        .filter(|fact| fact.subject_key == vendor_key)
        .collect();
    assert_eq!(vendors.len(), 1, "{facts:?}");
    assert_eq!(
        vendors[0].observed,
        Observed::Vendor {
            mac: mac(0x20),
            vendor: "MSFT 5.0".to_owned(),
        }
    );
    assert!(vendors[0].is_current(at(25)));

    // When neither is current, the most recently seen one stands.
    let facts = world.facts(at(90)).await;
    let vendors: Vec<_> = facts
        .iter()
        .filter(|fact| fact.subject_key == vendor_key)
        .collect();
    assert_eq!(vendors.len(), 1, "{facts:?}");
    let Observed::Vendor { vendor, .. } = &vendors[0].observed else {
        panic!("a vendor fact");
    };
    assert_eq!(vendor, "udhcp 1.35.0");

    // The name of one address in two VRFs is one fact; the address facts stay two.
    let world = World::new();
    let (one, two) = (VrfId::generate(), VrfId::generate());
    world
        .put(&lease(one, 0x20, at(0), BindingState::Active))
        .await;
    world
        .put(&lease(two, 0x21, at(10), BindingState::Active))
        .await;
    let facts = world.facts(at(20)).await;
    assert_eq!(
        facts
            .iter()
            .filter(|fact| fact.subject_key.starts_with("address:"))
            .count(),
        2
    );
    let names: Vec<_> = facts
        .iter()
        .filter(|fact| fact.subject_key == format!("name:{IP4}"))
        .collect();
    assert_eq!(names.len(), 1, "{facts:?}");
    assert_eq!(
        names[0].last_seen,
        at(10),
        "the more recent of two current facts"
    );
}

#[tokio::test]
async fn the_facts_are_found_by_mac_address_ip_address_and_name() {
    let world = World::new();
    world.leases.set_classifier(Arc::new(Windows));
    let vrf = VrfId::generate();
    let mut row = lease(vrf, 0x20, at(0), BindingState::Active);
    row.fqdn = Some("Printer.Example.Test.".to_owned());
    fingerprinted(&mut row, "MSFT 5.0");
    world.put(&row).await;
    world.put6(&lease6(vrf, at(0), BindingState::Active)).await;
    world.facts(at(1)).await;

    let keys = |naming: Naming| {
        let mut keys: Vec<String> = world
            .leases
            .facts_naming(&naming, at(1))
            .into_iter()
            .map(|fact| fact.subject_key)
            .collect();
        keys.sort();
        keys
    };
    // The MAC address is in the address facts of both IP versions and in the vendor fact.
    let mut by_mac = vec![
        address_key(vrf, IP4),
        address_key(vrf, "2001:db8::50"),
        format!("vendor:{}", mac(0x20)),
    ];
    by_mac.sort();
    assert_eq!(keys(Naming::Mac(mac(0x20))), by_mac);
    let mut by_ip = vec![
        address_key(vrf, IP4),
        format!("name:{IP4}"),
        format!("os:{IP4}"),
    ];
    by_ip.sort();
    assert_eq!(keys(Naming::Ip(IP4.into())), by_ip);
    // The name is compared without case.
    assert_eq!(
        keys(Naming::Name("PRINTER.example.test".to_owned())),
        [format!("name:{IP4}")]
    );
    assert!(
        keys(Naming::Name("scanner.example.test".to_owned())).is_empty(),
        "no such name"
    );

    // One fact of one source and subject.
    let fact = world
        .leases
        .fact(
            "dhcp:7",
            &FactSubject::Address {
                vrf,
                ip: IP4.into(),
            },
        )
        .expect("the address fact");
    assert_eq!(mac_of(&fact), Some(mac(0x20)));
    assert!(
        world
            .leases
            .fact(
                "dhcp:8",
                &FactSubject::Address {
                    vrf,
                    ip: IP4.into()
                }
            )
            .is_none()
    );
}

// The view built at start and the reader's `ensure`.

#[tokio::test]
async fn the_view_is_built_from_the_rows_that_exist() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .put(&lease(vrf, 0x20, at(0), BindingState::Active))
        .await;
    let revision = world.put6(&lease6(vrf, at(0), BindingState::Active)).await;
    world
        .put6(&delegation(vrf, at(0), BindingState::Active))
        .await;

    let view = LeaseFacts::new(ObserveConfig::default());
    assert_eq!(view.builds(), 0);
    let read = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    view.build(read.as_ref()).expect("build");
    assert_eq!((view.builds(), view.len()), (1, 3));
    assert_eq!(view.revision(), read.revision());
    assert!(view.revision() > revision);
    // Two address facts, one name fact and the network fact.
    assert_eq!(view.facts(at(1)).len(), 4);

    // Building again replaces what the view holds.
    view.build(read.as_ref()).expect("build");
    assert_eq!((view.builds(), view.len()), (2, 3));

    // An empty store gives an empty view.
    let empty = World::new();
    let read = empty
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    view.build(read.as_ref()).expect("build");
    assert_eq!((view.builds(), view.is_empty()), (3, true));
}

#[tokio::test]
async fn a_build_reads_more_rows_than_one_page() {
    let world = World::new();
    let vrf = VrfId::generate();
    let rows = u32::try_from(PAGE).expect("page") + 5;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), at(0));
    for index in 0..rows {
        let mut row = lease(vrf, 0x20, at(0), BindingState::Active);
        row.addr = Ipv4Addr::from(0xc633_6400_u32 + index);
        batch
            .put_typed(&tables::LEASES, &(vrf, row.addr), &row)
            .expect("put");
    }
    world.store.propose(batch).await.expect("commit");
    let read = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    world.leases.build(read.as_ref()).expect("build");
    assert_eq!(world.leases.len(), PAGE + 5);
}

#[tokio::test]
async fn ensure_without_a_follower_rebuilds_only_when_the_view_is_newer() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .put(&lease(vrf, 0x20, at(0), BindingState::Active))
        .await;
    let old = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");

    world.leases.ensure(old.as_ref()).expect("ensure");
    assert_eq!((world.leases.builds(), world.leases.len()), (1, 1));
    // The same view again, or an older one: nothing to do.
    world.leases.ensure(old.as_ref()).expect("ensure");
    assert_eq!(world.leases.builds(), 1);

    let mut second = lease(vrf, 0x21, at(0), BindingState::Active);
    second.addr = Ipv4Addr::new(198, 51, 100, 16);
    world.put(&second).await;
    let new = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    world.leases.ensure(old.as_ref()).expect("ensure");
    assert_eq!(
        (world.leases.builds(), world.leases.len()),
        (1, 1),
        "older view"
    );
    world.leases.ensure(new.as_ref()).expect("ensure");
    assert_eq!((world.leases.builds(), world.leases.len()), (2, 2));
    world.leases.ensure(new.as_ref()).expect("ensure");
    assert_eq!(world.leases.builds(), 2);

    // Through the trait of the fact sources, as every reader without a follower does.
    let third = Ipv4Addr::new(198, 51, 100, 17);
    let mut row = lease(vrf, 0x22, at(0), BindingState::Active);
    row.addr = third;
    world.put(&row).await;
    let newest = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let facts = FactSource::facts(world.leases.as_ref(), newest.as_ref(), at(1)).expect("facts");
    assert!(has(&facts, &address_key(vrf, third)));
    assert_eq!(world.leases.builds(), 3);
}

#[tokio::test]
async fn a_view_without_a_follower_answers_caught_up_from_what_it_holds() {
    let world = World::new();
    let vrf = VrfId::generate();
    let revision = world
        .put(&lease(vrf, 0x20, at(0), BindingState::Active))
        .await;
    assert!(!world.leases.caught_up(revision).await, "not built yet");
    world.facts(at(1)).await;
    assert!(world.leases.caught_up(revision).await);
}

// The follower.

/// Polls `check` for a quarter of a second.
async fn within_a_quarter_of_a_second(mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    loop {
        if check() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

fn started(
    store: &Arc<dyn Store>,
) -> (
    Arc<LeaseFacts>,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let leases = LeaseFacts::new(ObserveConfig::default());
    let stop = CancellationToken::new();
    let task = leases.spawn(Arc::clone(store), stop.clone());
    (leases, stop, task)
}

#[tokio::test]
async fn the_follower_builds_at_start_and_follows_a_lease_change() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    put(&store, &lease(vrf, 0x20, at(0), BindingState::Active)).await;

    let (leases, stop, task) = started(&store);
    assert!(leases.is_following());
    assert!(
        within_a_quarter_of_a_second(|| leases.builds() == 1 && leases.len() == 1).await,
        "built at start"
    );

    // A commit shows in the view without a read of the reader's.
    let mut second = lease(vrf, 0x21, at(1), BindingState::Active);
    second.addr = Ipv4Addr::new(198, 51, 100, 16);
    let revision = put(&store, &second).await;
    let key = address_key(vrf, second.addr);
    assert!(
        within_a_quarter_of_a_second(|| has(&leases.facts(at(2)), &key)).await,
        "the fact of a new lease"
    );
    assert!(leases.caught_up(revision).await);
    assert!(leases.revision() >= revision);

    // A rewritten row replaces its entry.
    let mut renewed = second.clone();
    renewed.client.chaddr = HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x2f]);
    let revision = put(&store, &renewed).await;
    assert!(leases.caught_up(revision).await);
    let facts = leases.facts(at(2));
    assert_eq!(mac_of(subject(&facts, &key)), Some(mac(0x2f)));
    assert_eq!(subject(&facts, &key).revision, revision);

    // A DHCPv6 row too.
    let revision = put6(&store, &lease6(vrf, at(1), BindingState::Active)).await;
    assert!(leases.caught_up(revision).await);
    assert!(has(&leases.facts(at(2)), &address_key(vrf, "2001:db8::50")));
    assert_eq!(leases.builds(), 1, "followed, not built again");

    stop.cancel();
    task.await.expect("the follower");
    assert!(!leases.is_following());
}

#[tokio::test]
async fn a_deleted_lease_row_leaves_the_view() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    let row = lease(vrf, 0x20, at(0), BindingState::Active);
    put(&store, &row).await;
    let row6 = lease6(vrf, at(0), BindingState::Active);
    put6(&store, &row6).await;
    let (leases, stop, task) = started(&store);
    assert!(within_a_quarter_of_a_second(|| leases.len() == 2).await);

    commit(&store, |batch| {
        batch.delete_typed(&tables::LEASES, &(vrf, row.addr));
    })
    .await;
    assert!(
        within_a_quarter_of_a_second(|| !has(&leases.facts(at(1)), &address_key(vrf, IP4))).await,
        "the deleted row's facts are gone"
    );
    let revision = commit(&store, |batch| {
        batch.delete_typed(&tables::LEASES6, &(vrf, row6.addr6()));
    })
    .await;
    assert!(leases.caught_up(revision).await);
    assert!(leases.is_empty(), "{:?}", leases.facts(at(1)));

    // A row that turns free leaves the view as well.
    let mut free = row.clone();
    free.state = BindingState::Free;
    put(&store, &row).await;
    assert!(within_a_quarter_of_a_second(|| leases.len() == 1).await);
    let revision = put(&store, &free).await;
    assert!(leases.caught_up(revision).await);
    assert!(leases.is_empty());
    stop.cancel();
    task.await.expect("the follower");
}

#[tokio::test]
async fn changes_wake_after_a_lease_change_and_not_after_a_change_of_another_table() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let (leases, stop, task) = started(&store);
    assert!(within_a_quarter_of_a_second(|| leases.builds() == 1).await);
    // The build leaves a wake behind; drain it.
    while tokio::time::timeout(Duration::from_millis(30), leases.changes().notified())
        .await
        .is_ok()
    {}

    let vrf = VrfId::generate();
    let revision = put(&store, &lease(vrf, 0x20, at(0), BindingState::Active)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), leases.changes().notified())
            .await
            .is_ok(),
        "woken after the lease change"
    );
    assert!(leases.caught_up(revision).await);

    // A change of a table that is no lease table moves the view along but wakes nobody.
    let other = commit(&store, |batch| {
        batch
            .put_typed(
                &LAST_SEEN,
                &ObjectRef::from(AddressId::generate()),
                &IntentSighting {
                    at: at(0),
                    source: "inventory:none".to_owned(),
                    observation: ObservationId::generate(),
                },
            )
            .expect("put");
    })
    .await;
    assert!(
        leases.caught_up(other).await,
        "the view followed the revision"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), leases.changes().notified())
            .await
            .is_err(),
        "not woken by another table"
    );
    assert_eq!(leases.len(), 1);
    stop.cancel();
    task.await.expect("the follower");
}

#[tokio::test]
async fn the_follower_stops_when_told_to() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let (leases, stop, task) = started(&store);
    assert!(within_a_quarter_of_a_second(|| leases.builds() == 1).await);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("stopped in time")
        .expect("the follower");
    assert!(!leases.is_following());
    // Nothing follows any more.
    let revision = put(
        &store,
        &lease(VrfId::generate(), 0x20, at(0), BindingState::Active),
    )
    .await;
    assert!(!leases.caught_up(revision).await);
    assert!(leases.is_empty());
}

// The view after a stream that ends in an error.

/// A store that delegates to a memory store, except that the first stream of `watch` first
/// commits a batch behind the view's back and then ends with an error.
struct Interrupting {
    inner: Arc<dyn Store>,
    behind: Mutex<Option<WriteBatch>>,
    error: fn() -> WatchError,
}

#[async_trait::async_trait]
impl Store for Interrupting {
    async fn propose(&self, batch: WriteBatch) -> Result<tenko_store::Committed, StoreError> {
        self.inner.propose(batch).await
    }

    async fn read(&self, consistency: ReadConsistency) -> Result<Arc<dyn ReadView>, StoreError> {
        self.inner.read(consistency).await
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<tenko_store::ChangeStream, StoreError> {
        let behind = self
            .behind
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match behind {
            Some(batch) => {
                let inner = Arc::clone(&self.inner);
                let error = self.error;
                Ok(futures::stream::once(async move {
                    inner.propose(batch).await.expect("the change behind");
                    Err(error())
                })
                .boxed())
            }
            None => self.inner.watch(from, filter),
        }
    }

    fn register_index(&self, index: Arc<dyn tenko_store::DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> tenko_store::StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// Runs the rebuild scenario: rows exist, the follower builds, a change lands behind its
/// back and the stream ends with `error`.
async fn rebuilds_after(error: fn() -> WatchError) {
    let memory: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    let (kept, changed, removed, added) = (
        Ipv4Addr::new(198, 51, 100, 15),
        Ipv4Addr::new(198, 51, 100, 16),
        Ipv4Addr::new(198, 51, 100, 17),
        Ipv4Addr::new(198, 51, 100, 18),
    );
    let row = |addr: Ipv4Addr, last: u8| {
        let mut row = lease(vrf, last, at(0), BindingState::Active);
        row.addr = addr;
        row
    };
    for (addr, last) in [(kept, 0x20), (changed, 0x21), (removed, 0x22)] {
        put(&memory, &row(addr, last)).await;
    }

    // What lands behind the view's back: a new row, a rewritten row and a deleted row.
    let mut behind = WriteBatch::new(Principal::system(SystemComponent::Dhcp), at(1));
    let new = row(added, 0x23);
    behind
        .put_typed(&tables::LEASES, &(vrf, added), &new)
        .expect("put");
    let rewritten = row(changed, 0x2c);
    behind
        .put_typed(&tables::LEASES, &(vrf, changed), &rewritten)
        .expect("put");
    behind.delete_typed(&tables::LEASES, &(vrf, removed));

    let store: Arc<dyn Store> = Arc::new(Interrupting {
        inner: Arc::clone(&memory),
        behind: Mutex::new(Some(behind)),
        error,
    });
    let (leases, stop, task) = started(&store);
    assert!(
        within_a_quarter_of_a_second(|| leases.builds() >= 2).await,
        "the view was built again from the tables, builds: {}",
        leases.builds()
    );
    let facts = leases.facts(at(2));
    assert_eq!(
        mac_of(subject(&facts, &address_key(vrf, kept))),
        Some(mac(0x20))
    );
    assert_eq!(
        mac_of(subject(&facts, &address_key(vrf, changed))),
        Some(mac(0x2c))
    );
    assert_eq!(
        mac_of(subject(&facts, &address_key(vrf, added))),
        Some(mac(0x23))
    );
    assert!(!has(&facts, &address_key(vrf, removed)), "{facts:?}");
    assert_eq!(leases.len(), 3);

    // And it follows again, through the delegated watch.
    let later = row(removed, 0x24);
    let revision = put(&memory, &later).await;
    assert!(leases.caught_up(revision).await);
    assert!(has(&leases.facts(at(2)), &address_key(vrf, removed)));
    assert_eq!(leases.builds(), 2, "one rebuild only");
    stop.cancel();
    task.await.expect("the follower");
}

#[tokio::test]
async fn a_compacted_journal_rebuilds_the_view_from_the_tables() {
    rebuilds_after(|| WatchError::Compacted {
        oldest: Revision(2),
    })
    .await;
}

#[tokio::test]
async fn a_lagging_stream_rebuilds_the_view_from_the_tables() {
    rebuilds_after(|| WatchError::Lagged { last: Revision(1) }).await;
}

#[tokio::test]
async fn a_row_that_ended_longer_ago_than_the_retention_is_not_presented() {
    let world = World::new();
    world.leases.set_retention(Duration::from_secs(3_600));
    let vrf = VrfId::generate();
    // Times from 50 minutes ago, so that the build (which cuts at the clock) keeps every row.
    let base = Timestamp::now()
        .checked_sub(Duration::from_secs(50 * 60))
        .expect("time");
    let at = |minutes: u64| {
        base.checked_add(Duration::from_secs(minutes * 60))
            .expect("time")
    };
    // Released at 5 minutes: its facts ended then.
    world
        .put(&lease(vrf, 0x20, at(5), BindingState::Released))
        .await;
    // An abandoned row whose hold ended at 70 minutes.
    let mut abandoned = lease(vrf, 0x21, at(10), BindingState::Abandoned);
    abandoned.addr = Ipv4Addr::new(198, 51, 100, 16);
    abandoned.ends = at(70);
    world.put(&abandoned).await;
    // An active binding whose last transaction is old but whose end has not come.
    let mut bound = lease(vrf, 0x22, at(0), BindingState::Active);
    bound.addr = Ipv4Addr::new(198, 51, 100, 17);
    bound.ends = at(10_000);
    world.put(&bound).await;

    let addresses = |facts: &[ObservedFact]| {
        let mut ips: Vec<IpAddr> = facts.iter().flat_map(ObservedFact::ips).collect();
        ips.sort();
        ips.dedup();
        ips
    };
    // Within the hour after each end, every row is there.
    assert_eq!(addresses(&world.facts(at(60)).await).len(), 3);
    // Past an hour after the release, the released row is gone; the conflict still counts.
    assert_eq!(
        addresses(&world.facts(at(100)).await),
        [
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 16)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 17)),
        ]
    );
    // Past an hour after the hold ended, only the binding is left.
    assert_eq!(
        addresses(&world.facts(at(200)).await),
        [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 17))]
    );
    // The default retention is the stored facts' (30 days).
    assert_eq!(
        LeaseFacts::new(ObserveConfig::default()).retention(),
        ObserveConfig::default().retention
    );
}

#[tokio::test]
async fn the_build_at_start_leaves_out_the_rows_past_the_retention() {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let vrf = VrfId::generate();
    // Released long ago (the fixture's times are in 2026-10-22) and a binding that holds.
    put(&store, &lease(vrf, 0x20, at(0), BindingState::Released)).await;
    let mut bound = lease(vrf, 0x21, Timestamp::now(), BindingState::Active);
    bound.addr = Ipv4Addr::new(198, 51, 100, 16);
    put(&store, &bound).await;
    let leases = LeaseFacts::new(ObserveConfig::default());
    leases.set_retention(Duration::from_secs(3_600));
    let view = store.read(ReadConsistency::Local).await.expect("view");
    leases.build(view.as_ref()).expect("build");
    assert_eq!(leases.len(), 1, "the released row is not kept");
}

#[test]
fn an_entry_of_the_view_stays_compact() {
    // The inline part of one lease row in the view: the entry and its key (ADR 0031 states
    // the memory per row from it); the names and the vendor class add their length on the
    // heap.
    let inline = std::mem::size_of::<Entry>() + std::mem::size_of::<(VrfId, IpAddr)>();
    println!(
        "entry {} octets, key {} octets",
        std::mem::size_of::<Entry>(),
        std::mem::size_of::<(VrfId, IpAddr)>()
    );
    assert!(inline <= 200, "{inline} octets inline per row");
}
