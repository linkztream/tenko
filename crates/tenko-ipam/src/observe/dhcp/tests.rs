//! The rules of the lease facts against the in-memory store: what a grant, a renewal, a
//! refresh, another client and a release write, and the index that follows the store.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use tenko_core::{
    NodeId, PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, ClientKey, DdnsState, Lease},
    observe::Observed,
    serde_util::HexBytes,
};
use tenko_store::{MemStore, ReadConsistency, ReadViewExt, Store, WriteBatch};

use super::{FactOutcome, LeaseFacts, lease_name};
use crate::observe::{
    ObserveConfig,
    model::FactSubject,
    tables::{BY_IP, BY_MAC, BY_NAME, FACTS},
};

const NODE: NodeId = NodeId(7);

fn at(minutes: u64) -> Timestamp {
    "2026-10-22T08:00:00Z"
        .parse::<Timestamp>()
        .expect("time")
        .checked_add(Duration::from_secs(minutes * 60))
        .expect("time")
}

fn lease(vrf: VrfId, mac: u8, cltt: Timestamp, state: BindingState) -> Lease {
    Lease {
        addr: Ipv4Addr::new(198, 51, 100, 15),
        vrf,
        scope: PrefixId::generate(),
        client: ClientKey {
            htype: 1,
            chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, mac]),
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
    }
}

struct World {
    store: Arc<dyn Store>,
    facts: Arc<LeaseFacts>,
}

impl World {
    fn new() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        let facts = LeaseFacts::new(NODE, ObserveConfig::default());
        facts.register(store.as_ref()).expect("register");
        Self { store, facts }
    }

    /// Observes `lease` at `now` and commits the batch.
    async fn observe(&self, lease: &Lease, now: Timestamp) -> super::LeaseObservation {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        let outcome = self.facts.observe(lease, now, &mut batch).expect("observe");
        assert_eq!(outcome.wrote(), !batch.mutations.is_empty(), "{outcome:?}");
        if !batch.mutations.is_empty() {
            self.store.propose(batch).await.expect("commit");
        }
        outcome
    }

    fn address(&self, vrf: VrfId) -> super::ObservedFact {
        self.facts
            .fact(&FactSubject::Address {
                vrf,
                ip: Ipv4Addr::new(198, 51, 100, 15).into(),
            })
            .expect("the address fact")
    }
}

#[tokio::test]
async fn a_renewal_writes_nothing_until_the_refresh_is_due() {
    let world = World::new();
    let vrf = VrfId::generate();
    let granted = lease(vrf, 0x20, at(0), BindingState::Active);
    let first = world.observe(&granted, at(0)).await;
    assert_eq!(
        (first.address, first.name),
        (FactOutcome::New, FactOutcome::New)
    );
    assert_eq!(first.observed_at, Some(at(0)));

    // The index follows the store: the fact, and its rows by MAC, address and name.
    let fact = world.address(vrf);
    assert_eq!(fact.sightings, 1);
    assert_eq!(fact.expires_at, Some(granted.ends));
    assert_eq!(fact.source_key, "dhcp:7");
    let view = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let ip = Ipv4Addr::new(198, 51, 100, 15).into();
    let subject = fact.subject_key.clone();
    let mac = "00:00:5e:00:53:20".parse().expect("mac");
    assert!(
        view.get_typed(&BY_MAC, &(mac, "dhcp:7".to_owned(), subject.clone()))
            .expect("read")
            .is_some()
    );
    assert!(
        view.get_typed(&BY_IP, &(ip, "dhcp:7".to_owned(), subject.clone()))
            .expect("read")
            .is_some()
    );
    assert!(
        view.get_typed(
            &BY_NAME,
            &(
                "printer".to_owned(),
                "dhcp:7".to_owned(),
                format!("name:{ip}")
            )
        )
        .expect("read")
        .is_some()
    );

    // A renewal ten minutes later: nothing written, counted as unchanged.
    let renewal = lease(vrf, 0x20, at(10), BindingState::Active);
    let quiet = world.observe(&renewal, at(10)).await;
    assert_eq!(
        (quiet.address, quiet.name),
        (FactOutcome::Unchanged, FactOutcome::Unchanged)
    );
    assert_eq!(quiet.observed_at, None);
    assert_eq!(world.address(vrf).last_seen, at(0));

    // At the renewal point (T1, half the hour), the refresh is due: one more sighting.
    let t1 = lease(vrf, 0x20, at(30), BindingState::Active);
    let due = world.observe(&t1, at(30)).await;
    assert_eq!(due.address, FactOutcome::Refreshed);
    let fact = world.address(vrf);
    assert_eq!((fact.first_seen, fact.last_seen), (at(0), at(30)));
    assert_eq!(fact.sightings, 2);
    assert_eq!(fact.expires_at, Some(t1.ends));
}

#[tokio::test]
async fn another_client_changes_the_fact_and_a_release_expires_it() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .observe(&lease(vrf, 0x20, at(0), BindingState::Active), at(0))
        .await;

    // The client releases: both facts expire at once.
    let mut released = lease(vrf, 0x20, at(5), BindingState::Released);
    released.ends = at(5);
    let gone = world.observe(&released, at(5)).await;
    assert_eq!(
        (gone.address, gone.name),
        (FactOutcome::Expired, FactOutcome::Expired)
    );
    assert!(!world.address(vrf).is_current(at(5)));
    // A second release finds nothing current.
    let again = world.observe(&released, at(6)).await;
    assert_eq!(
        (again.address, again.name),
        (FactOutcome::None, FactOutcome::None)
    );

    // Another client takes the address without a name: the address fact starts again
    // with its MAC, and the name fact stays expired.
    let mut other = lease(vrf, 0x21, at(7), BindingState::Active);
    other.hostname = None;
    let taken = world.observe(&other, at(7)).await;
    assert_eq!(
        (taken.address, taken.name),
        (FactOutcome::Changed, FactOutcome::None)
    );
    let fact = world.address(vrf);
    assert_eq!((fact.first_seen, fact.sightings), (at(7), 1));
    let Observed::Address { mac, .. } = fact.observed else {
        panic!("an address fact");
    };
    assert_eq!(mac, Some("00:00:5e:00:53:21".parse().expect("mac")));
    let view = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let old_mac = "00:00:5e:00:53:20".parse().expect("mac");
    assert!(
        view.get_typed(
            &BY_MAC,
            &(old_mac, "dhcp:7".to_owned(), fact.subject_key.clone())
        )
        .expect("read")
        .is_none(),
        "the old MAC leaves the index"
    );

    // A lease that ran out keeps no current fact without any write.
    assert!(!world.address(vrf).is_current(other.ends));
}

#[tokio::test]
async fn the_index_is_built_from_the_stored_facts() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .observe(&lease(vrf, 0x20, at(0), BindingState::Active), at(0))
        .await;
    // A second index of the same node, registered later, starts from the stored facts, so a
    // restarted role does not write its facts again.
    let later = LeaseFacts::new(NODE, ObserveConfig::default());
    later.register(world.store.as_ref()).expect("register");
    assert_eq!(later.len(), 2);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), at(1));
    let outcome = later
        .observe(
            &lease(vrf, 0x20, at(1), BindingState::Active),
            at(1),
            &mut batch,
        )
        .expect("observe");
    assert_eq!(outcome.address, FactOutcome::Unchanged);
    // Another node's facts are not this node's.
    let other = LeaseFacts::new(NodeId(8), ObserveConfig::default());
    other.register(world.store.as_ref()).expect("register");
    assert!(other.is_empty());
    let view = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    assert_eq!(
        view.scan_typed(&FACTS, tenko_store::KeyRange::all(), 10, false)
            .expect("scan")
            .len(),
        2
    );
}

#[tokio::test]
async fn a_conflict_replaces_the_lease_fact_with_the_answering_mac() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .observe(&lease(vrf, 0x20, at(0), BindingState::Active), at(0))
        .await;

    // An ARP answer from another device (WP8.5 stores its MAC as the row's chaddr): the
    // address fact names that MAC until the hold ends, the name fact ends.
    let mut conflict = lease(vrf, 0x2a, at(5), BindingState::Abandoned);
    conflict.hostname = None;
    conflict.ends = at(65);
    let seen = world.observe(&conflict, at(5)).await;
    assert_eq!(
        (seen.address, seen.name),
        (FactOutcome::Changed, FactOutcome::Expired)
    );
    assert_eq!(seen.observed_at, Some(at(5)));
    let fact = world.address(vrf);
    assert_eq!(fact.expires_at, Some(at(65)));
    let Observed::Address { mac, .. } = fact.observed else {
        panic!("an address fact");
    };
    assert_eq!(mac, Some("00:00:5e:00:53:2a".parse().expect("mac")));

    // An ICMP answer or a DECLINE carries no client: the fact names no MAC.
    let mut icmp = conflict.clone();
    icmp.client = ClientKey {
        htype: 0,
        chaddr: HexBytes(Vec::new()),
        client_id: None,
    };
    icmp.cltt = at(6);
    let seen = world.observe(&icmp, at(6)).await;
    assert_eq!(seen.address, FactOutcome::Changed);
    let Observed::Address { mac, .. } = world.address(vrf).observed else {
        panic!("an address fact");
    };
    assert_eq!(mac, None);
}

#[test]
fn the_name_is_the_fqdn_else_the_host_name() {
    let vrf = VrfId::generate();
    let mut row = lease(vrf, 0x20, at(0), BindingState::Active);
    assert_eq!(lease_name(&row).as_deref(), Some("printer"));
    row.fqdn = Some("printer.example.test.".to_owned());
    assert_eq!(lease_name(&row).as_deref(), Some("printer.example.test"));
    row.fqdn = Some("  ".to_owned());
    row.hostname = None;
    assert_eq!(lease_name(&row), None);
}

// WP8.2: the OS and vendor facts of a lease's fingerprint.

/// A classifier that knows one fingerprint: Windows's vendor class.
struct Windows;

impl super::LeaseClassifier for Windows {
    fn os(&self, fingerprint: &tenko_core::dhcp::Fingerprint) -> Option<super::OsReading> {
        (fingerprint.vendor_class.as_deref() == Some("MSFT 5.0")).then(|| super::OsReading {
            guess: "Windows 10 or 11".to_owned(),
            confidence: 85,
        })
    }
}

fn fingerprinted(vrf: VrfId, cltt: Timestamp, vendor: &str) -> Lease {
    let mut row = lease(vrf, 0x20, cltt, BindingState::Active);
    row.fingerprint = Some(tenko_core::dhcp::Fingerprint {
        parameters: HexBytes(vec![
            1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252,
        ]),
        vendor_class: Some(vendor.to_owned()),
        ..tenko_core::dhcp::Fingerprint::default()
    });
    row
}

#[tokio::test]
async fn a_fingerprint_gives_an_os_fact_and_option_60_a_vendor_fact() {
    let world = World::new();
    let vrf = VrfId::generate();
    let ip = Ipv4Addr::new(198, 51, 100, 15).into();
    let mac = "00:00:5e:00:53:20".parse().expect("mac");

    // Without a classifier the vendor class is still a fact; no OS guess is made.
    let first = world
        .observe(&fingerprinted(vrf, at(0), "MSFT 5.0"), at(0))
        .await;
    assert_eq!(
        (first.os, first.vendor),
        (FactOutcome::None, FactOutcome::New)
    );
    assert!(world.facts.fact(&FactSubject::Os { ip }).is_none());

    // With one, the next refresh writes the guess with the source dhcp:<node>.
    assert!(world.facts.set_classifier(Arc::new(Windows)));
    assert!(!world.facts.set_classifier(Arc::new(Windows)), "set once");
    let due = world
        .observe(&fingerprinted(vrf, at(30), "MSFT 5.0"), at(30))
        .await;
    assert_eq!(due.os, FactOutcome::New);
    assert_eq!(due.vendor, FactOutcome::Refreshed);
    let os = world
        .facts
        .fact(&FactSubject::Os { ip })
        .expect("the OS fact");
    assert_eq!(os.source_key, "dhcp:7");
    assert_eq!(
        os.observed,
        Observed::Os {
            ip,
            guess: "Windows 10 or 11".to_owned(),
            confidence: 85
        }
    );
    let vendor = world
        .facts
        .fact(&FactSubject::Vendor { mac })
        .expect("the vendor fact");
    assert_eq!(
        vendor.observed,
        Observed::Vendor {
            mac,
            vendor: "MSFT 5.0".to_owned()
        }
    );
    // A renewal within the refresh interval writes neither.
    let quiet = world
        .observe(&fingerprinted(vrf, at(35), "MSFT 5.0"), at(35))
        .await;
    assert_eq!(
        (quiet.os, quiet.vendor),
        (FactOutcome::Unchanged, FactOutcome::Unchanged)
    );

    // A vendor class the classifier does not know: the guess ends, the vendor changes.
    let other = world
        .observe(&fingerprinted(vrf, at(40), "udhcp 1.35.0"), at(40))
        .await;
    assert_eq!(
        (other.os, other.vendor),
        (FactOutcome::Expired, FactOutcome::Changed)
    );
    assert!(
        !world
            .facts
            .fact(&FactSubject::Os { ip })
            .expect("kept")
            .is_current(at(40))
    );

    // A release expires the vendor fact with the others.
    let mut released = fingerprinted(vrf, at(45), "udhcp 1.35.0");
    released.state = BindingState::Released;
    released.ends = at(45);
    let gone = world.observe(&released, at(45)).await;
    assert_eq!(gone.vendor, FactOutcome::Expired);
    assert_eq!(gone.os, FactOutcome::None);
    assert_eq!(
        super::lease_vendor(&released).as_deref(),
        Some("udhcp 1.35.0")
    );
}

// WP9.2: the network fact of a delegated prefix.

fn delegation(vrf: VrfId, cltt: Timestamp, state: BindingState) -> tenko_core::dhcp::Lease6 {
    use tenko_core::{
        dhcp::{Lease6, Lease6Kind},
        net::Duid,
    };
    Lease6 {
        addr: "2001:db8:1:100::"
            .parse::<std::net::Ipv6Addr>()
            .expect("addr")
            .into(),
        prefix_len: 56,
        kind: Lease6Kind::Pd,
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
    }
}

impl World {
    /// Observes the DHCPv6 `lease` at `now` and commits the batch.
    async fn observe6(
        &self,
        lease: &tenko_core::dhcp::Lease6,
        now: Timestamp,
    ) -> super::LeaseObservation {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
        let outcome = self
            .facts
            .observe6(lease, now, &mut batch)
            .expect("observe6");
        assert_eq!(outcome.wrote(), !batch.mutations.is_empty(), "{outcome:?}");
        if !batch.mutations.is_empty() {
            self.store.propose(batch).await.expect("commit");
        }
        outcome
    }

    fn delegated(&self, vrf: VrfId) -> super::ObservedFact {
        self.facts
            .fact(&FactSubject::Network {
                controller: format!("dhcp-pd/{vrf}/2001:db8:1:100::/56"),
            })
            .expect("the network fact")
    }
}

#[tokio::test]
async fn a_delegated_prefix_is_one_network_fact_and_nothing_else() {
    let world = World::new();
    let vrf = VrfId::generate();
    // Even with a name the client sent, no address, name or other fact is written.
    let mut granted = delegation(vrf, at(0), BindingState::Active);
    granted.fqdn = Some("router.example.net.".to_owned());
    let first = world.observe6(&granted, at(0)).await;
    assert_eq!(first.address, FactOutcome::New);
    assert_eq!(
        (first.name, first.os, first.vendor),
        (FactOutcome::None, FactOutcome::None, FactOutcome::None)
    );
    assert_eq!(first.observed_at, Some(at(0)));
    assert_eq!(world.facts.len(), 1);
    let fact = world.delegated(vrf);
    assert_eq!(
        fact.subject_key,
        format!("network:dhcp-pd/{vrf}/2001:db8:1:100::/56")
    );
    assert_eq!(fact.source_key, "dhcp:7");
    assert_eq!(fact.expires_at, Some(granted.ends));
    assert_eq!(fact.sightings, 1);
    assert_eq!(
        fact.observed,
        Observed::Network {
            controller: format!("dhcp-pd/{vrf}/2001:db8:1:100::/56"),
            name: "delegated to 00:00:5e:00:53:20".to_owned(),
            subnet: Some("2001:db8:1:100::/56".parse().expect("prefix")),
            vlan: None,
            dhcp: tenko_core::observe::NetworkDhcp::Server,
            management: false,
        }
    );
    // The rows of the store: no address fact for the prefix's first address, no name fact.
    let ip = "2001:db8:1:100::"
        .parse::<std::net::Ipv6Addr>()
        .expect("addr");
    assert!(
        world
            .facts
            .fact(&FactSubject::Address { vrf, ip: ip.into() })
            .is_none()
    );
    assert!(
        world
            .facts
            .fact(&FactSubject::Name { ip: ip.into() })
            .is_none()
    );
    let view = world
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    assert_eq!(
        view.scan_typed(&FACTS, tenko_store::KeyRange::all(), 10, false)
            .expect("scan")
            .len(),
        1
    );
}

#[tokio::test]
async fn a_client_without_a_mac_address_is_named_by_its_duid() {
    let world = World::new();
    let vrf = VrfId::generate();
    let mut granted = delegation(vrf, at(0), BindingState::Active);
    granted.link_layer = None;
    granted.link_layer_type = None;
    world.observe6(&granted, at(0)).await;
    let Observed::Network { name, .. } = world.delegated(vrf).observed else {
        panic!("a network fact");
    };
    assert_eq!(name, "delegated to DUID 0003000100005e005320");
}

#[tokio::test]
async fn a_renewal_of_a_delegation_writes_nothing_until_the_refresh_is_due() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .observe6(&delegation(vrf, at(0), BindingState::Active), at(0))
        .await;
    // A renewal ten minutes later: nothing written.
    let quiet = world
        .observe6(&delegation(vrf, at(10), BindingState::Active), at(10))
        .await;
    assert_eq!(quiet.address, FactOutcome::Unchanged);
    assert_eq!(quiet.observed_at, None);
    assert_eq!(world.delegated(vrf).last_seen, at(0));
    // At the renewal point (half the hour) the refresh is due.
    let renewed = delegation(vrf, at(30), BindingState::Active);
    let due = world.observe6(&renewed, at(30)).await;
    assert_eq!(due.address, FactOutcome::Refreshed);
    let fact = world.delegated(vrf);
    assert_eq!((fact.first_seen, fact.last_seen), (at(0), at(30)));
    assert_eq!(fact.sightings, 2);
    assert_eq!(fact.expires_at, Some(renewed.ends));
}

#[tokio::test]
async fn a_release_of_a_delegation_expires_its_fact() {
    let world = World::new();
    let vrf = VrfId::generate();
    world
        .observe6(&delegation(vrf, at(0), BindingState::Active), at(0))
        .await;
    let mut released = delegation(vrf, at(5), BindingState::Released);
    released.ends = at(5);
    let gone = world.observe6(&released, at(5)).await;
    assert_eq!(gone.address, FactOutcome::Expired);
    assert_eq!(gone.name, FactOutcome::None);
    assert!(!world.delegated(vrf).is_current(at(5)));
    // A second release finds nothing current and writes nothing.
    let again = world.observe6(&released, at(6)).await;
    assert_eq!(again.address, FactOutcome::None);
    // A new delegation of the same prefix starts the fact again.
    let renewed = world
        .observe6(&delegation(vrf, at(7), BindingState::Active), at(7))
        .await;
    assert_eq!(renewed.address, FactOutcome::Changed);
    assert!(world.delegated(vrf).is_current(at(8)));
}

#[tokio::test]
async fn an_address_lease_of_dhcpv6_still_writes_the_address_fact() {
    // The delegation branch must not touch the address leases of DHCPv6.
    let world = World::new();
    let vrf = VrfId::generate();
    let mut address = delegation(vrf, at(0), BindingState::Active);
    address.kind = tenko_core::dhcp::Lease6Kind::Na;
    address.prefix_len = 128;
    address.addr = "2001:db8::50"
        .parse::<std::net::Ipv6Addr>()
        .expect("addr")
        .into();
    let first = world.observe6(&address, at(0)).await;
    assert_eq!(first.address, FactOutcome::New);
    assert!(
        world
            .facts
            .fact(&FactSubject::Address {
                vrf,
                ip: address.addr
            })
            .is_some()
    );
    assert!(
        world
            .facts
            .fact(&FactSubject::Network {
                controller: format!("dhcp-pd/{vrf}/2001:db8::50/128")
            })
            .is_none()
    );
}
