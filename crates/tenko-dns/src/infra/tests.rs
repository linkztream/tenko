//! The infrastructure cache against the rules of the contract and its bounds.

use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use tenko_core::dns::DnsName;

use super::*;
use crate::recursion::infra::EdnsSupport;

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

#[test]
fn cuts_names_and_servers_keep_the_contract() {
    let infra = Infra::new(InfraBounds::HOME);
    let now = Instant::now();
    let id = infra.put_cut(&DnsName::root(), vec![name("a.root.test")], 60, now);
    assert_eq!(
        infra.put_cut(&DnsName::root(), vec![name("b.root.test")], 60, now),
        id,
        "a known cut keeps its identifier"
    );
    infra.put_cut(&name("test"), vec![name("ns.test")], 30, now);
    assert_eq!(
        infra
            .closest_cut(&name("www.example.test"), now)
            .expect("a cut")
            .zone,
        name("test")
    );
    assert_eq!(
        infra
            .closest_cut(&name("www.example.test"), now + Duration::from_secs(31))
            .expect("the root")
            .zone,
        DnsName::root(),
        "an expired cut falls back to the one above"
    );
    infra.set_ds(
        &name("test"),
        DsState::Insecure {
            until: now + Duration::from_secs(5),
        },
    );
    infra.set_minimise_fallback(&name("test"), now + Duration::from_secs(5));
    let cut = infra.cut(&name("test"), now).expect("cut");
    assert_eq!(cut.ds.as_str(), "insecure");
    assert!(cut.minimise_fallback.is_some());

    let host = name("ns.test");
    infra.put_addresses(&host, &[(v4(20), 60)], AddressOrigin::SiblingGlue, now);
    infra.put_addresses(&host, &[(v4(21), 60)], AddressOrigin::Glue, now);
    let known = infra.name_server(&host, now).expect("addresses");
    assert_eq!(
        known
            .addresses
            .iter()
            .map(|address| (address.address, address.origin))
            .collect::<Vec<_>>(),
        [(v4(21), AddressOrigin::Glue)],
        "in-domain glue replaces sibling glue"
    );
    infra.put_addresses(&host, &[(v4(22), 60)], AddressOrigin::Hints, now);
    assert_eq!(
        infra.name_server(&host, now).expect("addresses").addresses[0].address,
        v4(21),
        "the hints never replace glue"
    );

    infra.update_server(v4(21), now, &mut |state| {
        state.edns = EdnsSupport::No;
        state
            .lame
            .push((name("test"), now + Duration::from_secs(10)));
    });
    let state = infra.server(v4(21), now);
    assert!(state.is_lame(&name("test"), now));
    assert_eq!(state.edns, EdnsSupport::No);
    assert_eq!(infra.sizes().servers, 1);
    let listed = infra.list(None, None, 10, now);
    assert_eq!(
        listed
            .iter()
            .map(|cut| cut.zone.as_str())
            .collect::<Vec<_>>(),
        [".", "test"]
    );
    assert_eq!(infra.list(None, Some(&DnsName::root()), 10, now).len(), 1);
    assert_eq!(infra.flush(Some(&name("test"))), 2, "the cut and the name");
    // The learnt capability holds for the infrastructure TTL, then the server is probed
    // again.
    assert_eq!(
        infra.server(v4(21), now + Duration::from_secs(899)).edns,
        EdnsSupport::No
    );
    assert_eq!(
        infra.server(v4(21), now + Duration::from_secs(901)).edns,
        EdnsSupport::Unknown
    );
    assert_eq!(
        infra.purge(now + Duration::from_secs(3600)),
        2,
        "the expired root and the server with nothing left to remember"
    );
    assert_eq!(infra.flush(None), 0);
    assert_eq!(infra.sizes(), InfraSizes::default());
}

#[test]
fn the_bounds_hold_least_recently_used_out() {
    let infra = Infra::new(InfraBounds {
        cuts: 32,
        servers: 32,
        ttl: Duration::from_secs(900),
    });
    let now = Instant::now();
    infra.put_cut(&DnsName::root(), vec![name("a.root.test")], 600, now);
    for index in 0..200 {
        let zone = name(&format!("zone{index}.test"));
        infra.put_cut(&zone, vec![name("ns.test")], 600, now);
        // The root is used all the time and stays.
        assert!(infra.cut(&DnsName::root(), now).is_some());
        infra.put_addresses(
            &name(&format!("ns{index}.test")),
            &[(v4(1), 600)],
            AddressOrigin::Glue,
            now,
        );
        infra.update_server(
            IpAddr::V4(Ipv4Addr::new(
                198,
                51,
                100,
                u8::try_from(index % 250).unwrap_or(0),
            )),
            now,
            &mut |state| state.tcp_only = true,
        );
    }
    let sizes = infra.sizes();
    assert!(
        sizes.cuts <= 32 && sizes.names <= 32 && sizes.servers <= 32,
        "{sizes:?}"
    );
    assert!(infra.cut(&name("zone199.test"), now).is_some());
}

#[test]
fn trim_drops_a_sixteenth_of_the_oldest() {
    let mut map: HashMap<u32, u64> = (0..33).map(|key| (key, u64::from(key))).collect();
    trim(&mut map, 32, |used| *used);
    assert_eq!(map.len(), 31, "two: the excess and a sixteenth of 32");
    assert!(!map.contains_key(&0) && !map.contains_key(&1));
}
