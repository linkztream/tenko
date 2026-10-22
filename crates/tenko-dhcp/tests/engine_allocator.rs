//! The hashed allocator of the engine against the reference allocator (WP7.3, plan section
//! 2.3): over random scopes, pools, exclusions, reservations, leases of other clients and
//! offers held, the two agree on whether there is an address and on every choice but the
//! free pool address, which for the hashed one passes the same rules; the hashed order
//! spreads clients over the pool and gives a client the same start every time.

use std::{collections::BTreeSet, net::Ipv4Addr, time::Duration};

use ipnet::Ipv4Net;
use proptest::prelude::*;
use tenko_core::{
    HostId, InterfaceId, NodeId, PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{BindingState, DdnsPolicy, LeaseEventKind, LeaseTimes, SharedNetworkId},
};
use tenko_dhcp::{
    allocator::{
        AdmitAll, Allocator, Choice, NoOffers, OfferHold, ReferenceAllocator, Request, SingleNode,
    },
    image::{ConfigImage, ImageBuilder, PoolImage, ReservationImage, ScopeImage},
    lease::{LeaseTable, MemLeaseTable, PendingChange},
    v4::engine::HashedAllocator,
};

fn t0() -> Timestamp {
    "2026-10-22T12:00:00Z".parse().expect("time")
}

fn identity(k: u8) -> Vec<u8> {
    vec![0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, k]
}

const NETS: [&str; 2] = ["192.0.2.0/24", "198.51.100.0/24"];

fn host(network: Ipv4Net, last: u8) -> Ipv4Addr {
    let [a, b, c, _] = network.network().octets();
    Ipv4Addr::new(a, b, c, last)
}

#[derive(Debug, Clone)]
struct Spec {
    pools: Vec<(u8, u8)>,
    excluded: Vec<(u8, u8)>,
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        prop::collection::vec((1u8..200, 0u8..40), 1..3),
        prop::collection::vec((1u8..250, 0u8..20), 0..3),
    )
        .prop_map(|(pools, excluded)| Spec {
            pools: pools
                .into_iter()
                .map(|(first, len)| (first, first.saturating_add(len).min(254)))
                .collect(),
            excluded: excluded
                .into_iter()
                .map(|(first, len)| (first, first.saturating_add(len).min(254)))
                .collect(),
        })
}

struct Held(Ipv4Addr, Vec<u8>);

impl OfferHold for Held {
    fn held_for_other(&self, _: PrefixId, addr: Ipv4Addr, id: &[u8], _: Timestamp) -> bool {
        addr == self.0 && id != self.1
    }
}

fn build(specs: &[Spec], shared: bool, reservations: &[(u8, usize, u8)]) -> (ConfigImage, VrfId) {
    let vrf = VrfId::generate();
    let network_of = SharedNetworkId::generate();
    let mut builder = ImageBuilder::new(Revision(1));
    let mut prefixes = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let network: Ipv4Net = NETS[index].parse().expect("a network");
        let prefix = PrefixId::generate();
        prefixes.push((prefix, network));
        builder.scope(ScopeImage {
            prefix,
            vrf,
            network,
            authoritative: true,
            restricted: false,
            server_id: None,
            lease: LeaseTimes::default(),
            shared_network: shared.then_some(network_of),
            pools: spec
                .pools
                .iter()
                .map(|(first, last)| PoolImage {
                    range: RangeId::generate(),
                    first: host(network, *first),
                    last: host(network, *last),
                    lease: LeaseTimes::default(),
                    classes: Vec::new(),
                    options: Vec::new(),
                })
                .collect(),
            excluded: spec
                .excluded
                .iter()
                .map(|(first, last)| (host(network, *first), host(network, *last)))
                .collect(),
            options: Vec::new(),
            classes: Vec::new(),
            ddns: DdnsPolicy::default(),
        });
    }
    for (client, scope, last) in reservations {
        let (prefix, network) = prefixes[scope % prefixes.len()];
        let _ = builder.reservation(ReservationImage {
            scope: prefix,
            addr: host(network, *last),
            host: HostId::generate(),
            interface: InterfaceId::generate(),
            identity: identity(*client),
            options: Vec::new(),
        });
    }
    (builder.build(), vrf)
}

#[allow(clippy::too_many_arguments, reason = "one random case")]
fn compare(
    specs: &[Spec],
    shared: bool,
    reservations: &[(u8, usize, u8)],
    leases: &[(u8, usize, u8, u8, u64)],
    client: u8,
    requested: Option<(usize, u8)>,
    hold: Option<(usize, u8, u8)>,
) -> Result<(), TestCaseError> {
    let (image, vrf) = build(specs, shared, reservations);
    let mut table = MemLeaseTable::default();
    for (owner, scope, last, state, ends) in leases {
        let scope = &image.scopes()[scope % specs.len()];
        let state = [
            BindingState::Active,
            BindingState::Abandoned,
            BindingState::Expired,
            BindingState::Released,
        ][usize::from(state % 4)];
        let change = PendingChange::new(
            LeaseEventKind::Granted,
            vrf,
            scope.prefix,
            host(scope.network, *last),
            1,
            &identity(*owner)[2..],
            None,
            state,
            t0(),
            t0().checked_add(Duration::from_secs(*ends)).expect("time"),
        );
        table.apply(change.to_lease(NodeId(1), None));
    }
    let now = t0().checked_add(Duration::from_secs(100)).expect("time");
    let offer = hold.map(|(scope, last, owner)| {
        let network = image.scopes()[scope % specs.len()].network;
        Held(host(network, last), identity(owner))
    });
    let offers: &dyn OfferHold = offer.as_ref().map_or(&NoOffers, |held| held);
    let id = identity(client);
    for scope in image.scopes() {
        let request = Request {
            image: &image,
            scope,
            identity: &id,
            hardware: &id,
            admission: &AdmitAll,
            requested: requested
                .map(|(index, last)| host(image.scopes()[index % specs.len()].network, last)),
            leases: &table,
            offers,
            ownership: &SingleNode,
            now,
        };
        let reference = ReferenceAllocator.pick(&request);
        let hashed = HashedAllocator.pick(&request);
        prop_assert_eq!(hashed, HashedAllocator.pick(&request), "deterministic");
        match (reference, hashed) {
            (None, None) => {}
            (Some(Choice::Pool(_)), Some(Choice::Pool(addr))) => {
                let home = image
                    .siblings(scope)
                    .find(|sibling| sibling.network.contains(&addr))
                    .expect("a home scope");
                prop_assert!(request.is_free(home, addr), "{} is free", addr);
            }
            (want, got) => prop_assert_eq!(want, got),
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn the_hashed_allocator_keeps_every_rule_of_the_reference(
        specs in prop::collection::vec(spec(), 1..=2),
        shared in any::<bool>(),
        reservations in prop::collection::vec((0u8..6, 0usize..2, 1u8..=254), 0..4),
        leases in prop::collection::vec((0u8..6, 0usize..2, 1u8..=254, 0u8..4, 0u64..400), 0..40),
        client in 0u8..6,
        requested in prop::option::of((0usize..2, 1u8..=254)),
        hold in prop::option::of((0usize..2, 1u8..=254, 0u8..6)),
    ) {
        compare(&specs, shared, &reservations, &leases, client, requested, hold)?;
    }
}

#[test]
fn the_hashed_order_spreads_clients_and_keeps_each_client_on_its_start() {
    let spec = Spec {
        pools: vec![(1, 254)],
        excluded: Vec::new(),
    };
    let (image, _) = build(&[spec], false, &[]);
    let scope = &image.scopes()[0];
    let table = MemLeaseTable::default();
    let mut firsts = BTreeSet::new();
    for client in 0..64u8 {
        let id = identity(client);
        let request = Request {
            image: &image,
            scope,
            identity: &id,
            hardware: &id,
            admission: &AdmitAll,
            requested: None,
            leases: &table,
            offers: &NoOffers,
            ownership: &SingleNode,
            now: t0(),
        };
        let Some(Choice::Pool(addr)) = HashedAllocator.pick(&request) else {
            panic!("a pool address");
        };
        assert_eq!(HashedAllocator.pick(&request), Some(Choice::Pool(addr)));
        firsts.insert(addr);
    }
    // 64 clients in an empty pool of 254: the reference gives all of them .1; the hashed
    // order gives most of them their own address.
    assert!(firsts.len() > 48, "{} distinct starts", firsts.len());
}
