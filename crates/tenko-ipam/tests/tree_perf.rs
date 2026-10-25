//! Speed of the prefix tree on a space the size of a /16.
//!
//! The space is `2001:db8::/112`, a supernet of exactly 65,536 addresses like a /16, with
//! 256 networks of `/120` (256 addresses each). Every network holds 240 address objects
//! (offsets 1 to 240) and one DHCP pool of ten addresses (offsets 241 to 250), so 61,440
//! addresses, 256 ranges and 257 prefixes are written straight to the store through the
//! typed tables, bypassing the planner, to keep the setup fast. The service is created
//! afterwards: that builds the tree index from the tables, which is the first measurement.
//!
//! Measured on the development machine (Windows 11, 32 logical CPUs, `MemStore`), in
//! milliseconds, the best of five runs unless noted:
//!
//! | Operation | debug build | release build |
//! |---|---|---|
//! | build the index from 61,440 addresses (once) | 1,580 | 166 |
//! | `tree(vrf, None, None)`, 257 nodes with utilization | 6.0 | 0.43 |
//! | `utilization(root)` | 3.6 | 0.17 |
//! | `next_free_addresses` in a nearly full /120 | 0.08 | 0.01 |
//! | one `execute` creating an address (plan, apply, index update) | 0.9 | 0.4 |
//!
//! The assertion is on the tree with utilization: under 50 ms in a debug build.

mod common;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use common::*;
use tenko_core::{
    AddressId, PrefixId, Principal, RangeId, SystemComponent, TenantId, Timestamp, VrfId,
    ipam::{
        Address, AllocPolicy, Meta, Prefix, PrefixRole, Range, RangeRole, Stamp, Status, Tenant,
        Vrf,
    },
};
use tenko_ipam::{
    IpamCommand, IpamService, codes,
    tables::{
        ADDRESS_IPS, ADDRESSES, PREFIX_CIDRS, PREFIX_RANGES, PREFIXES, RANGES, TENANT_NAMES,
        TENANTS, VRF_NAMES, VRFS,
    },
};
use tenko_store::{MemStore, Store, WriteBatch};

const NETWORKS: u32 = 256;
/// Address objects per network: offsets 1 to this.
const USED: u32 = 240;
/// The DHCP pool of each network.
const POOL: (u32, u32) = (241, 250);
/// Addresses per chunk of raw writes.
const CHUNK: usize = 2_000;
const BASE: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0000;

fn address_text(network: u32, offset: u32) -> String {
    std::net::Ipv6Addr::from(BASE | (u128::from(network) << 8) | u128::from(offset)).to_string()
}

fn network_text(network: u32) -> String {
    format!("{}/120", address_text(network, 0))
}

struct Space {
    vrf: VrfId,
    root: PrefixId,
    networks: Vec<PrefixId>,
    pools: Vec<RangeId>,
}

async fn propose(store: &MemStore, batch: WriteBatch) {
    store.propose(batch).await.expect("raw write");
}

/// Writes the whole space into the store, in chunks.
#[allow(clippy::too_many_lines)] // One pass over the whole space.
async fn fill(store: &MemStore) -> Space {
    let at = Timestamp::now();
    let by = Principal::system(SystemComponent::Import);
    let meta = || Meta::new(Stamp::new(at, by.clone()));
    let batch = || WriteBatch::new(by.clone(), at);
    let (tenant, vrf, root) = (
        TenantId::generate(),
        VrfId::generate(),
        PrefixId::generate(),
    );

    // Tenant, VRF and every prefix and range.
    let mut first = batch();
    first
        .put_typed(
            &TENANTS,
            &tenant,
            &Tenant {
                dns: tenko_core::dns::TenantDns::default(),
                id: tenant,
                name: "default".to_owned(),
                meta: meta(),
            },
        )
        .expect("tenant")
        .put_typed(&TENANT_NAMES, &"default".to_owned(), &tenant)
        .expect("name")
        .put_typed(
            &VRFS,
            &vrf,
            &Vrf {
                id: vrf,
                tenant,
                name: "default".to_owned(),
                rd: None,
                meta: meta(),
            },
        )
        .expect("vrf")
        .put_typed(&VRF_NAMES, &(tenant, "default".to_owned()), &vrf)
        .expect("name");
    let prefix_of = |id: PrefixId, cidr: &str, role: PrefixRole| Prefix {
        id,
        vrf,
        cidr: net(cidr),
        role,
        status: Status::Active,
        vlan: None,
        site: None,
        alarm: None,
        alloc: AllocPolicy::Lowest,
        dns_reverse: None,
        meta: meta(),
    };
    let supernet_prefix = prefix_of(root, "2001:db8::/112", PrefixRole::Supernet);
    first
        .put_typed(&PREFIXES, &root, &supernet_prefix)
        .expect("root")
        .put_typed(&PREFIX_CIDRS, &(vrf, supernet_prefix.cidr), &root)
        .expect("root cidr");
    let mut networks = Vec::new();
    let mut pools = Vec::new();
    for n in 0..NETWORKS {
        let id = PrefixId::generate();
        let item = prefix_of(id, &network_text(n), PrefixRole::Network);
        first
            .put_typed(&PREFIXES, &id, &item)
            .expect("network")
            .put_typed(&PREFIX_CIDRS, &(vrf, item.cidr), &id)
            .expect("network cidr");
        let pool = RangeId::generate();
        first
            .put_typed(
                &RANGES,
                &pool,
                &Range {
                    id: pool,
                    prefix: id,
                    first: ip(&address_text(n, POOL.0)),
                    last: ip(&address_text(n, POOL.1)),
                    role: RangeRole::DhcpPool,
                    lease_secs: None,
                    delegated_len: None,
                    status: Status::Active,
                    meta: meta(),
                },
            )
            .expect("range")
            .put_typed(&PREFIX_RANGES, &(id, pool), &())
            .expect("membership");
        networks.push(id);
        pools.push(pool);
    }
    propose(store, first).await;

    // The addresses, a few thousand rows per batch.
    let mut pending = batch();
    let mut rows = 0;
    for (n, network) in networks.iter().enumerate() {
        let n = u32::try_from(n).expect("small");
        for offset in 1..=USED {
            let id = AddressId::generate();
            let item = Address {
                id,
                vrf,
                ip: ip(&address_text(n, offset)),
                prefix: *network,
                status: Status::Active,
                interface: None,
                dns_name: None,
                meta: meta(),
            };
            pending
                .put_typed(&ADDRESSES, &id, &item)
                .expect("address")
                .put_typed(&ADDRESS_IPS, &(vrf, item.ip), &id)
                .expect("address ip");
            rows += 1;
            if rows == CHUNK {
                propose(store, std::mem::replace(&mut pending, batch())).await;
                rows = 0;
            }
        }
    }
    if rows > 0 {
        propose(store, pending).await;
    }
    Space {
        vrf,
        root,
        networks,
        pools,
    }
}

/// The best of `runs` runs of `f`, and the last answer.
fn best_of<T>(runs: usize, mut f: impl FnMut() -> T) -> (Duration, T) {
    let mut best = Duration::MAX;
    let mut answer = None;
    for _ in 0..runs {
        let started = Instant::now();
        let value = f();
        best = best.min(started.elapsed());
        answer = Some(value);
    }
    (best, answer.expect("at least one run"))
}

fn ms(duration: Duration) -> String {
    format!("{:.2} ms", duration.as_secs_f64() * 1000.0)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from setup to the last check.
async fn the_tree_of_a_sixteen_equivalent_space_is_fast() {
    let store = MemStore::default();
    let setup = Instant::now();
    let space = fill(&store).await;
    eprintln!(
        "tree_perf: raw setup of 61,440 addresses took {}",
        ms(setup.elapsed())
    );

    // The service builds the index from the tables.
    let started = Instant::now();
    let service =
        IpamService::with_direct_jobs(Arc::new(store.clone()) as Arc<dyn Store>).expect("service");
    let build = started.elapsed();
    eprintln!("tree_perf: index build {}", ms(build));
    assert_eq!(service.tree().revision(), store.status().revision);

    // The flattened tree with utilization of every node.
    let (tree_time, nodes) = best_of(5, || service.tree().tree(space.vrf, None, None));
    eprintln!("tree_perf: tree of 257 nodes {} (best of 5)", ms(tree_time));
    assert!(
        tree_time < Duration::from_millis(50),
        "the tree took {} (best of 5)",
        ms(tree_time)
    );
    assert_eq!(nodes.len(), 257);
    let root = &nodes[0];
    assert_eq!(root.id, space.root);
    assert_eq!((root.depth, root.parent, root.children), (0, None, 256));
    assert_eq!(root.role, PrefixRole::Supernet);
    // The children cover the whole supernet.
    assert_eq!(root.utilization.capacity, "65536");
    assert_eq!(root.utilization.covered, "65536");
    assert_eq!(root.utilization.used, "65536");
    assert_eq!(root.utilization.free, "0");
    assert!((root.utilization.percent - 100.0).abs() < f64::EPSILON);
    let depths: Vec<u32> = nodes.iter().map(|n| n.depth).collect();
    assert!(depths[1..].iter().all(|d| *d == 1));
    assert_eq!(nodes.iter().map(|n| n.children).sum::<u32>(), 256);
    // Pre-order and ascending: the networks follow the root in address order.
    let listed: Vec<PrefixId> = nodes[1..].iter().map(|n| n.id).collect();
    assert_eq!(listed, space.networks);
    for (n, node) in nodes[1..].iter().enumerate() {
        assert_eq!(node.parent, Some(space.root), "network {n}");
        assert_eq!(
            node.cidr,
            net(&network_text(u32::try_from(n).expect("small")))
        );
        assert_eq!(
            (
                node.utilization.capacity.as_str(),
                node.utilization.used.as_str(),
                node.utilization.reserved.as_str(),
                node.utilization.free.as_str(),
            ),
            ("255", "240", "10", "5"),
            "network {n}"
        );
        assert!(
            (node.utilization.percent - 98.0).abs() < f64::EPSILON,
            "{}",
            node.utilization.percent
        );
        assert_eq!(node.utilization.by_role.len(), 1);
        assert_eq!(node.utilization.by_role[0].size, "10");
        assert_eq!(node.utilization.by_role[0].used, "0");
    }
    // Limits: the top level only, and a subtree.
    let top = service.tree().tree(space.vrf, None, Some(0));
    assert_eq!(top.len(), 1);
    let within = service
        .tree()
        .tree(space.vrf, Some(net("2001:db8::100/120")), None);
    assert_eq!(within.len(), 1);
    assert_eq!(within[0].id, space.networks[1]);

    // Utilization of the root alone.
    let (util_time, utilization) = best_of(5, || service.tree().utilization(space.root));
    eprintln!("tree_perf: utilization(root) {} (best of 5)", ms(util_time));
    let utilization = utilization.expect("utilization");
    assert_eq!(
        (utilization.capacity, utilization.used, utilization.free),
        (65_536, 65_536, 0)
    );
    assert_eq!(service.tree().children(space.root).len(), 256);
    assert_eq!(
        service
            .tree()
            .containing(space.vrf, ip(&address_text(17, 33))),
        Some(space.networks[17])
    );

    // Next free in a nearly full network: five addresses are left outside the pool.
    let target = space.networks[7];
    let (free_time, free) = best_of(5, || {
        service.tree().next_free_addresses(target, None, None, 10)
    });
    eprintln!(
        "tree_perf: next_free_addresses {} (best of 5)",
        ms(free_time)
    );
    let expected: Vec<_> = (251..=255).map(|o| ip(&address_text(7, o))).collect();
    assert_eq!(free, expected);
    let highest = service
        .tree()
        .next_free_addresses(target, Some(AllocPolicy::Highest), None, 10);
    assert_eq!(highest, expected.iter().rev().copied().collect::<Vec<_>>());
    let in_pool = service
        .tree()
        .next_free_addresses(target, None, Some(space.pools[7]), 20);
    assert_eq!(
        in_pool,
        (241..=250)
            .map(|o| ip(&address_text(7, o)))
            .collect::<Vec<_>>()
    );

    // One more address through the service: the index follows incrementally.
    let revision = service.tree().revision();
    let started = Instant::now();
    let applied = run(
        &service,
        vec![IpamCommand::CreateAddress(address(
            Some(space.vrf),
            &address_text(7, 251),
        ))],
    )
    .await;
    eprintln!(
        "tree_perf: execute of one address {}",
        ms(started.elapsed())
    );
    assert_eq!(applied.retries, 0);
    assert_eq!(service.tree().revision(), applied.revision);
    assert!(applied.revision > revision);
    let after = service.tree().utilization(target).expect("utilization");
    assert_eq!((after.used, after.free), (241, 4));
    let neighbour = service
        .tree()
        .utilization(space.networks[8])
        .expect("utilization");
    assert_eq!(
        (neighbour.used, neighbour.free),
        (240, 5),
        "other networks stay as they were"
    );
    let root_after = service.tree().utilization(space.root).expect("utilization");
    assert_eq!((root_after.used, root_after.free), (65_536, 0));
    assert_eq!(
        service
            .tree()
            .next_free_addresses(target, None, None, 10)
            .len(),
        4
    );

    // The rest of the network fills through allocation, and then it is full.
    for offset in 252..=255 {
        let applied = run(
            &service,
            vec![IpamCommand::AllocateAddress(allocate(target))],
        )
        .await;
        assert_eq!(applied.retries, 0);
        let stored = fetch::<Address>(&service, id_of(applied.results[0])).await;
        assert_eq!(stored.ip, ip(&address_text(7, offset)));
    }
    let full = service.tree().utilization(target).expect("utilization");
    assert_eq!((full.used, full.reserved, full.free), (245, 10, 0));
    assert_eq!(
        service
            .tree()
            .next_free_addresses(target, None, None, 10)
            .len(),
        0
    );
    run_err(
        &service,
        vec![IpamCommand::AllocateAddress(allocate(target))],
        codes::ADDRESS_FULL,
    )
    .await;
    // The tree with utilization stays fast after the changes.
    let (again, nodes) = best_of(5, || service.tree().tree(space.vrf, None, None));
    eprintln!(
        "tree_perf: tree of 257 nodes after the changes {}",
        ms(again)
    );
    assert!(again < Duration::from_millis(50), "{}", ms(again));
    assert_eq!(nodes[8].utilization.used, "245");
}
