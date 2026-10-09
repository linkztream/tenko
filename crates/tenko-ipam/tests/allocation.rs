//! Concurrent next free allocation (IPAM-07): many allocators on one controller, several
//! controllers over one store, prefix allocation, and allocation mixed with manual creates.
//!
//! Each test starts its tasks on a multi-thread runtime. The allocation protocol promises
//! that two allocators never receive the same address or network and that allocators on one
//! controller queue instead of invalidating each other's plans.

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
};

use common::*;
use tenko_core::{AddressId, PrefixId, ipam::Address};
use tenko_ipam::{
    Applied, DirectJobs, IpNet, IpamCommand, IpamConfig, IpamError, IpamService, PlanOptions,
    codes, command::AllocatePrefix, tables::PREFIXES,
};
use tenko_store::{KeyRange, MemStore, ReadViewExt, Store};
use tokio::task::JoinSet;

/// A next-free prefix command.
fn allocate_prefix(parent: PrefixId, length: u8) -> AllocatePrefix {
    AllocatePrefix {
        parent,
        length,
        policy: None,
        id: None,
        role: None,
        status: None,
        vlan: None,
        site: None,
        alarm: None,
        tags: BTreeSet::new(),
        custom: BTreeMap::new(),
        description: None,
        hint: None,
    }
}

/// `count` controllers over clones of one store, each with its own prefix tree.
fn controllers(store: &MemStore, count: usize) -> Vec<Arc<IpamService>> {
    (0..count)
        .map(|_| {
            let shared: Arc<dyn Store> = Arc::new(store.clone());
            IpamService::new(
                Arc::clone(&shared),
                Arc::new(DirectJobs::new(shared)),
                IpamConfig::default(),
            )
            .expect("controller")
        })
        .collect()
}

/// Runs one single-command request per entry, all at once; the label tells the kinds of
/// request apart in the results.
async fn race<L: Copy + Send + 'static>(
    commands: Vec<(L, Arc<IpamService>, IpamCommand)>,
) -> Vec<(L, Result<Applied, IpamError>)> {
    let mut tasks = JoinSet::new();
    for (label, service, command) in commands {
        tasks.spawn(async move {
            let result = service
                .execute(&[command], &person(), &PlanOptions::default())
                .await;
            (label, result)
        });
    }
    let mut results = Vec::new();
    while let Some(done) = tasks.join_next().await {
        results.push(done.expect("task"));
    }
    results
}

/// The addresses behind the results of address allocations.
async fn ips_of(service: &IpamService, applied: &[Applied]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for item in applied {
        for result in &item.results {
            let id: AddressId = id_of(*result);
            ips.push(fetch::<Address>(service, id).await.ip);
        }
    }
    ips
}

fn host_range(prefix: &str, first: u8, last: u8) -> BTreeSet<IpAddr> {
    (first..=last)
        .map(|n| ip(&format!("{prefix}.{n}")))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn thirty_two_allocators_on_one_controller_get_distinct_addresses() {
    let (service, store) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(network)]).await;
    let before = revision_of(&store);

    let commands = (0..32)
        .map(|_| {
            (
                (),
                Arc::clone(&service),
                IpamCommand::AllocateAddress(allocate(network_id)),
            )
        })
        .collect();
    let results = race(commands).await;
    let applied: Vec<Applied> = results
        .into_iter()
        .map(|((), r)| r.expect("every allocator succeeds"))
        .collect();
    let max_retries = applied.iter().map(|a| a.retries).max().unwrap_or_default();
    assert!(
        applied.iter().all(|a| a.retries <= 1),
        "allocators on one controller queue; most retries seen: {max_retries}"
    );
    eprintln!("one controller, 32 allocators: most retries seen {max_retries}");

    // Distinct addresses; with the default policy and nothing else around, the lowest 32.
    let ips = ips_of(&service, &applied).await;
    let distinct: BTreeSet<IpAddr> = ips.iter().copied().collect();
    assert_eq!(ips.len(), 32);
    assert_eq!(distinct.len(), 32, "an address was handed out twice");
    assert_eq!(distinct, host_range("192.0.2", 1, 32));
    // One revision per allocation.
    let revisions: BTreeSet<_> = applied.iter().map(|a| a.revision).collect();
    assert_eq!(revisions.len(), 32);
    assert_eq!(revision_of(&store), tenko_core::Revision(before.0 + 32));
    assert_eq!(all_of::<Address>(&service).await.len(), 32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_controllers_with_eight_allocators_each_get_distinct_addresses() {
    let store = MemStore::default();
    let services = controllers(&store, 4);
    let network = prefix(None, "198.51.100.0/24");
    let network_id = network.id.expect("id");
    run(&services[0], vec![IpamCommand::CreatePrefix(network)]).await;

    let commands = (0..32)
        .map(|n| {
            (
                (),
                Arc::clone(&services[n % 4]),
                IpamCommand::AllocateAddress(allocate(network_id)),
            )
        })
        .collect();
    let results = race(commands).await;
    let failures: Vec<String> = results
        .iter()
        .filter_map(|((), r)| r.as_ref().err().map(|e| format!("{} ({e})", e.code_str())))
        .collect();
    let applied: Vec<Applied> = results.into_iter().filter_map(|((), r)| r.ok()).collect();
    let max_retries = applied.iter().map(|a| a.retries).max().unwrap_or_default();
    eprintln!(
        "four controllers, 32 allocators: most retries seen {max_retries}, {} failures",
        failures.len()
    );

    // Safety first: whatever succeeded got its own address, the lowest ones, and every
    // controller's tree followed the commits of the others.
    let ips = ips_of(&services[0], &applied).await;
    let distinct: BTreeSet<IpAddr> = ips.iter().copied().collect();
    assert_eq!(distinct.len(), ips.len(), "an address was handed out twice");
    assert_eq!(
        distinct,
        host_range("198.51.100", 1, u8::try_from(ips.len()).expect("small"))
    );
    let view = services[0].view(None).await.expect("view");
    for service in &services {
        assert_eq!(service.tree().revision(), view.revision());
        let utilization = service.tree().utilization(network_id).expect("utilization");
        assert_eq!(utilization.used, u128::try_from(ips.len()).expect("small"));
    }

    // Then liveness: every allocator gets its address within the attempts of a request.
    assert!(
        failures.is_empty(),
        "{} of 32 allocators failed (most retries seen by the others: {max_retries}): {failures:?}",
        failures.len()
    );
    assert_eq!(
        applied.len(),
        32,
        "all succeed; most retries seen: {max_retries}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sixteen_concurrent_prefix_allocations_get_distinct_blocks() {
    let (service, _) = service();
    let outer = supernet(None, "198.51.100.0/24");
    let outer_id = outer.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(outer)]).await;

    let commands = (0..16)
        .map(|_| {
            (
                (),
                Arc::clone(&service),
                IpamCommand::AllocatePrefix(allocate_prefix(outer_id, 28)),
            )
        })
        .collect();
    let applied: Vec<Applied> = race(commands)
        .await
        .into_iter()
        .map(|((), r)| r.expect("every allocator succeeds"))
        .collect();
    let max_retries = applied.iter().map(|a| a.retries).max().unwrap_or_default();
    assert!(
        applied.iter().all(|a| a.retries <= 1),
        "most retries seen: {max_retries}"
    );
    eprintln!("16 prefix allocators: most retries seen {max_retries}");

    let view = snapshot(&service).await;
    let mut networks: Vec<IpNet> = Vec::new();
    for item in &applied {
        let id: PrefixId = id_of(item.results[0]);
        let (stored, _) = view
            .get_typed(&PREFIXES, &id)
            .expect("read")
            .expect("prefix");
        assert_eq!(stored.cidr.prefix_len(), 28);
        networks.push(stored.cidr);
    }
    let distinct: BTreeSet<IpNet> = networks.iter().copied().collect();
    assert_eq!(distinct.len(), 16);
    // Pairwise disjoint, and inside the supernet.
    let parent = net("198.51.100.0/24");
    for (n, a) in networks.iter().enumerate() {
        assert!(
            parent.contains(&a.network()) && parent.contains(&a.broadcast()),
            "{a}"
        );
        for b in &networks[n + 1..] {
            assert!(
                !a.contains(&b.network()) && !b.contains(&a.network()),
                "{a} overlaps {b}"
            );
        }
    }
    // All sixteen /28 blocks of the /24 are taken now.
    assert_eq!(service.tree().children(outer_id).len(), 16);
    let error = run_err(
        &service,
        vec![IpamCommand::AllocatePrefix(allocate_prefix(outer_id, 28))],
        codes::PREFIX_FULL,
    )
    .await;
    assert_eq!(status_of(&error), 409);
    let live = view
        .scan_typed(&PREFIXES, KeyRange::all(), usize::MAX, false)
        .expect("scan");
    assert_eq!(live.len(), 17);
}

/// `pairs` allocators and `pairs` manual creates race in one network; the manual creates
/// ask for the addresses the allocators are about to reach.
async fn mixed_allocation_and_creates(pairs: u8) {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Kind {
        Allocator,
        Manual,
    }
    let (service, _) = service();
    let network = prefix(None, "203.0.113.0/24");
    let network_id = network.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(network)]).await;

    let mut commands: Vec<(Kind, Arc<IpamService>, IpamCommand)> = Vec::new();
    for n in 1..=pairs {
        commands.push((
            Kind::Allocator,
            Arc::clone(&service),
            IpamCommand::AllocateAddress(allocate(network_id)),
        ));
        commands.push((
            Kind::Manual,
            Arc::clone(&service),
            IpamCommand::CreateAddress(address(None, &format!("203.0.113.{n}"))),
        ));
    }
    let results = race(commands).await;
    let mut allocated = 0;
    let mut created = 0;
    let mut duplicates = 0;
    let mut unexpected: Vec<String> = Vec::new();
    for (kind, result) in &results {
        match (kind, result) {
            (Kind::Allocator, Ok(_)) => allocated += 1,
            (Kind::Manual, Ok(_)) => created += 1,
            (Kind::Manual, Err(error)) if error.is(codes::ADDRESS_DUPLICATE) => duplicates += 1,
            (kind, Err(error)) => {
                unexpected.push(format!("{kind:?}: {} ({error})", error.code_str()));
            }
        }
    }
    eprintln!("mixed: {allocated} allocated, {created} created, {duplicates} duplicates");

    // Safety first: no address exists twice, whatever failed.
    let addresses = all_of::<Address>(&service).await;
    let ips: BTreeSet<IpAddr> = addresses.iter().map(|a| a.ip).collect();
    assert_eq!(
        ips.len(),
        addresses.len(),
        "two address objects share an IP"
    );
    assert_eq!(addresses.len(), allocated + created);
    let view = snapshot(&service).await;
    let indexed = view
        .scan_typed(
            &tenko_ipam::tables::ADDRESS_IPS,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("scan");
    assert_eq!(indexed.len(), addresses.len());
    let utilization = service.tree().utilization(network_id).expect("utilization");
    assert_eq!(
        utilization.used,
        u128::try_from(addresses.len()).expect("small")
    );

    // Then liveness: only colliding manual creates fail, and every allocator succeeds.
    assert!(
        unexpected.is_empty(),
        "only colliding manual creates may fail, but: {unexpected:?} \
         ({allocated} allocated, {created} created, {duplicates} duplicates)"
    );
    assert_eq!(
        allocated,
        usize::from(pairs),
        "every allocator gets an address"
    );
    assert_eq!(created + duplicates, usize::from(pairs));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn allocation_and_manual_creates_mix_without_duplicates() {
    mixed_allocation_and_creates(6).await;
}

/// The same race with twice the writers. Each commit in the prefix invalidates the plans of
/// the others, and a request gives up after `IpamConfig::max_attempts` plans, so this load
/// exhausts the attempts of some requests (`ipam.contended`).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn allocation_and_manual_creates_mix_under_heavy_load() {
    mixed_allocation_and_creates(12).await;
}

// ----- concurrent churn ---------------------------------------------------------------------

/// A small deterministic generator (xorshift), so that every task makes the same choices on
/// every run; only the interleaving differs.
struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(bound).expect("small")).expect("small")
    }
}

/// What the tasks of the churn test know of the objects created so far.
#[derive(Default)]
struct Pool {
    prefixes: Vec<PrefixId>,
    addresses: Vec<AddressId>,
    deleted: Vec<tenko_core::ObjectRef>,
}

fn pick<T: Copy>(items: &[T], rng: &mut Rng) -> Option<T> {
    (!items.is_empty()).then(|| items[rng.below(items.len())])
}

/// One command chosen by `rng` against what the pool holds; `None` when the choice has no
/// target yet.
fn churn_command(
    pool: &std::sync::Mutex<Pool>,
    supernet_id: PrefixId,
    rng: &mut Rng,
) -> Option<IpamCommand> {
    let pool = pool.lock().expect("pool");
    let child = |rng: &mut Rng| {
        let length = 26 + u8::try_from(rng.below(3)).expect("small");
        let blocks = 1usize << (length - 24);
        let start = rng.below(blocks) * (1usize << (32 - length));
        net(&format!("192.0.2.{start}/{length}"))
    };
    Some(match rng.below(10) {
        0 | 1 => {
            IpamCommand::CreateAddress(address(None, &format!("192.0.2.{}", 1 + rng.below(254))))
        }
        2 | 3 => IpamCommand::CreatePrefix({
            let mut input = prefix(None, &child(rng).to_string());
            input.role = (rng.below(3) == 0).then_some(tenko_core::ipam::PrefixRole::Supernet);
            input
        }),
        4 => {
            IpamCommand::AllocateAddress(allocate(pick(&pool.prefixes, rng).unwrap_or(supernet_id)))
        }
        5 => IpamCommand::Delete {
            object: if rng.below(2) == 0 {
                pick(&pool.prefixes, rng)?.into()
            } else {
                pick(&pool.addresses, rng)?.into()
            },
            expected: None,
            cascade: rng.below(2) == 0,
        },
        6 | 7 => IpamCommand::Restore {
            object: pick(&pool.deleted, rng)?,
            expected: None,
        },
        8 => IpamCommand::UpdatePrefix(tenko_ipam::command::UpdatePrefix {
            id: pick(&pool.prefixes, rng)?,
            expected: None,
            patch: tenko_ipam::command::PrefixPatch {
                cidr: Some(child(rng)),
                ..Default::default()
            },
        }),
        _ => IpamCommand::UpdateAddress(tenko_ipam::command::UpdateAddress {
            id: pick(&pool.addresses, rng)?,
            expected: None,
            patch: tenko_ipam::command::AddressPatch {
                ip: Some(ip(&format!("192.0.2.{}", 1 + rng.below(254)))),
                ..Default::default()
            },
        }),
    })
}

/// Runs `steps` random commands; returns how many succeeded and the errors that are not
/// refusals of the request.
async fn churn(
    service: Arc<IpamService>,
    pool: Arc<std::sync::Mutex<Pool>>,
    supernet_id: PrefixId,
    seed: u64,
    steps: usize,
) -> (usize, Vec<String>) {
    let mut rng = Rng(seed);
    let (mut succeeded, mut broken) = (0, Vec::new());
    for _ in 0..steps {
        let Some(command) = churn_command(&pool, supernet_id, &mut rng) else {
            continue;
        };
        match try_run(&service, vec![command.clone()]).await {
            Ok(applied) => {
                succeeded += 1;
                let mut pool = pool.lock().expect("pool");
                match command {
                    IpamCommand::CreatePrefix(_) => pool.prefixes.push(id_of(applied.results[0])),
                    IpamCommand::CreateAddress(_) | IpamCommand::AllocateAddress(_) => {
                        pool.addresses.push(id_of(applied.results[0]));
                    }
                    IpamCommand::Delete { object, .. } => pool.deleted.push(object),
                    IpamCommand::Restore { object, .. } => pool.deleted.retain(|o| *o != object),
                    _ => {}
                }
            }
            // Refusals of the request, and giving up under contention, are fine.
            Err(error)
                if status_of(&error) < 500 && error.code_str() != codes::PLAN_STALE
                    || error.is(codes::CONTENDED) => {}
            Err(error) => broken.push(format!("{command:?}: {error:?}")),
        }
    }
    (succeeded, broken)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_churn_keeps_every_invariant() {
    let (service, store) = service();
    let outer = supernet(None, "192.0.2.0/24");
    let outer_id = outer.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(outer)]).await;
    let pool = Arc::new(std::sync::Mutex::new(Pool {
        prefixes: vec![outer_id],
        ..Pool::default()
    }));

    let mut tasks = JoinSet::new();
    for seed in 1..=8u64 {
        tasks.spawn(churn(
            Arc::clone(&service),
            Arc::clone(&pool),
            outer_id,
            0x9E37_79B9_7F4A_7C15 ^ (seed * 0x1000_0000_01B3),
            60,
        ));
    }
    let (mut succeeded, mut broken) = (0, Vec::new());
    while let Some(done) = tasks.join_next().await {
        let (ok, errors) = done.expect("task");
        succeeded += ok;
        broken.extend(errors);
    }
    assert!(broken.is_empty(), "internal errors: {broken:?}");
    assert!(
        succeeded >= 100,
        "only {succeeded} of 480 requests succeeded"
    );
    eprintln!("churn: {succeeded} of 480 requests succeeded");

    check_invariants(&service)
        .await
        .unwrap_or_else(|problem| panic!("after the churn: {problem}"));
    // The index of another controller, built from the tables now, agrees as well.
    let other = controllers(&store, 1).remove(0);
    let view = snapshot(&service).await;
    let vrf = fetch::<tenko_core::ipam::Prefix>(&service, outer_id)
        .await
        .vrf;
    assert_eq!(
        other.tree().tree(vrf, None, None),
        service.tree().tree(vrf, None, None)
    );
    assert_eq!(other.tree().revision(), view.revision());
}
