//! Property tests of the IPAM domain over `MemStore`.
//!
//! 1. After any sequence of creates, deletes, restores and resizes, no two live prefixes of
//!    a VRF overlap except as supernet over contents, every address belongs to the most
//!    specific live prefix of its VRF, and the uniqueness tables and the prefix tree agree
//!    with the live objects.
//! 2. Next free never returns a used address, and allocates exactly the free space.
//! 3. A previewed and applied plan leaves the same store as a direct execute.
//!
//! Each case runs on its own current-thread runtime. The case count is kept modest so that
//! the suite stays well under a minute in debug builds.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use common::*;
use proptest::prelude::*;
use tenko_core::{
    AddressId, HostId, InterfaceId, ObjectRef, PrefixId, RangeId, RequestCtx, RequestId, SiteId,
    VrfId,
    ipam::{AllocPolicy, AssignmentMode, PrefixRole, RangeRole, Status},
    table::TableDef,
};
use tenko_ipam::{
    IpNet, IpamCommand, IpamService, PlanOptions, codes,
    command::{
        AddressPatch, AllocateAddress, AllocatePrefix, PrefixPatch, RangePatch, SiteInput,
        UpdateAddress, UpdatePrefix, UpdateRange,
    },
    tables::{
        ADDRESS_IPS, ADDRESSES, ALARMS, CUSTOM_FIELD_KEYS, CUSTOM_FIELDS, FIELD_USAGE, HISTORY,
        HOST_INTERFACES, HOST_NAMES, HOSTS, INTERFACE_ADDRESSES, INTERFACE_MACS, INTERFACES,
        PREFIX_CIDRS, PREFIX_RANGES, PREFIXES, RANGES, RECEIPTS, SITE_NAMES, SITES, TAG_USAGE,
        TENANT_NAMES, TENANTS, VLAN_VIDS, VLANS, VRF_NAMES, VRFS,
    },
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, Versioned};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

/// The case count, overridable with `PROPTEST_CASES` for deeper runs.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        max_shrink_iters: 200,
        // No regression files next to the sources.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Whether an error is a failure of the system rather than a refusal of the request.
fn is_internal(error: &tenko_ipam::IpamError) -> bool {
    status_of(error) >= 500
        || error.code_str().starts_with("sys.")
        || [codes::PLAN_STALE, codes::CONTENDED, codes::JOB_FAILED].contains(&error.code_str())
}

// ----- generators --------------------------------------------------------------------------

/// A network in the documentation space: IPv4 /24 to /30 inside 192.0.2.0/24 or
/// 198.51.100.0/24, or IPv6 /48 to /64 on a nibble boundary inside `2001:db8::/48`.
#[derive(Debug, Clone, Copy)]
enum NetSpec {
    V4 { base: u8, len: u8, host: u8 },
    V6 { len: u8, subnet: u8 },
}

impl NetSpec {
    fn text(self) -> String {
        match self {
            NetSpec::V4 { base, len, host } => {
                let root = if base == 0 { "192.0.2" } else { "198.51.100" };
                let size = 1u16 << (32 - u32::from(len));
                let mask = u8::try_from(256 - size).unwrap_or(0);
                format!("{root}.{}/{len}", host & mask)
            }
            NetSpec::V6 { len, subnet } => {
                // The subnet identifier is the 16 bits after /48; keep the bits the length
                // covers, on top of a nibble-aligned base of 16 values.
                let wanted = u32::from(subnet) << 4;
                let mask = (0xFFFFu32 << (64 - u32::from(len))) & 0xFFFF;
                format!("2001:db8:0:{:x}::/{len}", wanted & mask)
            }
        }
    }

    fn net(self) -> IpNet {
        net(&self.text())
    }

    /// The same selectors, read in the given family.
    fn in_family(self, v6: bool) -> NetSpec {
        match (self, v6) {
            (NetSpec::V4 { .. }, false) | (NetSpec::V6 { .. }, true) => self,
            (NetSpec::V4 { base, len, host }, true) => NetSpec::V6 {
                len: 48 + 4 * (len % 5),
                subnet: host % 16 + base,
            },
            (NetSpec::V6 { len, subnet }, false) => NetSpec::V4 {
                base: subnet % 2,
                len: 24 + (len % 7),
                host: subnet.wrapping_mul(17),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AddrSpec {
    V4 { base: u8, host: u8 },
    V6 { subnet: u8, host: u8 },
}

impl AddrSpec {
    fn text(self) -> String {
        match self {
            AddrSpec::V4 { base, host } => {
                let root = if base == 0 { "192.0.2" } else { "198.51.100" };
                format!("{root}.{host}")
            }
            AddrSpec::V6 { subnet, host } => {
                format!(
                    "2001:db8:0:{:x}::{:x}",
                    u16::from(subnet % 16) << 4,
                    host % 16
                )
            }
        }
    }
}

fn net_spec() -> impl Strategy<Value = NetSpec> {
    prop_oneof![
        3 => (0u8..2, 24u8..=30, any::<u8>())
            .prop_map(|(base, len, host)| NetSpec::V4 { base, len, host }),
        2 => (prop::sample::select(vec![48u8, 52, 56, 60, 64]), 0u8..16)
            .prop_map(|(len, subnet)| NetSpec::V6 { len, subnet }),
    ]
}

fn addr_spec() -> impl Strategy<Value = AddrSpec> {
    prop_oneof![
        3 => (0u8..2, any::<u8>()).prop_map(|(base, host)| AddrSpec::V4 { base, host }),
        2 => (0u8..16, 0u8..16).prop_map(|(subnet, host)| AddrSpec::V6 { subnet, host }),
    ]
}

fn role_spec() -> impl Strategy<Value = Option<PrefixRole>> {
    prop_oneof![
        4 => Just(None),
        3 => Just(Some(PrefixRole::Supernet)),
        1 => Just(Some(PrefixRole::Network)),
    ]
}

// ----- 1. no overlap after any command sequence --------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    /// A prefix anywhere in the documentation space.
    CreatePrefix {
        vrf: usize,
        net: NetSpec,
        role: Option<PrefixRole>,
    },
    /// A prefix inside a prefix created earlier.
    CreateChild {
        pick: usize,
        extra: u8,
        index: u8,
        role: Option<PrefixRole>,
    },
    /// An address anywhere.
    CreateAddress {
        vrf: usize,
        addr: AddrSpec,
    },
    /// An address at an offset inside a prefix created earlier.
    CreateAddressIn {
        pick: usize,
        offset: u8,
    },
    Delete {
        pick: usize,
        cascade: bool,
    },
    Restore {
        pick: usize,
    },
    Resize {
        pick: usize,
        net: NetSpec,
    },
    /// An address moves to an offset inside another prefix.
    Renumber {
        pick: usize,
        target: usize,
        offset: u8,
    },
    /// The next free address of a prefix.
    AllocateAddress {
        pick: usize,
        highest: bool,
    },
    /// The next free child of a prefix.
    AllocatePrefix {
        pick: usize,
        extra: u8,
        highest: bool,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0usize..2, net_spec(), role_spec())
            .prop_map(|(vrf, net, role)| Op::CreatePrefix { vrf, net, role }),
        5 => (any::<usize>(), 1u8..=3, any::<u8>(), role_spec())
            .prop_map(|(pick, extra, index, role)| Op::CreateChild { pick, extra, index, role }),
        1 => (0usize..2, addr_spec()).prop_map(|(vrf, addr)| Op::CreateAddress { vrf, addr }),
        6 => (any::<usize>(), any::<u8>())
            .prop_map(|(pick, offset)| Op::CreateAddressIn { pick, offset }),
        3 => (any::<usize>(), any::<bool>())
            .prop_map(|(pick, cascade)| Op::Delete { pick, cascade }),
        3 => any::<usize>().prop_map(|pick| Op::Restore { pick }),
        2 => (any::<usize>(), net_spec()).prop_map(|(pick, net)| Op::Resize { pick, net }),
        2 => (any::<usize>(), any::<usize>(), any::<u8>())
            .prop_map(|(pick, target, offset)| Op::Renumber { pick, target, offset }),
        3 => (any::<usize>(), any::<bool>())
            .prop_map(|(pick, highest)| Op::AllocateAddress { pick, highest }),
        2 => (any::<usize>(), 1u8..=3, any::<bool>())
            .prop_map(|(pick, extra, highest)| Op::AllocatePrefix { pick, extra, highest }),
    ]
}

/// What the interpreter knows of the objects it created.
#[derive(Default)]
struct Model {
    /// Identifier, VRF and network (as last set).
    prefixes: Vec<(PrefixId, usize, IpNet)>,
    addresses: Vec<AddressId>,
    deleted: Vec<ObjectRef>,
}

impl Model {
    fn any_object(&self, pick: usize) -> Option<ObjectRef> {
        let all: Vec<ObjectRef> = self
            .prefixes
            .iter()
            .map(|(id, _, _)| ObjectRef::from(*id))
            .chain(self.addresses.iter().map(|id| ObjectRef::from(*id)))
            .collect();
        (!all.is_empty()).then(|| all[pick % all.len()])
    }
}

/// The address `offset` addresses into a network (wrapping inside IPv4 networks).
fn address_in(net: IpNet, offset: u8) -> std::net::IpAddr {
    match net {
        IpNet::V4(net) => {
            let size = 1u64 << (32 - u32::from(net.prefix_len()));
            let value = u64::from(u32::from(net.network())) + u64::from(offset) % size;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                u32::try_from(value).expect("inside the network"),
            ))
        }
        IpNet::V6(net) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            u128::from(net.network()) + u128::from(offset),
        )),
    }
}

#[allow(clippy::too_many_lines)] // One arm per operation.
async fn apply_op(
    service: &IpamService,
    vrfs: &[VrfId; 2],
    model: &mut Model,
    op: &Op,
) -> Result<(), tenko_ipam::IpamError> {
    match op {
        Op::CreatePrefix { vrf, net, role } => {
            let mut input = prefix(Some(vrfs[*vrf]), &net.text());
            input.role = *role;
            let (id, cidr) = (input.id.expect("id"), input.cidr);
            try_run(service, vec![IpamCommand::CreatePrefix(input)]).await?;
            model.prefixes.push((id, *vrf, cidr));
        }
        Op::CreateChild {
            pick,
            extra,
            index,
            role,
        } => {
            if model.prefixes.is_empty() {
                return Ok(());
            }
            let (_, vrf, parent) = model.prefixes[*pick % model.prefixes.len()];
            // IPv6 children stay on a nibble boundary.
            let (extra, cap) = match parent {
                IpNet::V4(_) => (*extra, 30),
                IpNet::V6(_) => (4, 64),
            };
            let length = (parent.prefix_len() + extra).min(cap);
            let Ok(subnets) = parent.subnets(length) else {
                return Ok(());
            };
            let count = 1usize << (length - parent.prefix_len());
            let Some(child) = subnets.into_iter().nth(usize::from(*index) % count) else {
                return Ok(());
            };
            let mut input = prefix(Some(vrfs[vrf]), &child.to_string());
            input.role = *role;
            let id = input.id.expect("id");
            try_run(service, vec![IpamCommand::CreatePrefix(input)]).await?;
            model.prefixes.push((id, vrf, child));
        }
        Op::CreateAddress { vrf, addr } => {
            let input = address(Some(vrfs[*vrf]), &addr.text());
            let id = input.id.expect("id");
            try_run(service, vec![IpamCommand::CreateAddress(input)]).await?;
            model.addresses.push(id);
        }
        Op::CreateAddressIn { pick, offset } => {
            if model.prefixes.is_empty() {
                return Ok(());
            }
            let (_, vrf, cidr) = model.prefixes[*pick % model.prefixes.len()];
            let input = address(Some(vrfs[vrf]), &address_in(cidr, *offset).to_string());
            let id = input.id.expect("id");
            try_run(service, vec![IpamCommand::CreateAddress(input)]).await?;
            model.addresses.push(id);
        }
        Op::Delete { pick, cascade } => {
            let Some(object) = model.any_object(*pick) else {
                return Ok(());
            };
            try_run(
                service,
                vec![IpamCommand::Delete {
                    object,
                    expected: None,
                    cascade: *cascade,
                }],
            )
            .await?;
            model.deleted.push(object);
        }
        Op::Restore { pick } => {
            let object = if model.deleted.is_empty() {
                model.any_object(*pick)
            } else {
                Some(model.deleted[*pick % model.deleted.len()])
            };
            let Some(object) = object else {
                return Ok(());
            };
            try_run(
                service,
                vec![IpamCommand::Restore {
                    object,
                    expected: None,
                }],
            )
            .await?;
            model.deleted.retain(|o| *o != object);
        }
        Op::Resize { pick, net } => {
            if model.prefixes.is_empty() {
                return Ok(());
            }
            let index = *pick % model.prefixes.len();
            let (id, _, current) = model.prefixes[index];
            let cidr = net.in_family(current.addr().is_ipv6()).net();
            try_run(
                service,
                vec![IpamCommand::UpdatePrefix(UpdatePrefix {
                    id,
                    expected: None,
                    patch: PrefixPatch {
                        cidr: Some(cidr),
                        ..PrefixPatch::default()
                    },
                })],
            )
            .await?;
            model.prefixes[index].2 = cidr;
        }
        Op::Renumber {
            pick,
            target,
            offset,
        } => {
            if model.addresses.is_empty() || model.prefixes.is_empty() {
                return Ok(());
            }
            let id = model.addresses[*pick % model.addresses.len()];
            let (_, _, cidr) = model.prefixes[*target % model.prefixes.len()];
            try_run(
                service,
                vec![IpamCommand::UpdateAddress(UpdateAddress {
                    id,
                    expected: None,
                    patch: AddressPatch {
                        ip: Some(address_in(cidr, *offset)),
                        ..AddressPatch::default()
                    },
                })],
            )
            .await?;
        }
        Op::AllocateAddress { pick, highest } => {
            if model.prefixes.is_empty() {
                return Ok(());
            }
            let (prefix_id, _, _) = model.prefixes[*pick % model.prefixes.len()];
            let applied = try_run(
                service,
                vec![IpamCommand::AllocateAddress(AllocateAddress {
                    policy: Some(if *highest {
                        AllocPolicy::Highest
                    } else {
                        AllocPolicy::Lowest
                    }),
                    ..allocate(prefix_id)
                })],
            )
            .await?;
            model.addresses.push(id_of(applied.results[0]));
        }
        Op::AllocatePrefix {
            pick,
            extra,
            highest,
        } => {
            if model.prefixes.is_empty() {
                return Ok(());
            }
            let (parent_id, vrf, parent) = model.prefixes[*pick % model.prefixes.len()];
            let (extra, cap) = match parent {
                IpNet::V4(_) => (*extra, 30),
                IpNet::V6(_) => (4, 64),
            };
            let applied = try_run(
                service,
                vec![IpamCommand::AllocatePrefix(AllocatePrefix {
                    parent: parent_id,
                    length: (parent.prefix_len() + extra).min(cap),
                    policy: Some(if *highest {
                        AllocPolicy::Highest
                    } else {
                        AllocPolicy::Lowest
                    }),
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
                })],
            )
            .await?;
            let child: PrefixId = id_of(applied.results[0]);
            let cidr = fetch::<tenko_core::ipam::Prefix>(service, child).await.cidr;
            model.prefixes.push((child, vrf, cidr));
        }
    }
    Ok(())
}

async fn run_sequence(ops: Vec<Op>) -> Result<(), String> {
    let (service, _store) = service();
    let (alpha, beta) = (vrf("alpha"), vrf("beta"));
    let vrfs = [alpha.id.expect("id"), beta.id.expect("id")];
    try_run(
        &service,
        vec![IpamCommand::CreateVrf(alpha), IpamCommand::CreateVrf(beta)],
    )
    .await
    .map_err(|e| format!("setup: {e:?}"))?;
    let mut model = Model::default();
    for (n, op) in ops.iter().enumerate() {
        if let Err(error) = apply_op(&service, &vrfs, &mut model, op).await
            && is_internal(&error)
        {
            return Err(format!("step {n} {op:?}: internal error {error:?}"));
        }
        check_invariants(&service)
            .await
            .map_err(|e| format!("after step {n} {op:?}: {e}"))?;
    }
    Ok(())
}

proptest! {
    #![proptest_config(config(48))]

    #[test]
    fn no_overlap_inside_a_vrf_after_any_command_sequence(
        ops in prop::collection::vec(op(), 1..=30)
    ) {
        let outcome = runtime().block_on(run_sequence(ops));
        prop_assert!(outcome.is_ok(), "{}", outcome.err().unwrap_or_default());
    }
}

// ----- 2. next free never returns a used address ---------------------------------------------

/// A network with existing addresses and ranges, described by offsets inside the network.
#[derive(Debug, Clone)]
struct Layout {
    v6: bool,
    /// Which block of the family: the /26 or /27 slot, or the third byte group of the /120.
    slot: u8,
    /// IPv4 only: /27 instead of /26.
    small: bool,
    addresses: Vec<u8>,
    ranges: Vec<(u8, u8, u8)>,
    batches: Vec<u8>,
}

fn layout() -> impl Strategy<Value = Layout> {
    (
        any::<bool>(),
        any::<u8>(),
        any::<bool>(),
        prop::collection::vec(any::<u8>(), 0..=60),
        prop::collection::vec((any::<u8>(), 1u8..=12, 0u8..3), 0..=4),
        prop::collection::vec(1u8..=4, 1..=8),
    )
        .prop_map(|(v6, slot, small, addresses, ranges, batches)| Layout {
            v6,
            slot,
            small,
            addresses,
            ranges,
            batches,
        })
}

/// The expected shape of a layout, computed without the domain code.
struct Shape {
    network: String,
    /// Text of the address at an offset.
    address_at: Box<dyn Fn(u32) -> String>,
    /// Assignable offsets.
    assignable: std::ops::RangeInclusive<u32>,
    /// Used offsets, ascending.
    used: BTreeSet<u32>,
    /// Accepted ranges as (first, last, role), by offset.
    ranges: Vec<(u32, u32, RangeRole)>,
}

fn shape(layout: &Layout) -> Shape {
    let (network, size, address_at): (String, u32, Box<dyn Fn(u32) -> String>) = if layout.v6 {
        let high = u32::from(layout.slot);
        (
            format!("2001:db8::{high:x}00/120"),
            256,
            Box::new(move |offset| format!("2001:db8::{:x}", (high << 8) | offset)),
        )
    } else {
        let size: u32 = if layout.small { 32 } else { 64 };
        let start = (u32::from(layout.slot) % (256 / size)) * size;
        (
            format!("192.0.2.{start}/{}", 32 - size.trailing_zeros()),
            size,
            Box::new(move |offset| format!("192.0.2.{}", start + offset)),
        )
    };
    let assignable = if layout.v6 {
        1..=size - 1
    } else {
        1..=size - 2
    };
    let mut ranges: Vec<(u32, u32, RangeRole)> = Vec::new();
    for &(start, len, role) in &layout.ranges {
        let first = u32::from(start) % size;
        let last = (first + u32::from(len) - 1).min(size - 1);
        if ranges.iter().any(|&(a, b, _)| first <= b && a <= last) {
            continue;
        }
        let role = match role {
            0 => RangeRole::DhcpPool,
            1 => RangeRole::Reserved,
            _ => RangeRole::Infrastructure,
        };
        ranges.push((first, last, role));
    }
    // Addresses avoid the network and broadcast address (IPv4) or the network address
    // (IPv6, the subnet-router anycast address), which are not assignable.
    let used: BTreeSet<u32> = layout
        .addresses
        .iter()
        .map(|a| u32::from(*a) % size)
        .filter(|offset| assignable.contains(offset))
        .collect();
    Shape {
        network,
        address_at,
        assignable,
        used,
        ranges,
    }
}

impl Shape {
    fn blocked(&self, offset: u32) -> bool {
        self.ranges
            .iter()
            .any(|&(a, b, _)| a <= offset && offset <= b)
    }

    /// Offsets outside every range that are neither used nor out of bounds, ascending.
    fn free_outside_ranges(&self) -> Vec<u32> {
        self.assignable
            .clone()
            .filter(|o| !self.blocked(*o) && !self.used.contains(o))
            .collect()
    }

    /// Offsets inside a range that are assignable and not used, ascending.
    fn free_inside(&self, range: (u32, u32), taken: &BTreeSet<u32>) -> Vec<u32> {
        (range.0..=range.1)
            .filter(|o| self.assignable.contains(o) && !self.used.contains(o) && !taken.contains(o))
            .collect()
    }
}

fn ordered(mut offsets: Vec<u32>, policy: AllocPolicy) -> Vec<u32> {
    if policy == AllocPolicy::Highest {
        offsets.reverse();
    }
    offsets
}

/// The offset of an address inside the layout's network.
fn offset_of(shape: &Shape, ip: std::net::IpAddr) -> Option<u32> {
    (0..=255)
        .find(|offset| (shape.address_at)(*offset).parse::<std::net::IpAddr>().ok() == Some(ip))
}

async fn allocate_all(
    service: &IpamService,
    shape: &Shape,
    prefix_id: PrefixId,
    policy: AllocPolicy,
    range: Option<RangeId>,
    batches: &[u8],
) -> Result<Vec<u32>, String> {
    let mut got: Vec<u32> = Vec::new();
    let mut round = 0usize;
    loop {
        let mut size = usize::from(batches[round % batches.len()]);
        round += 1;
        loop {
            let commands: Vec<IpamCommand> = (0..size)
                .map(|_| {
                    IpamCommand::AllocateAddress(AllocateAddress {
                        policy: Some(policy),
                        range,
                        ..allocate(prefix_id)
                    })
                })
                .collect();
            match try_run(service, commands).await {
                Ok(applied) => {
                    for result in applied.results {
                        let stored =
                            fetch::<tenko_core::ipam::Address>(service, id_of(result)).await;
                        let offset = offset_of(shape, stored.ip)
                            .ok_or_else(|| format!("{} is outside the network", stored.ip))?;
                        got.push(offset);
                    }
                    break;
                }
                Err(error) if error.is(codes::ADDRESS_FULL) => {
                    // A bulk request that does not fit fails as a whole; try one by one.
                    if size == 1 {
                        return Ok(got);
                    }
                    size = 1;
                }
                Err(error) => return Err(format!("allocation failed: {error:?}")),
            }
            if got.len() > 600 {
                return Err("allocation does not end".to_owned());
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // One scenario from setup to the last allocation.
async fn allocation_scenario(layout: &Layout, policy: AllocPolicy) -> Result<(), String> {
    let (service, _store) = service();
    let shape = shape(layout);
    let mut network = prefix(None, &shape.network);
    network.alloc = Some(policy);
    let network_id = network.id.expect("id");
    let mut commands = vec![IpamCommand::CreatePrefix(network)];
    let mut range_ids = Vec::new();
    for &(first, last, role) in &shape.ranges {
        let mut item = range(
            network_id,
            &(shape.address_at)(first),
            &(shape.address_at)(last),
            role,
        );
        let id = RangeId::generate();
        item.id = Some(id);
        range_ids.push(id);
        commands.push(IpamCommand::CreateRange(item));
    }
    for offset in &shape.used {
        commands.push(IpamCommand::CreateAddress(address(
            None,
            &(shape.address_at)(*offset),
        )));
    }
    try_run(&service, commands)
        .await
        .map_err(|e| format!("setup of {}: {e:?}", shape.network))?;

    // The tree proposes the same candidates the planner will accept.
    let expected = ordered(shape.free_outside_ranges(), policy);
    let proposed: Vec<u32> = service
        .tree()
        .next_free_addresses(network_id, None, None, 1000)
        .into_iter()
        .map(|ip| offset_of(&shape, ip).ok_or_else(|| format!("{ip} is outside")))
        .collect::<Result<_, _>>()?;
    if proposed != expected {
        return Err(format!(
            "the tree proposes {proposed:?}, expected {expected:?}"
        ));
    }
    for (index, &(first, last, _)) in shape.ranges.iter().enumerate() {
        let inside = ordered(shape.free_inside((first, last), &BTreeSet::new()), policy);
        let proposed: Vec<u32> = service
            .tree()
            .next_free_addresses(network_id, None, Some(range_ids[index]), 1000)
            .into_iter()
            .map(|ip| offset_of(&shape, ip).ok_or_else(|| format!("{ip} is outside")))
            .collect::<Result<_, _>>()?;
        if proposed != inside {
            return Err(format!(
                "the tree proposes {proposed:?} in range {first}-{last}, expected {inside:?}"
            ));
        }
    }

    // Allocate until the network is full: exactly the free space, in policy order.
    let got = allocate_all(&service, &shape, network_id, policy, None, &layout.batches).await?;
    if got != expected {
        return Err(format!(
            "allocated {got:?}, expected {expected:?} ({policy:?})"
        ));
    }
    let distinct: BTreeSet<u32> = got.iter().copied().collect();
    if distinct.len() != got.len() {
        return Err("an address was handed out twice".to_owned());
    }
    if got
        .iter()
        .any(|o| shape.used.contains(o) || shape.blocked(*o))
    {
        return Err("a used or reserved address was handed out".to_owned());
    }

    // Then inside each range, up to its end.
    for (index, &(first, last, _)) in shape.ranges.iter().enumerate() {
        let inside = ordered(shape.free_inside((first, last), &BTreeSet::new()), policy);
        let got = allocate_all(
            &service,
            &shape,
            network_id,
            policy,
            Some(range_ids[index]),
            &layout.batches,
        )
        .await?;
        if got != inside {
            return Err(format!(
                "allocated {got:?} in range {first}-{last}, expected {inside:?} ({policy:?})"
            ));
        }
    }

    // In the end every assignable address outside nothing but the unassignable ones is used.
    let total: usize = shape.assignable.clone().count();
    let view = snapshot(&service).await;
    let stored = view
        .scan_typed(&ADDRESS_IPS, KeyRange::all(), usize::MAX, false)
        .map_err(|e| e.to_string())?;
    if stored.len() != total {
        return Err(format!(
            "{} addresses stored, {total} assignable",
            stored.len()
        ));
    }
    let utilization = service
        .tree()
        .utilization(network_id)
        .ok_or("no utilization")?;
    if utilization.free != 0 {
        return Err(format!(
            "{} addresses still free in the tree",
            utilization.free
        ));
    }
    Ok(())
}

proptest! {
    #![proptest_config(config(48))]

    #[test]
    fn next_free_never_returns_a_used_address(layout in layout()) {
        for policy in [AllocPolicy::Lowest, AllocPolicy::Highest] {
            let outcome = runtime().block_on(allocation_scenario(&layout, policy));
            prop_assert!(outcome.is_ok(), "{}", outcome.err().unwrap_or_default());
        }
    }
}

// ----- 3. plan then apply equals direct apply ---------------------------------------------------

#[derive(Debug, Clone)]
enum Step {
    CreateVrf {
        name: u8,
    },
    CreateSite {
        name: u8,
        parent: Option<usize>,
    },
    CreatePrefix {
        net: NetSpec,
        role: Option<PrefixRole>,
        client_id: bool,
        vrf: Option<usize>,
    },
    CreateChild {
        pick: usize,
        index: u8,
        role: Option<PrefixRole>,
    },
    CreateAddress {
        addr: AddrSpec,
        client_id: bool,
    },
    CreateAddressIn {
        pick: usize,
        offset: u8,
        interface: Option<usize>,
    },
    Allocate {
        pick: usize,
        policy: Option<AllocPolicy>,
        count: u8,
    },
    CreateRange {
        pick: usize,
        first: u8,
        len: u8,
        role: u8,
    },
    Describe {
        pick: usize,
        text: u8,
    },
    Tag {
        pick: usize,
        tag: u8,
    },
    SetStatus {
        pick: usize,
        status: u8,
    },
    Renumber {
        pick: usize,
        addr: AddrSpec,
    },
    Resize {
        pick: usize,
        net: NetSpec,
    },
    ResizeRange {
        pick: usize,
        last: u8,
    },
    Delete {
        pick: usize,
        cascade: bool,
    },
    Restore {
        pick: usize,
    },
    CreateHost {
        name: u8,
        mode: u8,
        lock: bool,
    },
    SetLock {
        pick: usize,
        lock: bool,
    },
    SetMode {
        pick: usize,
        mode: u8,
    },
    DefineField {
        key: u8,
    },
    SetField {
        pick: usize,
        key: u8,
        value: u8,
    },
    DeleteField {
        key: u8,
    },
}

/// A step and whether automation (the reconciler) performs it instead of a person.
fn step() -> impl Strategy<Value = (Step, bool)> {
    let step = prop_oneof![
        1 => (0u8..3).prop_map(|name| Step::CreateVrf { name }),
        1 => (0u8..3, proptest::option::of(0usize..4))
            .prop_map(|(name, parent)| Step::CreateSite { name, parent }),
        5 => (net_spec(), role_spec(), any::<bool>(), proptest::option::of(0usize..3))
            .prop_map(|(net, role, client_id, vrf)| Step::CreatePrefix { net, role, client_id, vrf }),
        5 => (any::<usize>(), any::<u8>(), role_spec())
            .prop_map(|(pick, index, role)| Step::CreateChild { pick, index, role }),
        1 => (addr_spec(), any::<bool>())
            .prop_map(|(addr, client_id)| Step::CreateAddress { addr, client_id }),
        5 => (any::<usize>(), any::<u8>(), proptest::option::of(0usize..4))
            .prop_map(|(pick, offset, interface)| Step::CreateAddressIn { pick, offset, interface }),
        4 => (any::<usize>(), proptest::option::of(prop_oneof![
                Just(AllocPolicy::Lowest), Just(AllocPolicy::Highest)]), 1u8..=3)
            .prop_map(|(pick, policy, count)| Step::Allocate { pick, policy, count }),
        3 => (any::<usize>(), any::<u8>(), 1u8..=30, 0u8..3)
            .prop_map(|(pick, first, len, role)| Step::CreateRange { pick, first, len, role }),
        2 => (any::<usize>(), 0u8..4).prop_map(|(pick, text)| Step::Describe { pick, text }),
        2 => (any::<usize>(), 0u8..4).prop_map(|(pick, tag)| Step::Tag { pick, tag }),
        2 => (any::<usize>(), 0u8..4).prop_map(|(pick, status)| Step::SetStatus { pick, status }),
        1 => (any::<usize>(), addr_spec()).prop_map(|(pick, addr)| Step::Renumber { pick, addr }),
        1 => (any::<usize>(), net_spec()).prop_map(|(pick, net)| Step::Resize { pick, net }),
        1 => (any::<usize>(), any::<u8>()).prop_map(|(pick, last)| Step::ResizeRange { pick, last }),
        3 => (any::<usize>(), any::<bool>()).prop_map(|(pick, cascade)| Step::Delete { pick, cascade }),
        2 => any::<usize>().prop_map(|pick| Step::Restore { pick }),
        2 => (0u8..3, 0u8..4, any::<bool>()).prop_map(|(name, mode, lock)| Step::CreateHost { name, mode, lock }),
        1 => (any::<usize>(), any::<bool>()).prop_map(|(pick, lock)| Step::SetLock { pick, lock }),
        1 => (any::<usize>(), 0u8..4).prop_map(|(pick, mode)| Step::SetMode { pick, mode }),
        1 => (0u8..2).prop_map(|key| Step::DefineField { key }),
        1 => (any::<usize>(), 0u8..2, 0u8..3).prop_map(|(pick, key, value)| Step::SetField { pick, key, value }),
        1 => (0u8..2).prop_map(|key| Step::DeleteField { key }),
    ];
    (step, prop_oneof![4 => Just(false), 1 => Just(true)])
}

/// What the generator has seen created, taken from the results of the first store.
#[derive(Default)]
struct Known {
    vrfs: Vec<VrfId>,
    sites: Vec<SiteId>,
    prefixes: Vec<(PrefixId, IpNet, Option<VrfId>)>,
    ranges: Vec<RangeId>,
    addresses: Vec<AddressId>,
    hosts: Vec<HostId>,
    interfaces: Vec<InterfaceId>,
    everything: Vec<ObjectRef>,
    deleted: Vec<ObjectRef>,
}

impl Known {
    fn record(&mut self, command: &IpamCommand, result: ObjectRef) {
        match command {
            IpamCommand::CreateVrf(_) => self.vrfs.push(id_of(result)),
            IpamCommand::CreateSite(_) => self.sites.push(id_of(result)),
            IpamCommand::CreatePrefix(input) => {
                self.prefixes.push((id_of(result), input.cidr, input.vrf));
            }
            IpamCommand::CreateRange(_) => self.ranges.push(id_of(result)),
            IpamCommand::CreateAddress(_) | IpamCommand::AllocateAddress(_) => {
                self.addresses.push(id_of(result));
            }
            IpamCommand::CreateHost(input) => {
                self.hosts.push(id_of(result));
                self.interfaces
                    .extend(input.interfaces.iter().filter_map(|i| i.id));
            }
            _ => return,
        }
        self.everything.push(result);
    }
}

fn pick_from<T: Copy>(items: &[T], pick: usize) -> Option<T> {
    (!items.is_empty()).then(|| items[pick % items.len()])
}

fn field_key(key: u8) -> tenko_core::ipam::FieldKey {
    tenko_core::ipam::FieldKey::new(&format!("field{key}")).expect("key")
}

/// Turns a step into commands, or none when it has nothing to refer to yet.
#[allow(clippy::too_many_lines)] // One arm per step.
fn commands_of(step: &Step, known: &Known) -> Vec<IpamCommand> {
    match step {
        Step::CreateVrf { name } => vec![IpamCommand::CreateVrf(vrf(&format!("vrf{name}")))],
        Step::CreateSite { name, parent } => {
            let parent = parent.and_then(|p| pick_from(&known.sites, p));
            vec![IpamCommand::CreateSite(SiteInput {
                id: None,
                name: format!("site{name}"),
                parent,
                ad_site: None,
                tags: BTreeSet::new(),
                custom: BTreeMap::new(),
                description: None,
            })]
        }
        Step::CreatePrefix {
            net,
            role,
            client_id,
            vrf,
        } => {
            let vrf = vrf.and_then(|v| pick_from(&known.vrfs, v));
            let mut input = prefix(vrf, &net.text());
            input.role = *role;
            if !client_id {
                input.id = None;
            }
            vec![IpamCommand::CreatePrefix(input)]
        }
        Step::CreateChild { pick, index, role } => {
            let Some((_, parent, parent_vrf)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            let (extra, cap) = match parent {
                IpNet::V4(_) => (2, 30),
                IpNet::V6(_) => (4, 64),
            };
            let length = (parent.prefix_len() + extra).min(cap);
            let Ok(subnets) = parent.subnets(length) else {
                return Vec::new();
            };
            let count = 1usize << (length - parent.prefix_len());
            let Some(child) = subnets.into_iter().nth(usize::from(*index) % count) else {
                return Vec::new();
            };
            let mut input = prefix(parent_vrf, &child.to_string());
            input.role = *role;
            input.id = None;
            vec![IpamCommand::CreatePrefix(input)]
        }
        Step::CreateAddress { addr, client_id } => {
            let mut input = address(None, &addr.text());
            if !client_id {
                input.id = None;
            }
            vec![IpamCommand::CreateAddress(input)]
        }
        Step::CreateAddressIn {
            pick,
            offset,
            interface,
        } => {
            let Some((_, cidr, _)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            let mut input = address(None, &address_in(cidr, *offset).to_string());
            input.id = None;
            input.interface = interface.and_then(|i| pick_from(&known.interfaces, i));
            vec![IpamCommand::CreateAddress(input)]
        }
        Step::Allocate {
            pick,
            policy,
            count,
        } => {
            let Some((prefix_id, _, _)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            (0..*count)
                .map(|_| {
                    IpamCommand::AllocateAddress(AllocateAddress {
                        policy: *policy,
                        ..allocate(prefix_id)
                    })
                })
                .collect()
        }
        Step::CreateRange {
            pick,
            first,
            len,
            role,
        } => {
            let Some((prefix_id, cidr, _)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            let role = match role {
                0 => RangeRole::DhcpPool,
                1 => RangeRole::Reserved,
                _ => RangeRole::Infrastructure,
            };
            let last = first.saturating_add(*len);
            vec![IpamCommand::CreateRange(range(
                prefix_id,
                &address_in(cidr, *first).to_string(),
                &address_in(cidr, last).to_string(),
                role,
            ))]
        }
        Step::Describe { pick, text } => {
            let Some(object) = pick_from(&known.everything, *pick) else {
                return Vec::new();
            };
            let text = Some(format!("note {text}"));
            vec![match object.kind {
                tenko_core::ObjectKind::Prefix => IpamCommand::UpdatePrefix(UpdatePrefix {
                    id: id_of(object),
                    expected: None,
                    patch: PrefixPatch {
                        description: Some(text),
                        ..PrefixPatch::default()
                    },
                }),
                tenko_core::ObjectKind::Address => IpamCommand::UpdateAddress(UpdateAddress {
                    id: id_of(object),
                    expected: None,
                    patch: AddressPatch {
                        description: Some(text),
                        ..AddressPatch::default()
                    },
                }),
                tenko_core::ObjectKind::Range => IpamCommand::UpdateRange(UpdateRange {
                    id: id_of(object),
                    expected: None,
                    patch: RangePatch {
                        description: Some(text),
                        ..RangePatch::default()
                    },
                }),
                _ => return Vec::new(),
            }]
        }
        Step::Tag { pick, tag } => {
            let Some((prefix_id, _, _)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            let tags = BTreeSet::from([
                tenko_core::ipam::Tag::new(&format!("tag{tag}")).expect("tag"),
                tenko_core::ipam::Tag::new("common").expect("tag"),
            ]);
            vec![IpamCommand::UpdatePrefix(UpdatePrefix {
                id: prefix_id,
                expected: None,
                patch: PrefixPatch {
                    tags: Some(tags),
                    ..PrefixPatch::default()
                },
            })]
        }
        Step::SetStatus { pick, status } => {
            let Some((prefix_id, _, _)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            let status = [
                Status::Planned,
                Status::Active,
                Status::Reserved,
                Status::Deprecated,
            ][usize::from(*status)];
            vec![IpamCommand::UpdatePrefix(UpdatePrefix {
                id: prefix_id,
                expected: None,
                patch: PrefixPatch {
                    status: Some(status),
                    ..PrefixPatch::default()
                },
            })]
        }
        Step::Renumber { pick, addr } => {
            let Some(address_id) = pick_from(&known.addresses, *pick) else {
                return Vec::new();
            };
            vec![IpamCommand::UpdateAddress(UpdateAddress {
                id: address_id,
                expected: None,
                patch: AddressPatch {
                    ip: Some(addr.text().parse().expect("ip")),
                    ..AddressPatch::default()
                },
            })]
        }
        Step::Resize { pick, net } => {
            let Some((prefix_id, cidr, _)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            vec![IpamCommand::UpdatePrefix(UpdatePrefix {
                id: prefix_id,
                expected: None,
                patch: PrefixPatch {
                    cidr: Some(net.in_family(cidr.addr().is_ipv6()).net()),
                    ..PrefixPatch::default()
                },
            })]
        }
        Step::ResizeRange { pick, last } => {
            let Some(range_id) = pick_from(&known.ranges, *pick) else {
                return Vec::new();
            };
            vec![IpamCommand::UpdateRange(UpdateRange {
                id: range_id,
                expected: None,
                patch: RangePatch {
                    last: Some(format!("192.0.2.{last}").parse().expect("ip")),
                    ..RangePatch::default()
                },
            })]
        }
        Step::Delete { pick, cascade } => {
            let Some(object) = pick_from(&known.everything, *pick) else {
                return Vec::new();
            };
            vec![IpamCommand::Delete {
                object,
                expected: None,
                cascade: *cascade,
            }]
        }
        Step::Restore { pick } => {
            let object =
                pick_from(&known.deleted, *pick).or_else(|| pick_from(&known.everything, *pick));
            let Some(object) = object else {
                return Vec::new();
            };
            vec![IpamCommand::Restore {
                object,
                expected: None,
            }]
        }
        Step::CreateHost { name, mode, lock } => {
            let mode = [
                AssignmentMode::Static,
                AssignmentMode::Reserved,
                AssignmentMode::Dynamic,
                AssignmentMode::Unmanaged,
            ][usize::from(*mode)];
            let (mut input, _) = host(&format!("host{name}"), mode, Some("00-00-5E-00-53-20"));
            input.id = None;
            input.lock = Some(*lock);
            vec![IpamCommand::CreateHost(input)]
        }
        Step::SetLock { pick, lock } => {
            let Some(host) = pick_from(&known.hosts, *pick) else {
                return Vec::new();
            };
            vec![IpamCommand::SetLock {
                host,
                lock: *lock,
                expected: None,
            }]
        }
        Step::SetMode { pick, mode } => {
            let Some(host) = pick_from(&known.hosts, *pick) else {
                return Vec::new();
            };
            let mode = [
                AssignmentMode::Static,
                AssignmentMode::Reserved,
                AssignmentMode::Dynamic,
                AssignmentMode::Unmanaged,
            ][usize::from(*mode)];
            vec![IpamCommand::SetMode {
                host,
                mode,
                expected: None,
            }]
        }
        Step::DefineField { key } => vec![IpamCommand::CreateCustomField(
            tenko_ipam::command::CustomFieldInput {
                id: None,
                key: field_key(*key),
                kind: tenko_core::ipam::CustomKind::Text,
                applies_to: vec![tenko_core::ObjectKind::Prefix],
                required: false,
            },
        )],
        Step::SetField { pick, key, value } => {
            let Some((prefix_id, _, _)) = pick_from(&known.prefixes, *pick) else {
                return Vec::new();
            };
            vec![IpamCommand::UpdatePrefix(UpdatePrefix {
                id: prefix_id,
                expected: None,
                patch: PrefixPatch {
                    custom: Some(BTreeMap::from([(
                        field_key(*key),
                        Some(tenko_core::ipam::CustomValue::Text(format!(
                            "value {value}"
                        ))),
                    )])),
                    ..PrefixPatch::default()
                },
            })]
        }
        Step::DeleteField { key } => vec![IpamCommand::DeleteCustomField {
            key: field_key(*key),
            expected: None,
        }],
    }
}

/// Every `ipam.*` table of the domain, plus the counters.
fn table_names() -> Vec<tenko_core::TableName> {
    fn name<K, V>(table: &TableDef<K, V>) -> tenko_core::TableName {
        table.name().clone()
    }
    vec![
        name(&TENANTS),
        name(&VRFS),
        name(&SITES),
        name(&VLANS),
        name(&PREFIXES),
        name(&RANGES),
        name(&ADDRESSES),
        name(&HOSTS),
        name(&INTERFACES),
        name(&CUSTOM_FIELDS),
        name(&CUSTOM_FIELD_KEYS),
        name(&TENANT_NAMES),
        name(&VRF_NAMES),
        name(&SITE_NAMES),
        name(&VLAN_VIDS),
        name(&PREFIX_CIDRS),
        name(&ADDRESS_IPS),
        name(&HOST_NAMES),
        name(&HOST_INTERFACES),
        name(&INTERFACE_ADDRESSES),
        name(&INTERFACE_MACS),
        name(&PREFIX_RANGES),
        name(&TAG_USAGE),
        name(&FIELD_USAGE),
        name(&HISTORY),
        name(&ALARMS),
        name(&RECEIPTS),
        tenko_store::tables::COUNTERS,
    ]
}

type Dump = BTreeMap<String, Vec<(Bytes, Versioned)>>;

async fn dump(store: &MemStore) -> Dump {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    table_names()
        .into_iter()
        .map(|table| {
            let rows = view
                .scan(&table, KeyRange::all(), usize::MAX, false)
                .expect("scan");
            (table.to_string(), rows)
        })
        .collect()
}

fn describe_difference(a: &Dump, b: &Dump) -> String {
    for (table, rows) in a {
        if rows != &b[table] {
            return format!(
                "table {table} differs: {} rows by plan and apply, {} by execute",
                rows.len(),
                b[table].len()
            );
        }
    }
    "tables are equal".to_owned()
}

fn outcome(result: &Result<tenko_ipam::Applied, tenko_ipam::IpamError>) -> String {
    match result {
        Ok(applied) => format!(
            "ok {:?} {:?} {:?} {} {}",
            applied.results, applied.warnings, applied.revision, applied.replayed, applied.retries
        ),
        Err(error) => format!("error {}", error.code_str()),
    }
}

async fn plan_vs_execute(steps: Vec<(Step, bool)>) -> Result<(), String> {
    let store_a = MemStore::default();
    let store_b = MemStore::default();
    let service_a = IpamService::with_direct_jobs(std::sync::Arc::new(store_a.clone()) as _)
        .map_err(|e| format!("{e:?}"))?;
    let service_b = IpamService::with_direct_jobs(std::sync::Arc::new(store_b.clone()) as _)
        .map_err(|e| format!("{e:?}"))?;
    let person = principal();
    let automation = tenko_core::Principal::system(tenko_core::SystemComponent::Reconciler);
    let options = PlanOptions::default();
    let mut known = Known::default();
    for (n, (step, auto)) in steps.iter().enumerate() {
        let commands = commands_of(step, &known);
        if commands.is_empty() {
            continue;
        }
        let acting = if *auto { &automation } else { &person };
        let mut cx: RequestCtx = request_of(
            acting,
            1_790_000_000_000_000_000 + i128::try_from(n).expect("small") * 1_000_000_000,
        );
        cx.request = RequestId(uuid::Uuid::from_u128(
            0x0190_0000_0000_7000_8000_0000_0000_0000 + n as u128,
        ));
        let before = store_a.status().revision;

        // Store A: a dry run, then the previewed plan.
        let previewed = service_a.preview(&commands, &cx, &options, None).await;
        if store_a.status().revision != before {
            return Err(format!("step {n} {step:?}: the dry run wrote"));
        }
        let applied_a = match previewed {
            Ok(plan) => service_a.apply(&plan, &cx).await,
            Err(error) => Err(error),
        };
        // Store B: direct.
        let applied_b = service_b.execute(&commands, &cx, &options).await;

        if outcome(&applied_a) != outcome(&applied_b) {
            return Err(format!(
                "step {n} {step:?}: plan and apply gave {}, execute gave {}",
                outcome(&applied_a),
                outcome(&applied_b)
            ));
        }
        let (tables_a, tables_b) = (dump(&store_a).await, dump(&store_b).await);
        if tables_a != tables_b {
            return Err(format!(
                "step {n} {step:?}: {}",
                describe_difference(&tables_a, &tables_b)
            ));
        }
        if store_a.status().revision != store_b.status().revision {
            return Err(format!("step {n} {step:?}: the revisions differ"));
        }
        if let Err(error) = &applied_a
            && is_internal(error)
        {
            return Err(format!("step {n} {step:?}: internal error {error:?}"));
        }
        if let Ok(applied) = &applied_a {
            // Both stores agree; record what the commands created.
            for (command, result) in commands.iter().zip(&applied.results) {
                known.record(command, *result);
            }
            for command in &commands {
                match command {
                    IpamCommand::Delete { object, .. } => known.deleted.push(*object),
                    IpamCommand::Restore { object, .. } => known.deleted.retain(|o| o != object),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(config(48))]

    #[test]
    fn plan_then_apply_equals_direct_apply(steps in prop::collection::vec(step(), 1..=30)) {
        let outcome = runtime().block_on(plan_vs_execute(steps));
        prop_assert!(outcome.is_ok(), "{}", outcome.err().unwrap_or_default());
    }
}
