//! The image build against a reference over random configurations (WP7.4's acceptance),
//! and the rules of the build on small fixed cases.
//!
//! The reference puts the image together with [`ImageBuilder`] from the rules of
//! [`super::image`] the slow way: it marks every address of a network to find the excluded
//! runs, merges the option levels by looking up each code from the most specific level
//! down, and finds duplicate reservations with sets of its own. The generator builds
//! configurations with the corners the rules name: supernets, deleted rows, disabled scopes,
//! IPv6 prefixes, ranges of every role, hosts of every mode, interfaces without identity,
//! two hosts on one address, two interfaces with one MAC, option sets on every level.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::{IpNet, Ipv4Net};
use proptest::prelude::*;
use tenko_core::{
    InterfaceId, PrefixId, Revision, VrfId,
    dhcp::{
        AddressRange, Class, ClassId, Condition, DdnsPolicy, DhcpSettings, ExclusionId,
        ExclusionRange, Filter, FilterId, FilterKind, Join, LeaseTimes, MacPattern, Match,
        OptionOwner, OptionSet, OptionValue, Policy, PolicyAction, PolicyId, PoolSettings,
        ReservationCandidate, ReservationWarning, Scope, SharedNetwork, SharedNetworkId, Term,
        check_reservations,
    },
    ipam::{Address, AssignmentMode, PrefixRole, RangeRole, Status},
};

use super::{
    image::{Built, build, interface_identity},
    testkit::{address, host, interface, meta, prefix, range, stamp},
};
use crate::{
    feed::DhcpData,
    image::{ImageBuilder, PoolImage, ReservationImage, ScopeImage},
};

// ---------------------------------------------------------------------------------------
// The reference

fn v4(address: IpAddr) -> Option<Ipv4Addr> {
    match address {
        IpAddr::V4(address) => Some(address),
        IpAddr::V6(_) => None,
    }
}

fn reference_dynamic(data: &DhcpData, address: &Address) -> bool {
    let Some(interface) = address.interface.and_then(|id| data.interfaces.get(&id)) else {
        return false;
    };
    if interface.meta.is_deleted() {
        return false;
    }
    let Some(host) = data.hosts.get(&interface.host) else {
        return false;
    };
    !host.meta.is_deleted() && host.mode == AssignmentMode::Dynamic
}

/// The maximal runs of marked addresses of a network.
fn runs(network: Ipv4Net, marked: &[bool]) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let base = u32::from(network.network());
    let mut out = Vec::new();
    let mut start: Option<u32> = None;
    for (offset, flag) in marked.iter().enumerate() {
        let at = base + u32::try_from(offset).expect("offset");
        match (flag, start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                out.push((Ipv4Addr::from(from), Ipv4Addr::from(at - 1)));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        out.push((Ipv4Addr::from(from), network.broadcast()));
    }
    out
}

fn mark(network: Ipv4Net, marked: &mut [bool], first: Ipv4Addr, last: Ipv4Addr) {
    let base = u32::from(network.network());
    for at in u32::from(first)..=u32::from(last) {
        marked[usize::try_from(at - base).expect("offset")] = true;
    }
}

/// Each code once, in the order of its first appearance, with the value of the most
/// specific level that has it.
fn reference_merge(levels: &[&[OptionValue]]) -> Vec<OptionValue> {
    let mut order: Vec<(String, u16)> = Vec::new();
    for level in levels {
        for value in *level {
            let key = (value.space.as_str().to_owned(), value.code);
            if !order.contains(&key) {
                order.push(key);
            }
        }
    }
    order
        .into_iter()
        .map(|(space, code)| {
            levels
                .iter()
                .rev()
                .find_map(|level| {
                    level
                        .iter()
                        .find(|value| value.space.as_str() == space && value.code == code)
                })
                .expect("a level has it")
                .clone()
        })
        .collect()
}

fn set(data: &DhcpData, owner: OptionOwner) -> Vec<OptionValue> {
    data.option_sets
        .get(&owner)
        .map(|set| set.values.clone())
        .unwrap_or_default()
}

fn reference_scope(data: &DhcpData, id: PrefixId, scope: &Scope) -> Option<ScopeImage> {
    let row = data.prefixes.get(&id)?;
    if !scope.enabled || row.meta.is_deleted() || row.role != PrefixRole::Network {
        return None;
    }
    let IpNet::V4(network) = row.cidr else {
        return None;
    };
    let settings = data.settings.clone().unwrap_or_default();
    let lease = scope.lease.unwrap_or(settings.lease);
    let size = usize::try_from(
        u64::from(u32::from(network.broadcast())) - u64::from(u32::from(network.network())) + 1,
    )
    .expect("size");
    let mut marked = vec![false; size];
    let mut pools = Vec::new();
    for range in data.ranges.values() {
        if range.prefix != id || range.meta.is_deleted() {
            continue;
        }
        let (Some(first), Some(last)) = (v4(range.first), v4(range.last)) else {
            continue;
        };
        if range.role == RangeRole::DhcpPool {
            let settings = data.pools.get(&range.id);
            let pool_lease = match (settings.and_then(|s| s.lease), range.lease_secs) {
                (Some(own), _) => own,
                (None, Some(secs)) => LeaseTimes::fixed(secs),
                (None, None) => lease,
            };
            pools.push(PoolImage {
                range: range.id,
                first,
                last,
                lease: pool_lease,
                classes: settings.map(|s| s.classes.clone()).unwrap_or_default(),
                options: set(data, OptionOwner::Pool(range.id)),
            });
        } else {
            mark(network, &mut marked, first, last);
        }
    }
    for ((scope_id, _), exclusion) in &data.exclusions {
        if *scope_id == id
            && let (Some(first), Some(last)) = (v4(exclusion.first), v4(exclusion.last))
        {
            mark(network, &mut marked, first, last);
        }
    }
    for address in data.addresses.values() {
        if address.prefix == id
            && !address.meta.is_deleted()
            && let Some(ip) = v4(address.ip)
            && !reference_dynamic(data, address)
        {
            mark(network, &mut marked, ip, ip);
        }
    }
    let mut levels = vec![set(data, OptionOwner::Server)];
    if let Some(network) = scope.shared_network {
        levels.push(set(data, OptionOwner::SharedNetwork(network)));
    }
    levels.push(set(data, OptionOwner::Scope(id)));
    let borrowed: Vec<&[OptionValue]> = levels.iter().map(Vec::as_slice).collect();
    Some(ScopeImage {
        prefix: id,
        vrf: row.vrf,
        network,
        authoritative: scope.authoritative.unwrap_or(settings.authoritative),
        restricted: scope.restricted,
        server_id: scope.server_id.and_then(v4),
        lease,
        shared_network: scope.shared_network,
        pools,
        excluded: runs(network, &marked),
        options: reference_merge(&borrowed),
        classes: scope.classes.clone(),
        ddns: scope.ddns.clone(),
    })
}

fn reference_identity(interface: &tenko_core::ipam::Interface) -> Option<Vec<u8>> {
    if let Some(client_id) = &interface.client_id {
        let mut out = vec![1];
        out.extend(client_id.0.iter().take(255));
        return Some(out);
    }
    interface.mac.map(|mac| {
        let mut out = vec![0, 1];
        out.extend(mac.octets());
        out
    })
}

fn reference(data: &DhcpData) -> Built {
    let mut builder = ImageBuilder::new(data.revision);
    let mut served = BTreeSet::new();
    for (id, scope) in &data.scopes {
        if let Some(image) = reference_scope(data, *id, scope) {
            served.insert(*id);
            builder.scope(image);
        }
    }
    let mut candidates = Vec::new();
    let mut dropped = Vec::new();
    let mut identities: BTreeSet<(PrefixId, Vec<u8>)> = BTreeSet::new();
    let mut addresses: BTreeSet<(PrefixId, Ipv4Addr)> = BTreeSet::new();
    for host in data.hosts.values() {
        if host.meta.is_deleted() || host.mode != AssignmentMode::Reserved {
            continue;
        }
        for interface in data.interfaces.values() {
            if interface.host != host.id || interface.meta.is_deleted() {
                continue;
            }
            let identity = reference_identity(interface);
            for address in data.addresses.values() {
                if address.interface != Some(interface.id)
                    || address.meta.is_deleted()
                    || !matches!(address.status, Status::Active | Status::Planned)
                    || !served.contains(&address.prefix)
                {
                    continue;
                }
                let Some(ip) = v4(address.ip) else {
                    continue;
                };
                candidates.push(ReservationCandidate {
                    host: host.id,
                    scope: address.prefix,
                    address: address.ip,
                    identity: identity.clone(),
                });
                let Some(identity) = &identity else {
                    continue;
                };
                let reservation = ReservationImage {
                    scope: address.prefix,
                    addr: ip,
                    host: host.id,
                    interface: interface.id,
                    identity: identity.clone(),
                    options: set(data, OptionOwner::Host(interface.id)),
                };
                if identities.contains(&(address.prefix, identity.clone()))
                    || addresses.contains(&(address.prefix, ip))
                {
                    dropped.push(reservation);
                } else {
                    identities.insert((address.prefix, identity.clone()));
                    addresses.insert((address.prefix, ip));
                    assert!(builder.reservation(reservation).is_none());
                }
            }
        }
    }
    // WP8.4: every policy's option set, for the matcher (the image compiles the ones of
    // the policies it holds).
    for (owner, set) in &data.option_sets {
        if let OptionOwner::Policy(policy) = owner
            && !set.values.is_empty()
        {
            builder.policy_options(*policy, set.values.clone());
        }
    }
    builder
        .filters(data.filters.values().cloned().collect())
        .classes(data.classes.values().cloned().collect())
        .policies(
            data.policies
                .values()
                .filter(|policy| {
                    policy.enabled && policy.scope.is_none_or(|scope| served.contains(&scope))
                })
                .cloned()
                .collect(),
        );
    // WP9.1: the DHCPv6 part as the build makes it.
    let (warnings6, dropped6) = super::image::build_v6_into(data, &mut builder);
    Built {
        image: builder.build(),
        warnings: check_reservations(&candidates),
        dropped,
        warnings6,
        dropped6,
    }
}

#[track_caller]
fn assert_same(data: &DhcpData) {
    let built = build(data);
    let expected = reference(data);
    assert_eq!(
        format!("{:#?}", built.image),
        format!("{:#?}", expected.image),
        "the image differs from the reference"
    );
    assert_eq!(built.warnings, expected.warnings);
    assert_eq!(built.dropped, expected.dropped);
}

// ---------------------------------------------------------------------------------------
// The generator

/// A small deterministic generator (xorshift), seeded by proptest.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            items.get(usize::try_from(self.below(items.len() as u64)).expect("index"))
        }
    }

    fn u8(&mut self) -> u8 {
        u8::try_from(self.below(256)).expect("octet")
    }
}

/// Two addresses of a network, ordered.
fn span(rng: &mut Rng, network: Ipv4Net) -> (Ipv4Addr, Ipv4Addr) {
    let base = u32::from(network.network());
    let size = u32::from(network.broadcast()) - base + 1;
    let a = base + u32::try_from(rng.below(u64::from(size))).expect("offset");
    let b = base + u32::try_from(rng.below(u64::from(size))).expect("offset");
    (Ipv4Addr::from(a.min(b)), Ipv4Addr::from(a.max(b)))
}

fn values(rng: &mut Rng) -> Vec<OptionValue> {
    let codes = [3u8, 6, 15, 42, 224];
    let mut out: Vec<OptionValue> = Vec::new();
    for _ in 0..rng.below(4) {
        let code = *rng.pick(&codes).expect("a code");
        if out.iter().any(|value| value.code == u16::from(code)) {
            continue;
        }
        out.push(OptionValue::v4(
            code,
            vec![rng.u8(), rng.u8(), rng.u8(), rng.u8()],
        ));
    }
    out
}

#[allow(clippy::too_many_lines, reason = "one generator, read top to bottom")]
fn generate(seed: u64) -> DhcpData {
    let mut rng = Rng(seed | 1);
    let mut data = DhcpData::at(Revision(rng.below(1000) + 1));
    if rng.chance(50) {
        data.settings = Some(DhcpSettings {
            lease: LeaseTimes::fixed(u32::try_from(rng.below(10_000) + 60).expect("secs")),
            authoritative: rng.chance(50),
            ..DhcpSettings::default()
        });
    }
    let vrfs = [VrfId::generate(), VrfId::generate()];
    let networks: Vec<SharedNetworkId> = (0..2).map(|_| SharedNetworkId::generate()).collect();
    for id in &networks {
        if rng.chance(70) {
            data.shared_networks.insert(
                *id,
                SharedNetwork {
                    id: *id,
                    name: format!("net-{}", rng.below(100)),
                    interface: None,
                    description: None,
                    created: stamp(),
                    updated: stamp(),
                },
            );
        }
    }
    let classes: Vec<ClassId> = (0..3).map(|_| ClassId::generate()).collect();
    for id in &classes {
        if rng.chance(70) {
            data.classes.insert(
                *id,
                Class {
                    id: *id,
                    name: format!("class-{}", rng.below(100)),
                    matches: vec![Match::VendorClass {
                        value: "MSFT".to_owned(),
                        prefix: true,
                    }],
                    description: None,
                    created: stamp(),
                    updated: stamp(),
                },
            );
        }
    }
    // Prefixes: networks of the documentation blocks, some supernets, deleted, IPv6.
    let blocks = [[192, 0, 2, 0], [198, 51, 100, 0], [203, 0, 113, 0]];
    let mut v4_prefixes = Vec::new();
    for _ in 0..=rng.below(5) {
        let block = *rng.pick(&blocks).expect("a block");
        let len = u8::try_from(24 + rng.below(6)).expect("length");
        let step = 1u32 << (32 - u32::from(len));
        let offset = u32::try_from(rng.below(u64::from(256 / step))).expect("offset") * step;
        let base = Ipv4Addr::from(u32::from(Ipv4Addr::from(block)) + offset);
        let role = if rng.chance(85) {
            PrefixRole::Network
        } else {
            PrefixRole::Supernet
        };
        let mut row = prefix(
            *rng.pick(&vrfs).expect("a VRF"),
            &format!("{base}/{len}"),
            role,
        );
        row.meta = meta(rng.chance(10));
        v4_prefixes.push(row);
    }
    let mut v6 = prefix(vrfs[0], "2001:db8::/64", PrefixRole::Network);
    v6.meta = meta(false);
    let all_prefixes: Vec<_> = v4_prefixes
        .iter()
        .cloned()
        .chain(std::iter::once(v6.clone()))
        .collect();
    for row in &all_prefixes {
        data.prefixes.insert(row.id, row.clone());
        if !rng.chance(75) {
            continue;
        }
        let server_id = match rng.below(3) {
            0 => None,
            1 => Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            _ => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        };
        data.scopes.insert(
            row.id,
            Scope {
                v6: None,
                prefix: row.id,
                enabled: rng.chance(80),
                lease: rng.chance(40).then(|| {
                    LeaseTimes::fixed(u32::try_from(rng.below(5_000) + 60).expect("secs"))
                }),
                authoritative: match rng.below(3) {
                    0 => None,
                    1 => Some(true),
                    _ => Some(false),
                },
                server_id,
                ddns: DdnsPolicy::default(),
                shared_network: rng
                    .chance(50)
                    .then(|| *rng.pick(&networks).expect("a network")),
                restricted: rng.chance(30),
                classes: classes.iter().copied().filter(|_| rng.chance(30)).collect(),
                description: None,
                created: stamp(),
                updated: stamp(),
            },
        );
    }
    // Ranges and exclusions inside the IPv4 networks; one IPv6 range.
    let roles = [
        RangeRole::DhcpPool,
        RangeRole::DhcpPool,
        RangeRole::Reserved,
        RangeRole::Infrastructure,
    ];
    let mut pool_ranges = Vec::new();
    for row in &v4_prefixes {
        let IpNet::V4(network) = row.cidr else {
            continue;
        };
        for _ in 0..rng.below(4) {
            let (first, last) = span(&mut rng, network);
            let role = *rng.pick(&roles).expect("a role");
            let mut item = range(row.id, &first.to_string(), &last.to_string(), role);
            item.lease_secs = rng
                .chance(40)
                .then(|| u32::try_from(rng.below(9_000) + 60).expect("secs"));
            item.meta = meta(rng.chance(10));
            if role == RangeRole::DhcpPool {
                pool_ranges.push(item.id);
                if rng.chance(50) {
                    data.pools.insert(
                        item.id,
                        PoolSettings {
                            range: item.id,
                            classes: classes.iter().copied().filter(|_| rng.chance(30)).collect(),
                            lease: rng.chance(50).then(|| LeaseTimes::fixed(600)),
                            updated: stamp(),
                        },
                    );
                }
            }
            data.ranges.insert(item.id, item);
        }
        for _ in 0..rng.below(3) {
            let (first, last) = span(&mut rng, network);
            let id = ExclusionId::generate();
            data.exclusions.insert(
                (row.id, id),
                ExclusionRange {
                    id,
                    scope: row.id,
                    first: IpAddr::V4(first),
                    last: IpAddr::V4(last),
                    description: None,
                    created: stamp(),
                },
            );
        }
    }
    let v6_range = range(v6.id, "2001:db8::10", "2001:db8::20", RangeRole::DhcpPool);
    data.ranges.insert(v6_range.id, v6_range);
    // Hosts, interfaces and addresses; the MACs come from a few values so they collide.
    let modes = [
        AssignmentMode::Reserved,
        AssignmentMode::Reserved,
        AssignmentMode::Static,
        AssignmentMode::Dynamic,
        AssignmentMode::Unmanaged,
    ];
    let statuses = [
        Status::Active,
        Status::Planned,
        Status::Reserved,
        Status::Deprecated,
    ];
    let mut interfaces: Vec<InterfaceId> = Vec::new();
    for index in 0..rng.below(10) {
        let mut row = host(&format!("host-{index}"), *rng.pick(&modes).expect("a mode"));
        row.meta = meta(rng.chance(10));
        for _ in 0..rng.below(3) {
            let mac = rng
                .chance(70)
                .then(|| u8::try_from(rng.below(2)).expect("octet"));
            let client_id: Option<Vec<u8>> = rng
                .chance(30)
                .then(|| vec![1, 0, 0, 0x5e, 0, 0x53, rng.u8()]);
            let mut item = interface(row.id, mac, client_id.as_deref());
            item.meta = meta(rng.chance(10));
            for _ in 0..rng.below(3) {
                let Some(target) = rng.pick(&all_prefixes) else {
                    continue;
                };
                let ip = match target.cidr {
                    IpNet::V4(network) if rng.chance(50) => Ipv4Addr::from(
                        u32::from(network.network())
                            + u32::try_from(rng.below(2)).expect("offset")
                            + 1,
                    )
                    .to_string(),
                    IpNet::V4(network) => span(&mut rng, network).0.to_string(),
                    IpNet::V6(_) => "2001:db8::15".to_owned(),
                };
                let mut row_address = address(target, &ip, Some(item.id));
                row_address.status = *rng.pick(&statuses).expect("a status");
                row_address.meta = meta(rng.chance(10));
                data.addresses.insert(row_address.id, row_address);
            }
            interfaces.push(item.id);
            data.interfaces.insert(item.id, item);
        }
        data.hosts.insert(row.id, row);
    }
    // A second reserved host with the identity of an existing interface, on another
    // address of the same prefix: one client reserved twice (IPAM-23).
    let existing: Vec<Address> = data.addresses.values().cloned().collect();
    if rng.chance(60)
        && let Some(taken) = rng.pick(&existing)
        && let Some(source) = taken
            .interface
            .and_then(|id| data.interfaces.get(&id))
            .cloned()
        && let Some(target) = data.prefixes.get(&taken.prefix).cloned()
        && let IpNet::V4(network) = target.cidr
    {
        let twin = host("twin", AssignmentMode::Reserved);
        let mut twin_if = interface(twin.id, None, None);
        twin_if.mac = source.mac;
        twin_if.client_id.clone_from(&source.client_id);
        let twin_address = address(
            &target,
            &span(&mut rng, network).1.to_string(),
            Some(twin_if.id),
        );
        interfaces.push(twin_if.id);
        data.addresses.insert(twin_address.id, twin_address);
        data.interfaces.insert(twin_if.id, twin_if);
        data.hosts.insert(twin.id, twin);
    }
    for _ in 0..rng.below(3) {
        if let Some(target) = rng.pick(&v4_prefixes)
            && let IpNet::V4(network) = target.cidr
        {
            let row_address = address(target, &span(&mut rng, network).0.to_string(), None);
            data.addresses.insert(row_address.id, row_address);
        }
    }
    // Policies, filters and option sets on every level.
    let mut policies = Vec::new();
    for index in 0..rng.below(4) {
        let id = PolicyId::generate();
        policies.push(id);
        let scope = if rng.chance(60) {
            rng.pick(&all_prefixes).map(|row| row.id)
        } else {
            None
        };
        data.policies.insert(
            id,
            Policy {
                id,
                name: format!("policy-{index}"),
                scope,
                order: u32::try_from(rng.below(5)).expect("order"),
                enabled: rng.chance(80),
                condition: Condition {
                    join: Join::Or,
                    terms: vec![Term::Match(Match::Architecture { code: 7 })],
                },
                action: PolicyAction {
                    range: rng.chance(30).then_some(AddressRange {
                        first: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                        last: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
                    }),
                    ..PolicyAction::default()
                },
                description: None,
                created: stamp(),
                updated: stamp(),
            },
        );
    }
    for _ in 0..rng.below(3) {
        let id = FilterId::generate();
        data.filters.insert(
            id,
            Filter {
                id,
                mac: MacPattern::new(&format!("00:00:5e:00:53:{:02x}", rng.below(4)))
                    .expect("pattern"),
                kind: if rng.chance(50) {
                    FilterKind::Allow
                } else {
                    FilterKind::Deny
                },
                note: None,
                created: stamp(),
                updated: stamp(),
            },
        );
    }
    let mut owners = vec![OptionOwner::Server];
    owners.extend(networks.iter().map(|id| OptionOwner::SharedNetwork(*id)));
    owners.extend(all_prefixes.iter().map(|row| OptionOwner::Scope(row.id)));
    owners.extend(pool_ranges.iter().map(|id| OptionOwner::Pool(*id)));
    owners.extend(policies.iter().map(|id| OptionOwner::Policy(*id)));
    owners.extend(interfaces.iter().map(|id| OptionOwner::Host(*id)));
    for owner in owners {
        if rng.chance(50) {
            data.option_sets.insert(
                owner,
                OptionSet {
                    owner,
                    values: values(&mut rng),
                    updated: stamp(),
                },
            );
        }
    }
    data
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The image of random rows equals the reference's.
    #[test]
    fn the_image_equals_the_reference(seed in any::<u64>()) {
        assert_same(&generate(seed));
    }
}

// ---------------------------------------------------------------------------------------
// Fixed cases

fn one_scope() -> (DhcpData, PrefixId) {
    let mut data = DhcpData::at(Revision(7));
    let row = prefix(VrfId::generate(), "192.0.2.0/24", PrefixRole::Network);
    let id = row.id;
    data.prefixes.insert(id, row);
    data.scopes.insert(
        id,
        Scope {
            v6: None,
            prefix: id,
            enabled: true,
            lease: None,
            authoritative: None,
            server_id: None,
            ddns: DdnsPolicy::default(),
            shared_network: None,
            restricted: false,
            classes: Vec::new(),
            description: None,
            created: stamp(),
            updated: stamp(),
        },
    );
    (data, id)
}

#[test]
fn a_pool_takes_its_lease_from_its_settings_then_the_range_then_the_scope() {
    let (mut data, id) = one_scope();
    let mut a = range(id, "192.0.2.100", "192.0.2.109", RangeRole::DhcpPool);
    a.lease_secs = Some(900);
    let mut b = range(id, "192.0.2.110", "192.0.2.119", RangeRole::DhcpPool);
    b.lease_secs = Some(900);
    let c = range(id, "192.0.2.120", "192.0.2.129", RangeRole::DhcpPool);
    data.pools.insert(
        b.id,
        PoolSettings {
            range: b.id,
            classes: Vec::new(),
            lease: Some(LeaseTimes::fixed(300)),
            updated: stamp(),
        },
    );
    for item in [&a, &b, &c] {
        data.ranges.insert(item.id, item.clone());
    }
    let built = build(&data);
    let scope = built.image.scope(id).expect("the scope");
    let lease_of = |range: tenko_core::RangeId| {
        scope
            .pools
            .iter()
            .find(|pool| pool.range == range)
            .expect("the pool")
            .lease
    };
    assert_eq!(lease_of(a.id), LeaseTimes::fixed(900));
    assert_eq!(lease_of(b.id), LeaseTimes::fixed(300));
    assert_eq!(lease_of(c.id), LeaseTimes::default());
    assert_same(&data);
}

#[test]
fn a_static_host_inside_a_pool_is_excluded_and_a_dynamic_one_is_not() {
    let (mut data, id) = one_scope();
    let pool = range(id, "192.0.2.100", "192.0.2.199", RangeRole::DhcpPool);
    data.ranges.insert(pool.id, pool);
    let row = data.prefixes[&id].clone();
    let server = host("server", AssignmentMode::Static);
    let laptop = host("laptop", AssignmentMode::Dynamic);
    let server_if = interface(server.id, Some(1), None);
    let laptop_if = interface(laptop.id, Some(2), None);
    let a = address(&row, "192.0.2.150", Some(server_if.id));
    let b = address(&row, "192.0.2.151", Some(laptop_if.id));
    for item in [server, laptop] {
        data.hosts.insert(item.id, item);
    }
    for item in [server_if, laptop_if] {
        data.interfaces.insert(item.id, item);
    }
    for item in [a, b] {
        data.addresses.insert(item.id, item);
    }
    let built = build(&data);
    let scope = built.image.scope(id).expect("the scope");
    assert!(scope.is_excluded(Ipv4Addr::new(192, 0, 2, 150)));
    assert!(scope.is_dynamic(Ipv4Addr::new(192, 0, 2, 151)));
    assert_same(&data);
}

#[test]
fn a_reserved_host_without_identity_is_warned_and_reserves_nothing() {
    let (mut data, id) = one_scope();
    let row = data.prefixes[&id].clone();
    let printer = host("printer", AssignmentMode::Reserved);
    let bare = interface(printer.id, None, None);
    let with_mac = interface(printer.id, Some(9), None);
    let a = address(&row, "192.0.2.20", Some(bare.id));
    let b = address(&row, "192.0.2.21", Some(with_mac.id));
    let host_id = printer.id;
    data.hosts.insert(printer.id, printer);
    for item in [bare.clone(), with_mac.clone()] {
        data.interfaces.insert(item.id, item);
    }
    for item in [a, b] {
        data.addresses.insert(item.id, item);
    }
    let built = build(&data);
    assert_eq!(
        built.warnings,
        vec![tenko_core::dhcp::ReservationWarning::NoIdentity { host: host_id }]
    );
    assert_eq!(built.image.reservations().len(), 1);
    let identity = interface_identity(&with_mac).expect("an identity");
    let reservation = built
        .image
        .reservation(id, &identity)
        .expect("the reservation");
    assert_eq!(reservation.addr, Ipv4Addr::new(192, 0, 2, 21));
    assert_eq!(identity, vec![0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 9]);
    assert!(interface_identity(&bare).is_none());
    assert_same(&data);
}

#[test]
fn the_options_merge_server_shared_network_and_scope() {
    let (mut data, id) = one_scope();
    let network = SharedNetworkId::generate();
    data.scopes.get_mut(&id).expect("scope").shared_network = Some(network);
    let put = |data: &mut DhcpData, owner, values: Vec<OptionValue>| {
        data.option_sets.insert(
            owner,
            OptionSet {
                owner,
                values,
                updated: stamp(),
            },
        );
    };
    put(
        &mut data,
        OptionOwner::Server,
        vec![
            OptionValue::v4(6, vec![192, 0, 2, 53]),
            OptionValue::v4(42, vec![192, 0, 2, 123]),
        ],
    );
    put(
        &mut data,
        OptionOwner::SharedNetwork(network),
        vec![OptionValue::v4(15, b"example.test".to_vec())],
    );
    put(
        &mut data,
        OptionOwner::Scope(id),
        vec![OptionValue::v4(6, vec![198, 51, 100, 53])],
    );
    let built = build(&data);
    let scope = built.image.scope(id).expect("the scope");
    let codes: Vec<u16> = scope.options.iter().map(|value| value.code).collect();
    assert_eq!(codes, vec![6, 42, 15]);
    assert_eq!(
        scope.option(6).expect("option 6").data.0,
        vec![198, 51, 100, 53]
    );
    assert_same(&data);
}

#[test]
fn disabled_scopes_supernets_and_ipv6_prefixes_are_not_served() {
    let (mut data, id) = one_scope();
    data.scopes.get_mut(&id).expect("scope").enabled = false;
    let supernet = prefix(VrfId::generate(), "198.51.100.0/24", PrefixRole::Supernet);
    let v6 = prefix(VrfId::generate(), "2001:db8::/64", PrefixRole::Network);
    for row in [supernet, v6] {
        let mut scope = data.scopes[&id].clone();
        scope.prefix = row.id;
        scope.enabled = true;
        data.scopes.insert(row.id, scope);
        data.prefixes.insert(row.id, row);
    }
    assert_eq!(build(&data).image.scopes(), &[] as &[ScopeImage]);
    assert_same(&data);
}

#[test]
fn the_reference_agrees_on_a_few_fixed_seeds() {
    for seed in [1, 2, 3, 42, 4711, u64::MAX] {
        assert_same(&generate(seed));
    }
}

/// The generator reaches the corners the rules name, so the equality above means
/// something: served scopes with pools and exclusions, reservations, dropped duplicates,
/// and each kind of warning.
#[test]
fn the_generator_reaches_every_rule() {
    let (mut scopes, mut pools, mut excluded, mut reservations, mut dropped) = (0, 0, 0, 0, 0);
    let (mut no_identity, mut address_collisions, mut client_collisions) = (0, 0, 0);
    for seed in 0..400u64 {
        let built = build(&generate(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)));
        scopes += built.image.scopes().len();
        pools += built
            .image
            .scopes()
            .iter()
            .map(|s| s.pools.len())
            .sum::<usize>();
        excluded += built
            .image
            .scopes()
            .iter()
            .map(|s| s.excluded.len())
            .sum::<usize>();
        reservations += built.image.reservations().len();
        dropped += built.dropped.len();
        for warning in &built.warnings {
            match warning {
                ReservationWarning::NoIdentity { .. } => no_identity += 1,
                ReservationWarning::AddressCollision { .. } => address_collisions += 1,
                ReservationWarning::ClientCollision { .. } => client_collisions += 1,
            }
        }
    }
    for (what, count) in [
        ("scopes", scopes),
        ("pools", pools),
        ("excluded runs", excluded),
        ("reservations", reservations),
        ("dropped reservations", dropped),
        ("no-identity warnings", no_identity),
        ("address collisions", address_collisions),
        ("client collisions", client_collisions),
    ] {
        assert!(count >= 5, "the generator made only {count} {what}");
    }
}
