//! The DHCPv6 part of the configuration image built from the rows (WP9.1): the scopes on
//! IPv6 networks with their pools and exclusions, the options merged per code, the
//! Interface-Id, the reservations keyed by DUID or by MAC address with their findings, and
//! the guarantee that the IPv6 rows leave the DHCPv4 part of the image as it was.
//!
//! The rows are built here by hand (the crate's own test kit is private): documentation
//! ranges only, locally administered MACs of RFC 7042.

use std::{collections::BTreeSet, net::Ipv6Addr};

use tenko_core::{
    AddressId, HostId, InterfaceId, PrefixId, Principal, RangeId, SystemComponent, TenantId, VrfId,
    dhcp::{
        DdnsPolicy, LeaseTimes, OptionOwner, OptionSet, OptionSpace, OptionValue,
        ReservationWarning, Scope, Scope6Settings,
    },
    ipam::{
        Address, AllocPolicy, AssignmentMode, Host, Interface, Meta, Prefix, PrefixRole, Range,
        RangeRole, Stamp, Status,
    },
    net::{Duid, HostName, MacAddr},
    serde_util::HexBytes,
};
use tenko_dhcp::{
    config::image::{Built, build},
    feed::DhcpData,
    v6::image::{Reservation6Key, Scope6Image},
};

fn stamp() -> Stamp {
    Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    )
}

fn meta() -> Meta {
    Meta::new(stamp())
}

fn ip6(text: &str) -> Ipv6Addr {
    text.parse().expect("an IPv6 address")
}

fn mac(last: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])
}

fn duid(last: u8) -> Vec<u8> {
    vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, last]
}

fn dhcp6(code: u16, data: &[u8]) -> OptionValue {
    OptionValue {
        space: OptionSpace::dhcp6(),
        code,
        data: HexBytes(data.to_vec()),
    }
}

fn dhcp4(code: u16, data: &[u8]) -> OptionValue {
    OptionValue {
        space: OptionSpace::dhcp4(),
        code,
        data: HexBytes(data.to_vec()),
    }
}

/// The wire form of a domain name list with one name.
fn domain(labels: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for label in labels {
        out.push(u8::try_from(label.len()).expect("short label"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Rows put together for the tests.
struct Rows {
    data: DhcpData,
    vrf: VrfId,
    next: u128,
}

impl Rows {
    fn new() -> Self {
        Self {
            data: DhcpData::default(),
            vrf: VrfId::from_uuid(uuid::Uuid::from_u128(1)),
            next: 100,
        }
    }

    /// The next identifier: the same rows get the same identifiers in every build.
    fn uuid(&mut self) -> uuid::Uuid {
        self.next += 1;
        uuid::Uuid::from_u128(self.next)
    }

    fn prefix(&mut self, cidr: &str, role: PrefixRole) -> PrefixId {
        let prefix = Prefix {
            id: PrefixId::from_uuid(self.uuid()),
            vrf: self.vrf,
            cidr: cidr.parse().expect("cidr"),
            role,
            status: Status::Active,
            vlan: None,
            site: None,
            alarm: None,
            alloc: AllocPolicy::Lowest,
            dns_reverse: None,
            meta: meta(),
        };
        let id = prefix.id;
        self.data.prefixes.insert(id, prefix);
        id
    }

    fn range(
        &mut self,
        prefix: PrefixId,
        first: &str,
        last: &str,
        role: RangeRole,
        lease_secs: Option<u32>,
    ) -> RangeId {
        let range = Range {
            id: RangeId::from_uuid(self.uuid()),
            prefix,
            first: first.parse().expect("first"),
            last: last.parse().expect("last"),
            role,
            lease_secs,
            delegated_len: None,
            status: Status::Active,
            meta: meta(),
        };
        let id = range.id;
        self.data.ranges.insert(id, range);
        id
    }

    fn scope(&mut self, prefix: PrefixId, enabled: bool, v6: Option<Scope6Settings>) {
        self.data.scopes.insert(
            prefix,
            Scope {
                prefix,
                enabled,
                lease: Some(LeaseTimes {
                    default_secs: 4_000,
                    min_secs: 600,
                    max_secs: 8_000,
                    t1_secs: None,
                    t2_secs: None,
                }),
                authoritative: None,
                server_id: None,
                ddns: DdnsPolicy::default(),
                shared_network: None,
                restricted: false,
                classes: Vec::new(),
                description: None,
                v6,
                created: stamp(),
                updated: stamp(),
            },
        );
    }

    fn options(&mut self, owner: OptionOwner, values: Vec<OptionValue>) {
        self.data.option_sets.insert(
            owner,
            OptionSet {
                owner,
                values,
                updated: stamp(),
            },
        );
    }

    /// A host of `mode` with one interface; the host's id and the interface's.
    fn host(
        &mut self,
        name: &str,
        mode: AssignmentMode,
        duid: Option<Vec<u8>>,
        mac: Option<MacAddr>,
    ) -> (HostId, InterfaceId) {
        let host = Host {
            id: HostId::from_uuid(self.uuid()),
            tenant: TenantId::generate(),
            name: HostName::new(name).expect("host name"),
            mode,
            lock: false,
            site: None,
            meta: meta(),
        };
        let interface = Interface {
            id: InterfaceId::from_uuid(self.uuid()),
            host: host.id,
            name: "eth0".to_owned(),
            mac,
            duid: duid.map(|octets| Duid::new(octets).expect("a DUID")),
            client_id: None,
            meta: meta(),
        };
        let ids = (host.id, interface.id);
        self.data.hosts.insert(host.id, host);
        self.data.interfaces.insert(interface.id, interface);
        ids
    }

    fn address(
        &mut self,
        prefix: PrefixId,
        ip: &str,
        interface: Option<InterfaceId>,
        status: Status,
    ) {
        let address = Address {
            id: AddressId::from_uuid(self.uuid()),
            vrf: self.vrf,
            ip: ip.parse().expect("ip"),
            prefix,
            status,
            interface,
            dns_name: None,
            meta: meta(),
        };
        self.data.addresses.insert(address.id, address);
    }
}

/// The identifiers of the rows `world` made, for the assertions.
struct World {
    data: DhcpData,
    scope6: PrefixId,
    unserved6: PrefixId,
    network4: PrefixId,
    pool_a: RangeId,
    pool_b: RangeId,
    h_duid: HostId,
    h_mac: HostId,
    h_none: HostId,
    h_dup: [HostId; 2],
}

/// The rows of the tests. With `with6` false only the DHCPv4 rows are in, so that the two
/// builds can be compared.
#[allow(clippy::too_many_lines, reason = "one configuration, row by row")]
fn world(with6: bool) -> World {
    let mut rows = Rows::new();

    // The DHCPv4 side: a network with a pool, an option set and a reserved host.
    let network4 = rows.prefix("192.0.2.0/24", PrefixRole::Network);
    rows.range(
        network4,
        "192.0.2.100",
        "192.0.2.199",
        RangeRole::DhcpPool,
        None,
    );
    rows.scope(network4, true, None);
    rows.options(
        OptionOwner::Scope(network4),
        vec![dhcp4(3, &[192, 0, 2, 1]), dhcp4(6, &[192, 0, 2, 53])],
    );
    let (_, interface4) = rows.host("printer", AssignmentMode::Reserved, None, Some(mac(0x40)));
    rows.address(network4, "192.0.2.30", Some(interface4), Status::Active);
    // The server's options hold values of both spaces; the DHCPv4 scope keeps them all and
    // reads its own space.
    rows.options(
        OptionOwner::Server,
        vec![
            dhcp4(6, &[192, 0, 2, 54]),
            dhcp6(23, &ip6("2001:db8::53").octets()),
            dhcp6(24, &domain(&["server", "test"])),
        ],
    );

    let scope6 = rows.prefix("2001:db8:1::/64", PrefixRole::Network);
    let unserved6 = rows.prefix("2001:db8:2::/64", PrefixRole::Network);
    let supernet = rows.prefix("2001:db8::/32", PrefixRole::Supernet);
    let (pool_a, pool_b);
    let mut ids = (HostId::generate(), HostId::generate(), HostId::generate());
    let mut dup = [HostId::generate(), HostId::generate()];
    if with6 {
        pool_a = rows.range(
            scope6,
            "2001:db8:1::100",
            "2001:db8:1::1ff",
            RangeRole::DhcpPool,
            None,
        );
        pool_b = rows.range(
            scope6,
            "2001:db8:1::400",
            "2001:db8:1::4ff",
            RangeRole::DhcpPool,
            Some(1_200),
        );
        // A range held back, and an infrastructure range outside the pools.
        rows.range(
            scope6,
            "2001:db8:1::180",
            "2001:db8:1::18f",
            RangeRole::Reserved,
            None,
        );
        rows.range(
            scope6,
            "2001:db8:1::3f0",
            "2001:db8:1::3ff",
            RangeRole::Infrastructure,
            None,
        );
        rows.scope(
            scope6,
            true,
            Some(Scope6Settings {
                preferred_secs: Some(3_000),
                interface_id: Some("eth1".to_owned()),
                ..Scope6Settings::default()
            }),
        );
        // A network with a scope that is switched off, and a supernet with a scope: neither
        // is served.
        rows.range(
            unserved6,
            "2001:db8:2::100",
            "2001:db8:2::1ff",
            RangeRole::DhcpPool,
            None,
        );
        rows.scope(unserved6, false, None);
        rows.scope(supernet, true, None);
        // The options: the server's (set above) and the scope's win per code.
        rows.options(
            OptionOwner::Scope(scope6),
            vec![
                dhcp6(24, &domain(&["scope", "test"])),
                dhcp6(56, &ip6("2001:db8::123").octets()),
            ],
        );

        // A static host's address inside a pool: never offered.
        let (_, interface) = rows.host("router", AssignmentMode::Static, None, Some(mac(0x10)));
        rows.address(scope6, "2001:db8:1::150", Some(interface), Status::Active);
        // A dynamic host's address inside a pool stays dynamic.
        let (_, interface) = rows.host("laptop", AssignmentMode::Dynamic, None, Some(mac(0x11)));
        rows.address(scope6, "2001:db8:1::160", Some(interface), Status::Active);

        // Reserved hosts: by DUID (with options), by MAC address only, with neither.
        let (h_duid, interface) = rows.host(
            "by-duid",
            AssignmentMode::Reserved,
            Some(duid(0x20)),
            Some(mac(0x20)),
        );
        rows.address(scope6, "2001:db8:1::80", Some(interface), Status::Active);
        rows.options(
            OptionOwner::Host(interface),
            vec![dhcp6(23, &ip6("2001:db8::99").octets())],
        );
        let (h_mac, interface) =
            rows.host("by-mac", AssignmentMode::Reserved, None, Some(mac(0x21)));
        rows.address(scope6, "2001:db8:1::81", Some(interface), Status::Planned);
        let (h_none, interface) = rows.host("nobody", AssignmentMode::Reserved, None, None);
        rows.address(scope6, "2001:db8:1::82", Some(interface), Status::Active);
        // Two hosts reserving one address.
        let (first, interface_first) =
            rows.host("dup-a", AssignmentMode::Reserved, Some(duid(0x30)), None);
        let (second, interface_second) =
            rows.host("dup-b", AssignmentMode::Reserved, Some(duid(0x31)), None);
        rows.address(
            scope6,
            "2001:db8:1::83",
            Some(interface_first),
            Status::Active,
        );
        rows.address(
            scope6,
            "2001:db8:1::83",
            Some(interface_second),
            Status::Active,
        );
        // A reserved host in a network without a served scope gives nothing.
        let (_, interface) =
            rows.host("unserved", AssignmentMode::Reserved, Some(duid(0x40)), None);
        rows.address(unserved6, "2001:db8:2::10", Some(interface), Status::Active);
        // A reserved host whose address was retired gives nothing.
        let (_, interface) = rows.host("retired", AssignmentMode::Reserved, Some(duid(0x41)), None);
        rows.address(
            scope6,
            "2001:db8:1::90",
            Some(interface),
            Status::Deprecated,
        );
        ids = (h_duid, h_mac, h_none);
        dup = [first, second];
    } else {
        pool_a = RangeId::generate();
        pool_b = RangeId::generate();
    }
    World {
        data: rows.data,
        scope6,
        unserved6,
        network4,
        pool_a,
        pool_b,
        h_duid: ids.0,
        h_mac: ids.1,
        h_none: ids.2,
        h_dup: dup,
    }
}

fn scope_of(built: &Built, prefix: PrefixId) -> &Scope6Image {
    built.image.v6().scope(prefix).expect("the scope is served")
}

#[test]
fn a_scope_on_an_ipv6_network_gets_its_pools_exclusions_and_settings() {
    let world = world(true);
    let built = build(&world.data);
    let image = built.image.v6();

    // Only the enabled scope on the IPv6 network is in: the disabled scope, the scope on a
    // supernet and the IPv4 scope are not.
    assert_eq!(image.scopes().len(), 1);
    assert!(image.scope(world.unserved6).is_none());
    assert!(image.scope(world.network4).is_none());
    assert_eq!(built.image.scopes().len(), 1);
    assert_eq!(built.image.scopes()[0].prefix, world.network4);

    let scope = scope_of(&built, world.scope6);
    assert_eq!(scope.network.to_string(), "2001:db8:1::/64");
    assert_eq!(scope.lease.default_secs, 4_000);
    assert_eq!(scope.v6.preferred_secs, Some(3_000));
    assert_eq!(scope.interface_id.as_deref(), Some(&b"eth1"[..]));
    assert_eq!(
        image.by_interface_id(b"eth1").map(|scope| scope.prefix),
        Some(world.scope6)
    );
    assert!(image.by_interface_id(b"eth2").is_none());
    assert_eq!(
        image
            .select(ip6("2001:db8:1::beef"))
            .map(|scope| scope.prefix),
        Some(world.scope6)
    );
    assert!(image.select(ip6("2001:db8:2::1")).is_none());

    // Two pools, by first address; the second has its range's fixed lease time.
    assert_eq!(scope.pools.len(), 2);
    assert_eq!(scope.pools[0].range, world.pool_a);
    assert_eq!(scope.pools[0].first, ip6("2001:db8:1::100"));
    assert_eq!(scope.pools[0].last, ip6("2001:db8:1::1ff"));
    assert_eq!(scope.pools[0].lease, scope.lease, "the scope's lease times");
    assert_eq!(scope.pools[1].range, world.pool_b);
    assert_eq!(scope.pools[1].lease, LeaseTimes::fixed(1_200));
    assert_eq!(scope.pools[1].size(), 0x100);

    // Excluded: the reserved range, the infrastructure range, the static host's address,
    // and every address that is no dynamic host's (the reserved hosts' merged into a run,
    // the retired one); a dynamic host's address is not.
    assert_eq!(
        scope.excluded,
        vec![
            (ip6("2001:db8:1::80"), ip6("2001:db8:1::83")),
            (ip6("2001:db8:1::90"), ip6("2001:db8:1::90")),
            (ip6("2001:db8:1::150"), ip6("2001:db8:1::150")),
            (ip6("2001:db8:1::180"), ip6("2001:db8:1::18f")),
            (ip6("2001:db8:1::3f0"), ip6("2001:db8:1::3ff")),
        ]
    );
    assert!(scope.is_excluded(ip6("2001:db8:1::150")));
    assert!(scope.is_excluded(ip6("2001:db8:1::185")));
    assert!(
        scope.is_excluded(ip6("2001:db8:1::")),
        "the anycast address"
    );
    assert!(!scope.is_excluded(ip6("2001:db8:1::160")));
    assert!(scope.is_dynamic(ip6("2001:db8:1::160")));
    assert!(scope.is_dynamic(ip6("2001:db8:1::100")));
    assert!(scope.is_dynamic(ip6("2001:db8:1::450")));
    assert!(!scope.is_dynamic(ip6("2001:db8:1::150")));
    assert!(!scope.is_dynamic(ip6("2001:db8:1::185")));
    assert!(
        !scope.is_dynamic(ip6("2001:db8:1::300")),
        "outside the pools"
    );
}

#[test]
fn the_options_of_the_server_and_the_scope_merge_with_the_scope_winning_per_code() {
    let world = world(true);
    let built = build(&world.data);
    let scope = scope_of(&built, world.scope6);
    // 23 only at the server, 24 at both (the scope's wins), 56 only at the scope.
    assert_eq!(
        scope.option(23).map(|value| value.data.0.clone()),
        Some(ip6("2001:db8::53").octets().to_vec())
    );
    assert_eq!(
        scope.option(24).map(|value| value.data.0.clone()),
        Some(domain(&["scope", "test"]))
    );
    assert_eq!(
        scope.option(56).map(|value| value.data.0.clone()),
        Some(ip6("2001:db8::123").octets().to_vec())
    );
    // Each code once; the DHCPv4 option of the server is of the other space and answers to
    // no DHCPv6 code.
    let v6_codes: Vec<u16> = scope
        .options
        .iter()
        .filter(|value| value.space.is_dhcp6())
        .map(|value| value.code)
        .collect();
    let unique: BTreeSet<u16> = v6_codes.iter().copied().collect();
    assert_eq!(v6_codes.len(), unique.len());
    assert_eq!(unique, BTreeSet::from([23, 24, 56]));
    assert!(
        scope.option(6).is_none(),
        "dhcp4 option 6 is not a dhcp6 option"
    );
    // The DHCPv4 scope reads its own space: its option 6 is its own, not the server's.
    assert_eq!(
        built.image.scopes()[0]
            .option(6)
            .map(|value| value.data.0.clone()),
        Some(vec![192, 0, 2, 53])
    );
}

#[test]
fn reservations_are_keyed_by_duid_or_mac_and_the_findings_name_what_was_left_out() {
    let world = world(true);
    let built = build(&world.data);
    let image = built.image.v6();

    // Three reservations: by DUID, by MAC, and the first of the two on one address.
    assert_eq!(image.reservations().len(), 3);
    let by_duid = image
        .reservation(world.scope6, &duid(0x20), None)
        .expect("the DUID reservation");
    assert_eq!(by_duid.addr, ip6("2001:db8:1::80"));
    assert_eq!(by_duid.host, world.h_duid);
    assert_eq!(by_duid.key, Reservation6Key::Duid(duid(0x20)));
    assert_eq!(by_duid.options.len(), 1, "the interface's option set");
    assert_eq!(by_duid.options[0].code, 23);
    assert_eq!(
        image
            .reserved_at(world.scope6, ip6("2001:db8:1::80"))
            .map(|reservation| reservation.host),
        Some(world.h_duid)
    );

    // An interface with only a MAC address: keyed by the MAC (a planned address counts).
    let by_mac = image
        .reservation(
            world.scope6,
            &[0, 1],
            Some([0x00, 0x00, 0x5e, 0x00, 0x53, 0x21]),
        )
        .expect("the MAC reservation");
    assert_eq!(by_mac.addr, ip6("2001:db8:1::81"));
    assert_eq!(by_mac.host, world.h_mac);
    assert_eq!(
        by_mac.key,
        Reservation6Key::Mac([0x00, 0x00, 0x5e, 0x00, 0x53, 0x21])
    );
    // A DUID wins over the MAC address when a client has both.
    let both = image
        .reservation(
            world.scope6,
            &duid(0x20),
            Some([0x00, 0x00, 0x5e, 0x00, 0x53, 0x21]),
        )
        .expect("by DUID first");
    assert_eq!(both.host, world.h_duid);

    // Neither: no reservation and a finding.
    assert!(
        image
            .reserved_at(world.scope6, ip6("2001:db8:1::82"))
            .is_none()
    );
    assert!(
        built
            .warnings6
            .contains(&ReservationWarning::NoIdentity { host: world.h_none }),
        "{:?}",
        built.warnings6
    );

    // Two hosts on one address: one wins, the other is dropped, and the check says so.
    let kept = image
        .reserved_at(world.scope6, ip6("2001:db8:1::83"))
        .expect("one of them holds the address");
    assert_eq!(built.dropped6.len(), 1);
    let dropped = &built.dropped6[0];
    assert_eq!(dropped.addr, ip6("2001:db8:1::83"));
    assert_ne!(dropped.host, kept.host);
    let both_hosts: BTreeSet<HostId> = [kept.host, dropped.host].into_iter().collect();
    assert_eq!(both_hosts, world.h_dup.into_iter().collect());
    assert!(
        built.warnings6.iter().any(|warning| matches!(
            warning,
            ReservationWarning::AddressCollision { address, hosts }
                if *address == "2001:db8:1::83".parse::<std::net::IpAddr>().expect("ip")
                    && hosts.len() == 2
        )),
        "{:?}",
        built.warnings6
    );

    // Nothing for the host in a network without a scope, nor for the retired address.
    assert!(
        image
            .reservation(world.unserved6, &duid(0x40), None)
            .is_none()
    );
    assert!(image.reservation(world.scope6, &duid(0x41), None).is_none());
    assert!(
        image
            .reserved_at(world.scope6, ip6("2001:db8:1::90"))
            .is_none()
    );
    assert!(
        image
            .reserved_at(world.unserved6, ip6("2001:db8:2::10"))
            .is_none()
    );

    // The DHCPv4 findings are not touched by the DHCPv6 hosts.
    assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    assert_eq!(built.dropped.len(), 0);
}

#[test]
fn the_ipv6_rows_leave_the_dhcpv4_part_of_the_image_as_it_was() {
    let with = build(&world(true).data);
    let without = build(&world(false).data);
    assert_eq!(without.image.v6().scopes().len(), 0);
    assert_eq!(with.image.v6().scopes().len(), 1);
    assert_eq!(
        format!("{:?}", with.image.scopes()),
        format!("{:?}", without.image.scopes())
    );
    assert_eq!(
        format!("{:?}", with.image.reservations()),
        format!("{:?}", without.image.reservations())
    );
    assert_eq!(with.image.reservations().len(), 1, "the printer");
    assert_eq!(
        format!("{:?}", with.warnings),
        format!("{:?}", without.warnings)
    );
    assert_eq!(
        format!("{:?}", with.dropped),
        format!("{:?}", without.dropped)
    );
    assert!(without.warnings6.is_empty() && without.dropped6.is_empty());
}

#[test]
fn a_scope_without_dhcpv6_settings_gets_the_defaults_and_no_interface_id() {
    let mut world = world(true);
    world.data.scopes.get_mut(&world.scope6).expect("scope").v6 = None;
    let built = build(&world.data);
    let scope = scope_of(&built, world.scope6);
    assert_eq!(scope.v6, Scope6Settings::default());
    assert_eq!(scope.interface_id, None);
    assert!(built.image.v6().by_interface_id(b"eth1").is_none());
}

#[test]
fn a_scope_switched_off_drops_the_scope_and_its_reservations() {
    let mut world = world(true);
    world
        .data
        .scopes
        .get_mut(&world.scope6)
        .expect("scope")
        .enabled = false;
    let built = build(&world.data);
    assert_eq!(built.image.v6().scopes().len(), 0);
    assert_eq!(built.image.v6().reservations().len(), 0);
    assert_eq!(built.dropped6.len(), 0);
    assert!(built.warnings6.is_empty(), "{:?}", built.warnings6);
}
