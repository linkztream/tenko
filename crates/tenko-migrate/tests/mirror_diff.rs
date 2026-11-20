//! The diff of a mirrored scope against a Tenko that already holds a scope of the network
//! (plan section 2.5): every action a row can name, the rule for server options, options of
//! a class and of a code without a definition, the case of values, the inherited lease time,
//! reservations found by address and by identity (also a client identifier held outside
//! the scope), the DDNS settings, and the VRF the network is looked up in.

use std::{net::IpAddr, sync::Arc};

use ipnet::IpNet;
use tenko_core::{
    AddressId, HostId, InterfaceId, PrefixId, Principal, RangeId, SystemComponent, TenantId, VrfId,
    dhcp::{
        ExclusionRange, OptionOwner, OptionSet, OptionValue, Scope,
        tables::{EXCLUSIONS, OPTION_SETS, SCOPES},
    },
    ipam::{
        Address, AllocPolicy, AssignmentMode, Host, Interface, Meta, Prefix, PrefixRole, Range,
        RangeRole, Stamp, Status,
    },
    ir::MirrorSnapshot,
    migrate::Snapshot,
    net::{HostName, MacAddr},
    serde_util::HexBytes,
};
use tenko_ipam::tables::{
    ADDRESS_IPS, ADDRESSES, HOST_INTERFACES, HOSTS, INTERFACE_ADDRESSES, INTERFACE_MACS,
    INTERFACES, PREFIX_CIDRS, PREFIX_RANGES, PREFIXES, RANGES, TENANT_NAMES, VRF_NAMES,
};
use tenko_migrate::mirror::{DiffAction, DiffKind, DiffRow, body, diff::diff};
use tenko_store::{MemStore, ReadConsistency, Store, WriteBatch};

const FIXTURE: &str = include_str!("../../tenko-core/tests/fixtures/mirror/snapshot.json");

fn stamp() -> Stamp {
    Stamp::new(
        "2026-11-01T08:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    )
}

fn mac(last: u8) -> MacAddr {
    MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, last])
}

fn v4(code: u8, data: &[u8]) -> OptionValue {
    OptionValue::v4(code, data.to_vec())
}

/// Tenko's side, written straight into a store.
struct Tenko {
    batch: WriteBatch,
    vrf: VrfId,
}

impl Tenko {
    fn new() -> Self {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), stamp().at);
        let tenant = TenantId::generate();
        let vrf = VrfId::generate();
        batch
            .put_typed(&TENANT_NAMES, &"default".to_owned(), &tenant)
            .expect("tenant");
        batch
            .put_typed(&VRF_NAMES, &(tenant, "default".to_owned()), &vrf)
            .expect("vrf");
        Self { batch, vrf }
    }

    fn prefix(&mut self, vrf: VrfId, cidr: &str) -> Prefix {
        let prefix = Prefix {
            id: PrefixId::generate(),
            vrf,
            cidr: cidr.parse().expect("cidr"),
            role: PrefixRole::Network,
            status: Status::Active,
            vlan: None,
            site: None,
            alarm: None,
            alloc: AllocPolicy::Lowest,
            dns_reverse: None,
            meta: Meta::new(stamp()),
        };
        self.batch
            .put_typed(&PREFIXES, &prefix.id, &prefix)
            .expect("prefix");
        self.batch
            .put_typed(&PREFIX_CIDRS, &(vrf, prefix.cidr), &prefix.id)
            .expect("index");
        prefix
    }

    fn scope(&mut self, prefix: &Prefix) {
        let scope = Scope {
            prefix: prefix.id,
            enabled: false,
            lease: None,
            authoritative: None,
            server_id: None,
            ddns: tenko_core::dhcp::DdnsPolicy::default(),
            shared_network: None,
            restricted: false,
            classes: Vec::new(),
            description: None,
            v6: None,
            created: stamp(),
            updated: stamp(),
        };
        self.batch
            .put_typed(&SCOPES, &prefix.id, &scope)
            .expect("scope");
    }

    fn range(&mut self, prefix: &Prefix, first: &str, last: &str) {
        let range = Range {
            id: RangeId::generate(),
            prefix: prefix.id,
            first: first.parse().expect("first"),
            last: last.parse().expect("last"),
            role: RangeRole::DhcpPool,
            lease_secs: None,
            delegated_len: None,
            status: Status::Active,
            meta: Meta::new(stamp()),
        };
        self.batch
            .put_typed(&RANGES, &range.id, &range)
            .expect("range");
        self.batch
            .put_typed(&PREFIX_RANGES, &(prefix.id, range.id), &())
            .expect("index");
    }

    fn exclusion(&mut self, prefix: &Prefix, first: &str, last: &str) {
        let id = tenko_core::dhcp::ExclusionId::generate();
        let exclusion = ExclusionRange {
            id,
            scope: prefix.id,
            first: first.parse().expect("first"),
            last: last.parse().expect("last"),
            description: None,
            created: stamp(),
        };
        self.batch
            .put_typed(&EXCLUSIONS, &(prefix.id, id), &exclusion)
            .expect("exclusion");
    }

    fn options(&mut self, owner: OptionOwner, values: Vec<OptionValue>) {
        let set = OptionSet {
            owner,
            values,
            updated: stamp(),
        };
        self.batch
            .put_typed(&OPTION_SETS, &owner, &set)
            .expect("options");
    }

    /// A host with one interface, and its address in `prefix` when given.
    fn host(
        &mut self,
        name: &str,
        mode: AssignmentMode,
        mac: Option<MacAddr>,
        client_id: Option<&str>,
        at: Option<(&Prefix, &str)>,
    ) -> InterfaceId {
        let host = Host {
            id: HostId::generate(),
            tenant: TenantId::generate(),
            name: HostName::new(name).expect("name"),
            mode,
            lock: false,
            site: None,
            decommissioned: None,
            meta: Meta::new(stamp()),
        };
        let interface = Interface {
            id: InterfaceId::generate(),
            host: host.id,
            name: "eth0".to_owned(),
            mac,
            duid: None,
            client_id: client_id
                .map(|hex| HexBytes(tenko_core::serde_util::from_hex(hex).expect("hex"))),
            meta: Meta::new(stamp()),
        };
        self.batch.put_typed(&HOSTS, &host.id, &host).expect("host");
        self.batch
            .put_typed(&INTERFACES, &interface.id, &interface)
            .expect("interface");
        self.batch
            .put_typed(&HOST_INTERFACES, &(host.id, interface.id), &())
            .expect("index");
        if let Some(mac) = mac {
            self.batch
                .put_typed(&INTERFACE_MACS, &(mac, interface.id), &())
                .expect("index");
        }
        if let Some((prefix, ip)) = at {
            let address = Address {
                id: AddressId::generate(),
                vrf: prefix.vrf,
                ip: ip.parse::<IpAddr>().expect("ip"),
                prefix: prefix.id,
                status: Status::Active,
                interface: Some(interface.id),
                dns_name: None,
                meta: Meta::new(stamp()),
            };
            self.batch
                .put_typed(&ADDRESSES, &address.id, &address)
                .expect("address");
            self.batch
                .put_typed(&ADDRESS_IPS, &(address.vrf, address.ip), &address.id)
                .expect("index");
            self.batch
                .put_typed(&INTERFACE_ADDRESSES, &(interface.id, address.id), &())
                .expect("index");
        }
        interface.id
    }

    async fn store(self) -> Arc<dyn Store> {
        let store: Arc<dyn Store> = Arc::new(MemStore::default());
        store.propose(self.batch).await.expect("rows");
        store
    }
}

fn snapshot(envelope: MirrorSnapshot) -> Snapshot {
    Snapshot {
        mirror: tenko_core::MirrorId::generate(),
        sequence: envelope.sequence,
        hash: HexBytes(Vec::new()),
        received: envelope.taken_at,
        envelope,
    }
}

fn fixture() -> MirrorSnapshot {
    body::decode(FIXTURE.as_bytes(), false).expect("fixture")
}

const SCOPE: &str = "192.0.2.0/24";

/// The rows of `kind`, as (item, action).
fn rows_of(rows: &[DiffRow], kind: DiffKind) -> Vec<(String, DiffAction)> {
    rows.iter()
        .filter(|row| row.kind == kind)
        .map(|row| (row.item.clone(), row.action))
        .collect()
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one Tenko, every kind of row")]
async fn every_row_says_what_the_prepare_would_do() {
    let mut tenko = Tenko::new();
    let vrf = tenko.vrf;
    let prefix = tenko.prefix(vrf, SCOPE);
    let elsewhere = tenko.prefix(vrf, "198.51.100.0/24");
    tenko.scope(&prefix);
    tenko.range(&prefix, "192.0.2.100", "192.0.2.199");
    tenko.exclusion(&prefix, "192.0.2.120", "192.0.2.129");
    tenko.options(
        OptionOwner::Server,
        vec![v4(6, &[192, 0, 2, 5, 192, 0, 2, 7])],
    );
    tenko.options(
        OptionOwner::Scope(prefix.id),
        vec![
            v4(3, &[192, 0, 2, 1]),
            v4(42, &[192, 0, 2, 9]),
            v4(67, b"Boot.efi"),
            v4(224, &[1, 2]),
            v4(119, b"\x04corp\x07example\x04test\x00"),
        ],
    );
    // .10: the same identity at the address, reserved, with the same option: nothing.
    let printer = tenko.host(
        "printer01",
        AssignmentMode::Reserved,
        Some(mac(0x0a)),
        None,
        Some((&prefix, "192.0.2.10")),
    );
    tenko.options(OptionOwner::Host(printer), vec![v4(3, &[192, 0, 2, 254])]);
    // .11: the address on a host with another MAC, the reservation's MAC on none.
    tenko.host(
        "other",
        AssignmentMode::Reserved,
        Some(mac(0xf1)),
        None,
        Some((&prefix, "192.0.2.11")),
    );
    // .12: the MAC on a host at another address, with an option of its own.
    let nas = tenko.host(
        "nas01",
        AssignmentMode::Reserved,
        Some(mac(0x0c)),
        None,
        Some((&prefix, "192.0.2.250")),
    );
    tenko.options(OptionOwner::Host(nas), vec![v4(3, &[192, 0, 2, 1])]);
    // .13: the address on a host without an identity, the MAC on another host.
    tenko.host(
        "empty",
        AssignmentMode::Reserved,
        None,
        None,
        Some((&prefix, "192.0.2.13")),
    );
    tenko.host("nas02", AssignmentMode::Static, Some(mac(0x0d)), None, None);
    // .14: the identity at the address, but the host is not a reservation.
    tenko.host(
        "switch01",
        AssignmentMode::Static,
        Some(mac(0x0e)),
        None,
        Some((&prefix, "192.0.2.14")),
    );
    // .35: its client identifier on a host of another network.
    tenko.host(
        "tv",
        AssignmentMode::Reserved,
        None,
        Some("ff00000001000100012e5a1c4000005e005323"),
        Some((&elsewhere, "198.51.100.35")),
    );
    // .40: a reservation the mirror does not have.
    tenko.host(
        "gone",
        AssignmentMode::Reserved,
        Some(mac(0xf2)),
        None,
        Some((&prefix, "192.0.2.40")),
    );
    let store = tenko.store().await;

    let mut envelope = fixture();
    let ir = &mut envelope.dhcp.scopes[0];
    ir.options.push(tenko_core::ir::dhcp::IrOption {
        code: 224,
        vendor_class: None,
        user_class: None,
        values: vec!["0102".to_owned()],
        origin: tenko_core::ir::SourceLocation::default(),
    });
    ir.options.push(tenko_core::ir::dhcp::IrOption {
        code: 67,
        vendor_class: None,
        user_class: None,
        values: vec!["boot.efi".to_owned()],
        origin: tenko_core::ir::SourceLocation::default(),
    });
    ir.options.push(tenko_core::ir::dhcp::IrOption {
        code: 119,
        vendor_class: None,
        user_class: None,
        values: vec!["CORP.example.test".to_owned()],
        origin: tenko_core::ir::SourceLocation::default(),
    });
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let scope: IpNet = SCOPE.parse().expect("net");
    let found = diff(view.as_ref(), &snapshot(envelope.clone()), scope, 2, None).expect("diff");
    assert_eq!(found.tenko_scope, Some(prefix.id));
    assert_eq!(found.losses_open, 2);
    let rows = &found.rows;

    assert_eq!(rows_of(rows, DiffKind::Prefix), []);
    assert_eq!(rows_of(rows, DiffKind::Pool), [], "the pool agrees");
    assert_eq!(
        rows_of(rows, DiffKind::Exclusion),
        [
            ("192.0.2.100-192.0.2.109".to_owned(), DiffAction::Create),
            ("192.0.2.120-192.0.2.129".to_owned(), DiffAction::Remove),
        ]
    );
    assert_eq!(
        rows_of(rows, DiffKind::LeaseTime),
        [("lease_secs".to_owned(), DiffAction::Update)],
        "eight days against the inherited day"
    );
    let options = rows_of(rows, DiffKind::Option);
    let option = |item: &str| {
        options
            .iter()
            .find(|(found, _)| found == item)
            .map(|(_, action)| *action)
    };
    assert_eq!(
        option("server:6"),
        Some(DiffAction::Decide),
        "the server rule"
    );
    assert_eq!(option("server:15"), Some(DiffAction::Create));
    assert_eq!(option("scope:3"), None, "the router agrees");
    assert_eq!(option("scope:42"), Some(DiffAction::Update));
    assert_eq!(
        option("scope:67"),
        Some(DiffAction::Update),
        "a boot file name keeps its case"
    );
    assert_eq!(
        option("scope:119"),
        None,
        "a domain name compares without case"
    );
    assert_eq!(
        option("scope:224"),
        Some(DiffAction::Decide),
        "no definition to compare with"
    );
    assert_eq!(
        option("scope:1@Microsoft Windows 2000 Options"),
        Some(DiffAction::Decide),
        "Tenko's option sets carry no class"
    );
    assert_eq!(option("scope:6"), Some(DiffAction::Create));
    assert_eq!(
        option("192.0.2.10:3"),
        None,
        "the reservation's option agrees"
    );
    assert_eq!(
        option("192.0.2.12:3"),
        Some(DiffAction::Remove),
        "compared with the host that holds the MAC"
    );

    let reservations = rows_of(rows, DiffKind::Reservation);
    let reservation = |ip: &str| {
        reservations
            .iter()
            .find(|(found, _)| found == ip)
            .map(|(_, action)| *action)
    };
    assert_eq!(reservation("192.0.2.10"), None);
    assert_eq!(reservation("192.0.2.11"), Some(DiffAction::Decide));
    assert_eq!(reservation("192.0.2.12"), Some(DiffAction::Attach));
    assert_eq!(reservation("192.0.2.13"), Some(DiffAction::Decide));
    assert_eq!(reservation("192.0.2.14"), Some(DiffAction::Update));
    assert_eq!(
        reservation("192.0.2.35"),
        Some(DiffAction::Attach),
        "found outside the scope"
    );
    assert_eq!(reservation("192.0.2.40"), Some(DiffAction::Remove));
    assert_eq!(
        reservations
            .iter()
            .filter(|(_, action)| *action == DiffAction::Create)
            .count(),
        30 - 6,
        "the other reservations are new"
    );
    assert_eq!(
        rows_of(rows, DiffKind::Ddns),
        [("ddns".to_owned(), DiffAction::Update)]
    );

    // The same lease time as the inherited one gives no row.
    envelope.dhcp.scopes[0].lease_secs = Some(86_400);
    let found = diff(view.as_ref(), &snapshot(envelope), scope, 0, None).expect("diff");
    assert_eq!(rows_of(&found.rows, DiffKind::LeaseTime), []);
}

#[tokio::test]
async fn the_network_is_looked_up_in_the_default_vrf() {
    let mut tenko = Tenko::new();
    let prefix = tenko.prefix(VrfId::generate(), SCOPE);
    tenko.scope(&prefix);
    let store = tenko.store().await;
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let found = diff(
        view.as_ref(),
        &snapshot(fixture()),
        SCOPE.parse().expect("net"),
        0,
        None,
    )
    .expect("diff");
    assert_eq!(
        found.tenko_scope, None,
        "a scope of another VRF is not this one"
    );
    assert_eq!(
        rows_of(&found.rows, DiffKind::Prefix),
        [(SCOPE.to_owned(), DiffAction::Create)]
    );
}
