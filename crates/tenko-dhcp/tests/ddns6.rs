//! The DDNS worker for DHCPv6 leases over the in-memory store (WP9.1, plan section 2.9):
//! `dhcp.leases6` rows are written as the committer and the expiry service write them, and
//! the worker follows them into the zones through the zone service, as `ddns.rs` does for
//! DHCPv4.
//!
//! - A lease with option 39 (S and E set) gets its AAAA record, its DHCID of identifier
//!   type 2 over the DUID and its PTR under `ip6.arpa`, all of origin `dhcp`; the outcome
//!   lands on the row.
//! - A second DUID that claims the name is refused by name protection.
//! - A release removes the AAAA, the DHCID and the PTR.
//! - A client that writes its own AAAA record gets only its PTR.
//! - A dual-stack client (an RFC 4361 client identifier on the DHCPv4 side with the IAID
//!   and DUID of its DHCPv6 lease) holds one name with an A and an AAAA record and one
//!   DHCID, which goes with the second of the two releases.

use std::{
    fmt::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tenko_core::{
    NodeId, PrefixId, Principal, RangeId, RequestCtx, SystemComponent, Timestamp, VrfId,
    cluster::LeaderService as _,
    dhcp::{
        BindingState, ClientKey, DdnsConflict, DdnsPolicy, DdnsState, Lease, Lease6, Lease6Kind,
        Scope6Settings,
        tables::{LEASES, LEASES6},
    },
    dns::{
        DnsName, Origin, RecordData, RrSet, RrSetKey, Rtype, ScopeName, SerialPolicy, SoaDefaults,
        UpdatePolicy, ZoneId, ZoneKind, tables::RRSETS,
    },
    ipam::{AllocPolicy, Meta, Prefix, PrefixRole, Range, RangeRole, Stamp, Status},
    net::Duid,
    serde_util::HexBytes,
};
use tenko_dhcp::{
    config::{
        ConfigService,
        scopes::{NewScope, ScopeChange},
    },
    ddns::{DdnsProfile, DdnsService, DdnsSettings, dhcid, plan::DHCID},
    v4::ClientFqdn,
};
use tenko_dns::zone::{NewZone, ZoneConfig, ZoneService};
use tenko_ipam::tables::{PREFIX_RANGES, PREFIXES, RANGES};
use tenko_store::{MemStore, ReadConsistency, ReadViewExt as _, Store, WriteBatch};
use tokio_util::sync::CancellationToken;

/// The forward zone.
const FORWARD: &str = "example.test";
/// The reverse zone of `2001:db8:1::/64`: the sixteen nibbles of `2001:0db8:0001:0000`,
/// least significant first.
const REVERSE6: &str = "0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
/// The reverse zone of the DHCPv4 network of the dual-stack client.
const REVERSE4: &str = "2.0.192.in-addr.arpa";

/// S and E, in the layout of option 81: the server writes the AAAA record, the name is in
/// the canonical wire format.
const FLAGS_S_E: u8 = ClientFqdn::FLAG_S | 0x04;

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::new(Principal::system(SystemComponent::Api))
}

fn meta() -> Meta {
    Meta::new(Stamp::new(
        "2026-10-22T12:00:00Z".parse().expect("time"),
        Principal::system(SystemComponent::Api),
    ))
}

/// The DUID-LL of the client with this last MAC octet (RFC 7042 documentation MACs).
fn duid(last: u8) -> Vec<u8> {
    vec![0, 3, 0, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, last]
}

fn ip6(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x100 + last)
}

fn ip4(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

/// The name of the PTR record of `addr` under `ip6.arpa`.
fn ptr6(addr: Ipv6Addr) -> String {
    let mut out = String::new();
    for octet in addr.octets().iter().rev() {
        let _ = write!(out, "{:x}.{:x}.", octet & 0x0f, octet >> 4);
    }
    out.push_str("ip6.arpa");
    out
}

fn new_zone(apex: &str) -> NewZone {
    NewZone {
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: Vec::new(),
        serial: SerialPolicy::Counter,
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        name_servers: vec![name("ns1.example.test")],
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        description: None,
        reverse_of: None,
        catalog: false,
    }
}

struct Lab {
    store: Arc<dyn Store>,
    config: Arc<ConfigService>,
    vrf: VrfId,
    scope6: PrefixId,
    scope4: PrefixId,
    forward: ZoneId,
    reverse6: ZoneId,
    reverse4: ZoneId,
    stop: CancellationToken,
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Writes an IPAM network with a DHCP pool.
async fn network(store: &Arc<dyn Store>, vrf: VrfId, cidr: &str, pool: (&str, &str)) -> PrefixId {
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
        meta: meta(),
    };
    let range = Range {
        id: RangeId::generate(),
        prefix: prefix.id,
        first: pool.0.parse().expect("first"),
        last: pool.1.parse().expect("last"),
        role: RangeRole::DhcpPool,
        lease_secs: None,
        delegated_len: None,
        status: Status::Active,
        meta: meta(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch
        .put_typed(&PREFIXES, &prefix.id, &prefix)
        .expect("prefix");
    batch.put_typed(&RANGES, &range.id, &range).expect("range");
    batch
        .put_typed(&PREFIX_RANGES, &(prefix.id, range.id), &())
        .expect("index");
    store.propose(batch).await.expect("IPAM rows");
    prefix.id
}

fn new_scope(prefix: PrefixId, v6: bool, forward: ZoneId) -> NewScope {
    NewScope {
        v6: v6.then(Scope6Settings::default),
        prefix,
        enabled: None,
        lease: None,
        authoritative: None,
        server_id: None,
        ddns: Some(DdnsPolicy {
            enabled: true,
            forward_zone: Some(forward),
            ..DdnsPolicy::default()
        }),
        shared_network: None,
        restricted: false,
        classes: Vec::new(),
        description: None,
    }
}

async fn lab() -> Lab {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let zones = ZoneService::with_direct_jobs(Arc::clone(&store), None, ZoneConfig::default());
    let mut ids = Vec::new();
    for apex in [FORWARD, REVERSE6, REVERSE4] {
        ids.push(
            zones
                .create(&cx(), new_zone(apex))
                .await
                .expect("zone")
                .zone
                .id,
        );
    }
    let config = ConfigService::with_direct_jobs(Arc::clone(&store));
    let vrf = VrfId::generate();
    let scope6 = network(
        &store,
        vrf,
        "2001:db8:1::/64",
        ("2001:db8:1::100", "2001:db8:1::1ff"),
    )
    .await;
    let scope4 = network(&store, vrf, "192.0.2.0/24", ("192.0.2.100", "192.0.2.199")).await;
    config
        .create_scope(&cx(), new_scope(scope6, true, ids[0]))
        .await
        .expect("the DHCPv6 scope");
    config
        .create_scope(&cx(), new_scope(scope4, false, ids[0]))
        .await
        .expect("the DHCPv4 scope");
    let profile = Arc::new(Mutex::new(DdnsProfile::HOME));
    let source = {
        let profile = Arc::clone(&profile);
        Arc::new(move |_: &dyn tenko_store::ReadView| {
            *profile.lock().unwrap_or_else(PoisonError::into_inner)
        })
    };
    let service = Arc::new(DdnsService::new(
        Arc::clone(&store),
        Arc::clone(&zones),
        source,
        DdnsSettings {
            backoff: Duration::from_millis(20),
            retry_after: Duration::from_millis(200),
            ..DdnsSettings::default()
        },
    ));
    let stop = CancellationToken::new();
    let token = stop.child_token();
    tokio::spawn(async move { service.run(0, token).await });
    Lab {
        store,
        config,
        vrf,
        scope6,
        scope4,
        forward: ids[0],
        reverse6: ids[1],
        reverse4: ids[2],
        stop,
    }
}

impl Lab {
    /// A DHCPv6 lease of the client with `who` as the last octet of its DUID.
    fn lease6(&self, last: u16, who: u8, fqdn: Option<(&str, u8)>) -> Lease6 {
        let now = Timestamp::now();
        Lease6 {
            addr: IpAddr::V6(ip6(last)),
            prefix_len: 128,
            kind: Lease6Kind::Na,
            vrf: self.vrf,
            scope: self.scope6,
            iaid: 1,
            duid: Duid::new(duid(who)).expect("a DUID"),
            link_layer: None,
            link_layer_type: None,
            state: BindingState::Active,
            cltt: now,
            ends: now.checked_add(Duration::from_secs(3_600)).expect("end"),
            preferred_ends: now.checked_add(Duration::from_secs(1_800)).expect("end"),
            node: NodeId(1),
            fqdn: fqdn.map(|(name, _)| name.to_owned()),
            fqdn_flags: fqdn.map(|(_, flags)| flags),
            relay: None,
            observed_at: None,
            ddns: DdnsState::default(),
        }
    }

    /// A DHCPv4 lease whose client identifier is the RFC 4361 form of `iaid` and the DUID of
    /// client `who`.
    fn lease4_rfc4361(&self, last: u8, who: u8, iaid: u32, fqdn: (&str, u8)) -> Lease {
        let now = Timestamp::now();
        let mut id = vec![255];
        id.extend_from_slice(&iaid.to_be_bytes());
        id.extend_from_slice(&duid(who));
        Lease {
            addr: ip4(last),
            vrf: self.vrf,
            scope: self.scope4,
            client: ClientKey {
                htype: 1,
                chaddr: HexBytes(vec![0x00, 0x00, 0x5e, 0x00, 0x53, who]),
                client_id: Some(HexBytes(id)),
            },
            state: BindingState::Active,
            cltt: now,
            ends: now.checked_add(Duration::from_secs(3_600)).expect("end"),
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: None,
            fqdn: Some(fqdn.0.to_owned()),
            fqdn_flags: Some(fqdn.1),
            ddns_policy: None,
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
        }
    }

    /// Writes a DHCPv6 row as the committer does: the held row's DDNS outcome stays when
    /// the client is the same.
    async fn commit6(&self, mut lease: Lease6) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        let key = (lease.vrf, lease.addr6());
        if let Some((held, _)) = view.get_typed(&LEASES6, &key).expect("row")
            && held.client_key() == lease.client_key()
        {
            lease.ddns = held.ddns;
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        batch.put_typed(&LEASES6, &key, &lease).expect("lease");
        self.store.propose(batch).await.expect("commit");
    }

    async fn commit4(&self, mut lease: Lease) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        if let Some((held, _)) = view
            .get_typed(&LEASES, &(lease.vrf, lease.addr))
            .expect("row")
            && held.client == lease.client
        {
            lease.ddns = held.ddns;
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), Timestamp::now());
        batch
            .put_typed(&LEASES, &(lease.vrf, lease.addr), &lease)
            .expect("lease");
        self.store.propose(batch).await.expect("commit");
    }

    /// Ends a DHCPv6 binding as a release or the expiry service does.
    async fn end6(&self, last: u16, state: BindingState) {
        let mut lease = self.row6(last).await.expect("lease");
        lease.state = state;
        lease.ends = Timestamp::now();
        self.commit6(lease).await;
    }

    async fn end4(&self, last: u8, state: BindingState) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        let (mut lease, _) = view
            .get_typed(&LEASES, &(self.vrf, ip4(last)))
            .expect("row")
            .expect("lease");
        lease.state = state;
        lease.ends = Timestamp::now();
        self.commit4(lease).await;
    }

    async fn row6(&self, last: u16) -> Option<Lease6> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.get_typed(&LEASES6, &(self.vrf, ip6(last)))
            .expect("row")
            .map(|(lease, _)| lease)
    }

    async fn ddns6(&self, last: u16) -> DdnsState {
        self.row6(last)
            .await
            .map(|lease| lease.ddns)
            .unwrap_or_default()
    }

    async fn rrset(&self, zone: ZoneId, owner: &str, rtype: Rtype) -> Option<RrSet> {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.get_typed(
            &RRSETS,
            &RrSetKey {
                zone,
                scope: ScopeName::DEFAULT,
                name: name(owner),
                rtype,
            },
        )
        .expect("rrset")
        .map(|(set, _)| set)
    }

    async fn aaaa(&self, owner: &str) -> Vec<RecordData> {
        self.rrset(self.forward, owner, Rtype::AAAA)
            .await
            .map(|set| {
                set.rdata
                    .iter()
                    .map(|rdata| rdata.decode(Rtype::AAAA).expect("AAAA"))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn a(&self, owner: &str) -> Vec<RecordData> {
        self.rrset(self.forward, owner, Rtype::A)
            .await
            .map(|set| {
                set.rdata
                    .iter()
                    .map(|rdata| rdata.decode(Rtype::A).expect("A"))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn ptr6(&self, last: u16) -> Option<RecordData> {
        self.rrset(self.reverse6, &ptr6(ip6(last)), Rtype::PTR)
            .await
            .map(|set| set.rdata[0].decode(Rtype::PTR).expect("PTR"))
    }

    async fn ptr4(&self, last: u8) -> Option<RecordData> {
        self.rrset(
            self.reverse4,
            &format!("{last}.2.0.192.in-addr.arpa"),
            Rtype::PTR,
        )
        .await
        .map(|set| set.rdata[0].decode(Rtype::PTR).expect("PTR"))
    }
}

async fn until<F, Fut>(what: &str, mut done: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if done().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn aaaa_of(last: u16) -> RecordData {
    RecordData::Aaaa { address: ip6(last) }
}

fn ptr_to(target: &str) -> RecordData {
    RecordData::Ptr {
        target: name(target),
    }
}

#[test]
fn the_reverse_zone_of_the_scope_is_the_one_the_test_names() {
    // The nibbles of 2001:db8:1::/64, least significant first, and a host's PTR below it.
    assert_eq!(
        ptr6(ip6(0)),
        "0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
    assert!(ptr6(ip6(0)).ends_with(REVERSE6));
}

#[tokio::test]
async fn a_dhcpv6_lease_gets_its_aaaa_dhcid_and_ptr_and_a_release_takes_them_away() {
    let lab = lab().await;
    let lease = lab.lease6(0x10, 1, Some(("laptop", FLAGS_S_E)));
    let key = lease.client_key();
    lab.commit6(lease).await;
    let owner = "laptop.example.test";
    until("the names", || async {
        lab.aaaa(owner).await == vec![aaaa_of(0x10)]
            && lab.ptr6(0x10).await.is_some()
            && lab.ddns6(0x10).await.dhcid.is_some()
    })
    .await;

    // The AAAA record carries the lease's address, of origin dhcp, with a third of the
    // lease time as its TTL.
    let aaaa = lab
        .rrset(lab.forward, owner, Rtype::AAAA)
        .await
        .expect("AAAA");
    assert_eq!(aaaa.origin, Origin::Dhcp);
    assert_eq!(aaaa.ttl, 1_200, "a third of the lease time");
    assert!(
        lab.rrset(lab.forward, owner, Rtype::A).await.is_none(),
        "no A record for an IPv6 lease"
    );

    // The DHCID: identifier type 2 over the DUID, as dhcid() computes it for the lease's
    // client key.
    let set = lab.rrset(lab.forward, owner, DHCID).await.expect("DHCID");
    assert_eq!(set.origin, Origin::Dhcp);
    assert_eq!(set.rdata.len(), 1);
    let expected = dhcid::dhcid(&key, &name(owner));
    assert_eq!(set.rdata[0].as_bytes(), expected.as_slice());
    assert_eq!(&set.rdata[0].as_bytes()[..2], &[0x00, 0x02]);

    // The PTR under ip6.arpa points at the name; it is of origin dhcp too.
    assert_eq!(lab.ptr6(0x10).await, Some(ptr_to(owner)));
    let ptr = lab
        .rrset(lab.reverse6, &ptr6(ip6(0x10)), Rtype::PTR)
        .await
        .expect("PTR");
    assert_eq!(ptr.origin, Origin::Dhcp);

    // The outcome is on the row.
    let state = lab.ddns6(0x10).await;
    assert_eq!(state.forward, Some(name(owner)));
    assert_eq!(state.reverse, Some(name(&ptr6(ip6(0x10)))));
    assert_eq!(state.dhcid, Some(HexBytes(expected)));
    assert_eq!(state.last_error, None);

    // A second DUID claims the name: refused by name protection, and the row says why.
    lab.commit6(lab.lease6(0x11, 2, Some(("LAPTOP.example.test", FLAGS_S_E))))
        .await;
    until("the refusal", || async {
        lab.ddns6(0x11)
            .await
            .last_error
            .is_some_and(|error| error.contains("name protection"))
    })
    .await;
    assert_eq!(lab.aaaa(owner).await, vec![aaaa_of(0x10)]);
    assert!(lab.ptr6(0x11).await.is_none());

    // A renewal changes nothing in the zones.
    let serial_before = lab
        .rrset(lab.forward, FORWARD, Rtype::SOA)
        .await
        .expect("SOA")
        .rdata;
    lab.commit6(lab.lease6(0x10, 1, Some(("laptop", FLAGS_S_E))))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let serial_after = lab
        .rrset(lab.forward, FORWARD, Rtype::SOA)
        .await
        .expect("SOA")
        .rdata;
    assert_eq!(serial_before, serial_after);

    // The release removes the AAAA, the DHCID and the PTR.
    lab.end6(0x10, BindingState::Released).await;
    until("the removal", || async {
        lab.aaaa(owner).await.is_empty()
            && lab.ptr6(0x10).await.is_none()
            && lab.rrset(lab.forward, owner, DHCID).await.is_none()
    })
    .await;
    until("the cleared row", || async {
        let state = lab.ddns6(0x10).await;
        state.forward.is_none() && state.reverse.is_none()
    })
    .await;
    // Now the second client may have the name, on its next renewal.
    lab.commit6(lab.lease6(0x11, 2, Some(("laptop", FLAGS_S_E))))
        .await;
    until("the name for the second client", || async {
        lab.aaaa(owner).await == vec![aaaa_of(0x11)]
    })
    .await;
    // Its DHCID differs from the first client's.
    let second = lab.rrset(lab.forward, owner, DHCID).await.expect("DHCID");
    assert_ne!(second.rdata[0].as_bytes(), set.rdata[0].as_bytes());
    assert_eq!(&second.rdata[0].as_bytes()[..2], &[0x00, 0x02]);
}

#[tokio::test]
async fn an_expiry_removes_the_names_and_a_client_may_write_its_own_aaaa_record() {
    let lab = lab().await;
    lab.config
        .update_scope(
            &cx(),
            lab.scope6,
            ScopeChange {
                ddns: Some(DdnsPolicy {
                    enabled: true,
                    forward_zone: Some(lab.forward),
                    conflict: DdnsConflict::Protect,
                    client_may_update_a: true,
                    ..DdnsPolicy::default()
                }),
                ..ScopeChange::default()
            },
            None,
        )
        .await
        .expect("scope");
    lab.commit6(lab.lease6(0x20, 3, Some(("tv", FLAGS_S_E))))
        .await;
    // A client that writes its AAAA record itself (S clear) gets only its PTR.
    lab.commit6(lab.lease6(0x21, 4, Some(("phone", 0x04))))
        .await;
    until("the PTRs", || async {
        lab.ptr6(0x20).await.is_some() && lab.ptr6(0x21).await.is_some()
    })
    .await;
    assert_eq!(lab.aaaa("tv.example.test").await, vec![aaaa_of(0x20)]);
    assert_eq!(
        lab.aaaa("phone.example.test").await,
        Vec::<RecordData>::new()
    );
    assert_eq!(lab.ptr6(0x21).await, Some(ptr_to("phone.example.test")));
    // The expiry ends the first client's binding.
    lab.end6(0x20, BindingState::Expired).await;
    until("the expiry's removal", || async {
        lab.aaaa("tv.example.test").await.is_empty() && lab.ptr6(0x20).await.is_none()
    })
    .await;
    assert!(
        lab.ptr6(0x21).await.is_some(),
        "the other client keeps its PTR"
    );
}

#[tokio::test]
async fn a_dual_stack_client_holds_one_name_with_an_a_and_an_aaaa_record_and_one_dhcid() {
    let lab = lab().await;
    let owner = "desktop.example.test";
    // The same IAID and DUID on both sides: the DHCPv4 client sends an RFC 4361 client
    // identifier.
    let lease4 = lab.lease4_rfc4361(150, 7, 1, ("desktop", ClientFqdn::FLAG_S));
    let lease6 = lab.lease6(0x30, 7, Some(("desktop", FLAGS_S_E)));
    let expected = dhcid::dhcid(&lease6.client_key(), &name(owner));
    assert_eq!(
        dhcid::dhcid(&lease4.client, &name(owner)),
        expected,
        "both families give one DHCID"
    );
    lab.commit4(lease4).await;
    until("the A record", || async {
        lab.a(owner).await == vec![RecordData::A { address: ip4(150) }]
            && lab.ptr4(150).await.is_some()
    })
    .await;
    lab.commit6(lease6).await;
    until("the AAAA record", || async {
        lab.aaaa(owner).await == vec![aaaa_of(0x30)] && lab.ptr6(0x30).await.is_some()
    })
    .await;
    // Both address records, one DHCID.
    assert_eq!(
        lab.a(owner).await,
        vec![RecordData::A { address: ip4(150) }]
    );
    let set = lab.rrset(lab.forward, owner, DHCID).await.expect("DHCID");
    assert_eq!(set.rdata.len(), 1);
    assert_eq!(set.rdata[0].as_bytes(), expected.as_slice());
    assert_eq!(&set.rdata[0].as_bytes()[..2], &[0x00, 0x02]);
    assert_eq!(set.origin, Origin::Dhcp);
    until("both outcomes on the rows", || async {
        lab.ddns6(0x30).await.dhcid == Some(HexBytes(expected.clone()))
    })
    .await;

    // Releasing the DHCPv4 lease removes the A record and its PTR; the AAAA record and the
    // DHCID stay.
    lab.end4(150, BindingState::Released).await;
    until("the A record's removal", || async {
        lab.a(owner).await.is_empty() && lab.ptr4(150).await.is_none()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(lab.aaaa(owner).await, vec![aaaa_of(0x30)]);
    assert_eq!(lab.ptr6(0x30).await, Some(ptr_to(owner)));
    let kept = lab
        .rrset(lab.forward, owner, DHCID)
        .await
        .expect("the DHCID stays while the AAAA record does");
    assert_eq!(kept.rdata[0].as_bytes(), expected.as_slice());

    // Releasing the DHCPv6 lease takes the rest.
    lab.end6(0x30, BindingState::Released).await;
    until("the last removal", || async {
        lab.aaaa(owner).await.is_empty()
            && lab.ptr6(0x30).await.is_none()
            && lab.rrset(lab.forward, owner, DHCID).await.is_none()
    })
    .await;

    // The other order: the DHCPv6 release first leaves the A record and the DHCID.
    let lease4 = lab.lease4_rfc4361(151, 8, 1, ("tablet", ClientFqdn::FLAG_S));
    let lease6 = lab.lease6(0x31, 8, Some(("tablet", FLAGS_S_E)));
    lab.commit4(lease4).await;
    until("tablet A", || async {
        lab.a("tablet.example.test").await == vec![RecordData::A { address: ip4(151) }]
    })
    .await;
    lab.commit6(lease6).await;
    until("tablet AAAA", || async {
        lab.aaaa("tablet.example.test").await == vec![aaaa_of(0x31)]
    })
    .await;
    lab.end6(0x31, BindingState::Expired).await;
    until("tablet AAAA removal", || async {
        lab.aaaa("tablet.example.test").await.is_empty() && lab.ptr6(0x31).await.is_none()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        lab.a("tablet.example.test").await,
        vec![RecordData::A { address: ip4(151) }]
    );
    assert!(
        lab.rrset(lab.forward, "tablet.example.test", DHCID)
            .await
            .is_some(),
        "the DHCID stays while the A record does"
    );
    lab.end4(151, BindingState::Released).await;
    until("tablet removal", || async {
        lab.a("tablet.example.test").await.is_empty()
            && lab
                .rrset(lab.forward, "tablet.example.test", DHCID)
                .await
                .is_none()
    })
    .await;
}
