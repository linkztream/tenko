//! The DDNS worker over the in-memory store (WP8.3, plan section 2.9, ADR 0020): lease
//! rows are written as the committer and the expiry service write them, and the worker
//! follows them into the zones through the zone service.
//!
//! - A client with option 81 and a legacy client with option 12 only get their A record,
//!   their DHCID and their PTR; the lease rows record the names and the DHCID.
//! - A second client that claims the first one's name is refused by name protection, and
//!   its lease says why; under `replace` it takes the name over.
//! - A release and an expiry remove the records whose DHCID still matches.
//! - An address IPAM names, and a name held by a manual RRset, are left alone.
//! - Under Standard a zone takes DHCP updates only when its policy allows them.
//! - A client that asks to write its A record itself, where the scope allows that, gets
//!   only its PTR.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tenko_core::{
    AddressId, NodeId, PrefixId, Principal, RangeId, RequestCtx, SystemComponent, Timestamp, VrfId,
    cluster::LeaderService as _,
    dhcp::{BindingState, ClientKey, DdnsConflict, DdnsPolicy, DdnsState, Lease, tables::LEASES},
    dns::{
        DnsName, Origin, RecordData, RrSet, RrSetKey, Rtype, ScopeName, SerialPolicy, SoaDefaults,
        UpdatePolicy, ZoneId, ZoneKind, tables::RRSETS,
    },
    ipam::{Address, AllocPolicy, Meta, Prefix, PrefixRole, Range, RangeRole, Stamp, Status},
    net::Fqdn,
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
use tenko_dns::zone::{
    NewZone, ZoneConfig, ZoneService,
    records::{Change, Op},
};
use tenko_ipam::tables::{ADDRESS_IPS, ADDRESSES, PREFIX_RANGES, PREFIXES, RANGES};
use tenko_store::{MemStore, ReadConsistency, ReadViewExt as _, Store, WriteBatch};
use tokio_util::sync::CancellationToken;

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

fn mac(last: u8) -> Vec<u8> {
    vec![0x00, 0x00, 0x5e, 0x00, 0x53, last]
}

fn client(last: u8) -> ClientKey {
    ClientKey {
        htype: 1,
        chaddr: HexBytes(mac(last)),
        client_id: None,
    }
}

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

struct Lab {
    store: Arc<dyn Store>,
    zones: Arc<ZoneService>,
    config: Arc<ConfigService>,
    vrf: VrfId,
    scope: PrefixId,
    forward: ZoneId,
    reverse: ZoneId,
    profile: Arc<Mutex<DdnsProfile>>,
    stop: CancellationToken,
}

fn new_zone(apex: &str, update: UpdatePolicy) -> NewZone {
    NewZone {
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: Vec::new(),
        serial: SerialPolicy::Counter,
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        name_servers: vec![name("ns1.example.test")],
        transfer: tenko_core::dns::TransferPolicy::default(),
        update,
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        description: None,
        reverse_of: None,
        catalog: false,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the zones, the network, the scope and the worker of one lab"
)]
async fn lab(profile: DdnsProfile, update: UpdatePolicy) -> Lab {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let zones = ZoneService::with_direct_jobs(Arc::clone(&store), None, ZoneConfig::default());
    let forward = zones
        .create(&cx(), new_zone("lan.example.test", update.clone()))
        .await
        .expect("forward zone")
        .zone
        .id;
    let reverse = zones
        .create(&cx(), new_zone("2.0.192.in-addr.arpa", update))
        .await
        .expect("reverse zone")
        .zone
        .id;
    let config = ConfigService::with_direct_jobs(Arc::clone(&store));
    let vrf = VrfId::generate();
    let prefix = Prefix {
        id: PrefixId::generate(),
        vrf,
        cidr: "192.0.2.0/24".parse().expect("cidr"),
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
        first: ip(50).into(),
        last: ip(99).into(),
        role: RangeRole::DhcpPool,
        lease_secs: None,
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
    config
        .create_scope(
            &cx(),
            NewScope {
                prefix: prefix.id,
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
            },
        )
        .await
        .expect("scope");
    let profile = Arc::new(Mutex::new(profile));
    let stop = CancellationToken::new();
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
    let token = stop.child_token();
    tokio::spawn(async move { service.run(0, token).await });
    Lab {
        store,
        zones,
        config,
        vrf,
        scope: prefix.id,
        forward,
        reverse,
        profile,
        stop,
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Lab {
    fn lease(&self, last: u8, who: u8, fqdn: Option<(&str, u8)>, hostname: Option<&str>) -> Lease {
        let now = Timestamp::now();
        Lease {
            addr: ip(last),
            vrf: self.vrf,
            scope: self.scope,
            client: client(who),
            state: BindingState::Active,
            cltt: now,
            ends: now.checked_add(Duration::from_secs(3_600)).expect("end"),
            tstp: None,
            tsfp: None,
            atsfp: None,
            node: NodeId(1),
            share: None,
            hostname: hostname.map(str::to_owned),
            fqdn: fqdn.map(|(name, _)| name.to_owned()),
            fqdn_flags: fqdn.map(|(_, flags)| flags),
            ddns: DdnsState::default(),
            fingerprint: None,
            relay: None,
            observed_at: None,
        }
    }

    /// Writes a lease row as the committer does: the held row's DDNS outcome stays.
    async fn commit(&self, mut lease: Lease) {
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

    /// Ends a binding as a release or the expiry service does.
    async fn end(&self, last: u8, state: BindingState) {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        let (mut lease, _) = view
            .get_typed(&LEASES, &(self.vrf, ip(last)))
            .expect("row")
            .expect("lease");
        lease.state = state;
        lease.ends = Timestamp::now();
        self.commit(lease).await;
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

    async fn ddns(&self, last: u8) -> DdnsState {
        let view = self.store.read(ReadConsistency::Local).await.expect("view");
        view.get_typed(&LEASES, &(self.vrf, ip(last)))
            .expect("row")
            .map(|(lease, _)| lease.ddns)
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

    async fn ptr(&self, last: u8) -> Option<RecordData> {
        self.rrset(
            self.reverse,
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

fn a_of(last: u8) -> RecordData {
    RecordData::A { address: ip(last) }
}

#[tokio::test]
async fn names_come_on_ack_and_go_on_release_and_expiry() {
    let lab = lab(DdnsProfile::HOME, UpdatePolicy::default()).await;
    // A client with option 81 (S set: the server writes A) and a legacy client.
    lab.commit(lab.lease(50, 1, Some(("laptop", ClientFqdn::FLAG_S)), Some("ignored")))
        .await;
    lab.commit(lab.lease(51, 2, None, Some("printer"))).await;
    until("the names", || async {
        lab.a("laptop.lan.example.test").await == vec![a_of(50)]
            && lab.a("printer.lan.example.test").await == vec![a_of(51)]
            && lab.ptr(51).await.is_some()
            && lab.ddns(51).await.reverse.is_some()
    })
    .await;
    assert_eq!(
        lab.ptr(50).await,
        Some(RecordData::Ptr {
            target: name("laptop.lan.example.test")
        })
    );
    let set = lab
        .rrset(lab.forward, "laptop.lan.example.test", DHCID)
        .await
        .expect("DHCID");
    assert_eq!(set.origin, Origin::Dhcp);
    let expected = dhcid::dhcid(&client(1), &name("laptop.lan.example.test"));
    assert_eq!(set.rdata[0].as_bytes(), expected.as_slice());
    let a = lab
        .rrset(lab.forward, "laptop.lan.example.test", Rtype::A)
        .await
        .expect("A");
    assert_eq!(a.origin, Origin::Dhcp);
    assert_eq!(a.ttl, 1_200, "a third of the lease time");
    until("the outcome on the row", || async {
        lab.ddns(50).await.dhcid.is_some()
    })
    .await;
    let state = lab.ddns(50).await;
    assert_eq!(state.forward, Some(name("laptop.lan.example.test")));
    assert_eq!(state.reverse, Some(name("50.2.0.192.in-addr.arpa")));
    assert_eq!(state.dhcid, Some(HexBytes(expected)));
    assert_eq!(state.last_error, None);

    // A second client claims the first one's name: refused, and the lease says why.
    lab.commit(lab.lease(
        52,
        3,
        Some(("LAPTOP.lan.example.test", ClientFqdn::FLAG_S)),
        None,
    ))
    .await;
    until("the refusal", || async {
        lab.ddns(52)
            .await
            .last_error
            .is_some_and(|error| error.contains("name protection"))
    })
    .await;
    assert_eq!(lab.a("laptop.lan.example.test").await, vec![a_of(50)]);
    assert!(lab.ptr(52).await.is_none());

    // A renewal changes nothing in the zones.
    let serial_before = lab
        .rrset(lab.forward, "lan.example.test", Rtype::SOA)
        .await
        .expect("SOA")
        .rdata;
    lab.commit(lab.lease(50, 1, Some(("laptop", ClientFqdn::FLAG_S)), None))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let serial_after = lab
        .rrset(lab.forward, "lan.example.test", Rtype::SOA)
        .await
        .expect("SOA")
        .rdata;
    assert_eq!(serial_before, serial_after);

    // The release removes the first client's names; the expiry the second's.
    lab.end(50, BindingState::Released).await;
    lab.end(51, BindingState::Expired).await;
    until("the removal", || async {
        lab.a("laptop.lan.example.test").await.is_empty()
            && lab.a("printer.lan.example.test").await.is_empty()
            && lab.ptr(50).await.is_none()
            && lab.ptr(51).await.is_none()
            && lab
                .rrset(lab.forward, "laptop.lan.example.test", DHCID)
                .await
                .is_none()
    })
    .await;
    until("the cleared rows", || async {
        lab.ddns(50).await.forward.is_none() && lab.ddns(51).await.reverse.is_none()
    })
    .await;
    // Now the third client may have the name, on its next renewal.
    lab.commit(lab.lease(52, 3, Some(("laptop", ClientFqdn::FLAG_S)), None))
        .await;
    until("the name for the third client", || async {
        lab.a("laptop.lan.example.test").await == vec![a_of(52)]
    })
    .await;
}

#[tokio::test]
async fn ipam_names_manual_records_and_zone_policy_are_respected() {
    let lab = lab(DdnsProfile::STANDARD, UpdatePolicy::default()).await;
    // Under Standard a zone that says nothing takes no DHCP updates.
    lab.commit(lab.lease(60, 1, None, Some("desk"))).await;
    until("the refusal of the zone", || async {
        lab.ddns(60)
            .await
            .last_error
            .is_some_and(|error| error.contains("does not allow DHCP"))
    })
    .await;
    assert_eq!(
        lab.a("desk.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    // The operator allows DHCP in both zones: the worker reads everything again.
    for zone in [lab.forward, lab.reverse] {
        lab.zones
            .update(
                &cx(),
                zone,
                tenko_dns::zone::ZoneChange {
                    update: Some(UpdatePolicy {
                        dhcp: Some(true),
                        ..UpdatePolicy::default()
                    }),
                    ..tenko_dns::zone::ZoneChange::default()
                },
                None,
            )
            .await
            .expect("zone policy");
    }
    until("the name after the policy change", || async {
        lab.a("desk.lan.example.test").await == vec![a_of(60)] && lab.ptr(60).await.is_some()
    })
    .await;

    // A manual record holds the name: refused.
    lab.zones
        .change_records(
            &cx(),
            lab.forward,
            &[Change {
                op: Op::Set,
                scope: ScopeName::DEFAULT,
                name: name("nas.lan.example.test"),
                rtype: Rtype::A,
                ttl: None,
                records: vec![a_of(9)],
                take_over: false,
                origin: Origin::Manual,
            }],
            false,
        )
        .await
        .expect("manual record");
    lab.commit(lab.lease(61, 2, None, Some("nas"))).await;
    until("the refusal of the manual name", || async {
        lab.ddns(61)
            .await
            .last_error
            .is_some_and(|error| error.contains("origin manual"))
    })
    .await;
    assert_eq!(lab.a("nas.lan.example.test").await, vec![a_of(9)]);

    // An address IPAM names is skipped.
    let address = Address {
        id: AddressId::generate(),
        vrf: lab.vrf,
        ip: IpAddr::V4(ip(62)),
        prefix: lab.scope,
        status: Status::Active,
        interface: None,
        dns_name: Some(Fqdn::new("server.lan.example.test").expect("fqdn")),
        meta: meta(),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch
        .put_typed(&ADDRESSES, &address.id, &address)
        .expect("address");
    batch
        .put_typed(&ADDRESS_IPS, &(lab.vrf, address.ip), &address.id)
        .expect("index");
    lab.store.propose(batch).await.expect("IPAM address");
    lab.commit(lab.lease(62, 3, None, Some("server"))).await;
    until("the skip", || async {
        lab.ddns(62)
            .await
            .last_error
            .is_some_and(|error| error.contains("IPAM manages"))
    })
    .await;
    assert_eq!(
        lab.a("server.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert!(lab.ptr(62).await.is_none());
}

#[tokio::test]
async fn replace_moves_a_name_and_a_client_may_write_its_own_a_record() {
    let lab = lab(DdnsProfile::LAB, UpdatePolicy::default()).await;
    lab.config
        .update_scope(
            &cx(),
            lab.scope,
            ScopeChange {
                ddns: Some(DdnsPolicy {
                    enabled: true,
                    forward_zone: Some(lab.forward),
                    conflict: DdnsConflict::Replace,
                    client_may_update_a: true,
                    ..DdnsPolicy::default()
                }),
                ..ScopeChange::default()
            },
            None,
        )
        .await
        .expect("scope");
    lab.commit(lab.lease(70, 1, Some(("tv", ClientFqdn::FLAG_S)), None))
        .await;
    until("the first name", || async {
        lab.a("tv.lan.example.test").await == vec![a_of(70)]
    })
    .await;
    // Under `replace` the last client wins.
    lab.commit(lab.lease(71, 2, Some(("tv", ClientFqdn::FLAG_S)), None))
        .await;
    until("the moved name", || async {
        lab.a("tv.lan.example.test").await == vec![a_of(71)]
    })
    .await;
    // The first client's expiry leaves the name alone: its DHCID is gone.
    lab.end(70, BindingState::Expired).await;
    until("the first PTR gone", || async {
        lab.ptr(70).await.is_none()
    })
    .await;
    assert_eq!(lab.a("tv.lan.example.test").await, vec![a_of(71)]);
    // A client that writes its A record itself (S clear) gets only its PTR.
    lab.commit(lab.lease(72, 3, Some(("phone", 0)), None)).await;
    until("the PTR only", || async { lab.ptr(72).await.is_some() }).await;
    assert_eq!(
        lab.a("phone.lan.example.test").await,
        Vec::<RecordData>::new()
    );
    assert_eq!(
        lab.ptr(72).await,
        Some(RecordData::Ptr {
            target: name("phone.lan.example.test")
        })
    );
    // Hardened forces name protection whatever the scope says.
    *lab.profile.lock().unwrap_or_else(PoisonError::into_inner) = DdnsProfile::HARDENED;
    let forced = AtomicBool::new(false);
    lab.zones
        .update(
            &cx(),
            lab.forward,
            tenko_dns::zone::ZoneChange {
                update: Some(UpdatePolicy {
                    dhcp: Some(true),
                    ..UpdatePolicy::default()
                }),
                ..tenko_dns::zone::ZoneChange::default()
            },
            None,
        )
        .await
        .expect("zone policy");
    lab.zones
        .update(
            &cx(),
            lab.reverse,
            tenko_dns::zone::ZoneChange {
                update: Some(UpdatePolicy {
                    dhcp: Some(true),
                    ..UpdatePolicy::default()
                }),
                ..tenko_dns::zone::ZoneChange::default()
            },
            None,
        )
        .await
        .expect("zone policy");
    lab.commit(lab.lease(73, 4, Some(("tv", ClientFqdn::FLAG_S)), None))
        .await;
    until("the protected name", || async {
        let refused = lab
            .ddns(73)
            .await
            .last_error
            .is_some_and(|error| error.contains("name protection"));
        forced.store(refused, Ordering::Relaxed);
        refused
    })
    .await;
    assert!(forced.load(Ordering::Relaxed));
    assert_eq!(lab.a("tv.lan.example.test").await, vec![a_of(71)]);
}
