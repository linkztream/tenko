//! The flip of the AD zones (Windows takeover plan section 2.6, E75): three secondary
//! zones copied by transfer from a primary on loopback that serves the fixture zones of
//! `tests/fixtures/ad-zones/`, flipped to primary in place with the origins of the plan's
//! table; an unsigned update from the controllers' access list changes a locator record and
//! one of a frozen DHCP name is refused and audited; `release` lists, releases and deletes
//! the frozen names; the reverse flip makes a zone a secondary again, and the next transfer
//! replaces its records whatever its serial.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use tenko_core::{
    RequestCtx, SystemComponent,
    audit::AuditDraft,
    cluster::LeaderService,
    dns::{
        AclEntry, DnsName, Origin, PrimaryServer, QueryTransport, RecordData, RrSet, Rtype,
        SecondarySource, SerialPolicy, SoaDefaults, UpdatePolicy, Zone, ZoneFlip, ZoneFlipReport,
        ZoneKind, ZoneRelease, codes, tables::RRSETS,
    },
    testing::wait_until_async,
};
use tenko_dns::{
    catalog,
    respond::Conn,
    store_feed,
    update::{
        UpdatePath,
        message::{CLASS_ANY, CLASS_IN, push_record, rcode, write_request},
        policy::{ProfileCell, UpdateProfile},
    },
    wire,
    xfr::{
        Directory, TransferAudit,
        message::{MessageWriter, read_request},
    },
    zone::{
        NewZone, ZoneConfig, ZoneService,
        acl::NewAcl,
        secondary::{KeyLoader, SecondaryService, SecondarySettings},
        serial,
        zonefile::{Item, Reader},
    },
};
use tenko_store::{KeyRange, MemStore, ReadViewExt, Store};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

const CORP: &str = "corp.example.test";
const MSDCS: &str = "_msdcs.corp.example.test";
const REVERSE: &str = "2.0.192.in-addr.arpa";
/// The serial of the fixture zones, older than any a flip continues at.
const FIXTURE_SERIAL: u32 = 2_026_110_105;
const DHCID: Rtype = Rtype(49);

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

/// The fixture records of a zone, its SOA first.
fn fixture(apex: &str) -> Vec<(DnsName, Rtype, u32, Vec<u8>)> {
    let text = match apex {
        CORP => include_str!("fixtures/ad-zones/corp.example.test.zone"),
        MSDCS => include_str!("fixtures/ad-zones/_msdcs.corp.example.test.zone"),
        _ => include_str!("fixtures/ad-zones/2.0.192.in-addr.arpa.zone"),
    };
    let mut reader = Reader::new(text, &name(apex), 65_536).expect("reader");
    let mut out = Vec::new();
    while let Some(item) = reader.next_item().expect("the fixture parses") {
        if let Item::Record(record) = item {
            out.push((
                record.name,
                record.rtype,
                record.ttl,
                record.rdata.as_bytes().to_vec(),
            ));
        }
    }
    out.sort_by_key(|(_, rtype, ..)| *rtype != Rtype::SOA);
    out
}

/// A primary on loopback that answers every transfer with the whole fixture zone asked for.
async fn primary() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let Ok(len) = stream.read_u16().await else {
                continue;
            };
            let mut message = vec![0u8; usize::from(len)];
            if stream.read_exact(&mut message).await.is_err() {
                continue;
            }
            let request = read_request(&message).expect("a request");
            let apex = request.question.name.to_string();
            let records = fixture(apex.trim_end_matches('.'));
            let mut writer = MessageWriter::new(&message, &request, 65_000);
            let soa = &records[0];
            for (owner, rtype, ttl, rdata) in records.iter().chain(std::iter::once(soa)) {
                assert!(writer.push(&owner.to_wire(), rtype.0, *ttl, rdata));
            }
            let out = writer.take();
            let mut framed = u16::try_from(out.len())
                .expect("size")
                .to_be_bytes()
                .to_vec();
            framed.extend_from_slice(&out);
            let _ = stream.write_all(&framed).await;
        }
    });
    address
}

#[derive(Default)]
struct Refusals(Mutex<Vec<AuditDraft>>);

impl TransferAudit for Refusals {
    fn record(&self, draft: AuditDraft) {
        self.0.lock().expect("refusals").push(draft);
    }
}

struct Lab {
    zones: Arc<ZoneService>,
    store: Arc<MemStore>,
    source: SecondarySource,
    ids: HashMap<&'static str, Zone>,
    stop: CancellationToken,
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Lab {
    /// The three secondary zones of the domain, each copied once by the transfer service,
    /// which keeps running; updates allowed unsigned from the controllers' addresses.
    async fn new() -> Self {
        let store = Arc::new(MemStore::default());
        let zones = ZoneService::with_direct_jobs(
            Arc::clone(&store) as Arc<dyn Store>,
            None,
            ZoneConfig::default(),
        );
        let (controllers, _) = zones
            .create_acl(
                &cx(),
                NewAcl {
                    name: "controllers".to_owned(),
                    entries: ["192.0.2.5/32", "192.0.2.6/32"]
                        .map(|prefix| AclEntry::Prefix {
                            prefix: prefix.parse().expect("prefix"),
                            deny: false,
                        })
                        .to_vec(),
                    description: None,
                },
            )
            .await
            .expect("acl");
        let address = primary().await;
        let source = SecondarySource {
            primaries: vec![PrimaryServer {
                address: address.ip(),
                port: address.port(),
                key: None,
                xot: false,
                tls_name: None,
            }],
        };
        let mut ids = HashMap::new();
        for apex in [CORP, MSDCS, REVERSE] {
            let written = zones
                .create(
                    &cx(),
                    NewZone {
                        name: name(apex),
                        kind: ZoneKind::Secondary,
                        tenant: None,
                        scopes: Vec::new(),
                        serial: SerialPolicy::default(),
                        soa: SoaDefaults::new(
                            name("dc1.corp.example.test"),
                            name("hostmaster.corp.example.test"),
                        ),
                        name_servers: Vec::new(),
                        transfer: tenko_core::dns::TransferPolicy::default(),
                        update: UpdatePolicy {
                            allowed: vec![controllers.id],
                            require_tsig: false,
                            ..UpdatePolicy::default()
                        },
                        dnssec: tenko_core::dns::DnssecPolicy::default(),
                        source: Some(source.clone()),
                        description: None,
                        reverse_of: None,
                        catalog: false,
                    },
                )
                .await
                .expect("zone");
            ids.insert(apex, written.zone);
        }
        let stop = CancellationToken::new();
        let keys = Arc::new(KeyLoader::new(Arc::clone(&zones)));
        let service = SecondaryService::new(Arc::clone(&zones), keys, SecondarySettings::default());
        let token = stop.child_token();
        tokio::spawn(async move { service.run(0, token).await });
        let lab = Self {
            zones,
            store,
            source,
            ids,
            stop,
        };
        for apex in [CORP, MSDCS, REVERSE] {
            lab.wait_for_copy(apex).await;
        }
        lab
    }

    fn zone(&self, apex: &str) -> &Zone {
        &self.ids[apex]
    }

    async fn rrsets(&self, apex: &str) -> Vec<RrSet> {
        let view = self.zones.view(None).await.expect("view");
        view.scan_typed(
            &RRSETS,
            KeyRange::prefix(tenko_core::codec::key::encode_key(&self.zone(apex).id)),
            usize::MAX,
            false,
        )
        .expect("scan")
        .into_iter()
        .map(|(_, rrset, _)| rrset)
        .collect()
    }

    async fn rrset(&self, apex: &str, owner: &str, rtype: Rtype) -> Option<RrSet> {
        self.rrsets(apex)
            .await
            .into_iter()
            .find(|rrset| rrset.name == name(owner) && rrset.rtype == rtype)
    }

    /// Waits until the zone holds the fixture's copy, every RRset `transfer`.
    async fn wait_for_copy(&self, apex: &str) {
        let expected = fixture(apex);
        wait_until_async(&format!("the copy of {apex}"), || async {
            let rrsets = self.rrsets(apex).await;
            let soa = rrsets.iter().find(|rrset| rrset.rtype == Rtype::SOA);
            soa.is_some_and(|soa| soa.rdata[0].as_bytes() == expected[0].3.as_slice())
                && rrsets.iter().all(|rrset| rrset.origin == Origin::Transfer)
                && expected.iter().all(|(owner, rtype, ..)| {
                    rrsets
                        .iter()
                        .any(|rrset| &rrset.name == owner && rrset.rtype == *rtype)
                })
                && rrsets.iter().all(|rrset| {
                    expected
                        .iter()
                        .any(|(owner, rtype, ..)| &rrset.name == owner && rrset.rtype == *rtype)
                })
        })
        .await;
    }

    async fn to_primary(&self, apex: &str) -> ZoneFlipReport {
        let flip = ZoneFlip::Primary {
            soa: SoaDefaults::new(
                name("tenko1.corp.example.test"),
                name("hostmaster.corp.example.test"),
            ),
            ns: vec![name("tenko1.corp.example.test")],
        };
        self.zones
            .flip(&cx(), self.zone(apex).id, &flip)
            .await
            .expect("the flip to primary")
    }

    async fn audits(&self) -> Vec<AuditDraft> {
        let view = self.zones.view(None).await.expect("view");
        view.scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit")
        .into_iter()
        .map(|(_, record, _)| record.draft)
        .collect()
    }
}

fn count(report: &ZoneFlipReport, origin: Origin) -> u32 {
    report
        .origins
        .iter()
        .find(|item| item.origin == origin)
        .map_or(0, |item| item.rrsets)
}

/// An unsigned UPDATE of `zone` from `from` with the update records in wire form.
async fn update(path: &UpdatePath, zone: &str, from: &str, records: (u16, &[u8])) -> u16 {
    let mut message = Vec::new();
    write_request(
        &mut message,
        0x2136,
        &name(zone).to_wire(),
        (0, &[]),
        records,
    );
    let conn = Conn {
        client: SocketAddr::new(from.parse().expect("address"), 40_000),
        local: "192.0.2.53:53".parse().expect("local"),
        transport: QueryTransport::Udp,
    };
    let answer = path.answer(&message, &conn).await.expect("an answer");
    u16::from(wire::parse_header(&answer).expect("header").rcode)
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "the exit check in its order")]
async fn the_ad_zones_flip_take_updates_release_and_flip_back() {
    let lab = Lab::new().await;
    let fixture_serial = |report: &ZoneFlipReport| serial::newer(report.serial, FIXTURE_SERIAL);

    // The forward zones first, then the reverse zone, as the runbook orders them.
    let corp = lab.to_primary(CORP).await;
    assert_eq!(corp.kind, ZoneKind::Primary);
    assert!(
        fixture_serial(&corp),
        "the serial continues from the copy's: {}",
        corp.serial
    );
    // Sixty DHCP names with their A and DHCID records stay frozen; the controllers' records,
    // the locators and the static host become `ad`; the apex SOA and NS are the operator's.
    assert_eq!(
        (
            count(&corp, Origin::Transfer),
            count(&corp, Origin::Ad),
            count(&corp, Origin::Manual)
        ),
        (120, 17, 2)
    );
    let msdcs = lab.to_primary(MSDCS).await;
    assert_eq!(
        (
            count(&msdcs, Origin::Transfer),
            count(&msdcs, Origin::Ad),
            count(&msdcs, Origin::Manual)
        ),
        (0, 11, 2)
    );
    let reverse = lab.to_primary(REVERSE).await;
    // The PTR records of the sixty DHCP names stay frozen, those of the controllers and the
    // static host become `ad`.
    assert_eq!(
        (
            count(&reverse, Origin::Transfer),
            count(&reverse, Origin::Ad)
        ),
        (60, 3)
    );
    for (owner, rtype, origin) in [
        ("laptop-01.corp.example.test", Rtype::A, Origin::Transfer),
        ("laptop-01.corp.example.test", DHCID, Origin::Transfer),
        ("old-laptop-02.corp.example.test", DHCID, Origin::Transfer),
        ("dc1.corp.example.test", Rtype::A, Origin::Ad),
        ("_ldap._tcp.corp.example.test", Rtype::SRV, Origin::Ad),
        ("tenko1.corp.example.test", Rtype::A, Origin::Ad),
    ] {
        let rrset = lab.rrset(CORP, owner, rtype).await.expect(owner);
        assert_eq!(rrset.origin, origin, "{owner} {rtype}");
    }
    let soa = lab.rrset(CORP, CORP, Rtype::SOA).await.expect("SOA");
    let records = soa.records().expect("SOA data");
    let [RecordData::Soa { mname, serial, .. }] = records.as_slice() else {
        panic!("an SOA record");
    };
    assert_eq!(
        (mname.as_str(), *serial),
        ("tenko1.corp.example.test", corp.serial)
    );
    let flips: Vec<AuditDraft> = lab
        .audits()
        .await
        .into_iter()
        .filter(|draft| draft.action.as_str() == "dns.zone.flip")
        .collect();
    assert_eq!(flips.len(), 3);
    assert_eq!(
        flips[0]
            .details
            .context
            .get("rrsets.transfer")
            .map(String::as_str),
        Some("120")
    );

    // Updates from the controllers' list, unsigned, as under Home.
    let store = Arc::clone(&lab.store) as Arc<dyn Store>;
    let mut feed = store_feed::register(store).expect("feed");
    let served = catalog::initial(&mut feed).await.expect("catalog");
    tokio::spawn(catalog::follow(
        feed,
        served.clone(),
        lab.stop.child_token(),
    ));
    let directory = Arc::new(Directory::default());
    directory
        .load(&lab.zones, &mut HashMap::new())
        .await
        .expect("directory");
    let refusals = Arc::new(Refusals::default());
    let path = UpdatePath::new(
        served,
        directory,
        Arc::clone(&lab.zones),
        Arc::new(ProfileCell::new(UpdateProfile::Home)),
        Arc::clone(&refusals) as Arc<dyn TransferAudit>,
        lab.stop.child_token(),
    );
    // Netlogon registers `_ldap._tcp` again with one controller only.
    let mut srv = vec![0, 0, 0, 100, 1, 0x85];
    srv.extend_from_slice(&name("dc1.corp.example.test").to_wire());
    let owner = name("_ldap._tcp.corp.example.test").to_wire();
    let mut records = Vec::new();
    push_record(&mut records, &owner, Rtype::SRV.0, CLASS_ANY, 0, &[]);
    push_record(&mut records, &owner, Rtype::SRV.0, CLASS_IN, 600, &srv);
    assert_eq!(update(&path, CORP, "192.0.2.5", (2, &records)).await, 0);
    let locator = lab
        .rrset(CORP, "_ldap._tcp.corp.example.test", Rtype::SRV)
        .await
        .expect("SRV");
    assert_eq!((locator.origin, locator.rdata.len()), (Origin::Dynamic, 1));
    // Windows DHCP rewrites a frozen name: refused and audited.
    let mut records = Vec::new();
    push_record(
        &mut records,
        &name("laptop-01.corp.example.test").to_wire(),
        Rtype::A.0,
        CLASS_IN,
        1200,
        &[192, 0, 2, 250],
    );
    assert_eq!(
        update(&path, CORP, "192.0.2.6", (1, &records)).await,
        rcode::REFUSED
    );
    let refused = refusals.0.lock().expect("refusals").clone();
    assert!(
        refused
            .iter()
            .any(|draft| draft.action.as_str() == "dns.update.refuse"
                && draft.details.context.get("code").map(String::as_str)
                    == Some(codes::UPDATE_REFUSED)),
        "{refused:?}"
    );
    assert_eq!(
        lab.rrset(CORP, "laptop-01.corp.example.test", Rtype::A)
            .await
            .expect("A")
            .origin,
        Origin::Transfer
    );

    // `release`: the dry run lists the frozen names, then they become `manual`, or go.
    let listed = lab
        .zones
        .release(
            &cx(),
            lab.zone(REVERSE).id,
            ZoneRelease {
                delete: false,
                dry_run: true,
            },
        )
        .await
        .expect("dry run");
    assert_eq!(
        (listed.names.len(), listed.rrsets, listed.revision),
        (60, 60, None)
    );
    assert_eq!(
        count_origin(&lab.rrsets(REVERSE).await, Origin::Transfer),
        60
    );
    let released = lab
        .zones
        .release(&cx(), lab.zone(REVERSE).id, ZoneRelease::default())
        .await
        .expect("release");
    assert!(released.revision.is_some());
    let after = lab.rrsets(REVERSE).await;
    assert_eq!(
        (
            count_origin(&after, Origin::Transfer),
            count_origin(&after, Origin::Manual)
        ),
        (0, 62)
    );
    let deleted = lab
        .zones
        .release(
            &cx(),
            lab.zone(CORP).id,
            ZoneRelease {
                delete: true,
                dry_run: false,
            },
        )
        .await
        .expect("release with delete");
    assert_eq!((deleted.names.len(), deleted.rrsets), (60, 120));
    assert!(
        lab.rrset(CORP, "laptop-01.corp.example.test", Rtype::A)
            .await
            .is_none()
    );
    assert!(
        lab.audits()
            .await
            .iter()
            .any(|draft| draft.action.as_str() == "dns.zone.release")
    );

    // The refusals of the kinds.
    let again = lab
        .zones
        .flip(
            &cx(),
            lab.zone(CORP).id,
            &ZoneFlip::Primary {
                soa: SoaDefaults::new(
                    name("tenko1.corp.example.test"),
                    name("hostmaster.corp.example.test"),
                ),
                ns: vec![name("tenko1.corp.example.test")],
            },
        )
        .await
        .expect_err("a primary does not flip to primary");
    assert!(again.is(codes::ZONE_FLIP_NOT_SECONDARY), "{again:?}");

    // The reverse flip: a secondary again, and the next transfer brings the copy back, older
    // serial and all, every RRset `transfer`.
    let back = lab
        .zones
        .flip(
            &cx(),
            lab.zone(CORP).id,
            &ZoneFlip::Secondary {
                primaries: lab.source.primaries.clone(),
            },
        )
        .await
        .expect("the flip to secondary");
    assert_eq!(back.kind, ZoneKind::Secondary);
    lab.wait_for_copy(CORP).await;
    let locator = lab
        .rrset(CORP, "_ldap._tcp.corp.example.test", Rtype::SRV)
        .await
        .expect("SRV");
    assert_eq!((locator.origin, locator.rdata.len()), (Origin::Transfer, 2));
    let release = lab
        .zones
        .release(&cx(), lab.zone(CORP).id, ZoneRelease::default())
        .await
        .expect_err("a secondary releases nothing");
    assert!(release.is(codes::ZONE_FLIP_NOT_PRIMARY), "{release:?}");
}

fn count_origin(rrsets: &[RrSet], origin: Origin) -> usize {
    rrsets.iter().filter(|rrset| rrset.origin == origin).count()
}

/// A primary catalog zone.
fn catalog_zone() -> NewZone {
    NewZone {
        name: name("catalog.example.test"),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: Vec::new(),
        serial: SerialPolicy::default(),
        soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
        name_servers: vec![name("ns1.example.test")],
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        description: None,
        reverse_of: None,
        catalog: true,
    }
}

/// A catalog zone keeps its own rule: neither flipped nor released; a secondary zone that
/// holds no copy yet has nothing to keep.
#[tokio::test]
async fn a_catalog_zone_and_a_zone_without_a_copy_are_refused() {
    let zones =
        ZoneService::with_direct_jobs(Arc::new(MemStore::default()), None, ZoneConfig::default());
    let catalog = zones
        .create(&cx(), catalog_zone())
        .await
        .expect("catalog zone")
        .zone;
    let flip = zones
        .flip(
            &cx(),
            catalog.id,
            &ZoneFlip::Secondary {
                primaries: vec![PrimaryServer {
                    address: "192.0.2.5".parse().expect("address"),
                    port: 53,
                    key: None,
                    xot: false,
                    tls_name: None,
                }],
            },
        )
        .await
        .expect_err("refused");
    assert!(flip.is(codes::ZONE_FLIP_CATALOG), "{flip:?}");
    let release = zones
        .release(&cx(), catalog.id, ZoneRelease::default())
        .await
        .expect_err("refused");
    assert!(release.is(codes::ZONE_FLIP_CATALOG), "{release:?}");
    let empty = zones
        .create(
            &cx(),
            NewZone {
                name: name("copy.example.test"),
                kind: ZoneKind::Secondary,
                source: Some(SecondarySource {
                    primaries: vec![PrimaryServer {
                        address: "192.0.2.5".parse().expect("address"),
                        port: 53,
                        key: None,
                        xot: false,
                        tls_name: None,
                    }],
                }),
                name_servers: Vec::new(),
                catalog: false,
                ..catalog_zone()
            },
        )
        .await
        .expect("secondary zone")
        .zone;
    let flip = zones
        .flip(
            &cx(),
            empty.id,
            &ZoneFlip::Primary {
                soa: SoaDefaults::new(name("ns1.example.test"), name("hostmaster.example.test")),
                ns: vec![name("ns1.example.test")],
            },
        )
        .await
        .expect_err("refused");
    assert!(flip.is(codes::ZONE_INVALID), "{flip:?}");
}
