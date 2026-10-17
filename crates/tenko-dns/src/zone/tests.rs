//! Tests of the zone service over an in-memory store, with the jobs run in place.

use std::{fmt::Write as _, sync::Arc};

use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{
        AclEntry, DnsName, Origin, Rdata, RecordData, RrSet, Rtype, ScopeName, SerialPolicy,
        SoaDefaults, TsigAlgorithm, ZoneKind, codes, tables::RRSETS,
    },
    ipam::Stamp,
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, WriteBatch};
use tenko_vault::MemVault;

use super::{
    NewZone, ZoneConfig, ZoneService,
    acl::NewAcl,
    import::{ImportRequest, report_of},
    journal::{self, JournalLimits},
    keys::NewKey,
    records::{Change, Op},
};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn service_with(config: ZoneConfig) -> (Arc<ZoneService>, Arc<MemStore>) {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        config,
    );
    (service, store)
}

fn new_service() -> (Arc<ZoneService>, Arc<MemStore>) {
    service_with(ZoneConfig::default())
}

fn new_zone(apex: &str) -> NewZone {
    NewZone {
        name: name(apex),
        kind: ZoneKind::Primary,
        tenant: None,
        scopes: Vec::new(),
        serial: SerialPolicy::Counter,
        soa: SoaDefaults::new(
            name(&format!("ns1.{apex}")),
            name(&format!("hostmaster.{apex}")),
        ),
        name_servers: vec![name(&format!("ns1.{apex}"))],
        transfer: tenko_core::dns::TransferPolicy::default(),
        update: tenko_core::dns::UpdatePolicy::default(),
        dnssec: tenko_core::dns::DnssecPolicy::default(),
        source: None,
        description: None,
    }
}

fn a(owner: &str, addresses: &[&str]) -> Change {
    Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name(owner),
        rtype: Rtype::A,
        ttl: Some(300),
        records: addresses
            .iter()
            .map(|address| RecordData::A {
                address: address.parse().expect("address"),
            })
            .collect(),
        take_over: false,
    }
}

async fn summary(service: &ZoneService, zone: tenko_core::dns::ZoneId) -> super::ZoneSummary {
    let view = service.view(None).await.expect("view");
    let row = ZoneService::zone(view.as_ref(), zone).expect("zone");
    ZoneService::summary(view.as_ref(), &row.zone).expect("summary")
}

#[tokio::test]
async fn a_primary_zone_starts_with_its_soa_and_ns() {
    let (service, _) = new_service();
    let created = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create");
    let summary = summary(&service, created.zone.id).await;
    assert_eq!(summary.soa_serial, 1);
    assert_eq!(summary.rrsets, 2);
    assert_eq!(summary.origins, vec![(Origin::Manual, 2)]);

    let error = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect_err("a second zone of the name");
    assert!(error.is(codes::ZONE_EXISTS), "{error:?}");

    let mut secondary = new_zone("example.test");
    secondary.kind = ZoneKind::Secondary;
    secondary.name = name("other.test");
    let error = service
        .create(&cx(), secondary.clone())
        .await
        .expect_err("no source");
    assert!(error.is(codes::ZONE_INVALID), "{error:?}");
}

#[tokio::test]
async fn a_batch_writes_the_records_the_serial_and_a_journal_entry() {
    let (service, _) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let changes = vec![a("www.example.test", &["192.0.2.10", "192.0.2.11"])];

    let dry = service
        .change_records(&cx(), zone.id, &changes, true)
        .await
        .expect("dry run");
    assert!(dry.dry_run && dry.written.is_none());
    assert_eq!(dry.diff.len(), 1);
    assert_eq!(dry.serial(), Some(2));
    assert_eq!(
        summary(&service, zone.id).await.rrsets,
        2,
        "a dry run writes nothing"
    );

    let done = service
        .change_records(&cx(), zone.id, &changes, false)
        .await
        .expect("write");
    assert!(done.written.is_some());
    assert_eq!(done.serial(), Some(2));
    let after = summary(&service, zone.id).await;
    assert_eq!((after.soa_serial, after.rrsets), (2, 3));

    let view = service.view(None).await.expect("view");
    let entries =
        journal::list(view.as_ref(), zone.id, &ScopeName::DEFAULT, None, 10).expect("journal");
    assert_eq!(entries.len(), 1);
    assert_eq!((entries[0].from_serial, entries[0].to_serial), (1, 2));
    assert_eq!(entries[0].removed[0].rtype, Rtype::SOA);
    assert_eq!(entries[0].added[0].rtype, Rtype::SOA);
    assert_eq!(entries[0].added.len(), 3);

    // The same batch again changes nothing and moves no serial.
    let again = service
        .change_records(&cx(), zone.id, &changes, false)
        .await
        .expect("again");
    assert!(again.diff.is_empty() && again.written.is_none());
    assert_eq!(summary(&service, zone.id).await.soa_serial, 2);
}

#[tokio::test]
async fn the_rules_between_rrsets_hold() {
    let (service, _) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    service
        .change_records(
            &cx(),
            zone.id,
            &[a("www.example.test", &["192.0.2.10"])],
            false,
        )
        .await
        .expect("A");
    let cname = Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name("www.example.test"),
        rtype: Rtype::CNAME,
        ttl: None,
        records: vec![RecordData::Cname {
            target: name("web.example.test"),
        }],
        take_over: false,
    };
    let error = service
        .change_records(&cx(), zone.id, std::slice::from_ref(&cname), false)
        .await
        .expect_err("CNAME beside A");
    assert!(error.is(codes::RECORD_CONFLICT), "{error:?}");

    // Deleting the A set in the same batch makes room for the CNAME.
    let delete = Change {
        op: Op::Delete,
        records: Vec::new(),
        ..a("www.example.test", &[])
    };
    service
        .change_records(&cx(), zone.id, &[delete, cname], false)
        .await
        .expect("swap");

    let soa = Change {
        op: Op::Set,
        scope: ScopeName::DEFAULT,
        name: name("example.test"),
        rtype: Rtype::SOA,
        ttl: None,
        records: Vec::new(),
        take_over: false,
    };
    let error = service
        .change_records(&cx(), zone.id, &[soa], false)
        .await
        .expect_err("SOA");
    assert!(error.is(codes::RECORD_INVALID), "{error:?}");

    let outside = a("www.other.test", &["192.0.2.1"]);
    let error = service
        .change_records(&cx(), zone.id, &[outside], false)
        .await
        .expect_err("outside");
    assert!(error.is(codes::RECORD_INVALID), "{error:?}");

    let ns_delete = Change {
        op: Op::Delete,
        scope: ScopeName::DEFAULT,
        name: name("example.test"),
        rtype: Rtype::NS,
        ttl: None,
        records: Vec::new(),
        take_over: false,
    };
    let error = service
        .change_records(&cx(), zone.id, &[ns_delete], false)
        .await
        .expect_err("apex NS");
    assert!(error.is(codes::RECORD_INVALID), "{error:?}");
}

#[tokio::test]
async fn another_origin_needs_a_take_over() {
    let (service, store) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let ipam = RrSet {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: name("host.example.test"),
        rtype: Rtype::A,
        ttl: 600,
        rdata: vec![Rdata::from_data(&RecordData::A {
            address: "192.0.2.20".parse().expect("address"),
        })],
        origin: Origin::Ipam,
        key: None,
        updated: Stamp::new(cx().now, cx().principal),
    };
    let mut batch = WriteBatch::for_request(&cx());
    super::stage_put(&mut batch, None, &ipam).expect("stage");
    store.propose(batch).await.expect("ipam write");
    assert_eq!(
        summary(&service, zone.id).await.origins,
        vec![(Origin::Manual, 2), (Origin::Ipam, 1)]
    );

    let change = a("host.example.test", &["192.0.2.21"]);
    let error = service
        .change_records(&cx(), zone.id, std::slice::from_ref(&change), false)
        .await
        .expect_err("origin");
    assert!(error.is(codes::RECORD_ORIGIN), "{error:?}");
    assert_eq!(
        error.coded().params.get("origin").map(String::as_str),
        Some("ipam")
    );

    let take_over = Change {
        take_over: true,
        ..change
    };
    let done = service
        .change_records(&cx(), zone.id, &[take_over], false)
        .await
        .expect("take over");
    assert_eq!(
        done.diff[0].after.as_ref().map(|rrset| rrset.origin),
        Some(Origin::Manual)
    );
    assert_eq!(
        summary(&service, zone.id).await.origins,
        vec![(Origin::Manual, 3)]
    );
}

#[tokio::test]
async fn the_journal_stays_within_its_bound() {
    let (service, _) = service_with(ZoneConfig {
        journal: JournalLimits {
            entries: 5,
            days: 30,
        },
        ..ZoneConfig::default()
    });
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    for round in 0..40u8 {
        let address = format!("192.0.2.{}", round + 1);
        service
            .change_records(
                &cx(),
                zone.id,
                &[a("churn.example.test", &[&address])],
                false,
            )
            .await
            .expect("change");
    }
    let view = service.view(None).await.expect("view");
    let entries =
        journal::list(view.as_ref(), zone.id, &ScopeName::DEFAULT, None, 100).expect("journal");
    assert_eq!(entries.len(), 5);
    assert_eq!(
        journal::count(view.as_ref(), zone.id, &ScopeName::DEFAULT).expect("count"),
        5
    );
    assert_eq!(entries[0].to_serial, 41, "newest first");
    assert_eq!(entries[4].to_serial, 37);
}

const ZONE_FILE: &str = "$ORIGIN example.test.
$TTL 300
@ IN SOA ns1.example.test. hostmaster.example.test. 2026101705 3600 900 604800 300
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.254
www 600 IN A 192.0.2.10
www 600 IN A 192.0.2.11
mail IN MX 10 mx.example.test.
txt IN TXT \"hello world\" \"second\"
alias IN CNAME www
$GENERATE 1-3 host-$ IN A 198.51.100.$
chaos CH TXT \"not served\"
outside.other.test. IN A 192.0.2.99
";

#[tokio::test]
async fn an_import_previews_writes_and_exports_byte_stable() {
    let (service, _) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let request = ImportRequest {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        text: ZONE_FILE.to_owned(),
        replace: false,
    };
    let preview = service
        .preview_import(&cx(), &request)
        .await
        .expect("preview");
    assert!(preview.dry_run);
    assert_eq!(preview.added, 8, "{preview:?}");
    assert_eq!(preview.replaced, 1, "the apex NS");
    assert_eq!(preview.lost, 2);
    assert_eq!(preview.types.get(&Rtype::A), Some(&6));
    assert_eq!(preview.types.get(&Rtype::SOA), Some(&1));
    assert_eq!(
        summary(&service, zone.id).await.rrsets,
        2,
        "a preview writes nothing"
    );

    let (job, _) = service.start_import(&cx(), request).await.expect("import");
    let direct = service.direct_jobs().expect("direct jobs");
    let report = report_of(&direct.job(job).expect("job")).expect("report");
    assert!(!report.dry_run);
    assert_eq!(report.added, 8);
    assert_eq!(
        report.serial,
        Some(2_026_101_705),
        "the newer file serial is kept"
    );
    assert!(report.revision.is_some());

    let first = service
        .export(&cx(), zone.id, &ScopeName::DEFAULT)
        .await
        .expect("export");
    let expected = "$ORIGIN example.test.
$TTL 300
@ 300 IN SOA ns1.example.test. hostmaster.example.test. 2026101705 3600 900 604800 300
@ 300 IN NS ns1.example.test.
alias 300 IN CNAME www.example.test.
host-1 300 IN A 198.51.100.1
host-2 300 IN A 198.51.100.2
host-3 300 IN A 198.51.100.3
mail 300 IN MX 10 mx.example.test.
ns1 300 IN A 192.0.2.254
txt 300 IN TXT \"hello world\" \"second\"
www 600 IN A 192.0.2.10
www 600 IN A 192.0.2.11
";
    assert_eq!(first.text, expected);

    // The export imported into a fresh zone exports to the same bytes.
    let (other, _) = new_service();
    let zone2 = other
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let (job, _) = other
        .start_import(
            &cx(),
            ImportRequest {
                zone: zone2.id,
                scope: ScopeName::DEFAULT,
                text: first.text.clone(),
                replace: true,
            },
        )
        .await
        .expect("import the export");
    let report =
        report_of(&other.direct_jobs().expect("direct").job(job).expect("job")).expect("report");
    assert_eq!(report.lost, 0, "{report:?}");
    let second = other
        .export(&cx(), zone2.id, &ScopeName::DEFAULT)
        .await
        .expect("export");
    assert_eq!(second.text, first.text);
}

#[tokio::test]
async fn replace_removes_what_the_file_does_not_hold() {
    let (service, _) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    service
        .change_records(
            &cx(),
            zone.id,
            &[a("old.example.test", &["192.0.2.1"])],
            false,
        )
        .await
        .expect("old");
    let request = ImportRequest {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        text: "new 300 IN A 192.0.2.2\n".to_owned(),
        replace: true,
    };
    let preview = service
        .preview_import(&cx(), &request)
        .await
        .expect("preview");
    assert_eq!((preview.added, preview.removed), (1, 1), "{preview:?}");
    let (job, _) = service.start_import(&cx(), request).await.expect("import");
    let report = report_of(
        &service
            .direct_jobs()
            .expect("direct")
            .job(job)
            .expect("job"),
    )
    .expect("report");
    assert_eq!((report.added, report.removed), (1, 1));
    let file = service
        .export(&cx(), zone.id, &ScopeName::DEFAULT)
        .await
        .expect("export");
    assert!(file.text.contains("new 300 IN A 192.0.2.2"));
    assert!(!file.text.contains("old"));
    assert!(
        file.text.contains("@ 3600 IN NS ns1.example.test."),
        "the apex NS stays:\n{}",
        file.text
    );
    assert_eq!(
        file.serial, 3,
        "one serial step for the batch, one for the import"
    );
}

#[tokio::test]
async fn a_large_import_runs_in_chunks() {
    let (service, store) = service_with(ZoneConfig {
        import_chunk: 7,
        ..ZoneConfig::default()
    });
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let mut text = String::from("$ORIGIN example.test.\n$TTL 300\n");
    for n in 0..50 {
        let _ = writeln!(text, "h{n} IN A 192.0.2.{}", n % 250 + 1);
    }
    // A name listed again later is merged into what the import wrote.
    text.push_str("h3 IN A 192.0.2.200\n");
    let (job, preview) = service
        .start_import(
            &cx(),
            ImportRequest {
                zone: zone.id,
                scope: ScopeName::DEFAULT,
                text,
                replace: false,
            },
        )
        .await
        .expect("import");
    assert_eq!(
        preview.added, 51,
        "the preview counts the repeated name twice"
    );
    let job = service
        .direct_jobs()
        .expect("direct")
        .job(job)
        .expect("job");
    assert_eq!(job.steps.len(), 9, "8 chunks and the finish step");
    let report = report_of(&job).expect("report");
    assert_eq!(report.added, 50);
    let view = store.read(ReadConsistency::Local).await.expect("view");
    let h3 = view
        .get_typed(
            &RRSETS,
            &tenko_core::dns::RrSetKey {
                zone: zone.id,
                scope: ScopeName::DEFAULT,
                name: name("h3.example.test"),
                rtype: Rtype::A,
            },
        )
        .expect("read")
        .expect("h3");
    assert_eq!(h3.0.rdata.len(), 2);
    assert_eq!(
        journal::count(view.as_ref(), zone.id, &ScopeName::DEFAULT).expect("count"),
        0,
        "a multi-chunk import resets the journal"
    );
}

#[tokio::test]
async fn include_is_refused_with_its_line() {
    let (service, _) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let request = ImportRequest {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        text: "www IN A 192.0.2.1\n\n$INCLUDE other.zone\n".to_owned(),
        replace: false,
    };
    let error = service
        .preview_import(&cx(), &request)
        .await
        .expect_err("include");
    assert!(error.is(codes::ZONE_FILE_INVALID), "{error:?}");
    assert_eq!(
        error.coded().params.get("line").map(String::as_str),
        Some("3")
    );

    let request = ImportRequest {
        text: "www IN A 192.0.2.1\nbad IN A not-an-address\n".to_owned(),
        ..request
    };
    let error = service
        .preview_import(&cx(), &request)
        .await
        .expect_err("syntax");
    assert!(error.is(codes::ZONE_FILE_INVALID), "{error:?}");
    assert_eq!(
        error.coded().params.get("line").map(String::as_str),
        Some("2")
    );
}

#[tokio::test]
async fn deleting_a_zone_removes_its_records() {
    let (service, store) = service_with(ZoneConfig {
        import_chunk: 2,
        ..ZoneConfig::default()
    });
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    service
        .change_records(
            &cx(),
            zone.id,
            &[
                a("a.example.test", &["192.0.2.1"]),
                a("b.example.test", &["192.0.2.2"]),
                a("c.example.test", &["192.0.2.3"]),
            ],
            false,
        )
        .await
        .expect("records");
    service.delete(&cx(), zone.id, None).await.expect("delete");
    let view = store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(
        view.scan(RRSETS.name(), KeyRange::all(), 10, false)
            .expect("scan")
            .len(),
        0
    );
    let error = ZoneService::zone(view.as_ref(), zone.id).expect_err("gone");
    assert!(error.is(codes::ZONE_NOT_FOUND));
}

#[tokio::test]
async fn an_access_list_in_use_stays() {
    let (service, _) = new_service();
    let (acl, _) = service
        .create_acl(
            &cx(),
            NewAcl {
                name: "secondaries".to_owned(),
                entries: vec![AclEntry::Prefix {
                    prefix: "192.0.2.0/24".parse().expect("prefix"),
                    deny: false,
                }],
                description: None,
            },
        )
        .await
        .expect("acl");
    let mut zone = new_zone("example.test");
    zone.transfer.allow = vec![acl.id];
    let zone = service.create(&cx(), zone).await.expect("zone").zone;
    let error = service
        .delete_acl(&cx(), acl.id, None)
        .await
        .expect_err("in use");
    assert!(error.is(codes::ACL_IN_USE), "{error:?}");
    let view = service.view(None).await.expect("view");
    assert_eq!(
        ZoneService::acl(view.as_ref(), acl.id)
            .expect("acl")
            .used_by,
        vec!["zone:example.test".to_owned()]
    );
    drop(view);
    service
        .delete(&cx(), zone.id, None)
        .await
        .expect("zone gone");
    service
        .delete_acl(&cx(), acl.id, None)
        .await
        .expect("acl gone");

    let error = service
        .create(&cx(), {
            let mut zone = new_zone("example.test");
            zone.update.allowed = vec![acl.id];
            zone
        })
        .await
        .expect_err("unknown acl");
    assert!(error.is(codes::ZONE_INVALID), "{error:?}");
}

#[tokio::test]
async fn tsig_keys_keep_their_secret_in_the_vault() {
    let (service, _) = new_service();
    let created = service
        .create_key(
            &cx(),
            NewKey {
                name: name("transfer.example.test"),
                algorithm: TsigAlgorithm::HmacSha256,
                secret: None,
                description: None,
            },
        )
        .await
        .expect("key");
    let secret: Vec<u8> = domain::utils::base64::decode(created.secret.as_str()).expect("base64");
    assert_eq!(secret.len(), 32);
    let error = service
        .create_key(
            &cx(),
            NewKey {
                name: name("transfer.example.test"),
                algorithm: TsigAlgorithm::HmacSha256,
                secret: Some("c2VjcmV0c2VjcmV0c2VjcmV0".to_owned()),
                description: None,
            },
        )
        .await
        .expect_err("exists");
    assert!(error.is(codes::KEY_EXISTS), "{error:?}");
    let imported = service
        .create_key(
            &cx(),
            NewKey {
                name: name("update.example.test"),
                algorithm: TsigAlgorithm::HmacSha1,
                secret: Some("c2VjcmV0c2VjcmV0c2VjcmV0".to_owned()),
                description: Some("for the old server".to_owned()),
            },
        )
        .await
        .expect("import");
    assert_eq!(imported.secret.as_str(), "c2VjcmV0c2VjcmV0c2VjcmV0");
    let view = service.view(None).await.expect("view");
    assert_eq!(ZoneService::keys(view.as_ref()).expect("keys").len(), 2);
    drop(view);
    service
        .delete_key(&cx(), &name("update.example.test"))
        .await
        .expect("delete");
    let error = service
        .delete_key(&cx(), &name("update.example.test"))
        .await
        .expect_err("gone");
    assert!(error.is(codes::KEY_NOT_FOUND));
}

/// The import and export of a large zone file named by `TENKO_ZONE_FILE` (a file of the
/// `example.test` zone, such as `phase2-dns zonegen --records 1000000`), over the
/// in-memory store, with the times printed: `cargo test -p tenko-dns --release --lib
/// zone::tests::a_large_zone_file_round_trips -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "needs TENKO_ZONE_FILE; a measurement, not a check"]
async fn a_large_zone_file_round_trips() {
    let path = std::env::var("TENKO_ZONE_FILE").expect("TENKO_ZONE_FILE");
    let text = std::fs::read_to_string(&path).expect("zone file");
    let (service, _) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let started = std::time::Instant::now();
    let (job, preview) = service
        .start_import(
            &cx(),
            ImportRequest {
                zone: zone.id,
                scope: ScopeName::DEFAULT,
                text,
                replace: true,
            },
        )
        .await
        .expect("import");
    let imported = started.elapsed();
    let report = report_of(
        &service
            .direct_jobs()
            .expect("direct")
            .job(job)
            .expect("job"),
    )
    .expect("report");
    let started = std::time::Instant::now();
    let first = service
        .export(&cx(), zone.id, &ScopeName::DEFAULT)
        .await
        .expect("export");
    let exported = started.elapsed();
    println!(
        "import {imported:?} (preview added {}, report added {}, lost {}), export {exported:?} ({} RRsets, {} bytes)",
        preview.added,
        report.added,
        report.lost,
        first.rrsets,
        first.text.len()
    );
    let (other, _) = new_service();
    let zone2 = other
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    let started = std::time::Instant::now();
    other
        .start_import(
            &cx(),
            ImportRequest {
                zone: zone2.id,
                scope: ScopeName::DEFAULT,
                text: first.text.clone(),
                replace: true,
            },
        )
        .await
        .expect("import the export");
    let second = other
        .export(&cx(), zone2.id, &ScopeName::DEFAULT)
        .await
        .expect("export");
    println!("second round trip {:?}", started.elapsed());
    assert!(
        second.text == first.text,
        "the export imported again exports to the same bytes"
    );
}

#[tokio::test]
async fn importing_an_export_into_its_own_zone_changes_nothing() {
    let (service, _) = new_service();
    let zone = service
        .create(&cx(), new_zone("example.test"))
        .await
        .expect("create")
        .zone;
    service
        .change_records(
            &cx(),
            zone.id,
            &[
                a("www.example.test", &["192.0.2.10"]),
                a("old.example.test", &["192.0.2.1"]),
            ],
            false,
        )
        .await
        .expect("records");
    let first = service
        .export(&cx(), zone.id, &ScopeName::DEFAULT)
        .await
        .expect("export");
    for replace in [false, true] {
        let request = ImportRequest {
            zone: zone.id,
            scope: ScopeName::DEFAULT,
            text: first.text.clone(),
            replace,
        };
        let preview = service
            .preview_import(&cx(), &request)
            .await
            .expect("preview");
        assert_eq!(
            (preview.added, preview.replaced, preview.removed),
            (0, 0, 0),
            "{preview:?}"
        );
        let (job, _) = service.start_import(&cx(), request).await.expect("import");
        let report = report_of(
            &service
                .direct_jobs()
                .expect("direct")
                .job(job)
                .expect("job"),
        )
        .expect("report");
        assert_eq!(
            (report.added, report.replaced, report.removed),
            (0, 0, 0),
            "{report:?}"
        );
        assert_eq!(report.serial, Some(first.serial), "the serial stays");
        let again = service
            .export(&cx(), zone.id, &ScopeName::DEFAULT)
            .await
            .expect("export");
        assert_eq!(again.text, first.text);
    }
}
