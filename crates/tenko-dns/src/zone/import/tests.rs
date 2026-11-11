//! The bounds of a zone file import: the records of a file, the RRsets of a zone, the
//! imports staged at once.

use std::{fmt::Write as _, sync::Arc};

use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{DnsName, ScopeName, SerialPolicy, SoaDefaults, ZoneKind},
};
use tenko_store::{MemStore, Store};
use tenko_vault::MemVault;

use super::*;
use crate::zone::{NewZone, ZoneConfig, zonefile::Dialect};

fn name(text: &str) -> DnsName {
    DnsName::new(text).expect("name")
}

fn cx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Dns)
}

fn service() -> Arc<ZoneService> {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    ZoneService::with_direct_jobs(
        store as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    )
}

async fn zone(service: &ZoneService) -> Zone {
    let apex = "example.test";
    service
        .create(
            &cx(),
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
                reverse_of: None,
                catalog: false,
            },
        )
        .await
        .expect("create")
        .zone
}

fn request(zone: &Zone, text: String) -> ImportRequest {
    ImportRequest {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        text,
        replace: false,
        dialect: Dialect::Rfc1035,
    }
}

/// A few lines of `$GENERATE` cannot become more than a million records: each directive
/// keeps its own bound (65,536), and the file's directives together stop at
/// `MAX_GENERATED`.
#[tokio::test]
async fn generated_records_of_a_file_are_bounded_together() {
    let service = service();
    let zone = zone(&service).await;
    let mut text = String::new();
    for directive in 0..16 {
        let _ = writeln!(text, "$GENERATE 0-65535 h$-{directive} A 192.0.2.1");
    }
    let error = service
        .preview_import(&cx(), &request(&zone, text))
        .await
        .expect_err("more than a million generated records");
    assert_eq!(
        error.coded().code,
        tenko_core::dns::codes::ZONE_FILE_INVALID
    );
    assert!(error.to_string().contains("1000000"), "{error}");
}

/// After an import a zone holds at most the bound of RRsets over all its scopes; a zone
/// with an SOA and an NS set has two.
#[tokio::test]
async fn an_import_past_the_zone_bound_is_refused() {
    let service = service();
    let zone = zone(&service).await;
    let view = service.view(None).await.expect("view");
    let report = |added| ImportReport {
        added,
        ..ImportReport::default()
    };
    let scope = ScopeName::DEFAULT;
    check_zone_bound(view.as_ref(), &zone, &scope, &report(1), None, 3)
        .await
        .expect("3 RRsets");
    let error = check_zone_bound(view.as_ref(), &zone, &scope, &report(2), None, 3)
        .await
        .expect_err("4 RRsets");
    assert!(error.to_string().contains("4 RRsets"), "{error}");
    // A replacing import keeps only what it says of the scope.
    check_zone_bound(view.as_ref(), &zone, &scope, &report(3), Some(0), 3)
        .await
        .expect("the scope is replaced");
}

/// At most `MAX_STAGED` imports hold their files at once, and one per zone; a further one
/// is refused with 429 before its file is read. An import whose job has ended, or whose
/// job is gone, no longer counts.
#[tokio::test]
async fn imports_beyond_the_staging_bound_are_refused() {
    let service = service();
    let zone = zone(&service).await;
    let other = Zone {
        id: ZoneId::generate(),
        ..zone.clone()
    };
    let stage = |zone: &Zone, job: Option<JobId>| {
        let id = Uuid::now_v7();
        service.staging.put(
            id,
            ImportRun {
                request: request(zone, String::new()),
                chunk: 1,
                journal: service.config.journal,
                max_generate: 1,
                state: None,
            },
        );
        if let Some(job) = job {
            service.staging.set_job(id, job);
        }
    };
    // One staged import of the zone: a second of it is refused.
    stage(&zone, None);
    let error = service
        .start_import(
            &cx(),
            request(
                &zone,
                "www A 192.0.2.1
"
                .to_owned(),
            ),
        )
        .await
        .expect_err("the zone is busy");
    assert_eq!(error.coded().code, IMPORT_BUSY);
    assert_eq!(error.coded().status, 429);
    // Two staged imports in all: any further one is refused.
    stage(&other, None);
    let third = Zone {
        id: ZoneId::generate(),
        ..zone.clone()
    };
    assert_eq!(
        service
            .start_import(&cx(), request(&third, String::new()))
            .await
            .expect_err("two are staged")
            .coded()
            .code,
        IMPORT_BUSY
    );
    // Staged imports whose jobs are gone (canceled, failed, ended) are let go.
    service.staging.take_all();
    stage(&zone, Some(JobId::generate()));
    stage(&other, Some(JobId::generate()));
    assert_eq!(service.staging.len(), 2);
    service
        .check_staging(third.id)
        .await
        .expect("the ended imports no longer count");
    assert_eq!(service.staging.len(), 0);
}
