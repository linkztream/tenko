//! M11 (IPAM-11): 10,000 rows preview under 2 s and apply under 5 s.
//!
//! The data is an address list of 10,000 rows, each a host with one address in
//! `2001:db8:1::/64` (documentation range), plus the network in a second file: 30,000
//! objects with their history, audit and index rows. The apply runs through the job engine
//! in chunks on `MemStore`, as in production.
//!
//! Measured on the reference workstation (Windows 11, 32 logical CPUs), release build
//! (`cargo test --release -p tenko-ipam --test import_perf -- --nocapture`), 2026-10-09:
//! see the comment on [`ten_thousand_rows_preview_and_apply_in_time`]. The debug build is
//! several times slower, so the thresholds are asserted only in release builds; debug
//! builds check correctness and print the timings.

use std::{
    fmt::Write as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::{AuthStrength, Principal, RequestCtx, SessionId, UserId};
use tenko_ipam::{
    IpamConfig, IpamService,
    import::{ApplyRequest, CredentialGate, ImportConfig, ImportService, Upload},
    jobs::register_steps,
    tables::{ADDRESS_IPS, HOST_NAMES},
};
use tenko_jobs::{EngineConfig, JobEngine, JobState};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadView, Store};

const ROWS: usize = 10_000;

fn uploads() -> Vec<Upload> {
    let mut rows = String::from("address,host,description\n");
    for n in 1..=ROWS {
        let _ = writeln!(rows, "2001:db8:1::{n:x},host{n:05},rack {}", n % 40);
    }
    vec![
        Upload {
            name: "prefixes.csv".to_owned(),
            bytes: b"prefix,description\n2001:db8:1::/64,Load test\n".to_vec(),
        },
        Upload {
            name: "hosts.csv".to_owned(),
            bytes: rows.into_bytes(),
        },
    ]
}

/// Measured 2026-10-09 on the reference workstation, release build, over five runs: upload
/// and preview 1.0 to 1.7 s (the IPAM plan of 20,001 commands, 67.7 MB of batch payload,
/// takes about 0.8 s of it), apply from the request to the succeeded job 2.5 to 3.6 s in
/// 14 chunks. Debug build: about 5 s and 13 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_thousand_rows_preview_and_apply_in_time() {
    let store = Arc::new(MemStore::default());
    let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
    let mut engine = JobEngine::new(Arc::clone(&dyn_store), EngineConfig::default());
    register_steps(&mut engine);
    let ipam =
        IpamService::new(dyn_store, Arc::new(engine.clone()), IpamConfig::default()).expect("ipam");
    let staging: PathBuf =
        std::env::temp_dir().join(format!("tenko-import-perf-{}", uuid::Uuid::now_v7()));
    let imports = ImportService::new(
        ipam,
        engine.clone(),
        None,
        ImportConfig {
            staging_dir: staging,
            ..ImportConfig::default()
        },
    )
    .expect("imports");
    let _runner = engine.start().expect("runner");
    let cx = RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Passkey,
    });

    let started = Instant::now();
    let view = imports.upload(&cx, uploads()).await.expect("upload");
    let preview = imports
        .preview(&cx, view.id, None, &CredentialGate::Allowed)
        .await
        .expect("preview");
    let preview_time = started.elapsed();
    assert!(
        preview.can_apply,
        "{:?} {:?}",
        preview.blockers, preview.plan_error
    );
    assert_eq!(preview.summary.rows.imported, ROWS + 1);

    let started = Instant::now();
    let job = imports
        .apply(
            &cx,
            view.id,
            &ApplyRequest::default(),
            &CredentialGate::Allowed,
        )
        .await
        .expect("apply");
    let job = loop {
        let job = engine.job(job).await.expect("job");
        if job.state.is_terminal() {
            break job;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let apply_time = started.elapsed();
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);

    let read: Arc<dyn ReadView> = store.read(ReadConsistency::Local).await.expect("view");
    let hosts = read
        .scan(HOST_NAMES.name(), KeyRange::all(), usize::MAX, false)
        .expect("scan")
        .len();
    let addresses = read
        .scan(ADDRESS_IPS.name(), KeyRange::all(), usize::MAX, false)
        .expect("scan")
        .len();
    assert_eq!((hosts, addresses), (ROWS, ROWS));
    println!(
        "M11: {ROWS} rows: upload and preview {preview_time:?}, apply {apply_time:?} in {} chunks",
        job.steps.len() - 1
    );
    if !cfg!(debug_assertions) {
        assert!(
            preview_time < Duration::from_secs(2),
            "preview took {preview_time:?}"
        );
        assert!(
            apply_time < Duration::from_secs(5),
            "apply took {apply_time:?}"
        );
    }
}
