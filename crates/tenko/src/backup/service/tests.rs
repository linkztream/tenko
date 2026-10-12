use std::sync::Arc;

use tenko_api::dto::backup::{BackupOutcome, BackupReason, BackupSettingsUpdate};
use tenko_core::{NodeId, RequestCtx, SystemComponent, Timestamp};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{
    ReadConsistency,
    raft::{RaftStore, RaftStoreConfig},
};
use tenko_vault::{KekProtection, KekProvider, KekRing, StoreVault, kek::LocalKek};
use zeroize::Zeroizing;

use super::*;
use crate::backup::keys::BackupKey;

struct Fixture {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    store: RaftStore,
    service: Arc<BackupService>,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("dir");
    let data_dir = dir.path().join("data");
    let mut config = RaftStoreConfig::new(data_dir.join("store"));
    config.fsync_probe_samples = 0;
    let store = RaftStore::open(config).await.expect("store");
    let kek: Arc<dyn KekProvider> = Arc::new(
        LocalKek::new(
            "mem-00000001",
            KekProtection::Memory,
            &Zeroizing::new([3; 32]),
        )
        .expect("kek"),
    );
    let ring = KekRing::from_generations([kek]).expect("ring");
    let shared: Arc<dyn Store> = Arc::new(store.clone());
    let vault = Arc::new(
        StoreVault::open(Arc::clone(&shared), ring)
            .await
            .expect("vault"),
    );
    let engine = JobEngine::new(shared, EngineConfig::default());
    let service = BackupService::new(
        store.clone(),
        vault,
        &engine,
        Config {
            node: NodeId(1),
            data_dir: data_dir.clone(),
            host_target: data_dir.join("backups"),
            tls: None,
            config_file: None,
            kdf: KdfParams {
                memory_kib: 19_456,
                passes: 1,
                lanes: 1,
            },
        },
    );
    Fixture {
        _dir: dir,
        data_dir,
        store,
        service,
    }
}

fn ctx() -> RequestCtx {
    RequestCtx::system(SystemComponent::Backup)
}

fn update(enabled: bool, recipient: Option<String>) -> BackupSettingsUpdate {
    BackupSettingsUpdate {
        enabled,
        interval_hours: 24,
        keep: 1,
        target_dir: None,
        recipient,
        include_config: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_are_validated_stored_and_audited() {
    let fixture = fixture().await;
    let status = fixture.service.status_view().await.expect("status");
    assert!(!status.settings.enabled);
    assert_eq!(status.settings.revision, None);
    assert_eq!(status.recent.len(), 0);
    assert!(status.settings.effective_target_dir.ends_with("backups"));

    let refused = fixture
        .service
        .store_settings(&ctx(), update(true, None), None)
        .await
        .expect_err("a schedule without a recipient");
    assert_eq!(refused.code, "backup.key.missing");
    for bad in [
        BackupSettingsUpdate {
            interval_hours: 0,
            ..update(false, None)
        },
        BackupSettingsUpdate {
            keep: 366,
            ..update(false, None)
        },
        BackupSettingsUpdate {
            target_dir: Some("relative/dir".to_owned()),
            ..update(false, None)
        },
    ] {
        let error = fixture
            .service
            .store_settings(&ctx(), bad, None)
            .await
            .expect_err("invalid");
        assert_eq!(error.code, "backup.settings.invalid");
    }
    let invalid = fixture
        .service
        .store_settings(&ctx(), update(false, Some("tkbr1:nope".to_owned())), None)
        .await
        .expect_err("recipient");
    assert_eq!(invalid.code, "backup.key.invalid");

    let key = BackupKey::generate().expect("key");
    let stored = fixture
        .service
        .store_settings(
            &ctx(),
            update(true, Some(key.recipient().to_string())),
            None,
        )
        .await
        .expect("stored");
    let revision = stored.revision.expect("revision");
    let stale = fixture
        .service
        .store_settings(
            &ctx(),
            update(false, None),
            Some(tenko_core::Revision(revision.0 - 1)),
        )
        .await
        .expect_err("stale");
    assert_eq!(stale.code, "sys.store.precondition_failed");
    let view = fixture
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view");
    let audited = view
        .scan_typed(
            &tenko_store::tables::AUDIT,
            tenko_store::KeyRange::all(),
            100,
            true,
        )
        .expect("audit")
        .into_iter()
        .any(|(_, record, _)| record.draft.action == actions::SETTINGS);
    assert!(audited);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_through_the_api_is_written_recorded_and_listed() {
    let fixture = fixture().await;
    let none = fixture
        .service
        .run(&ctx(), RunReason::Manual, None, None)
        .await
        .expect_err("no key");
    assert_eq!(none.code, "backup.key.missing");
    let weak = fixture
        .service
        .run(
            &ctx(),
            RunReason::Manual,
            Some(Zeroizing::new("short".to_owned())),
            None,
        )
        .await
        .expect_err("weak");
    assert_eq!(weak.code, "backup.passphrase.weak");

    let run = fixture
        .service
        .run(
            &ctx(),
            RunReason::Manual,
            Some(Zeroizing::new("a long backup passphrase".to_owned())),
            None,
        )
        .await
        .expect("backup");
    assert_eq!(run.outcome, BackupOutcome::Succeeded);
    assert_eq!(run.reason, BackupReason::Manual);
    assert_eq!(run.slots, ["passphrase"]);
    assert!(run.job.is_some());
    let file = fixture
        .data_dir
        .join("backups")
        .join(run.file.as_deref().expect("file"));
    assert!(file.is_file());

    let status = fixture.service.status_view().await.expect("status");
    let last = status.last_good.expect("last good");
    assert_eq!(last.id, run.id);
    assert_eq!(last.job, run.job);
    assert!(status.last_failed.is_none());
    assert!(status.age_seconds.is_some());
    let (summary, warnings) = fixture.service.summary_view().await;
    assert!(summary.expect("summary").last_good_at.is_some());
    assert_eq!(warnings.len(), 0, "{warnings:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_backup_is_recorded_and_warned_about() {
    let fixture = fixture().await;
    // The target directory is a file.
    let blocker = fixture.data_dir.join("not-a-dir");
    std::fs::write(&blocker, b"x").expect("file");
    let key = BackupKey::generate().expect("key");
    let mut settings = update(false, Some(key.recipient().to_string()));
    settings.target_dir = Some(blocker.display().to_string());
    fixture
        .service
        .store_settings(&ctx(), settings, None)
        .await
        .expect("settings");
    let error = fixture
        .service
        .run(&ctx(), RunReason::Manual, None, None)
        .await
        .expect_err("fails");
    assert_eq!(error.code, "backup.io");
    let status = fixture.service.status_view().await.expect("status");
    let failed = status.last_failed.expect("failed");
    assert_eq!(failed.outcome, BackupOutcome::Failed);
    assert_eq!(failed.error.expect("error").code, "backup.io");
    assert!(
        status
            .warnings
            .iter()
            .any(|warning| warning.code == "backup.failed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_schedule_writes_when_due_and_keeps_the_newest_files() {
    let fixture = fixture().await;
    let key = BackupKey::generate().expect("key");
    fixture
        .service
        .tick(1)
        .await
        .expect("nothing to do without settings");
    fixture
        .service
        .store_settings(
            &ctx(),
            update(true, Some(key.recipient().to_string())),
            None,
        )
        .await
        .expect("settings");
    let epoch = fixture
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view")
        .counter(&LEADER_EPOCH)
        .expect("epoch");
    fixture.service.tick(epoch).await.expect("tick");
    let status = fixture.service.status_view().await.expect("status");
    let first = status.last_good.expect("scheduled backup");
    assert_eq!(first.reason, BackupReason::Scheduled);
    assert_eq!(first.slots, ["recipient"]);
    assert!(status.next_due_at.expect("due") > Timestamp::now());
    fixture.service.tick(epoch).await.expect("tick");
    assert_eq!(
        fixture
            .service
            .status_view()
            .await
            .expect("status")
            .recent
            .len(),
        1,
        "not due again"
    );

    // A deposed leader's record is refused by the fence, and its file removed.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let stale = fixture
        .service
        .run(&ctx(), RunReason::Scheduled, None, Some(epoch + 1))
        .await;
    assert!(stale.is_err());
    assert_eq!(
        std::fs::read_dir(fixture.data_dir.join("backups"))
            .expect("dir")
            .count(),
        1
    );

    // The keep count (1) removes the older file after the next scheduled backup.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    fixture
        .service
        .run(&ctx(), RunReason::Manual, None, None)
        .await
        .expect("manual");
    let dir = fixture.data_dir.join("backups");
    assert_eq!(BackupService::prune(&dir, 1), 1);
    let left: Vec<_> = std::fs::read_dir(&dir)
        .expect("dir")
        .filter_map(Result::ok)
        .filter(|entry| create::is_backup_name(&entry.file_name().to_string_lossy()))
        .collect();
    assert_eq!(left.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_is_recorded_once_and_shown_until_the_next_backup() {
    let fixture = fixture().await;
    let notice = restore::Notice {
        restored_at: Timestamp::now(),
        backup_created_at: Timestamp::now(),
        file: "tenko-backup-20261011T080000Z-n1.tkbk".to_owned(),
        source_node: 2,
        source_voters: vec![1, 2, 3],
        revision: 41,
        tenko_version: "0.0.1".to_owned(),
    };
    std::fs::write(
        fixture.data_dir.join(restore::NOTICE_FILE),
        serde_json::to_vec(&notice).expect("json"),
    )
    .expect("notice");
    let record = fixture
        .service
        .record_restore()
        .await
        .expect("record")
        .expect("some");
    assert_eq!(record.source_node, 2);
    assert!(!fixture.data_dir.join(restore::NOTICE_FILE).exists());
    assert!(
        fixture
            .service
            .record_restore()
            .await
            .expect("again")
            .is_none()
    );
    let status = fixture.service.status_view().await.expect("status");
    assert_eq!(status.restored.expect("restored").revision.0, 41);
    assert!(
        status
            .warnings
            .iter()
            .any(|warning| warning.code == "backup.restored")
    );

    fixture
        .service
        .run(
            &ctx(),
            RunReason::Manual,
            Some(Zeroizing::new("a long backup passphrase".to_owned())),
            None,
        )
        .await
        .expect("backup");
    let status = fixture.service.status_view().await.expect("status");
    assert!(status.restored.is_none());
}

#[test]
fn standard_and_hardened_warn_after_seven_days() {
    let now = Timestamp::now();
    let old = Timestamp(now.0 - time::Duration::days(8));
    let recent = Timestamp(now.0 - time::Duration::days(2));
    let run = |at: Timestamp| BackupRun {
        reason: RunReason::Scheduled,
        node: 1,
        target_dir: "/srv/backup".to_owned(),
        file: Some("tenko-backup-x.tkbk".to_owned()),
        bytes: Some(1),
        revision: Some(1),
        slots: vec!["recipient".to_owned()],
        started_at: at,
        finished_at: at,
        by: "system".to_owned(),
        job: None,
        error: None,
    };
    let codes = |profile, setup, good: Option<&BackupRun>| {
        warnings(profile, setup, good, None, None, now)
            .into_iter()
            .map(|warning| warning.code)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        codes(Some(Profile::Standard), Some(old), None),
        ["backup.stale"]
    );
    assert_eq!(
        codes(Some(Profile::Hardened), None, Some(&run(old))),
        ["backup.stale"]
    );
    assert_eq!(codes(Some(Profile::Home), Some(old), None).len(), 0);
    assert_eq!(codes(Some(Profile::Standard), Some(recent), None).len(), 0);
    assert_eq!(
        codes(Some(Profile::Standard), Some(old), Some(&run(recent))).len(),
        0
    );
}

#[test]
fn a_failed_scheduled_backup_is_retried_after_an_hour() {
    let now = Timestamp::now();
    let mut failed = BackupRun {
        reason: RunReason::Scheduled,
        node: 1,
        target_dir: "/srv/backup".to_owned(),
        file: None,
        bytes: None,
        revision: None,
        slots: Vec::new(),
        started_at: now,
        finished_at: Timestamp(now.0 - time::Duration::minutes(10)),
        by: "system".to_owned(),
        job: None,
        error: Some(RunError {
            code: "backup.io".to_owned(),
            detail: "disk full".to_owned(),
        }),
    };
    let due = next_due(&[(Uuid::now_v7(), failed.clone())], 24, now);
    assert_eq!(due, add_hours(failed.finished_at, 1));
    failed.finished_at = Timestamp(now.0 - time::Duration::hours(2));
    assert_eq!(next_due(&[(Uuid::now_v7(), failed)], 24, now), now);
}
