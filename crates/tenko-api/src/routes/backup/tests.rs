//! Route tests of the backup area over a fake service, with the authentication service of
//! the secrets tests: the authorization by role, the step-up, `If-Match`, the status
//! fragment and the stub answers.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::Extension;
use futures::future::BoxFuture;
use serde_json::json;
use tenko_auth::settings::Profile;
use tenko_core::{CodedError, RequestCtx, Revision, Timestamp};
use uuid::Uuid;

use super::{
    BackupOutcome, BackupReason, BackupRunView, BackupService, BackupSettingsUpdate,
    BackupSettingsView, BackupStatusView, BackupSummaryView,
};
use crate::{
    dto::system::StatusWarning,
    routes::{
        auth::testkit::Credential,
        secrets::tests::{Harness, USER_PIN},
    },
};

/// A service that remembers what it was asked.
#[derive(Default)]
struct Fake {
    passphrases: Mutex<Vec<Option<String>>>,
    expects: Mutex<Vec<Option<Revision>>>,
}

fn settings(revision: Option<Revision>) -> BackupSettingsView {
    BackupSettingsView {
        enabled: false,
        interval_hours: 24,
        keep: 7,
        target_dir: None,
        recipient: None,
        include_config: true,
        effective_target_dir: "/srv/tenko/backups".to_owned(),
        revision,
    }
}

impl BackupService for Fake {
    fn status<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<BackupStatusView, CodedError>> {
        Box::pin(async {
            Ok(BackupStatusView {
                settings: settings(Some(Revision(12))),
                last_good: None,
                last_failed: None,
                age_seconds: None,
                next_due_at: None,
                running: false,
                recent: Vec::new(),
                restored: None,
                warnings: Vec::new(),
            })
        })
    }

    fn create<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        passphrase: Option<String>,
    ) -> BoxFuture<'a, Result<BackupRunView, CodedError>> {
        self.passphrases
            .lock()
            .expect("lock")
            .push(passphrase.clone());
        Box::pin(async move {
            Ok(BackupRunView {
                id: Uuid::nil(),
                outcome: BackupOutcome::Succeeded,
                reason: BackupReason::Manual,
                node: 1,
                target_dir: "/srv/tenko/backups".to_owned(),
                file: Some("tenko-backup-20261011T080000Z-n1.tkbk".to_owned()),
                bytes: Some(4_096),
                revision: Some(Revision(12)),
                slots: if passphrase.is_some() {
                    vec!["recipient".to_owned(), "passphrase".to_owned()]
                } else {
                    vec!["recipient".to_owned()]
                },
                started_at: Timestamp::now(),
                finished_at: Timestamp::now(),
                by: ctx.principal.subject(),
                job: None,
                error: None,
            })
        })
    }

    fn update_settings<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        update: BackupSettingsUpdate,
        expect: Option<Revision>,
    ) -> BoxFuture<'a, Result<BackupSettingsView, CodedError>> {
        self.expects.lock().expect("lock").push(expect);
        Box::pin(async move {
            Ok(BackupSettingsView {
                keep: update.keep,
                ..settings(Some(Revision(13)))
            })
        })
    }

    fn summary(&self) -> BoxFuture<'_, (Option<BackupSummaryView>, Vec<StatusWarning>)> {
        Box::pin(async {
            (
                Some(BackupSummaryView {
                    schedule_enabled: false,
                    last_good_at: None,
                    age_seconds: None,
                    last_failed_at: None,
                    restored_at: None,
                }),
                vec![StatusWarning {
                    code: "backup.stale".to_owned(),
                    detail: "there has been no backup since setup, more than 7 days ago".to_owned(),
                    params: std::collections::BTreeMap::new(),
                }],
            )
        })
    }
}

async fn harness() -> (Harness, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let service: Arc<dyn BackupService> = fake.clone();
    let mut harness = Harness::new(Profile::Home).await;
    harness.router = harness.router.clone().layer(Extension(service));
    (harness, fake)
}

fn update_body() -> serde_json::Value {
    json!({
        "enabled": false,
        "interval_hours": 24,
        "keep": 3,
        "target_dir": null,
        "recipient": null,
        "include_config": true
    })
}

#[tokio::test]
async fn an_administrator_reads_the_status_with_an_etag() {
    let (h, _) = harness().await;
    let reply = h
        .call("GET", "/system/backups", Credential::Cookie(&h.admin), None)
        .await;
    reply.assert_status(200);
    assert_eq!(reply.header("etag"), Some("\"12\""));
    assert_eq!(reply.body["settings"]["keep"], 7);
    assert_eq!(reply.body["running"], false);
    let status: BackupStatusView = reply.parse();
    assert_eq!(status.recent.len(), 0);
}

#[tokio::test]
async fn a_fresh_administrator_writes_a_backup_with_a_passphrase() {
    let (h, fake) = harness().await;
    let reply = h
        .call(
            "POST",
            "/system/backups",
            Credential::Cookie(&h.admin),
            Some(&json!({"passphrase": "a long backup passphrase"})),
        )
        .await;
    reply.assert_status(201);
    assert_eq!(reply.body["outcome"], "succeeded");
    assert_eq!(reply.body["slots"], json!(["recipient", "passphrase"]));
    assert!(
        reply.body["by"]
            .as_str()
            .expect("a subject")
            .starts_with("user:")
    );
    h.call(
        "POST",
        "/system/backups",
        Credential::Cookie(&h.admin),
        Some(&json!({})),
    )
    .await
    .assert_status(201);
    assert_eq!(
        *fake.passphrases.lock().expect("lock"),
        [Some("a long backup passphrase".to_owned()), None]
    );
}

#[tokio::test]
async fn a_viewer_reads_but_neither_writes_nor_changes_settings() {
    let (h, fake) = harness().await;
    h.create_user("vera", &["viewer"]).await;
    let viewer = h.login("vera", USER_PIN).await;
    h.call("GET", "/system/backups", Credential::Cookie(&viewer), None)
        .await
        .assert_status(200);
    h.call(
        "POST",
        "/system/backups",
        Credential::Cookie(&viewer),
        Some(&json!({})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    h.call(
        "PUT",
        "/system/backups/settings",
        Credential::Cookie(&viewer),
        Some(&update_body()),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    assert_eq!(fake.passphrases.lock().expect("lock").len(), 0);
}

#[tokio::test]
async fn an_old_session_needs_a_step_up() {
    let (h, fake) = harness().await;
    let stale = h.aged_admin_session(Duration::from_secs(600)).await;
    let refused = h
        .call(
            "POST",
            "/system/backups",
            Credential::Cookie(&stale),
            Some(&json!({})),
        )
        .await;
    refused.assert_problem(403, "auth.step_up_required");
    assert_eq!(refused.body["params"]["required"], "fresh");
    h.call(
        "PUT",
        "/system/backups/settings",
        Credential::Cookie(&stale),
        Some(&update_body()),
    )
    .await
    .assert_problem(403, "auth.step_up_required");
    assert_eq!(fake.passphrases.lock().expect("lock").len(), 0);
    assert_eq!(fake.expects.lock().expect("lock").len(), 0);
}

#[tokio::test]
async fn settings_pass_if_match_and_answer_with_the_new_etag() {
    let (h, fake) = harness().await;
    let reply = h
        .call_with(
            "PUT",
            "/system/backups/settings",
            Credential::Cookie(&h.admin),
            Some(&update_body()),
            &[("If-Match", "\"12\"")],
        )
        .await;
    reply.assert_status(200);
    assert_eq!(reply.header("etag"), Some("\"13\""));
    assert_eq!(reply.body["keep"], 3);
    h.call(
        "PUT",
        "/system/backups/settings",
        Credential::Cookie(&h.admin),
        Some(&update_body()),
    )
    .await
    .assert_status(200);
    assert_eq!(
        *fake.expects.lock().expect("lock"),
        [Some(Revision(12)), None]
    );
}

#[tokio::test]
async fn the_status_carries_the_backup_fragment_and_its_warnings() {
    let (h, _) = harness().await;
    let reply = h
        .call("GET", "/system/status", Credential::Cookie(&h.admin), None)
        .await;
    reply.assert_status(200);
    assert_eq!(reply.body["backup"]["schedule_enabled"], false);
    let codes: Vec<&str> = reply.body["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(|warning| warning["code"].as_str())
        .collect();
    assert!(codes.contains(&"backup.stale"), "{codes:?}");
}

#[tokio::test]
async fn without_a_service_every_endpoint_is_a_stub() {
    let h = Harness::new(Profile::Home).await;
    let admin = Credential::Cookie(&h.admin);
    h.call("GET", "/system/backups", admin, None)
        .await
        .assert_problem(501, "sys.not_implemented");
    h.call("POST", "/system/backups", admin, Some(&json!({})))
        .await
        .assert_problem(501, "sys.not_implemented");
    h.call(
        "PUT",
        "/system/backups/settings",
        admin,
        Some(&update_body()),
    )
    .await
    .assert_problem(501, "sys.not_implemented");
    let status = h.call("GET", "/system/status", admin, None).await;
    status.assert_status(200);
    assert!(status.body.get("backup").is_none());
}
