//! The audit export: sinks (syslog, CEF, JSON lines), their status and a test record (IAM-18, TGL-21).
//!
//! Area: `audit_export`. Owner: WP3.3.
//! Requirements: IAM-18, TGL-21.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /settings/audit-export` | 200 `AuditExportView` with `ETag: "<revision>"` | 401, 403, 501 |
//! | `PUT /settings/audit-export` | 200 `AuditExportView` with the new `ETag` | 400 `audit.export.invalid`, 401, 403, 409 `audit.export.required` or `audit.export.conflict`, 501 |
//! | `POST /settings/audit-export/test` | 200 `AuditExportTestResult` | 400, 401, 403, 404 `audit.export.not_found`, 501 |
//! | `GET /audit/export` | 200 `AuditExportPage` | 400, 401, 403 |
//!
//! The sinks live in the store (`sys.audit_export_settings`) and the cursors in
//! `sys.audit_export_cursors`; both reach the `system` event topic. Reading the settings
//! and their status needs the global read permission on the audit log, the same check as
//! `GET /audit/verify` (`AUDIT_OBJECT`: for example an administrator, the auditor role or a
//! token with `audit:read`); changing them and sending a test needs
//! the update permission on the system. `GET /audit/export` reads records in sequence
//! order for `tenko audit export`, with the same permission as `GET /audit/verify`.
//!
//! The server binary provides the service as the request extension
//! `Arc<AuditExportAdmin>`; without it the settings routes answer 501.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tenko_auth::{
    audit_export::{
        admin::{AuditExportAdmin, AuditExportTest, AuditExportTestResult},
        model::AuditExportUpdate,
        status::AuditExportView,
    },
    authz::AUDIT_OBJECT,
};
use tenko_core::{
    Action, AuditSeq, Revision,
    audit::{AuditRecord, ChainHead},
};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, tables};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    auth::{ApiJson, if_match, with_etag},
    not_implemented,
    system::system_object,
};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails, codes},
    state::AppState,
};

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_audit_export, put_audit_export))
        .routes(routes!(test_audit_export))
        .routes(routes!(export_audit))
}

const PATH: &str = "/settings/audit-export";

/// The most records one `GET /audit/export` returns.
pub const MAX_EXPORT_PAGE: u32 = 5_000;

type Admin = Option<Extension<Arc<AuditExportAdmin>>>;

fn admin_or_stub(
    admin: Admin,
    method: &str,
    path: &str,
) -> Result<Arc<AuditExportAdmin>, ApiError> {
    admin
        .map(|Extension(admin)| admin)
        .ok_or_else(|| not_implemented(method, path))
}

fn view_response(view: AuditExportView) -> Response {
    let revision = Revision(view.revision);
    with_etag(Json(view).into_response(), revision)
}

/// Reads the sinks with the status of each, the TGL-21 policy and the warnings.
#[utoipa::path(
    get,
    path = "/settings/audit-export",
    tag = "audit_export",
    operation_id = "get_audit_export",
    summary = "Get the audit export sinks with their status",
    description = "The sinks in their order, each with its state (`disabled`, `pending`, `ok`, \
        `behind`, `failing`, `alarm`), the last record delivered and the lag behind the log; \
        `policy` says whether TGL-21 requires an export and whether the settings satisfy it; \
        `warnings` are those `/system/status` shows (`audit.export.failing`, \
        `audit.export.required`).",
    responses(
        (status = 200, description = "The settings and their status", body = AuditExportView,
            headers(("ETag" = String, description = "The revision of the settings, for `If-Match`"))),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "The server runs without the audit export", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_audit_export(
    State(state): State<AppState>,
    admin: Admin,
    Ctx(ctx): Ctx,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &AUDIT_OBJECT)?;
    let admin = admin_or_stub(admin, "GET", PATH)?;
    Ok(view_response(admin.view(ctx.now).await?))
}

/// Replaces the sinks. Sinks left out are removed with their cursors; a new sink exports
/// the log from record 1.
#[utoipa::path(
    put,
    path = "/settings/audit-export",
    tag = "audit_export",
    operation_id = "put_audit_export",
    summary = "Replace the audit export sinks",
    description = "The body is the complete list of sinks: a sink with the `id` of a stored \
        sink keeps its position, a sink without `id` is new and exports the log from record 1, \
        and a stored sink left out is removed. While TGL-21 requires an export (the Hardened \
        profile), at least one sink must stay enabled (409 `audit.export.required`). The \
        change is audited as `sys.audit_export.update`.",
    params(("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag`; a stale revision is refused with 409")),
    request_body = AuditExportUpdate,
    responses(
        (status = 200, description = "The new settings and their status", body = AuditExportView,
            headers(("ETag" = String, description = "The new revision"))),
        (status = 400, description = "A value is invalid (`audit.export.invalid` with one entry per field in `errors`), the body is malformed, or `If-Match` is malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "TGL-21 requires an enabled sink (`audit.export.required`), or `If-Match` is stale (`audit.export.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "The server runs without the audit export", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn put_audit_export(
    State(state): State<AppState>,
    admin: Admin,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    ApiJson(update): ApiJson<AuditExportUpdate>,
) -> Result<Response, ApiError> {
    state.authorize(&ctx.principal, Action::Update, &system_object())?;
    let admin = admin_or_stub(admin, "PUT", PATH)?;
    let expect = if_match(&headers)?.map(|revision| revision.0);
    Ok(view_response(admin.update(&ctx, update, expect).await?))
}

/// Sends a test message from the controller that serves the request.
#[utoipa::path(
    post,
    path = "/settings/audit-export/test",
    tag = "audit_export",
    operation_id = "test_audit_export",
    summary = "Send a test message to a sink",
    description = "Sends one test message (MSGID `test`, not part of the chain) to a stored \
        sink (`sink`) or to a sink as the form holds it before saving (`spec`), from the \
        controller that serves the request: a file sink writes into this controller's export \
        directory. A failed delivery answers 200 with `delivered: false` and the failure. \
        Audited as `sys.audit_export.test`.",
    request_body = AuditExportTest,
    responses(
        (status = 200, description = "The outcome of the attempt", body = AuditExportTestResult),
        (status = 400, description = "Neither or both of `sink` and `spec`, or an invalid `spec` (`audit.export.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No sink has this id (`audit.export.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "The server runs without the audit export", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn test_audit_export(
    State(state): State<AppState>,
    admin: Admin,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<AuditExportTest>,
) -> Result<Json<AuditExportTestResult>, ApiError> {
    state.authorize(&ctx.principal, Action::Update, &system_object())?;
    let admin = admin_or_stub(admin, "POST", "/settings/audit-export/test")?;
    Ok(Json(admin.test(&ctx, request).await?))
}

/// Query of `GET /audit/export`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditExportQuery {
    /// The first sequence number (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<u64>,
    /// Records per page, 1 to 5,000 (default 1,000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// A page of the audit log in sequence order, for an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditExportPage {
    /// The position before the first record: the record `from - 1` (sequence 0 and the
    /// zero hash for `from = 1`). An export starts with it as a checkpoint, so it verifies
    /// on its own.
    pub anchor: ChainHead,
    /// The records from `from` in sequence order.
    pub records: Vec<AuditRecord>,
    /// The `from` of the next page; null at the end of the log.
    pub next: Option<AuditSeq>,
    /// The newest record of the log.
    pub store_head: AuditSeq,
}

/// Reads records in sequence order from a sequence number.
#[utoipa::path(
    get,
    path = "/audit/export",
    tag = "audit_export",
    operation_id = "export_audit",
    summary = "Read the audit log in sequence order for an export",
    description = "Every record from `from` in sequence order with the anchor before it, for \
        `tenko audit export`. Needs the global read permission on the audit log, as `GET \
        /audit/verify`; a principal with scoped grants only is refused, because an export \
        is only verifiable whole.",
    params(AuditExportQuery),
    responses(
        (status = 200, description = "A page of records", body = AuditExportPage),
        (status = 400, description = "`from` or `limit` is out of range or malformed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Not authenticated", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Not allowed", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn export_audit(
    State(state): State<AppState>,
    Ctx(ctx): Ctx,
    query: Result<Query<AuditExportQuery>, QueryRejection>,
) -> Result<Json<AuditExportPage>, ApiError> {
    state.authorize(&ctx.principal, Action::Read, &AUDIT_OBJECT)?;
    let Query(query) = query
        .map_err(|rejection| ApiError::new(codes::INVALID_QUERY, 400, rejection.body_text()))?;
    let from = query.from.unwrap_or(1);
    let limit = query.limit.unwrap_or(1_000);
    if from == 0 || !(1..=MAX_EXPORT_PAGE).contains(&limit) {
        return Err(ApiError::new(
            codes::INVALID_QUERY,
            400,
            format!("`from` starts at 1 and `limit` is 1 to {MAX_EXPORT_PAGE}"),
        ));
    }
    let view = state.store.read(ReadConsistency::Local).await?;
    let page = tokio::task::spawn_blocking(move || {
        let store_head = tenko_auth::audit_export::status::store_head(view.as_ref())?;
        let anchor = match from - 1 {
            0 => ChainHead::default(),
            seq => view.get_typed(&tables::AUDIT, &AuditSeq(seq))?.map_or(
                ChainHead::default(),
                |(record, _)| ChainHead {
                    seq: record.seq,
                    hash: record.hash,
                },
            ),
        };
        let range = KeyRange::all().after(tables::AUDIT.key(&AuditSeq(from - 1)));
        let records: Vec<AuditRecord> = view
            .scan_typed(&tables::AUDIT, range, limit as usize, false)?
            .into_iter()
            .map(|(_, record, _)| record)
            .collect();
        let next = records
            .last()
            .filter(|last| last.seq < store_head)
            .map(|last| last.seq.next());
        Ok::<_, tenko_store::StoreError>(AuditExportPage {
            anchor,
            records,
            next,
            store_head,
        })
    })
    .await
    .map_err(|_| {
        ApiError::from_coded_error(tenko_core::CodedError::internal(
            "the audit read was interrupted",
        ))
    })??;
    Ok(Json(page))
}

/// How often [`follow_warnings`] reads the export's status.
pub const WARNING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Event kind of a change of the export's warnings on the `system` topic.
pub const WARNING_EVENT: &str = "audit.export.warning";

/// Keeps the export's warnings in `/system/status` of this controller current: every
/// [`WARNING_INTERVAL`] it reads the cursors that the exporting controller writes and sets
/// or clears the notices `audit.export.failing` and `audit.export.required`. A notice that
/// appears or goes is also a `system` event (`audit.export.warning` with `code` and
/// `active`). Runs on every controller, so the warning shows wherever the status is read.
pub fn follow_warnings(
    state: AppState,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    use tenko_auth::audit_export::error::{FAILING, REQUIRED};

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(WARNING_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut active: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return;
                    }
                    continue;
                }
                _ = tick.tick() => {}
            }
            let Ok(view) = state.store.read(ReadConsistency::Local).await else {
                continue;
            };
            let Ok(status) = tenko_auth::audit_export::status::read_view(
                view.as_ref(),
                tenko_core::Timestamp::now(),
            ) else {
                continue;
            };
            let now: std::collections::BTreeSet<String> =
                status.warnings.iter().map(|w| w.code.clone()).collect();
            for warning in status.warnings {
                state.set_notice(crate::dto::system::StatusWarning {
                    code: warning.code,
                    detail: warning.detail,
                    params: warning.params,
                });
            }
            for code in [FAILING, REQUIRED] {
                let is = now.contains(code);
                if !is {
                    state.clear_notice(code);
                }
                if is != active.contains(code) {
                    let mut event = crate::sse::EventData::new(crate::sse::Topic::System, None);
                    event.kind = Some(WARNING_EVENT.to_owned());
                    event.params.insert("code".to_owned(), code.to_owned());
                    event.params.insert("active".to_owned(), is.to_string());
                    state.events().publish_system(&event);
                    if is {
                        tracing::warn!(code, "audit export warning raised");
                    } else {
                        tracing::info!(code, "audit export warning cleared");
                    }
                }
            }
            active = now;
        }
    })
}

#[cfg(test)]
mod tests {
    //! Route tests of the audit export over the real authentication service on one
    //! `MemStore`, with an `AuditExportAdmin` whose file sinks write below a temporary
    //! directory. Nothing leaves the machine: network sinks are never connected, except a
    //! TCP sink to a loopback port with no listener.

    use std::{path::PathBuf, sync::Arc};

    use axum::Extension;
    use serde_json::{Value, json};
    use tenko_auth::{
        audit_export::{
            admin::AuditExportAdmin,
            model::CURSORS,
            sink::{Opener, Timeouts},
        },
        settings::Profile,
        testing::TestEnv,
    };
    use tenko_core::{Timestamp, audit::AuditDraft};
    use tenko_store::{ReadConsistency, ReadViewExt, Store};
    use uuid::Uuid;

    use super::super::auth::testkit::{Credential::*, Harness, Reply};

    const PIN: &str = "7391";
    const SETTINGS: &str = "/settings/audit-export";

    /// The installation with an administrator and, optionally, the export service.
    struct Lab {
        h: Harness,
        admin: String,
        dir: PathBuf,
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Lab {
        async fn new(with_service: bool) -> Self {
            let dir = std::env::temp_dir().join(format!("tenko-audit-export-{}", Uuid::now_v7()));
            std::fs::create_dir_all(&dir).expect("a temporary directory");
            let env = TestEnv::new().await;
            env.clock.set(Timestamp::now());
            let store: Arc<dyn Store> = env.store.clone();
            let opener = Opener {
                file_dir: Some(dir.clone()),
                vault: None,
                timeouts: Timeouts::default(),
            };
            let service = Arc::new(AuditExportAdmin::new(
                store,
                opener,
                "controller.example.test",
                "0.0.0-test",
            ));
            let h = Harness::wired(env, move |state| {
                let router = crate::api(state).0;
                if with_service {
                    router.layer(Extension(service))
                } else {
                    router
                }
            });
            let admin = h
                .env
                .setup(Profile::Home)
                .await
                .expect("setup succeeds")
                .secret
                .expose()
                .to_owned();
            Self { h, admin, dir }
        }

        async fn login_as(&self, name: &str, role: &str) -> String {
            self.h.create_user(&self.admin, name, PIN, &[role]).await;
            self.h.login(name, PIN).await
        }

        async fn put(&self, body: &Value, if_match: Option<&str>) -> Reply {
            let headers: Vec<(&str, &str)> =
                if_match.map(|v| ("If-Match", v)).into_iter().collect();
            self.h
                .call_with("PUT", SETTINGS, Cookie(&self.admin), Some(body), &headers)
                .await
        }

        async fn get(&self) -> Reply {
            self.h
                .call("GET", SETTINGS, Cookie(&self.admin), None)
                .await
        }

        async fn drafts(&self, action: &str) -> Vec<AuditDraft> {
            self.h
                .audit()
                .await
                .into_iter()
                .filter(|draft| draft.action.as_str() == action)
                .collect()
        }

        async fn has_cursor(&self, id: &str) -> bool {
            let view = self
                .h
                .env
                .store
                .read(ReadConsistency::Local)
                .await
                .expect("a view");
            view.get_typed(&CURSORS, &id.parse::<Uuid>().expect("a sink id"))
                .expect("the cursor table")
                .is_some()
        }
    }

    fn syslog_sink() -> Value {
        json!({
            "name": "siem",
            "target": { "kind": "syslog", "transport": "tls", "host": "siem.example.test" }
        })
    }

    fn file_sink() -> Value {
        json!({
            "name": "local file",
            "format": "json",
            "target": { "kind": "file", "file": "audit.jsonl" }
        })
    }

    fn errors_of(reply: &Reply) -> Vec<(String, String)> {
        reply.body["errors"]
            .as_array()
            .expect("errors")
            .iter()
            .map(|e| {
                (
                    e["field"].as_str().expect("a field").to_owned(),
                    e["code"].as_str().expect("a code").to_owned(),
                )
            })
            .collect()
    }

    /// A loopback port with no listener.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        listener.local_addr().expect("an address").port()
    }

    #[tokio::test]
    async fn without_the_service_the_settings_answer_not_implemented() {
        let lab = Lab::new(false).await;
        let reply = lab.get().await;
        reply.assert_problem(501, "sys.not_implemented");
        assert_eq!(
            reply.body["params"]["path"],
            "/api/v1/settings/audit-export"
        );
        lab.put(&json!({ "sinks": [] }), None)
            .await
            .assert_problem(501, "sys.not_implemented");
        lab.h
            .call(
                "POST",
                "/settings/audit-export/test",
                Cookie(&lab.admin),
                Some(&json!({ "spec": file_sink() })),
            )
            .await
            .assert_problem(501, "sys.not_implemented");
        // The export of records does not need the service.
        lab.h
            .call("GET", "/audit/export", Cookie(&lab.admin), None)
            .await
            .assert_status(200);
    }

    #[tokio::test]
    async fn an_administrator_reads_the_empty_settings() {
        let lab = Lab::new(true).await;
        let reply = lab.get().await;
        reply.assert_status(200);
        assert_eq!(reply.header("etag"), Some("\"0\""));
        let body = &reply.body;
        assert_eq!(body["revision"], 0);
        assert_eq!(body["sinks"], json!([]));
        assert_eq!(body["alert_after_secs"], 300);
        assert_eq!(body["policy"]["audit_export"], "local");
        assert_eq!(body["policy"]["required"], false);
        assert_eq!(body["policy"]["satisfied"], true);
        assert_eq!(body["warnings"], json!([]));
        assert!(body["store_head"].as_u64().expect("a head") >= 1);
    }

    #[tokio::test]
    async fn sinks_are_replaced_audited_conflicting_and_removed() {
        let lab = Lab::new(true).await;
        let put = lab
            .put(
                &json!({ "sinks": [syslog_sink(), file_sink()] }),
                Some("\"0\""),
            )
            .await;
        put.assert_status(200);
        let revision = put.body["revision"].as_u64().expect("a revision");
        assert!(revision > 0);
        let etag = format!("\"{revision}\"");
        assert_eq!(put.header("etag"), Some(etag.as_str()));
        let sinks = put.body["sinks"].as_array().expect("sinks");
        assert_eq!(sinks.len(), 2);
        assert_eq!(sinks[0]["name"], "siem");
        assert_eq!(sinks[0]["enabled"], true);
        assert_eq!(sinks[0]["format"], "rfc5424");
        assert_eq!(sinks[0]["target"]["host"], "siem.example.test");
        assert_eq!(sinks[1]["name"], "local file");
        assert_eq!(sinks[1]["target"]["file"], "audit.jsonl");
        let ids: Vec<String> = sinks
            .iter()
            .map(|sink| sink["id"].as_str().expect("an id").to_owned())
            .collect();
        for id in &ids {
            id.parse::<Uuid>().expect("an assigned id");
            assert!(lab.has_cursor(id).await, "cursor of {id}");
        }
        let updates = lab.drafts("sys.audit_export.update").await;
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].outcome, tenko_core::audit::AuditOutcome::Success);
        let fields: Vec<&str> = updates[0]
            .details
            .changes
            .iter()
            .map(|change| change.field.as_str())
            .collect();
        assert_eq!(fields.len(), 2, "{fields:?}");
        for id in &ids {
            assert!(
                fields.contains(&format!("sink:{id}").as_str()),
                "{fields:?}"
            );
        }
        assert!(updates[0].details.changes.iter().all(|c| c.old.is_none()));
        assert!(updates[0].details.changes.iter().any(|c| {
            c.new
                .as_deref()
                .is_some_and(|n| n.contains("siem.example.test"))
        }));

        // The view reads back the same, with the new ETag.
        let read = lab.get().await;
        assert_eq!(read.header("etag"), Some(etag.as_str()));
        assert_eq!(read.body["sinks"][0]["id"], ids[0].as_str());

        // A stale If-Match is a conflict and changes nothing.
        let stale = lab.put(&json!({ "sinks": [] }), Some("\"0\"")).await;
        stale.assert_problem(409, "audit.export.conflict");
        assert_eq!(stale.body["params"]["expected"], "0");
        assert_eq!(stale.body["params"]["current"], revision.to_string());
        assert_eq!(
            lab.get().await.body["sinks"]
                .as_array()
                .expect("sinks")
                .len(),
            2
        );
        // A malformed If-Match is a bad request.
        lab.put(&json!({ "sinks": [] }), Some("nonsense"))
            .await
            .assert_status(400);

        // Keeping the first sink by id and leaving the second out removes its cursor.
        let mut kept = syslog_sink();
        kept["id"] = json!(ids[0]);
        let dropped = lab.put(&json!({ "sinks": [kept] }), Some(&etag)).await;
        dropped.assert_status(200);
        assert!(dropped.body["revision"].as_u64().expect("a revision") > revision);
        assert_eq!(dropped.body["sinks"].as_array().expect("sinks").len(), 1);
        assert_eq!(dropped.body["sinks"][0]["id"], ids[0].as_str());
        assert!(lab.has_cursor(&ids[0]).await);
        assert!(!lab.has_cursor(&ids[1]).await);
        let updates = lab.drafts("sys.audit_export.update").await;
        assert_eq!(updates.len(), 2);
        let change = &updates[1].details.changes;
        assert_eq!(change.len(), 1, "{change:?}");
        assert_eq!(change[0].field, format!("sink:{}", ids[1]));
        assert!(change[0].old.is_some() && change[0].new.is_none());
    }

    #[tokio::test]
    async fn invalid_sinks_are_refused_with_one_error_per_field() {
        let lab = Lab::new(true).await;
        let body = json!({ "sinks": [
            { "name": "  ", "target": { "kind": "file", "file": "ok.jsonl" } },
            { "name": "two", "target": { "kind": "file", "file": "../x" } },
            { "name": "three", "target": {
                "kind": "syslog", "transport": "tcp", "host": "siem.example.test", "port": 0 } },
        ] });
        let reply = lab.put(&body, None).await;
        reply.assert_problem(400, "audit.export.invalid");
        assert_eq!(
            errors_of(&reply),
            [
                ("sinks[0].name".to_owned(), "audit.export.name".to_owned()),
                (
                    "sinks[1].target.file".to_owned(),
                    "audit.export.file".to_owned()
                ),
                (
                    "sinks[2].target.port".to_owned(),
                    "audit.export.port".to_owned()
                ),
            ]
        );
        // An id that no stored sink has is refused: clients cannot pick ids.
        let mut unknown = file_sink();
        unknown["id"] = json!(Uuid::now_v7());
        let reply = lab.put(&json!({ "sinks": [unknown] }), None).await;
        reply.assert_problem(400, "audit.export.invalid");
        assert_eq!(
            errors_of(&reply),
            [(
                "sinks[0].id".to_owned(),
                "audit.export.unknown_sink".to_owned()
            )]
        );
        // A malformed body is a bad request too.
        lab.put(&json!({ "sinks": "none" }), None)
            .await
            .assert_status(400);
        // Nothing was stored or audited.
        assert_eq!(lab.get().await.body["revision"], 0);
        assert_eq!(lab.drafts("sys.audit_export.update").await.len(), 0);
    }

    #[tokio::test]
    async fn a_required_export_needs_an_enabled_sink() {
        let lab = Lab::new(true).await;
        // Switching to a required export while no sink is enabled is refused (TGL-21): the
        // policy stays the profile's and nothing is warned about.
        let refused = lab
            .h
            .call(
                "PATCH",
                "/settings/security",
                Cookie(&lab.admin),
                Some(&json!({ "audit_export": "required" })),
            )
            .await;
        refused.assert_problem(409, "audit.export.required");
        let view = lab.get().await;
        assert_eq!(view.body["policy"]["audit_export"], "local");
        assert_eq!(view.body["policy"]["required"], false);
        assert_eq!(view.body["policy"]["satisfied"], true);
        assert_eq!(view.body["warnings"], json!([]));

        // With an enabled sink the switch passes and the policy is satisfied.
        lab.put(&json!({ "sinks": [file_sink()] }), None)
            .await
            .assert_status(200);
        let toggle = lab
            .h
            .call(
                "PATCH",
                "/settings/security",
                Cookie(&lab.admin),
                Some(&json!({ "audit_export": "required" })),
            )
            .await;
        toggle.assert_status(200);
        let view = lab.get().await;
        assert_eq!(view.body["policy"]["audit_export"], "required");
        assert_eq!(view.body["policy"]["required"], true);
        assert_eq!(view.body["policy"]["satisfied"], true);
        assert_eq!(view.body["warnings"], json!([]));
        let revision = view.body["revision"].clone();

        // No sink, and only a disabled one, are both refused and audited as failed.
        lab.put(&json!({ "sinks": [] }), None)
            .await
            .assert_problem(409, "audit.export.required");
        let mut disabled = file_sink();
        disabled["enabled"] = json!(false);
        lab.put(&json!({ "sinks": [disabled] }), None)
            .await
            .assert_problem(409, "audit.export.required");
        let updates = lab.drafts("sys.audit_export.update").await;
        let failed = updates
            .iter()
            .filter(|draft| {
                draft.outcome
                    == tenko_core::audit::AuditOutcome::Failed {
                        code: "audit.export.required".into(),
                    }
            })
            .count();
        assert_eq!(failed, 2);
        assert_eq!(lab.get().await.body["revision"], revision);

        // Removing the sink with a fresh ETag is refused as well, and the sink stays.
        let etag = view.header("etag").expect("an etag").to_owned();
        lab.put(&json!({ "sinks": [] }), Some(&etag))
            .await
            .assert_problem(409, "audit.export.required");
        assert_eq!(
            lab.get().await.body["sinks"]
                .as_array()
                .expect("sinks")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn the_test_message_reaches_a_file_and_reports_a_refused_connection() {
        let lab = Lab::new(true).await;
        let test = |body: Value| {
            let lab = &lab;
            async move {
                lab.h
                    .call(
                        "POST",
                        "/settings/audit-export/test",
                        Cookie(&lab.admin),
                        Some(&body),
                    )
                    .await
            }
        };

        let delivered = test(json!({ "spec": file_sink() })).await;
        delivered.assert_status(200);
        assert_eq!(delivered.body["delivered"], true);
        assert!(delivered.body.get("error").is_none(), "{}", delivered.body);
        assert!(delivered.body["elapsed_ms"].is_u64());
        let written = std::fs::read_to_string(lab.dir.join("audit.jsonl")).expect("the file");
        assert_eq!(written.lines().count(), 1, "{written}");
        assert!(written.contains("test"), "{written}");

        // A stored sink by id.
        let put = lab.put(&json!({ "sinks": [file_sink()] }), None).await;
        let id = put.body["sinks"][0]["id"]
            .as_str()
            .expect("an id")
            .to_owned();
        let stored = test(json!({ "sink": id })).await;
        stored.assert_status(200);
        assert_eq!(stored.body["delivered"], true);
        let written = std::fs::read_to_string(lab.dir.join("audit.jsonl")).expect("the file");
        assert_eq!(written.lines().count(), 2, "{written}");

        // Unknown id, neither field, both fields, invalid spec.
        let unknown = Uuid::now_v7();
        let missing = test(json!({ "sink": unknown })).await;
        missing.assert_problem(404, "audit.export.not_found");
        assert_eq!(missing.body["params"]["sink"], unknown.to_string());
        let neither = test(json!({})).await;
        neither.assert_problem(400, "audit.export.invalid");
        assert_eq!(errors_of(&neither)[0].0, "sink");
        test(json!({ "sink": id, "spec": file_sink() }))
            .await
            .assert_problem(400, "audit.export.invalid");
        let mut bad = file_sink();
        bad["target"]["file"] = json!("../x");
        let invalid = test(json!({ "spec": bad })).await;
        invalid.assert_problem(400, "audit.export.invalid");
        assert_eq!(errors_of(&invalid)[0].0, "spec.target.file");

        // A TCP sink to a loopback port without a listener: 200 with the failure.
        let refused = test(json!({ "spec": {
            "name": "loopback",
            "target": { "kind": "syslog", "transport": "tcp", "host": "127.0.0.1",
                "port": closed_port() }
        } }))
        .await;
        refused.assert_status(200);
        assert_eq!(refused.body["delivered"], false);
        assert_eq!(refused.body["error"]["code"], "audit.export.connect");
        assert_ne!(refused.body["error"]["detail"], "");

        // Every attempt that reached the sink is audited with its outcome; the refusals
        // of the request itself are not.
        let tests = lab.drafts("sys.audit_export.test").await;
        assert_eq!(tests.len(), 3, "{tests:?}");
        assert_eq!(tests[0].outcome, tenko_core::audit::AuditOutcome::Success);
        assert_eq!(tests[0].details.context["sink_name"], "local file");
        assert!(!tests[0].details.context.contains_key("sink"));
        assert_eq!(tests[1].outcome, tenko_core::audit::AuditOutcome::Success);
        assert_eq!(tests[1].details.context["sink"], id);
        assert_eq!(
            tests[2].outcome,
            tenko_core::audit::AuditOutcome::Failed {
                code: "audit.export.connect".into()
            }
        );
        assert!(tests[2].details.context["target"].contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn viewers_and_auditors_are_limited() {
        let lab = Lab::new(true).await;
        let viewer = lab.login_as("vera", "viewer").await;
        let auditor = lab.login_as("alma", "auditor").await;
        let test_path = "/settings/audit-export/test";
        let sink = json!({ "spec": file_sink() });
        let sinks = json!({ "sinks": [file_sink()] });

        // The viewer role reads the system object, which includes the audit log in this
        // build, so its reads are not pinned here; changing and testing are refused.
        for (method, path, body) in [
            ("PUT", SETTINGS, Some(&sinks)),
            ("POST", test_path, Some(&sink)),
        ] {
            lab.h
                .call(method, path, Cookie(&viewer), body)
                .await
                .assert_problem(403, "auth.forbidden");
        }
        for (method, path, body) in [
            ("GET", SETTINGS, None),
            ("PUT", SETTINGS, Some(&sinks)),
            ("POST", test_path, Some(&sink)),
            ("GET", "/audit/export", None),
        ] {
            lab.h
                .call(method, path, Anonymous, body)
                .await
                .assert_problem(401, "auth.unauthenticated");
        }

        let read = lab.h.call("GET", SETTINGS, Cookie(&auditor), None).await;
        read.assert_status(200);
        assert_eq!(read.body["revision"], 0);
        lab.h
            .call("GET", "/audit/export", Cookie(&auditor), None)
            .await
            .assert_status(200);
        lab.h
            .call("PUT", SETTINGS, Cookie(&auditor), Some(&sinks))
            .await
            .assert_problem(403, "auth.forbidden");
        lab.h
            .call("POST", test_path, Cookie(&auditor), Some(&sink))
            .await
            .assert_problem(403, "auth.forbidden");
        assert_eq!(lab.get().await.body["revision"], 0);
        assert!(!lab.dir.join("audit.jsonl").exists());
        assert_eq!(lab.drafts("sys.audit_export.test").await.len(), 0);
    }

    #[tokio::test]
    async fn a_token_with_the_audit_read_scope_reads_but_cannot_change() {
        let lab = Lab::new(true).await;
        let created = lab
            .h
            .call(
                "POST",
                "/auth/tokens",
                Cookie(&lab.admin),
                Some(&json!({ "name": "siem reader", "scopes": ["audit:read"] })),
            )
            .await;
        created.assert_status(201);
        let token = created.body["token"].as_str().expect("a token").to_owned();
        lab.h
            .call("GET", SETTINGS, Bearer(&token), None)
            .await
            .assert_status(200);
        lab.h
            .call("GET", "/audit/export", Bearer(&token), None)
            .await
            .assert_status(200);
        lab.h
            .call(
                "PUT",
                SETTINGS,
                Bearer(&token),
                Some(&json!({ "sinks": [file_sink()] })),
            )
            .await
            .assert_problem(403, "auth.forbidden");
        lab.h
            .call(
                "POST",
                "/settings/audit-export/test",
                Bearer(&token),
                Some(&json!({ "spec": file_sink() })),
            )
            .await
            .assert_problem(403, "auth.forbidden");
    }

    async fn export(lab: &Lab, query: &str) -> Reply {
        lab.h
            .call(
                "GET",
                &format!("/audit/export{query}"),
                Cookie(&lab.admin),
                None,
            )
            .await
    }

    #[tokio::test]
    async fn the_audit_export_pages_records_with_their_anchor() {
        let lab = Lab::new(true).await;
        // A few more records on top of the setup's.
        lab.login_as("vera", "viewer").await;
        lab.login_as("oscar", "operator").await;

        let first = export(&lab, "?from=1&limit=2").await;
        first.assert_status(200);
        let head = first.body["store_head"].as_u64().expect("a head");
        assert!(head >= 4, "head {head}");
        let records = first.body["records"].as_array().expect("records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["seq"], 1);
        assert_eq!(records[1]["seq"], 2);
        assert_eq!(first.body["anchor"]["seq"], 0);
        assert_eq!(first.body["anchor"]["hash"], "0".repeat(64));
        assert_eq!(first.body["next"], 3);
        // The records chain onto each other.
        assert_eq!(records[1]["prev"], records[0]["hash"]);

        // The default is from 1.
        let default = export(&lab, "?limit=1").await;
        assert_eq!(default.body["records"][0]["seq"], 1);

        // The anchor of from=2 is record 1.
        let second = export(&lab, "?from=2&limit=1").await;
        second.assert_status(200);
        assert_eq!(second.body["anchor"]["seq"], 1);
        assert_eq!(second.body["anchor"]["hash"], records[0]["hash"]);
        assert_eq!(second.body["records"][0]["seq"], 2);
        assert_eq!(second.body["records"][0]["hash"], records[1]["hash"]);
        assert_eq!(second.body["next"], 3);

        // The last page has no next; past the end there are no records.
        let all = export(&lab, "").await;
        all.assert_status(200);
        assert_eq!(
            all.body["records"].as_array().expect("records").len() as u64,
            head
        );
        assert_eq!(all.body["next"], Value::Null);
        let last_hash = all.body["records"]
            .as_array()
            .and_then(|records| records.last())
            .expect("a last record")["hash"]
            .clone();
        let beyond = export(&lab, &format!("?from={}", head + 1)).await;
        beyond.assert_status(200);
        assert_eq!(beyond.body["records"], json!([]));
        assert_eq!(beyond.body["next"], Value::Null);
        assert_eq!(beyond.body["anchor"]["seq"], head);
        assert_eq!(beyond.body["anchor"]["hash"], last_hash);
        let far = export(&lab, &format!("?from={}", head + 100)).await;
        far.assert_status(200);
        assert_eq!(far.body["records"], json!([]));
        assert_eq!(far.body["next"], Value::Null);
    }

    #[tokio::test]
    async fn the_audit_export_refuses_a_bad_range() {
        let lab = Lab::new(true).await;
        for query in [
            "?from=0",
            "?limit=0",
            "?limit=5001",
            "?from=-1",
            "?from=abc",
            "?limit=x",
        ] {
            export(&lab, query)
                .await
                .assert_problem(400, "sys.invalid_query");
        }
        export(&lab, "?limit=5000").await.assert_status(200);
    }
}
