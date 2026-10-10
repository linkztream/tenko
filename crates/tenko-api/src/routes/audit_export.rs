//! The audit export: sinks (syslog, CEF, JSON lines), their status and a test record (IAM-18, TGL-21).
//!
//! Area: `audit_export`. Owner: WP3.3.
//! Requirements: IAM-18.
//!
//! Planned operations: `GET` and `PUT /settings/audit-export`, `POST
//! /settings/audit-export/test`. Sinks live in the store and the cursors in
//! `sys.audit_export_cursors`; both reach the `system` event topic.
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
