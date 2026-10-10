//! Backups: create a backup into the target directory, the backup status and the schedule (OPS-07).
//!
//! Area: backup. Owner: WP3.4b.
//! Requirements: OPS-07.
//!
//! Planned operations: `POST /system/backups` (administrator, step-up, an inline job) and
//! the status and schedule settings. Phase 1 offers no download of a backup through the
//! API (owner decision S3-Q11).
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
