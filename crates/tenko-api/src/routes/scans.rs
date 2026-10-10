//! On-demand scan jobs, per-probe scan configuration and the remote kill switch (SCAN-09, OPS-28).
//!
//! Area: scans. Owner: WP3.10.
//! Requirements: SCAN-05, SCAN-09, OPS-28.
//!
//! Planned operations: `POST /scans`, `GET` and `PUT /nodes/{id}/scan-config`, and
//! `POST /nodes/{id}/scan/stop|resume`. Part of the Discovery module: registered only while
//! it runs.
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
