//! Changes queued on an isolated controller and their conflicts after the partition heals (OPS-26).
//!
//! Area: queue. Owner: WP3.9.
//! Requirements: OPS-26.
//!
//! Planned operations: `POST /queue` and `GET /queue` on the isolated controller, and the
//! conflict views. Part of the IPAM module: registered only while it runs.
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
