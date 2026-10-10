//! The controller cluster: members with their replication state, promotion, removal and step-down (OPS-03).
//!
//! Area: cluster. Owner: WP3.1a.
//! Requirements: OPS-03, OPS-04, OPS-08.
//!
//! Planned operations: `GET /cluster/members`, `POST /cluster/members/{id}/promote`,
//! `DELETE /cluster/members/{id}` and `POST /cluster/step-down`, each membership change an
//! inline job `cluster.edit` with audit (`cluster.member.join`, `.promote`, `.remove`).
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
