//! Key-encryption keys: provider, protection, generations and online rotation (IAM-15).
//!
//! Area: kek. Owner: WP3.4a.
//! Requirements: IAM-15, IAM-16.
//!
//! Planned operations: `GET /system/kek` and `POST /system/kek/rotate` (administrator,
//! step-up), the rotation running on the leader in two phases.
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
