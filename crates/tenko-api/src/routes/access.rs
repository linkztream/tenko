//! Scoped access: grants over VRFs, sites and prefixes, delegation, and service accounts (IAM-01, IAM-10).
//!
//! Area: access. Owner: WP3.2.
//! Requirements: IAM-01, IAM-06, IAM-10.
//!
//! Grants live in `auth.grants` and scoped tokens in `auth.scoped_tokens`, tables an older
//! build does not read, so a rollback refuses them instead of widening them (plan section
//! 2.1). Their changes reach the `admin` event topic through the `auth` namespace.
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
