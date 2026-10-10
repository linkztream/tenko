//! Language packs: the active languages, the compiled packs, upload, preview, activation and the template (API-21).
//!
//! Area: i18n. Owner: WP3.7.
//! Requirements: API-21.
//!
//! Planned operations: `GET /i18n/languages` and `GET /i18n/packs/{tag}` (public: the
//! sign-in page needs them), `POST /i18n/packs`, `GET /i18n/packs/{tag}/report`,
//! `POST /i18n/packs/{tag}/activate`, `DELETE /i18n/packs/{tag}` and
//! `GET /i18n/template.xlf`. Packs live in the store (`i18n.packs`, see
//! `tenko_core::i18n`), whose active set the authorization index reads for the language
//! check of users and setup.
//!
//! The module and its OpenAPI tag exist before the operations do (WP3.0), so the owning
//! package adds its handlers to [`routes`] without editing `routes/mod.rs`.

use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

/// The routes of the area; none yet.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
}
