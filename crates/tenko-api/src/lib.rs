//! HTTP API: axum routes, the generated OpenAPI document, and server-sent event (SSE)
//! streams.
//!
//! The crate builds the router of the controller. Every endpoint of the Slice 1 surface
//! (plan `docs/plans/phase-1-execution.md`, section 4) is declared with `#[utoipa::path]`,
//! registered with `utoipa_axum::routes!`, and therefore appears in the OpenAPI document
//! that [`openapi`] returns and CI compares with `docs/api/openapi.json`. Until a package
//! implements an endpoint, its handler is a stub that answers `501` with the
//! `sys.not_implemented` problem details.
//!
//! | Module | Contents |
//! |---|---|
//! | [`routes`] | one file per API area, and the OpenAPI assembly |
//! | [`problem`] | RFC 9457 problem details and [`problem::ApiError`] |
//! | [`extract`] | [`extract::Ctx`], the `RequestCtx` extractor |
//! | [`state`] | [`state::AppState`], the shared services |
//!
//! # Ownership
//!
//! WP1.0 owns `lib.rs` and `routes/mod.rs`; each `routes/<area>.rs` belongs to the package
//! that implements the area (WP1.2: setup, auth, users, settings; WP1.4: tenancy, prefixes,
//! addresses, hosts, common; WP1.5: import, export; WP1.6: jobs; WP1.7: audit, events,
//! system, plus `problem.rs`, `extract.rs`, `state.rs` and everything else in the crate).
//! Other packages never edit `lib.rs` or `routes/mod.rs`; contract changes go through the
//! lead.
//!
//! # How to add a route
//!
//! Write a handler with `#[utoipa::path]` in the area file and add it to that file's
//! `routes!` list; nothing else changes. Pass every handler of one path to the same
//! `routes!` call (one handler per method) and register each path in exactly one file:
//! axum panics on overlapping routes. Path templates are relative to [`API_BASE`], which
//! the router nests every area under.

use std::sync::OnceLock;

use utoipa_axum::router::OpenApiRouter;

pub mod extract;
pub mod problem;
pub mod routes;
pub mod state;

use state::AppState;

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-api";

/// Path prefix of every API route.
pub const API_BASE: &str = "/api/v1";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Builds the router of the API under [`API_BASE`] together with its OpenAPI document.
///
/// The router carries a default [`AppState`]; the server crate adds the listener, TLS,
/// headers and the static UI around it.
pub fn app() -> (axum::Router, utoipa::openapi::OpenApi) {
    let (router, document) = OpenApiRouter::<AppState>::with_openapi(routes::api_doc())
        .nest(API_BASE, routes::router())
        .split_for_parts();
    (router.with_state(AppState::default()), document)
}

/// The router of the API, mounted under [`API_BASE`].
pub fn router() -> axum::Router {
    app().0
}

/// The OpenAPI document of the API. Built once and cloned out.
pub fn openapi() -> utoipa::openapi::OpenApi {
    static DOCUMENT: OnceLock<utoipa::openapi::OpenApi> = OnceLock::new();
    DOCUMENT.get_or_init(|| app().1).clone()
}

/// The OpenAPI document as pretty-printed JSON that ends with a newline. CI compares this
/// output with `docs/api/openapi.json`.
///
/// # Panics
///
/// Panics if the document cannot be serialized, which would be a bug in a schema.
pub fn openapi_json() -> String {
    let mut json =
        serde_json::to_string_pretty(&openapi()).expect("the OpenAPI document serializes");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches_manifest() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
        assert!(version().starts_with(|c: char| c.is_ascii_digit()));
    }

    #[test]
    fn every_documented_path_is_under_the_api_base() {
        let document = openapi();
        assert!(!document.paths.paths.is_empty());
        assert!(
            document
                .paths
                .paths
                .keys()
                .all(|path| path.starts_with("/api/v1/"))
        );
        assert_eq!(API_BASE, "/api/v1");
    }

    #[test]
    fn openapi_json_is_pretty_and_ends_with_a_newline() {
        let json = openapi_json();
        assert!(json.ends_with("}\n"));
        assert!(json.lines().count() > 1);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["info"]["title"], "Tenko DDI API");
    }
}
