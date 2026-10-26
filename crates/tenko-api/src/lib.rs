//! HTTP API of Tenko DDI: the axum server with its listener, TLS modes and middleware, the
//! generated OpenAPI document, server-sent events, the embedded web UI, and the API client
//! of the command line.
//!
//! Every endpoint of the Slice 1 surface (plan `docs/plans/phase-1-execution.md`, section 4)
//! is declared with `#[utoipa::path]`, registered with `utoipa_axum::routes!`, and therefore
//! appears in the OpenAPI document that [`openapi`] returns and CI compares with
//! `docs/api/openapi.json`. Until a package implements an endpoint, its handler is a stub
//! that answers `501` with the `sys.not_implemented` problem details.
//!
//! # Features
//!
//! - `server` (default): everything below that touches axum, the listener and the store.
//! - `client`: [`client`], a `reqwest` client over rustls for the `tenko` CLI (API-03). It
//!   shares [`dto`] and [`problem::ProblemDetails`] with the server and pulls in no axum.
//!
//! # Modules
//!
//! | Module | Contents |
//! |---|---|
//! | [`dto`] | shared bodies: [`dto::Page`], audit, events and system DTOs |
//! | [`problem`] | RFC 9457 problem details, `ApiError`, the platform's error codes |
//! | [`modules`] | the product modules of OPS-25 (`Module`, `ModuleSet`) |
//! | `client` | the API client (feature `client`) |
//! | `server` | [`serve`], [`start`], [`ServerConfig`], the listener, PROXY protocol, trusted proxies |
//! | `middleware` | security headers, CSRF guard, rate limits, idempotency, request counters |
//! | `extract` | `Ctx` (the `RequestCtx` extractor) and `ClientInfo` |
//! | `list` | pagination, opaque cursors, filters and sorting for every list endpoint |
//! | `sse` | the event hub behind `GET /events` |
//! | `ui` | the embedded web UI (`build.rs`, ADR 0008) |
//! | `routes` | one file per API area, and the OpenAPI assembly |
//! | `state` | `AppState`, the shared services |
//!
//! # Ownership
//!
//! WP1.0 owns `routes/mod.rs`; each `routes/<area>.rs` belongs to the package that
//! implements the area (WP1.2: setup, auth, users, settings; WP1.4: tenancy, prefixes,
//! addresses, hosts, common; WP1.5: import, export; WP1.6: jobs). WP1.7 owns
//! `routes/{audit,events,system}.rs` and everything else in the crate.
//!
//! # How to add a route
//!
//! Write a handler with `#[utoipa::path]` in the area file and add it to that file's
//! `routes!` list; nothing else changes. Pass every handler of one path to the same
//! `routes!` call (one handler per method) and register each path in exactly one file:
//! axum panics on overlapping routes. Path templates are relative to [`API_BASE`], which
//! the router nests every area under. List endpoints use `list::Filters` and
//! `list::PageParams` and answer with [`dto::Page`].

#[cfg(feature = "client")]
pub mod client;
pub mod dto;
pub mod i18n;
pub mod modules;
pub mod problem;
pub mod redact;

#[cfg(feature = "server")]
pub mod extract;
#[cfg(feature = "server")]
pub mod findings;
#[cfg(feature = "server")]
pub mod host;
#[cfg(feature = "server")]
pub mod list;
#[cfg(feature = "server")]
pub mod middleware;
#[cfg(feature = "server")]
pub mod routes;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod sse;
#[cfg(feature = "server")]
pub mod state;
#[cfg(feature = "server")]
pub mod ui;

#[cfg(feature = "server")]
pub use server::{RunningServer, ServeError, ServerConfig, serve, shutdown_signal, start};

/// Name of this crate as declared in its manifest.
pub const CRATE_NAME: &str = "tenko-api";

/// Path prefix of every API route.
pub const API_BASE: &str = "/api/v1";

/// Returns the version of this crate as declared in its manifest.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Builds the router of the API under [`API_BASE`], over `state`, together with its OpenAPI
/// document. The server wraps it with its middleware and the UI ([`server::app`]). Only the
/// routes of the modules of the state are registered ([`state::AppState::modules`],
/// OPS-25).
#[cfg(feature = "server")]
pub fn api(state: state::AppState) -> (axum::Router, utoipa::openapi::OpenApi) {
    let modules = state.modules();
    api_with(state, modules)
}

/// [`api`] with an explicit module set: a disabled module registers no route, so its
/// paths answer 404 like unknown ones (OPS-25). The document describes the registered
/// routes; [`openapi`] always describes the whole API.
#[cfg(feature = "server")]
pub fn api_with(
    state: state::AppState,
    modules: modules::ModuleSet,
) -> (axum::Router, utoipa::openapi::OpenApi) {
    let (router, mut document) =
        utoipa_axum::router::OpenApiRouter::<state::AppState>::with_openapi(routes::api_doc())
            .nest(API_BASE, routes::router_for(modules))
            .split_for_parts();
    add_stream_schemas(&mut document);
    (router.with_state(state), document)
}

/// Adds the schemas that travel inside the event stream rather than as a response body
/// (`reset` data), so that clients generate types for them too.
#[cfg(feature = "server")]
fn add_stream_schemas(document: &mut utoipa::openapi::OpenApi) {
    use utoipa::{PartialSchema as _, ToSchema};

    let mut schemas = vec![(
        dto::events::ResetData::name().into_owned(),
        dto::events::ResetData::schema(),
    )];
    dto::events::ResetData::schemas(&mut schemas);
    let components = document.components.get_or_insert_with(Default::default);
    for (name, schema) in schemas {
        components.schemas.entry(name).or_insert(schema);
    }
}

/// The API router over a default [`state::AppState`] (an in-memory store) and the OpenAPI
/// document; for tests and the OpenAPI dump.
#[cfg(feature = "server")]
pub fn app() -> (axum::Router, utoipa::openapi::OpenApi) {
    api(state::AppState::default())
}

/// The router of the API, mounted under [`API_BASE`], over a default state.
#[cfg(feature = "server")]
pub fn router() -> axum::Router {
    app().0
}

/// The OpenAPI document of the API. Built once and cloned out.
#[cfg(feature = "server")]
pub fn openapi() -> utoipa::openapi::OpenApi {
    static DOCUMENT: std::sync::OnceLock<utoipa::openapi::OpenApi> = std::sync::OnceLock::new();
    DOCUMENT
        .get_or_init(|| {
            let mut document = utoipa_axum::router::OpenApiRouter::<state::AppState>::with_openapi(
                routes::api_doc(),
            )
            .nest(API_BASE, routes::router())
            .split_for_parts()
            .1;
            add_stream_schemas(&mut document);
            document
        })
        .clone()
}

/// The OpenAPI document as pretty-printed JSON that ends with a newline. CI compares this
/// output with `docs/api/openapi.json`.
///
/// # Panics
///
/// Panics if the document cannot be serialized, which would be a bug in a schema.
#[cfg(feature = "server")]
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

    #[cfg(feature = "server")]
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

    #[cfg(feature = "server")]
    #[test]
    fn openapi_json_is_pretty_and_ends_with_a_newline() {
        let json = openapi_json();
        assert!(json.ends_with("}\n"));
        assert!(json.lines().count() > 1);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["info"]["title"], "Tenko DDI API");
        for schema in ["ResetData", "ResetReason", "EventData", "SystemStatus"] {
            assert!(
                value["components"]["schemas"].get(schema).is_some()
                    || json.contains(&format!("\"{schema}\"")),
                "{schema}"
            );
        }
    }
}
