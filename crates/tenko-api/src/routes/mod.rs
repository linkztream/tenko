//! Routes of the API, one module per area, and the assembly of the OpenAPI document.
//!
//! Each area module exposes `routes()`, an `OpenApiRouter<AppState>` built with
//! `utoipa_axum::routes!`; [`router`] merges them all on top of the document skeleton
//! (info, tags and security schemes). Path templates in the area modules are relative to
//! [`API_BASE`]; `crate::app` nests the merged router under it.
//!
//! WP1.0 owns this file. Each area module belongs to the package that implements the area:
//!
//! | Module | Area | Owner |
//! |---|---|---|
//! | [`setup`] | first-run setup (API-10) | WP1.2 |
//! | [`auth`] | login, sessions, factors, recovery codes, tokens | WP1.2 |
//! | [`users`] | users, roles, break-glass | WP1.2 |
//! | [`settings`] | security settings | WP1.2 |
//! | [`tenancy`] | tenants, VRFs, sites, VLANs | WP1.4 |
//! | [`prefixes`] | prefixes, the prefix tree, next free, ranges | WP1.4 |
//! | [`addresses`] | addresses | WP1.4 |
//! | [`hosts`] | hosts and interfaces | WP1.4 |
//! | [`common`] | history, restore, bulk, tags, custom fields, search | WP1.4 |
//! | [`import`] | import upload, mapping, preview, apply | WP1.5 |
//! | [`export`] | CSV export | WP1.5 |
//! | [`jobs`] | jobs and manual steps | WP1.6 |
//! | [`moves`] | preview and start moves to another network (IPAM-19) | WP1.4b |
//! | [`connectors`] | connector plugins and instances | WP2.0 |
//! | [`secrets`] | operator secrets, reveal, host credentials | WP2.1 |
//! | [`remote`] | RDP file and SSH URI of a host (API-11) | WP2.1 |
//! | [`observations`] | observations of connectors and probes, per source and across sources | WP2.4 |
//! | [`proposals`] | proposals, decisions, reconcile runs, adoption policies | WP2.4 |
//! | [`audit`] | audit log and chain verification | WP1.7 |
//! | [`events`] | server-sent events | WP1.7 |
//! | [`system`] | health, status, OpenAPI document, metrics | WP1.7 |
//!
//! Every path is registered in exactly one module (axum panics on overlapping routes), and
//! the stubs answer `501` with `sys.not_implemented` until their owner replaces them.

use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use utoipa_axum::router::OpenApiRouter;

use crate::{
    API_BASE,
    modules::{Module, ModuleSet},
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

pub mod addresses;
pub mod audit;
pub mod auth;
pub mod common;
pub mod connectors;
pub mod events;
pub mod export;
pub mod hosts;
pub mod import;
pub mod jobs;
pub mod moves;
pub mod observations;
pub mod prefixes;
pub mod proposals;
pub mod remote;
pub mod secrets;
pub mod settings;
pub mod setup;
pub mod system;
pub mod tenancy;
pub mod users;

/// The skeleton of the OpenAPI document: info, one tag per area and the security schemes.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Tenko DDI API",
        description = "HTTP API of Tenko DDI: DNS, DHCP and IP address management."
    ),
    tags(
        (name = "setup", description = "First-run setup of a new installation"),
        (name = "auth", description = "Login, sessions, authentication factors, recovery codes and personal tokens"),
        (name = "users", description = "Users, roles and break-glass access"),
        (name = "settings", description = "Security settings"),
        (name = "tenancy", description = "Tenants, VRFs, sites and VLANs"),
        (name = "prefixes", description = "Prefixes, the prefix tree, next free allocation and ranges"),
        (name = "addresses", description = "IP addresses"),
        (name = "hosts", description = "Hosts and their interfaces"),
        (name = "common", description = "History, restore, bulk changes, tags, custom fields and search"),
        (name = "import", description = "Import of spreadsheets and CSV files"),
        (name = "export", description = "CSV export in the import vocabulary"),
        (name = "jobs", description = "Jobs and manual steps"),
        (name = "moves", description = "Moving hosts and addresses to another network"),
        (name = "audit", description = "Audit log and chain verification"),
        (name = "events", description = "Server-sent events"),
        (name = "system", description = "Health, status, the OpenAPI document and metrics"),
        (name = "connectors", description = "Connector plugins and connector instances"),
        (name = "secrets", description = "Operator secrets, their reveal, host credentials and the remote access hand-off"),
        (name = "observations", description = "Observations of connectors and probes, per source and across sources"),
        (name = "proposals", description = "Proposals of the reconciler, their decisions and adoption policies"),
    ),
    components(schemas(ProblemDetails, crate::dto::SortOrder, tenko_ipam::query::Deleted)),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

/// Adds the security schemes `session` (the UI cookie) and `token` (personal API tokens).
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "tenko_session",
                "Session cookie of the web UI. Mutating requests must carry a same-origin \
                 `Origin` header.",
            ))),
        );
        components.add_security_scheme(
            "token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("opaque")
                    .description(Some(
                        "Personal API token, sent as `Authorization: Bearer <token>`.",
                    ))
                    .build(),
            ),
        );
    }
}

/// The document skeleton that [`router`] starts from and `crate::app` builds on.
pub(crate) fn api_doc() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// Every route of the API, relative to [`API_BASE`], with the document skeleton as base;
/// all modules, so the OpenAPI document always describes the whole API.
pub fn router() -> OpenApiRouter<AppState> {
    router_for(ModuleSet::ALL)
}

/// The routes of the platform and of the enabled product modules (OPS-25). A disabled
/// module registers nothing, so its paths answer 404 `sys.route_not_found` like any
/// unknown path. The platform areas (setup, auth, users, settings, jobs, audit, events,
/// system) are always registered; IPAM owns tenancy, prefixes, addresses, hosts, common,
/// import, export and moves; DNS, DHCP and Discovery have no routes yet.
pub fn router_for(modules: ModuleSet) -> OpenApiRouter<AppState> {
    let mut router = OpenApiRouter::with_openapi(api_doc())
        .merge(setup::routes())
        .merge(auth::routes())
        .merge(users::routes())
        .merge(settings::routes())
        .merge(jobs::routes())
        .merge(audit::routes())
        .merge(events::routes())
        .merge(system::routes())
        .merge(connectors::routes())
        .merge(secrets::routes());
    if modules.contains(Module::Ipam) {
        router = router
            .merge(tenancy::routes())
            .merge(prefixes::routes())
            .merge(addresses::routes())
            .merge(hosts::routes())
            .merge(common::routes())
            .merge(import::routes())
            .merge(export::routes())
            .merge(moves::routes())
            .merge(observations::routes())
            .merge(proposals::routes())
            .merge(secrets::host_routes())
            .merge(remote::routes());
    }
    router
}

/// The stub answer of an endpoint that is declared but not implemented yet.
///
/// `path` is the template relative to [`API_BASE`], for example
/// `/prefixes/{id}`; the problem details carry the full template.
pub(crate) fn not_implemented(method: &str, path: &str) -> ApiError {
    ApiError::not_implemented(method, &format!("{API_BASE}{path}"))
}
