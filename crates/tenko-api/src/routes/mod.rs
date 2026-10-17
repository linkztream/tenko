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
//! | [`observations`] | observations of connectors and probes, per source and across sources | WP2.4 |
//! | [`proposals`] | proposals, decisions, reconcile runs, adoption policies | WP2.4 |
//! | [`nodes`] | cluster nodes: enrolment tokens, enrolment, registry, revocation | WP2.2 |
//! | [`secrets`] | operator secrets, reveal, host credentials | WP2.1 |
//! | [`remote`] | RDP file and SSH URI of a host (API-11) | WP2.1 |
//! | [`vlans`] | VLAN provisioning through network controllers, the prefixes of a VLAN | WP2.7 |
//! | [`topology`] | the topology map (IPAM-20) | WP2.7 |
//! | [`audit`] | audit log and chain verification | WP1.7 |
//! | [`events`] | server-sent events | WP1.7 |
//! | [`system`] | health, status, OpenAPI document | WP1.7 |
//! | [`metrics`] | metrics in the `OpenMetrics` text format (split from `system`) | WP3.5 |
//! | [`cluster`] | controller members, promotion, removal, step-down | WP3.1a |
//! | [`access`] | scoped grants and service accounts | WP3.2 |
//! | [`audit_export`] | audit export sinks, status and test | WP3.3 |
//! | [`kek`] | key-encryption keys: status and online rotation | WP3.4a |
//! | [`backup`] | backups: create, status, schedule | WP3.4b |
//! | [`reconciler`] | reconciler settings (IPAM module) | WP3.12a |
//! | [`guardrails`] | guardrails of network-controller writes | WP3.12a |
//! | [`i18n`] | language packs (partly public) | WP3.7 |
//! | [`queue`] | changes queued on an isolated controller (IPAM module) | WP3.9 |
//! | [`scans`] | scan jobs, probe scan configuration, kill switch (Discovery module) | WP3.10 |
//! | [`dns`] | zones, records, views, forwarders, access lists, keys, lists, the DNS role of a node (DNS module) | WP4.0 (contracts) |
//!
//! The Slice 3 modules were created empty by WP3.0 with their tags registered, so each
//! package adds its operations in its own file. The quorum gate of WP3.9 sits in the API
//! middleware (`middleware::quorum`), not here.
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

pub mod access;
pub mod addresses;
pub mod audit;
pub mod audit_export;
pub mod auth;
pub mod backup;
pub mod cluster;
pub mod common;
pub mod connectors;
pub mod dns;
pub mod events;
pub mod export;
pub mod guardrails;
pub mod hosts;
pub mod i18n;
pub mod import;
pub mod jobs;
pub mod kek;
pub mod metrics;
pub mod moves;
pub mod nodes;
pub mod observations;
pub mod prefixes;
pub mod proposals;
pub mod queue;
pub mod reconciler;
pub mod remote;
pub mod scans;
pub mod secrets;
pub mod settings;
pub mod setup;
pub mod system;
pub mod tenancy;
pub mod topology;
pub mod users;
pub mod vlans;

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
        (name = "system", description = "Health, status and the OpenAPI document"),
        (name = "metrics", description = "Metrics in the OpenMetrics text format"),
        (name = "connectors", description = "Connector plugins and connector instances"),
        (name = "guardrails", description = "Guardrails of network-controller writes: protected paths and move parallelism"),
        (name = "observations", description = "Observations of connectors and probes, per source and across sources"),
        (name = "proposals", description = "Proposals of the reconciler, their decisions and adoption policies"),
        (name = "reconciler", description = "Settings of the reconciler: intervals, retention and adoption"),
        (name = "nodes", description = "Cluster nodes: enrolment tokens, enrolment, the node registry and revocation"),
        (name = "secrets", description = "Operator secrets, their reveal, host credentials and the remote access hand-off"),
        (name = "topology", description = "The topology map: nodes, edges, ports and neighbours"),
        (name = "cluster", description = "The controller cluster: members, their replication state, promotion, removal and step-down"),
        (name = "access", description = "Scoped grants over VRFs, sites and prefixes, delegation and service accounts"),
        (name = "audit_export", description = "Audit export sinks (syslog, CEF, JSON lines), their status and test records"),
        (name = "kek", description = "Key-encryption keys: provider, protection, generations and online rotation"),
        (name = "backup", description = "Backups: creation, status and schedule"),
        (name = "i18n", description = "Language packs: the active languages, upload, preview, activation and the template"),
        (name = "queue", description = "Changes queued on an isolated controller and their conflicts"),
        (name = "scans", description = "Scan jobs, probe scan configuration and the remote kill switch"),
        (name = "dns", description = "DNS: zones and records, views, forwarders, access lists, TSIG keys, block lists and the DNS role of a node"),
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
/// import, export, moves and the queue of an isolated controller; Discovery owns the scan
/// jobs; DNS owns the zones, records, views, forwarders, access lists, keys, lists and the DNS
/// routes of a node; DHCP has no routes yet. The Slice 3 platform areas (cluster, access,
/// audit export, KEK, backup, metrics, language packs) are always registered.
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
        .merge(metrics::routes())
        .merge(connectors::routes())
        .merge(guardrails::routes())
        .merge(secrets::routes())
        .merge(nodes::routes())
        .merge(cluster::routes())
        .merge(access::routes())
        .merge(audit_export::routes())
        .merge(kek::routes())
        .merge(backup::routes())
        .merge(i18n::routes());
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
            .merge(reconciler::routes())
            .merge(secrets::host_routes())
            .merge(remote::routes())
            .merge(vlans::routes())
            .merge(topology::routes())
            .merge(queue::routes());
    }
    if modules.contains(Module::Discovery) {
        router = router.merge(scans::routes());
    }
    if modules.contains(Module::Dns) {
        router = router.merge(dns::routes());
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
