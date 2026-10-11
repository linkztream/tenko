//! The route table of the Slice 1 API surface.
//!
//! `ENDPOINTS` lists every endpoint of plan section 4 with its operation id. The tests send
//! each one through the router, and compare the table with the OpenAPI document in both
//! directions, so the routes, the document and the table cannot drift apart.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::Value;
use tower::ServiceExt;
use utoipa::openapi::{
    RefOr,
    path::{Operation, ParameterIn, PathItem},
};

const API_BASE: &str = "/api/v1";
const PROBLEM_JSON: &str = "application/problem+json";
const ID: &str = "0190d1c2-0000-7000-8000-000000000001";

/// (method, path template relative to the API base, operation id).
const ENDPOINTS: &[(&str, &str, &str)] = &[
    // setup
    ("GET", "/setup", "get_setup"),
    ("POST", "/setup", "complete_setup"),
    // auth
    ("POST", "/auth/login/password", "login_password"),
    ("POST", "/auth/login/totp", "login_totp"),
    ("POST", "/auth/login/recovery", "login_recovery"),
    ("POST", "/auth/webauthn/login/start", "webauthn_login_start"),
    (
        "POST",
        "/auth/webauthn/login/finish",
        "webauthn_login_finish",
    ),
    ("POST", "/auth/logout", "logout"),
    ("GET", "/auth/session", "get_session"),
    ("GET", "/auth/sessions", "list_sessions"),
    ("DELETE", "/auth/sessions/{id}", "revoke_session"),
    ("POST", "/auth/password", "change_password"),
    ("POST", "/auth/password/check", "check_password"),
    ("POST", "/auth/totp/enroll/start", "totp_enroll_start"),
    ("POST", "/auth/totp/enroll/finish", "totp_enroll_finish"),
    ("DELETE", "/auth/totp", "remove_totp"),
    (
        "POST",
        "/auth/webauthn/register/start",
        "webauthn_register_start",
    ),
    (
        "POST",
        "/auth/webauthn/register/finish",
        "webauthn_register_finish",
    ),
    (
        "GET",
        "/auth/webauthn/credentials",
        "list_webauthn_credentials",
    ),
    (
        "DELETE",
        "/auth/webauthn/credentials/{id}",
        "delete_webauthn_credential",
    ),
    ("POST", "/auth/recovery-codes", "regenerate_recovery_codes"),
    ("GET", "/auth/tokens", "list_tokens"),
    ("POST", "/auth/tokens", "create_token"),
    ("DELETE", "/auth/tokens/{id}", "revoke_token"),
    // users
    ("GET", "/users", "list_users"),
    ("POST", "/users", "create_user"),
    ("GET", "/users/{id}", "get_user"),
    ("PATCH", "/users/{id}", "update_user"),
    ("DELETE", "/users/{id}", "delete_user"),
    ("POST", "/users/{id}/unlock", "unlock_user"),
    ("DELETE", "/users/{id}/sessions", "revoke_user_sessions"),
    ("PUT", "/users/{id}/roles", "set_user_roles"),
    ("GET", "/roles", "list_roles"),
    ("PUT", "/system/break-glass", "set_break_glass"),
    // settings
    ("GET", "/settings/security", "get_security_settings"),
    ("PATCH", "/settings/security", "update_security_settings"),
    ("PUT", "/settings/default-language", "set_default_language"),
    // tenancy
    ("GET", "/tenants", "list_tenants"),
    ("POST", "/tenants", "create_tenant"),
    ("GET", "/tenants/{id}", "get_tenant"),
    ("PATCH", "/tenants/{id}", "update_tenant"),
    ("DELETE", "/tenants/{id}", "delete_tenant"),
    ("GET", "/vrfs", "list_vrfs"),
    ("POST", "/vrfs", "create_vrf"),
    ("GET", "/vrfs/{id}", "get_vrf"),
    ("PATCH", "/vrfs/{id}", "update_vrf"),
    ("DELETE", "/vrfs/{id}", "delete_vrf"),
    ("GET", "/sites", "list_sites"),
    ("POST", "/sites", "create_site"),
    ("GET", "/sites/{id}", "get_site"),
    ("PATCH", "/sites/{id}", "update_site"),
    ("DELETE", "/sites/{id}", "delete_site"),
    ("GET", "/vlans", "list_vlans"),
    ("POST", "/vlans", "create_vlan"),
    ("GET", "/vlans/{id}", "get_vlan"),
    ("PATCH", "/vlans/{id}", "update_vlan"),
    ("DELETE", "/vlans/{id}", "delete_vlan"),
    // prefixes
    ("GET", "/prefixes", "list_prefixes"),
    ("POST", "/prefixes", "create_prefix"),
    ("GET", "/prefixes/{id}", "get_prefix"),
    ("PATCH", "/prefixes/{id}", "update_prefix"),
    ("DELETE", "/prefixes/{id}", "delete_prefix"),
    ("GET", "/prefixes/tree", "get_prefix_tree"),
    (
        "POST",
        "/prefixes/{id}/next-free-address",
        "next_free_address",
    ),
    (
        "POST",
        "/prefixes/{id}/next-free-prefix",
        "next_free_prefix",
    ),
    ("GET", "/prefixes/{id}/addresses", "list_prefix_addresses"),
    ("GET", "/prefixes/{id}/ranges", "list_prefix_ranges"),
    ("POST", "/prefixes/{id}/ranges", "create_range"),
    ("GET", "/ranges/{id}", "get_range"),
    ("PATCH", "/ranges/{id}", "update_range"),
    ("DELETE", "/ranges/{id}", "delete_range"),
    // addresses
    ("GET", "/addresses", "list_addresses"),
    ("POST", "/addresses", "create_address"),
    ("GET", "/addresses/{id}", "get_address"),
    ("PATCH", "/addresses/{id}", "update_address"),
    ("DELETE", "/addresses/{id}", "delete_address"),
    // hosts
    ("GET", "/hosts", "list_hosts"),
    ("POST", "/hosts", "create_host"),
    ("GET", "/hosts/{id}", "get_host"),
    ("PATCH", "/hosts/{id}", "update_host"),
    ("DELETE", "/hosts/{id}", "delete_host"),
    ("GET", "/hosts/{id}/interfaces", "list_host_interfaces"),
    ("POST", "/hosts/{id}/interfaces", "create_interface"),
    ("GET", "/interfaces/{id}", "get_interface"),
    ("PATCH", "/interfaces/{id}", "update_interface"),
    ("DELETE", "/interfaces/{id}", "delete_interface"),
    // common: history, restore and bulk of every collection
    ("GET", "/tenants/{id}/history", "get_tenant_history"),
    ("POST", "/tenants/{id}/restore", "restore_tenant"),
    ("POST", "/tenants/bulk", "bulk_tenants"),
    ("GET", "/vrfs/{id}/history", "get_vrf_history"),
    ("POST", "/vrfs/{id}/restore", "restore_vrf"),
    ("POST", "/vrfs/bulk", "bulk_vrfs"),
    ("GET", "/sites/{id}/history", "get_site_history"),
    ("POST", "/sites/{id}/restore", "restore_site"),
    ("POST", "/sites/bulk", "bulk_sites"),
    ("GET", "/vlans/{id}/history", "get_vlan_history"),
    ("POST", "/vlans/{id}/restore", "restore_vlan"),
    ("POST", "/vlans/bulk", "bulk_vlans"),
    ("GET", "/prefixes/{id}/history", "get_prefix_history"),
    ("POST", "/prefixes/{id}/restore", "restore_prefix"),
    ("POST", "/prefixes/bulk", "bulk_prefixes"),
    ("GET", "/ranges/{id}/history", "get_range_history"),
    ("POST", "/ranges/{id}/restore", "restore_range"),
    ("POST", "/ranges/bulk", "bulk_ranges"),
    ("GET", "/addresses/{id}/history", "get_address_history"),
    ("POST", "/addresses/{id}/restore", "restore_address"),
    ("POST", "/addresses/bulk", "bulk_addresses"),
    ("GET", "/hosts/{id}/history", "get_host_history"),
    ("POST", "/hosts/{id}/restore", "restore_host"),
    ("POST", "/hosts/bulk", "bulk_hosts"),
    ("GET", "/interfaces/{id}/history", "get_interface_history"),
    ("POST", "/interfaces/{id}/restore", "restore_interface"),
    ("POST", "/interfaces/bulk", "bulk_interfaces"),
    // common: tags, custom fields, search
    ("GET", "/tags", "list_tags"),
    ("GET", "/custom-fields", "list_custom_fields"),
    ("POST", "/custom-fields", "create_custom_field"),
    ("GET", "/custom-fields/{key}", "get_custom_field"),
    ("PATCH", "/custom-fields/{key}", "update_custom_field"),
    ("DELETE", "/custom-fields/{key}", "delete_custom_field"),
    ("GET", "/search", "search"),
    // import
    ("POST", "/imports", "create_import"),
    ("GET", "/imports/{id}", "get_import"),
    ("DELETE", "/imports/{id}", "delete_import"),
    ("PUT", "/imports/{id}/mapping", "set_import_mapping"),
    ("GET", "/imports/{id}/preview", "preview_import"),
    ("GET", "/imports/{id}/rows", "list_import_rows"),
    ("POST", "/imports/{id}/apply", "apply_import"),
    // export
    ("GET", "/exports/prefixes.csv", "export_prefixes_csv"),
    ("GET", "/exports/addresses.csv", "export_addresses_csv"),
    ("GET", "/exports/hosts.csv", "export_hosts_csv"),
    // jobs
    ("GET", "/jobs", "list_jobs"),
    ("GET", "/jobs/{id}", "get_job"),
    ("POST", "/jobs/{id}/cancel", "cancel_job"),
    (
        "POST",
        "/jobs/{id}/steps/{index}/complete",
        "complete_job_step",
    ),
    // moves
    ("POST", "/moves", "create_move"),
    // audit
    ("GET", "/audit", "list_audit"),
    ("GET", "/audit/{seq}", "get_audit_record"),
    ("GET", "/audit/verify", "verify_audit"),
    // events
    ("GET", "/events", "events"),
    // system
    ("GET", "/system/ca-root", "get_ca_root"),
    ("GET", "/system/updates", "get_updates"),
    ("POST", "/system/updates/check", "check_updates"),
    ("PUT", "/system/updates/manifest", "put_update_manifest"),
    ("POST", "/system/updates/install", "install_update"),
    ("POST", "/system/updates/upload", "upload_update"),
    ("GET", "/system/updates/whats-new", "get_whats_new"),
    (
        "POST",
        "/system/updates/whats-new/seen",
        "mark_whats_new_seen",
    ),
    ("GET", "/system/modules", "get_modules"),
    ("PUT", "/system/modules", "put_modules"),
    ("GET", "/health", "health"),
    ("GET", "/health/ready", "ready"),
    ("GET", "/system/status", "system_status"),
    ("GET", "/openapi.json", "openapi_document"),
    ("GET", "/metrics", "metrics"),
    // nodes
    ("GET", "/nodes", "list_nodes"),
    ("GET", "/nodes/{id}", "get_node"),
    ("DELETE", "/nodes/{id}", "revoke_node"),
    ("GET", "/nodes/enrolments", "list_enrolments"),
    ("POST", "/nodes/enrolments", "create_enrolment"),
    ("DELETE", "/nodes/enrolments/{id}", "delete_enrolment"),
    // cluster
    ("GET", "/cluster/members", "list_cluster_members"),
    (
        "POST",
        "/cluster/members/{id}/promote",
        "promote_cluster_member",
    ),
    ("DELETE", "/cluster/members/{id}", "remove_cluster_member"),
    ("POST", "/cluster/step-down", "step_down_cluster_leader"),
    ("GET", "/cluster/digests", "get_cluster_digests"),
    // kek
    ("GET", "/system/kek", "get_kek_status"),
    ("POST", "/system/kek/rotate", "rotate_kek"),
    ("POST", "/nodes/enrol", "enrol_node"),
    // secrets
    ("GET", "/secrets", "list_secrets"),
    ("POST", "/secrets", "create_secret"),
    ("GET", "/secrets/{id}", "get_secret"),
    ("PATCH", "/secrets/{id}", "update_secret"),
    ("DELETE", "/secrets/{id}", "delete_secret"),
    ("GET", "/secrets/{id}/references", "list_secret_references"),
    ("POST", "/secrets/{id}/reveal", "reveal_secret"),
    ("GET", "/hosts/{id}/credentials", "get_host_credentials"),
    ("PUT", "/hosts/{id}/credentials", "update_host_credentials"),
    ("GET", "/hosts/{id}/remote", "get_host_remote"),
    // observations
    ("GET", "/observations", "list_observations"),
    ("GET", "/observations/{subject}", "get_observation"),
    // topology (WP2.7)
    ("GET", "/topology", "get_topology"),
    ("GET", "/topology/nodes/{id}", "get_topology_node"),
    // VLAN provisioning (WP2.7)
    ("POST", "/vlans/provision", "provision_vlan"),
    ("GET", "/vlans/{id}/prefixes", "list_vlan_prefixes"),
    // proposals
    ("GET", "/proposals", "list_proposals"),
    ("POST", "/proposals/reconcile", "reconcile_proposals"),
    ("GET", "/proposals/{id}", "get_proposal"),
    ("POST", "/proposals/{id}/approve", "approve_proposal"),
    ("POST", "/proposals/{id}/reject", "reject_proposal"),
    ("GET", "/prefixes/{id}/adoption", "get_adoption_policy"),
    ("PUT", "/prefixes/{id}/adoption", "set_adoption_policy"),
    ("DELETE", "/prefixes/{id}/adoption", "clear_adoption_policy"),
    // connectors
    ("GET", "/connectors/plugins", "list_connector_plugins"),
    ("GET", "/connectors", "list_connectors"),
    ("POST", "/connectors", "create_connector"),
    ("GET", "/connectors/{id}", "get_connector"),
    ("PATCH", "/connectors/{id}", "update_connector"),
    ("DELETE", "/connectors/{id}", "delete_connector"),
    ("POST", "/connectors/{id}/enable", "enable_connector"),
    ("POST", "/connectors/{id}/disable", "disable_connector"),
    ("POST", "/connectors/{id}/run", "run_connector"),
    ("POST", "/connectors/{id}/check", "check_connector"),
];

/// The only endpoint that is not a stub.
const OPENAPI_PATH: &str = "/openapi.json";

/// Replaces the path parameters of a template with sample values.
fn concrete(template: &str) -> String {
    template
        .replace("{id}", ID)
        .replace("{key}", "owner")
        .replace("{seq}", "1")
        .replace("{index}", "0")
        .replace("{subject}", "00-00-5E-00-53-01")
}

fn request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

fn content_type(response: &Response) -> &str {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("content-type header")
        .to_str()
        .expect("content-type is text")
}

/// Every operation of a path item with its upper-case method.
fn operations(item: &PathItem) -> Vec<(&'static str, &Operation)> {
    [
        ("GET", &item.get),
        ("PUT", &item.put),
        ("POST", &item.post),
        ("DELETE", &item.delete),
        ("OPTIONS", &item.options),
        ("HEAD", &item.head),
        ("PATCH", &item.patch),
        ("TRACE", &item.trace),
        ("QUERY", &item.query),
    ]
    .into_iter()
    .filter_map(|(method, operation)| operation.as_ref().map(|operation| (method, operation)))
    .collect()
}

/// The `{name}` segments of a path template.
fn template_params(template: &str) -> BTreeSet<&str> {
    template
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .collect()
}

#[tokio::test]
async fn every_endpoint_answers_with_the_expected_status() {
    let router = tenko_api::router();
    for &(method, template, _) in ENDPOINTS {
        let uri = format!("{API_BASE}{}", concrete(template));
        let response = router
            .clone()
            .oneshot(request(method, &uri))
            .await
            .expect("response");
        let label = format!("{method} {uri}");

        if template == OPENAPI_PATH {
            assert_eq!(response.status(), StatusCode::OK, "{label}");
            assert_eq!(content_type(&response), "application/json", "{label}");
            let document = body_json(response).await;
            assert_eq!(document["info"]["title"], "Tenko DDI API", "{label}");
            continue;
        }

        // Every endpoint of the table is routed. An implemented endpoint answers with its own
        // status (the area's tests cover it); a stub answers 501 with the stub body. Without
        // the server's fallbacks an unrouted request gets axum's bare 404 or 405, while an
        // implemented endpoint answers a missing object with a problem document.
        let status = response.status();
        let problem = response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value == PROBLEM_JSON);
        assert!(
            problem
                || (status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED),
            "{label}: not routed ({status})"
        );
        if status != StatusCode::NOT_IMPLEMENTED {
            continue;
        }
        assert_eq!(content_type(&response), PROBLEM_JSON, "{label}");
        let body = body_json(response).await;
        assert_eq!(body["type"], "about:blank", "{label}");
        assert_eq!(body["status"], 501, "{label}");
        assert_eq!(body["code"], "sys.not_implemented", "{label}");
        assert_eq!(body["title"], "Not Implemented", "{label}");
        assert_eq!(body["params"]["method"], method, "{label}");
        // The stub names the endpoint (the path template), not the concrete URL.
        assert_eq!(
            body["params"]["path"],
            format!("{API_BASE}{template}"),
            "{label}"
        );
    }
}

#[test]
fn the_document_contains_exactly_the_table() {
    let document = tenko_api::openapi();

    let mut documented: BTreeMap<(String, String), &Operation> = BTreeMap::new();
    for (path, item) in &document.paths.paths {
        assert!(item.additional_operations.is_empty(), "{path}");
        for (method, operation) in operations(item) {
            let key = (method.to_owned(), path.clone());
            assert!(documented.insert(key, operation).is_none());
        }
    }

    let expected: BTreeSet<(String, String)> = ENDPOINTS
        .iter()
        .map(|&(method, template, _)| (method.to_owned(), format!("{API_BASE}{template}")))
        .collect();
    assert_eq!(
        expected.len(),
        ENDPOINTS.len(),
        "the table lists an endpoint twice"
    );
    let documented_keys: BTreeSet<(String, String)> = documented.keys().cloned().collect();

    let missing: Vec<_> = expected.difference(&documented_keys).collect();
    let extra: Vec<_> = documented_keys.difference(&expected).collect();
    assert!(missing.is_empty(), "not in the document: {missing:?}");
    assert!(extra.is_empty(), "not in the table: {extra:?}");

    // Operation ids are unique and agree with the table.
    let mut ids = BTreeSet::new();
    for &(method, template, operation_id) in ENDPOINTS {
        let key = (method.to_owned(), format!("{API_BASE}{template}"));
        let operation = documented[&key];
        assert_eq!(
            operation.operation_id.as_deref(),
            Some(operation_id),
            "{method} {template}"
        );
        assert!(
            ids.insert(operation_id),
            "duplicate operation id {operation_id}"
        );
    }
}

#[test]
fn every_path_parameter_is_declared() {
    let document = tenko_api::openapi();
    for (path, item) in &document.paths.paths {
        for (method, operation) in operations(item) {
            let declared: BTreeSet<&str> = operation
                .parameters
                .iter()
                .flatten()
                .filter_map(|parameter| match parameter {
                    RefOr::T(parameter) if parameter.parameter_in == ParameterIn::Path => {
                        Some(parameter.name.as_str())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                declared,
                template_params(path),
                "path parameters of {method} {path}"
            );
        }
    }
}

#[test]
fn operations_have_a_declared_tag_and_a_summary() {
    let document = tenko_api::openapi();
    let tags: BTreeSet<&str> = document
        .tags
        .iter()
        .flatten()
        .map(|tag| tag.name.as_str())
        .collect();
    // 22 areas of Slices 1 and 2, nine Slice 3 areas (metrics split from system, cluster and
    // kek with their operations, and six that start empty: access, audit_export, backup,
    // i18n, queue, scans).
    assert_eq!(tags.len(), 31, "one tag per area");
    for (path, item) in &document.paths.paths {
        for (method, operation) in operations(item) {
            let operation_tags = operation.tags.as_deref().unwrap_or_default();
            assert_eq!(operation_tags.len(), 1, "{method} {path}");
            assert!(tags.contains(operation_tags[0].as_str()), "{method} {path}");
            assert!(
                operation
                    .summary
                    .as_deref()
                    .is_some_and(|summary| !summary.is_empty()),
                "{method} {path}"
            );
        }
    }
}

#[test]
fn the_document_has_security_schemes_and_the_problem_schema() {
    let document = tenko_api::openapi();
    let components = document.components.as_ref().expect("components");
    assert!(components.security_schemes.contains_key("session"));
    assert!(components.security_schemes.contains_key("token"));
    assert!(components.schemas.contains_key("ProblemDetails"));
    assert!(components.schemas.contains_key("FieldError"));
    assert_eq!(document.info.title, "Tenko DDI API");
    assert_eq!(document.info.version, tenko_api::version());
}

#[tokio::test]
async fn an_invalid_idempotency_key_is_a_bad_request() {
    let request = Request::builder()
        .method("POST")
        .uri(format!("{API_BASE}/prefixes"))
        .header("Idempotency-Key", "has a space")
        .body(Body::empty())
        .expect("request");
    let response = tenko_api::router()
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(content_type(&response), PROBLEM_JSON);
    let body = body_json(response).await;
    assert_eq!(body["code"], "sys.invalid_value");
    assert_eq!(body["status"], 400);
    assert_eq!(body["params"]["kind"], "idempotency key");
}

#[tokio::test]
async fn a_valid_idempotency_key_reaches_the_handler() {
    let request = Request::builder()
        .method("POST")
        .uri(format!("{API_BASE}/prefixes"))
        .header("Idempotency-Key", "import-a1b2c3")
        .body(Body::empty())
        .expect("request");
    let response = tenko_api::router()
        .oneshot(request)
        .await
        .expect("response");
    // The key passes the extractor; what the handler answers (a stub's 501, or 503 while
    // the area's service is not wired into the bare router) is the area's business.
    assert_ne!(response.status(), StatusCode::BAD_REQUEST);
    if content_type(&response) == PROBLEM_JSON {
        let body = body_json(response).await;
        assert_ne!(body["code"], "sys.invalid_value");
    }
}

#[tokio::test]
async fn an_unknown_path_has_no_route() {
    for uri in [format!("{API_BASE}/nope"), "/setup".to_owned()] {
        let response = tenko_api::router()
            .oneshot(request("GET", &uri))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_ne!(response.status(), StatusCode::NOT_IMPLEMENTED, "{uri}");
    }
}

#[tokio::test]
async fn the_served_document_is_the_dumped_document() {
    let json = tenko_api::openapi_json();
    assert!(json.ends_with('\n'));
    let dumped: Value = serde_json::from_str(&json).expect("openapi_json is JSON");

    let response = tenko_api::router()
        .oneshot(request("GET", &format!("{API_BASE}{OPENAPI_PATH}")))
        .await
        .expect("response");
    assert_eq!(body_json(response).await, dumped);
}
