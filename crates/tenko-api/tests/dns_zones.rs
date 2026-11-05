//! The DNS zone, zone journal and access list operations through the router, over the
//! zone service on an in-memory store.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_core::{
    Action, Authorizer, Denied, DenyReason, ObjectKind, ObjectRef, Principal, ScopeFilter,
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;

const API: &str = "/api/v1";
const PROBLEM_JSON: &str = "application/problem+json";
const MISSING: &str = "0190d1c2-0000-7000-8000-0000000000ff";

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn etag(&self) -> String {
        self.headers
            .get(header::ETAG)
            .expect("etag")
            .to_str()
            .expect("text")
            .to_owned()
    }

    #[track_caller]
    fn assert_problem(&self, status: u16, code: &str) {
        assert_eq!(self.status.as_u16(), status, "{}", self.body);
        assert_eq!(
            self.headers
                .get(header::CONTENT_TYPE)
                .map(axum::http::HeaderValue::as_bytes),
            Some(PROBLEM_JSON.as_bytes())
        );
        assert_eq!(self.body["code"], code, "{}", self.body);
    }
}

/// An authorizer of an operator with every DNS right but `dns.keys`: every action on a
/// `DnsKey` is refused, everything else allowed.
struct WithoutKeys;

impl Authorizer for WithoutKeys {
    fn check(&self, _: &Principal, action: Action, object: &ObjectRef) -> Result<(), Denied> {
        if object.kind == ObjectKind::DnsKey {
            Err(Denied {
                action,
                object: *object,
                reason: DenyReason::MissingPermission,
            })
        } else {
            Ok(())
        }
    }

    fn scope(&self, _: &Principal, _: Action, kind: ObjectKind) -> ScopeFilter {
        if kind == ObjectKind::DnsKey {
            ScopeFilter::Nothing
        } else {
            ScopeFilter::All
        }
    }
}

fn app_with(authorizer: Option<Arc<dyn Authorizer>>) -> Router {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(tenko_vault::MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let mut state = AppState::default();
    state.authorizer = authorizer;
    let (router, _) = tenko_api::api(state);
    router.layer(axum::Extension(service))
}

fn app() -> Router {
    app_with(None)
}

async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
    send_with(router, method, path, body, &[]).await
}

async fn send_with(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    extra: &[(&str, &str)],
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{API}{path}"));
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON")
    };
    Reply {
        status,
        headers,
        body,
    }
}

fn zone_body(name: &str) -> Value {
    json!({
        "name": name,
        "kind": "primary",
        "serial": "counter",
        "soa": {"mname": format!("ns1.{name}"), "rname": format!("hostmaster.{name}")},
        "name_servers": [format!("ns1.{name}")],
    })
}

async fn create_zone(router: &Router, name: &str) -> Reply {
    let reply = send(router, "POST", "/dns/zones", Some(zone_body(name))).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    reply
}

fn acl_body(name: &str) -> Value {
    json!({
        "name": name,
        "entries": [{"kind": "prefix", "prefix": "192.0.2.0/24"}],
    })
}

#[tokio::test]
async fn a_zone_is_created_read_listed_and_deleted() {
    let router = app();
    let created = create_zone(&router, "example.test").await;
    assert_eq!(created.body["name"], "example.test");
    assert_eq!(created.body["kind"], "primary");
    assert_eq!(created.body["soa_serial"], 1);
    assert_eq!(created.body["rrsets"], 2);
    let id = created.body["id"].as_str().expect("id").to_owned();
    assert!(created.headers.contains_key(header::ETAG));

    let got = send(&router, "GET", &format!("/dns/zones/{id}"), None).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body["id"], created.body["id"]);
    assert_eq!(got.etag(), created.etag());

    create_zone(&router, "other.test").await;
    let list = send(&router, "GET", "/dns/zones", None).await;
    assert_eq!(list.status, StatusCode::OK);
    let names: Vec<&str> = list.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["example.test", "other.test"]);

    let deleted = send(&router, "DELETE", &format!("/dns/zones/{id}"), None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = send(&router, "GET", &format!("/dns/zones/{id}"), None).await;
    gone.assert_problem(404, "dns.zone.not_found");
}

#[tokio::test]
async fn the_zone_list_pages_by_cursor() {
    let router = app();
    for name in ["a.test", "b.test", "c.test"] {
        create_zone(&router, name).await;
    }
    let first = send(&router, "GET", "/dns/zones?limit=2", None).await;
    assert_eq!(first.body["items"].as_array().expect("items").len(), 2);
    let cursor = first.body["next_cursor"]
        .as_str()
        .expect("next cursor")
        .to_owned();
    let second = send(
        &router,
        "GET",
        &format!("/dns/zones?limit=2&cursor={cursor}"),
        None,
    )
    .await;
    let items = second.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "c.test");
    assert!(second.body["next_cursor"].is_null());
}

#[tokio::test]
async fn a_duplicate_or_invalid_zone_is_refused() {
    let router = app();
    create_zone(&router, "example.test").await;
    let again = send(
        &router,
        "POST",
        "/dns/zones",
        Some(zone_body("example.test")),
    )
    .await;
    again.assert_problem(409, "dns.zone.exists");

    let mut bad = zone_body("bad.test");
    bad["name_servers"] = json!([]);
    let reply = send(&router, "POST", "/dns/zones", Some(bad)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.body["code"], "dns.zone.invalid");

    let malformed = send(&router, "POST", "/dns/zones", Some(json!({"name": 3}))).await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_unknown_or_malformed_zone_id_is_refused() {
    let router = app();
    send(&router, "GET", &format!("/dns/zones/{MISSING}"), None)
        .await
        .assert_problem(404, "dns.zone.not_found");
    send(&router, "DELETE", &format!("/dns/zones/{MISSING}"), None)
        .await
        .assert_problem(404, "dns.zone.not_found");
    send(
        &router,
        "PATCH",
        &format!("/dns/zones/{MISSING}"),
        Some(json!({"description": "x"})),
    )
    .await
    .assert_problem(404, "dns.zone.not_found");
    send(&router, "GET", "/dns/zones/not-a-uuid", None)
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn a_zone_is_changed_with_its_etag() {
    let router = app();
    let created = create_zone(&router, "example.test").await;
    let id = created.body["id"].as_str().expect("id");
    let path = format!("/dns/zones/{id}");
    let etag = created.etag();

    let patched = send_with(
        &router,
        "PATCH",
        &path,
        Some(json!({"description": "main zone"})),
        &[("if-match", &etag)],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["description"], "main zone");
    assert_ne!(patched.etag(), etag);

    let soa = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"soa": {"mname": "ns2.example.test", "rname": "hostmaster.example.test"}})),
    )
    .await;
    assert_eq!(soa.status, StatusCode::OK, "{}", soa.body);
    assert_eq!(soa.body["soa_serial"], 2);
}

#[tokio::test]
async fn a_stale_if_match_is_refused_for_a_zone() {
    let router = app();
    let created = create_zone(&router, "example.test").await;
    let id = created.body["id"].as_str().expect("id");
    let path = format!("/dns/zones/{id}");
    let stale = created.etag();
    let first = send(&router, "PATCH", &path, Some(json!({"description": "one"}))).await;
    assert_eq!(first.status, StatusCode::OK);

    let refused_patch = send_with(
        &router,
        "PATCH",
        &path,
        Some(json!({"description": "two"})),
        &[("if-match", &stale)],
    )
    .await;
    assert_eq!(
        refused_patch.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        refused_patch.body
    );
    let delete = send_with(&router, "DELETE", &path, None, &[("if-match", &stale)]).await;
    assert_eq!(
        delete.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        delete.body
    );
    let current = first.etag();
    let delete = send_with(&router, "DELETE", &path, None, &[("if-match", &current)]).await;
    assert_eq!(delete.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_journal_lists_serial_steps_newest_first() {
    let router = app();
    let created = create_zone(&router, "example.test").await;
    let id = created.body["id"].as_str().expect("id");
    for host in ["www", "mail"] {
        let batch = json!({"changes": [{
            "op": "set", "name": format!("{host}.example.test"), "type": "A", "ttl": 300,
            "records": [{"type": "A", "address": "192.0.2.10"}],
        }]});
        let reply = send(
            &router,
            "POST",
            &format!("/dns/zones/{id}/records/batch"),
            Some(batch),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    }
    let journal = send(&router, "GET", &format!("/dns/zones/{id}/journal"), None).await;
    assert_eq!(journal.status, StatusCode::OK, "{}", journal.body);
    let items = journal.body["items"].as_array().expect("items");
    assert!(items.len() >= 2, "{items:?}");
    assert_eq!(items[0]["to_serial"], 3);
    assert_eq!(items[0]["from_serial"], 2);
    assert_eq!(items[0]["added"], 1);

    let page = send(
        &router,
        "GET",
        &format!("/dns/zones/{id}/journal?limit=1"),
        None,
    )
    .await;
    assert_eq!(page.body["items"].as_array().expect("items").len(), 1);
    assert!(page.body["next_cursor"].is_string());
}

#[tokio::test]
async fn the_journal_refuses_an_unknown_scope_and_zone() {
    let router = app();
    let created = create_zone(&router, "example.test").await;
    let id = created.body["id"].as_str().expect("id");
    let reply = send(
        &router,
        "GET",
        &format!("/dns/zones/{id}/journal?scope=nowhere"),
        None,
    )
    .await;
    reply.assert_problem(400, "dns.zone.invalid");
    send(
        &router,
        "GET",
        &format!("/dns/zones/{MISSING}/journal"),
        None,
    )
    .await
    .assert_problem(404, "dns.zone.not_found");
}

#[tokio::test]
async fn an_access_list_is_created_read_changed_listed_and_deleted() {
    let router = app();
    let created = send(&router, "POST", "/dns/acls", Some(acl_body("secondaries"))).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["name"], "secondaries");
    assert_eq!(created.body["used_by"], json!([]));
    let id = created.body["id"].as_str().expect("id");
    let path = format!("/dns/acls/{id}");

    let got = send(&router, "GET", &path, None).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.etag(), created.etag());

    let patched = send_with(
        &router,
        "PATCH",
        &path,
        Some(json!({"description": "peers", "entries": [{"kind": "any", "deny": true}]})),
        &[("if-match", &created.etag())],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["description"], "peers");
    assert_eq!(patched.body["entries"][0]["kind"], "any");

    send(&router, "POST", "/dns/acls", Some(acl_body("clients"))).await;
    let list = send(&router, "GET", "/dns/acls?limit=1", None).await;
    assert_eq!(list.body["items"][0]["name"], "clients");
    let cursor = list.body["next_cursor"].as_str().expect("next");
    let rest = send(
        &router,
        "GET",
        &format!("/dns/acls?limit=1&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(rest.body["items"][0]["name"], "secondaries");

    let deleted = send(&router, "DELETE", &path, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    send(&router, "GET", &path, None)
        .await
        .assert_problem(404, "dns.acl.not_found");
}

#[tokio::test]
async fn an_access_list_refuses_duplicates_bad_bodies_and_stale_deletes() {
    let router = app();
    let created = send(&router, "POST", "/dns/acls", Some(acl_body("secondaries"))).await;
    let id = created.body["id"].as_str().expect("id");
    let path = format!("/dns/acls/{id}");
    let stale = created.etag();

    let again = send(&router, "POST", "/dns/acls", Some(acl_body("secondaries"))).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{}", again.body);
    assert_eq!(again.body["code"], "sys.invalid_value");
    assert_eq!(again.body["params"]["field"], "name");

    let bad = send(
        &router,
        "POST",
        "/dns/acls",
        Some(json!({"name": "x", "entries": [{"kind": "prefix", "prefix": "nope"}]})),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    send(&router, "PATCH", &path, Some(json!({"description": "new"}))).await;
    let delete = send_with(&router, "DELETE", &path, None, &[("if-match", &stale)]).await;
    assert_eq!(
        delete.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        delete.body
    );

    send(&router, "GET", &format!("/dns/acls/{MISSING}"), None)
        .await
        .assert_problem(404, "dns.acl.not_found");
    send(&router, "GET", "/dns/acls/nope", None)
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn an_access_list_a_zone_names_stays() {
    let router = app();
    let acl = send(&router, "POST", "/dns/acls", Some(acl_body("secondaries"))).await;
    let acl_id = acl.body["id"].as_str().expect("id").to_owned();
    let mut body = zone_body("example.test");
    body["transfer"] = json!({"allow": [acl_id]});
    let zone = send(&router, "POST", "/dns/zones", Some(body)).await;
    assert_eq!(zone.status, StatusCode::CREATED, "{}", zone.body);

    let read = send(&router, "GET", &format!("/dns/acls/{acl_id}"), None).await;
    assert_eq!(read.body["used_by"], json!(["zone:example.test"]));
    let delete = send(&router, "DELETE", &format!("/dns/acls/{acl_id}"), None).await;
    delete.assert_problem(409, "dns.acl.in_use");

    let zone_id = zone.body["id"].as_str().expect("id");
    send(&router, "DELETE", &format!("/dns/zones/{zone_id}"), None).await;
    let delete = send(&router, "DELETE", &format!("/dns/acls/{acl_id}"), None).await;
    assert_eq!(delete.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn without_the_zone_service_the_routes_answer_module_disabled() {
    let (router, _) = tenko_api::api(AppState::default());
    send(&router, "GET", "/dns/zones", None)
        .await
        .assert_problem(409, "dns.module.disabled");
    send(&router, "GET", "/dns/acls", None)
        .await
        .assert_problem(409, "dns.module.disabled");
}

/// A secondary zone of `primaries`, each `(address, key)`.
fn secondary_body(name: &str, primaries: &[(&str, Option<&str>)]) -> Value {
    let primaries: Vec<Value> = primaries
        .iter()
        .map(|(address, key)| match key {
            Some(key) => json!({"address": address, "key": key}),
            None => json!({"address": address}),
        })
        .collect();
    json!({
        "name": name,
        "kind": "secondary",
        "soa": {"mname": format!("ns1.{name}"), "rname": format!("hostmaster.{name}")},
        "source": {"primaries": primaries},
    })
}

/// A TSIG key a zone or an access list names needs `dns.keys` (403, as the key routes
/// answer it); a request that names no key asks nothing of the keys.
#[tokio::test]
async fn a_named_tsig_key_needs_the_key_right() {
    // Without `dns.keys`: zones and access lists without a key are written, any key named
    // in the primaries, the NOTIFY targets or a `key` entry is refused.
    let router = app_with(Some(Arc::new(WithoutKeys)));
    create_zone(&router, "plain.example.test").await;
    let acl = send(&router, "POST", "/dns/acls", Some(acl_body("plain"))).await;
    assert_eq!(acl.status, StatusCode::CREATED, "{}", acl.body);
    let acl_id = acl.body["id"].as_str().expect("id").to_owned();
    let secondary = send(
        &router,
        "POST",
        "/dns/zones",
        Some(secondary_body("copy.example.test", &[("192.0.2.10", None)])),
    )
    .await;
    assert_eq!(secondary.status, StatusCode::CREATED, "{}", secondary.body);
    let secondary_id = secondary.body["id"].as_str().expect("id").to_owned();
    send(
        &router,
        "POST",
        "/dns/zones",
        Some(secondary_body(
            "keyed.example.test",
            &[("192.0.2.10", Some("transfer-key"))],
        )),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    let mut notified = zone_body("notified.example.test");
    notified["transfer"] = json!({"notify": [{"address": "192.0.2.54", "key": "transfer-key"}]});
    send(&router, "POST", "/dns/zones", Some(notified))
        .await
        .assert_problem(403, "auth.forbidden");
    send(
        &router,
        "PATCH",
        &format!("/dns/zones/{secondary_id}"),
        Some(json!({"source": {"primaries": [{"address": "192.0.2.10", "key": "transfer-key"}]}})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    send(
        &router,
        "PATCH",
        &format!("/dns/zones/{secondary_id}"),
        Some(json!({"transfer": {"notify": [{"address": "192.0.2.54", "key": "transfer-key"}]}})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    send(
        &router,
        "POST",
        "/dns/acls",
        Some(json!({"name": "signers", "entries": [{"kind": "key", "name": "transfer-key"}]})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    send(
        &router,
        "PATCH",
        &format!("/dns/acls/{acl_id}"),
        Some(json!({"entries": [{"kind": "key", "name": "transfer-key"}]})),
    )
    .await
    .assert_problem(403, "auth.forbidden");
    // A change that names no key still goes through.
    let described = send(
        &router,
        "PATCH",
        &format!("/dns/acls/{acl_id}"),
        Some(json!({"description": "no key"})),
    )
    .await;
    assert_eq!(described.status, StatusCode::OK, "{}", described.body);
}

/// With `dns.keys`: a key that does not exist is 404, an existing one is accepted.
#[tokio::test]
async fn a_named_tsig_key_must_exist() {
    let router = app();
    send(
        &router,
        "POST",
        "/dns/zones",
        Some(secondary_body(
            "keyed.example.test",
            &[("192.0.2.10", Some("missing-key"))],
        )),
    )
    .await
    .assert_problem(404, "dns.key.not_found");
    send(
        &router,
        "POST",
        "/dns/acls",
        Some(json!({"name": "signers", "entries": [{"kind": "key", "name": "missing-key"}]})),
    )
    .await
    .assert_problem(404, "dns.key.not_found");
    let key = send(
        &router,
        "POST",
        "/dns/keys",
        Some(json!({"name": "transfer-key"})),
    )
    .await;
    assert_eq!(key.status, StatusCode::CREATED, "{}", key.body);
    let keyed = send(
        &router,
        "POST",
        "/dns/zones",
        Some(secondary_body(
            "keyed.example.test",
            &[("192.0.2.10", Some("transfer-key"))],
        )),
    )
    .await;
    assert_eq!(keyed.status, StatusCode::CREATED, "{}", keyed.body);
    let mut notified = zone_body("notified.example.test");
    notified["transfer"] = json!({"notify": [{"address": "192.0.2.54", "key": "transfer-key"}]});
    let notified = send(&router, "POST", "/dns/zones", Some(notified)).await;
    assert_eq!(notified.status, StatusCode::CREATED, "{}", notified.body);
    let signers = send(
        &router,
        "POST",
        "/dns/acls",
        Some(json!({"name": "signers", "entries": [{"kind": "key", "name": "transfer-key"}]})),
    )
    .await;
    assert_eq!(signers.status, StatusCode::CREATED, "{}", signers.body);
    let keyed_id = keyed.body["id"].as_str().expect("id").to_owned();
    send(
        &router,
        "PATCH",
        &format!("/dns/zones/{keyed_id}"),
        Some(json!({"source": {"primaries": [{"address": "192.0.2.11", "key": "missing-key"}]}})),
    )
    .await
    .assert_problem(404, "dns.key.not_found");
}

/// The primaries of a secondary zone pass the egress policy of server-side fetches: no
/// loopback, link-local, multicast, unspecified or metadata service address.
#[tokio::test]
async fn a_primary_on_a_refused_address_is_invalid() {
    let router = app();
    for address in [
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "fd00:ec2::254",
        "224.0.0.251",
        "0.0.0.0",
        "fe80::1",
    ] {
        let reply = send(
            &router,
            "POST",
            "/dns/zones",
            Some(secondary_body(
                "copy.example.test",
                &[("192.0.2.10", None), (address, None)],
            )),
        )
        .await;
        reply.assert_problem(400, "dns.zone.invalid");
        assert_eq!(
            reply.body["params"]["field"], "source.primaries",
            "{address}"
        );
    }
    let copy = send(
        &router,
        "POST",
        "/dns/zones",
        Some(secondary_body(
            "copy.example.test",
            &[("192.0.2.10", None), ("2001:db8::53", None)],
        )),
    )
    .await;
    assert_eq!(copy.status, StatusCode::CREATED, "{}", copy.body);
    let id = copy.body["id"].as_str().expect("id").to_owned();
    let reply = send(
        &router,
        "PATCH",
        &format!("/dns/zones/{id}"),
        Some(json!({"source": {"primaries": [{"address": "127.0.0.1"}]}})),
    )
    .await;
    reply.assert_problem(400, "dns.zone.invalid");
    assert_eq!(reply.body["params"]["field"], "source.primaries");
    let unchanged = send(&router, "GET", &format!("/dns/zones/{id}"), None).await;
    assert_eq!(
        unchanged.body["source"]["primaries"][0]["address"],
        "192.0.2.10"
    );
}
