//! The DNS record operations through the router: listing, batch changes, zone file import
//! and export, over the zone service on an in-memory store.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_core::{
    RequestCtx, SystemComponent,
    dns::{DnsName, Origin, Rdata, RecordData, RrSet, Rtype, ScopeName, tables::RRSETS},
    ipam::Stamp,
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, Store, WriteBatch};
use tower::ServiceExt;

const API: &str = "/api/v1";
const PROBLEM_JSON: &str = "application/problem+json";
const MISSING: &str = "0190d1c2-0000-7000-8000-0000000000ff";

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    text: String,
}

impl Reply {
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

fn app() -> (Router, Arc<ZoneService>, Arc<MemStore>) {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(tenko_vault::MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let (router, _) = tenko_api::api(AppState::default());
    (
        router.layer(axum::Extension(Arc::clone(&service))),
        service,
        store,
    )
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
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let body = if bytes.is_empty() || !text.starts_with(['{', '[']) {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON")
    };
    Reply {
        status,
        headers,
        body,
        text,
    }
}

fn zone_body(name: &str) -> Value {
    json!({
        "name": name,
        "kind": "primary",
        "serial": "counter",
        "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"},
        "name_servers": ["ns1.example.test"],
    })
}

async fn create_zone(router: &Router, name: &str) -> String {
    let reply = send(router, "POST", "/dns/zones", Some(zone_body(name))).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    reply.body["id"].as_str().expect("id").to_owned()
}

fn set_a(name: &str, address: &str) -> Value {
    json!({
        "op": "set", "name": name, "type": "A", "ttl": 300,
        "records": [{"type": "A", "address": address}],
    })
}

async fn batch(router: &Router, id: &str, changes: Vec<Value>, query: &str) -> Reply {
    send(
        router,
        "POST",
        &format!("/dns/zones/{id}/records/batch{query}"),
        Some(json!({ "changes": changes })),
    )
    .await
}

async fn list(router: &Router, id: &str, query: &str) -> Reply {
    let reply = send(
        router,
        "GET",
        &format!("/dns/zones/{id}/records{query}"),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    reply
}

fn owners(reply: &Reply) -> Vec<String> {
    reply.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            format!(
                "{} {}",
                item["name"].as_str().expect("name"),
                item["type"].as_str().expect("type")
            )
        })
        .collect()
}

/// A zone with a few hosts: `a`, `b`, `c` as A sets and `a` also as TXT.
async fn populated(router: &Router) -> String {
    let id = create_zone(router, "example.test").await;
    let reply = batch(
        router,
        &id,
        vec![
            set_a("a.example.test", "192.0.2.1"),
            set_a("b.example.test", "192.0.2.2"),
            set_a("c.example.test", "192.0.2.3"),
            json!({"op": "set", "name": "a.example.test", "type": "TXT", "ttl": 60,
                   "records": [{"type": "TXT", "strings": ["hello"]}]}),
        ],
        "",
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    id
}

async fn put_ipam(store: &Arc<MemStore>, zone: &str, name: &str, address: &str) {
    let cx = RequestCtx::system(SystemComponent::Dns);
    let rrset = RrSet {
        zone: zone.parse().expect("zone id"),
        scope: ScopeName::DEFAULT,
        name: DnsName::new(name).expect("name"),
        rtype: Rtype::A,
        ttl: 600,
        rdata: vec![Rdata::from_data(&RecordData::A {
            address: address.parse().expect("address"),
        })],
        origin: Origin::Ipam,
        key: None,
        updated: Stamp::new(cx.now, cx.principal.clone()),
    };
    let mut write = WriteBatch::for_request(&cx);
    write
        .put_typed(&RRSETS, &rrset.key(), &rrset)
        .expect("stage");
    store.propose(write).await.expect("ipam write");
}

#[tokio::test]
async fn the_records_list_in_canonical_order_and_page_by_cursor() {
    let (router, ..) = app();
    let id = populated(&router).await;
    let all = list(&router, &id, "").await;
    assert_eq!(
        owners(&all),
        [
            "example.test NS",
            "example.test SOA",
            "a.example.test A",
            "a.example.test TXT",
            "b.example.test A",
            "c.example.test A",
        ]
    );
    let first = list(&router, &id, "?limit=2").await;
    assert_eq!(owners(&first), ["example.test NS", "example.test SOA"]);
    let mut seen = owners(&first);
    let mut cursor = first.body["next_cursor"].as_str().map(str::to_owned);
    while let Some(next) = cursor {
        let page = list(&router, &id, &format!("?limit=2&cursor={next}")).await;
        seen.extend(owners(&page));
        cursor = page.body["next_cursor"].as_str().map(str::to_owned);
    }
    assert_eq!(seen, owners(&all));
}

#[tokio::test]
async fn the_records_filter_by_name_type_and_origin() {
    let (router, _, store) = app();
    let id = populated(&router).await;
    assert_eq!(
        owners(&list(&router, &id, "?name=a").await),
        ["a.example.test A", "a.example.test TXT"]
    );
    assert_eq!(
        owners(&list(&router, &id, "?name=%40").await),
        ["example.test NS", "example.test SOA"]
    );
    assert_eq!(
        owners(&list(&router, &id, "?type=TXT").await),
        ["a.example.test TXT"]
    );
    assert_eq!(
        owners(&list(&router, &id, "?name=b&type=A").await),
        ["b.example.test A"]
    );
    assert_eq!(
        list(&router, &id, "?origin=ipam").await.body["items"],
        json!([])
    );
    put_ipam(&store, &id, "host.example.test", "192.0.2.20").await;
    let ipam = list(&router, &id, "?origin=ipam").await;
    assert_eq!(owners(&ipam), ["host.example.test A"]);
    assert_eq!(ipam.body["items"][0]["origin"], "ipam");
    assert_eq!(owners(&list(&router, &id, "?origin=manual").await).len(), 6);
}

#[tokio::test]
async fn the_record_list_refuses_bad_queries_scopes_and_zones() {
    let (router, ..) = app();
    let id = populated(&router).await;
    let reply = send(
        &router,
        "GET",
        &format!("/dns/zones/{id}/records?limit=0"),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    let reply = send(
        &router,
        "GET",
        &format!("/dns/zones/{id}/records?cursor=garbage"),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    send(
        &router,
        "GET",
        &format!("/dns/zones/{id}/records?scope=nowhere"),
        None,
    )
    .await
    .assert_problem(400, "dns.zone.invalid");
    send(
        &router,
        "GET",
        &format!("/dns/zones/{MISSING}/records"),
        None,
    )
    .await
    .assert_problem(404, "dns.zone.not_found");
    send(&router, "GET", "/dns/zones/nope/records", None)
        .await
        .assert_problem(400, "sys.invalid_request");
}

#[tokio::test]
async fn a_batch_sets_adds_removes_and_deletes_rrsets() {
    let (router, ..) = app();
    let id = create_zone(&router, "example.test").await;

    let set = batch(
        &router,
        &id,
        vec![set_a("www.example.test", "192.0.2.10")],
        "",
    )
    .await;
    assert_eq!(set.status, StatusCode::OK, "{}", set.body);
    assert_eq!(set.body["dry_run"], false);
    assert_eq!(set.body["serial"], 2);
    assert!(set.body["revision"].is_number());
    assert!(set.body["changes"][0]["before"].is_null());
    assert_eq!(set.body["changes"][0]["after"]["ttl"], 300);

    let add = batch(
        &router,
        &id,
        vec![json!({"op": "add", "name": "www.example.test", "type": "A",
                    "records": [{"type": "A", "address": "192.0.2.11"}]})],
        "",
    )
    .await;
    assert_eq!(add.status, StatusCode::OK, "{}", add.body);
    assert_eq!(add.body["serial"], 3);
    assert_eq!(
        add.body["changes"][0]["after"]["records"]
            .as_array()
            .expect("records")
            .len(),
        2
    );

    let remove = batch(
        &router,
        &id,
        vec![
            json!({"op": "remove", "name": "www.example.test", "type": "A",
                    "records": [{"type": "A", "address": "192.0.2.10"}]}),
        ],
        "",
    )
    .await;
    assert_eq!(remove.status, StatusCode::OK, "{}", remove.body);
    assert_eq!(
        remove.body["changes"][0]["after"]["records"][0]["address"],
        "192.0.2.11"
    );

    let delete = batch(
        &router,
        &id,
        vec![json!({"op": "delete", "name": "www.example.test", "type": "A"})],
        "",
    )
    .await;
    assert_eq!(delete.status, StatusCode::OK, "{}", delete.body);
    assert!(delete.body["changes"][0]["after"].is_null());
    assert_eq!(delete.body["serial"], 5);
    assert_eq!(
        owners(&list(&router, &id, "").await),
        ["example.test NS", "example.test SOA"]
    );
}

#[tokio::test]
async fn a_dry_run_batch_writes_nothing() {
    let (router, ..) = app();
    let id = create_zone(&router, "example.test").await;
    let before = list(&router, &id, "").await;
    let dry = batch(
        &router,
        &id,
        vec![set_a("www.example.test", "192.0.2.10")],
        "?dry_run=true",
    )
    .await;
    assert_eq!(dry.status, StatusCode::OK, "{}", dry.body);
    assert_eq!(dry.body["dry_run"], true);
    assert!(dry.body["revision"].is_null());
    assert_eq!(dry.body["changes"].as_array().expect("changes").len(), 1);
    assert_eq!(dry.body["changes"][0]["after"]["name"], "www.example.test");
    let after = list(&router, &id, "").await;
    assert_eq!(after.body["items"], before.body["items"]);
    let zone = send(&router, "GET", &format!("/dns/zones/{id}"), None).await;
    assert_eq!(zone.body["soa_serial"], 1);
}

#[tokio::test]
async fn an_invalid_or_conflicting_batch_is_refused_whole() {
    let (router, ..) = app();
    let id = create_zone(&router, "example.test").await;
    batch(
        &router,
        &id,
        vec![set_a("www.example.test", "192.0.2.10")],
        "",
    )
    .await;

    // A record of another type than the set.
    let invalid = batch(
        &router,
        &id,
        vec![
            set_a("ok.example.test", "192.0.2.50"),
            json!({"op": "set", "name": "bad.example.test", "type": "A", "ttl": 300,
                   "records": [{"type": "MX", "preference": 10, "exchange": "mail.example.test"}]}),
        ],
        "",
    )
    .await;
    invalid.assert_problem(400, "dns.record.invalid");

    // A name outside the zone.
    let outside = batch(
        &router,
        &id,
        vec![set_a("www.other.test", "192.0.2.51")],
        "",
    )
    .await;
    assert_eq!(outside.status, StatusCode::BAD_REQUEST, "{}", outside.body);

    // A CNAME beside the A set.
    let conflict = batch(
        &router,
        &id,
        vec![
            json!({"op": "set", "name": "www.example.test", "type": "CNAME", "ttl": 300,
                    "records": [{"type": "CNAME", "target": "host.example.test"}]}),
        ],
        "",
    )
    .await;
    conflict.assert_problem(409, "dns.record.conflict");

    // Nothing of the refused batches was written.
    assert_eq!(
        owners(&list(&router, &id, "").await),
        ["example.test NS", "example.test SOA", "www.example.test A"]
    );
    send(
        &router,
        "POST",
        &format!("/dns/zones/{MISSING}/records/batch"),
        Some(json!({"changes": []})),
    )
    .await
    .assert_problem(404, "dns.zone.not_found");
}

#[tokio::test]
async fn another_origin_needs_a_take_over() {
    let (router, _, store) = app();
    let id = create_zone(&router, "example.test").await;
    put_ipam(&store, &id, "host.example.test", "192.0.2.20").await;

    let refused = batch(
        &router,
        &id,
        vec![set_a("host.example.test", "192.0.2.21")],
        "",
    )
    .await;
    refused.assert_problem(409, "dns.record.origin");
    assert_eq!(refused.body["params"]["origin"], "ipam");

    let mut change = set_a("host.example.test", "192.0.2.21");
    change["take_over"] = json!(true);
    let taken = batch(&router, &id, vec![change], "").await;
    assert_eq!(taken.status, StatusCode::OK, "{}", taken.body);
    let after = list(&router, &id, "?name=host").await;
    assert_eq!(after.body["items"][0]["origin"], "manual");
    assert_eq!(
        after.body["items"][0]["records"][0]["address"],
        "192.0.2.21"
    );
}

const ZONE_FILE: &str = "$ORIGIN example.test.\n$TTL 300\nwww A 192.0.2.10\nwww A 192.0.2.11\nmail MX 10 mx.example.test.\n@ TXT \"hello world\"\n";

async fn import(router: &Router, id: &str, text: &str, query: &str, replace: bool) -> Reply {
    send(
        router,
        "POST",
        &format!("/dns/zones/{id}/records/import{query}"),
        Some(json!({"zone_file": text, "replace": replace})),
    )
    .await
}

#[tokio::test]
async fn a_dry_run_import_previews_without_writing() {
    let (router, ..) = app();
    let id = create_zone(&router, "example.test").await;
    let preview = import(&router, &id, ZONE_FILE, "?dry_run=true", false).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.body);
    assert_eq!(preview.body["dry_run"], true);
    assert_eq!(preview.body["added"], 3);
    assert_eq!(preview.body["losses"], json!([]));
    let types = preview.body["types"].as_array().expect("types");
    let count = |name: &str| {
        types
            .iter()
            .find(|entry| entry["rtype"] == name)
            .map(|entry| entry["records"].clone())
    };
    assert_eq!(count("A"), Some(json!(2)));
    assert_eq!(count("MX"), Some(json!(1)));
    assert_eq!(count("TXT"), Some(json!(1)));
    assert_eq!(
        owners(&list(&router, &id, "").await),
        ["example.test NS", "example.test SOA"]
    );
}

#[tokio::test]
async fn an_import_starts_a_job_that_writes_the_records() {
    let (router, service, _) = app();
    let id = create_zone(&router, "example.test").await;
    let started = import(&router, &id, ZONE_FILE, "", false).await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.body);
    let job_id = started.body["job_id"].as_str().expect("job id");
    assert_eq!(
        started.headers.get(header::LOCATION).expect("location"),
        &format!("/api/v1/jobs/{job_id}")
    );

    let job = service
        .direct_jobs()
        .expect("direct jobs")
        .job(job_id.parse().expect("job id"))
        .expect("finished job");
    let report = tenko_dns::zone::import::report_of(&job).expect("report");
    assert_eq!(report.added, 3);
    assert!(!report.dry_run);
    assert_eq!(
        owners(&list(&router, &id, "").await),
        [
            "example.test NS",
            "example.test SOA",
            "example.test TXT",
            "mail.example.test MX",
            "www.example.test A",
        ]
    );
}

#[tokio::test]
async fn a_zone_file_with_an_include_or_a_syntax_error_is_refused_with_its_line() {
    let (router, ..) = app();
    let id = create_zone(&router, "example.test").await;
    for query in ["?dry_run=true", ""] {
        let include = import(
            &router,
            &id,
            "$TTL 300\n$INCLUDE other.zone\n",
            query,
            false,
        )
        .await;
        assert_eq!(
            include.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            include.body
        );
        assert_eq!(include.body["code"], "dns.zonefile.invalid");
        assert_eq!(include.body["params"]["line"], "2");

        let syntax = import(
            &router,
            &id,
            "$TTL 300\nwww A 192.0.2.10\nwww A not-an-address\n",
            query,
            false,
        )
        .await;
        assert_eq!(
            syntax.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            syntax.body
        );
        assert_eq!(syntax.body["code"], "dns.zonefile.invalid");
        assert_eq!(syntax.body["params"]["line"], "3");
    }
    assert_eq!(
        owners(&list(&router, &id, "").await),
        ["example.test NS", "example.test SOA"]
    );
    import(&router, MISSING, ZONE_FILE, "", false)
        .await
        .assert_problem(404, "dns.zone.not_found");
}

#[tokio::test]
async fn an_export_is_a_zone_file_that_imports_to_the_same_bytes() {
    let (router, ..) = app();
    let id = populated(&router).await;
    let path = format!("/dns/zones/{id}/records/export");
    let export = send(&router, "GET", &path, None).await;
    assert_eq!(export.status, StatusCode::OK);
    assert_eq!(
        export.headers.get(header::CONTENT_TYPE).expect("type"),
        "text/dns"
    );
    assert!(
        export.text.starts_with("$ORIGIN example.test.\n"),
        "{}",
        export.text
    );
    assert!(export.text.contains("192.0.2.1"));
    assert_eq!(send(&router, "GET", &path, None).await.text, export.text);

    let second = create_zone(&router, "copy.test").await;
    let text = export
        .text
        .replace("$ORIGIN example.test.", "$ORIGIN copy.test.");
    let started = import(&router, &second, &text, "", true).await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.body);
    let copy = send(
        &router,
        "GET",
        &format!("/dns/zones/{second}/records/export"),
        None,
    )
    .await;
    assert_eq!(copy.status, StatusCode::OK);
    assert!(copy.text.starts_with("$ORIGIN copy.test.\n"));
    let body = |text: &str| text.lines().skip(1).collect::<Vec<_>>().join("\n");
    assert_eq!(body(&copy.text), body(&export.text));

    send(
        &router,
        "GET",
        &format!("/dns/zones/{MISSING}/records/export"),
        None,
    )
    .await
    .assert_problem(404, "dns.zone.not_found");
}
