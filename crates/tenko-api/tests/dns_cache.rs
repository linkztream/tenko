//! The listing of a node's cache through the router: a role whose cache holds a few
//! answers, its pages in canonical name order with a cursor, the filters, the refusals of
//! malformed parameters, and the audit record of every page read.

use std::{sync::Arc, time::Instant};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tenko_api::{routes::dns::DnsNodeSlot, state::AppState};
use tenko_core::{
    NodeId, Revision, Timestamp,
    dns::{DnsName, ViewId},
};
use tenko_dns::{
    cache::{Cache, CacheKey, CacheSettings},
    status::{self, CommandResult, DnsNode, DnsStatus, Outcome, Output},
    zone::{ZoneConfig, ZoneService},
};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;

const API: &str = "/api/v1";
const NODE: NodeId = NodeId(1);

/// A `dns` role whose cache is filled by the test; it answers `dns.cache.list` with the
/// role's own handler.
struct CacheNode {
    cache: Cache,
}

impl DnsNode for CacheNode {
    fn node(&self) -> NodeId {
        NODE
    }

    fn status(&self) -> DnsStatus {
        DnsStatus {
            // WP10.1: no recursive resolver in this test.
            recursion: None,
            validation: None,
            trust_anchors: Vec::new(),
            stripping_rules: Vec::new(),
            active_ntas: Vec::new(),
            node: NODE,
            serving: true,
            revision: Revision(0),
            lag: 0,
            zones: 0,
            rrsets: 0,
            index_bytes: 0,
            listeners: Vec::new(),
            cache_entries: u64::try_from(self.cache.len()).unwrap_or(u64::MAX),
            cache_bytes: 0,
            cache_hits: 0,
            cache_misses: 0,
            cache_stale: 0,
            problems: Vec::new(),
            started: Timestamp::now(),
            layout: None,
            log: None,
            blocked: Vec::new(),
            upstreams: Vec::new(),
            blocking_paused: None,
        }
    }

    fn execute(&self, kind: &str, args: &[u8]) -> CommandResult {
        match kind {
            status::CACHE_LIST => status::list_cache(Some(&self.cache), args),
            other => CommandResult {
                outcome: Outcome::Rejected,
                detail: format!("`{other}` is not run by this test"),
                output: Output::None,
            },
        }
    }
}

/// An upstream's answer: `qname` A 192.0.2.`last` with a TTL of 300.
fn answer(qname: &[u8], last: u8) -> Vec<u8> {
    let mut out = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    out.extend_from_slice(qname);
    out.extend_from_slice(&[0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
    out.extend_from_slice(&[192, 0, 2, last]);
    out
}

fn lab(view: ViewId) -> Router {
    let cache = Cache::new(CacheSettings::default());
    let now = Instant::now();
    for (n, (view, name)) in [
        (None, "www.example.test"),
        (None, "api.example.test"),
        (Some(view), "www.example.test"),
        (None, "badexample.test"),
        (None, "www.example.net"),
    ]
    .into_iter()
    .enumerate()
    {
        let qname = DnsName::new(name).expect("name").to_wire();
        let key = CacheKey::new(view, &qname, 1, 1);
        let last = u8::try_from(n + 1).expect("small");
        assert!(cache.insert(&key, &answer(&qname, last), now, None));
    }
    let slot = DnsNodeSlot::default();
    slot.set(Arc::new(CacheNode { cache }) as Arc<dyn DnsNode>);
    let store = Arc::new(MemStore::default());
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        None,
        ZoneConfig::default(),
    );
    tenko_api::api(AppState::new(store as Arc<dyn Store>))
        .0
        .layer(Extension(service))
        .layer(Extension(slot))
}

async fn call(router: &Router, path: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("GET")
        .uri(format!("{API}{path}"))
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

async fn page(router: &Router, query: &str) -> Value {
    let (status, body) = call(router, &format!("/nodes/1/dns/cache?{query}")).await;
    assert_eq!(status, StatusCode::OK, "{query}: {body}");
    body
}

fn names(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["name"].as_str().expect("name").to_owned())
        .collect()
}

async fn audit(router: &Router) -> Vec<Value> {
    let (status, body) = call(router, "/audit?action=dns.cache.read&limit=100").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["items"].as_array().expect("records").clone()
}

#[tokio::test]
async fn pages_come_in_canonical_order_and_every_read_is_audited() {
    let view = ViewId::generate();
    let router = lab(view);
    let first = page(&router, "limit=3").await;
    assert_eq!(
        names(&first),
        ["www.example.net", "badexample.test", "api.example.test"]
    );
    let item = &first["items"][2];
    assert_eq!(item["type"], "A");
    assert_eq!(item["rcode"], 0);
    assert_eq!(item["stale"], false);
    assert_eq!(item["hits"], 0);
    assert_eq!(item["state"], "unvalidated");
    assert!(item.get("dnssec_ok").is_none(), "{item}");
    assert!(
        item["ttl"]
            .as_u64()
            .is_some_and(|ttl| ttl > 290 && ttl <= 300),
        "{item}"
    );
    assert!(item.get("view").is_none(), "{item}");
    assert_eq!(
        item["records"],
        json!([{ "type": "A", "address": "192.0.2.2" }])
    );
    let cursor = first["next_cursor"].as_str().expect("a next page");
    let second = page(&router, &format!("limit=3&cursor={cursor}")).await;
    assert_eq!(names(&second), ["www.example.test", "www.example.test"]);
    assert!(second["items"][0].get("view").is_none());
    assert_eq!(second["items"][1]["view"], view.to_string());
    assert!(second["next_cursor"].is_null(), "{second}");

    let narrowed = page(&router, &format!("suffix=example.test&view={view}")).await;
    assert_eq!(names(&narrowed), ["www.example.test"]);
    let default = page(&router, "suffix=example.test&view=default").await;
    assert_eq!(names(&default), ["api.example.test", "www.example.test"]);

    let records = audit(&router).await;
    assert_eq!(records.len(), 4, "{records:?}");
    let text = Value::Array(records).to_string();
    for part in [
        "\"from_cursor\":\"first\"".to_owned(),
        format!("\"to_cursor\":\"{cursor}\""),
        format!("\"from_cursor\":\"{cursor}\""),
        "\"filter.suffix\":\"example.test\"".to_owned(),
        format!("\"filter.view\":\"{view}\""),
        "\"filter.view\":\"default\"".to_owned(),
        "\"entries\":\"3\"".to_owned(),
    ] {
        assert!(text.contains(&part), "{part}: {text}");
    }
}

#[tokio::test]
async fn malformed_parameters_and_unknown_nodes_are_refused() {
    let router = lab(ViewId::generate());
    for (query, field) in [
        ("limit=0", "limit"),
        ("limit=1001", "limit"),
        ("suffix=a..b", "suffix"),
        ("view=lan", "view"),
        ("cursor=zz", "cursor"),
    ] {
        let (status, body) = call(&router, &format!("/nodes/1/dns/cache?{query}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert_eq!(body["code"], "sys.invalid_value", "{query}: {body}");
        assert_eq!(body["params"]["field"], field, "{query}: {body}");
    }
    let (status, body) = call(&router, "/nodes/7/dns/cache").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "cluster.node.not_found");
    assert_eq!(audit(&router).await, Vec::<Value>::new());
}
