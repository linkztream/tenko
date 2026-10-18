//! The query log through the router: a real local `dns` role with a query log on a
//! temporary directory, its pages, filters and cursor, the addresses withheld from a
//! principal that may not update the node, the kill switch, and the audit records.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::Value;
use tenko_api::{routes::dns::DnsNodeSlot, state::AppState};
use tenko_core::{
    Action, Authorizer, Denied, DenyReason, NodeId, ObjectKind, ObjectRef, Principal, ScopeFilter,
    dns::{DnsName, QueryTransport},
};
use tenko_dns::{
    catalog::{Catalog, CatalogHandle},
    log::{QueryLogEntry, QueryLogSink as _},
    querylog::{ClientField, LogSettings, LogWriter},
    server::{Hooks, Server, ServerConfig},
    status::{DnsNode, LocalNode},
    store_feed::FeedProgress,
    transport::udp::UdpSettings,
    zone::{ZoneConfig, ZoneService},
};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;

const API: &str = "/api/v1";
const NODE: NodeId = NodeId(1);
const AT: u64 = 1_792_000_000_000_000;

/// Allows everything but updating a node, unless `node_update`.
struct Gate {
    node_update: bool,
}

impl Authorizer for Gate {
    fn check(
        &self,
        _principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        if action == Action::Update && object.kind == ObjectKind::Node && !self.node_update {
            return Err(Denied {
                action,
                object: *object,
                reason: DenyReason::MissingPermission,
            });
        }
        Ok(())
    }

    fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
        ScopeFilter::All
    }
}

struct Lab {
    router: Router,
    node: Arc<LocalNode>,
    dir: PathBuf,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn server() -> Server {
    Server::start_authoritative(
        ServerConfig {
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
            udp: UdpSettings {
                workers: 1,
                ..UdpSettings::default()
            },
            ..ServerConfig::default()
        },
        CatalogHandle::new(Catalog::default()),
        Hooks::default(),
    )
    .await
    .expect("server")
}

/// The queries of the log, oldest first: name, type, RCODE, client.
const QUERIES: [(&str, u16, u16, [u8; 4]); 6] = [
    ("www.example.test", 1, 0, [192, 0, 2, 10]),
    ("mail.example.test", 15, 0, [192, 0, 2, 11]),
    ("missing.example.test", 1, 3, [192, 0, 2, 10]),
    ("badexample.test", 1, 0, [198, 51, 100, 4]),
    ("www.example.test", 28, 0, [192, 0, 2, 11]),
    ("other.test", 1, 2, [192, 0, 2, 10]),
];

async fn lab(node_update: bool, client: ClientField, log_on: bool) -> Lab {
    let dir = std::env::temp_dir().join(format!("tenko-api-dns-log-{}", uuid::Uuid::now_v7()));
    let writer = LogWriter::start(LogSettings {
        client,
        ..LogSettings::new(&dir)
    })
    .expect("log");
    let sink = writer.sink();
    for (n, (name, qtype, rcode, client)) in QUERIES.iter().enumerate() {
        let qname = DnsName::new(name).expect("name").to_wire();
        sink.record(&QueryLogEntry {
            at_micros: AT + n as u64 * 1_000_000,
            client: IpAddr::from(*client),
            transport: QueryTransport::Udp,
            qname: &qname,
            qtype: *qtype,
            rcode: *rcode,
            view: None,
            blocked: None,
            cached: false,
            duration_micros: 30,
        });
    }
    writer.stop();
    let node = Arc::new(LocalNode::new(
        NODE,
        server().await,
        FeedProgress::default(),
        None,
        log_on.then(|| (sink, dir.clone())),
    ));
    let slot = DnsNodeSlot::default();
    slot.set(Arc::clone(&node) as Arc<dyn DnsNode>);
    let store = Arc::new(MemStore::default());
    let service = ZoneService::with_direct_jobs(
        Arc::clone(&store) as Arc<dyn Store>,
        None,
        ZoneConfig::default(),
    );
    let mut state = AppState::new(store as Arc<dyn Store>);
    state.authorizer = Some(Arc::new(Gate { node_update }));
    let router = tenko_api::api(state)
        .0
        .layer(Extension(service))
        .layer(Extension(slot));
    Lab { router, node, dir }
}

async fn call(router: &Router, method: &str, path: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("{API}{path}"))
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON")
    };
    (status, body)
}

async fn page(router: &Router, query: &str) -> Value {
    let (status, body) = call(router, "GET", &format!("/nodes/1/dns/log?{query}")).await;
    assert_eq!(status, StatusCode::OK, "{query}: {body}");
    body
}

fn names(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|line| line["qname"].as_str().expect("qname").to_owned())
        .collect()
}

async fn audit(router: &Router, action: &str) -> Vec<Value> {
    let (status, body) = call(router, "GET", &format!("/audit?action={action}&limit=100")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["items"].as_array().expect("records").clone()
}

#[tokio::test]
async fn pages_come_newest_first_with_a_cursor_and_every_read_is_audited() {
    let lab = lab(true, ClientField::Address, true).await;
    let first = page(&lab.router, "limit=4").await;
    assert_eq!(
        names(&first),
        [
            "other.test",
            "www.example.test",
            "badexample.test",
            "missing.example.test"
        ]
    );
    assert_eq!(first["items"][0]["client"], "192.0.2.10");
    assert_eq!(first["items"][0]["rcode"], 2);
    assert_eq!(first["items"][1]["type"], "AAAA");
    assert_eq!(first["items"][0]["duration_micros"], 30);
    let cursor = first["next_cursor"].as_str().expect("a cursor").to_owned();
    let second = page(&lab.router, &format!("limit=4&cursor={cursor}")).await;
    assert_eq!(names(&second), ["mail.example.test", "www.example.test"]);

    let records = audit(&lab.router, "dns.log.read").await;
    assert_eq!(records.len(), 2, "{records:?}");
    let text = Value::Array(records).to_string();
    assert!(text.contains("\"from_cursor\":\"newest\""), "{text}");
    assert!(
        text.contains(&format!("\"to_cursor\":\"{cursor}\"")),
        "{text}"
    );
    assert!(
        text.contains(&format!("\"from_cursor\":\"{cursor}\"")),
        "{text}"
    );
    assert!(text.contains("\"to_cursor\":\"end\""), "{text}");
}

#[tokio::test]
async fn the_filters_apply_and_are_checked() {
    let lab = lab(true, ClientField::Pseudonym, true).await;
    let under = page(&lab.router, "qname=example.test").await;
    assert_eq!(
        names(&under),
        [
            "www.example.test",
            "missing.example.test",
            "mail.example.test",
            "www.example.test"
        ]
    );
    assert_eq!(
        names(&page(&lab.router, "rcode=3").await),
        ["missing.example.test"]
    );
    let by_address = page(&lab.router, "client=192.0.2.11").await;
    assert_eq!(
        names(&by_address),
        ["www.example.test", "mail.example.test"]
    );
    let pseudonym = by_address["items"][0]["client"]
        .as_str()
        .expect("pseudonym")
        .to_owned();
    assert!(pseudonym.starts_with("p:"), "{pseudonym}");
    assert_eq!(
        names(&page(&lab.router, &format!("client={pseudonym}")).await),
        ["www.example.test", "mail.example.test"]
    );
    let window = page(
        &lab.router,
        "from=2026-10-14T17:46:41Z&until=2026-10-14T17:46:43Z",
    )
    .await;
    assert_eq!(
        names(&window),
        [
            "badexample.test",
            "missing.example.test",
            "mail.example.test"
        ]
    );
    for (query, field) in [
        ("client=somebody", "client"),
        ("rcode=5000", "rcode"),
        ("limit=0", "limit"),
        (
            "from=2026-10-14T17:46:43Z&until=2026-10-14T17:46:41Z",
            "until",
        ),
    ] {
        let (status, body) = call(&lab.router, "GET", &format!("/nodes/1/dns/log?{query}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert_eq!(body["code"], "sys.invalid_value", "{query}: {body}");
        assert_eq!(body["params"]["field"], field, "{query}: {body}");
    }
    let records = audit(&lab.router, "dns.log.read").await;
    let text = Value::Array(records).to_string();
    assert!(text.contains("\"filter.qname\":\"example.test\""), "{text}");
    assert!(text.contains("\"filter.client\":\"192.0.2.11\""), "{text}");
    assert!(text.contains("\"filter.rcode\":\"3\""), "{text}");
}

#[tokio::test]
async fn addresses_stay_on_the_node_for_a_principal_that_may_not_update_it() {
    let lab = lab(false, ClientField::Address, true).await;
    let all = page(&lab.router, "limit=10").await;
    assert_eq!(names(&all).len(), 6);
    assert!(
        all["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|line| line.get("client").is_none()),
        "{all}"
    );
    let (status, body) = call(&lab.router, "GET", "/nodes/1/dns/log?client=192.0.2.10").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let pseudonymised = lab_pseudonyms_for_viewer().await;
    assert!(pseudonymised.starts_with("p:"), "{pseudonymised}");
}

async fn lab_pseudonyms_for_viewer() -> String {
    let lab = lab(false, ClientField::Pseudonym, true).await;
    let all = page(&lab.router, "limit=1").await;
    let pseudonym = all["items"][0]["client"]
        .as_str()
        .expect("a pseudonym")
        .to_owned();
    let found = page(&lab.router, &format!("client={pseudonym}")).await;
    assert_eq!(names(&found).len(), 3, "{found}");
    pseudonym
}

#[tokio::test]
async fn the_kill_switch_stops_and_starts_the_log_and_is_audited() {
    let lab = lab(true, ClientField::Pseudonym, true).await;
    let (status, body) = call(&lab.router, "GET", "/nodes/1/dns").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["query_log"]["state"], "on", "{body}");
    assert_eq!(body["query_log"]["client"], "pseudonym");
    assert_eq!(body["query_log"]["written"], 6);
    assert_eq!(body["query_log"]["dropped"], 0);

    let (status, body) = call(&lab.router, "POST", "/nodes/1/dns/log/stop").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(body["command_id"].is_string(), "{body}");
    let (_, body) = call(&lab.router, "GET", "/nodes/1/dns").await;
    assert_eq!(body["query_log"]["state"], "stopped", "{body}");
    assert!(lab.node.status().log.expect("figures").stopped);
    assert!(lab.dir.join("stopped").exists());

    let (status, body) = call(&lab.router, "POST", "/nodes/1/dns/log/start").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (_, body) = call(&lab.router, "GET", "/nodes/1/dns").await;
    assert_eq!(body["query_log"]["state"], "on", "{body}");
    assert_eq!(audit(&lab.router, "dns.log.stop").await.len(), 1);
    assert_eq!(audit(&lab.router, "dns.log.start").await.len(), 1);
}

#[tokio::test]
async fn a_node_whose_log_is_off_answers_409() {
    let lab = lab(true, ClientField::Pseudonym, false).await;
    for (method, path) in [
        ("GET", "/nodes/1/dns/log"),
        ("POST", "/nodes/1/dns/log/stop"),
        ("POST", "/nodes/1/dns/log/start"),
    ] {
        let (status, body) = call(&lab.router, method, path).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}: {body}");
        assert_eq!(body["code"], "dns.node.not_dns", "{path}: {body}");
    }
    let (_, body) = call(&lab.router, "GET", "/nodes/1/dns").await;
    assert!(body.get("query_log").is_none(), "{body}");
    assert_eq!(audit(&lab.router, "dns.log.").await, Vec::<Value>::new());
}
