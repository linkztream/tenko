//! The blocking view through the router: the figures counted from a real local `dns` role's
//! query log, the addresses withheld from a principal that may not update the node, the
//! pause and its end, allow from the log into a created allow list, the audit records, and
//! the upstreams' figures on the node status and the forwarding rules.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::{routes::dns::DnsNodeSlot, state::AppState};
use tenko_core::{
    Action, Authorizer, Denied, DenyReason, NodeId, ObjectKind, ObjectRef, Principal, ScopeFilter,
    Timestamp,
    dns::{BlockListId, DnsName, QueryTransport},
};
use tenko_dns::{
    catalog::{Catalog, CatalogHandle},
    lists::{CompileStep, ListStaging},
    log::{QueryLogEntry, QueryLogSink as _},
    querylog::{ClientField, LogSettings, LogWriter},
    server::{Hooks, Server, ServerConfig},
    status::{DnsNode, LocalNode},
    store_feed::FeedProgress,
    transport::udp::UdpSettings,
    zone::{DirectJobs, ImportStaging, ZoneConfig, ZoneJobs, ZoneService},
};
use tenko_jobs::JobState;
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store};
use tower::ServiceExt;

const API: &str = "/api/v1";
const NODE: NodeId = NodeId(1);

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
    store: Arc<MemStore>,
    jobs: Arc<DirectJobs>,
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

/// The list the log names as the blocker.
fn ads() -> BlockListId {
    "0190d1c2-0000-7000-8000-0000000000aa".parse().expect("id")
}

/// The queries of the log, oldest first, a minute apart: name, client, blocked.
const QUERIES: [(&str, [u8; 4], bool); 6] = [
    ("www.example.test", [192, 0, 2, 10], false),
    ("ads.example.test", [192, 0, 2, 10], true),
    ("ads.example.test", [192, 0, 2, 11], true),
    ("tracker.example.test", [192, 0, 2, 10], true),
    ("mail.example.test", [192, 0, 2, 11], false),
    ("www.example.test", [192, 0, 2, 10], false),
];

async fn lab(node_update: bool, log_on: bool) -> Lab {
    let dir = std::env::temp_dir().join(format!("tenko-api-dns-blocking-{}", uuid::Uuid::now_v7()));
    let writer = LogWriter::start(LogSettings {
        client: ClientField::Address,
        ..LogSettings::new(&dir)
    })
    .expect("log");
    let sink = writer.sink();
    // The queries of the last hour.
    let now = u64::try_from(Timestamp::now().unix_nanos() / 1_000).expect("now");
    let start = now - 3_600_000_000;
    for (n, (name, client, blocked)) in QUERIES.iter().enumerate() {
        let qname = DnsName::new(name).expect("name").to_wire();
        sink.record(&QueryLogEntry {
            at_micros: start + n as u64 * 60_000_000,
            client: IpAddr::from(*client),
            transport: QueryTransport::Udp,
            qname: &qname,
            qtype: 1,
            rcode: if *blocked { 3 } else { 0 },
            view: None,
            blocked: blocked.then(ads),
            cached: n == 5,
            duration_micros: 30,
            // WP10.1: the resolution of the log line.
            resolution: None,
            subqueries: 0,
            validation: None,
            ede: None,
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
    slot.set(node as Arc<dyn DnsNode>);
    let store = Arc::new(MemStore::default());
    let import_staging = Arc::new(ImportStaging::default());
    let list_staging = Arc::new(ListStaging::default());
    let mut direct = DirectJobs::new(Arc::clone(&store) as Arc<dyn Store>);
    for handler in tenko_dns::zone::step_handlers(&import_staging) {
        direct.register(handler);
    }
    direct.register(Arc::new(CompileStep::new(None, Arc::clone(&list_staging))));
    let jobs = Arc::new(direct);
    let service = ZoneService::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Arc::clone(&jobs) as Arc<dyn ZoneJobs>,
        None,
        import_staging,
        ZoneConfig::default(),
    );
    let mut state = AppState::new(Arc::clone(&store) as Arc<dyn Store>);
    state.authorizer = Some(Arc::new(Gate { node_update }));
    let router = tenko_api::api(state)
        .0
        .layer(Extension(service))
        .layer(Extension(list_staging))
        .layer(Extension(slot));
    Lab {
        router,
        store,
        jobs,
        dir,
    }
}

async fn call(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(format!("{API}{path}"));
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
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

/// The audit actions in the store, in order.
async fn audit_actions(store: &MemStore) -> Vec<String> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(
        &tenko_store::tables::AUDIT,
        KeyRange::all(),
        usize::MAX,
        false,
    )
    .expect("audit")
    .into_iter()
    .map(|(_, record, _)| record.draft.action.as_str().to_owned())
    .collect()
}

#[tokio::test]
async fn the_figures_count_the_log_per_list_client_and_hour() {
    let lab = lab(true, true).await;
    let (status, body) = call(&lab.router, "GET", "/dns/blocking/stats", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["window"], "24h");
    assert_eq!(body["queries"], 6, "{body}");
    assert_eq!(body["blocked"], 3);
    assert_eq!(body["cached"], 1);
    assert_eq!(body["clients"], 2);
    assert_eq!(body["blocked_share"], 0.5);
    assert_eq!(body["log_client"], "address");
    let hours = body["hours"].as_array().expect("hours");
    assert!((24..=25).contains(&hours.len()), "{}", hours.len());
    let total: u64 = hours
        .iter()
        .map(|hour| hour["queries"].as_u64().expect("count"))
        .sum();
    assert_eq!(total, 6);
    assert_eq!(body["lists"][0]["list"], ads().to_string());
    assert_eq!(body["lists"][0]["blocked"], 3);
    // A list no row names any more has no name.
    assert!(body["lists"][0].get("name").is_none(), "{body}");
    assert_eq!(body["top_blocked"][0]["name"], "ads.example.test");
    assert_eq!(body["top_blocked"][0]["blocked"], 2);
    assert_eq!(body["top_names"][0]["queries"], 2);
    assert_eq!(body["top_clients"][0]["client"], "192.0.2.10");
    assert_eq!(body["top_clients"][0]["queries"], 4);
    assert_eq!(body["top_clients"][0]["blocked"], 2);
    let recent = body["recent_blocked"].as_array().expect("recent");
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0]["qname"], "tracker.example.test", "newest first");
    assert!(body.get("paused").is_none());
    assert_eq!(body["truncated"], false);
    let (status, week) = call(
        &lab.router,
        "GET",
        "/dns/blocking/stats?window=7d&top=1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{week}");
    assert_eq!(week["window"], "7d");
    assert_eq!(week["queries"], 6);
    assert_eq!(week["top_names"].as_array().expect("top").len(), 1);
    assert_eq!(
        audit_actions(&lab.store)
            .await
            .iter()
            .filter(|action| *action == "dns.blocking.stats")
            .count(),
        2
    );
    let (status, refused) = call(&lab.router, "GET", "/dns/blocking/stats?top=0", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
}

#[tokio::test]
async fn addresses_are_withheld_without_the_right_to_update_the_node() {
    let lab = lab(false, true).await;
    let (status, body) = call(&lab.router, "GET", "/dns/blocking/stats", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["queries"], 6);
    assert!(body["top_clients"][0].get("client").is_none(), "{body}");
    assert!(body["recent_blocked"][0].get("client").is_none(), "{body}");
}

#[tokio::test]
async fn a_node_without_its_log_answers_log_off() {
    let lab = lab(true, false).await;
    let (status, body) = call(&lab.router, "GET", "/dns/blocking/stats", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "dns.blocking.log_off");
}

// The pause is one state of the process: one test holds it from start to end.
#[tokio::test]
async fn the_pause_starts_shows_and_ends_with_audit_records() {
    let lab = lab(true, true).await;
    let (status, refused) = call(
        &lab.router,
        "POST",
        "/dns/blocking/pause",
        Some(json!({"minutes": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let (status, paused) = call(
        &lab.router,
        "POST",
        "/dns/blocking/pause",
        Some(json!({"minutes": 15})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{paused}");
    assert_eq!(paused["node"], 1);
    let since = paused["paused"]["since"].as_str().expect("since");
    let until = paused["paused"]["until"].as_str().expect("until");
    assert!(until > since, "{paused}");
    let (_, status_body) = call(&lab.router, "GET", "/nodes/1/dns", None).await;
    assert_eq!(status_body["blocking_paused"]["until"], until);
    let (_, figures) = call(&lab.router, "GET", "/dns/blocking/stats", None).await;
    assert_eq!(figures["paused"]["until"], until);
    let (status, open) = call(&lab.router, "POST", "/dns/blocking/pause", Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{open}");
    assert!(open["paused"]["since"].is_string(), "{open}");
    assert!(
        open["paused"].get("until").is_none(),
        "until resumed: {open}"
    );
    let (status, resumed) = call(&lab.router, "DELETE", "/dns/blocking/pause", None).await;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    assert!(resumed.get("paused").is_none(), "{resumed}");
    let (_, status_body) = call(&lab.router, "GET", "/nodes/1/dns", None).await;
    assert!(
        status_body.get("blocking_paused").is_none(),
        "{status_body}"
    );
    let actions = audit_actions(&lab.store).await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "dns.blocking.pause")
            .count(),
        2,
        "{actions:?}"
    );
    assert!(actions.contains(&"dns.blocking.resume".to_owned()));

    let viewer = lab_router_without_update().await;
    let (status, _) = call(&viewer.router, "DELETE", "/dns/blocking/pause", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

async fn lab_router_without_update() -> Lab {
    lab(false, true).await
}

#[tokio::test]
async fn allow_from_the_log_adds_the_name_to_the_allow_list() {
    let lab = lab(true, true).await;
    let (status, first) = call(
        &lab.router,
        "POST",
        "/dns/blocking/allow",
        Some(json!({"name": "ads.example.test"})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    assert_eq!(first["list_name"], "allowed");
    assert_eq!(first["created"], true);
    assert_eq!(first["already"], false);
    let job = first["job"].as_str().expect("job").parse().expect("job id");
    let finished = lab.jobs.job(job).expect("job ran");
    assert_eq!(finished.state, JobState::Succeeded, "{finished:?}");
    let list = first["list"].as_str().expect("list").to_owned();
    let (_, read) = call(&lab.router, "GET", &format!("/dns/lists/{list}"), None).await;
    assert_eq!(read["kind"], "allow", "{read}");
    assert_eq!(read["version"]["entries"], 1, "{read}");

    let (status, second) = call(
        &lab.router,
        "POST",
        "/dns/blocking/allow",
        Some(json!({"name": "tracker.example.test", "list": list})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{second}");
    assert_eq!(second["created"], false);
    let (_, read) = call(&lab.router, "GET", &format!("/dns/lists/{list}"), None).await;
    assert_eq!(
        read["version"]["entries"], 2,
        "the first name stays: {read}"
    );

    // A name under an allowed name is covered already.
    let (status, again) = call(
        &lab.router,
        "POST",
        "/dns/blocking/allow",
        Some(json!({"name": "cdn.ads.example.test"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["already"], true);
    assert!(again.get("job").is_none());

    let actions = audit_actions(&lab.store).await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "dns.blocking.allow")
            .count(),
        2,
        "{actions:?}"
    );
    assert!(actions.contains(&"dns.list.create".to_owned()));

    // A block list is no target.
    let (status, block) = call(
        &lab.router,
        "POST",
        "/dns/lists",
        Some(json!({"name": "ads", "source": {"kind": "upload"}, "format": "domains"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{block}");
    let (status, refused) = call(
        &lab.router,
        "POST",
        "/dns/blocking/allow",
        Some(json!({"name": "ads.example.test", "list": block["id"]})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "dns.list.invalid");
}

#[tokio::test]
async fn the_node_status_carries_the_upstreams_and_the_pause() {
    let lab = lab(true, true).await;
    let (status, body) = call(&lab.router, "GET", "/nodes/1/dns", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A role without a forwarder has no upstreams.
    assert_eq!(body["upstreams"], json!([]));
}
