//! The fields the recursive resolver adds to forwarding rules and views (WP10.0), through the
//! router over the zone service on an in-memory store: the defaults show in the answers, and
//! until WP10.1, WP10.2 and WP10.4 build them the other values answer 501 and write nothing.
//! The `node_routes` module (WP10.1) tests the status, the priming and the infrastructure
//! cache of a node.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use tenko_api::state::AppState;
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{MemStore, Store};
use tower::ServiceExt;

const API: &str = "/api/v1";
const PROBLEM_JSON: &str = "application/problem+json";

struct Reply {
    status: StatusCode,
    content_type: Option<String>,
    body: Value,
}

impl Reply {
    #[track_caller]
    fn assert_not_implemented(&self, method: &str, path: &str) {
        assert_eq!(self.status, StatusCode::NOT_IMPLEMENTED, "{}", self.body);
        assert_eq!(self.content_type.as_deref(), Some(PROBLEM_JSON));
        assert_eq!(self.body["code"], "sys.not_implemented", "{}", self.body);
        assert_eq!(self.body["params"]["method"], method, "{}", self.body);
        assert_eq!(
            self.body["params"]["path"],
            format!("{API}{path}"),
            "{}",
            self.body
        );
    }
}

fn app() -> Router {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(tenko_vault::MemVault::with_store(Arc::clone(&store)));
    let service = ZoneService::with_direct_jobs(
        store as Arc<dyn Store>,
        Some(vault as Arc<dyn tenko_vault::Vault>),
        ZoneConfig::default(),
    );
    let (router, _) = tenko_api::api(AppState::default());
    router.layer(axum::Extension(service))
}

async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
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
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().expect("text").to_owned());
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
        content_type,
        body,
    }
}

async fn items(router: &Router, path: &str) -> Vec<Value> {
    let list = send(router, "GET", path, None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    list.body["items"].as_array().expect("items").clone()
}

#[tokio::test]
async fn a_rule_created_as_before_shows_the_defaults() {
    let router = app();
    let created = send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({"suffix": "example.net", "upstreams": [{"address": "192.0.2.53"}]})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["mode"], "forward");
    assert_eq!(created.body["validate"], true);

    // The defaults named in the request are the same rule.
    let named = send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({
            "suffix": "example.org",
            "mode": "forward",
            "validate": true,
            "upstreams": [{"address": "192.0.2.53"}]
        })),
    )
    .await;
    assert_eq!(named.status, StatusCode::CREATED, "{}", named.body);
    assert_eq!(named.body["mode"], "forward");
    assert_eq!(named.body["validate"], true);
}

#[tokio::test]
async fn a_recurse_rule_and_validate_false_answer_501_and_write_nothing() {
    let router = app();
    // A recurse rule names no upstream: the field may be absent.
    send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({"suffix": "example.net", "mode": "recurse"})),
    )
    .await
    .assert_not_implemented("POST", "/dns/forwarders");
    send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({
            "suffix": "example.net",
            "validate": false,
            "upstreams": [{"address": "192.0.2.53"}]
        })),
    )
    .await
    .assert_not_implemented("POST", "/dns/forwarders");
    assert_eq!(items(&router, "/dns/forwarders").await, Vec::<Value>::new());

    let created = send(
        &router,
        "POST",
        "/dns/forwarders",
        Some(json!({"suffix": "example.net", "upstreams": [{"address": "192.0.2.53"}]})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let path = format!(
        "/dns/forwarders/{}",
        created.body["id"].as_str().expect("id")
    );
    for patch in [json!({"mode": "recurse"}), json!({"validate": false})] {
        send(&router, "PATCH", &path, Some(patch))
            .await
            .assert_not_implemented("PATCH", "/dns/forwarders/{id}");
    }
    let got = send(&router, "GET", &path, None).await;
    assert_eq!(got.body, created.body);

    // The defaults are accepted in a patch.
    let patched = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"mode": "forward", "validate": true, "description": "kept"})),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["mode"], "forward");
    assert_eq!(patched.body["validate"], true);
}

#[tokio::test]
async fn a_view_resolution_answers_501_and_writes_nothing() {
    let router = app();
    send(
        &router,
        "POST",
        "/dns/views",
        Some(json!({"name": "lan", "order": 1, "resolution": "recurse"})),
    )
    .await
    .assert_not_implemented("POST", "/dns/views");
    assert_eq!(items(&router, "/dns/views").await, Vec::<Value>::new());

    let created = send(
        &router,
        "POST",
        "/dns/views",
        Some(json!({"name": "lan", "order": 1})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert!(created.body.get("resolution").is_none(), "{}", created.body);
    let path = format!("/dns/views/{}", created.body["id"].as_str().expect("id"));
    for patch in [
        json!({"resolution": "refuse"}),
        json!({"default_resolution": true}),
    ] {
        send(&router, "PATCH", &path, Some(patch))
            .await
            .assert_not_implemented("PATCH", "/dns/views/{id}");
    }
    let got = send(&router, "GET", &path, None).await;
    assert_eq!(got.body, created.body);

    // `default_resolution: false` is the absent field.
    let patched = send(
        &router,
        "PATCH",
        &path,
        Some(json!({"default_resolution": false, "description": "kept"})),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["description"], "kept");
}

// WP10.1: the node routes of the recursive resolver (the status, the priming and the
// infrastructure cache) through the router, over a fake `dns` role whose status carries a
// recursion report and whose commands answer like the engine's.
mod node_routes {
    use std::{
        net::IpAddr,
        sync::{Arc, Mutex, PoisonError},
        time::Duration,
    };

    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use tenko_api::{routes::dns::DnsNodeSlot, state::AppState};
    use tenko_cluster::node_sync::commands;
    use tenko_core::{
        Action, Authorizer, Denied, DenyReason, NodeId, ObjectKind, ObjectRef, Principal, Revision,
        ScopeFilter, Timestamp, codec::from_cbor, dns::DnsName,
    };
    use tenko_dns::{
        infra::ServerFigures,
        recurse::{
            CounterValues, InfraAddressView, InfraCutView, InfraServerView, PrimingReport,
            RecursionReport, RootServer,
        },
        recursion::{AddressOrigin, InfraSizes, WorkBudget, infra::EdnsSupport},
        status::{
            self, CommandResult, DnsNode, DnsStatus, InfraFlushArgs, InfraListArgs, InfraPage,
            Outcome, Output,
        },
        zone::{ZoneConfig, ZoneService},
    };
    use tenko_store::{MemStore, ReadConsistency, Store};
    use tower::ServiceExt;

    use super::API;

    const NODE: NodeId = NodeId(1);

    /// Allows everything but what `read` and `write` withhold: reading anything, updating a
    /// node and executing on the zone kind.
    struct Gate {
        read: bool,
        write: bool,
    }

    impl Authorizer for Gate {
        fn check(
            &self,
            _principal: &Principal,
            action: Action,
            object: &ObjectRef,
        ) -> Result<(), Denied> {
            let allowed = match action {
                Action::Read => self.read,
                Action::Update | Action::Execute => self.write,
                _ => true,
            };
            if allowed {
                Ok(())
            } else {
                Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::MissingPermission,
                })
            }
        }

        fn scope(&self, _principal: &Principal, _action: Action, _kind: ObjectKind) -> ScopeFilter {
            ScopeFilter::All
        }
    }

    /// A `dns` role with (or without) a resolver; it remembers the commands it ran.
    struct Resolver {
        report: Option<RecursionReport>,
        cuts: Vec<InfraCutView>,
        ran: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl Resolver {
        fn ran(&self) -> Vec<(String, Vec<u8>)> {
            self.ran
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    fn done(detail: &str, output: Output) -> CommandResult {
        CommandResult {
            outcome: Outcome::Done,
            detail: detail.to_owned(),
            output,
        }
    }

    impl DnsNode for Resolver {
        fn node(&self) -> NodeId {
            NODE
        }

        fn status(&self) -> DnsStatus {
            DnsStatus {
                recursion: self.report.clone(),
                node: NODE,
                serving: true,
                revision: Revision(0),
                lag: 0,
                zones: 0,
                rrsets: 0,
                index_bytes: 0,
                listeners: Vec::new(),
                cache_entries: 0,
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
            self.ran
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((kind.to_owned(), args.to_vec()));
            match kind {
                status::RECURSION_PRIME => done("the priming of the root starts now", Output::None),
                status::INFRA_LIST => {
                    let args: InfraListArgs = if args.is_empty() {
                        InfraListArgs::default()
                    } else {
                        from_cbor(args).expect("arguments")
                    };
                    let suffix = args
                        .suffix
                        .map(|suffix| DnsName::new(&suffix).expect("suffix"));
                    let after = args.after.map(|after| DnsName::new(&after).expect("after"));
                    let limit = usize::try_from(args.limit).expect("limit");
                    // The fake keeps its cuts in the order the test wants them listed and
                    // continues after the cursor's position.
                    let start = after.as_ref().map_or(0, |after| {
                        self.cuts
                            .iter()
                            .position(|cut| cut.zone == *after)
                            .map_or(self.cuts.len(), |at| at + 1)
                    });
                    let cuts: Vec<InfraCutView> = self.cuts[start..]
                        .iter()
                        .filter(|cut| {
                            suffix
                                .as_ref()
                                .is_none_or(|suffix| cut.zone.is_subdomain_of(suffix))
                        })
                        .take(limit)
                        .cloned()
                        .collect();
                    let next = (cuts.len() == limit)
                        .then(|| cuts.last().map(|cut| cut.zone.as_str().to_owned()))
                        .flatten();
                    done("cuts", Output::Infra(Box::new(InfraPage { cuts, next })))
                }
                status::INFRA_FLUSH => {
                    let args: InfraFlushArgs = if args.is_empty() {
                        InfraFlushArgs::default()
                    } else {
                        from_cbor(args).expect("arguments")
                    };
                    match args.suffix {
                        None => done(
                            "7 entries removed; the root is primed again",
                            Output::Flushed(7),
                        ),
                        Some(suffix) => done(
                            &format!("2 entries at or below {suffix} removed"),
                            Output::Flushed(2),
                        ),
                    }
                }
                other => CommandResult {
                    outcome: Outcome::Rejected,
                    detail: format!("`{other}` is not run by this test"),
                    output: Output::None,
                },
            }
        }
    }

    fn name(text: &str) -> DnsName {
        DnsName::new(text).expect("name")
    }

    fn report() -> RecursionReport {
        RecursionReport {
            hints_source: "shipped".to_owned(),
            hints_date: "2026-01-31".to_owned(),
            priming: Some(PrimingReport {
                at: Timestamp::now(),
                ok: true,
                duration: Duration::from_millis(42),
            }),
            root_expires_in: Some(Duration::from_secs(518_400)),
            root: vec![
                RootServer {
                    name: name("a.root-servers.test"),
                    address: "192.0.2.1".parse::<IpAddr>().expect("address"),
                    srtt: Some(Duration::from_micros(12_500)),
                },
                RootServer {
                    name: name("b.root-servers.test"),
                    address: "2001:db8::2".parse::<IpAddr>().expect("address"),
                    srtt: None,
                },
            ],
            infra: InfraSizes {
                cuts: 3,
                servers: 5,
                names: 4,
            },
            infra_bounds: (10_000, 50_000),
            counters: CounterValues {
                answered: 100,
                servfail: 7,
                budget: 3,
                timeout: 2,
                local: 11,
                failure_hits: 5,
                joined: 9,
                subqueries: 420,
                bound_queries: 1,
                bound_restarts: 2,
                bound_depth: 3,
                bound_time: 4,
                primings_ok: 6,
                primings_failed: 1,
                unwanted: 8,
                unwanted_flushes: 12,
            },
            budget: WorkBudget::DEFAULT,
            problems: vec!["priming_failed".to_owned()],
        }
    }

    fn address(last: u8, edns: EdnsSupport) -> InfraAddressView {
        InfraAddressView {
            address: IpAddr::from([192, 0, 2, last]),
            origin: AddressOrigin::Glue,
            ttl: 3_600,
            figures: ServerFigures {
                srtt: Some(Duration::from_micros(20_250)),
                p50: Some(Duration::from_millis(18)),
                p99: Some(Duration::from_millis(90)),
                failures: 2,
                down: true,
                lower_case: true,
                unwanted: 3,
                ..ServerFigures::default()
            },
            edns,
            tcp_only: true,
            lame: false,
        }
    }

    fn cut(zone: &str, servers: &[(&str, Vec<InfraAddressView>)]) -> InfraCutView {
        InfraCutView {
            zone: name(zone),
            servers: servers
                .iter()
                .map(|(server, addresses)| InfraServerView {
                    name: name(server),
                    addresses: addresses.clone(),
                })
                .collect(),
            ds: "unknown",
            ttl: 7_200,
        }
    }

    fn cuts() -> Vec<InfraCutView> {
        vec![
            cut(
                "example.test",
                &[(
                    "ns1.example.test",
                    vec![
                        address(1, EdnsSupport::Yes),
                        address(2, EdnsSupport::No),
                        InfraAddressView {
                            figures: ServerFigures::default(),
                            tcp_only: false,
                            ..address(3, EdnsSupport::Unknown)
                        },
                    ],
                )],
            ),
            cut("example.org", &[("ns.example.org", Vec::new())]),
            cut("sub.example.test", &[]),
            cut("test", &[]),
        ]
    }

    struct Lab {
        router: Router,
        role: Arc<Resolver>,
        store: Arc<MemStore>,
    }

    fn lab(report: Option<RecursionReport>, gate: Gate) -> Lab {
        let role = Arc::new(Resolver {
            report,
            cuts: cuts(),
            ran: Mutex::default(),
        });
        let slot = DnsNodeSlot::default();
        slot.set(Arc::clone(&role) as Arc<dyn DnsNode>);
        let store = Arc::new(MemStore::default());
        let service = ZoneService::with_direct_jobs(
            Arc::clone(&store) as Arc<dyn Store>,
            None,
            ZoneConfig::default(),
        );
        let mut state = AppState::new(Arc::clone(&store) as Arc<dyn Store>);
        state.authorizer = Some(Arc::new(gate));
        let router = tenko_api::api(state)
            .0
            .layer(Extension(service))
            .layer(Extension(slot));
        Lab {
            router,
            role,
            store,
        }
    }

    fn open(report: Option<RecursionReport>) -> Lab {
        lab(
            report,
            Gate {
                read: true,
                write: true,
            },
        )
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
        (status, serde_json::from_slice(&bytes).expect("JSON"))
    }

    /// The commands recorded for the node, oldest first: id, kind, state, detail.
    async fn rows(lab: &Lab) -> Vec<(String, String, String, String)> {
        let view = lab.store.read(ReadConsistency::Local).await.expect("view");
        commands::of_node(view.as_ref(), NODE)
            .expect("commands")
            .into_iter()
            .map(|(record, _)| {
                (
                    record.id.to_string(),
                    record.kind,
                    record.state.as_str().to_owned(),
                    record.detail.unwrap_or_default(),
                )
            })
            .collect()
    }

    async fn audit(lab: &Lab, action: &str) -> Vec<Value> {
        let (status, body) = call(
            &lab.router,
            "GET",
            &format!("/audit?action={action}&limit=100"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["items"].as_array().expect("records").clone()
    }

    #[tokio::test]
    async fn a_node_without_a_resolver_reads_as_off() {
        let lab = open(None);
        let (status, body) = call(&lab.router, "GET", "/nodes/1/dns/recursion").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["enabled"], false);
        assert_eq!(body["hints_source"], "");
        assert_eq!(body["root_servers"], json!([]));
        assert_eq!(body["trust_anchors"], json!([]));
        assert_eq!(body["problems"], json!([]));
        assert_eq!(body["infra"]["zones"], 0);
        assert_eq!(body["infra"]["max_zones"], 0);
        assert_eq!(body["budget"]["queries"], 0);
        assert_eq!(body["counters"]["answered"], 0);
        assert!(body.get("last_priming").is_none(), "{body}");
        assert!(body.get("root_expires_secs").is_none(), "{body}");
    }

    #[tokio::test]
    async fn the_status_maps_the_report() {
        let lab = open(Some(report()));
        let (status, body) = call(&lab.router, "GET", "/nodes/1/dns/recursion").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["enabled"], true);
        assert_eq!(body["hints_source"], "shipped");
        assert_eq!(body["hints_date"], "2026-01-31");
        assert_eq!(body["last_priming"]["outcome"], "ok");
        assert_eq!(body["last_priming"]["duration_ms"], 42.0);
        assert!(body["last_priming"]["at"].is_string(), "{body}");
        assert_eq!(body["root_expires_secs"], 518_400);
        let roots = body["root_servers"].as_array().expect("roots");
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0]["address"], "192.0.2.1");
        assert_eq!(roots[0]["srtt_ms"], 12.5);
        assert_eq!(roots[1]["address"], "2001:db8::2");
        assert!(roots[1].get("srtt_ms").is_none(), "{body}");
        assert_eq!(
            body["infra"],
            json!({"zones": 3, "max_zones": 10_000, "servers": 5, "max_servers": 50_000, "names": 4})
        );
        assert_eq!(
            body["budget"],
            json!({"queries": 32, "restarts": 8, "depth": 6, "attempts": 3, "wall_ms": 10_000})
        );
        let counters = &body["counters"];
        for (field, value) in [
            ("answered", 100),
            ("servfail", 7),
            ("budget", 3),
            ("timeout", 2),
            ("local", 11),
            ("failure_cache_hits", 5),
            ("joined", 9),
            ("subqueries", 420),
            ("budget_queries", 1),
            ("budget_restarts", 2),
            ("budget_depth", 3),
            ("budget_time", 4),
            ("primings_ok", 6),
            ("primings_failed", 1),
            ("unwanted", 8),
            ("unwanted_flushes", 12),
            ("secure", 0),
            ("insecure", 0),
            ("bogus", 0),
            ("indeterminate", 0),
        ] {
            assert_eq!(counters[field], value, "{field}: {body}");
        }
        assert_eq!(body["trust_anchors"], json!([]));
        assert_eq!(body["problems"], json!(["priming_failed"]));
        // A read of the status is not a node command.
        assert_eq!(lab.role.ran(), []);
    }

    #[tokio::test]
    async fn priming_is_a_recorded_and_audited_command() {
        let lab = open(Some(report()));
        let (status, body) = call(&lab.router, "POST", "/nodes/1/dns/recursion/prime").await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = body["command_id"].as_str().expect("command id").to_owned();
        assert_eq!(
            lab.role.ran(),
            [(status::RECURSION_PRIME.to_owned(), Vec::new())]
        );
        assert_eq!(
            rows(&lab).await,
            [(
                id,
                "dns.recursion.prime".to_owned(),
                "done".to_owned(),
                "the priming of the root starts now".to_owned()
            )]
        );
        let records = audit(&lab, "dns.recursion.prime").await;
        assert_eq!(records.len(), 1, "{records:?}");
        assert!(
            records[0]
                .to_string()
                .contains("the priming of the root starts now"),
            "{records:?}"
        );
    }

    #[tokio::test]
    async fn the_commands_of_a_node_without_a_resolver_answer_409() {
        let lab = open(None);
        for (method, path) in [
            ("POST", "/nodes/1/dns/recursion/prime"),
            ("GET", "/nodes/1/dns/infra"),
            ("POST", "/nodes/1/dns/infra/flush"),
        ] {
            let (status, body) = call(&lab.router, method, path).await;
            assert_eq!(status, StatusCode::CONFLICT, "{path}: {body}");
            assert_eq!(body["code"], "dns.recursion.disabled", "{path}: {body}");
        }
        assert_eq!(lab.role.ran(), []);
        assert_eq!(rows(&lab).await, []);
        for action in ["dns.recursion.prime", "dns.infra.flush"] {
            assert_eq!(audit(&lab, action).await, Vec::<Value>::new());
        }
    }

    fn zones(page: &Value) -> Vec<String> {
        page["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["zone"].as_str().expect("zone").to_owned())
            .collect()
    }

    #[tokio::test]
    async fn the_infrastructure_cache_is_listed_in_pages_and_recorded_without_audit() {
        let lab = open(Some(report()));
        let (status, first) = call(&lab.router, "GET", "/nodes/1/dns/infra?limit=2").await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(zones(&first), ["example.test", "example.org"]);
        let cursor = first["next_cursor"]
            .as_str()
            .expect("a next page")
            .to_owned();
        assert_eq!(cursor, "example.org");

        let item = &first["items"][0];
        assert_eq!(item["ds"], "unknown");
        assert_eq!(item["ttl"], 7_200);
        assert_eq!(item["servers"][0]["name"], "ns1.example.test");
        let addresses = item["servers"][0]["addresses"]
            .as_array()
            .expect("addresses");
        assert_eq!(addresses.len(), 3);
        assert_eq!(
            addresses[0],
            json!({
                "address": "192.0.2.1",
                "origin": "glue",
                "ttl": 3_600,
                "srtt_ms": 20.25,
                "p50_ms": 18.0,
                "p99_ms": 90.0,
                "failures": 2,
                "down": true,
                "edns": true,
                "tcp_only": true,
                "lame": false,
                "lower_case": true,
                "unwanted": 3
            })
        );
        assert_eq!(addresses[1]["edns"], false);
        // No figures yet, EDNS unknown: the optional fields are left out.
        for field in ["srtt_ms", "p50_ms", "p99_ms", "edns"] {
            assert!(addresses[2].get(field).is_none(), "{field}: {first}");
        }
        assert_eq!(addresses[2]["failures"], 0);
        assert_eq!(addresses[2]["down"], false);

        let (status, second) = call(
            &lab.router,
            "GET",
            &format!("/nodes/1/dns/infra?limit=2&cursor={cursor}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(zones(&second), ["sub.example.test", "test"]);

        let (status, narrowed) =
            call(&lab.router, "GET", "/nodes/1/dns/infra?suffix=example.test").await;
        assert_eq!(status, StatusCode::OK, "{narrowed}");
        assert_eq!(zones(&narrowed), ["example.test", "sub.example.test"]);
        assert!(narrowed["next_cursor"].is_null(), "{narrowed}");

        // The route asked the role with the suffix and the default limit.
        let ran = lab.role.ran();
        assert_eq!(ran.len(), 3);
        let last: InfraListArgs = from_cbor(&ran[2].1).expect("arguments");
        assert_eq!(
            last,
            InfraListArgs {
                suffix: Some("example.test".to_owned()),
                after: None,
                limit: 200
            }
        );
        let rows = rows(&lab).await;
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter()
                .all(|(_, kind, state, _)| kind == "dns.infra.list" && state == "done")
        );
        // The cache holds no client data: nothing is audited.
        assert_eq!(audit(&lab, "dns.infra.list").await, Vec::<Value>::new());
        assert_eq!(audit(&lab, "dns.cache.read").await, Vec::<Value>::new());
    }

    #[tokio::test]
    async fn malformed_parameters_and_unknown_nodes_are_refused() {
        let lab = open(Some(report()));
        for (path, field) in [
            ("/nodes/1/dns/infra?limit=0", "limit"),
            ("/nodes/1/dns/infra?limit=1001", "limit"),
            ("/nodes/1/dns/infra?suffix=a..b", "suffix"),
            ("/nodes/1/dns/infra?cursor=a..b", "cursor"),
        ] {
            let (status, body) = call(&lab.router, "GET", path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert_eq!(body["code"], "sys.invalid_value", "{path}: {body}");
            assert_eq!(body["params"]["field"], field, "{path}: {body}");
        }
        let (status, body) =
            call(&lab.router, "POST", "/nodes/1/dns/infra/flush?suffix=a..b").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "sys.invalid_value");
        assert_eq!(body["params"]["field"], "suffix");
        for (method, path) in [
            ("GET", "/nodes/7/dns/recursion"),
            ("POST", "/nodes/7/dns/recursion/prime"),
            ("GET", "/nodes/7/dns/infra"),
            ("POST", "/nodes/7/dns/infra/flush"),
        ] {
            let (status, body) = call(&lab.router, method, path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
            assert_eq!(body["code"], "cluster.node.not_found", "{path}: {body}");
        }
        assert_eq!(lab.role.ran(), []);
        assert_eq!(rows(&lab).await, []);
    }

    #[tokio::test]
    async fn flushing_the_infrastructure_cache_is_audited() {
        let lab = open(Some(report()));
        let (status, body) = call(&lab.router, "POST", "/nodes/1/dns/infra/flush").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"entries": 7}));
        let (status, body) = call(
            &lab.router,
            "POST",
            "/nodes/1/dns/infra/flush?suffix=example.test",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"entries": 2}));

        let ran = lab.role.ran();
        assert_eq!(ran[0], (status::INFRA_FLUSH.to_owned(), Vec::new()));
        let args: InfraFlushArgs = from_cbor(&ran[1].1).expect("arguments");
        assert_eq!(
            args,
            InfraFlushArgs {
                suffix: Some("example.test".to_owned())
            }
        );
        let rows = rows(&lab).await;
        assert_eq!(
            rows.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
            ["dns.infra.flush", "dns.infra.flush"]
        );
        assert!(rows[1].3.contains("example.test"), "{rows:?}");
        let records = audit(&lab, "dns.infra.flush").await;
        assert_eq!(records.len(), 2, "{records:?}");
        let text = Value::Array(records).to_string();
        for part in [
            "\"suffix\":\"example.test\"",
            "2 entries at or below example.test removed",
            "7 entries removed; the root is primed again",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
    }

    #[tokio::test]
    async fn a_caller_without_the_scope_is_refused() {
        let viewer = lab(
            Some(report()),
            Gate {
                read: true,
                write: false,
            },
        );
        for (method, path) in [
            ("POST", "/nodes/1/dns/recursion/prime"),
            ("POST", "/nodes/1/dns/infra/flush"),
        ] {
            let (status, body) = call(&viewer.router, method, path).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
            assert_eq!(body["code"], "auth.forbidden", "{path}: {body}");
        }
        for path in ["/nodes/1/dns/recursion", "/nodes/1/dns/infra"] {
            let (status, body) = call(&viewer.router, "GET", path).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
        }
        assert_eq!(viewer.role.ran().len(), 1);

        let nobody = lab(
            Some(report()),
            Gate {
                read: false,
                write: false,
            },
        );
        for path in ["/nodes/1/dns/recursion", "/nodes/1/dns/infra"] {
            let (status, body) = call(&nobody.router, "GET", path).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        }
        assert_eq!(nobody.role.ran(), []);
        assert_eq!(rows(&nobody).await, []);
    }
}
// WP10.1: end.
