//! OPS-26 acceptance test (ADR 0013) on a three-node in-process Raft cluster: a split of two
//! members against one.
//!
//! Every member runs the full API (`tenko_api::start` on a loopback port, the IPAM service,
//! the quorum gate) and the local queue with its drain task (`tenko::serve::queue::start`).
//! The minority member refuses a write with 503 `cluster.no_quorum`, keeps serving reads
//! with the staleness header and takes two changes into its queue; the majority changes one
//! of the same objects. After the heal the queue drains: the unchanged plan is applied on the
//! author's behalf, the other one is a conflict, nothing is merged silently, and the three
//! stores hold equal state.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use reqwest::{Method, header::HeaderMap};
use serde_json::{Value, json};
use tenko::serve::queue::{self, Parts};
use tenko_api::{RunningServer, ServerConfig, middleware::quorum::Staleness, state::AppState};
use tenko_cluster::ca::{TlsMode, TlsPolicy, TlsService, TrustedProxies};
use tenko_core::auth::AuthFuture;
use tenko_core::{
    AuthFailure, AuthStrength, Authenticated, Authenticator, Credentials, NodeId, Principal,
    SessionId, Timestamp, UserId,
};
use tenko_ipam::{IpamService, queue::LocalQueue};
use tenko_store::{
    Store,
    raft::{RaftStore, fixture::InProcessCluster},
    testing::ConformanceConfig,
};
use tokio::sync::watch;

/// How long the whole test may take before it fails instead of hanging.
const LIMIT: Duration = Duration::from_secs(60);

/// How long the whole scenario may take.
const TOTAL: Duration = Duration::from_secs(240);

/// The bearer token of the person who makes every change.
const TOKEN: &str = "alice";

/// Runs a future for at most [`LIMIT`].
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, future)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within {LIMIT:?}"))
}

/// Polls `check` until it returns `Some`, or fails after [`LIMIT`].
async fn until<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    within(what, async {
        loop {
            if let Some(found) = check().await {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
}

/// Knows one person: the bearer token [`TOKEN`] is always the same user.
struct Alice {
    principal: Principal,
}

impl Authenticator for Alice {
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
        _source_ip: Option<IpAddr>,
        _now: Timestamp,
    ) -> AuthFuture<'a> {
        let answer = match credentials {
            Credentials::Bearer(token) if token == TOKEN => Ok(Authenticated {
                principal: self.principal.clone(),
                user: self.principal.user(),
                roles: std::collections::BTreeSet::new(),
                strength: AuthStrength::Password,
                expires_at: None,
                flags: tenko_core::AuthFlags::default(),
            }),
            Credentials::None => Err(AuthFailure::Missing),
            _ => Err(AuthFailure::Invalid),
        };
        Box::pin(async move { answer })
    }
}

/// One answer of the API.
struct Reply {
    status: u16,
    headers: HeaderMap,
    text: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    #[track_caller]
    fn expect(&self, status: u16) -> Value {
        assert_eq!(self.status, status, "unexpected answer: {}", self.text);
        self.json()
    }
}

/// A controller: its store, services, API on loopback and queue.
struct Controller {
    store: RaftStore,
    queue: Arc<LocalQueue>,
    server: RunningServer,
    base: String,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

impl Controller {
    async fn start(store: &RaftStore, principal: &Principal, stop: &watch::Receiver<bool>) -> Self {
        let shared: Arc<dyn Store> = Arc::new(store.clone());
        let ipam = IpamService::with_direct_jobs(Arc::clone(&shared)).expect("the IPAM service");
        let dir = tempfile::tempdir().expect("a data directory");
        let started = queue::start(Parts {
            data_dir: dir.path().to_path_buf(),
            node: store.node_id(),
            ipam: Arc::clone(&ipam),
            authorizer: None,
            scope: None,
            quorum: Some(store.quorum()),
            stop: stop.clone(),
        })
        .expect("the queue opens");

        let mut state = AppState::new(shared);
        state.auth = Some(Arc::new(Alice {
            principal: principal.clone(),
        }));
        let mode = TlsMode::ReverseProxy {
            trusted_proxies: "192.0.2.1".parse::<TrustedProxies>().expect("proxies"),
            proxy_protocol: false,
            public_host: "ddi.example.test".to_owned(),
        };
        let tls = TlsService::new(mode, TlsPolicy::default()).expect("a TLS service");
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let mut config = ServerConfig::new(vec![addr], tls, TlsPolicy::default());
        config.lab_plain_http = true;
        config.extensions.insert(ipam);
        config.extensions.insert(Arc::clone(&started.queue));
        let server = tenko_api::start(config, state)
            .await
            .expect("the API starts");
        let base = format!("http://{}/api/v1", server.local_addrs()[0]);
        Self {
            store: store.clone(),
            queue: started.queue,
            server,
            base,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("an HTTP client"),
            _dir: dir,
        }
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Reply {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(TOKEN);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("the request is answered");
        Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            text: response.text().await.expect("a body"),
        }
    }

    async fn get(&self, path: &str) -> Reply {
        self.call(Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> Reply {
        self.call(Method::POST, path, Some(body)).await
    }

    async fn patch(&self, path: &str, body: Value) -> Reply {
        self.call(Method::PATCH, path, Some(body)).await
    }

    fn accepts_writes(&self) -> bool {
        self.store.status().quorum.accepts_writes()
    }

    /// The description of an address as this controller reads it, once it has applied
    /// `at_least`.
    async fn description(&self, id: &str, at_least: u64) -> Option<String> {
        let reply = self
            .get(&format!("/addresses/{id}?at_least={at_least}"))
            .await;
        if reply.status != 200 {
            return None;
        }
        reply.json()["meta"]["description"]
            .as_str()
            .map(str::to_owned)
    }
}

/// Waits until `check` holds on the member's status.
async fn applied(member: &RaftStore, revision: u64) {
    until("the member applies the revision", || async {
        (member.status().revision.0 >= revision).then_some(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_split_two_against_one_queues_on_the_minority_and_settles_after_the_heal() {
    tokio::time::timeout(TOTAL, scenario())
        .await
        .unwrap_or_else(|_| panic!("the scenario did not finish within {TOTAL:?}"));
}

#[allow(clippy::too_many_lines)]
async fn scenario() {
    let cluster = InProcessCluster::start_with(3, &ConformanceConfig::default(), |config| {
        config.isolation_after = Duration::from_millis(300);
    })
    .await;
    let alice = Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Password,
    };
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut controllers = Vec::new();
    for node in 1..=3 {
        let member = cluster.member(NodeId(node));
        controllers.push(Controller::start(member, &alice, &stop_rx).await);
    }
    let [one, two, three] = controllers.as_slice() else {
        unreachable!("three controllers")
    };

    // 1. A prefix and two addresses through member 1; member 3 applies them.
    one.post("/prefixes", json!({ "cidr": "192.0.2.0/24" }))
        .await
        .expect(201);
    let a = one
        .post("/addresses", json!({ "ip": "192.0.2.10" }))
        .await
        .expect(201);
    let a_id = a["item"]["id"].as_str().expect("the id of A").to_owned();
    let b = one
        .post("/addresses", json!({ "ip": "192.0.2.11" }))
        .await
        .expect(201);
    let b_id = b["item"]["id"].as_str().expect("the id of B").to_owned();
    let created = b["revision"].as_u64().expect("the revision of the creates");
    applied(&three.store, created).await;

    // 2. Member 3 is the minority; the majority keeps a leader.
    if cluster.wait_for_leader().await.node_id() == NodeId(3) {
        cluster.hand_over().await;
    }
    cluster.network().set_isolated(3, true);
    until(
        "member 3 loses its quorum and the majority keeps it",
        || async {
            let majority_leads = [&one.store, &two.store].iter().any(|member| {
                member
                    .leadership()
                    .borrow()
                    .is_some_and(|seen| seen.is_self)
            });
            (!three.accepts_writes()
                && one.accepts_writes()
                && two.accepts_writes()
                && majority_leads)
                .then_some(())
        },
    )
    .await;

    // 3. The minority reads with a staleness header and refuses a write.
    let read = three.get("/addresses").await;
    read.expect(200);
    let staleness: Staleness = read
        .headers
        .get("tenko-staleness")
        .and_then(|value| value.to_str().ok())
        .expect("the staleness header on a read")
        .parse()
        .expect("a readable staleness header");
    assert!(
        staleness.revision.0 >= created,
        "the local copy has the addresses"
    );

    let refused = three
        .patch(
            &format!("/addresses/{a_id}"),
            json!({ "description": "refused" }),
        )
        .await;
    let problem = refused.expect(503);
    assert_eq!(problem["code"], "cluster.no_quorum", "{problem}");
    assert_eq!(problem["params"]["queueable"], "true", "{problem}");
    assert!(refused.headers.contains_key("retry-after"), "a retry hint");

    // 4. Two changes go into the queue of member 3.
    for id in [&a_id, &b_id] {
        three
            .post(
                "/queue",
                json!({
                    "method": "PATCH",
                    "path": format!("/addresses/{id}"),
                    "body": { "description": "queued on the minority" },
                }),
            )
            .await
            .expect(201);
    }
    assert_eq!(three.queue.len().expect("the queue length"), 2);

    // 5. The majority changes B meanwhile.
    let changed = one
        .patch(
            &format!("/addresses/{b_id}"),
            json!({ "description": "changed on the majority" }),
        )
        .await
        .expect(200);
    let majority_revision = changed["revision"]
        .as_u64()
        .expect("the revision of the change");

    // 6. Heal: member 3 accepts writes and drains its queue.
    cluster.network().set_isolated(3, false);
    until("member 3 accepts writes again", || async {
        three.accepts_writes().then_some(())
    })
    .await;
    until("the queue of member 3 is drained", || async {
        three
            .queue
            .is_empty()
            .ok()
            .filter(|empty| *empty)
            .map(|_| ())
    })
    .await;

    // 7. The author finds both outcomes, from any controller.
    let list = until("both records are listed on member 1", || async {
        let reply = one.get("/queue/conflicts").await;
        let body = reply.json();
        (reply.status == 200
            && body["items"]
                .as_array()
                .is_some_and(|items| items.len() == 2))
        .then_some(body)
    })
    .await;
    let record = |id: &str| {
        list["items"]
            .as_array()
            .and_then(|items| {
                items.iter().find(|item| {
                    item["request"]["path"]
                        .as_str()
                        .is_some_and(|p| p.ends_with(id))
                })
            })
            .unwrap_or_else(|| panic!("no record for {id} in {list}"))
            .clone()
    };
    let record_a = record(&a_id);
    assert_eq!(record_a["state"], "applied", "{record_a}");
    let record_b = record(&b_id);
    assert_eq!(record_b["state"], "conflict", "{record_b}");
    assert_eq!(
        record_b["conflict"]["code"], "queue.plan_changed",
        "{record_b}"
    );

    let settled = list["revision"].as_u64().expect("the revision of the list");
    let at_least = settled.max(majority_revision);
    for controller in [one, two, three] {
        let description = until("A carries the queued description", || async {
            controller.description(&a_id, at_least).await
        })
        .await;
        assert_eq!(description, "queued on the minority");
        let description = until("B is readable", || async {
            controller.description(&b_id, at_least).await
        })
        .await;
        assert_eq!(
            description, "changed on the majority",
            "B keeps the majority's change"
        );
    }

    // 8. Equal state on all three members at one revision.
    let digests = until("the three members hold the same revision", || async {
        let revisions: Vec<_> = [one, two, three]
            .iter()
            .map(|controller| controller.store.status().revision)
            .collect();
        let target = revisions[0];
        if !revisions.iter().all(|revision| *revision == target) || target.0 < at_least {
            return None;
        }
        let mut digests = Vec::new();
        for controller in [one, two, three] {
            digests.push(controller.store.digest(Some(target)).await.ok()?);
        }
        digests
            .iter()
            .all(|digest| *digest == digests[0])
            .then_some(digests)
    })
    .await;
    assert_eq!(digests[0], digests[1], "members 1 and 2 hold equal state");
    assert_eq!(digests[1], digests[2], "members 2 and 3 hold equal state");

    let _ = stop_tx.send(true);
    for controller in &controllers {
        controller.server.shutdown();
    }
    cluster.shutdown().await;
}
