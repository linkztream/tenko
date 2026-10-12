//! Route tests of the queue area over the full application, so that the quorum gate runs:
//! a store whose quorum state the test switches, two people behind bearer tokens, and a
//! local queue in a directory of its own. Test data stays in the documentation ranges.

use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, header},
};
use bytes::Bytes;
use serde_json::{Value, json};
use tenko_core::{
    AddressId, AuthFailure, AuthFlags, AuthStrength, Authenticated, Authenticator, Credentials,
    NodeId, Principal, Revision, SessionId, Timestamp, UserId, auth::AuthFuture,
};
use tenko_ipam::{
    IpamCommand, IpamService, PlanView,
    command::{AddressPatch, UpdateAddress},
    queue::{
        ChangeState, ChangeSummary, LocalQueue, QUEUED_CHANGES, QueuedChange, QueuedRequest,
        SummaryAction,
    },
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, MemStore, QuorumState, ReadConsistency, ReadView, Store,
    StoreError, StoreStatus, WatchFilter, WriteBatch,
};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    API_BASE,
    middleware::{HttpConfig, quorum::Staleness},
    problem::PROBLEM_JSON,
    server,
    state::AppState,
    ui::UiSource,
};

/// A memory store whose quorum state the test switches while the application runs.
#[derive(Default)]
struct SwitchStore {
    inner: MemStore,
    quorum: Mutex<QuorumState>,
}

impl SwitchStore {
    fn set(&self, quorum: QuorumState) {
        *self.quorum.lock().expect("quorum lock") = quorum;
    }
}

/// A boxed future, as `async_trait` desugars the async methods of [`Store`].
type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl Store for SwitchStore {
    fn propose<'life0, 'async_trait>(
        &'life0 self,
        batch: WriteBatch,
    ) -> Boxed<'async_trait, Result<Committed, StoreError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.propose(batch)
    }

    fn read<'life0, 'async_trait>(
        &'life0 self,
        consistency: ReadConsistency,
    ) -> Boxed<'async_trait, Result<Arc<dyn ReadView>, StoreError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.read(consistency)
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        StoreStatus {
            quorum: *self.quorum.lock().expect("quorum lock"),
            ..self.inner.status()
        }
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<tenko_store::Leadership>> {
        self.inner.leadership()
    }
}

/// Maps the bearer tokens `alice` and `bob` to two different people.
struct People {
    alice: UserId,
    bob: UserId,
}

impl Authenticator for People {
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
        _source_ip: Option<IpAddr>,
        _now: Timestamp,
    ) -> AuthFuture<'a> {
        Box::pin(async move {
            let user = match credentials {
                Credentials::Bearer(token) if token == "alice" => self.alice,
                Credentials::Bearer(token) if token == "bob" => self.bob,
                Credentials::None => return Err(AuthFailure::Missing),
                _ => return Err(AuthFailure::Invalid),
            };
            Ok(Authenticated {
                principal: Principal::User {
                    id: user,
                    session: SessionId::generate(),
                    strength: AuthStrength::Password,
                },
                user: Some(user),
                roles: BTreeSet::new(),
                strength: AuthStrength::Password,
                expires_at: None,
                flags: AuthFlags::default(),
            })
        })
    }
}

/// An answer, decoded.
struct Reply {
    status: u16,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Asserts a problem document with this status and code.
    fn assert_problem(&self, status: u16, code: &str) -> &Self {
        let label = format!("{} {}", self.status, self.body);
        assert_eq!(self.status, status, "{label}");
        assert_eq!(self.header("content-type"), Some(PROBLEM_JSON), "{label}");
        assert_eq!(self.body["code"], code, "{label}");
        self
    }

    fn param(&self, name: &str) -> &str {
        self.body["params"][name].as_str().unwrap_or_default()
    }

    fn items(&self) -> &[Value] {
        self.body["items"].as_array().expect("items")
    }

    fn staleness(&self) -> Staleness {
        self.header("tenko-staleness")
            .expect("staleness header")
            .parse()
            .expect("staleness value")
    }
}

/// The full application over a switchable store, a queue and two people.
struct Env {
    app: Router,
    store: Arc<SwitchStore>,
    people: Arc<People>,
    dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        Self::build(true)
    }

    fn without_queue() -> Self {
        Self::build(false)
    }

    fn build(with_queue: bool) -> Self {
        let store = Arc::new(SwitchStore::default());
        let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
        let people = Arc::new(People {
            alice: UserId::generate(),
            bob: UserId::generate(),
        });
        let state = AppState {
            auth: Some(Arc::clone(&people) as Arc<dyn Authenticator>),
            ..AppState::new(Arc::clone(&dyn_store))
        };
        let service = IpamService::with_direct_jobs(dyn_store).expect("IPAM service");
        let dir = std::env::temp_dir().join(format!("tenko-queue-test-{}", Uuid::now_v7()));
        let mut app = server::app(state, &HttpConfig::default(), &UiSource::Embedded)
            .expect("application")
            .layer(Extension(service));
        if with_queue {
            let queue = LocalQueue::open(dir.join("queue"), NodeId(1)).expect("queue");
            app = app.layer(Extension(Arc::new(queue)));
        }
        Self {
            app,
            store,
            people,
            dir,
        }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes: Bytes = to_bytes(body, usize::MAX).await.expect("body");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON body")
        };
        Reply {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        }
    }

    async fn alice(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        self.send(method, path, Some("alice"), body).await
    }

    async fn bob(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        self.send(method, path, Some("bob"), body).await
    }

    /// Creates the prefix 192.0.2.0/24 and the address 192.0.2.10 while the store accepts
    /// writes; returns the identifier of the address.
    async fn address(&self) -> AddressId {
        let prefix = self
            .alice(
                "POST",
                "/prefixes",
                Some(&json!({ "cidr": "192.0.2.0/24" })),
            )
            .await;
        assert_eq!(prefix.status, 201, "{}", prefix.body);
        let address = self
            .alice("POST", "/addresses", Some(&json!({ "ip": "192.0.2.10" })))
            .await;
        assert_eq!(address.status, 201, "{}", address.body);
        address.body["item"]["id"]
            .as_str()
            .expect("address id")
            .parse()
            .expect("address identifier")
    }

    fn isolate(&self, applied: u64) -> (Timestamp, Revision) {
        let since = at("2026-10-11T12:00:00Z");
        let applied = Revision(applied);
        self.store.set(QuorumState::Isolated {
            since,
            last_contact: None,
            applied,
        });
        (since, applied)
    }

    /// Writes a settled queued change of `author` straight into the store.
    async fn record(&self, author: UserId, address: AddressId, state: ChangeState) -> Uuid {
        let id = Uuid::now_v7();
        let command = IpamCommand::UpdateAddress(UpdateAddress {
            id: address,
            expected: None,
            patch: AddressPatch {
                description: Some(Some("settled".to_owned())),
                ..AddressPatch::default()
            },
        });
        let plan: PlanView = serde_json::from_value(json!({
            "base_revision": 1,
            "summary": {
                "counts": [], "warnings": {}, "unacknowledged": [], "lines": [],
                "mutations": 0, "preconditions": 0
            },
            "changes": [],
            "warnings": [],
            "results": []
        }))
        .expect("plan");
        let now = at("2026-10-11T12:00:00Z");
        let record = QueuedChange {
            id,
            author,
            principal: Principal::User {
                id: author,
                session: SessionId::generate(),
                strength: AuthStrength::Password,
            },
            original_session: None,
            queued_at: now,
            queued_on: NodeId(1),
            settled_at: now,
            state,
            request: QueuedRequest {
                method: "PATCH".to_owned(),
                path: format!("/addresses/{address}"),
                query: None,
                body: Some(json!({ "description": "settled" })),
                if_match: None,
            },
            summary: ChangeSummary {
                action: SummaryAction::Update,
                kind: tenko_core::ObjectKind::Address,
                key: Some("192.0.2.10".to_owned()),
            },
            commands: vec![command],
            options: tenko_ipam::PlanOptions::default(),
            queued_plan: plan,
            current_plan: None,
            conflict: None,
        };
        let mut batch = WriteBatch::new(
            Principal::system(tenko_core::SystemComponent::Reconciler),
            now,
        );
        batch.put_typed(&QUEUED_CHANGES, &id, &record).expect("put");
        self.store.propose(batch).await.expect("record written");
        id
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn at(text: &str) -> Timestamp {
    text.parse().expect("timestamp")
}

fn patch_request(address: AddressId) -> Value {
    json!({
        "method": "PATCH",
        "path": format!("/addresses/{address}"),
        "body": { "description": "queued" }
    })
}

#[tokio::test]
async fn a_healthy_controller_adds_no_staleness_and_refuses_to_queue() {
    let env = Env::new();
    let read = env.alice("GET", "/addresses", None).await;
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(read.header("tenko-staleness"), None);
    let queued = env
        .alice(
            "POST",
            "/queue",
            Some(&json!({ "method": "POST", "path": "/addresses" })),
        )
        .await;
    queued.assert_problem(409, "queue.not_isolated");
}

#[tokio::test]
async fn an_isolated_controller_serves_reads_with_the_age_of_its_copy() {
    let env = Env::new();
    let (since, applied) = env.isolate(41);
    let read = env.alice("GET", "/addresses", None).await;
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(
        read.staleness(),
        Staleness {
            since,
            revision: applied
        }
    );
}

#[tokio::test]
async fn an_isolated_controller_refuses_writes_and_says_whether_they_can_be_queued() {
    let env = Env::new();
    let (since, applied) = env.isolate(41);
    let write = env
        .alice("POST", "/addresses", Some(&json!({ "ip": "192.0.2.11" })))
        .await;
    write.assert_problem(503, "cluster.no_quorum");
    assert_eq!(write.header("retry-after"), Some("15"));
    assert_eq!(write.param("state"), "isolated");
    assert_eq!(write.param("queueable"), "true");
    assert_eq!(write.param("revision"), "41");
    assert_eq!(write.param("since"), since.to_rfc3339());
    assert_eq!(
        write.staleness(),
        Staleness {
            since,
            revision: applied
        }
    );

    let other = env
        .alice("POST", "/users", Some(&json!({ "name": "carol" })))
        .await;
    other.assert_problem(503, "cluster.no_quorum");
    assert_eq!(other.param("queueable"), "false");
}

#[tokio::test]
async fn an_electing_controller_asks_to_retry_sooner() {
    let env = Env::new();
    env.store.set(QuorumState::Electing {
        since: at("2026-10-11T12:00:00Z"),
    });
    let write = env
        .alice("POST", "/addresses", Some(&json!({ "ip": "192.0.2.11" })))
        .await;
    write.assert_problem(503, "cluster.no_quorum");
    assert_eq!(write.header("retry-after"), Some("5"));
    assert_eq!(write.param("state"), "electing");
}

#[tokio::test]
async fn a_dry_run_passes_the_quorum_gate() {
    let env = Env::new();
    let address = env.address().await;
    env.isolate(7);
    let reply = env
        .alice(
            "PATCH",
            &format!("/addresses/{address}?dry_run=true"),
            Some(&json!({ "description": "preview" })),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body["dry_run"], true);
}

#[tokio::test]
async fn an_isolated_controller_queues_a_change_for_the_person_who_sent_it() {
    let env = Env::new();
    let address = env.address().await;
    env.isolate(7);

    let queued = env
        .alice("POST", "/queue", Some(&patch_request(address)))
        .await;
    assert_eq!(queued.status, 201, "{}", queued.body);
    assert_eq!(queued.body["state"], "queued");
    assert_eq!(queued.body["summary"]["action"], "update");
    assert_eq!(queued.body["summary"]["kind"], "address");
    assert_eq!(queued.body["summary"]["key"], "192.0.2.10");
    assert_eq!(
        queued.body["plan"]["changes"].as_array().map(Vec::len),
        Some(1)
    );
    let id = queued.body["id"].as_str().expect("id").to_owned();

    let mine = env.alice("GET", "/queue", None).await;
    assert_eq!(mine.status, 200, "{}", mine.body);
    assert_eq!(mine.items().len(), 1);
    assert_eq!(mine.items()[0]["id"], id.as_str());
    let theirs = env.bob("GET", "/queue", None).await;
    assert_eq!(theirs.status, 200, "{}", theirs.body);
    assert!(theirs.items().is_empty(), "{}", theirs.body);
}

#[tokio::test]
async fn only_the_author_withdraws_a_queued_change() {
    let env = Env::new();
    let address = env.address().await;
    env.isolate(7);
    let queued = env
        .alice("POST", "/queue", Some(&patch_request(address)))
        .await;
    let path = format!("/queue/{}", queued.body["id"].as_str().expect("id"));

    env.bob("DELETE", &path, None)
        .await
        .assert_problem(404, "queue.not_found");
    assert_eq!(env.alice("DELETE", &path, None).await.status, 204);
    env.alice("DELETE", &path, None)
        .await
        .assert_problem(404, "queue.not_found");
}

#[tokio::test]
async fn the_queue_refuses_what_it_cannot_take_and_what_it_cannot_reach() {
    let env = Env::new();
    env.isolate(7);
    let users = json!({ "method": "POST", "path": "/users", "body": { "name": "carol" } });
    env.alice("POST", "/queue", Some(&users))
        .await
        .assert_problem(422, "queue.not_queueable");
    assert_eq!(env.send("GET", "/queue", None, None).await.status, 401);

    let bare = Env::without_queue();
    bare.isolate(7);
    bare.alice(
        "POST",
        "/queue",
        Some(&patch_request(AddressId::generate())),
    )
    .await
    .assert_problem(503, "queue.unavailable");
}

#[tokio::test]
async fn settled_changes_are_listed_to_their_author_only() {
    let env = Env::new();
    let address = env.address().await;
    let mine = env
        .record(env.people.alice, address, ChangeState::Conflict)
        .await;
    env.record(env.people.bob, address, ChangeState::Conflict)
        .await;

    let list = env.alice("GET", "/queue/conflicts", None).await;
    assert_eq!(list.status, 200, "{}", list.body);
    assert_eq!(list.items().len(), 1, "{}", list.body);
    assert_eq!(list.items()[0]["id"], mine.to_string());
    assert_eq!(list.items()[0]["state"], "conflict");
    assert!(list.items()[0]["revision"].is_u64(), "{}", list.body);
    assert!(list.body["revision"].is_u64(), "{}", list.body);
}

#[tokio::test]
async fn a_dry_run_reapply_plans_and_keeps_the_record() {
    let env = Env::new();
    let address = env.address().await;
    let id = env
        .record(env.people.alice, address, ChangeState::Conflict)
        .await;

    let plan = env
        .alice(
            "POST",
            &format!("/queue/conflicts/{id}/reapply?dry_run=true"),
            None,
        )
        .await;
    assert_eq!(plan.status, 200, "{}", plan.body);
    assert_eq!(plan.body["dry_run"], true);
    assert!(plan.body["plan"]["changes"].is_array(), "{}", plan.body);
    let list = env.alice("GET", "/queue/conflicts", None).await;
    assert_eq!(list.items().len(), 1, "{}", list.body);
}

#[tokio::test]
async fn a_reapply_applies_the_change_and_removes_the_record() {
    let env = Env::new();
    let address = env.address().await;
    let id = env
        .record(env.people.alice, address, ChangeState::Conflict)
        .await;

    let applied = env
        .alice("POST", &format!("/queue/conflicts/{id}/reapply"), None)
        .await;
    assert_eq!(applied.status, 200, "{}", applied.body);
    assert_eq!(applied.body["dry_run"], false);
    assert_eq!(applied.body["item"]["meta"]["description"], "settled");
    let list = env.alice("GET", "/queue/conflicts", None).await;
    assert!(list.items().is_empty(), "{}", list.body);
}

#[tokio::test]
async fn an_applied_change_is_not_applied_again() {
    let env = Env::new();
    let address = env.address().await;
    let id = env
        .record(env.people.alice, address, ChangeState::Applied)
        .await;
    env.alice("POST", &format!("/queue/conflicts/{id}/reapply"), None)
        .await
        .assert_problem(409, "queue.changed");
}

#[tokio::test]
async fn only_the_author_discards_a_settled_change() {
    let env = Env::new();
    let address = env.address().await;
    let bobs = env
        .record(env.people.bob, address, ChangeState::Conflict)
        .await;
    let path = format!("/queue/conflicts/{bobs}");

    env.alice("DELETE", &path, None)
        .await
        .assert_problem(404, "queue.not_found");
    assert_eq!(env.bob("DELETE", &path, None).await.status, 204);
}
