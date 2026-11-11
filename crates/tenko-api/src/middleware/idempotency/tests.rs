use std::{
    collections::{BTreeSet, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use axum::http::Request as HttpRequest;
use tenko_auth::authz::anywhere;
use tenko_core::{
    AuthFlags, AuthStrength, Denied, DenyReason, ObjectKind, ScopeFilter, SessionId,
    SystemComponent, UserId, cluster::LEADER_EPOCH,
};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, MemStore, ReadView, ReadViewExt as _,
    StoreError, StoreStatus, WatchFilter,
};

use super::*;

fn principal() -> Principal {
    Principal::system(SystemComponent::Api)
}

/// The same principal, for test handlers whose scope names a local `principal`.
fn api() -> Principal {
    principal()
}

/// The object every test handler is checked on.
fn object() -> ObjectRef {
    anywhere(ObjectKind::Prefix)
}

fn post(key: &str, body: &'static str) -> Request {
    HttpRequest::builder()
        .method(Method::POST)
        .uri("/api/v1/prefixes")
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body))
        .expect("request")
}

fn env(principal: &Principal) -> Env<'_> {
    Env {
        principal: Some(principal),
        authorizer: None,
        secrets: SecretBodies::default(),
    }
}

/// Runs the middleware around a handler that passes one check (as the authorizer would
/// note it), answers `status` with a body naming the call, and does not read the body.
async fn run_with(
    store: &dyn Store,
    in_flight: &InFlight,
    env: Env<'_>,
    request: Request,
    calls: &Arc<AtomicUsize>,
    status: StatusCode,
) -> Response {
    let calls = Arc::clone(calls);
    let who = env.principal.cloned().unwrap_or_else(principal);
    handle(
        store,
        in_flight,
        IdempotencyConfig::default(),
        env,
        request,
        move |_request| async move {
            tenko_auth::journal::note_check(&who, Action::Create, &object());
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            let mut response = (status, format!("{{\"call\":{n}}}")).into_response();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_static("/api/v1/prefixes/1"),
            );
            response
        },
    )
    .await
}

async fn run(
    store: &MemStore,
    in_flight: &InFlight,
    request: Request,
    calls: &Arc<AtomicUsize>,
    status: StatusCode,
) -> Response {
    let principal = principal();
    run_with(store, in_flight, env(&principal), request, calls, status).await
}

async fn body(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf-8")
}

#[tokio::test]
async fn the_first_success_is_replayed() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let first = run(
        &store,
        &in_flight,
        post("k-1", "{\"a\":1}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);
    assert!(first.headers().get(REPLAYED_HEADER).is_none());
    assert_eq!(body(first).await, "{\"call\":1}");

    let again = run(
        &store,
        &in_flight,
        post("k-1", "{\"a\":1}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(again.status(), StatusCode::CREATED);
    assert_eq!(again.headers()[REPLAYED_HEADER], "true");
    assert_eq!(again.headers()[header::LOCATION], "/api/v1/prefixes/1");
    assert_eq!(body(again).await, "{\"call\":1}");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the handler ran once");

    let other = run(
        &store,
        &in_flight,
        post("k-1", "{\"a\":2}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(other.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body(other).await.contains(codes::IDEMPOTENCY_MISMATCH));

    let fresh = run(
        &store,
        &in_flight,
        post("k-2", "{\"a\":2}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(body(fresh).await, "{\"call\":2}");
}

#[tokio::test]
async fn a_body_the_handler_reads_is_fingerprinted_as_it_streams() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let reading = |request: Request| async move {
        tenko_auth::journal::note_check(&api(), Action::Create, &object());
        let body = to_bytes(request.into_body(), 1 << 20).await.expect("body");
        (StatusCode::CREATED, body).into_response()
    };
    let first = handle(
        &store,
        &in_flight,
        IdempotencyConfig::default(),
        env(&principal),
        post("read", "{\"cidr\":\"192.0.2.0/24\"}"),
        reading,
    )
    .await;
    assert_eq!(body(first).await, "{\"cidr\":\"192.0.2.0/24\"}");
    let again = handle(
        &store,
        &in_flight,
        IdempotencyConfig::default(),
        env(&principal),
        post("read", "{\"cidr\":\"192.0.2.0/24\"}"),
        reading,
    )
    .await;
    assert_eq!(again.headers()[REPLAYED_HEADER], "true");
    // The fingerprint of a streamed body is the fingerprint of the whole request.
    let stored = stored_records(&store).await;
    let key = in_flight.key();
    let uri: axum::http::Uri = "/api/v1/prefixes".parse().expect("uri");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert_eq!(
        stored[0].0.fingerprint.as_ref(),
        key.fingerprint(
            &Method::POST,
            &uri,
            &headers,
            b"{\"cidr\":\"192.0.2.0/24\"}"
        )
        .as_slice()
    );
}

#[tokio::test]
async fn failures_are_not_stored() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let failed = run(
        &store,
        &in_flight,
        post("k", "{}"),
        &calls,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(failed.status(), StatusCode::CONFLICT);
    let retried = run(&store, &in_flight, post("k", "{}"), &calls, StatusCode::OK).await;
    assert_eq!(retried.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn concurrent_duplicates_are_refused() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let key = record_key(&principal(), &IdempotencyKey::new("busy").expect("key"));
    let _guard = in_flight.enter(key).expect("first");
    let calls = Arc::new(AtomicUsize::new(0));
    let response = run(
        &store,
        &in_flight,
        post("busy", "{}"),
        &calls,
        StatusCode::OK,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn other_requests_pass_through() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let get = HttpRequest::builder()
        .method(Method::GET)
        .uri("/api/v1/prefixes")
        .header("idempotency-key", "k")
        .body(Body::empty())
        .expect("request");
    run(&store, &in_flight, get, &calls, StatusCode::OK).await;
    let unkeyed = HttpRequest::builder()
        .method(Method::POST)
        .uri("/api/v1/prefixes")
        .body(Body::empty())
        .expect("request");
    run(&store, &in_flight, unkeyed, &calls, StatusCode::OK).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        store.status().revision,
        tenko_core::Revision(0),
        "nothing stored"
    );
}

/// A store that counts the reads and the proposed batches of the store it wraps.
struct Counting {
    inner: MemStore,
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl Counting {
    fn new() -> Self {
        Self {
            inner: MemStore::default(),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        }
    }

    /// The reads and writes since the last call.
    fn take(&self) -> (usize, usize) {
        (
            self.reads.swap(0, Ordering::SeqCst),
            self.writes.swap(0, Ordering::SeqCst),
        )
    }
}

/// A boxed future, as `async_trait` desugars the async methods of [`Store`].
type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl Store for Counting {
    fn propose<'life0, 'async_trait>(
        &'life0 self,
        batch: WriteBatch,
    ) -> Boxed<'async_trait, Result<Committed, StoreError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.writes.fetch_add(1, Ordering::SeqCst);
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
        self.reads.fetch_add(1, Ordering::SeqCst);
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
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

/// What a request costs the store, with and without a key (the handler itself touches no
/// store here): without a key nothing; a first keyed request one read (the lookup, before
/// any body is read) and one write (the record and its expiry row in one batch); a replay
/// one read; a refused replay one read and the write of its audit record.
#[tokio::test]
async fn the_store_work_of_a_request_with_and_without_a_key() {
    let store = Counting::new();
    let in_flight = InFlight::default();
    let principal = principal();
    let calls = Arc::new(AtomicUsize::new(0));
    let unkeyed = HttpRequest::builder()
        .method(Method::POST)
        .uri("/api/v1/prefixes")
        .body(Body::from("{}"))
        .expect("request");
    run_with(
        &store,
        &in_flight,
        env(&principal),
        unkeyed,
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(store.take(), (0, 0), "without a key");

    let first = post("count", "{}");
    run_with(
        &store,
        &in_flight,
        env(&principal),
        first,
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(store.take(), (1, 1), "a first keyed request");

    let replayed = run_with(
        &store,
        &in_flight,
        env(&principal),
        post("count", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(replayed.headers()[REPLAYED_HEADER], "true");
    assert_eq!(store.take(), (1, 0), "a replay");

    let deny = DenyAll;
    let refused = run_with(
        &store,
        &in_flight,
        Env {
            authorizer: Some(&deny),
            ..env(&principal)
        },
        post("count", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        store.take(),
        (1, 1),
        "a refused replay and its audit record"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the handler ran twice");
}

/// Denies everything.
struct DenyAll;

impl Authorizer for DenyAll {
    fn check(&self, _: &Principal, action: Action, object: &ObjectRef) -> Result<(), Denied> {
        Err(Denied {
            action,
            object: *object,
            reason: DenyReason::MissingPermission,
        })
    }

    fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        ScopeFilter::Nothing
    }
}

/// A request whose body records whether anything read it.
fn watched_post(key: &str, polled: &Arc<AtomicBool>) -> Request {
    let polled = Arc::clone(polled);
    let stream = futures::stream::once(async move {
        polled.store(true, Ordering::SeqCst);
        Ok::<_, std::io::Error>(BodyBytes::from_static(b"{}"))
    });
    HttpRequest::builder()
        .method(Method::POST)
        .uri("/api/v1/prefixes")
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from_stream(stream))
        .expect("request")
}

#[tokio::test]
async fn a_replay_runs_the_checks_of_the_first_request_again_before_its_body() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let calls = Arc::new(AtomicUsize::new(0));
    run(
        &store,
        &in_flight,
        post("checked", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    let stored = stored_records(&store).await;
    assert_eq!(stored[0].0.checks, vec![(Action::Create, object())]);

    // The role is gone: the replay is refused as the request would be, before its body is
    // read, and the refusal is audited with the digest of the key.
    let polled = Arc::new(AtomicBool::new(false));
    let deny = DenyAll;
    let refused = run_with(
        &store,
        &in_flight,
        Env {
            authorizer: Some(&deny),
            ..env(&principal)
        },
        watched_post("checked", &polled),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(refused.headers().get(REPLAYED_HEADER).is_none());
    assert!(!polled.load(Ordering::SeqCst), "the body was never read");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let audits = audit_contexts(&store, REPLAY_REFUSED.as_str()).await;
    assert_eq!(audits.len(), 1);
    let digest = hex(&record_key(
        &principal,
        &IdempotencyKey::new("checked").expect("key"),
    ));
    assert_eq!(audits[0].get("key_digest"), Some(&digest));
    assert!(audits[0].values().all(|value| !value.contains("checked")));

    // With the right restored the replay is answered.
    let again = run(
        &store,
        &in_flight,
        post("checked", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(again.headers()[REPLAYED_HEADER], "true");
}

/// The context of the audit records of `action`.
async fn audit_contexts(
    store: &MemStore,
    action: &str,
) -> Vec<std::collections::BTreeMap<String, String>> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(&tenko_store::tables::AUDIT, KeyRange::all(), 1000, false)
        .expect("audit")
        .into_iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == action)
        .map(|(_, record, _)| record.draft.details.context)
        .collect()
}

#[tokio::test]
async fn a_request_with_nothing_to_check_again_is_never_replayed() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let calls = Arc::new(AtomicUsize::new(0));
    let unchecked = |request: Request| {
        let calls = Arc::clone(&calls);
        async move {
            drop(request);
            calls.fetch_add(1, Ordering::SeqCst);
            (StatusCode::CREATED, "{}").into_response()
        }
    };
    for _ in 0..2 {
        handle(
            &store,
            &in_flight,
            IdempotencyConfig::default(),
            env(&principal),
            post("unchecked", "{}"),
            unchecked,
        )
        .await;
    }
    let retry = handle(
        &store,
        &in_flight,
        IdempotencyConfig::default(),
        env(&principal),
        post("unchecked", "{}"),
        unchecked,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert!(
        body(retry)
            .await
            .contains(codes::IDEMPOTENCY_NOT_REPLAYABLE)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "performed once");
    let stored = stored_records(&store).await;
    assert!(stored[0].0.replay_unavailable && stored[0].0.body.is_empty());
}

/// An authentication outcome for a session principal with `roles`.
fn session(roles: &[&str], password_change_required: bool) -> (Principal, AuthOutcome) {
    let principal = Principal::User {
        id: UserId::from(uuid::Uuid::from_u128(1)),
        session: SessionId::from(uuid::Uuid::from_u128(2)),
        strength: AuthStrength::Password,
    };
    let authenticated = Authenticated {
        principal: principal.clone(),
        user: None,
        roles: roles
            .iter()
            .map(|role| (*role).to_owned())
            .collect::<BTreeSet<_>>(),
        strength: AuthStrength::Password,
        expires_at: None,
        flags: AuthFlags {
            password_change_required,
            ..AuthFlags::default()
        },
    };
    (principal, AuthOutcome(Ok(authenticated)))
}

fn post_as(key: &str, outcome: &AuthOutcome) -> Request {
    let mut request = post(key, "{}");
    request.extensions_mut().insert(outcome.clone());
    request
}

#[tokio::test]
async fn a_changed_principal_or_a_required_password_change_refuses_the_replay() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let (principal, operator) = session(&["operator"], false);
    run_with(
        &store,
        &in_flight,
        env(&principal),
        post_as("stamped", &operator),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    let replayed = run_with(
        &store,
        &in_flight,
        env(&principal),
        post_as("stamped", &operator),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(replayed.headers()[REPLAYED_HEADER], "true");

    // A role removed: the stamp no longer holds.
    let (_, viewer) = session(&["viewer"], false);
    let changed = run_with(
        &store,
        &in_flight,
        env(&principal),
        post_as("stamped", &viewer),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(changed.status(), StatusCode::CONFLICT);
    assert!(
        body(changed)
            .await
            .contains(codes::IDEMPOTENCY_NOT_REPLAYABLE)
    );

    // The account must change its password: refused as every other route.
    let (_, locked) = session(&["operator"], true);
    let refused = run_with(
        &store,
        &in_flight,
        env(&principal),
        post_as("stamped", &locked),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(
        body(refused)
            .await
            .contains("auth.password_change_required")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_fresh_session_that_cannot_be_checked_again_is_not_replayed() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let fresh = |request: Request| async move {
        drop(request);
        tenko_auth::journal::note_check(&api(), Action::Create, &object());
        tenko_auth::journal::note_fresh_session();
        (StatusCode::CREATED, "{}").into_response()
    };
    for _ in 0..2 {
        let response = handle(
            &store,
            &in_flight,
            IdempotencyConfig::default(),
            env(&principal),
            post("fresh", "{}"),
            fresh,
        )
        .await;
        assert!(response.headers().get(REPLAYED_HEADER).is_none());
    }
    let stored = stored_records(&store).await;
    assert!(stored[0].0.fresh_session);
}

/// Runs the middleware around a handler that answers 201 with a secret in the body and
/// the given extra headers.
async fn run_secret(
    store: &MemStore,
    in_flight: &InFlight,
    key: &str,
    calls: &Arc<AtomicUsize>,
    headers: &'static [(HeaderName, &'static str)],
    secrets: SecretBodies,
) -> Response {
    let calls = Arc::clone(calls);
    let principal = principal();
    handle(
        store,
        in_flight,
        IdempotencyConfig::default(),
        Env {
            secrets,
            ..env(&principal)
        },
        post(key, "{\"name\":\"ci\"}"),
        move |_request| async move {
            tenko_auth::journal::note_check(&api(), Action::Create, &object());
            calls.fetch_add(1, Ordering::SeqCst);
            let mut response =
                (StatusCode::CREATED, "{\"token\":\"tko_s3cr3t_value\"}").into_response();
            for (name, value) in headers {
                response
                    .headers_mut()
                    .append(name.clone(), HeaderValue::from_static(value));
            }
            response
        },
    )
    .await
}

/// Every stored record, decoded.
async fn stored_records(store: &MemStore) -> Vec<(StoredResponse, Bytes)> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan(&TABLE, KeyRange::all(), 100, false)
        .expect("scan")
        .into_iter()
        .map(|(_, versioned)| {
            (
                from_cbor::<StoredResponse>(&versioned.value).expect("record"),
                versioned.value,
            )
        })
        .collect()
}

#[tokio::test]
async fn secret_bearing_responses_leave_only_a_marker() {
    static NO_STORE: [(HeaderName, &str); 1] = [(header::CACHE_CONTROL, "private, No-Store")];
    static COOKIE: [(HeaderName, &str); 2] = [
        (
            header::SET_COOKIE,
            "tenko_session=abc; HttpOnly; Secure; SameSite=Strict",
        ),
        (header::CACHE_CONTROL, "no-cache"),
    ];
    static NONE: [(HeaderName, &str); 0] = [];
    let documented = SecretBodies {
        request: false,
        response: true,
    };
    let store = MemStore::default();
    let in_flight = InFlight::default();
    for (key, headers, secrets) in [
        ("token-1", &NO_STORE[..], SecretBodies::default()),
        ("login-1", &COOKIE[..], SecretBodies::default()),
        // The document says the answer carries a secret; the handler set nothing.
        ("key-1", &NONE[..], documented),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let first = run_secret(&store, &in_flight, key, &calls, headers, secrets).await;
        assert_eq!(first.status(), StatusCode::CREATED, "{key}");
        assert!(
            body(first).await.contains("tko_s3cr3t_value"),
            "the caller gets it once"
        );

        let again = run_secret(&store, &in_flight, key, &calls, headers, secrets).await;
        assert_eq!(again.status(), StatusCode::CONFLICT, "{key}");
        assert!(again.headers().get(REPLAYED_HEADER).is_none());
        let text = body(again).await;
        assert!(text.contains(codes::IDEMPOTENCY_NOT_REPLAYABLE), "{text}");
        assert!(text.contains("Already performed"), "{text}");
        assert!(!text.contains("tko_s3cr3t_value"), "{text}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the handler ran once for {key}"
        );

        // Another request under the same key is still a mismatch.
        let principal = principal();
        let other = handle(
            &store,
            &in_flight,
            IdempotencyConfig::default(),
            Env {
                secrets,
                ..env(&principal)
            },
            post(key, "{\"name\":\"other\"}"),
            |_request| async { StatusCode::CREATED.into_response() },
        )
        .await;
        assert_eq!(other.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    let records = stored_records(&store).await;
    assert_eq!(records.len(), 3);
    for (record, raw) in records {
        assert!(record.replay_unavailable);
        assert!(record.body.is_empty());
        assert_eq!(record.headers.len(), 0);
        assert_eq!(record.status, 201);
        let raw = String::from_utf8_lossy(&raw);
        assert!(!raw.contains("tko_s3cr3t_value") && !raw.contains("tenko_session"));
    }
}

#[tokio::test]
async fn a_request_body_with_a_secret_is_never_fingerprinted() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let calls = Arc::new(AtomicUsize::new(0));
    let secret_request = Env {
        secrets: SecretBodies {
            request: true,
            response: false,
        },
        ..env(&principal)
    };
    let first = run_with(
        &store,
        &in_flight,
        secret_request,
        post("import-1", "{\"secret\":\"c2VjcmV0\"}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let records = stored_records(&store).await;
    assert!(records[0].0.fingerprint.is_empty(), "no fingerprint");
    assert!(records[0].0.replay_unavailable);

    // Any retry under the key is refused without reading its body; nothing runs twice.
    let polled = Arc::new(AtomicBool::new(false));
    let retry = run_with(
        &store,
        &in_flight,
        secret_request,
        watched_post("import-1", &polled),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert!(!polled.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ordinary_responses_still_replay_next_to_markers() {
    static NO_STORE: [(HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let calls = Arc::new(AtomicUsize::new(0));
    run_secret(
        &store,
        &in_flight,
        "secret",
        &calls,
        &NO_STORE,
        SecretBodies::default(),
    )
    .await;
    let normal = Arc::new(AtomicUsize::new(0));
    run(
        &store,
        &in_flight,
        post("plain", "{}"),
        &normal,
        StatusCode::OK,
    )
    .await;
    let replayed = run(
        &store,
        &in_flight,
        post("plain", "{}"),
        &normal,
        StatusCode::OK,
    )
    .await;
    assert_eq!(replayed.headers()[REPLAYED_HEADER], "true");
    assert_eq!(normal.load(Ordering::SeqCst), 1);
    let records = stored_records(&store).await;
    assert_eq!(
        records.iter().filter(|(r, _)| r.replay_unavailable).count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|(r, _)| !r.replay_unavailable && !r.body.is_empty())
            .count(),
        1
    );
    assert!(!secret_bearing(&HeaderMap::new()));
}

#[tokio::test]
async fn an_unread_rest_longer_than_the_limit_leaves_a_record_that_is_not_replayed() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let small = IdempotencyConfig {
        max_request_bytes: 16,
        ..IdempotencyConfig::default()
    };
    let calls = Arc::new(AtomicUsize::new(0));
    // The handler reads nothing; the middleware reads the rest, at most 16 bytes.
    let ignoring = |request: Request| {
        let calls = Arc::clone(&calls);
        async move {
            drop(request);
            tenko_auth::journal::note_check(&api(), Action::Create, &object());
            calls.fetch_add(1, Ordering::SeqCst);
            (StatusCode::CREATED, "{}").into_response()
        }
    };
    let long = "{\"description\":\"longer than sixteen bytes\"}";
    for _ in 0..2 {
        handle(
            &store,
            &in_flight,
            small,
            env(&principal),
            post("long", long),
            ignoring,
        )
        .await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "performed once");
    let stored = stored_records(&store).await;
    assert!(stored[0].0.fingerprint.is_empty() && stored[0].0.replay_unavailable);
}

/// Allows everything; its scope of every kind is the filter it holds.
struct Scoped(ScopeFilter);

impl Authorizer for Scoped {
    fn check(&self, _: &Principal, _: Action, _: &ObjectRef) -> Result<(), Denied> {
        Ok(())
    }

    fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        self.0.clone()
    }
}

#[tokio::test]
async fn a_changed_scope_refuses_the_replay() {
    use tenko_core::{ScopeRule, TenantId};
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let first = ScopeFilter::Only(vec![ScopeRule::Tenant(TenantId::from(
        uuid::Uuid::from_u128(5),
    ))]);
    let scoped = {
        let first = first.clone();
        move |_request: Request| {
            let first = first.clone();
            async move {
                // As the authorizer does: a check on a scoped kind wants its scope.
                assert!(tenko_auth::journal::note_check(
                    &api(),
                    Action::Create,
                    &object()
                ));
                tenko_auth::journal::note_scope(&api(), Action::Create, ObjectKind::Prefix, &first);
                (StatusCode::CREATED, "{}").into_response()
            }
        }
    };
    let same = Scoped(first.clone());
    let with = |authorizer| Env {
        authorizer: Some(authorizer),
        ..env(&principal)
    };
    let created = handle(
        &store,
        &in_flight,
        IdempotencyConfig::default(),
        with(&same),
        post("scoped", "{}"),
        scoped.clone(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let replayed = handle(
        &store,
        &in_flight,
        IdempotencyConfig::default(),
        with(&same),
        post("scoped", "{}"),
        scoped.clone(),
    )
    .await;
    assert_eq!(replayed.headers()[REPLAYED_HEADER], "true");
    // The grant narrowed: the scope differs, the replay is refused.
    let narrowed = Scoped(ScopeFilter::Nothing);
    let refused = handle(
        &store,
        &in_flight,
        IdempotencyConfig::default(),
        with(&narrowed),
        post("scoped", "{}"),
        scoped,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert!(
        body(refused)
            .await
            .contains(codes::IDEMPOTENCY_NOT_REPLAYABLE)
    );
}

#[tokio::test]
async fn a_retry_longer_than_the_first_request_is_another_request() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let calls = Arc::new(AtomicUsize::new(0));
    run(
        &store,
        &in_flight,
        post("short", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    // A declared length that differs is refused before anything is read.
    let polled = Arc::new(AtomicBool::new(false));
    let mut declared = watched_post("short", &polled);
    declared.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_static("100000000"),
    );
    let refused = run(&store, &in_flight, declared, &calls, StatusCode::CREATED).await;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!polled.load(Ordering::SeqCst));
    // A streamed body is read no further than the first body's length.
    let stream = futures::stream::iter(
        (0..1000).map(|_| Ok::<_, std::io::Error>(BodyBytes::from_static(b"{}"))),
    );
    let long = HttpRequest::builder()
        .method(Method::POST)
        .uri("/api/v1/prefixes")
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", "short")
        .body(Body::from_stream(stream))
        .expect("request");
    let refused = run(&store, &in_flight, long, &calls, StatusCode::CREATED).await;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn fingerprints_are_keyed_per_process() {
    let uri: axum::http::Uri = "/api/v1/prefixes".parse().expect("uri");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let body = b"{\"cidr\":\"192.0.2.0/24\"}";
    let (first, second) = (InFlight::default().key(), InFlight::default().key());
    let a = first.fingerprint(&Method::POST, &uri, &headers, body);
    assert_eq!(a, first.fingerprint(&Method::POST, &uri, &headers, body));
    assert_ne!(a, second.fingerprint(&Method::POST, &uri, &headers, body));
    assert_ne!(first.id, second.id);
    assert_ne!(a, first.fingerprint(&Method::POST, &uri, &headers, b"{}"));
    // Not the plain SHA-256 of the same input.
    let mut plain = Sha256::new();
    plain.update(b"POST\0/api/v1/prefixes\0application/json\0");
    plain.update(body);
    let plain: [u8; 32] = plain.finalize().into();
    assert_ne!(a, plain);
    assert!(!format!("{first:?}").contains("key:"));
    // Keys from one cluster key agree on every controller; another cluster key differs.
    let cluster = FingerprintKey::from_cluster_key(&[7; 32]);
    let again = FingerprintKey::from_cluster_key(&[7; 32]);
    let other = FingerprintKey::from_cluster_key(&[8; 32]);
    assert_eq!(cluster.id(), again.id());
    assert_ne!(cluster.id(), other.id());
    let c = cluster.fingerprint(&Method::POST, &uri, &headers, body);
    assert_eq!(c, again.fingerprint(&Method::POST, &uri, &headers, body));
    assert_ne!(c, other.fingerprint(&Method::POST, &uri, &headers, body));
}

#[test]
fn ceremonies_are_recognized() {
    for path in [
        "/api/v1/setup",
        "/api/v1/auth/login/password",
        "/api/v1/auth/login/totp",
        "/api/v1/auth/login/recovery",
        "/api/v1/auth/webauthn/login/finish",
        "/api/v1/auth/password/check",
        "/api/v1/nodes/enroll",
        "/api/v1/nodes/enroll/",
    ] {
        assert!(is_ceremony(&Method::POST, path), "{path}");
    }
    for (method, path) in [
        (Method::GET, "/api/v1/setup"),
        (Method::POST, "/api/v1/prefixes"),
        (Method::POST, "/api/v1/auth/tokens"),
        (Method::POST, "/api/v1/auth/password"),
        (Method::POST, "/api/v1/users"),
        (Method::POST, "/setup"),
        (Method::POST, "/api/v1/auth/login"),
        (Method::POST, "/api/v1/dns/kerberos/rotate"),
    ] {
        assert!(!is_ceremony(&method, path), "{method} {path}");
    }
}

#[tokio::test]
async fn a_ceremony_body_leaves_no_fingerprint() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let calls = Arc::new(AtomicUsize::new(0));
    for (path, body) in [
        (
            "/api/v1/auth/login/password",
            "{\"username\":\"ada\",\"password\":\"correct horse\"}",
        ),
        (
            "/api/v1/setup",
            "{\"setup_token\":\"st-1\",\"admin\":{\"password\":\"7391\"}}",
        ),
    ] {
        for _ in 0..2 {
            let request = HttpRequest::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "sign-in-1")
                .body(Body::from(body))
                .expect("request");
            let calls = Arc::clone(&calls);
            let response = handle(
                &store,
                &in_flight,
                IdempotencyConfig::default(),
                env(&principal),
                request,
                move |_request| async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK.into_response()
                },
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert!(response.headers().get(REPLAYED_HEADER).is_none());
        }
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "every request reached its handler"
    );
    assert!(
        stored_records(&store).await.is_empty(),
        "no record, no fingerprint"
    );
}

#[tokio::test]
async fn records_of_another_process_or_an_earlier_format_are_not_replayed() {
    let store = MemStore::default();
    let earlier = InFlight::default();
    let calls = Arc::new(AtomicUsize::new(0));
    run(
        &store,
        &earlier,
        post("k-restart", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    let stored = stored_records(&store).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0.key_id.as_ref(), earlier.key().id.as_slice());

    // After a restart the record cannot be compared: 409, and the handler does not run.
    let restarted = InFlight::default();
    let retry = run(
        &store,
        &restarted,
        post("k-restart", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert!(
        body(retry)
            .await
            .contains(codes::IDEMPOTENCY_NOT_REPLAYABLE)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // A record of the earlier format (no journal, no stamp) is not replayed either.
    let key = record_key(&principal(), &IdempotencyKey::new("legacy").expect("key"));
    let legacy = StoredResponse {
        format: 0,
        checks: Vec::new(),
        stamp: Bytes::new(),
        ..stored[0].0.clone()
    };
    let mut batch = WriteBatch::new(principal(), Timestamp::now());
    batch.put(
        TABLE,
        Bytes::copy_from_slice(&key),
        to_cbor(&legacy).expect("cbor"),
    );
    store.propose(batch).await.expect("legacy");
    let retry = run(
        &store,
        &earlier,
        post("legacy", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_retry_on_another_controller_replays_under_the_cluster_key() {
    let store = MemStore::default();
    let (one, two) = (InFlight::default(), InFlight::default());
    one.set_key(FingerprintKey::from_cluster_key(&[3; 32]));
    two.set_key(FingerprintKey::from_cluster_key(&[3; 32]));
    let calls = Arc::new(AtomicUsize::new(0));
    let first = run(
        &store,
        &one,
        post("k-cluster", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let retry = run(
        &store,
        &two,
        post("k-cluster", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CREATED);
    assert_eq!(retry.headers()[REPLAYED_HEADER], "true");
    assert_eq!(body(retry).await, "{\"call\":1}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Another body under the same key is still a mismatch on the other controller.
    let other = run(
        &store,
        &two,
        post("k-cluster", "{\"a\":1}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(other.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------------------
// The secret bodies of the document.

#[test]
fn the_document_marks_every_secret_body_of_a_post() {
    let document = serde_json::to_value(crate::openapi()).expect("document");
    let found = secret_bodies(&document);
    let path = |relative: &str| format!("{API_BASE}{relative}");
    // Secrets typed as `SecretString`, found without a list.
    for (relative, request, response) in [
        ("/auth/tokens", false, true),
        ("/auth/recovery-codes", false, true),
        ("/auth/totp/enroll/start", false, true),
        ("/auth/totp/enroll/finish", true, true),
        ("/auth/webauthn/register/finish", false, true),
        ("/access/service-accounts/{id}/tokens", false, true),
        ("/secrets", true, false),
        ("/secrets/{id}/reveal", false, true),
        ("/system/backups", true, false),
        ("/auth/providers", true, false),
        ("/auth/providers/{id}/test", true, false),
        ("/dns/kerberos/adopt", true, false),
        ("/dns/kerberos/import", true, false),
        ("/users", true, false),
        ("/auth/password", true, false),
        // Plain strings, from the list.
        ("/dns/keys", true, true),
        ("/nodes/enrollments", false, true),
        ("/migrate/mirrors", false, true),
        ("/migrate/mirrors/{id}/token", false, true),
    ] {
        assert_eq!(
            found.get(&path(relative)),
            Some(&SecretBodies { request, response }),
            "{relative}"
        );
    }
    assert!(!found.contains_key(&path("/prefixes")));
    // A body that is not JSON (multipart, binary) is never fingerprinted.
    for relative in ["/imports", "/system/updates/upload"] {
        assert!(
            found
                .get(&path(relative))
                .is_some_and(|bodies| bodies.request),
            "{relative}"
        );
    }
    // A POST the document does not list is taken as carrying secrets both ways.
    let table = crate::middleware::metrics::RouteTable::get();
    assert_eq!(
        table.secrets(table.other_row(&Method::POST)),
        SecretBodies {
            request: true,
            response: true
        }
    );
    assert_eq!(
        table.secrets(table.row(Some(&path("/prefixes")), &Method::POST)),
        SecretBodies::default()
    );
    // Every listed plain secret is a documented `POST`.
    let paths = document["paths"].as_object().expect("paths");
    for relative in PLAIN_SECRETS.0.iter().chain(PLAIN_SECRETS.1.iter()) {
        assert!(
            paths
                .get(&path(relative))
                .is_some_and(|item| item.get("post").is_some()),
            "{relative}"
        );
    }
}

/// Field names that look like a secret, and the fields that carry such a name without
/// being one (with why).
const SECRET_NAMES: [&str; 12] = [
    "secret",
    "token",
    "password",
    "passphrase",
    "keytab",
    "codes",
    "recovery_codes",
    "setup_token",
    "client_secret",
    "private_key",
    "otpauth_uri",
    "value",
];
const NOT_SECRETS: [(&str, &str); 3] = [
    // A reference to a vault secret (its id), not its value.
    ("SecretRef", "secret"),
    // A parameter of an SVCB or HTTPS record.
    ("SvcParam", "value"),
    // An address, a range or a name a scan targets.
    ("ScanTarget", "value"),
];

/// Every field of a `POST` request or 2xx response body named like a secret is typed as one
/// (`SecretString`, format `password`), or its route is in [`PLAIN_SECRETS`], or it is
/// listed in `NOT_SECRETS` with the reason. A new route that answers with a secret in a
/// plain string fails here until it is typed or listed.
#[test]
fn every_field_named_like_a_secret_is_typed_or_listed() {
    let document = serde_json::to_value(crate::openapi()).expect("document");
    let schemas = document["components"]["schemas"]
        .as_object()
        .expect("schemas")
        .clone();
    let found = secret_bodies(&document);
    let mut missing = Vec::new();
    for (path, item) in document["paths"].as_object().expect("paths") {
        let Some(post) = item.get("post") else {
            continue;
        };
        // A ceremony's body never meets the middleware.
        if is_ceremony(&Method::POST, path) {
            continue;
        }
        let bodies = found.get(path).copied().unwrap_or_default();
        let mut check = |value: &serde_json::Value, covered: bool, side: &str| {
            let mut names = Vec::new();
            plain_secret_fields(value, &schemas, &mut BTreeSet::new(), &mut names);
            for (schema, field) in names {
                let listed = NOT_SECRETS.contains(&(schema.as_str(), field.as_str()));
                if !covered && !listed {
                    missing.push(format!("{side} of POST {path}: {schema}.{field}"));
                }
            }
        };
        if let Some(request) = post.get("requestBody") {
            check(request, bodies.request, "request");
        }
        for (status, answer) in post["responses"].as_object().expect("responses") {
            if status.starts_with('2') {
                check(answer, bodies.response, "response");
            }
        }
    }
    assert!(missing.is_empty(), "untyped secrets: {missing:#?}");
}

/// The fields named like a secret that are not typed as one, as (schema, field).
fn plain_secret_fields(
    value: &serde_json::Value,
    schemas: &serde_json::Map<String, serde_json::Value>,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<(String, String)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(name) = map
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                .and_then(|reference| reference.rsplit('/').next())
            {
                if seen.insert(name.to_owned())
                    && let Some(schema) = schemas.get(name)
                {
                    if let Some(properties) = schema
                        .get("properties")
                        .and_then(serde_json::Value::as_object)
                    {
                        for (field, property) in properties {
                            if SECRET_NAMES.contains(&field.as_str())
                                && !reaches_secret(property, Some(schemas), &mut HashSet::new())
                                && property_is_text(property, schemas)
                            {
                                out.push((name.to_owned(), field.clone()));
                            }
                        }
                    }
                    // Walk the schema's parts, not the schema as an inline object again.
                    if let Some(parts) = schema.as_object() {
                        for (key, value) in parts {
                            match key.as_str() {
                                "description" | "example" | "examples" => {}
                                "properties" => {
                                    for property in
                                        value.as_object().into_iter().flat_map(|map| map.values())
                                    {
                                        plain_secret_fields(property, schemas, seen, out);
                                    }
                                }
                                _ => plain_secret_fields(value, schemas, seen, out),
                            }
                        }
                    }
                }
                return;
            }
            if let Some(properties) = map.get("properties").and_then(serde_json::Value::as_object) {
                // `value` is the content field of every adjacently tagged enum.
                for (field, property) in properties {
                    if SECRET_NAMES.contains(&field.as_str())
                        && field != "value"
                        && !reaches_secret(property, Some(schemas), &mut HashSet::new())
                        && property_is_text(property, schemas)
                    {
                        out.push(("(inline)".to_owned(), field.clone()));
                    }
                }
            }
            for (key, value) in map {
                if !matches!(key.as_str(), "description" | "example" | "examples") {
                    plain_secret_fields(value, schemas, seen, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                plain_secret_fields(item, schemas, seen, out);
            }
        }
        _ => {}
    }
}

/// Whether a property holds text (a string, or an array or option of strings), which is
/// where a secret could hide.
fn property_is_text(
    property: &serde_json::Value,
    schemas: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let text = |value: &serde_json::Value| match value.get("type") {
        Some(serde_json::Value::String(kind)) => kind == "string",
        Some(serde_json::Value::Array(kinds)) => kinds.iter().any(|kind| kind == "string"),
        _ => false,
    };
    if text(property) {
        return true;
    }
    if let Some(items) = property.get("items") {
        return property_is_text(items, schemas);
    }
    if let Some(variants) = property.get("oneOf").and_then(serde_json::Value::as_array) {
        return variants
            .iter()
            .any(|variant| property_is_text(variant, schemas));
    }
    property
        .get("$ref")
        .and_then(serde_json::Value::as_str)
        .and_then(|reference| reference.rsplit('/').next())
        .and_then(|name| schemas.get(name))
        .is_some_and(text)
}

// ---------------------------------------------------------------------------------------
// Expiry.

/// Writes `count` records created at `created`, through the middleware's own save.
async fn seed(store: &MemStore, prefix: &str, count: usize, created: Timestamp) {
    let principal = principal();
    for n in 0..count {
        let key = record_key(
            &principal,
            &IdempotencyKey::new(format!("{prefix}-{n}")).expect("key"),
        );
        let record = Record {
            principal: &principal,
            key: &key,
            fingerprint: Some(([1; 32], 2)),
            key_id: &[0; 8],
            created,
            expected: None,
            journal: tenko_auth::journal::Journal::default(),
            stamp: [0; 32],
            secrets: SecretBodies::default(),
        };
        let stored = StoredResponse {
            fingerprint: Bytes::from_static(&[1; 32]),
            status: 201,
            headers: Vec::new(),
            body: Bytes::from_static(b"{}"),
            created,
            replay_unavailable: false,
            key_id: Bytes::new(),
            format: RECORD_FORMAT,
            checks: vec![(Action::Create, object())],
            scopes: Vec::new(),
            body_len: 2,
            fresh_session: false,
            stamp: Bytes::new(),
        };
        save(store, &record, &stored).await.expect("save");
    }
}

async fn count(store: &MemStore, table: &TableName) -> usize {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan(table, KeyRange::all(), usize::MAX, false)
        .expect("scan")
        .len()
}

const TTL: Duration = Duration::from_secs(24 * 3600);

fn hours_ago(hours: u64) -> Timestamp {
    Timestamp::now()
        .checked_sub(Duration::from_secs(hours * 3600))
        .expect("time")
}

#[tokio::test]
async fn the_purge_takes_every_expired_row_in_bounded_pages_and_keeps_the_live_ones() {
    let store = MemStore::default();
    seed(&store, "old", 2_345, hours_ago(30)).await;
    seed(&store, "new", 1_000, hours_ago(1)).await;
    // Before this change the purge examined the first 10,000 keys in key order; here the
    // pages are 100 rows, so the run needs 24 batches and must not stop after any of them.
    let purged = purge_pages(&store, TTL, Timestamp::now(), None, 100)
        .await
        .expect("purge");
    assert_eq!(purged, 2_345);
    assert_eq!(count(&store, &TABLE).await, 1_000);
    assert_eq!(count(&store, &EXPIRY_TABLE).await, 1_000);
    // Nothing is left to do.
    assert_eq!(
        purge_expired(&store, TTL, Timestamp::now(), None)
            .await
            .expect("purge"),
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_purge_yields_to_other_leader_services_between_pages() {
    let store = Arc::new(MemStore::default());
    seed(&store, "old", 1_000, hours_ago(30)).await;
    let ticks = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    // Another service on the same thread: it only runs when the purge yields.
    let other = {
        let (ticks, done) = (Arc::clone(&ticks), Arc::clone(&done));
        tokio::spawn(async move {
            while !done.load(Ordering::SeqCst) {
                ticks.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        })
    };
    let purged = purge_pages(store.as_ref(), TTL, Timestamp::now(), None, 50)
        .await
        .expect("purge");
    done.store(true, Ordering::SeqCst);
    other.await.expect("other");
    assert_eq!(purged, 1_000);
    assert!(
        ticks.load(Ordering::SeqCst) >= 19,
        "the other service ran between the 20 pages: {}",
        ticks.load(Ordering::SeqCst)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_leader_change_in_the_middle_of_a_purge_loses_nothing() {
    let store = Arc::new(MemStore::default());
    seed(&store, "old", 600, hours_ago(30)).await;
    seed(&store, "new", 50, hours_ago(1)).await;
    // The purge of the term with epoch 0 runs; another controller takes office after its
    // first page (the epoch moves to 1).
    let bumper = {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            loop {
                if count(&store, &EXPIRY_TABLE).await < 650 {
                    let mut batch = WriteBatch::new(principal(), Timestamp::now());
                    batch.bump(LEADER_EPOCH);
                    store.propose(batch).await.expect("bump");
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
    };
    let deposed = purge_pages(store.as_ref(), TTL, Timestamp::now(), Some(0), 100).await;
    bumper.await.expect("bumper");
    assert!(deposed.is_err(), "the deposed leader's next page fails");
    let left = count(&store, &TABLE).await;
    assert!(left < 650 && left > 50, "one page went: {left}");
    // Every expired record still has its row; the new leader's purge finishes the work.
    assert_eq!(count(&store, &EXPIRY_TABLE).await, left);
    let purged = purge_pages(store.as_ref(), TTL, Timestamp::now(), Some(1), 100)
        .await
        .expect("purge");
    assert_eq!(purged, left - 50);
    assert_eq!(count(&store, &TABLE).await, 50, "the live records stay");
}

#[tokio::test]
async fn a_replaced_record_outlives_its_old_expiry_row() {
    let store = MemStore::default();
    let in_flight = InFlight::default();
    let principal = principal();
    let calls = Arc::new(AtomicUsize::new(0));
    // A record that expired, and its key used again: the new record replaces the old row
    // and its expiry row in one batch.
    let key = record_key(&principal, &IdempotencyKey::new("again").expect("key"));
    let old = hours_ago(30);
    let record = Record {
        principal: &principal,
        key: &key,
        fingerprint: Some(([1; 32], 2)),
        key_id: &[0; 8],
        created: old,
        expected: None,
        journal: tenko_auth::journal::Journal::default(),
        stamp: [0; 32],
        secrets: SecretBodies::default(),
    };
    let stored = StoredResponse {
        fingerprint: Bytes::from_static(&[1; 32]),
        status: 201,
        headers: Vec::new(),
        body: Bytes::new(),
        created: old,
        replay_unavailable: false,
        key_id: Bytes::new(),
        format: RECORD_FORMAT,
        checks: Vec::new(),
        scopes: Vec::new(),
        body_len: 2,
        fresh_session: false,
        stamp: Bytes::new(),
    };
    save(&store, &record, &stored).await.expect("save");
    run(
        &store,
        &in_flight,
        post("again", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(count(&store, &EXPIRY_TABLE).await, 1, "the old row went");
    // An expiry row left behind by an older controller (which replaces records without
    // their rows) names a record that is newer now: the purge removes the row only.
    let mut batch = WriteBatch::new(principal.clone(), Timestamp::now());
    batch.put(EXPIRY_TABLE, expiry_key(old, &key), Bytes::new());
    store.propose(batch).await.expect("stale row");
    let purged = purge_expired(&store, TTL, Timestamp::now(), None)
        .await
        .expect("purge");
    assert_eq!(purged, 0);
    assert_eq!(count(&store, &TABLE).await, 1);
    assert_eq!(count(&store, &EXPIRY_TABLE).await, 1);
    let again = run(
        &store,
        &in_flight,
        post("again", "{}"),
        &calls,
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(again.headers()[REPLAYED_HEADER], "true");
}

#[tokio::test]
async fn the_sweep_indexes_or_removes_the_records_of_an_earlier_version() {
    let store = MemStore::default();
    let principal = principal();
    // Records of the earlier format, written without expiry rows: 40 expired, 30 live, and
    // one that cannot be read.
    for (prefix, n, created) in [("gone", 40, hours_ago(30)), ("kept", 30, hours_ago(2))] {
        for i in 0..n {
            let key = record_key(
                &principal,
                &IdempotencyKey::new(format!("{prefix}-{i}")).expect("key"),
            );
            let legacy = StoredResponse {
                fingerprint: Bytes::from_static(&[1; 32]),
                status: 201,
                headers: Vec::new(),
                body: Bytes::new(),
                created,
                replay_unavailable: false,
                key_id: Bytes::new(),
                format: 0,
                checks: Vec::new(),
                scopes: Vec::new(),
                body_len: 0,
                fresh_session: false,
                stamp: Bytes::new(),
            };
            let mut batch = WriteBatch::new(principal.clone(), Timestamp::now());
            batch.put(
                TABLE,
                Bytes::copy_from_slice(&key),
                to_cbor(&legacy).expect("cbor"),
            );
            store.propose(batch).await.expect("legacy");
        }
    }
    let mut batch = WriteBatch::new(principal.clone(), Timestamp::now());
    batch.put(
        TABLE,
        Bytes::from_static(&[0; 32]),
        Bytes::from_static(b"\xff"),
    );
    store.propose(batch).await.expect("garbage");
    seed(&store, "current", 20, hours_ago(1)).await;

    let changed = sweep_unindexed(&store, TTL, Timestamp::now(), None)
        .await
        .expect("sweep");
    assert_eq!(changed, 40 + 30 + 1);
    assert_eq!(count(&store, &TABLE).await, 50);
    assert_eq!(
        count(&store, &EXPIRY_TABLE).await,
        50,
        "every record has its row"
    );
    // A second sweep finds nothing; the purge takes the legacy records once they expire.
    assert_eq!(
        sweep_unindexed(&store, TTL, Timestamp::now(), None)
            .await
            .expect("sweep"),
        0
    );
    let later = Timestamp::now()
        .checked_add(Duration::from_secs(22 * 3600))
        .expect("time");
    assert_eq!(
        purge_expired(&store, TTL, later, None)
            .await
            .expect("purge"),
        30,
        "the legacy records, not the current ones"
    );
}
