//! `Idempotency-Key` on `POST` (API-04).
//!
//! Two layers make a retried `POST` safe:
//!
//! 1. **The store.** `RequestCtx::idempotency` carries the key, and handlers build their
//!    batch with `WriteBatch::for_request`, so the store records it under (principal, key)
//!    and replays the first `Committed` for an identical batch (ADR 0011 decision 5).
//! 2. **This middleware** replays the first *response*, which the store alone cannot do:
//!    a retried create computes a new id and thus a different batch. The first successful
//!    (2xx) response of a key is stored in the store table `sys.api_idempotency`, keyed by
//!    SHA-256 of the principal's subject and the key, together with a fingerprint of the
//!    request (method, path and query, content type, body). A retry with the same
//!    fingerprint within [`IdempotencyConfig::ttl`] gets the stored status, headers and
//!    body with `Idempotency-Replayed: true`; the same key with another request is 422
//!    `sys.idempotency_mismatch`; a retry while the first request still runs is 409
//!    `sys.idempotency_in_flight` with `Retry-After: 1`. Failed requests are not stored, so
//!    they can be retried. Records older than the TTL are ignored and purged hourly.
//!
//! **Secret-bearing responses are never stored (NEVER-01).** A successful response that
//! carries `Cache-Control: no-store` (set by every endpoint that returns a one-time secret:
//! personal tokens, recovery codes, TOTP seeds) or any `Set-Cookie` header leaves only a
//! bodiless marker: the record key, the status, the request fingerprint and the flag
//! `replay_unavailable`, without headers or body. A retry with the same key and request is
//! then answered 409 `sys.idempotency_not_replayable`: the handler does not run a second
//! time (no second token) and the secret is not served again. The API middleware adds its
//! default `Cache-Control: no-store` only after this check, so the rule sees what the
//! handler set.
//!
//! The record is a separate store write after the handler's own batch. If the node fails
//! between the two, a retry runs the handler again and the store's own idempotency decides
//! (a replay of the same batch, or 422 when the batch differs).

use std::{
    collections::HashSet,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use axum::{
    body::{Body, HttpBody, to_bytes},
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::{
    IdempotencyKey, Principal, TableName, Timestamp,
    codec::{from_cbor, to_cbor},
};
use tenko_store::{KeyRange, ReadConsistency, Store, WriteBatch};

use crate::problem::{ApiError, codes};

/// The store table of stored responses.
pub(crate) const TABLE: TableName = TableName::from_static("sys.api_idempotency");

/// Header that marks a replayed response.
pub const REPLAYED_HEADER: HeaderName = HeaderName::from_static("idempotency-replayed");

/// Settings of the idempotency middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdempotencyConfig {
    /// How long a stored response is replayed.
    pub ttl: Duration,
    /// Largest request body the middleware buffers to fingerprint; larger bodies with a key
    /// are refused with 413.
    pub max_request_bytes: usize,
    /// Largest response body that is stored; larger responses are not replayable.
    pub max_response_bytes: usize,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(24 * 3600),
            max_request_bytes: 32 * 1024 * 1024,
            max_response_bytes: 1024 * 1024,
        }
    }
}

/// A stored response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredResponse {
    fingerprint: Bytes,
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: Bytes,
    created: Timestamp,
    /// A marker of a secret-bearing response: the request was performed, but its response
    /// was not stored and cannot be replayed.
    #[serde(default)]
    replay_unavailable: bool,
}

/// Keys of requests being processed on this node.
#[derive(Debug, Default)]
pub(crate) struct InFlight {
    keys: Mutex<HashSet<[u8; 32]>>,
}

/// Removes a key from [`InFlight`] when dropped.
struct InFlightGuard<'a> {
    set: &'a InFlight,
    key: [u8; 32],
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.set
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
    }
}

impl InFlight {
    fn enter(&self, key: [u8; 32]) -> Option<InFlightGuard<'_>> {
        let inserted = self
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
        inserted.then_some(InFlightGuard { set: self, key })
    }
}

/// Headers kept with a stored response.
const KEPT_HEADERS: [HeaderName; 3] = [header::CONTENT_TYPE, header::LOCATION, header::ETAG];

/// Runs `next` under the idempotency rules when the request is a `POST` with a key and an
/// authenticated principal; any other request goes straight through.
pub(crate) async fn handle<F, Fut>(
    store: &dyn Store,
    in_flight: &InFlight,
    config: IdempotencyConfig,
    principal: Option<&Principal>,
    request: Request,
    next: F,
) -> Response
where
    F: FnOnce(Request) -> Fut,
    Fut: Future<Output = Response>,
{
    // Requests without a valid key go through; `Ctx` answers an invalid key with the
    // precise problem details. Unauthenticated requests go through as well: the handler
    // refuses them, or the endpoint is public.
    let (Some(key), Some(principal)) = (keyed_post(&request), principal) else {
        return next(request).await;
    };
    let record_key = record_key(principal, &key);

    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, config.max_request_bytes).await else {
        return ApiError::new(
            codes::BODY_TOO_LARGE,
            413,
            format!(
                "a request with an Idempotency-Key may carry at most {} bytes",
                config.max_request_bytes
            ),
        )
        .into_response();
    };
    let fingerprint = fingerprint(&parts.method, &parts.uri, &parts.headers, &body);
    let now = Timestamp::now();

    let expected = match lookup(store, &record_key, &fingerprint, now, config.ttl).await {
        Ok(expected) => expected,
        Err(response) => return *response,
    };
    let Some(_guard) = in_flight.enter(record_key) else {
        let mut response = ApiError::new(
            codes::IDEMPOTENCY_IN_FLIGHT,
            409,
            "a request with this Idempotency-Key is still being processed",
        )
        .into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return response;
    };

    let response = next(Request::from_parts(parts, Body::from(body))).await;
    let record = Record {
        principal,
        key: &record_key,
        fingerprint: &fingerprint,
        created: now,
        expected,
    };
    remember(store, config, &record, response).await
}

/// The key of a `POST` that carries a valid `Idempotency-Key`.
fn keyed_post(request: &Request) -> Option<IdempotencyKey> {
    if request.method() != Method::POST {
        return None;
    }
    let raw = request.headers().get(crate::extract::IDEMPOTENCY_HEADER)?;
    let text = std::str::from_utf8(raw.as_bytes()).ok()?;
    IdempotencyKey::new(text).ok()
}

/// Looks up a stored response. `Err` carries the response to send (a replay or a refusal);
/// `Ok` the revision an expired record has (`None` when there is none).
async fn lookup(
    store: &dyn Store,
    record_key: &[u8; 32],
    fingerprint: &[u8; 32],
    now: Timestamp,
    ttl: Duration,
) -> Result<Option<tenko_core::Revision>, Box<Response>> {
    let view = store
        .read(ReadConsistency::Local)
        .await
        .map_err(|error| Box::new(ApiError::from(error).into_response()))?;
    let existing = view
        .get(&TABLE, record_key)
        .ok()
        .flatten()
        .and_then(|versioned| {
            from_cbor::<StoredResponse>(&versioned.value)
                .ok()
                .map(|stored| (stored, versioned.revision))
        });
    let Some((stored, revision)) = existing else {
        return Ok(None);
    };
    if now.saturating_since(stored.created) >= ttl {
        return Ok(Some(revision));
    }
    if stored.fingerprint.as_ref() != fingerprint.as_slice() {
        return Err(Box::new(
            ApiError::new(
                codes::IDEMPOTENCY_MISMATCH,
                422,
                "the Idempotency-Key was already used for a different request",
            )
            .into_response(),
        ));
    }
    if stored.replay_unavailable {
        return Err(Box::new(not_replayable().into_response()));
    }
    Err(Box::new(replay(&stored)))
}

/// 409 `sys.idempotency_not_replayable`: the request was performed, and its response held a
/// secret that was deliberately not stored.
fn not_replayable() -> ApiError {
    ApiError::from_coded_error(
        tenko_core::CodedError::new(
            codes::IDEMPOTENCY_NOT_REPLAYABLE,
            409,
            "a request with this Idempotency-Key was already performed; its response carried \
             a secret and is not kept, so it cannot be replayed",
        )
        .with_title("Already performed; the original response cannot be replayed"),
    )
}

/// Whether a response must not be stored: `Cache-Control: no-store` or a `Set-Cookie`.
fn secret_bearing(headers: &HeaderMap) -> bool {
    headers.contains_key(header::SET_COOKIE)
        || headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
}

/// What identifies the record of one request.
struct Record<'a> {
    principal: &'a Principal,
    key: &'a [u8; 32],
    fingerprint: &'a [u8; 32],
    created: Timestamp,
    expected: Option<tenko_core::Revision>,
}

/// Stores a small successful response and passes it on; other responses pass unchanged.
async fn remember(
    store: &dyn Store,
    config: IdempotencyConfig,
    record: &Record<'_>,
    response: Response,
) -> Response {
    if !response.status().is_success() {
        return response;
    }
    if secret_bearing(response.headers()) {
        let marker = StoredResponse {
            fingerprint: Bytes::copy_from_slice(record.fingerprint),
            status: response.status().as_u16(),
            headers: Vec::new(),
            body: Bytes::new(),
            created: record.created,
            replay_unavailable: true,
        };
        if let Err(error) = save(store, record, &marker).await {
            tracing::warn!(%error, "could not store the marker of an idempotent request");
        }
        return response;
    }
    let small = response.body().size_hint().exact().is_some_and(|size| {
        usize::try_from(size).is_ok_and(|size| size <= config.max_response_bytes)
    });
    if !small {
        return response;
    }
    let (parts, body) = response.into_parts();
    let Ok(body) = to_bytes(body, config.max_response_bytes).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let stored = StoredResponse {
        fingerprint: Bytes::copy_from_slice(record.fingerprint),
        status: parts.status.as_u16(),
        headers: KEPT_HEADERS
            .iter()
            .filter_map(|name| {
                let value = parts.headers.get(name)?.to_str().ok()?;
                Some((name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body: body.clone(),
        created: record.created,
        replay_unavailable: false,
    };
    if let Err(error) = save(store, record, &stored).await {
        tracing::warn!(%error, "could not store the response of an idempotent request");
    }
    Response::from_parts(parts, Body::from(body))
}

/// SHA-256 of the principal's subject and the key: the record key.
fn record_key(principal: &Principal, key: &IdempotencyKey) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(principal.subject().as_bytes());
    hash.update([0]);
    hash.update(key.as_str().as_bytes());
    hash.finalize().into()
}

/// SHA-256 of what makes two requests the same.
fn fingerprint(
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(method.as_str().as_bytes());
    hash.update([0]);
    hash.update(
        uri.path_and_query()
            .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str)
            .as_bytes(),
    );
    hash.update([0]);
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        hash.update(content_type.as_bytes());
    }
    hash.update([0]);
    hash.update(body);
    hash.finalize().into()
}

fn replay(stored: &StoredResponse) -> Response {
    let mut response = Response::new(Body::from(stored.body.clone()));
    *response.status_mut() = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    for (name, value) in &stored.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
        .headers_mut()
        .insert(REPLAYED_HEADER, HeaderValue::from_static("true"));
    response
}

async fn save(
    store: &dyn Store,
    record: &Record<'_>,
    stored: &StoredResponse,
) -> Result<(), ApiError> {
    let value = to_cbor(stored).map_err(|error| {
        ApiError::from_coded_error(tenko_core::CodedError::internal(error.to_string()))
    })?;
    let key = Bytes::copy_from_slice(record.key);
    let mut batch = WriteBatch::new(record.principal.clone(), stored.created);
    batch
        .expect_version(TABLE, key.clone(), record.expected)
        .put(TABLE, key, value);
    store.propose(batch).await?;
    Ok(())
}

/// Deletes stored responses older than `ttl`; returns how many. Runs hourly in the server.
pub(crate) async fn purge_expired(
    store: &dyn Store,
    ttl: Duration,
    now: Timestamp,
) -> Result<usize, ApiError> {
    let view = store.read(ReadConsistency::Local).await?;
    let rows = view.scan(&TABLE, KeyRange::all(), 10_000, false)?;
    let mut batch = WriteBatch::new(Principal::system(tenko_core::SystemComponent::Api), now);
    let mut purged = 0;
    for (key, versioned) in rows {
        let expired = from_cbor::<StoredResponse>(&versioned.value)
            .map_or(true, |stored| now.saturating_since(stored.created) >= ttl);
        if expired {
            batch
                .expect_version(TABLE, key.clone(), Some(versioned.revision))
                .delete(TABLE, key);
            purged += 1;
        }
    }
    if purged > 0 {
        store.propose(batch).await?;
    }
    Ok(purged)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::http::Request as HttpRequest;
    use tenko_core::SystemComponent;
    use tenko_store::MemStore;

    use super::*;

    fn principal() -> Principal {
        Principal::system(SystemComponent::Api)
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

    async fn run(
        store: &MemStore,
        in_flight: &InFlight,
        request: Request,
        calls: &Arc<AtomicUsize>,
        status: StatusCode,
    ) -> Response {
        let calls = Arc::clone(calls);
        handle(
            store,
            in_flight,
            IdempotencyConfig::default(),
            Some(&principal()),
            request,
            move |_request| async move {
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

    /// Runs the middleware around a handler that answers 201 with a secret in the body and
    /// the given extra headers.
    async fn run_secret(
        store: &MemStore,
        in_flight: &InFlight,
        key: &str,
        calls: &Arc<AtomicUsize>,
        headers: &'static [(HeaderName, &'static str)],
    ) -> Response {
        let calls = Arc::clone(calls);
        handle(
            store,
            in_flight,
            IdempotencyConfig::default(),
            Some(&principal()),
            post(key, "{\"name\":\"ci\"}"),
            move |_request| async move {
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
        let store = MemStore::default();
        let in_flight = InFlight::default();
        for (key, headers) in [("token-1", &NO_STORE[..]), ("login-1", &COOKIE[..])] {
            let calls = Arc::new(AtomicUsize::new(0));
            let first = run_secret(&store, &in_flight, key, &calls, headers).await;
            assert_eq!(first.status(), StatusCode::CREATED, "{key}");
            assert!(
                body(first).await.contains("tko_s3cr3t_value"),
                "the caller gets it once"
            );

            let again = run_secret(&store, &in_flight, key, &calls, headers).await;
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
            let other = handle(
                &store,
                &in_flight,
                IdempotencyConfig::default(),
                Some(&principal()),
                post(key, "{\"name\":\"other\"}"),
                |_request| async { StatusCode::CREATED.into_response() },
            )
            .await;
            assert_eq!(other.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }

        let records = stored_records(&store).await;
        assert_eq!(records.len(), 2);
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
    async fn ordinary_responses_still_replay_next_to_markers() {
        static NO_STORE: [(HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];
        let store = MemStore::default();
        let in_flight = InFlight::default();
        let calls = Arc::new(AtomicUsize::new(0));
        run_secret(&store, &in_flight, "secret", &calls, &NO_STORE).await;
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
    async fn expired_records_are_purged() {
        let store = MemStore::default();
        let in_flight = InFlight::default();
        let calls = Arc::new(AtomicUsize::new(0));
        run(
            &store,
            &in_flight,
            post("old", "{}"),
            &calls,
            StatusCode::OK,
        )
        .await;
        let later = Timestamp::now()
            .checked_add(Duration::from_secs(25 * 3600))
            .expect("time");
        let purged = purge_expired(&store, Duration::from_secs(24 * 3600), later)
            .await
            .expect("purge");
        assert_eq!(purged, 1);
        let purged = purge_expired(&store, Duration::from_secs(24 * 3600), later)
            .await
            .expect("purge");
        assert_eq!(purged, 0);
    }
}
