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
//!    they can be retried.
//!
//! **Nothing is buffered before the handler.** The record is looked up by its key before the
//! body is read. A first request streams its body through the fingerprint to the handler,
//! whose own body limit and authorization apply as without a key; the fingerprint is
//! complete when the handler has read the body (an unread rest is read and discarded after
//! the handler, at most [`IdempotencyConfig::max_request_bytes`]; a longer rest leaves a
//! record that is not replayed). A retry against a stored record runs the re-checks below
//! first and only then reads its body, into the fingerprint and nowhere else, and no
//! further than the length of the first request's body: a declared or read length that
//! differs is 422 `sys.idempotency_mismatch`.
//!
//! **A replay is checked again (the owner's decision of 2026-11-06).** A replay runs what
//! the first request had to pass, against the principal as it is now, before it answers:
//!
//! - authentication (the API middleware authenticates every request) and the rule of an
//!   account that must change its password;
//! - every authorization check that passed during the first request, and the fresh-session
//!   rule when the first request needed it, from the request's check journal
//!   ([`tenko_auth::journal`]); a denial answers as the request would be answered, 401 or
//!   403, and is audited as the refused action `sys.idempotency.replay` with the digest of
//!   the key, never the key;
//! - the principal's scope on every scoped kind the first request touched (a digest of the
//!   scope filter its grants give it): a grant narrowed or widened since makes the replay
//!   409 `sys.idempotency_not_replayable`;
//! - a stamp of the principal (its session or token, roles, authentication strength and
//!   flags): when it changed, the replay is 409 `sys.idempotency_not_replayable`. The stamp
//!   catches what a journal could miss.
//!
//! A first request whose journal is empty (nothing to re-check), or overflowed, leaves only
//! a marker: a retry is 409 `sys.idempotency_not_replayable`, never a replay without checks.
//!
//! **Secret-bearing requests and responses are never stored (NEVER-01).** Which `POST`
//! carries a secret is read from the OpenAPI document of the router ([`secret_bodies`]): a
//! request or 2xx response body that reaches a field of the type `SecretString` (format
//! `password`), the few routes whose secrets are plain strings ([`PLAIN_SECRETS`]), every
//! request body that is not JSON (a multipart or binary upload), and every `POST` the
//! document does not list. A test over the document holds that list complete. A successful response that carries a
//! secret, or `Cache-Control: no-store`, or any `Set-Cookie` header, leaves only a bodiless
//! marker: the record key, the status, the request fingerprint and the flag
//! `replay_unavailable`. A request whose body carries a secret is never fingerprinted: its
//! marker holds no fingerprint, so any retry under its key is 409. Either way the handler
//! does not run a second time (no second token) and the secret is not served again. The API
//! middleware adds its default `Cache-Control: no-store` only after this check, so the rule
//! sees what the handler set.
//!
//! **Ceremonies take no part.** The sign-in ceremonies, first-run setup, the live password
//! check and the enrollment of a node ([`CEREMONIES`]) go straight to the handler: no
//! fingerprint and no record, whatever the key. They are safe to repeat, and their bodies
//! never meet a hash.
//!
//! **The fingerprint is keyed.** It is HMAC-SHA-256 under a [`FingerprintKey`], never a
//! plain hash. A plain hash of a body is a password oracle: whoever reads the store could
//! hash candidate passwords and compare them offline. Under a key that is not in the store
//! in plain, a stored fingerprint means nothing without it. The server derives the key
//! from the installation's cluster key (`sys.cluster_key`, a system secret in the vault),
//! so every controller and every restart computes the same fingerprints, and a retry that
//! a load balancer sends to another controller replays the first answer (Slice 3,
//! WP3.1b). Without a cluster key (tests, a server that could not read it) each process
//! draws a random key. Each record carries the public id of the key that made it; a
//! record made under another key (an earlier process key, records from before the cluster
//! key) cannot be compared, so a retry against it is answered 409
//! `sys.idempotency_not_replayable`: the request was performed and is neither run again nor
//! replayed. So is a record of an earlier version of the record format, which holds no
//! journal and no stamp.
//!
//! **Expiry.** Each record has a row in `sys.api_idempotency_expiry`, keyed by its creation
//! time and record key and written in the same batch, so the leader's hourly purge
//! ([`purge_expired`]) reads the expired rows in time order, page by page, and costs what
//! expired, not what lives. Rows that have no such row (written by an earlier version, also
//! by an older controller during a rolling upgrade) are found by [`sweep_unindexed`], which
//! the leader runs when it takes office and once a day.
//!
//! The record is a separate store write after the handler's own batch. If the node fails
//! between the two, a retry runs the handler again and the store's own idempotency decides
//! (a replay of the same batch, or 422 when the batch differs).

use std::{
    collections::{HashMap, HashSet},
    fmt,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use aws_lc_rs::{
    hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};

use axum::{
    body::{Body, BodyDataStream, Bytes as BodyBytes, HttpBody, to_bytes},
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures::{Stream, StreamExt as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenko_core::{
    Action, Authenticated, Authorizer, IdempotencyKey, ObjectKind, ObjectRef, Principal,
    RequestCtx, RequestId, Revision, SystemComponent, TableName, Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::{from_cbor, to_cbor},
    error::CodedError,
};
use tenko_store::{KeyRange, ReadConsistency, Store, WriteBatch};

use crate::{
    API_BASE,
    extract::{AuthOutcome, open_during_password_change},
    problem::{ApiError, codes},
};

/// The store table of stored responses.
pub(crate) const TABLE: TableName = TableName::from_static("sys.api_idempotency");

/// The store table that orders the records by creation time for the purge: the key is the
/// creation time (Unix nanoseconds, eight bytes big-endian) followed by the record key; the
/// value is empty.
pub(crate) const EXPIRY_TABLE: TableName = TableName::from_static("sys.api_idempotency_expiry");

/// Header that marks a replayed response.
pub const REPLAYED_HEADER: HeaderName = HeaderName::from_static("idempotency-replayed");

/// The audit action of a replay refused by its re-checks.
pub const REPLAY_REFUSED: AuditAction = AuditAction::from_static("sys.idempotency.replay");

/// The record format this version writes: 2 added the check journal, the principal stamp
/// and the expiry row. A record of an earlier format is never replayed.
const RECORD_FORMAT: u8 = 2;

/// Settings of the idempotency middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdempotencyConfig {
    /// How long a stored response is replayed.
    pub ttl: Duration,
    /// Largest rest of a first request's body that its handler did not read and the
    /// middleware reads into the fingerprint itself; a longer rest leaves a record that is
    /// not replayed. Nothing is buffered. (A retry is read no further than the length of
    /// the first request's body.)
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
    /// The request fingerprint; empty when the request was never fingerprinted (its body
    /// carries a secret, or its handler left more of it unread than the middleware reads).
    fingerprint: Bytes,
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: Bytes,
    created: Timestamp,
    /// A marker: the request was performed, but its response was not stored and cannot be
    /// replayed.
    #[serde(default)]
    replay_unavailable: bool,
    /// Public id of the process key that made `fingerprint`; empty in records written
    /// before fingerprints were keyed.
    #[serde(default)]
    key_id: Bytes,
    /// The record format ([`RECORD_FORMAT`]); 0 in records of earlier versions.
    #[serde(default)]
    format: u8,
    /// The authorization checks that passed during the first request.
    #[serde(default)]
    checks: Vec<(Action, ObjectRef)>,
    /// The principal's scopes on scoped kinds during the first request: SHA-256 of each
    /// scope filter ([`tenko_auth::journal::scope_digest`]).
    #[serde(default)]
    scopes: Vec<(Action, ObjectKind, Bytes)>,
    /// The length of the first request's body; a retry with a longer one is another request.
    #[serde(default)]
    body_len: u64,
    /// Whether the first request needed a fresh interactive sign-in.
    #[serde(default)]
    fresh_session: bool,
    /// SHA-256 of the principal's session or token, roles, strength and flags.
    #[serde(default)]
    stamp: Bytes,
}

/// The HMAC-SHA-256 key of the request fingerprints, with its public id. Never stored or
/// logged.
#[derive(Clone)]
pub struct FingerprintKey {
    key: hmac::Key,
    /// Public id of the key, stored with each record.
    id: [u8; 8],
}

/// HKDF-SHA-256 salt of the subkeys of the cluster key.
const CLUSTER_KEY_SALT: &[u8] = b"tenko cluster key v1";
/// HKDF info of the fingerprint subkey.
const FINGERPRINT_INFO: &[u8] = b"idempotency fingerprint";
/// HMAC input of the public key id.
const KEY_ID_INPUT: &[u8] = b"tenko idempotency key id";

impl FingerprintKey {
    /// The fingerprint subkey of the installation's cluster key (HKDF-SHA-256, salt
    /// `tenko cluster key v1`, info `idempotency fingerprint`). Every controller derives
    /// the same key and the same public id, so records compare across controllers and
    /// restarts.
    ///
    /// # Panics
    ///
    /// Never: HKDF-SHA-256 always yields one block.
    pub fn from_cluster_key(cluster_key: &[u8; 32]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, CLUSTER_KEY_SALT).extract(cluster_key);
        let okm = prk
            .expand(&[FINGERPRINT_INFO], hmac::HMAC_SHA256)
            .expect("HKDF-SHA-256 yields one block");
        let key = hmac::Key::from(okm);
        let tag = hmac::sign(&key, KEY_ID_INPUT);
        let mut id = [0_u8; 8];
        id.copy_from_slice(&tag.as_ref()[..8]);
        Self { key, id }
    }

    /// A random key of this process, with a random id.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random source fails, which leaves no way to key the
    /// fingerprints.
    pub fn random() -> Self {
        let random = SystemRandom::new();
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &random)
            .expect("the operating system's random source works");
        let mut id = [0_u8; 8];
        random
            .fill(&mut id)
            .expect("the operating system's random source works");
        Self { key, id }
    }

    /// The public id stored with each record.
    pub fn id(&self) -> [u8; 8] {
        self.id
    }

    /// The fingerprint context after what makes two requests the same before their body:
    /// method, path and query, content type.
    fn start(&self, method: &Method, uri: &axum::http::Uri, headers: &HeaderMap) -> hmac::Context {
        let mut mac = hmac::Context::with_key(&self.key);
        mac.update(method.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(
            uri.path_and_query()
                .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str)
                .as_bytes(),
        );
        mac.update(&[0]);
        if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
            mac.update(content_type.as_bytes());
        }
        mac.update(&[0]);
        mac
    }

    /// HMAC-SHA-256 under the key of a whole request (tests).
    #[cfg(test)]
    fn fingerprint(
        &self,
        method: &Method,
        uri: &axum::http::Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> [u8; 32] {
        let mut mac = self.start(method, uri, headers);
        mac.update(body);
        finish(mac)
    }
}

fn finish(mac: hmac::Context) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(mac.sign().as_ref());
    out
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FingerprintKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Per-process state of the middleware: the fingerprint key and the keys of requests being
/// processed.
pub(crate) struct InFlight {
    keys: Mutex<HashSet<[u8; 32]>>,
    /// The fingerprint key: random until the server installs the cluster's.
    key: RwLock<Arc<FingerprintKey>>,
}

impl Default for InFlight {
    /// Draws a random fingerprint key (see [`FingerprintKey::random`]).
    fn default() -> Self {
        Self {
            keys: Mutex::new(HashSet::new()),
            key: RwLock::new(Arc::new(FingerprintKey::random())),
        }
    }
}

impl fmt::Debug for InFlight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InFlight")
            .field("key_id", &self.key().id)
            .finish_non_exhaustive()
    }
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
    /// Uses `key` for the fingerprints from now on.
    pub(crate) fn set_key(&self, key: FingerprintKey) {
        *self.key.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(key);
    }

    /// The fingerprint key now.
    fn key(&self) -> Arc<FingerprintKey> {
        Arc::clone(&self.key.read().unwrap_or_else(PoisonError::into_inner))
    }

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

/// What the bodies of a `POST` operation carry, read from the OpenAPI document.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SecretBodies {
    /// The request body carries a secret: it is never fingerprinted.
    pub(crate) request: bool,
    /// A successful response carries a secret: it is never stored.
    pub(crate) response: bool,
}

/// What the middleware needs besides the request: the principal the API middleware
/// authenticated, the authorizer that re-runs the journaled checks, and what the route's
/// bodies carry.
#[derive(Clone, Copy)]
pub(crate) struct Env<'a> {
    /// The authenticated principal (the placeholder without an authenticator), if any.
    pub(crate) principal: Option<&'a Principal>,
    /// The authorizer of the state; without one every check passes, as for the handlers.
    pub(crate) authorizer: Option<&'a dyn Authorizer>,
    /// What the matched route's bodies carry.
    pub(crate) secrets: SecretBodies,
}

/// Runs `next` under the idempotency rules when the request is a `POST` with a key and an
/// authenticated principal; any other request goes straight through.
pub(crate) async fn handle<F, Fut>(
    store: &dyn Store,
    in_flight: &InFlight,
    config: IdempotencyConfig,
    env: Env<'_>,
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
    let (Some(key), Some(principal)) = (keyed_post(&request), env.principal) else {
        return next(request).await;
    };
    if is_ceremony(request.method(), request.uri().path()) {
        return next(request).await;
    }
    let record_key = record_key(principal, &key);
    let now = Timestamp::now();
    let fingerprint_key = in_flight.key();
    let authenticated = request
        .extensions()
        .get::<AuthOutcome>()
        .and_then(|AuthOutcome(outcome)| outcome.as_ref().ok())
        .cloned();
    let stamp = stamp(principal, authenticated.as_ref());

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

    let expected = match lookup(store, &record_key, now, config.ttl).await {
        Err(response) => return *response,
        Ok(Found::Live(stored)) => {
            let caller = Caller {
                principal,
                authenticated: authenticated.as_ref(),
                stamp: &stamp,
                record_key: &record_key,
                now,
            };
            return retry(store, env, &caller, &fingerprint_key, &stored, request).await;
        }
        Ok(Found::Expired { revision, created }) => Some((revision, created)),
        Ok(Found::Nothing) => None,
    };
    let (parts, body) = request.into_parts();
    let (body, fingerprint) = if env.secrets.request {
        (body, None)
    } else {
        let mac = fingerprint_key.start(&parts.method, &parts.uri, &parts.headers);
        let (body, slot) = Fingerprinting::wrap(body, mac);
        (body, Some(slot))
    };
    let (response, journal) =
        tenko_auth::journal::record(principal.clone(), next(Request::from_parts(parts, body)))
            .await;
    if !response.status().is_success() {
        return response;
    }
    let fingerprint = match fingerprint {
        Some(slot) => slot.complete(config.max_request_bytes).await,
        None => None,
    };
    let record = Record {
        principal,
        key: &record_key,
        fingerprint,
        key_id: &fingerprint_key.id,
        created: now,
        expected,
        journal,
        stamp,
        secrets: env.secrets,
    };
    remember(store, config, record, response).await
}

/// The ceremonies that take no part (relative to [`API_BASE`]): exact paths, then path
/// prefixes. They are safe to run again and their bodies are never fingerprinted.
pub(crate) const CEREMONIES: [&str; 3] = ["/setup", "/auth/password/check", "/nodes/enroll"];
const CEREMONY_PREFIXES: [&str; 2] = ["/auth/login/", "/auth/webauthn/login/"];

/// Whether a request is one of the [`CEREMONIES`].
fn is_ceremony(method: &Method, path: &str) -> bool {
    if *method != Method::POST {
        return false;
    }
    let Some(path) = path.strip_prefix(API_BASE) else {
        return false;
    };
    let path = path.strip_suffix('/').unwrap_or(path);
    CEREMONIES.contains(&path)
        || CEREMONY_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

/// The `POST` routes (relative to [`API_BASE`]) whose secrets are plain strings in the
/// document, not `SecretString`: request bodies, then responses. A test over the document
/// finds every other field that looks like a secret and is not typed as one.
pub(crate) const PLAIN_SECRETS: ([&str; 1], [&str; 4]) = (
    // `KeyCreate.secret`: a TSIG secret to import.
    ["/dns/keys"],
    [
        // `KeyCreated.secret`: the TSIG secret.
        "/dns/keys",
        // `CreatedEnrollment.token`: the enrollment token.
        "/nodes/enrollments",
        // `MirrorCreated.token`: the token of the DHCP mirror's exporter.
        "/migrate/mirrors",
        "/migrate/mirrors/{id}/token",
    ],
);

/// What the bodies of every documented `POST` carry, by path template (with the API base,
/// as the router matches it): a request body or a 2xx response body that reaches a string
/// of format `password` (the type `SecretString`), and the routes of [`PLAIN_SECRETS`].
/// Read from the serialized OpenAPI document once, when the request metrics are sealed.
pub(crate) fn secret_bodies(document: &serde_json::Value) -> HashMap<String, SecretBodies> {
    let schemas = document
        .pointer("/components/schemas")
        .and_then(serde_json::Value::as_object);
    let mut memo = HashSet::new();
    let mut found = HashMap::new();
    let Some(paths) = document.get("paths").and_then(serde_json::Value::as_object) else {
        return found;
    };
    for (path, item) in paths {
        let Some(post) = item.get("post") else {
            continue;
        };
        // A body that is not JSON (a multipart or binary upload) is never fingerprinted
        // either: its fields are not in the document.
        let request = post.get("requestBody").is_some_and(|body| {
            reaches_secret(body, schemas, &mut memo)
                || body
                    .get("content")
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(|content| content.keys().any(|kind| kind != "application/json"))
        });
        let response = post
            .get("responses")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|responses| {
                responses.iter().any(|(status, answer)| {
                    status.starts_with('2') && reaches_secret(answer, schemas, &mut memo)
                })
            });
        let relative = path.strip_prefix(API_BASE).unwrap_or(path);
        let bodies = SecretBodies {
            request: request || PLAIN_SECRETS.0.contains(&relative),
            response: response || PLAIN_SECRETS.1.contains(&relative),
        };
        if bodies != SecretBodies::default() {
            found.insert(path.clone(), bodies);
        }
    }
    found
}

/// Whether a schema value reaches a string of format `password`, following `$ref`s. `memo`
/// holds the schemas known to reach one; `visiting` the schemas on the current path, which
/// cuts cycles without remembering a schema as secret-free before its walk ended.
fn reaches_secret(
    value: &serde_json::Value,
    schemas: Option<&serde_json::Map<String, serde_json::Value>>,
    memo: &mut HashSet<String>,
) -> bool {
    reaches(value, schemas, memo, &mut HashSet::new())
}

fn reaches(
    value: &serde_json::Value,
    schemas: Option<&serde_json::Map<String, serde_json::Value>>,
    memo: &mut HashSet<String>,
    visiting: &mut HashSet<String>,
) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("format").and_then(serde_json::Value::as_str) == Some("password") {
                return true;
            }
            if let Some(name) = map
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                .and_then(|reference| reference.rsplit('/').next())
            {
                if memo.contains(name) {
                    return true;
                }
                if visiting.insert(name.to_owned()) {
                    let reached = schemas
                        .and_then(|schemas| schemas.get(name))
                        .is_some_and(|schema| reaches(schema, schemas, memo, visiting));
                    visiting.remove(name);
                    if reached {
                        memo.insert(name.to_owned());
                        return true;
                    }
                }
            }
            map.iter()
                .filter(|(key, _)| !matches!(key.as_str(), "description" | "example" | "examples"))
                .any(|(_, value)| reaches(value, schemas, memo, visiting))
        }
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| reaches(item, schemas, memo, visiting)),
        _ => false,
    }
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

/// What the lookup found under a record key.
enum Found {
    /// No record.
    Nothing,
    /// A record older than the TTL, with its revision and creation time.
    Expired {
        revision: Revision,
        created: Timestamp,
    },
    /// A record within the TTL.
    Live(Box<StoredResponse>),
}

/// Looks up a record; `Err` carries the response to send (a store failure).
async fn lookup(
    store: &dyn Store,
    record_key: &[u8; 32],
    now: Timestamp,
    ttl: Duration,
) -> Result<Found, Box<Response>> {
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
    Ok(match existing {
        None => Found::Nothing,
        Some((stored, revision)) if now.saturating_since(stored.created) >= ttl => Found::Expired {
            revision,
            created: stored.created,
        },
        Some((stored, _)) => Found::Live(Box::new(stored)),
    })
}

/// Who retries, as the re-checks of a replay need it.
struct Caller<'a> {
    principal: &'a Principal,
    authenticated: Option<&'a Authenticated>,
    stamp: &'a [u8; 32],
    record_key: &'a [u8; 32],
    now: Timestamp,
}

/// Answers a retry against a live record: the re-checks first, then the body into the
/// fingerprint, then the replay or the refusal.
async fn retry(
    store: &dyn Store,
    env: Env<'_>,
    caller: &Caller<'_>,
    fingerprint_key: &FingerprintKey,
    stored: &StoredResponse,
    request: Request,
) -> Response {
    if stored.key_id.as_ref() != fingerprint_key.id.as_slice() || stored.format < RECORD_FORMAT {
        // Fingerprinted under another process's key, or written by an earlier version
        // without a journal: the request cannot be compared or checked again, so it is
        // neither run again nor replayed.
        return not_replayable().into_response();
    }
    let head = RetryHead::of(caller, &request);
    if let Err(response) = recheck(store, env, caller, stored, &head).await {
        return *response;
    }
    if stored.stamp.as_ref() != caller.stamp.as_slice() {
        return not_replayable().into_response();
    }
    if stored.fingerprint.is_empty() {
        // Never fingerprinted: performed, and any retry under the key is refused.
        return not_replayable().into_response();
    }
    // A body longer than the first request's is another request: it is read no further
    // than that length, and a declared length that differs is not read at all.
    let mismatch = || {
        ApiError::new(
            codes::IDEMPOTENCY_MISMATCH,
            422,
            "the Idempotency-Key was already used for a different request",
        )
        .into_response()
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|declared| declared != stored.body_len) {
        return mismatch();
    }
    let limit = usize::try_from(stored.body_len).unwrap_or(usize::MAX);
    let (parts, body) = request.into_parts();
    let mac = fingerprint_key.start(&parts.method, &parts.uri, &parts.headers);
    let Some((fingerprint, _)) = hash_rest(mac, body.into_data_stream(), 0, limit).await else {
        return mismatch();
    };
    if stored.fingerprint.as_ref() != fingerprint.as_slice() {
        return mismatch();
    }
    if stored.replay_unavailable {
        return not_replayable().into_response();
    }
    replay(stored)
}

/// Runs what the first request had to pass against the principal as it is now: the rule of
/// an account that must change its password, every journaled check and the fresh-session
/// rule. A denial is audited and answered as the request would be.
async fn recheck(
    store: &dyn Store,
    env: Env<'_>,
    caller: &Caller<'_>,
    stored: &StoredResponse,
    head: &RetryHead,
) -> Result<(), Box<Response>> {
    if caller
        .authenticated
        .is_some_and(|authenticated| authenticated.flags.password_change_required)
        && !head.open_during_password_change
    {
        return Err(Box::new(
            ApiError::from(tenko_auth::AuthError::PasswordChangeRequired).into_response(),
        ));
    }
    if let Some(authorizer) = env.authorizer {
        for (action, kind, digest) in &stored.scopes {
            let now = tenko_auth::journal::scope_digest(&authorizer.scope(
                caller.principal,
                *action,
                *kind,
            ));
            if digest.as_ref() != now.as_slice() {
                // The grants changed since (narrowed or widened): not replayed.
                return Err(Box::new(not_replayable().into_response()));
            }
        }
        for (action, object) in &stored.checks {
            if let Err(denied) = authorizer.check(caller.principal, *action, object) {
                audit_refused(store, caller, head, vec![*object], &denied).await;
                return Err(Box::new(ApiError::from(denied).into_response()));
            }
        }
    }
    if stored.fresh_session {
        let Some(auth) = &head.auth else {
            // Nothing can tell whether the sign-in is still fresh.
            return Err(Box::new(not_replayable().into_response()));
        };
        if let Err(error) = auth.require_fresh_session(&head.ctx).await {
            audit_refused(store, caller, head, Vec::new(), &error).await;
            return Err(Box::new(
                ApiError::from_coded_error(CodedError::from_coded(&error)).into_response(),
            ));
        }
    }
    Ok(())
}

/// What the re-checks of a retry need from its request, taken before anything waits.
struct RetryHead {
    /// The request context, without its idempotency key.
    ctx: RequestCtx,
    /// The path of the request.
    path: String,
    /// Whether the route stays open to an account that must change its password.
    open_during_password_change: bool,
    /// The authentication service, which checks a fresh sign-in.
    auth: Option<Arc<tenko_auth::AuthService>>,
}

impl RetryHead {
    fn of(caller: &Caller<'_>, request: &Request) -> Self {
        let ctx = RequestCtx {
            principal: caller.principal.clone(),
            request: request
                .extensions()
                .get::<RequestId>()
                .copied()
                .unwrap_or_else(RequestId::generate),
            now: caller.now,
            source_ip: request
                .extensions()
                .get::<crate::extract::ClientInfo>()
                .and_then(|client| client.source_ip),
            idempotency: None,
        };
        Self {
            ctx,
            path: request.uri().path().to_owned(),
            open_during_password_change: open_during_password_change(
                request.method(),
                request.uri().path(),
            ),
            auth: request
                .extensions()
                .get::<Arc<tenko_auth::AuthService>>()
                .cloned(),
        }
    }
}

/// Audits a replay refused by its re-checks: `sys.idempotency.replay`, failed, with the
/// route and the digest of the key (the record key), never the key.
async fn audit_refused(
    store: &dyn Store,
    caller: &Caller<'_>,
    head: &RetryHead,
    objects: Vec<ObjectRef>,
    refusal: &(dyn tenko_core::Coded + Sync),
) {
    let draft = AuditDraft::failed(REPLAY_REFUSED, objects, refusal)
        .with_source_ip(head.ctx.source_ip)
        .with_context("route", head.path.clone())
        .with_context("key_digest", hex(caller.record_key));
    let mut batch = WriteBatch::for_request(&head.ctx);
    batch.audit(draft);
    if let Err(error) = store.propose(batch).await {
        tracing::warn!(%error, "a refused replay could not be audited");
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// 409 `sys.idempotency_not_replayable`: the request was performed, and its response is
/// not kept, or may not be replayed to the caller as it is now.
fn not_replayable() -> ApiError {
    ApiError::from_coded_error(
        CodedError::new(
            codes::IDEMPOTENCY_NOT_REPLAYABLE,
            409,
            "a request with this Idempotency-Key was already performed; its response is not \
             kept, or cannot be replayed to the caller as it is now, so it is not replayed",
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

/// SHA-256 of what a replay must find unchanged about its principal: the principal itself
/// (for a session its id and strength, for a token its id), its roles, its strength and
/// its flags.
fn stamp(principal: &Principal, authenticated: Option<&Authenticated>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"tenko idempotency stamp v1\0");
    hash.update(to_cbor(principal).unwrap_or_default());
    if let Some(authenticated) = authenticated {
        hash.update([1]);
        for role in &authenticated.roles {
            hash.update(role.as_bytes());
            hash.update([0]);
        }
        hash.update(to_cbor(&authenticated.strength).unwrap_or_default());
        let flags = &authenticated.flags;
        hash.update([
            u8::from(flags.password_change_required),
            u8::from(flags.mfa_enrollment_required),
            u8::from(flags.break_glass),
        ]);
    }
    hash.finalize().into()
}

/// What identifies and checks the record of one request.
struct Record<'a> {
    principal: &'a Principal,
    key: &'a [u8; 32],
    /// The fingerprint and the body's length, when the whole request went through it.
    fingerprint: Option<([u8; 32], u64)>,
    key_id: &'a [u8; 8],
    created: Timestamp,
    /// The revision and creation time of the expired record this one replaces.
    expected: Option<(Revision, Timestamp)>,
    journal: tenko_auth::journal::Journal,
    stamp: [u8; 32],
    secrets: SecretBodies,
}

/// Stores a successful response, or the marker of one that may not be replayed, and passes
/// it on.
async fn remember(
    store: &dyn Store,
    config: IdempotencyConfig,
    record: Record<'_>,
    response: Response,
) -> Response {
    let marker = |status: StatusCode| StoredResponse {
        fingerprint: record
            .fingerprint
            .map_or_else(Bytes::new, |(fingerprint, _)| {
                Bytes::copy_from_slice(&fingerprint)
            }),
        status: status.as_u16(),
        headers: Vec::new(),
        body: Bytes::new(),
        created: record.created,
        replay_unavailable: true,
        key_id: Bytes::copy_from_slice(record.key_id),
        format: RECORD_FORMAT,
        checks: record.journal.checks.clone(),
        scopes: record
            .journal
            .scopes
            .iter()
            .map(|(action, kind, digest)| (*action, *kind, Bytes::copy_from_slice(digest)))
            .collect(),
        body_len: record.fingerprint.map_or(0, |(_, len)| len),
        fresh_session: record.journal.fresh_session,
        stamp: Bytes::copy_from_slice(&record.stamp),
    };
    let checked = !record.journal.is_empty() && !record.journal.overflow;
    if record.secrets.response
        || secret_bearing(response.headers())
        || record.fingerprint.is_none()
        || !checked
    {
        if let Err(error) = save(store, &record, &marker(response.status())).await {
            tracing::warn!(%error, "could not store the marker of an idempotent request");
        }
        return response;
    }
    let small = response.body().size_hint().exact().is_some_and(|size| {
        usize::try_from(size).is_ok_and(|size| size <= config.max_response_bytes)
    });
    if !small {
        // Too large to keep, or of no known size: performed, so a retry is 409, not a
        // second run.
        if let Err(error) = save(store, &record, &marker(response.status())).await {
            tracing::warn!(%error, "could not store the marker of an idempotent request");
        }
        return response;
    }
    let (parts, body) = response.into_parts();
    let Ok(body) = to_bytes(body, config.max_response_bytes).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let stored = StoredResponse {
        headers: KEPT_HEADERS
            .iter()
            .filter_map(|name| {
                let value = parts.headers.get(name)?.to_str().ok()?;
                Some((name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body: body.clone(),
        replay_unavailable: false,
        ..marker(parts.status)
    };
    if let Err(error) = save(store, &record, &stored).await {
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

/// The key of a record's row in [`EXPIRY_TABLE`].
fn expiry_key(created: Timestamp, record_key: &[u8]) -> Bytes {
    let nanos = u64::try_from(created.unix_nanos().max(0)).unwrap_or(u64::MAX);
    let mut key = Vec::with_capacity(8 + record_key.len());
    key.extend_from_slice(&nanos.to_be_bytes());
    key.extend_from_slice(record_key);
    Bytes::from(key)
}

/// The first expiry key of records created at `cutoff` or later.
fn expiry_cutoff(cutoff: Timestamp) -> Bytes {
    let nanos = u64::try_from(cutoff.unix_nanos().max(0)).unwrap_or(u64::MAX);
    Bytes::copy_from_slice(&nanos.to_be_bytes())
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

/// Writes a record and its expiry row in one batch; replaces an expired record and its row.
async fn save(
    store: &dyn Store,
    record: &Record<'_>,
    stored: &StoredResponse,
) -> Result<(), ApiError> {
    let value = to_cbor(stored)
        .map_err(|error| ApiError::from_coded_error(CodedError::internal(error.to_string())))?;
    let key = Bytes::copy_from_slice(record.key);
    let mut batch = WriteBatch::new(record.principal.clone(), stored.created);
    batch
        .expect_version(
            TABLE,
            key.clone(),
            record.expected.map(|(revision, _)| revision),
        )
        .put(TABLE, key, value);
    if let Some((_, created)) = record.expected {
        batch.delete(EXPIRY_TABLE, expiry_key(created, record.key));
    }
    batch.put(
        EXPIRY_TABLE,
        expiry_key(stored.created, record.key),
        Bytes::new(),
    );
    store.propose(batch).await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The fingerprint of a streamed body.

/// Where a [`Fingerprinting`] body leaves its result: the fingerprint once the body ended,
/// or, when the handler dropped the body before its end, the context and the unread rest.
enum Slot {
    Reading,
    Done([u8; 32], u64),
    Unread(Box<(hmac::Context, BodyDataStream, u64)>),
    Failed,
}

/// The handle on a [`Fingerprinting`] body's result.
struct FingerprintSlot(Arc<Mutex<Slot>>);

impl FingerprintSlot {
    /// The fingerprint of the whole body: as read by the handler, with an unread rest read
    /// here (at most `limit` bytes). `None` when the body failed, or its rest was longer.
    async fn complete(self, limit: usize) -> Option<([u8; 32], u64)> {
        let slot = std::mem::replace(
            &mut *self.0.lock().unwrap_or_else(PoisonError::into_inner),
            Slot::Failed,
        );
        match slot {
            Slot::Done(fingerprint, read) => Some((fingerprint, read)),
            Slot::Unread(unread) => {
                let (mac, rest, read) = *unread;
                hash_rest(mac, rest, read, limit).await
            }
            Slot::Reading | Slot::Failed => None,
        }
    }
}

/// Reads `rest` into `mac` without keeping it, after `read` bytes before it; returns the
/// fingerprint and the whole length. `None` past `limit` bytes in all, or on an error.
async fn hash_rest(
    mut mac: hmac::Context,
    mut rest: BodyDataStream,
    mut read: u64,
    limit: usize,
) -> Option<([u8; 32], u64)> {
    let limit = u64::try_from(limit).unwrap_or(u64::MAX);
    while let Some(chunk) = rest.next().await {
        let chunk = chunk.ok()?;
        read = read.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if read > limit {
            return None;
        }
        mac.update(&chunk);
    }
    Some((finish(mac), read))
}

/// A request body that feeds every byte the handler reads into the fingerprint.
struct Fingerprinting {
    inner: BodyDataStream,
    mac: Option<hmac::Context>,
    /// The bytes read so far.
    read: u64,
    slot: Arc<Mutex<Slot>>,
}

impl Fingerprinting {
    /// Wraps `body`; the slot receives the fingerprint (`mac` holds the request's head).
    fn wrap(body: Body, mac: hmac::Context) -> (Body, FingerprintSlot) {
        let slot = Arc::new(Mutex::new(Slot::Reading));
        if body.is_end_stream() {
            // No body: the fingerprint is complete now, whether or not the handler reads.
            *slot.lock().unwrap_or_else(PoisonError::into_inner) = Slot::Done(finish(mac), 0);
            return (body, FingerprintSlot(slot));
        }
        let stream = Self {
            inner: body.into_data_stream(),
            mac: Some(mac),
            read: 0,
            slot: Arc::clone(&slot),
        };
        (Body::from_stream(stream), FingerprintSlot(slot))
    }

    fn set(&self, value: Slot) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = value;
    }
}

impl Stream for Fingerprinting {
    type Item = Result<BodyBytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        match this.inner.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(mac) = this.mac.as_mut() {
                    mac.update(&chunk);
                }
                this.read = this
                    .read
                    .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.mac = None;
                this.set(Slot::Failed);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if let Some(mac) = this.mac.take() {
                    this.set(Slot::Done(finish(mac), this.read));
                }
                Poll::Ready(None)
            }
        }
    }
}

impl Drop for Fingerprinting {
    fn drop(&mut self) {
        // Dropped before its end: leave the rest for `FingerprintSlot::complete`.
        if let Some(mac) = self.mac.take() {
            let rest = std::mem::replace(&mut self.inner, Body::empty().into_data_stream());
            self.set(Slot::Unread(Box::new((mac, rest, self.read))));
        }
    }
}

// ---------------------------------------------------------------------------------------
// Expiry.

/// Rows the purge handles per batch.
const PURGE_PAGE: usize = 500;
/// Rows the sweep reads per page (their values, up to the stored response size, are read).
const SWEEP_PAGE: usize = 16;

/// Deletes the records older than `ttl` through their expiry rows, oldest first, in batches
/// of at most [`PURGE_PAGE`] rows, yielding to the runtime between batches; returns how
/// many records it deleted. Each batch carries `fence` (`tenko_store::fence`), so a deposed
/// leader's batch fails instead of racing the new leader's. An expiry row whose record was
/// replaced (by a newer request, or by a controller of an earlier version that does not
/// keep expiry rows) goes alone; the record stays.
///
/// The server runs it hourly on the leader. The work is bounded by the number of expired
/// rows: [`PURGE_PAGE`] rows per batch, one batch per page, and pages until a page comes
/// back short.
///
/// # Errors
///
/// The store's errors, the precondition failure of a fenced batch among them.
pub async fn purge_expired(
    store: &dyn Store,
    ttl: Duration,
    now: Timestamp,
    fence: Option<u64>,
) -> Result<usize, ApiError> {
    purge_pages(store, ttl, now, fence, PURGE_PAGE).await
}

async fn purge_pages(
    store: &dyn Store,
    ttl: Duration,
    now: Timestamp,
    fence: Option<u64>,
    page: usize,
) -> Result<usize, ApiError> {
    let Some(cutoff) = now.checked_sub(ttl) else {
        return Ok(0);
    };
    let range = KeyRange {
        start: std::ops::Bound::Unbounded,
        end: std::ops::Bound::Excluded(expiry_cutoff(cutoff)),
    };
    let mut purged = 0;
    loop {
        let view = store.read(ReadConsistency::Local).await?;
        let rows = view.scan(&EXPIRY_TABLE, range.clone(), page, false)?;
        if rows.is_empty() {
            return Ok(purged);
        }
        let short = rows.len() < page;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), now);
        if let Some(epoch) = fence {
            batch.preconditions.push(tenko_store::fence(epoch));
        }
        for (index_key, index) in rows {
            batch
                .expect_version(EXPIRY_TABLE, index_key.clone(), Some(index.revision))
                .delete(EXPIRY_TABLE, index_key.clone());
            let Some(record_key) = index_key.get(8..) else {
                continue;
            };
            let Some(versioned) = view.get(&TABLE, record_key)? else {
                continue;
            };
            let same = from_cbor::<StoredResponse>(&versioned.value).map_or(true, |stored| {
                expiry_key(stored.created, record_key) == index_key
            });
            if same {
                batch
                    .expect_version(
                        TABLE,
                        Bytes::copy_from_slice(record_key),
                        Some(versioned.revision),
                    )
                    .delete(TABLE, Bytes::copy_from_slice(record_key));
                purged += 1;
            }
        }
        drop(view);
        store.propose(batch).await?;
        if short {
            return Ok(purged);
        }
        tokio::task::yield_now().await;
    }
}

/// Finds the records that have no expiry row: those of an earlier record format, written
/// by an earlier version or, during a rolling upgrade, by a controller of one. An expired
/// one is deleted; a live one gets its expiry row, so that the purge finds it. Reads the
/// whole table in pages of [`SWEEP_PAGE`] records, yielding between them, fenced like
/// [`purge_expired`]; returns how many records it deleted or indexed. The server runs it
/// on the leader when it takes office and once a day.
///
/// # Errors
///
/// The store's errors, the precondition failure of a fenced batch among them.
pub async fn sweep_unindexed(
    store: &dyn Store,
    ttl: Duration,
    now: Timestamp,
    fence: Option<u64>,
) -> Result<usize, ApiError> {
    let mut range = KeyRange::all();
    let mut changed = 0;
    loop {
        let view = store.read(ReadConsistency::Local).await?;
        let rows = view.scan(&TABLE, range.clone(), SWEEP_PAGE, false)?;
        let Some((last, _)) = rows.last() else {
            return Ok(changed);
        };
        let next = range.clone().after(last.clone());
        let short = rows.len() < SWEEP_PAGE;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), now);
        if let Some(epoch) = fence {
            batch.preconditions.push(tenko_store::fence(epoch));
        }
        let mut touched = 0;
        for (key, versioned) in rows {
            let stored = from_cbor::<StoredResponse>(&versioned.value).ok();
            match stored {
                Some(stored) if stored.format >= RECORD_FORMAT => {}
                Some(stored) if now.saturating_since(stored.created) < ttl => {
                    if view
                        .get(&EXPIRY_TABLE, &expiry_key(stored.created, &key))?
                        .is_some()
                    {
                        // Indexed by an earlier sweep.
                        continue;
                    }
                    batch
                        .expect_version(TABLE, key.clone(), Some(versioned.revision))
                        .put(EXPIRY_TABLE, expiry_key(stored.created, &key), Bytes::new());
                    touched += 1;
                }
                // Expired, or not readable at all.
                _ => {
                    batch
                        .expect_version(TABLE, key.clone(), Some(versioned.revision))
                        .delete(TABLE, key);
                    touched += 1;
                }
            }
        }
        drop(view);
        if touched > 0 {
            store.propose(batch).await?;
            changed += touched;
        }
        if short {
            return Ok(changed);
        }
        range = next;
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests;
