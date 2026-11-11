//! The middleware over the full application: which session cookie selects the principal of
//! the rate limits and of the idempotency records. The scheme comes from the request URI
//! (the router is used without a listener), so `https://` requests count as HTTPS.

use std::{
    collections::BTreeSet,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, header},
};
use serde_json::{Value, json};
use tenko_core::{
    Action, AuthFailure, AuthFlags, AuthStrength, Authenticated, Authenticator, Authorizer,
    Credentials, Denied, ObjectKind, ObjectRef, Principal, ScopeFilter, SessionId, Timestamp,
    UserId, auth::AuthFuture,
};
use tenko_ipam::IpamService;
use tenko_store::{MemStore, Store};
use tower::ServiceExt;
use uuid::Uuid;

use super::{HttpConfig, Quota, RateLimitConfig};
use crate::{server, state::AppState, ui::UiSource};

const SECRET: &str = "s3ss10n";
const HOST: &str = "ddi.example.org";

/// Accepts the session secret [`SECRET`] as one user with one session, whatever cookie name
/// carried it: the name is the middleware's business. Counts the session logins.
struct OneSession {
    sessions: AtomicUsize,
}

impl Authenticator for OneSession {
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
        _source_ip: Option<IpAddr>,
        _now: Timestamp,
    ) -> AuthFuture<'a> {
        Box::pin(async move {
            match credentials {
                Credentials::Session(secret) if secret == SECRET => {
                    self.sessions.fetch_add(1, Ordering::SeqCst);
                    let user = UserId::from_uuid(Uuid::from_u128(7));
                    Ok(Authenticated {
                        principal: Principal::User {
                            id: user,
                            session: SessionId::from_uuid(Uuid::from_u128(8)),
                            strength: AuthStrength::Password,
                        },
                        user: Some(user),
                        roles: BTreeSet::new(),
                        strength: AuthStrength::Password,
                        expires_at: None,
                        flags: AuthFlags::default(),
                    })
                }
                Credentials::None => Err(AuthFailure::Missing),
                _ => Err(AuthFailure::Invalid),
            }
        })
    }
}

/// Allows everything and notes its checks and scopes as the role-based authorizer does, so
/// that a stored answer can be replayed.
struct Journaled;

impl Authorizer for Journaled {
    fn check(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        if tenko_auth::journal::note_check(principal, action, object) {
            self.scope(principal, action, object.kind);
        }
        Ok(())
    }

    fn scope(&self, principal: &Principal, action: Action, kind: ObjectKind) -> ScopeFilter {
        let filter = ScopeFilter::All;
        tenko_auth::journal::note_scope(principal, action, kind, &filter);
        filter
    }
}

struct App {
    router: Router,
    auth: Arc<OneSession>,
}

fn app(http: &HttpConfig) -> App {
    let store: Arc<dyn Store> = Arc::new(MemStore::default());
    let auth = Arc::new(OneSession {
        sessions: AtomicUsize::new(0),
    });
    let state = AppState {
        auth: Some(Arc::clone(&auth) as Arc<dyn Authenticator>),
        authorizer: Some(Arc::new(Journaled)),
        ..AppState::new(Arc::clone(&store))
    };
    let service = IpamService::with_direct_jobs(store).expect("IPAM service");
    let router = server::app(state, http, &UiSource::Embedded)
        .expect("application")
        .layer(Extension(service));
    App { router, auth }
}

/// An HTTP configuration whose per-principal limit lets one request through.
fn one_request_per_principal() -> HttpConfig {
    HttpConfig {
        rate_limit: RateLimitConfig {
            per_ip: None,
            per_principal: Some(Quota {
                per_second: 1,
                burst: 1,
            }),
            ..RateLimitConfig::default()
        },
        ..HttpConfig::default()
    }
}

struct Reply {
    status: u16,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn replayed(&self) -> bool {
        self.headers.contains_key("idempotency-replayed")
    }
}

impl App {
    /// A request over `scheme` with the session secret in the cookie `cookie`; a POST
    /// carries this origin and the key `key`.
    async fn send(
        &self,
        scheme: &str,
        method: &str,
        path: &str,
        cookie: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{scheme}://{HOST}{}{path}", crate::API_BASE))
            .header(header::COOKIE, format!("theme=dark; {cookie}={SECRET}"));
        if method != "GET" {
            builder = builder.header(header::ORIGIN, format!("{scheme}://{HOST}"));
        }
        if let Some(key) = key {
            builder = builder.header("idempotency-key", key);
        }
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.expect("body");
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

    fn sessions(&self) -> usize {
        self.auth.sessions.load(Ordering::SeqCst)
    }
}

/// The cookie name the scheme accepts, and the other one.
fn names(scheme: &str) -> (&'static str, &'static str) {
    let valid = tenko_auth::service::session_cookie_name(scheme == "https");
    let other = tenko_auth::service::session_cookie_name(scheme != "https");
    (valid, other)
}

#[tokio::test]
async fn only_the_cookie_of_the_scheme_selects_the_principal_of_the_limit() {
    for scheme in ["https", "http"] {
        let (valid, other) = names(scheme);
        let app = app(&one_request_per_principal());
        // The other name signs nobody in, so it draws on no principal's bucket: every try
        // is 401, never 429, and the authenticator never sees the secret.
        for _ in 0..3 {
            let reply = app
                .send(scheme, "GET", "/system/status", other, None, None)
                .await;
            assert_eq!(reply.status, 401, "{scheme} {other}: {}", reply.body);
            assert_eq!(reply.body["code"], "auth.unauthenticated", "{scheme}");
        }
        assert_eq!(
            app.sessions(),
            0,
            "{scheme}: {other} was never authenticated"
        );
        // The valid name is the principal's, and its bucket holds one request.
        let first = app
            .send(scheme, "GET", "/system/status", valid, None, None)
            .await;
        assert_eq!(first.status, 200, "{scheme} {valid}: {}", first.body);
        let limited = app
            .send(scheme, "GET", "/system/status", valid, None, None)
            .await;
        assert_eq!(limited.status, 429, "{scheme} {valid}: {}", limited.body);
        assert_eq!(limited.body["params"]["scope"], "principal");
    }
}

#[tokio::test]
async fn a_stored_answer_is_replayed_to_the_cookie_of_its_scheme_only() {
    for scheme in ["https", "http"] {
        let (valid, other) = names(scheme);
        let app = app(&HttpConfig::default());
        let prefix = json!({ "cidr": "192.0.2.0/24" });
        let first = app
            .send(
                scheme,
                "POST",
                "/prefixes",
                valid,
                Some("p1"),
                Some(&prefix),
            )
            .await;
        assert_eq!(first.status, 201, "{scheme}: {}", first.body);
        assert!(!first.replayed());

        // The same key with the cookie of the other name reaches neither the record nor the
        // handler: no principal, so the request is refused as unauthenticated.
        let foreign = app
            .send(
                scheme,
                "POST",
                "/prefixes",
                other,
                Some("p1"),
                Some(&prefix),
            )
            .await;
        assert_eq!(foreign.status, 401, "{scheme} {other}: {}", foreign.body);
        assert!(!foreign.replayed(), "{scheme}: no replay to {other}");

        // The session of the valid name gets the stored answer: the stamp digests the
        // principal and its session, not the cookie that carried it.
        let replay = app
            .send(
                scheme,
                "POST",
                "/prefixes",
                valid,
                Some("p1"),
                Some(&prefix),
            )
            .await;
        assert_eq!(replay.status, 201, "{scheme}: {}", replay.body);
        assert!(replay.replayed(), "{scheme}: replayed");
        assert_eq!(replay.body, first.body);
    }
}
