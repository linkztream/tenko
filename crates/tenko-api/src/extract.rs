//! Request extractors.
//!
//! [`Ctx`] builds the [`RequestCtx`] that every domain call takes: who acts, the request id,
//! the processing time, the client address and the idempotency key.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use tenko_core::{
    Authenticated, Credentials, IdempotencyKey, InvalidValue, Principal, RequestCtx, RequestId,
    SystemComponent, Timestamp, auth::SESSION_COOKIE,
};

use crate::{problem::ApiError, state::AppState};

/// Name of the header that carries the client's idempotency key (API-04).
const IDEMPOTENCY_HEADER: &str = "idempotency-key";

/// The [`RequestCtx`] of the current request.
///
/// Filled from the request:
///
/// - `request` is a new [`RequestId`] and `now` the current time.
/// - `source_ip` is the peer address from the [`ConnectInfo`] extension, when the server was
///   started with connect info. Trusted proxy headers are handled by the server layer, not
///   here.
/// - `idempotency` is the `Idempotency-Key` header. A value that is not valid UTF-8, or that
///   [`IdempotencyKey::new`] rejects, is refused with 400 `sys.invalid_value`.
/// - `principal` comes from the [`Authenticator`](tenko_core::Authenticator) in the
///   [`AppState`], which resolves the session cookie or bearer token. Without credentials, or
///   with rejected ones, the request fails with the authenticator's problem details (401 or
///   503). When the state has no authenticator (development and tests), the request acts as
///   the API itself. The full [`Authenticated`] record is stored in the request extensions
///   for handlers that need roles or flags.
#[derive(Debug, Clone)]
pub struct Ctx(pub RequestCtx);

impl<S> FromRequestParts<S> for Ctx
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let idempotency = idempotency_key(parts)?;
        let source_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| peer.ip());
        let now = Timestamp::now();
        let principal = match &app.auth {
            None => placeholder_principal(),
            Some(authenticator) => {
                let credentials = credentials(parts);
                let authenticated = authenticator
                    .authenticate(&credentials, source_ip, now)
                    .await?;
                let principal = authenticated.principal.clone();
                parts.extensions.insert(authenticated);
                principal
            }
        };
        Ok(Self(RequestCtx {
            principal,
            request: RequestId::generate(),
            now,
            source_ip,
            idempotency,
        }))
    }
}

/// The principal of every request while no authenticator is configured: the API acting on
/// its own. Development and tests only.
fn placeholder_principal() -> Principal {
    Principal::System {
        component: SystemComponent::Api,
        on_behalf_of: None,
    }
}

/// Reads the session cookie and the `Authorization` header.
fn credentials(parts: &Parts) -> Credentials {
    let authorization = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let session = parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(session_cookie);
    Credentials::from_headers(session, authorization)
}

/// Finds the session cookie in one `Cookie` header value.
fn session_cookie(header: &str) -> Option<&str> {
    header.split(';').map(str::trim).find_map(|pair| {
        pair.strip_prefix(SESSION_COOKIE)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

/// Reads and validates the `Idempotency-Key` header.
fn idempotency_key(parts: &Parts) -> Result<Option<IdempotencyKey>, ApiError> {
    let Some(value) = parts.headers.get(IDEMPOTENCY_HEADER) else {
        return Ok(None);
    };
    let text = std::str::from_utf8(value.as_bytes()).map_err(|_| {
        InvalidValue::new(
            "idempotency key",
            &String::from_utf8_lossy(value.as_bytes()),
            "must be valid UTF-8",
        )
    })?;
    Ok(Some(IdempotencyKey::new(text)?))
}

/// The [`Authenticated`] record of the current request, when an authenticator resolved it.
///
/// Available after [`Ctx`] ran; returns `None` while the state has no authenticator.
#[must_use]
pub fn authenticated(parts: &Parts) -> Option<&Authenticated> {
    parts.extensions.get::<Authenticated>()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

    use axum::{
        body::{Body, to_bytes},
        http::{HeaderValue, Request, StatusCode, header},
        response::IntoResponse,
    };
    use serde_json::Value;
    use tenko_core::{
        AuthFailure, AuthFlags, AuthStrength, Authenticator, SessionId, UserId, auth::AuthFuture,
    };

    use super::*;
    use crate::problem::PROBLEM_JSON;

    fn parts(key: Option<&[u8]>) -> Parts {
        let mut builder = Request::builder().method("POST").uri("/api/v1/prefixes");
        if let Some(key) = key {
            builder = builder.header(
                IDEMPOTENCY_HEADER,
                HeaderValue::from_bytes(key).expect("header value"),
            );
        }
        builder.body(Body::empty()).expect("request").into_parts().0
    }

    async fn extract(parts: &mut Parts) -> Result<Ctx, ApiError> {
        Ctx::from_request_parts(parts, &AppState::default()).await
    }

    /// Accepts exactly one session value and one bearer token.
    struct FakeAuthenticator {
        session: &'static str,
        token: &'static str,
        user: UserId,
    }

    impl Authenticator for FakeAuthenticator {
        fn authenticate<'a>(
            &'a self,
            credentials: &'a Credentials,
            _source_ip: Option<IpAddr>,
            _now: Timestamp,
        ) -> AuthFuture<'a> {
            Box::pin(async move {
                let strength = match credentials {
                    Credentials::Session(value) if value == self.session => AuthStrength::Passkey,
                    Credentials::Bearer(value) if value == self.token => AuthStrength::Password,
                    Credentials::None => return Err(AuthFailure::Missing),
                    Credentials::Session(_) | Credentials::Bearer(_) => {
                        return Err(AuthFailure::Invalid);
                    }
                };
                Ok(Authenticated {
                    principal: Principal::User {
                        id: self.user,
                        session: SessionId::generate(),
                        strength,
                    },
                    user: Some(self.user),
                    roles: BTreeSet::from(["admin".to_owned()]),
                    strength,
                    expires_at: None,
                    flags: AuthFlags::default(),
                })
            })
        }
    }

    fn state_with_auth(user: UserId) -> AppState {
        AppState {
            auth: Some(Arc::new(FakeAuthenticator {
                session: "s3ss10n",
                token: "t0k3n",
                user,
            })),
            authorizer: None,
        }
    }

    #[tokio::test]
    async fn fills_the_generated_fields() {
        let before = Timestamp::now();
        let Ctx(first) = extract(&mut parts(None)).await.expect("ctx");
        let Ctx(second) = extract(&mut parts(None)).await.expect("ctx");
        let after = Timestamp::now();

        assert_ne!(first.request, second.request);
        assert!(before <= first.now && first.now <= after);
        assert_eq!(
            first.principal,
            Principal::System {
                component: SystemComponent::Api,
                on_behalf_of: None
            }
        );
        assert_eq!(first.source_ip, None);
        assert_eq!(first.idempotency, None);
    }

    #[tokio::test]
    async fn accepts_an_idempotency_key() {
        let Ctx(ctx) = extract(&mut parts(Some(b"import-2026-10-09-a1")))
            .await
            .expect("ctx");
        assert_eq!(
            ctx.idempotency.as_ref().map(IdempotencyKey::as_str),
            Some("import-2026-10-09-a1")
        );
    }

    #[tokio::test]
    async fn rejects_an_invalid_idempotency_key_with_problem_details() {
        for key in [
            &b"has space"[..],
            &b""[..],
            &[b'k'; 256][..],
            &[0xC3, 0x28][..],
        ] {
            let error = extract(&mut parts(Some(key)))
                .await
                .expect_err("key must be rejected");
            assert_eq!(error.coded_error().code, "sys.invalid_value");
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).expect("type"),
                PROBLEM_JSON
            );
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let body: Value = serde_json::from_slice(&bytes).expect("json");
            assert_eq!(body["code"], "sys.invalid_value");
            assert_eq!(body["status"], 400);
            assert_eq!(body["params"]["kind"], "idempotency key");
        }
    }

    #[tokio::test]
    async fn takes_the_source_ip_from_connect_info() {
        let mut parts = parts(None);
        let peer = SocketAddr::from(([192, 0, 2, 10], 40_000));
        parts.extensions.insert(ConnectInfo(peer));
        let Ctx(ctx) = extract(&mut parts).await.expect("ctx");
        assert_eq!(ctx.source_ip, Some(peer.ip()));
    }

    #[tokio::test]
    async fn resolves_the_session_cookie_through_the_authenticator() {
        let user = UserId::generate();
        let mut parts = parts(None);
        parts.headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; tenko_session=s3ss10n; other=1"),
        );
        let Ctx(ctx) = Ctx::from_request_parts(&mut parts, &state_with_auth(user))
            .await
            .expect("ctx");
        assert!(matches!(
            ctx.principal,
            Principal::User { id, strength: AuthStrength::Passkey, .. } if id == user
        ));
        let record = authenticated(&parts).expect("record");
        assert_eq!(record.user, Some(user));
        assert!(record.roles.contains("admin"));
    }

    #[tokio::test]
    async fn a_bearer_token_wins_over_the_cookie() {
        let user = UserId::generate();
        let mut parts = parts(None);
        parts.headers.insert(
            header::COOKIE,
            HeaderValue::from_static("tenko_session=s3ss10n"),
        );
        parts.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer t0k3n"),
        );
        let Ctx(ctx) = Ctx::from_request_parts(&mut parts, &state_with_auth(user))
            .await
            .expect("ctx");
        assert!(matches!(
            ctx.principal,
            Principal::User {
                strength: AuthStrength::Password,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn missing_or_wrong_credentials_are_refused_with_401() {
        let user = UserId::generate();
        for cookie in [None, Some("tenko_session=wrong")] {
            let mut parts = parts(None);
            if let Some(cookie) = cookie {
                parts.headers.insert(
                    header::COOKIE,
                    HeaderValue::from_str(cookie).expect("cookie"),
                );
            }
            let error = Ctx::from_request_parts(&mut parts, &state_with_auth(user))
                .await
                .expect_err("must be refused");
            assert_eq!(error.coded_error().code, "auth.unauthenticated");
            assert_eq!(error.into_response().status(), StatusCode::UNAUTHORIZED);
            assert!(authenticated(&parts).is_none());
        }
    }
}
