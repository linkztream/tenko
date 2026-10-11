//! Request extractors.
//!
//! - [`Ctx`] builds the [`RequestCtx`] that every domain call takes: who acts, the request
//!   id, the processing time, the client address and the idempotency key.
//! - [`ClientInfo`] is the client as the trusted proxy rules see it (OPS-22): the effective
//!   source address, whether the client used HTTPS and the host name it addressed. WP1.2
//!   derives the WebAuthn relying-party id and the `Secure` cookie flag from it.
//!
//! Inside the server, the API middleware fills three request extensions before any handler
//! runs: the [`RequestId`] (also sent as `X-Request-Id`), the [`ClientInfo`], and the
//! outcome of the authenticator ([`AuthOutcome`]), so that rate limits and idempotency see
//! the principal and the authenticator runs once per request. When the router runs without
//! the middleware (unit tests through `tenko_api::router()`), the extractors compute the
//! same values themselves from the request.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::{HeaderMap, Uri, header, request::Parts},
};
use tenko_core::{
    AuthFailure, Authenticated, Credentials, IdempotencyKey, InvalidValue, Principal, RequestCtx,
    RequestId, SystemComponent, Timestamp, auth::SESSION_COOKIE,
};

use crate::{problem::ApiError, state::AppState};

/// Name of the header that carries the client's idempotency key (API-04).
pub(crate) const IDEMPOTENCY_HEADER: &str = "idempotency-key";

/// The [`RequestCtx`] of the current request.
///
/// Filled from the request:
///
/// - `request` is the request id of the middleware (or a new [`RequestId`]) and `now` the
///   current time.
/// - `source_ip` is [`ClientInfo::source_ip`]: the TCP peer, or the client behind a trusted
///   reverse proxy.
/// - `idempotency` is the `Idempotency-Key` header. A value that is not valid UTF-8, or that
///   [`IdempotencyKey::new`] rejects, is refused with 400 `sys.invalid_value`.
/// - `principal` comes from the [`Authenticator`](tenko_core::Authenticator) in the
///   [`AppState`], which resolves the session cookie or bearer token. Without credentials, or
///   with rejected ones, the request fails with the authenticator's problem details (401 or
///   503). When the state has no authenticator (development and tests), the request acts as
///   the API itself. The full [`Authenticated`] record is stored in the request extensions
///   for handlers that need roles or flags ([`authenticated`]).
/// - While the account must change its password (`password_change_required`), every route
///   answers 403 `auth.password_change_required` except the password change and its live
///   check (`POST /auth/password`, `POST /auth/password/check`), sign-out
///   (`POST /auth/logout`) and the session (`GET /auth/session`) (WP3.2).
///
/// Public endpoints (setup, the login ceremonies, liveness) do not take `Ctx`.
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
        let source_ip = ClientInfo::from_parts(parts).source_ip;
        let request = parts
            .extensions
            .get::<RequestId>()
            .copied()
            .unwrap_or_else(RequestId::generate);
        let now = Timestamp::now();
        let principal = match &app.auth {
            None => placeholder_principal(),
            Some(authenticator) => {
                let outcome = if let Some(AuthOutcome(outcome)) = parts.extensions.get() {
                    outcome.clone()
                } else {
                    let credentials = credentials(&parts.headers);
                    authenticator
                        .authenticate(&credentials, source_ip, now)
                        .await
                };
                let authenticated = outcome?;
                if authenticated.flags.password_change_required
                    && !open_during_password_change(&parts.method, parts.uri.path())
                {
                    return Err(tenko_auth::AuthError::PasswordChangeRequired.into());
                }
                let principal = authenticated.principal.clone();
                parts.extensions.insert(authenticated);
                principal
            }
        };
        Ok(Self(RequestCtx {
            principal,
            request,
            now,
            source_ip,
            idempotency,
        }))
    }
}

/// The routes an account that must change its password may still use: the password change
/// and its live policy check, sign-out and the session. `path` may carry the API base or
/// not (nested routers see it without).
pub(crate) fn open_during_password_change(method: &axum::http::Method, path: &str) -> bool {
    let path = path.strip_prefix(crate::API_BASE).unwrap_or(path);
    let path = path.trim_end_matches('/');
    matches!(
        (method.as_str(), path),
        (
            "POST",
            "/auth/password" | "/auth/password/check" | "/auth/logout"
        ) | ("GET", "/auth/session")
    )
}

/// The outcome of the authenticator for the current request, stored by the API middleware
/// so that the authenticator runs once per request. Absent when the state has no
/// authenticator.
#[derive(Debug, Clone)]
pub struct AuthOutcome(pub Result<Authenticated, AuthFailure>);

impl AuthOutcome {
    /// The authenticated principal, if authentication succeeded.
    pub fn principal(&self) -> Option<&Principal> {
        self.0
            .as_ref()
            .ok()
            .map(|authenticated| &authenticated.principal)
    }
}

/// The principal of every request while no authenticator is configured: the API acting on
/// its own. Development and tests only.
pub(crate) fn placeholder_principal() -> Principal {
    Principal::System {
        component: SystemComponent::Api,
        on_behalf_of: None,
    }
}

/// Reads the session cookie and the `Authorization` header.
pub(crate) fn credentials(headers: &HeaderMap) -> Credentials {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let session = session_cookie(headers);
    Credentials::from_headers(session, authorization)
}

/// The value of the session cookie, if the request carries one.
pub(crate) fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|header| {
            header.split(';').map(str::trim).find_map(|pair| {
                pair.strip_prefix(SESSION_COOKIE)
                    .and_then(|rest| rest.strip_prefix('='))
            })
        })
}

/// Reads and validates the `Idempotency-Key` header.
pub(crate) fn idempotency_key(parts: &Parts) -> Result<Option<IdempotencyKey>, ApiError> {
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

/// The client of the request as the trusted proxy rules of OPS-22 see it.
///
/// - `source_ip` is the TCP peer; when the peer is a trusted reverse proxy, the address
///   from its PROXY protocol header or the nearest untrusted address of
///   `X-Forwarded-For`.
/// - `https` is true when the connection to Tenko uses TLS, or when a trusted proxy says
///   the client used HTTPS (`X-Forwarded-Proto` or the PROXY protocol v2 SSL record).
/// - `host` is the host the client addressed: `X-Forwarded-Host` from a trusted proxy, else
///   the `Host` header or the HTTP/2 authority, lower-cased and validated, with its port.
///
/// Forwarded headers from any other source are never used. Use [`ClientInfo::host_name`]
/// for the WebAuthn relying-party id and [`ClientInfo::https`] for the `Secure` cookie
/// flag.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientInfo {
    /// The effective client address.
    pub source_ip: Option<IpAddr>,
    /// The TCP peer of the connection.
    pub peer: Option<SocketAddr>,
    /// Whether the client reached Tenko over HTTPS.
    pub https: bool,
    /// The host and optional port the client addressed, lower-case.
    pub host: Option<String>,
    /// Whether address, scheme or host came from a trusted proxy.
    pub via_proxy: bool,
}

impl ClientInfo {
    /// `https` or `http`.
    pub const fn scheme(&self) -> &'static str {
        if self.https { "https" } else { "http" }
    }

    /// The host without its port (for IPv6 literals, without the brackets).
    pub fn host_name(&self) -> Option<&str> {
        let host = self.host.as_deref()?;
        if let Some(rest) = host.strip_prefix('[') {
            return rest.split(']').next();
        }
        Some(host.rsplit_once(':').map_or(host, |(name, _)| name))
    }

    /// The origin the client sees, `scheme://host[:port]`, with the default port of the
    /// scheme left out (the form browsers send in `Origin`).
    pub fn origin(&self) -> Option<String> {
        let host = self.host.as_deref()?;
        Some(normalize_origin(self.scheme(), host))
    }

    /// The client info of a request: the middleware's extension, or, without middleware,
    /// the peer from `ConnectInfo` with no proxy rules applied.
    pub(crate) fn from_parts(parts: &Parts) -> Self {
        if let Some(info) = parts.extensions.get::<ClientInfo>() {
            return info.clone();
        }
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| *peer);
        Self {
            source_ip: peer.map(|peer| peer.ip()),
            peer,
            https: parts.uri.scheme_str() == Some("https"),
            host: request_host(&parts.headers, &parts.uri),
            via_proxy: false,
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientInfo {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self::from_parts(parts)))
    }
}

/// The host of a request: the `Host` header, or the URI authority (HTTP/2), validated.
pub(crate) fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .and_then(valid_host)
}

/// Validates and lower-cases `host[:port]`: a DNS name, an IPv4 address or a bracketed
/// IPv6 address, with an optional decimal port. Anything else (user info, paths, spaces)
/// is refused.
pub(crate) fn valid_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 261 {
        return None;
    }
    let (name, port) = if let Some(rest) = raw.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        inside.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            after => Some(after.strip_prefix(':')?),
        };
        (format!("[{}]", inside.to_ascii_lowercase()), port)
    } else {
        let (name, port) = match raw.rsplit_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (raw, None),
        };
        let valid_name = !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid_name {
            return None;
        }
        (name.to_ascii_lowercase(), port)
    };
    match port {
        None => Some(name),
        Some(port) => {
            let port: u16 = port.parse().ok()?;
            Some(format!("{name}:{port}"))
        }
    }
}

/// `scheme://host[:port]` with the scheme's default port removed.
pub(crate) fn normalize_origin(scheme: &str, host: &str) -> String {
    // Hosts come from `valid_host`: only a bracketed IPv6 literal contains colons, and it
    // ends with `]` unless a port follows, so a `:port` suffix is always the port.
    let default = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let host = match host.strip_suffix(default) {
        Some(stripped) if !default.is_empty() => stripped,
        _ => host,
    };
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

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
            ..AppState::default()
        }
    }

    /// Answers every session as one whose password must change.
    struct MustChangePassword(UserId);

    impl Authenticator for MustChangePassword {
        fn authenticate<'a>(
            &'a self,
            _credentials: &'a Credentials,
            _source_ip: Option<IpAddr>,
            _now: Timestamp,
        ) -> AuthFuture<'a> {
            Box::pin(async move {
                Ok(Authenticated {
                    principal: Principal::User {
                        id: self.0,
                        session: SessionId::generate(),
                        strength: AuthStrength::Password,
                    },
                    user: Some(self.0),
                    roles: BTreeSet::from(["viewer".to_owned()]),
                    strength: AuthStrength::Password,
                    expires_at: None,
                    flags: AuthFlags {
                        password_change_required: true,
                        ..AuthFlags::default()
                    },
                })
            })
        }
    }

    #[tokio::test]
    async fn a_required_password_change_closes_every_route_but_four() {
        let state = AppState {
            auth: Some(Arc::new(MustChangePassword(UserId::generate()))),
            ..AppState::default()
        };
        let request = |method: &str, path: &str| {
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::COOKIE, "tenko_session=s3ss10n")
                .body(Body::empty())
                .expect("request")
                .into_parts()
                .0
        };
        for (method, path) in [
            ("POST", "/api/v1/auth/password"),
            ("POST", "/api/v1/auth/password/check"),
            ("POST", "/auth/logout"),
            ("GET", "/api/v1/auth/session"),
        ] {
            let mut parts = request(method, path);
            assert!(
                Ctx::from_request_parts(&mut parts, &state).await.is_ok(),
                "{method} {path}"
            );
        }
        for (method, path) in [
            ("GET", "/api/v1/prefixes"),
            ("GET", "/api/v1/auth/password"),
            ("DELETE", "/api/v1/auth/session"),
            ("GET", "/api/v1/events"),
            ("POST", "/api/v1/auth/tokens"),
        ] {
            let mut parts = request(method, path);
            let error = Ctx::from_request_parts(&mut parts, &state)
                .await
                .expect_err("refused");
            assert_eq!(error.coded_error().code, "auth.password_change_required");
            assert_eq!(error.into_response().status(), StatusCode::FORBIDDEN);
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
    async fn uses_the_middleware_request_id_and_client_info() {
        let mut parts = parts(None);
        let id = RequestId::generate();
        parts.extensions.insert(id);
        parts.extensions.insert(ClientInfo {
            source_ip: Some("198.51.100.20".parse().expect("ip")),
            peer: Some(SocketAddr::from(([192, 0, 2, 1], 50_000))),
            https: true,
            host: Some("ddi.example.org".to_owned()),
            via_proxy: true,
        });
        parts
            .extensions
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50_000))));
        let Ctx(ctx) = extract(&mut parts).await.expect("ctx");
        assert_eq!(ctx.request, id);
        assert_eq!(ctx.source_ip, Some("198.51.100.20".parse().expect("ip")));
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

    #[tokio::test]
    async fn uses_the_outcome_stored_by_the_middleware() {
        let user = UserId::generate();
        let mut parts = parts(None);
        parts
            .extensions
            .insert(AuthOutcome(Err(AuthFailure::Expired)));
        let error = Ctx::from_request_parts(&mut parts, &state_with_auth(user))
            .await
            .expect_err("expired");
        assert_eq!(error.coded_error().code, "auth.session_expired");
    }

    #[test]
    fn hosts_are_validated_and_lower_cased() {
        assert_eq!(
            valid_host("DDI.Example.org"),
            Some("ddi.example.org".to_owned())
        );
        assert_eq!(
            valid_host("ddi.example.org:8443"),
            Some("ddi.example.org:8443".to_owned())
        );
        assert_eq!(
            valid_host("192.0.2.10:443"),
            Some("192.0.2.10:443".to_owned())
        );
        assert_eq!(
            valid_host("[2001:DB8::1]:8443"),
            Some("[2001:db8::1]:8443".to_owned())
        );
        assert_eq!(
            valid_host("[2001:db8::1]"),
            Some("[2001:db8::1]".to_owned())
        );
        for bad in [
            "",
            "user@ddi.example.org",
            "ddi.example.org/path",
            "ddi example.org",
            "ddi.example.org:99999",
            "ddi.example.org:",
            "[2001:db8::1",
            "[not-v6]:80",
            "a..b",
        ] {
            assert_eq!(valid_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn origins_drop_default_ports() {
        assert_eq!(
            normalize_origin("https", "ddi.example.org:443"),
            "https://ddi.example.org"
        );
        assert_eq!(
            normalize_origin("https", "ddi.example.org:8443"),
            "https://ddi.example.org:8443"
        );
        assert_eq!(
            normalize_origin("http", "ddi.example.org:80"),
            "http://ddi.example.org"
        );
        assert_eq!(
            normalize_origin("http", "[2001:db8::1]:80"),
            "http://[2001:db8::1]"
        );
        assert_eq!(
            normalize_origin("https", "[2001:db8::1]:8443"),
            "https://[2001:db8::1]:8443"
        );
        let info = ClientInfo {
            https: true,
            host: Some("ddi.example.org:443".to_owned()),
            ..ClientInfo::default()
        };
        assert_eq!(info.origin().as_deref(), Some("https://ddi.example.org"));
        assert_eq!(info.host_name(), Some("ddi.example.org"));
        let v6 = ClientInfo {
            host: Some("[2001:db8::1]:8443".to_owned()),
            ..ClientInfo::default()
        };
        assert_eq!(v6.host_name(), Some("2001:db8::1"));
        assert_eq!(v6.scheme(), "http");
    }
}
