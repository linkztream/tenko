//! Login, sessions, authentication factors, recovery codes and personal tokens.
//!
//! Area: auth. Owner: WP1.2. Requirements: IAM-03, IAM-04, IAM-05, IAM-06, IAM-08, IAM-09,
//! IAM-10.
//!
//! Password login returns a session or a challenge with the remaining methods; `WebAuthn`
//! also covers break-glass. Sessions travel in the `tenko_session` cookie, personal tokens
//! as bearer tokens (shown once, expiry capped by TGL-05).
//!
//! The handlers are thin: [`tenko_auth::AuthService`] owns the rules and its errors carry
//! their own stable codes (`auth.*`, `users.*`, `settings.*`), which convert into problem
//! details with `?`.
//!
//! # The service
//!
//! The server adds the service to the router as a request extension
//! (`.layer(Extension(Arc<AuthService>))`); the handlers read it through `Svc`. Without it
//! every endpoint of the four areas of WP1.2 answers `503` `auth.unavailable`, before the
//! credentials or the body are looked at.
//!
//! # Public and authenticated endpoints
//!
//! Setup and the login ceremonies are public: they take `PublicCtx`, a request context of
//! the API itself with the client address and the `User-Agent`. Every other endpoint takes
//! [`Ctx`], which resolves the session cookie or bearer token and refuses with `401`
//! otherwise. `POST /auth/password/check` is public while setup is open and needs a session
//! afterwards; the service decides.
//!
//! # Sessions and tokens
//!
//! A personal token authenticates the reads (`GET /auth/sessions`, `/auth/tokens`,
//! `/auth/webauthn/credentials`, `/users`, `/roles`, `/settings/security`, ...) with the
//! rights of its owner. Whatever acts on the session itself, mints tokens, changes the
//! factors of an account, or administers users and settings needs the interactive login:
//! the service refuses a token there (`401 auth.unauthenticated` where the endpoint needs a
//! session, `403 auth.forbidden` where it needs the permission to administer). The OpenAPI
//! document lists only the `session` scheme on those endpoints.
//!
//! # Answers
//!
//! | Endpoint | Success | Notes |
//! |---|---|---|
//! | `POST /auth/login/password`, `/auth/login/totp`, `/auth/login/recovery` | 200 `LoginResponse` | `Set-Cookie` when the login is complete |
//! | `POST /auth/webauthn/login/start` | 200 `WebAuthnLoginOptions` | the body is optional |
//! | `POST /auth/webauthn/login/finish` | 200 `LoginResponse` | `Set-Cookie` |
//! | `POST /auth/logout` | 204 | `Set-Cookie` that removes the cookie |
//! | `GET /auth/session` | 200 `SessionInfo` | |
//! | `GET /auth/sessions`, `/auth/webauthn/credentials`, `/auth/tokens` | 200 page | not paginated |
//! | `DELETE /auth/sessions/{id}`, `/auth/tokens/{id}`, `/auth/webauthn/credentials/{id}`, `/auth/totp` | 204 | |
//! | `POST /auth/password` | 200 `PasswordChanged` | |
//! | `POST /auth/password/check` | 200 `PasswordCheckResult` | public while setup is open |
//! | `POST /auth/totp/enroll/start` | 200 `TotpEnrolment` | the seed is shown once |
//! | `POST /auth/totp/enroll/finish`, `/auth/webauthn/register/finish` | 200 `FactorEnrolled` | |
//! | `POST /auth/webauthn/register/start` | 200 `WebAuthnRegisterOptions` | the body is optional |
//! | `POST /auth/recovery-codes` | 200 `RecoveryCodes` | shown once |
//! | `POST /auth/tokens` | 201 `CreatedToken` | shown once |
//!
//! Lists answer a [`Page`] with `next_cursor: null` and the store revision: the lists of this
//! area are small and not paginated.
//!
//! # Secrets
//!
//! Nothing here logs a password, a code, a token or a session secret. Answers that carry a
//! secret (sessions, tokens, recovery codes, TOTP seeds) set `Cache-Control: no-store`
//! themselves.
//!
//! # Shared helpers
//!
//! This module also holds what the other areas of WP1.2 (`setup`, `users`, `settings`)
//! share: the service lookup (`Svc`), `PublicCtx`, the body extractors
//! (`ApiJson`, `OptionalJson`) that refuse with problem details, `RouteError` (adds
//! `Retry-After` to a throttled answer), `If-Match` parsing, `ETag` and the list page.

use std::{convert::Infallible, sync::Arc};

use axum::{
    Json,
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use tenko_auth::{
    AuthError, AuthService, LoginOutcome, NewSession,
    service::{
        CodeLogin, CreatedToken, CredentialInfo, FactorEnrolled, LoginResponse, PasswordChange,
        PasswordChanged, PasswordCheck, PasswordCheckResult, PasswordLogin, RecoveryCodes,
        SessionInfo, SessionSummary, TokenInfo, TokenRequest, TotpEnrolFinish, TotpEnrolment,
        WebAuthnLoginFinish, WebAuthnLoginOptions, WebAuthnLoginStart, WebAuthnRegisterFinish,
        WebAuthnRegisterOptions, WebAuthnRegisterStart,
    },
};
use tenko_core::{
    ApiTokenId, Coded, CodedError, FieldError, InvalidValue, RequestCtx, RequestId, Revision,
    SessionId, SystemComponent, Timestamp, error::codes as core_codes,
};
use utoipa::IntoResponses;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::Page,
    extract::{ClientInfo, Ctx},
    problem::{ApiError, ProblemDetails, codes as api_codes},
    state::AppState,
};

/// Longest `User-Agent` handed to the service, in characters.
const USER_AGENT_LIMIT: usize = 200;

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(login_password))
        .routes(routes!(login_totp))
        .routes(routes!(login_recovery))
        .routes(routes!(webauthn_login_start))
        .routes(routes!(webauthn_login_finish))
        .routes(routes!(logout))
        .routes(routes!(get_session))
        .routes(routes!(list_sessions))
        .routes(routes!(revoke_session))
        .routes(routes!(change_password))
        .routes(routes!(check_password))
        .routes(routes!(totp_enroll_start))
        .routes(routes!(totp_enroll_finish))
        .routes(routes!(remove_totp))
        .routes(routes!(webauthn_register_start))
        .routes(routes!(webauthn_register_finish))
        .routes(routes!(list_webauthn_credentials))
        .routes(routes!(delete_webauthn_credential))
        .routes(routes!(regenerate_recovery_codes))
        .routes(routes!(list_tokens, create_token))
        .routes(routes!(revoke_token))
}

// ---------------------------------------------------------------------------------------
// Shared problem responses
// ---------------------------------------------------------------------------------------

/// 401 of every authenticated endpoint.
#[derive(IntoResponses)]
#[response(
    status = 401,
    description = "No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way",
    content_type = "application/problem+json"
)]
#[allow(dead_code, reason = "only the OpenAPI response of the type is used")]
pub(crate) struct Unauthenticated(ProblemDetails);

/// 403 of the endpoints that check a permission or a fresh authentication.
#[derive(IntoResponses)]
#[response(
    status = 403,
    description = "The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`)",
    content_type = "application/problem+json"
)]
#[allow(dead_code, reason = "only the OpenAPI response of the type is used")]
pub(crate) struct Forbidden(ProblemDetails);

/// 503 of every endpoint that needs the authentication service.
#[derive(IntoResponses)]
#[response(
    status = 503,
    description = "The authentication service is not configured or not ready (`auth.unavailable`)",
    content_type = "application/problem+json"
)]
#[allow(dead_code, reason = "only the OpenAPI response of the type is used")]
pub(crate) struct Unavailable(ProblemDetails);

// ---------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------

/// The authentication service of the request: the `Arc<AuthService>` extension that the
/// server adds to the router. Without it the request is refused with `503`
/// `auth.unavailable`, before anything else about the request is looked at.
#[derive(Debug, Clone)]
pub(crate) struct Svc(pub(crate) Arc<AuthService>);

impl<S: Send + Sync> FromRequestParts<S> for Svc {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Arc<AuthService>>()
                .cloned()
                .map(Self)
                .ok_or_else(|| {
                    AuthError::Unavailable("authentication service not configured").into()
                }),
        )
    }
}

/// The error of the handlers of WP1.2: problem details, with `Retry-After` on a throttled
/// answer (`429` with a `retry_after` parameter).
#[derive(Debug)]
pub(crate) struct RouteError(ApiError);

impl<E: Coded> From<E> for RouteError {
    fn from(error: E) -> Self {
        Self(ApiError::from(error))
    }
}

impl From<ApiError> for RouteError {
    fn from(error: ApiError) -> Self {
        Self(error)
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let retry_after = (self.0.status() == 429)
            .then(|| self.0.coded_error().params.get("retry_after"))
            .flatten()
            .and_then(|seconds| seconds.parse::<u64>().ok());
        let mut response = self.0.into_response();
        if let Some(seconds) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

/// The request context of a public endpoint (setup, login ceremonies): the API acting on
/// its own, with the request id of the middleware, the effective client address and the
/// `User-Agent` for the service's session record.
#[derive(Debug, Clone)]
pub(crate) struct PublicCtx {
    /// The context handed to the service.
    pub(crate) ctx: RequestCtx,
    /// The `User-Agent` header, cut to 200 characters.
    pub(crate) user_agent: Option<String>,
}

impl PublicCtx {
    /// The context of a request: the request id of the middleware (or a new one), the
    /// current time, the effective client address and the `User-Agent`.
    fn from_parts(parts: &Parts) -> Self {
        let mut ctx = RequestCtx::system(SystemComponent::Api);
        ctx.request = parts
            .extensions
            .get::<RequestId>()
            .copied()
            .unwrap_or_else(RequestId::generate);
        ctx.now = Timestamp::now();
        ctx.source_ip = ClientInfo::from_parts(parts).source_ip;
        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|agent| agent.chars().take(USER_AGENT_LIMIT).collect::<String>())
            .filter(|agent| !agent.is_empty());
        Self { ctx, user_agent }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for PublicCtx {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self::from_parts(parts)))
    }
}

/// A required JSON body. Unlike the plain `Json` extractor, a bad body is refused with
/// problem details (`sys.invalid_request`, `400`; `415` for another content type; `413`
/// `sys.body_too_large` over the body limit), and the answer never repeats what the client
/// sent, because bodies of this area carry passwords and codes.
#[derive(Debug, Clone)]
pub(crate) struct ApiJson<T>(pub(crate) T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (is_json, bytes) = read_body(request, state).await?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(invalid_request(400, "the request needs a JSON body"));
        }
        if !is_json {
            return Err(unsupported_media_type());
        }
        parse_json(&bytes).map(Self)
    }
}

/// An optional JSON body: an empty body means `T::default()`.
#[derive(Debug, Clone)]
pub(crate) struct OptionalJson<T>(pub(crate) T);

impl<T, S> FromRequest<S> for OptionalJson<T>
where
    T: DeserializeOwned + Default,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (is_json, bytes) = read_body(request, state).await?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self(T::default()));
        }
        if !is_json {
            return Err(unsupported_media_type());
        }
        parse_json(&bytes).map(Self)
    }
}

/// Reads the body and tells whether the request declared JSON.
async fn read_body<S: Send + Sync>(request: Request, state: &S) -> Result<(bool, Bytes), ApiError> {
    let is_json = is_json_content_type(request.headers());
    let bytes = Bytes::from_request(request, state)
        .await
        .map_err(|rejection| {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::new(
                    api_codes::BODY_TOO_LARGE,
                    413,
                    "the request body exceeds the limit",
                )
            } else {
                invalid_request(400, "the request body cannot be read")
            }
        })?;
    Ok((is_json, bytes))
}

/// Whether the `Content-Type` is `application/json` or a `+json` type.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
}

/// A `sys.invalid_request` problem.
fn invalid_request(status: u16, detail: impl Into<String>) -> ApiError {
    ApiError::new(core_codes::INVALID_REQUEST, status, detail)
}

fn unsupported_media_type() -> ApiError {
    invalid_request(415, "the request body must be sent as application/json")
}

/// Parses a JSON body. The detail never quotes the body; a missing field is named, because
/// that is the schema of the endpoint and not what the client sent.
fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    // A struct would also accept a JSON array of its fields; every body here is an object.
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err(invalid_request(
            400,
            "the request body must be a JSON object",
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| {
        if error.classify() != serde_json::error::Category::Data {
            return invalid_request(400, "the request body is not valid JSON");
        }
        let message = error.to_string();
        let missing = message
            .strip_prefix("missing field `")
            .and_then(|rest| rest.split_once('`'))
            .map(|(field, _)| field.to_owned());
        match missing {
            Some(field) => ApiError::from_coded_error(
                CodedError::new(
                    core_codes::INVALID_REQUEST,
                    400,
                    format!("the request body is missing the field `{field}`"),
                )
                .with_param("field", field.clone())
                .with_field_error(FieldError::new(field, core_codes::INVALID_REQUEST)),
            ),
            None => invalid_request(
                400,
                "the request body does not match the schema of this endpoint",
            ),
        }
    })
}

/// A JSON answer that carries a secret or starts a session: `Cache-Control: no-store`
/// (set here so that nothing stores the answer) and, for a login, the `Set-Cookie` header.
pub(crate) fn secret_json<T: Serialize>(
    status: StatusCode,
    set_cookie: Option<&str>,
    body: &T,
) -> Result<Response, RouteError> {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(cookie) = set_cookie {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie_value(cookie)?);
    }
    Ok(response)
}

/// A `Set-Cookie` value from the service. The cookie holds a secret: the error names no
/// value.
fn cookie_value(cookie: &str) -> Result<HeaderValue, AuthError> {
    HeaderValue::from_str(cookie)
        .map_err(|_| AuthError::internal("the session cookie is not a valid header value"))
}

/// The page of a small list: every item, no cursor, the store revision it was read at.
pub(crate) fn page<T>(app: &AppState, items: Vec<T>) -> Json<Page<T>> {
    Json(Page::new(items, None, app.store.status().revision))
}

/// Adds `ETag: "<revision>"`.
pub(crate) fn with_etag(mut response: Response, revision: Revision) -> Response {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{revision}\"")) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

/// Reads `If-Match` into the service's `expect`: `"12"`, `12` and `W/"12"` mean revision 12,
/// `*` and an absent header mean no precondition. Anything else is `400`
/// `sys.invalid_value`.
pub(crate) fn if_match(headers: &HeaderMap) -> Result<Option<Revision>, ApiError> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(value.as_bytes());
    let invalid = || {
        ApiError::from(InvalidValue::new(
            "If-Match",
            &text,
            "expected a revision such as \"12\"",
        ))
    };
    if values.next().is_some() {
        return Err(invalid());
    }
    let trimmed = text.trim();
    if trimmed == "*" {
        return Ok(None);
    }
    let tag = trimmed.strip_prefix("W/").unwrap_or(trimmed);
    let digits = match tag.strip_prefix('"') {
        Some(quoted) => quoted.strip_suffix('"').ok_or_else(invalid)?,
        None => tag,
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    digits
        .parse::<u64>()
        .map(|revision| Some(Revision(revision)))
        .map_err(|_| invalid())
}

/// The answer of a complete or pending login step: the JSON of the [`LoginResponse`] and,
/// for a session, its cookie.
fn login_answer(outcome: LoginOutcome) -> Result<Response, RouteError> {
    let (body, cookie) = outcome.into_response();
    secret_json(StatusCode::OK, cookie.as_deref(), &body)
}

// ---------------------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------------------

/// Checks the user name and password. A complete login answers with the session and sets
/// the cookie; an account with a second factor answers with a challenge.
#[utoipa::path(
    post,
    path = "/auth/login/password",
    tag = "auth",
    operation_id = "login_password",
    summary = "Log in with a user name and password",
    request_body = PasswordLogin,
    responses(
        (status = 200, description = "The login is complete (`status: authenticated`) or a second factor is required (`status: second_factor`)", body = LoginResponse,
            headers(("Set-Cookie" = String, description = "The session cookie `tenko_session` (HttpOnly, SameSite=Strict, Secure); only when the login is complete"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The user name or password was not accepted (`auth.invalid_credentials`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Too many failed attempts, or the account is locked (`auth.throttled`); `Retry-After` gives the seconds", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn login_password(
    Svc(service): Svc,
    PublicCtx { ctx, user_agent }: PublicCtx,
    ApiJson(request): ApiJson<PasswordLogin>,
) -> Result<Response, RouteError> {
    login_answer(
        service
            .login_password(&ctx, user_agent.as_deref(), &request)
            .await?,
    )
}

/// Completes a login with the code of an authenticator app.
#[utoipa::path(
    post,
    path = "/auth/login/totp",
    tag = "auth",
    operation_id = "login_totp",
    summary = "Complete a login with a TOTP code",
    request_body = CodeLogin,
    responses(
        (status = 200, description = "The login is complete; the session cookie is set", body = LoginResponse,
            headers(("Set-Cookie" = String, description = "The session cookie `tenko_session`"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the challenge is unknown or expired (`auth.challenge_invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The code was not accepted (`auth.invalid_credentials`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Too many failed attempts (`auth.throttled`); `Retry-After` gives the seconds", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn login_totp(
    Svc(service): Svc,
    PublicCtx { ctx, user_agent }: PublicCtx,
    ApiJson(request): ApiJson<CodeLogin>,
) -> Result<Response, RouteError> {
    login_answer(
        service
            .login_totp(&ctx, user_agent.as_deref(), &request)
            .await?,
    )
}

/// Completes a login with one of the recovery codes; the code is spent.
#[utoipa::path(
    post,
    path = "/auth/login/recovery",
    tag = "auth",
    operation_id = "login_recovery",
    summary = "Complete a login with a recovery code",
    request_body = CodeLogin,
    responses(
        (status = 200, description = "The login is complete; the session cookie is set", body = LoginResponse,
            headers(("Set-Cookie" = String, description = "The session cookie `tenko_session`"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the challenge is unknown or expired (`auth.challenge_invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The code was not accepted (`auth.invalid_credentials`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Too many failed attempts (`auth.throttled`); `Retry-After` gives the seconds", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn login_recovery(
    Svc(service): Svc,
    PublicCtx { ctx, user_agent }: PublicCtx,
    ApiJson(request): ApiJson<CodeLogin>,
) -> Result<Response, RouteError> {
    login_answer(
        service
            .login_recovery(&ctx, user_agent.as_deref(), &request)
            .await?,
    )
}

/// Starts a passkey login: for a named account, for the passkey step of a password login
/// (pass its `challenge_id`), or discoverable (no body). The body is optional.
#[utoipa::path(
    post,
    path = "/auth/webauthn/login/start",
    tag = "auth",
    operation_id = "webauthn_login_start",
    summary = "Start a WebAuthn login and return the challenge",
    request_body(content = Option<WebAuthnLoginStart>, description = "Optional: the account, or the challenge of a password login", content_type = "application/json"),
    responses(
        (status = 200, description = "The options for `navigator.credentials.get()` and the ceremony id for the finish step", body = WebAuthnLoginOptions),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the password challenge is unknown (`auth.challenge_invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn webauthn_login_start(
    Svc(service): Svc,
    PublicCtx { ctx, .. }: PublicCtx,
    OptionalJson(request): OptionalJson<WebAuthnLoginStart>,
) -> Result<Json<WebAuthnLoginOptions>, RouteError> {
    Ok(Json(service.webauthn_login_start(&ctx, &request).await?))
}

/// Verifies the signed assertion and starts the session.
#[utoipa::path(
    post,
    path = "/auth/webauthn/login/finish",
    tag = "auth",
    operation_id = "webauthn_login_finish",
    summary = "Finish a WebAuthn login with the signed assertion",
    request_body = WebAuthnLoginFinish,
    responses(
        (status = 200, description = "The login is complete (`status: authenticated`); the session cookie is set", body = LoginResponse,
            headers(("Set-Cookie" = String, description = "The session cookie `tenko_session`"))),
        (status = 400, description = "The body or the assertion is malformed or fails verification (`sys.invalid_request`, `auth.challenge_invalid`, `auth.webauthn.*`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The credential is unknown (`auth.invalid_credentials`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The break-glass account needs a hardware key (`auth.break_glass.hardware_key_only`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "The break-glass rate limit applies (`auth.throttled`); `Retry-After` gives the seconds", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn webauthn_login_finish(
    Svc(service): Svc,
    PublicCtx { ctx, user_agent }: PublicCtx,
    ApiJson(request): ApiJson<WebAuthnLoginFinish>,
) -> Result<Response, RouteError> {
    let NewSession {
        info, set_cookie, ..
    } = service
        .webauthn_login_finish(&ctx, user_agent.as_deref(), &request)
        .await?;
    secret_json(
        StatusCode::OK,
        Some(&set_cookie),
        &LoginResponse::Authenticated { session: info },
    )
}

/// Ends the session of the request and removes the cookie. Only an interactive session can
/// log out; a bearer token is revoked with `DELETE /auth/tokens/{id}`.
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    operation_id = "logout",
    summary = "End the current session",
    responses(
        (status = 204, description = "The session ended",
            headers(("Set-Cookie" = String, description = "Removes the session cookie (`Max-Age=0`)"))),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn logout(Svc(service): Svc, Ctx(ctx): Ctx) -> Result<Response, RouteError> {
    let cookie = service.logout(&ctx).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, cookie_value(&cookie)?);
    Ok(response)
}

// ---------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------

/// Describes the session of the request.
#[utoipa::path(
    get,
    path = "/auth/session",
    tag = "auth",
    operation_id = "get_session",
    summary = "Describe the current session: principal, roles, strength and expiry",
    responses(
        (status = 200, description = "The session", body = SessionInfo),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn get_session(Svc(service): Svc, Ctx(ctx): Ctx) -> Result<Json<SessionInfo>, RouteError> {
    Ok(Json(service.current_session(&ctx).await?))
}

/// Lists the sessions of the current user, newest first. The list is small and not
/// paginated: `next_cursor` is always `null`.
#[utoipa::path(
    get,
    path = "/auth/sessions",
    tag = "auth",
    operation_id = "list_sessions",
    summary = "List the sessions of the current user",
    responses(
        (status = 200, description = "Every session of the user; `current` marks the session of the request", body = Page<SessionSummary>),
        Unauthenticated,
        Unavailable
    )
)]
async fn list_sessions(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<SessionSummary>>, RouteError> {
    Ok(page(&app, service.list_sessions(&ctx).await?))
}

/// Ends one session of the current user. Revoking the current session works like a logout
/// without the cookie removal.
#[utoipa::path(
    delete,
    path = "/auth/sessions/{id}",
    tag = "auth",
    operation_id = "revoke_session",
    summary = "Revoke one session of the current user",
    params(("id" = String, Path, description = "Session identifier")),
    responses(
        (status = 204, description = "The session ended"),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The user has no such session (`auth.session.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn revoke_session(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError> {
    let id = id.parse::<SessionId>()?;
    service.revoke_session(&ctx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------
// Password
// ---------------------------------------------------------------------------------------

/// Changes the password (or PIN) of the current user and ends the user's other sessions.
#[utoipa::path(
    post,
    path = "/auth/password",
    tag = "auth",
    operation_id = "change_password",
    summary = "Change the password of the current user",
    request_body = PasswordChange,
    responses(
        (status = 200, description = "The password changed; the other sessions ended", body = PasswordChanged),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current password is wrong (`auth.password.incorrect`) or the account is the break-glass account (`auth.break_glass.hardware_key_only`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The new password breaks the policy (`auth.password.policy`, with the violations in `errors`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong current passwords (`auth.throttled`); `Retry-After` gives the seconds", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn change_password(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<PasswordChange>,
) -> Result<Json<PasswordChanged>, RouteError> {
    Ok(Json(service.change_password(&ctx, &request).await?))
}

/// Checks a candidate password against the live policy and the breach lists, for feedback
/// while the user types. Open while first-run setup is open (with the preset of the chosen
/// profile); a session or token is needed afterwards.
#[utoipa::path(
    post,
    path = "/auth/password/check",
    tag = "auth",
    operation_id = "check_password",
    summary = "Check a candidate password against the live policy and breach lists",
    request_body = PasswordCheck,
    responses(
        (status = 200, description = "Whether the password would be accepted, and why not", body = PasswordCheckResult),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Setup has completed and the request carries no valid session or token (`auth.unauthenticated`, `auth.session_expired`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security((), ("session" = []), ("token" = []))
)]
async fn check_password(
    Svc(service): Svc,
    caller: Result<Ctx, ApiError>,
    ApiJson(request): ApiJson<PasswordCheck>,
) -> Result<Json<PasswordCheckResult>, RouteError> {
    let (ctx, refusal) = match caller {
        Ok(Ctx(ctx)) => (Some(ctx), None),
        Err(refusal) => (None, Some(refusal)),
    };
    match (
        service.check_password(ctx.as_ref(), &request).await,
        refusal,
    ) {
        // Say why the caller is unauthenticated (expired session, authenticator down)
        // rather than give the service's generic answer.
        (Err(AuthError::Unauthenticated), Some(refusal)) => Err(refusal.into()),
        (result, _) => Ok(Json(result?)),
    }
}

// ---------------------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------------------

/// Starts TOTP enrolment. The seed and the provisioning URI are shown once.
#[utoipa::path(
    post,
    path = "/auth/totp/enroll/start",
    tag = "auth",
    operation_id = "totp_enroll_start",
    summary = "Start TOTP enrolment and return the provisioning data",
    responses(
        (status = 200, description = "The seed, the `otpauth://` URI and the enrolment id for the finish step; shown once", body = TotpEnrolment),
        (status = 409, description = "TOTP is already enrolled (`auth.totp.already_enrolled`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn totp_enroll_start(Svc(service): Svc, Ctx(ctx): Ctx) -> Result<Response, RouteError> {
    secret_json(StatusCode::OK, None, &service.totp_enrol_start(&ctx).await?)
}

/// Finishes TOTP enrolment with a first code. The first factor of an account brings its
/// recovery codes, shown once.
#[utoipa::path(
    post,
    path = "/auth/totp/enroll/finish",
    tag = "auth",
    operation_id = "totp_enroll_finish",
    summary = "Finish TOTP enrolment with a first code",
    request_body = TotpEnrolFinish,
    responses(
        (status = 200, description = "TOTP is enrolled; recovery codes when the account had none; `reauthenticate` says whether the session must log in again to reach the required strength", body = FactorEnrolled),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the enrolment is unknown or expired (`auth.challenge_invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The code does not match the new seed (`auth.totp.code_mismatch`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn totp_enroll_finish(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<TotpEnrolFinish>,
) -> Result<Response, RouteError> {
    secret_json(
        StatusCode::OK,
        None,
        &service.totp_enrol_finish(&ctx, &request).await?,
    )
}

/// Removes the TOTP factor. Needs a fresh authentication and another way to meet the
/// profile.
#[utoipa::path(
    delete,
    path = "/auth/totp",
    tag = "auth",
    operation_id = "remove_totp",
    summary = "Remove the TOTP factor of the current user",
    responses(
        (status = 204, description = "TOTP was removed"),
        (status = 403, description = "The action needs a fresh authentication (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "TOTP is not enrolled (`auth.totp.not_enrolled`) or the profile requires it (`auth.factor.last_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn remove_totp(Svc(service): Svc, Ctx(ctx): Ctx) -> Result<StatusCode, RouteError> {
    service.remove_totp(&ctx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------
// WebAuthn credentials
// ---------------------------------------------------------------------------------------

/// Starts registering a passkey or a security key. The body is optional.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/start",
    tag = "auth",
    operation_id = "webauthn_register_start",
    summary = "Start registering a WebAuthn credential and return the challenge",
    request_body(content = Option<WebAuthnRegisterStart>, description = "Optional: a label, and whether to ask for a security key", content_type = "application/json"),
    responses(
        (status = 200, description = "The options for `navigator.credentials.create()` and the ceremony id for the finish step", body = WebAuthnRegisterOptions),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the label is invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn webauthn_register_start(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    OptionalJson(request): OptionalJson<WebAuthnRegisterStart>,
) -> Result<Json<WebAuthnRegisterOptions>, RouteError> {
    Ok(Json(service.webauthn_register_start(&ctx, &request).await?))
}

/// Verifies the attestation and stores the credential.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/finish",
    tag = "auth",
    operation_id = "webauthn_register_finish",
    summary = "Finish registering a WebAuthn credential with the attestation",
    request_body = WebAuthnRegisterFinish,
    responses(
        (status = 200, description = "The credential is registered; recovery codes when the account had none", body = FactorEnrolled),
        (status = 400, description = "The body or the attestation is malformed or fails verification (`sys.invalid_request`, `auth.challenge_invalid`, `auth.webauthn.*`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The attestation is refused (`auth.webauthn.attestation_required`, `auth.webauthn.attestation_untrusted`, `auth.webauthn.backup_eligible_refused`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The credential is registered already (`auth.webauthn.credential_exists`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn webauthn_register_finish(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<WebAuthnRegisterFinish>,
) -> Result<Response, RouteError> {
    secret_json(
        StatusCode::OK,
        None,
        &service.webauthn_register_finish(&ctx, &request).await?,
    )
}

/// Lists the WebAuthn credentials of the current user. The list is small and not
/// paginated: `next_cursor` is always `null`.
#[utoipa::path(
    get,
    path = "/auth/webauthn/credentials",
    tag = "auth",
    operation_id = "list_webauthn_credentials",
    summary = "List the WebAuthn credentials of the current user",
    responses(
        (status = 200, description = "Every credential of the user", body = Page<CredentialInfo>),
        Unauthenticated,
        Unavailable
    )
)]
async fn list_webauthn_credentials(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<CredentialInfo>>, RouteError> {
    Ok(page(&app, service.list_credentials(&ctx).await?))
}

/// Deletes one credential. Needs a fresh authentication and another way to meet the
/// profile.
#[utoipa::path(
    delete,
    path = "/auth/webauthn/credentials/{id}",
    tag = "auth",
    operation_id = "delete_webauthn_credential",
    summary = "Delete one WebAuthn credential of the current user",
    params(("id" = String, Path, description = "Credential identifier (base64url)")),
    responses(
        (status = 204, description = "The credential was deleted"),
        (status = 403, description = "The action needs a fresh authentication (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The user has no such credential (`auth.webauthn.credential_not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The profile requires this credential (`auth.factor.last_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn delete_webauthn_credential(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError> {
    service.delete_credential(&ctx, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------------------

/// Replaces the recovery codes with a new set, shown once. Needs a fresh authentication and
/// TOTP or a passkey.
#[utoipa::path(
    post,
    path = "/auth/recovery-codes",
    tag = "auth",
    operation_id = "regenerate_recovery_codes",
    summary = "Generate a new set of recovery codes, shown once",
    responses(
        (status = 200, description = "The new codes; the old ones no longer work", body = RecoveryCodes),
        (status = 400, description = "The account has neither TOTP nor a passkey (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The action needs a fresh authentication (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn regenerate_recovery_codes(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Response, RouteError> {
    secret_json(
        StatusCode::OK,
        None,
        &service.regenerate_recovery_codes(&ctx).await?,
    )
}

// ---------------------------------------------------------------------------------------
// Personal tokens
// ---------------------------------------------------------------------------------------

/// Lists the personal tokens of the current user, without their secrets. The list is small
/// and not paginated: `next_cursor` is always `null`.
#[utoipa::path(
    get,
    path = "/auth/tokens",
    tag = "auth",
    operation_id = "list_tokens",
    summary = "List the personal API tokens of the current user",
    responses(
        (status = 200, description = "Every token of the user", body = Page<TokenInfo>),
        Unauthenticated,
        Unavailable
    )
)]
async fn list_tokens(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<TokenInfo>>, RouteError> {
    Ok(page(&app, service.list_tokens(&ctx).await?))
}

/// Creates a personal token for scripts and the command line, or with `grants` or
/// `scopes` a scoped token (IAM-10) that acts with the intersection of its grants and the
/// owner's. The secret is shown once; its expiry is capped by TGL-05. Only an interactive
/// session that meets the profile can create one.
#[utoipa::path(
    post,
    path = "/auth/tokens",
    tag = "auth",
    operation_id = "create_token",
    summary = "Create a personal or scoped API token, shown once",
    request_body = TokenRequest,
    responses(
        (status = 201, description = "The token: its secret (`tnk_...`, shown once) and its metadata", body = CreatedToken),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the name or lifetime is invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The session is not strong enough (`auth.step_up_required`) is the break-glass session (`auth.break_glass.hardware_key_only`), or a grant of a scoped token goes beyond the owner's (`auth.grant.exceeds_own`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The lifetime exceeds the maximum of the profile (`auth.token.lifetime_exceeded`), a grant names a global-only role (`auth.grant.invalid_role`) or a scope that cannot be granted or does not exist (`auth.grant.invalid_scope`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn create_token(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<TokenRequest>,
) -> Result<Response, RouteError> {
    secret_json(
        StatusCode::CREATED,
        None,
        &service.create_token_with(&ctx, &request).await?,
    )
}

/// Revokes a personal token: the owner's own, or anybody's for an administrator.
#[utoipa::path(
    delete,
    path = "/auth/tokens/{id}",
    tag = "auth",
    operation_id = "revoke_token",
    summary = "Revoke one personal API token",
    params(("id" = String, Path, description = "Token identifier")),
    responses(
        (status = 204, description = "The token was revoked"),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such token (`auth.token.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    )
)]
async fn revoke_token(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError> {
    let id = id.parse::<ApiTokenId>()?;
    service.revoke_token(&ctx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Test support shared by the tests of the four route files of WP1.2.
#[cfg(test)]
pub(crate) mod testkit {
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode, header},
        response::Response,
    };
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use tenko_auth::{
        service::{
            WebAuthnLoginFinish, WebAuthnLoginOptions, WebAuthnRegisterFinish,
            WebAuthnRegisterOptions,
        },
        settings::Profile,
        testing::{SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv, env::ORIGIN},
    };
    use tenko_core::{Authenticator, Timestamp, audit::AuditDraft};
    use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, tables};
    use tower::ServiceExt;

    use crate::{API_BASE, problem::PROBLEM_JSON, state::AppState};

    use std::sync::Arc;

    /// How a request authenticates.
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum Credential<'a> {
        /// No credentials.
        Anonymous,
        /// The `tenko_session` cookie with this secret.
        Cookie(&'a str),
        /// `Authorization: Bearer` with this token.
        Bearer(&'a str),
    }

    /// A request to the API. `path` is relative to the API base.
    pub(crate) fn request(
        method: &str,
        path: &str,
        credential: Credential<'_>,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
        builder = match credential {
            Credential::Anonymous => builder,
            Credential::Cookie(secret) => {
                builder.header(header::COOKIE, format!("tenko_session={secret}"))
            }
            Credential::Bearer(token) => {
                builder.header(header::AUTHORIZATION, format!("Bearer {token}"))
            }
        };
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("a valid request")
    }

    /// A response, decoded.
    #[derive(Debug)]
    pub(crate) struct Reply {
        /// The status.
        pub(crate) status: StatusCode,
        /// The headers.
        pub(crate) headers: HeaderMap,
        /// The JSON body; `null` when there is none.
        pub(crate) body: Value,
        /// The body as text (lossy), for answers that are not JSON.
        pub(crate) text: String,
    }

    impl Reply {
        /// Reads a response.
        pub(crate) async fn read(response: Response) -> Self {
            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, usize::MAX).await.expect("a readable body");
            Self {
                status: parts.status,
                headers: parts.headers,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                text: String::from_utf8_lossy(&bytes).into_owned(),
            }
        }

        /// The first value of a header.
        pub(crate) fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).and_then(|value| value.to_str().ok())
        }

        /// Every `Set-Cookie` value.
        pub(crate) fn set_cookies(&self) -> Vec<&str> {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect()
        }

        /// The secret of the session cookie that the response sets.
        pub(crate) fn session_secret(&self) -> String {
            let cookies = self.set_cookies();
            let cookie = cookies
                .iter()
                .find_map(|cookie| cookie.strip_prefix("tenko_session="))
                .expect("a session cookie is set");
            cookie.split(';').next().expect("a cookie value").to_owned()
        }

        /// Asserts the status.
        #[track_caller]
        pub(crate) fn assert_status(&self, status: u16) -> &Self {
            assert_eq!(self.status.as_u16(), status, "body: {}", self.body);
            self
        }

        /// Asserts a problem-details answer with the given status and code.
        #[track_caller]
        pub(crate) fn assert_problem(&self, status: u16, code: &str) -> &Self {
            self.assert_status(status);
            assert_eq!(self.header("content-type"), Some(PROBLEM_JSON));
            assert_eq!(self.body["code"], code, "body: {}", self.body);
            assert_eq!(self.body["status"], status);
            self
        }

        /// The body as a type.
        pub(crate) fn parse<T: DeserializeOwned>(&self) -> T {
            serde_json::from_value(self.body.clone()).expect("a body of the expected type")
        }
    }

    /// The API over a `TestEnv`, with the service as a router extension.
    pub(crate) struct Harness {
        /// The environment (store, clock, service).
        pub(crate) env: TestEnv,
        router: Router,
    }

    impl Harness {
        fn over(env: TestEnv) -> Self {
            Self::wired(env, |state| crate::api(state).0)
        }

        /// A harness over `env` whose router `build` makes from the state of the service
        /// (authentication and authorization set); the service is added as an extension.
        pub(crate) fn wired(env: TestEnv, build: impl FnOnce(AppState) -> Router) -> Self {
            let authenticator: Arc<dyn Authenticator> = env.service.clone();
            let mut state = AppState::new(env.store.clone());
            state.auth = Some(authenticator);
            state.authorizer = Some(env.service.authorizer());
            let router = build(state).layer(Extension(env.service.clone()));
            Self { env, router }
        }

        /// An installation before setup. The mock clock stands at the real time: the API
        /// stamps requests with the real time, so sessions made on the mock clock would age
        /// out of the test.
        pub(crate) async fn fresh() -> Self {
            let env = TestEnv::new().await;
            env.clock.set(Timestamp::now());
            Self::over(env)
        }

        /// An installation set up under the Home profile (PIN preset, no MFA requirement)
        /// and the secret of the administrator's session.
        pub(crate) async fn installed() -> (Self, String) {
            let harness = Self::fresh().await;
            let session = harness
                .env
                .setup(Profile::Home)
                .await
                .expect("setup succeeds");
            let secret = session.secret.expose().to_owned();
            (harness, secret)
        }

        /// The router, for answers that stream.
        pub(crate) fn router(&self) -> Router {
            self.router.clone()
        }

        /// Sends a request.
        pub(crate) async fn send(&self, request: Request<Body>) -> Reply {
            send_to(self.router.clone(), request).await
        }

        /// Calls an endpoint.
        pub(crate) async fn call(
            &self,
            method: &str,
            path: &str,
            credential: Credential<'_>,
            body: Option<&Value>,
        ) -> Reply {
            self.call_with(method, path, credential, body, &[]).await
        }

        /// Calls an endpoint with extra headers.
        pub(crate) async fn call_with(
            &self,
            method: &str,
            path: &str,
            credential: Credential<'_>,
            body: Option<&Value>,
            headers: &[(&str, &str)],
        ) -> Reply {
            self.send(request(method, path, credential, body, headers))
                .await
        }

        /// Logs in through the API and returns the secret of the new session.
        pub(crate) async fn login(&self, name: &str, password: &str) -> String {
            let reply = self
                .call(
                    "POST",
                    "/auth/login/password",
                    Credential::Anonymous,
                    Some(&json!({ "user_name": name, "password": password })),
                )
                .await;
            reply.assert_status(200);
            assert_eq!(reply.body["status"], "authenticated", "{}", reply.body);
            reply.session_secret()
        }

        /// Creates a user as `admin` and returns the answer (`UserInfo`). The user starts
        /// with the password it was given, as if it had changed the one the administrator
        /// set (every route but the password change refuses an account that must change it).
        pub(crate) async fn create_user(
            &self,
            admin: &str,
            name: &str,
            pin: &str,
            roles: &[&str],
        ) -> Value {
            let reply = self
                .call(
                    "POST",
                    "/users",
                    Credential::Cookie(admin),
                    Some(&json!({ "name": name, "password": pin, "roles": roles })),
                )
                .await;
            reply.assert_status(201);
            let id: tenko_core::UserId =
                serde_json::from_value(reply.body["id"].clone()).expect("an id");
            self.env.accept_password(id).await;
            let current = self
                .call(
                    "GET",
                    &format!("/users/{id}"),
                    Credential::Cookie(admin),
                    None,
                )
                .await;
            current.assert_status(200);
            current.body
        }

        /// Registers a software passkey for the user of the session `cookie` and logs `name`
        /// in with it: returns the secret of the new session, whose strength is `passkey`.
        pub(crate) async fn passkey_session(&self, cookie: &str, name: &str) -> String {
            let mut authenticator =
                SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
            let start = self
                .call(
                    "POST",
                    "/auth/webauthn/register/start",
                    Credential::Cookie(cookie),
                    None,
                )
                .await;
            start.assert_status(200);
            let options: WebAuthnRegisterOptions = start.parse();
            let credential = authenticator.register(&options.public_key, ORIGIN);
            let finish = serde_json::to_value(WebAuthnRegisterFinish {
                ceremony_id: options.ceremony_id,
                credential,
            })
            .expect("json");
            self.call(
                "POST",
                "/auth/webauthn/register/finish",
                Credential::Cookie(cookie),
                Some(&finish),
            )
            .await
            .assert_status(200);

            let start = self
                .call(
                    "POST",
                    "/auth/webauthn/login/start",
                    Credential::Anonymous,
                    Some(&json!({ "user_name": name })),
                )
                .await;
            start.assert_status(200);
            let options: WebAuthnLoginOptions = start.parse();
            let finish = serde_json::to_value(WebAuthnLoginFinish {
                ceremony_id: options.ceremony_id,
                credential: authenticator.assert(&options.public_key, ORIGIN),
            })
            .expect("json");
            let login = self
                .call(
                    "POST",
                    "/auth/webauthn/login/finish",
                    Credential::Anonymous,
                    Some(&finish),
                )
                .await;
            login.assert_status(200);
            assert_eq!(login.body["session"]["strength"], "passkey");
            login.session_secret()
        }

        /// Fails logins of `name` until the service refuses with 429, and returns that
        /// answer.
        pub(crate) async fn fail_logins_until_throttled(&self, name: &str) -> Reply {
            for _ in 0..12 {
                let reply = self
                    .call(
                        "POST",
                        "/auth/login/password",
                        Credential::Anonymous,
                        Some(&json!({ "user_name": name, "password": "9999" })),
                    )
                    .await;
                if reply.status == StatusCode::TOO_MANY_REQUESTS {
                    return reply;
                }
                reply.assert_problem(401, "auth.invalid_credentials");
            }
            panic!("twelve failed logins were not throttled");
        }

        /// Every audit record, oldest first.
        pub(crate) async fn audit(&self) -> Vec<AuditDraft> {
            let view = self
                .env
                .store
                .read(ReadConsistency::Local)
                .await
                .expect("a read view");
            view.scan_typed(&tables::AUDIT, KeyRange::all(), 10_000, false)
                .expect("the audit table")
                .into_iter()
                .map(|(_, record, _)| record.draft)
                .collect()
        }

        /// The actions of the audit records, oldest first.
        pub(crate) async fn audit_actions(&self) -> Vec<String> {
            self.audit()
                .await
                .into_iter()
                .map(|draft| draft.action.as_str().to_owned())
                .collect()
        }
    }

    /// Sends a request to a router.
    pub(crate) async fn send_to(router: Router, request: Request<Body>) -> Reply {
        Reply::read(router.oneshot(request).await.expect("the router answers")).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::{body::Body, http::Request};
    use serde_json::{Value, json};
    use tenko_auth::{
        encoding::base32_decode,
        service::{
            SessionSummary, WebAuthnLoginFinish, WebAuthnLoginOptions, WebAuthnRegisterFinish,
            WebAuthnRegisterOptions,
        },
        settings::Profile,
        testing::{
            SoftAttestation, SoftAuthenticator, SoftKeyAlg,
            env::{ADMIN, ADMIN_PIN, ORIGIN},
        },
        totp::{self, TotpParams},
    };

    use crate::API_BASE;

    use super::{
        testkit::{Credential::*, Harness, request, send_to},
        *,
    };

    const SOME_ID: &str = "0190d1c2-0000-7000-8000-000000000001";

    fn headers_with(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                header::IF_MATCH,
                HeaderValue::from_str(value).expect("a header value"),
            );
        }
        headers
    }

    fn seconds_now() -> u64 {
        u64::try_from(Timestamp::now().0.unix_timestamp()).expect("a time after the epoch")
    }

    #[test]
    fn if_match_accepts_quoted_weak_bare_and_wildcard_values() {
        for (value, expected) in [
            ("\"12\"", Some(Revision(12))),
            ("12", Some(Revision(12))),
            ("W/\"12\"", Some(Revision(12))),
            ("  \"7\" ", Some(Revision(7))),
            ("\"0\"", Some(Revision(0))),
            ("*", None),
        ] {
            assert_eq!(if_match(&headers_with(&[value])).expect(value), expected);
        }
        assert_eq!(if_match(&HeaderMap::new()).expect("absent"), None);
    }

    #[test]
    fn if_match_refuses_what_is_not_a_revision() {
        for value in [
            "\"abc\"",
            "\"12",
            "12\"",
            "\"\"",
            "",
            "W/12x",
            "-3",
            "+3",
            "\"1\", \"2\"",
            "1 2",
            "99999999999999999999999",
        ] {
            let error = if_match(&headers_with(&[value])).expect_err(value);
            assert_eq!(error.coded_error().code, "sys.invalid_value", "{value}");
            assert_eq!(error.status(), 400, "{value}");
        }
        let two = if_match(&headers_with(&["\"1\"", "\"2\""])).expect_err("two headers");
        assert_eq!(two.coded_error().code, "sys.invalid_value");
    }

    #[test]
    fn a_throttled_answer_carries_retry_after() {
        let response = RouteError::from(AuthError::Throttled {
            retry_after: Some(7),
        })
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );

        // Locked until an administrator unlocks: there is no time to wait for.
        let locked = RouteError::from(AuthError::Throttled { retry_after: None }).into_response();
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(locked.headers().get(header::RETRY_AFTER).is_none());

        let conflict = RouteError::from(AuthError::Conflict).into_response();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(conflict.headers().get(header::RETRY_AFTER).is_none());

        let plain = RouteError::from(ApiError::new("sys.internal", 500, "x")).into_response();
        assert_eq!(plain.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn the_public_context_carries_request_id_address_and_a_cut_user_agent() {
        let request = Request::builder()
            .header(header::USER_AGENT, "x".repeat(300))
            .body(Body::empty())
            .expect("request");
        let (mut parts, _) = request.into_parts();
        let id = RequestId::generate();
        parts.extensions.insert(id);
        parts.extensions.insert(ClientInfo {
            source_ip: Some("198.51.100.7".parse().expect("ip")),
            ..ClientInfo::default()
        });
        let before = Timestamp::now();
        let PublicCtx { ctx, user_agent } = PublicCtx::from_request_parts(&mut parts, &())
            .await
            .expect("infallible");
        assert_eq!(ctx.request, id);
        assert_eq!(ctx.source_ip, Some("198.51.100.7".parse().expect("ip")));
        assert!(ctx.now >= before);
        assert_eq!(
            ctx.principal,
            tenko_core::Principal::System {
                component: SystemComponent::Api,
                on_behalf_of: None
            }
        );
        assert_eq!(user_agent.as_deref().map(str::len), Some(200));

        // Without extensions and headers the context still builds.
        let (mut bare, _) = Request::new(Body::empty()).into_parts();
        let PublicCtx { ctx, user_agent } = PublicCtx::from_request_parts(&mut bare, &())
            .await
            .expect("infallible");
        assert_eq!(ctx.source_ip, None);
        assert_eq!(user_agent, None);
    }

    #[tokio::test]
    async fn without_the_service_every_endpoint_of_the_areas_answers_503() {
        let document = crate::openapi();
        let areas = ["setup", "auth", "users", "settings"];
        let mut checked = 0;
        for (path, item) in &document.paths.paths {
            let operations = [
                ("GET", &item.get),
                ("PUT", &item.put),
                ("POST", &item.post),
                ("DELETE", &item.delete),
                ("PATCH", &item.patch),
            ];
            for (method, operation) in operations {
                let Some(operation) = operation else { continue };
                let tags = operation.tags.as_deref().unwrap_or_default();
                if !tags.iter().any(|tag| areas.contains(&tag.as_str())) {
                    continue;
                }
                let relative = path.strip_prefix(API_BASE).expect("under the API base");
                let relative = relative.replace("{id}", SOME_ID);
                let reply = send_to(
                    crate::router(),
                    request(method, &relative, Anonymous, None, &[]),
                )
                .await;
                assert_eq!(
                    reply.status.as_u16(),
                    503,
                    "{method} {path}: {}",
                    reply.body
                );
                assert_eq!(reply.body["code"], "auth.unavailable", "{method} {path}");
                assert_eq!(
                    reply.header("content-type"),
                    Some("application/problem+json"),
                    "{method} {path}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 40, "every endpoint of the four areas");
    }

    #[tokio::test]
    async fn bad_bodies_are_problem_details_that_do_not_repeat_the_body() {
        let (harness, _) = Harness::installed().await;
        let login = |body: Body, content_type: Option<&str>| {
            let mut builder = Request::builder()
                .method("POST")
                .uri(format!("{API_BASE}/auth/login/password"));
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            builder.body(body).expect("request")
        };

        let reply = harness
            .send(login(Body::from("{ not json"), Some("application/json")))
            .await;
        reply.assert_problem(400, "sys.invalid_request");

        let reply = harness
            .send(login(Body::from(""), Some("application/json")))
            .await;
        reply.assert_problem(400, "sys.invalid_request");

        let reply = harness
            .send(login(Body::from("{}"), Some("text/plain")))
            .await;
        reply.assert_problem(415, "sys.invalid_request");
        let reply = harness.send(login(Body::from("{}"), None)).await;
        reply.assert_problem(415, "sys.invalid_request");

        // A JSON media type with parameters and `+json` types are accepted.
        let reply = harness
            .send(login(
                Body::from(json!({ "user_name": ADMIN, "password": "0000" }).to_string()),
                Some("application/json; charset=utf-8"),
            ))
            .await;
        reply.assert_problem(401, "auth.invalid_credentials");

        // A missing field is named.
        let reply = harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": ADMIN })),
            )
            .await;
        reply.assert_problem(400, "sys.invalid_request");
        assert_eq!(reply.body["params"]["field"], "password");
        assert_eq!(reply.body["errors"][0]["field"], "password");

        // A value of the wrong type is refused without repeating it.
        let reply = harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": ADMIN, "password": 4_812_731 })),
            )
            .await;
        reply.assert_problem(400, "sys.invalid_request");
        assert!(
            !reply.body.to_string().contains("4812731"),
            "{}",
            reply.body
        );

        // A body over the limit.
        let big = login(
            Body::from(vec![b' '; 3 * 1024 * 1024]),
            Some("application/json"),
        );
        harness
            .send(big)
            .await
            .assert_problem(413, "sys.body_too_large");
    }

    #[tokio::test]
    async fn password_login_sets_a_secure_session_cookie() {
        let (harness, _) = Harness::installed().await;
        let reply = harness
            .call_with(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": ADMIN, "password": ADMIN_PIN })),
                &[("User-Agent", "route-test/1.0")],
            )
            .await;
        reply.assert_status(200);
        assert_eq!(reply.body["status"], "authenticated");
        assert_eq!(reply.body["session"]["user"]["name"], ADMIN);
        assert_eq!(reply.body["session"]["strength"], "pin");
        assert_eq!(reply.body["session"]["profile"], "home");
        assert_eq!(reply.header("cache-control"), Some("no-store"));
        let cookies = reply.set_cookies();
        assert_eq!(cookies.len(), 1);
        let cookie = cookies[0];
        assert!(cookie.starts_with("tenko_session="), "{cookie}");
        for attribute in [
            "HttpOnly",
            "SameSite=Strict",
            "Secure",
            "Path=/",
            "Max-Age=",
        ] {
            assert!(cookie.contains(attribute), "{attribute} in {cookie}");
        }
        // The secret is not in the body, and the cookie works.
        let secret = reply.session_secret();
        assert!(!reply.body.to_string().contains(&secret));
        let session = harness
            .call("GET", "/auth/session", Cookie(&secret), None)
            .await;
        session.assert_status(200);
        assert_eq!(session.body["user"]["name"], ADMIN);

        // The session record carries the client address and the user agent.
        let list = harness
            .call("GET", "/auth/sessions", Cookie(&secret), None)
            .await;
        let sessions: Vec<SessionSummary> =
            serde_json::from_value(list.body["items"].clone()).expect("session summaries");
        assert!(
            sessions
                .iter()
                .any(|session| session.user_agent.as_deref() == Some("route-test/1.0"))
        );
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.login.password".to_owned())
        );
    }

    #[tokio::test]
    async fn a_wrong_password_and_an_unknown_user_are_refused_alike() {
        let (harness, _) = Harness::installed().await;
        let wrong = harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": ADMIN, "password": "0000" })),
            )
            .await;
        wrong.assert_problem(401, "auth.invalid_credentials");
        assert_eq!(wrong.set_cookies().len(), 0);
        let unknown = harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": "nobody", "password": "0000" })),
            )
            .await;
        unknown.assert_problem(401, "auth.invalid_credentials");
        assert_eq!(wrong.body["detail"], unknown.body["detail"]);
        assert_eq!(wrong.body["title"], "Login failed");
    }

    #[tokio::test]
    async fn repeated_failures_are_throttled_with_retry_after() {
        let (harness, _) = Harness::installed().await;
        let reply = harness.fail_logins_until_throttled(ADMIN).await;
        reply.assert_problem(429, "auth.throttled");
        // Even the right PIN is refused while throttled, without a hint that it is right.
        let right = harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": ADMIN, "password": ADMIN_PIN })),
            )
            .await;
        right.assert_problem(429, "auth.throttled");
        let retry = right.body["params"]["retry_after"]
            .as_str()
            .expect("the wait in seconds");
        assert_eq!(right.header("retry-after"), Some(retry));
    }

    #[tokio::test]
    async fn the_session_endpoint_needs_a_valid_session() {
        let (harness, admin) = Harness::installed().await;
        let reply = harness
            .call("GET", "/auth/session", Cookie(&admin), None)
            .await;
        reply.assert_status(200);
        assert_eq!(reply.body["user"]["name"], ADMIN);
        assert_eq!(reply.body["roles"], json!(["admin"]));
        assert_eq!(reply.body["strength"], "pin");
        assert_eq!(reply.body["flags"]["break_glass"], false);
        assert!(reply.body["session_id"].is_string());
        assert!(reply.body["expires_at"].is_string());

        harness
            .call("GET", "/auth/session", Anonymous, None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call("GET", "/auth/session", Cookie("not-a-session"), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call("GET", "/auth/session", Bearer("tnk_unknown"), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
    }

    #[tokio::test]
    async fn logout_removes_the_cookie_and_ends_the_session() {
        let (harness, admin) = Harness::installed().await;
        let second = harness.login(ADMIN, ADMIN_PIN).await;
        let reply = harness
            .call("POST", "/auth/logout", Cookie(&second), None)
            .await;
        reply.assert_status(204);
        let cookies = reply.set_cookies();
        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].starts_with("tenko_session=;"), "{}", cookies[0]);
        assert!(cookies[0].contains("Max-Age=0"));
        assert!(cookies[0].contains("HttpOnly"));
        // The old cookie is refused; the other session is not affected.
        harness
            .call("GET", "/auth/session", Cookie(&second), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call("GET", "/auth/session", Cookie(&admin), None)
            .await
            .assert_status(200);
        // Logging out needs a session.
        harness
            .call("POST", "/auth/logout", Anonymous, None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.logout".to_owned())
        );
    }

    #[tokio::test]
    async fn sessions_are_listed_and_can_be_revoked() {
        let (harness, first) = Harness::installed().await;
        let second = harness.login(ADMIN, ADMIN_PIN).await;
        let list = harness
            .call("GET", "/auth/sessions", Cookie(&second), None)
            .await;
        list.assert_status(200);
        assert_eq!(list.body["next_cursor"], Value::Null);
        assert!(list.body["revision"].is_u64());
        let items = list.body["items"].as_array().expect("items");
        assert_eq!(items.len(), 2);
        let current: Vec<&Value> = items
            .iter()
            .filter(|item| item["current"] == true)
            .collect();
        assert_eq!(current.len(), 1);
        let other = items
            .iter()
            .find(|item| item["current"] == false)
            .expect("the other session");
        let other_id = other["id"].as_str().expect("an id").to_owned();

        harness
            .call(
                "DELETE",
                &format!("/auth/sessions/{other_id}"),
                Cookie(&second),
                None,
            )
            .await
            .assert_status(204);
        harness
            .call("GET", "/auth/session", Cookie(&first), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        let list = harness
            .call("GET", "/auth/sessions", Cookie(&second), None)
            .await;
        assert_eq!(list.body["items"].as_array().expect("items").len(), 1);

        // Unknown and malformed identifiers.
        harness
            .call(
                "DELETE",
                &format!("/auth/sessions/{SOME_ID}"),
                Cookie(&second),
                None,
            )
            .await
            .assert_problem(404, "auth.session.not_found");
        harness
            .call("DELETE", "/auth/sessions/not-a-uuid", Cookie(&second), None)
            .await
            .assert_problem(400, "sys.invalid_value");
        harness
            .call("GET", "/auth/sessions", Anonymous, None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.session.revoke".to_owned())
        );
    }

    #[tokio::test]
    async fn personal_tokens_are_shown_once_and_work_as_bearer_credentials() {
        let (harness, admin) = Harness::installed().await;
        let created = harness
            .call(
                "POST",
                "/auth/tokens",
                Cookie(&admin),
                Some(&json!({ "name": "ci", "expires_in_days": 30 })),
            )
            .await;
        created.assert_status(201);
        assert_eq!(created.header("cache-control"), Some("no-store"));
        let token = created.body["token"]
            .as_str()
            .expect("the token")
            .to_owned();
        assert!(token.starts_with("tnk_"), "{token}");
        assert_eq!(created.body["info"]["name"], "ci");
        assert!(created.body["info"]["expires_at"].is_string());
        let id = created.body["info"]["id"]
            .as_str()
            .expect("an id")
            .to_owned();
        assert!(token.starts_with(created.body["info"]["prefix"].as_str().expect("prefix")));

        // The list shows the token without its secret, to its owner and to the token itself.
        for credential in [Cookie(admin.as_str()), Bearer(token.as_str())] {
            let list = harness.call("GET", "/auth/tokens", credential, None).await;
            list.assert_status(200);
            assert_eq!(list.body["next_cursor"], Value::Null);
            assert_eq!(list.body["items"].as_array().expect("items").len(), 1);
            assert_eq!(list.body["items"][0]["id"], id.as_str());
            assert!(!list.body.to_string().contains(&token));
        }
        // A token is a principal for reading, but it has no session: whatever acts on the
        // session, mints tokens or changes factors needs the interactive login.
        harness
            .call("GET", "/auth/sessions", Bearer(&token), None)
            .await
            .assert_status(200);
        for (method, path, body) in [
            ("GET", "/auth/session", None),
            ("POST", "/auth/logout", None),
            ("POST", "/auth/tokens", Some(json!({ "name": "again" }))),
            ("POST", "/auth/totp/enroll/start", None),
            ("POST", "/auth/recovery-codes", None),
        ] {
            harness
                .call(method, path, Bearer(&token), body.as_ref())
                .await
                .assert_problem(401, "auth.unauthenticated");
        }

        harness
            .call(
                "DELETE",
                &format!("/auth/tokens/{id}"),
                Cookie(&admin),
                None,
            )
            .await
            .assert_status(204);
        harness
            .call("GET", "/auth/tokens", Bearer(&token), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call(
                "DELETE",
                &format!("/auth/tokens/{id}"),
                Cookie(&admin),
                None,
            )
            .await
            .assert_problem(404, "auth.token.not_found");
        harness
            .call("DELETE", "/auth/tokens/nope", Cookie(&admin), None)
            .await
            .assert_problem(400, "sys.invalid_value");
        let actions = harness.audit_actions().await;
        assert!(actions.contains(&"auth.token.create".to_owned()));
        assert!(actions.contains(&"auth.token.revoke".to_owned()));
    }

    #[tokio::test]
    async fn token_requests_are_checked_against_the_profile() {
        let (harness, admin) = Harness::installed().await;
        // Home allows 365 days at most.
        harness
            .call(
                "POST",
                "/auth/tokens",
                Cookie(&admin),
                Some(&json!({ "name": "long", "expires_in_days": 400 })),
            )
            .await
            .assert_problem(422, "auth.token.lifetime_exceeded");
        harness
            .call(
                "POST",
                "/auth/tokens",
                Cookie(&admin),
                Some(&json!({ "name": "none", "expires_in_days": 0 })),
            )
            .await
            .assert_problem(400, "auth.invalid_request");
        harness
            .call(
                "POST",
                "/auth/tokens",
                Anonymous,
                Some(&json!({ "name": "anon" })),
            )
            .await
            .assert_problem(401, "auth.unauthenticated");
        // The default lifetime is the profile maximum.
        let created = harness
            .call(
                "POST",
                "/auth/tokens",
                Cookie(&admin),
                Some(&json!({ "name": "d" })),
            )
            .await;
        created.assert_status(201);
        assert!(created.body["info"]["expires_at"].is_string());
    }

    #[tokio::test]
    async fn the_password_is_changed_and_other_sessions_end() {
        let (harness, admin) = Harness::installed().await;
        let other = harness.login(ADMIN, ADMIN_PIN).await;

        harness
            .call(
                "POST",
                "/auth/password",
                Cookie(&admin),
                Some(&json!({ "current_password": "0000", "new_password": "5936" })),
            )
            .await
            .assert_problem(403, "auth.password.incorrect");
        let weak = harness
            .call(
                "POST",
                "/auth/password",
                Cookie(&admin),
                Some(&json!({ "current_password": ADMIN_PIN, "new_password": "abcd" })),
            )
            .await;
        weak.assert_problem(422, "auth.password.policy");
        assert_eq!(weak.body["errors"][0]["field"], "password");

        let changed = harness
            .call(
                "POST",
                "/auth/password",
                Cookie(&admin),
                Some(&json!({ "current_password": ADMIN_PIN, "new_password": "5936" })),
            )
            .await;
        changed.assert_status(200);
        assert_eq!(changed.body["sessions_revoked"], 1);
        assert!(changed.body["breach_check"].is_string());

        harness
            .call("GET", "/auth/session", Cookie(&other), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call("GET", "/auth/session", Cookie(&admin), None)
            .await
            .assert_status(200);
        harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": ADMIN, "password": ADMIN_PIN })),
            )
            .await
            .assert_problem(401, "auth.invalid_credentials");
        harness.login(ADMIN, "5936").await;
        harness
            .call(
                "POST",
                "/auth/password",
                Anonymous,
                Some(&json!({ "new_password": "5936" })),
            )
            .await
            .assert_problem(401, "auth.unauthenticated");
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.password.change".to_owned())
        );
    }

    #[tokio::test]
    async fn the_password_check_is_public_only_while_setup_is_open() {
        let harness = Harness::fresh().await;
        let check = |password: &str| json!({ "password": password, "profile": "home" });
        let open = harness
            .call(
                "POST",
                "/auth/password/check",
                Anonymous,
                Some(&check("4812")),
            )
            .await;
        open.assert_status(200);
        assert_eq!(open.body["acceptable"], true);
        assert_eq!(open.body["policy"]["preset"], "pin");
        let weak = harness
            .call(
                "POST",
                "/auth/password/check",
                Anonymous,
                Some(&check("abcd")),
            )
            .await;
        weak.assert_status(200);
        assert_eq!(weak.body["acceptable"], false);
        assert_ne!(
            weak.body["violations"]
                .as_array()
                .expect("violations")
                .len(),
            0
        );

        let admin = harness
            .env
            .setup(Profile::Home)
            .await
            .expect("setup")
            .secret
            .expose()
            .to_owned();
        harness
            .call(
                "POST",
                "/auth/password/check",
                Anonymous,
                Some(&check("4812")),
            )
            .await
            .assert_problem(401, "auth.unauthenticated");
        let session = harness
            .call(
                "POST",
                "/auth/password/check",
                Cookie(&admin),
                Some(&check("4812")),
            )
            .await;
        session.assert_status(200);
        assert_eq!(session.body["acceptable"], true);
        // The caller's own settings apply now, whatever the body says.
        assert_eq!(session.body["policy"]["preset"], "pin");
        harness
            .call(
                "POST",
                "/auth/password/check",
                Cookie("expired-or-wrong"),
                Some(&check("4812")),
            )
            .await
            .assert_problem(401, "auth.unauthenticated");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One flow from enrolment to removal.
    async fn totp_is_enrolled_asked_for_at_login_and_removed() {
        let (harness, admin) = Harness::installed().await;
        let start = harness
            .call("POST", "/auth/totp/enroll/start", Cookie(&admin), None)
            .await;
        start.assert_status(200);
        assert_eq!(start.header("cache-control"), Some("no-store"));
        assert!(
            start.body["otpauth_uri"]
                .as_str()
                .expect("uri")
                .starts_with("otpauth://totp/")
        );
        let seed = base32_decode(start.body["secret"].as_str().expect("the seed")).expect("base32");
        assert_eq!(start.body["params"]["digits"], 6);
        let enrolment_id = start.body["enrolment_id"].as_str().expect("id").to_owned();

        // A wrong code does not enrol.
        harness
            .call(
                "POST",
                "/auth/totp/enroll/finish",
                Cookie(&admin),
                Some(&json!({ "enrolment_id": enrolment_id, "code": "00000" })),
            )
            .await
            .assert_problem(422, "auth.totp.code_mismatch");
        // An unknown enrolment is refused.
        harness
            .call(
                "POST",
                "/auth/totp/enroll/finish",
                Cookie(&admin),
                Some(&json!({ "enrolment_id": "unknown", "code": "123456" })),
            )
            .await
            .assert_problem(400, "auth.challenge_invalid");

        let start = harness
            .call("POST", "/auth/totp/enroll/start", Cookie(&admin), None)
            .await;
        let seed_again =
            base32_decode(start.body["secret"].as_str().expect("the seed")).expect("base32");
        assert_ne!(seed, seed_again, "every enrolment has its own seed");
        let params = TotpParams::default();
        let code = totp::code_at(&seed_again, &params, seconds_now());
        let finish = harness
            .call(
                "POST",
                "/auth/totp/enroll/finish",
                Cookie(&admin),
                Some(&json!({
                    "enrolment_id": start.body["enrolment_id"],
                    "code": code.as_str()
                })),
            )
            .await;
        finish.assert_status(200);
        assert_eq!(finish.header("cache-control"), Some("no-store"));
        let recovery = finish.body["recovery_codes"]
            .as_array()
            .expect("recovery codes");
        assert_eq!(recovery.len(), 10);
        let first_recovery = recovery[0].as_str().expect("a code").to_owned();
        harness
            .call("POST", "/auth/totp/enroll/start", Cookie(&admin), None)
            .await
            .assert_problem(409, "auth.totp.already_enrolled");

        // The password step now asks for the second factor and sets no cookie.
        let password = json!({ "user_name": ADMIN, "password": ADMIN_PIN });
        let step = harness
            .call("POST", "/auth/login/password", Anonymous, Some(&password))
            .await;
        step.assert_status(200);
        assert_eq!(step.body["status"], "second_factor");
        assert_eq!(step.set_cookies().len(), 0);
        assert_eq!(step.header("cache-control"), Some("no-store"));
        assert_eq!(step.body["methods"], json!(["totp", "recovery"]));
        assert!(step.body["expires_in"].is_u64());
        let challenge = step.body["challenge_id"]
            .as_str()
            .expect("a challenge")
            .to_owned();

        // A wrong code is refused, the right code of the next step completes the login.
        harness
            .call(
                "POST",
                "/auth/login/totp",
                Anonymous,
                Some(&json!({ "challenge_id": challenge, "code": "000000" })),
            )
            .await
            .assert_problem(401, "auth.invalid_credentials");
        let next = totp::code_at(&seed_again, &params, seconds_now() + params.period);
        let done = harness
            .call(
                "POST",
                "/auth/login/totp",
                Anonymous,
                Some(&json!({ "challenge_id": challenge, "code": next.as_str() })),
            )
            .await;
        done.assert_status(200);
        assert_eq!(done.body["status"], "authenticated");
        assert_eq!(done.body["session"]["strength"], "password_totp");
        let totp_session = done.session_secret();
        // The challenge is single use.
        harness
            .call(
                "POST",
                "/auth/login/totp",
                Anonymous,
                Some(&json!({ "challenge_id": challenge, "code": next.as_str() })),
            )
            .await
            .assert_problem(400, "auth.challenge_invalid");

        // A recovery code completes a login once.
        let step = harness
            .call("POST", "/auth/login/password", Anonymous, Some(&password))
            .await;
        let challenge = step.body["challenge_id"]
            .as_str()
            .expect("a challenge")
            .to_owned();
        let recovered = harness
            .call(
                "POST",
                "/auth/login/recovery",
                Anonymous,
                Some(&json!({ "challenge_id": challenge, "code": first_recovery })),
            )
            .await;
        recovered.assert_status(200);
        assert_eq!(recovered.body["status"], "authenticated");
        assert_eq!(recovered.set_cookies().len(), 1);
        let step = harness
            .call("POST", "/auth/login/password", Anonymous, Some(&password))
            .await;
        let challenge = step.body["challenge_id"]
            .as_str()
            .expect("a challenge")
            .to_owned();
        harness
            .call(
                "POST",
                "/auth/login/recovery",
                Anonymous,
                Some(&json!({ "challenge_id": challenge, "code": first_recovery })),
            )
            .await
            .assert_problem(401, "auth.invalid_credentials");
        harness
            .call(
                "POST",
                "/auth/login/recovery",
                Anonymous,
                Some(&json!({ "challenge_id": "unknown", "code": first_recovery })),
            )
            .await
            .assert_problem(400, "auth.challenge_invalid");

        // TOTP can be removed again with a fresh session; the second factor is gone.
        harness
            .call("DELETE", "/auth/totp", Cookie(&totp_session), None)
            .await
            .assert_status(204);
        harness
            .call("DELETE", "/auth/totp", Cookie(&totp_session), None)
            .await
            .assert_problem(409, "auth.totp.not_enrolled");
        let plain = harness
            .call("POST", "/auth/login/password", Anonymous, Some(&password))
            .await;
        assert_eq!(plain.body["status"], "authenticated");
        let actions = harness.audit_actions().await;
        for action in [
            "auth.totp.enrol",
            "auth.login.totp",
            "auth.login.recovery",
            "auth.totp.remove",
        ] {
            assert!(actions.contains(&action.to_owned()), "{action}");
        }
    }

    #[tokio::test]
    async fn recovery_codes_are_regenerated_once_a_factor_exists() {
        let (harness, admin) = Harness::installed().await;
        // A PIN alone has no recovery codes to regenerate.
        harness
            .call("POST", "/auth/recovery-codes", Cookie(&admin), None)
            .await
            .assert_problem(400, "auth.invalid_request");

        let start = harness
            .call("POST", "/auth/totp/enroll/start", Cookie(&admin), None)
            .await;
        let seed = base32_decode(start.body["secret"].as_str().expect("seed")).expect("base32");
        let code = totp::code_at(&seed, &TotpParams::default(), seconds_now());
        let finish = harness
            .call(
                "POST",
                "/auth/totp/enroll/finish",
                Cookie(&admin),
                Some(&json!({
                    "enrolment_id": start.body["enrolment_id"],
                    "code": code.as_str()
                })),
            )
            .await;
        let old = finish.body["recovery_codes"][0]
            .as_str()
            .expect("a code")
            .to_owned();

        let new = harness
            .call("POST", "/auth/recovery-codes", Cookie(&admin), None)
            .await;
        new.assert_status(200);
        assert_eq!(new.header("cache-control"), Some("no-store"));
        let codes = new.body["codes"].as_array().expect("codes");
        assert_eq!(codes.len(), 10);
        assert!(!codes.iter().any(|code| code.as_str() == Some(old.as_str())));
        harness
            .call("POST", "/auth/recovery-codes", Anonymous, None)
            .await
            .assert_problem(401, "auth.unauthenticated");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One flow from registration to deletion.
    async fn passkeys_register_log_in_and_are_deleted() {
        let (harness, admin) = Harness::installed().await;
        let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);

        // The body of the start step is optional.
        let start = harness
            .call(
                "POST",
                "/auth/webauthn/register/start",
                Cookie(&admin),
                None,
            )
            .await;
        start.assert_status(200);
        let options: WebAuthnRegisterOptions = start.parse();
        let unused = authenticator.register(&options.public_key, ORIGIN);
        // An unknown ceremony is refused.
        harness
            .call(
                "POST",
                "/auth/webauthn/register/finish",
                Cookie(&admin),
                Some(
                    &serde_json::to_value(WebAuthnRegisterFinish {
                        ceremony_id: "unknown".to_owned(),
                        credential: unused,
                    })
                    .expect("json"),
                ),
            )
            .await
            .assert_problem(400, "auth.challenge_invalid");

        let start = harness
            .call(
                "POST",
                "/auth/webauthn/register/start",
                Cookie(&admin),
                Some(&json!({ "label": "Laptop" })),
            )
            .await;
        let options: WebAuthnRegisterOptions = start.parse();
        let credential = authenticator.register(&options.public_key, ORIGIN);
        let finish = harness
            .call(
                "POST",
                "/auth/webauthn/register/finish",
                Cookie(&admin),
                Some(
                    &serde_json::to_value(WebAuthnRegisterFinish {
                        ceremony_id: options.ceremony_id,
                        credential,
                    })
                    .expect("json"),
                ),
            )
            .await;
        finish.assert_status(200);
        assert_eq!(finish.header("cache-control"), Some("no-store"));
        assert_eq!(finish.body["credential"]["label"], "Laptop");
        let credential_id = finish.body["credential"]["id"]
            .as_str()
            .expect("an id")
            .to_owned();

        let list = harness
            .call("GET", "/auth/webauthn/credentials", Cookie(&admin), None)
            .await;
        list.assert_status(200);
        assert_eq!(list.body["next_cursor"], Value::Null);
        assert_eq!(list.body["items"].as_array().expect("items").len(), 1);
        assert_eq!(list.body["items"][0]["id"], credential_id.as_str());
        assert_eq!(list.body["items"][0]["hardware_key"], false);

        // A discoverable login: no body, no user name.
        let start = harness
            .call("POST", "/auth/webauthn/login/start", Anonymous, None)
            .await;
        start.assert_status(200);
        let options: WebAuthnLoginOptions = start.parse();
        let assertion = authenticator.assert(&options.public_key, ORIGIN);
        let finish = |ceremony_id: String, credential| {
            serde_json::to_value(WebAuthnLoginFinish {
                ceremony_id,
                credential,
            })
            .expect("json")
        };
        let login = harness
            .call(
                "POST",
                "/auth/webauthn/login/finish",
                Anonymous,
                Some(&finish(options.ceremony_id.clone(), assertion.clone())),
            )
            .await;
        login.assert_status(200);
        assert_eq!(login.body["status"], "authenticated");
        assert_eq!(login.body["session"]["strength"], "passkey");
        assert_eq!(login.header("cache-control"), Some("no-store"));
        let passkey_session = login.session_secret();
        harness
            .call("GET", "/auth/session", Cookie(&passkey_session), None)
            .await
            .assert_status(200);
        // The ceremony is single use.
        harness
            .call(
                "POST",
                "/auth/webauthn/login/finish",
                Anonymous,
                Some(&finish(options.ceremony_id, assertion)),
            )
            .await
            .assert_problem(400, "auth.challenge_invalid");

        // A login for a named account works the same way.
        let start = harness
            .call(
                "POST",
                "/auth/webauthn/login/start",
                Anonymous,
                Some(&json!({ "user_name": ADMIN })),
            )
            .await;
        let options: WebAuthnLoginOptions = start.parse();
        let assertion = authenticator.assert(&options.public_key, ORIGIN);
        harness
            .call(
                "POST",
                "/auth/webauthn/login/finish",
                Anonymous,
                Some(&finish(options.ceremony_id, assertion)),
            )
            .await
            .assert_status(200);

        // The credential can be deleted by a fresh session; unknown ones are not found.
        harness
            .call(
                "DELETE",
                "/auth/webauthn/credentials/AAAA",
                Cookie(&admin),
                None,
            )
            .await
            .assert_problem(404, "auth.webauthn.credential_not_found");
        harness
            .call(
                "DELETE",
                &format!("/auth/webauthn/credentials/{credential_id}"),
                Cookie(&admin),
                None,
            )
            .await
            .assert_status(204);
        let list = harness
            .call("GET", "/auth/webauthn/credentials", Cookie(&admin), None)
            .await;
        assert_eq!(list.body["items"].as_array().expect("items").len(), 0);
        let actions = harness.audit_actions().await;
        for action in [
            "auth.webauthn.register",
            "auth.login.webauthn",
            "auth.webauthn.remove",
        ] {
            assert!(actions.contains(&action.to_owned()), "{action}");
        }
    }

    /// The refs under `value` that point into `components.schemas`.
    fn schema_refs(value: &Value, found: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    match (key.as_str(), inner.as_str()) {
                        ("$ref", Some(target)) => {
                            let name = target
                                .strip_prefix("#/components/schemas/")
                                .unwrap_or_else(|| panic!("unexpected ref {target}"));
                            found.insert(name.to_owned());
                        }
                        _ => schema_refs(inner, found),
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|item| schema_refs(item, found)),
            _ => {}
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One walk over the document.
    fn the_document_describes_the_endpoints_of_the_areas_completely() {
        let document = serde_json::to_value(crate::openapi()).expect("the document is JSON");
        let areas = ["setup", "auth", "users", "settings"];
        let public = [
            "get_setup",
            "complete_setup",
            "login_password",
            "login_totp",
            "login_recovery",
            "webauthn_login_start",
            "webauthn_login_finish",
        ];
        // What acts on the session, mints tokens or changes users, settings or factors needs an
        // interactive session: a personal token is refused.
        let session_only = [
            "logout",
            "get_session",
            "revoke_session",
            "change_password",
            "totp_enroll_start",
            "totp_enroll_finish",
            "remove_totp",
            "webauthn_register_start",
            "webauthn_register_finish",
            "delete_webauthn_credential",
            "regenerate_recovery_codes",
            "create_token",
            "create_user",
            "update_user",
            "delete_user",
            "unlock_user",
            "revoke_user_sessions",
            "set_user_roles",
            "set_break_glass",
            "update_security_settings",
            "set_default_language",
            "list_preferences",
            "put_preference",
            "delete_preference",
        ];
        let schemas = document["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        let mut refs = BTreeSet::new();
        let mut operations = 0;
        for (path, item) in document["paths"].as_object().expect("paths") {
            for (method, operation) in item.as_object().expect("a path item") {
                let tag = operation["tags"][0].as_str().expect("a tag");
                if !areas.contains(&tag) {
                    continue;
                }
                operations += 1;
                let label = format!("{method} {path}");
                let id = operation["operation_id"]
                    .as_str()
                    .or_else(|| operation["operationId"].as_str())
                    .expect("an operation id");
                assert!(
                    !operation["summary"].as_str().unwrap_or_default().is_empty(),
                    "{label}"
                );
                let responses = operation["responses"].as_object().expect("responses");
                assert!(responses.contains_key("503"), "{label}: 503");
                assert!(
                    responses.keys().any(|status| status.starts_with('2')),
                    "{label}: a success"
                );
                // The operation's own requirement, else the document's.
                let security: Vec<Vec<&str>> = operation
                    .get("security")
                    .unwrap_or(&document["security"])
                    .as_array()
                    .map(|requirements| {
                        requirements
                            .iter()
                            .map(|requirement| {
                                requirement
                                    .as_object()
                                    .expect("a requirement")
                                    .keys()
                                    .map(String::as_str)
                                    .collect()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if public.contains(&id) {
                    assert!(security.is_empty(), "{label}: public");
                } else if session_only.contains(&id) {
                    assert_eq!(security, [vec!["session"]], "{label}: session only");
                    assert!(responses.contains_key("401"), "{label}: 401");
                } else {
                    assert!(security.contains(&vec!["session"]), "{label}: session");
                    assert!(security.contains(&vec!["token"]), "{label}: token");
                    assert!(responses.contains_key("401"), "{label}: 401");
                }
                // Every error response is problem details.
                for (status, response) in responses {
                    if status.starts_with('2') {
                        continue;
                    }
                    assert_eq!(
                        response["content"]["application/problem+json"]["schema"]["$ref"],
                        "#/components/schemas/ProblemDetails",
                        "{label}: {status}"
                    );
                }
                schema_refs(operation, &mut refs);
            }
        }
        assert_eq!(operations, 40);
        // Every schema the operations name exists, and so does everything those name.
        let mut pending: Vec<String> = refs.iter().cloned().collect();
        while let Some(name) = pending.pop() {
            let schema = schemas
                .get(&name)
                .unwrap_or_else(|| panic!("schema {name} is missing from the document"));
            let mut inner = BTreeSet::new();
            schema_refs(schema, &mut inner);
            for next in inner {
                if refs.insert(next.clone()) {
                    pending.push(next);
                }
            }
        }
        for name in [
            "ProblemDetails",
            "SessionInfo",
            "UserInfo",
            "LoginResponse",
            "Page_UserInfo",
        ] {
            assert!(schemas.contains_key(name), "{name}");
        }
    }
}
