//! Sign-in providers and the directory sign-in flows (identity plan sections 3.12 to 3.14
//! and 4.3; WP13.0 declares the routes, WP13.5 builds the providers and `OpenID Connect`,
//! WP13.6 LDAP with the chain fetch, WP13.7 Kerberos through the browser).
//!
//! Area: auth. Owner: WP13.0 (the contracts). Requirements: IAM-11, IAM-12, IAM-13.
//!
//! Every operation is declared with its request and answer types so that the OpenAPI
//! document, the typed client of the UI and the mock server have them. The administrative
//! operations check the caller's right on the settings (an interactive session for every
//! change, as for the security settings) and then answer `501` with `sys.not_implemented`
//! until their package replaces them; the public ones (the sign-in page's buttons, the
//! `OpenID Connect` flow, the Negotiate exchange) take no context and answer `501` as well.
//!
//! | Endpoint | Check | Purpose |
//! |---|---|---|
//! | `GET /auth/providers` | Read on settings | List the providers with their state |
//! | `POST /auth/providers` | Update on settings, interactive | Create a provider (draft) |
//! | `GET /auth/providers/{id}` | Read on settings | Get a provider |
//! | `PATCH /auth/providers/{id}` | Update on settings, interactive | Change a provider, its state or its trust |
//! | `DELETE /auth/providers/{id}` | Update on settings, interactive | Delete a provider and its mappings |
//! | `POST /auth/providers/{id}/test` | Update on settings, interactive | Test an LDAP provider with a user name and password; the groups found and the roles they map to |
//! | `POST /auth/providers/ldap/chain` | Update on settings, interactive | Fetch the certificate chain of an LDAP server for confirmation; stores nothing |
//! | `GET /auth/providers/public` | public | The verified providers the sign-in page offers |
//! | `GET /auth/oidc/{id}/start` | public | Start an `OpenID Connect` sign-in: the flow cookie and a redirect to the provider |
//! | `GET /auth/oidc/{id}/callback` | public | The provider's callback: the code exchange, the ID token checks, the session |
//! | `GET /auth/negotiate` | public | Kerberos through the browser (RFC 4559): `401` with `WWW-Authenticate: Negotiate`, then the session |
//!
//! A test sign-in of an OIDC provider goes through the flow itself (`start` with
//! `?test=1`, the administrator's session completes it); `POST /auth/providers/{id}/test`
//! serves LDAP, whose sign-in is a bind. Never a secret, a token or a ticket in an answer
//! or an audit record.

use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use serde::{Deserialize, Serialize};
use tenko_auth::{
    authz::anywhere,
    directory::{DirectoryProvider, LdapTransport, ProviderId, ProviderState},
    roles::RoleName,
    service::SecretString,
};
use tenko_core::{Action, ObjectKind, Timestamp};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{ApiJson, Svc, Unavailable};
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    routes::not_implemented,
    state::AppState,
};

/// The routes of the providers and the directory sign-in flows.
#[inline(never)]
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_auth_providers, create_auth_provider))
        .routes(routes!(list_public_auth_providers))
        .routes(routes!(fetch_ldap_chain))
        .routes(routes!(
            get_auth_provider,
            update_auth_provider,
            delete_auth_provider
        ))
        .routes(routes!(test_auth_provider))
        .routes(routes!(start_oidc_login))
        .routes(routes!(finish_oidc_login))
        .routes(routes!(negotiate_login))
}

/// A sign-in provider as the API shows it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProviderItem {
    /// The id.
    pub id: ProviderId,
    /// The name.
    pub name: String,
    /// The settings; secrets as references, never values.
    pub provider: DirectoryProvider,
    /// Draft, verified or disabled.
    pub state: ProviderState,
    /// When it was created.
    pub created_at: Timestamp,
    /// The last change.
    pub updated_at: Timestamp,
    /// The last successful sign-in or test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success: Option<Timestamp>,
    /// The last error, in English.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Body of `POST /auth/providers`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProviderCreate {
    /// A unique name, 1 to 64 characters.
    pub name: String,
    /// The settings. A client secret or a service account password is given as a
    /// secret value here once and stored in the vault; the answer carries its reference.
    pub provider: DirectoryProvider,
    /// The client secret of an OIDC provider, or the service account password of an LDAP
    /// provider; absent for a negotiate provider or a user-bind-only LDAP provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretString>,
}

/// Body of `PATCH /auth/providers/{id}`; absent fields stay.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ProviderPatch {
    /// A new name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New settings of the same kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<DirectoryProvider>,
    /// A new secret, replacing the stored one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretString>,
    /// `disabled` to switch the provider off, `draft` to withdraw it from the sign-in page;
    /// `verified` is set by a completed test sign-in only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ProviderState>,
}

/// Body of `POST /auth/providers/{id}/test` (an LDAP provider).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProviderTest {
    /// The user name to sign in with.
    pub user_name: String,
    /// Its password; refused when empty, before any bind.
    pub password: SecretString,
}

/// The answer of a test sign-in.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProviderTestResult {
    /// The immutable subject the directory gave (`objectGUID`).
    pub subject: String,
    /// The display name.
    pub display_name: String,
    /// The groups found (SIDs, DNs or claim values).
    pub groups: Vec<String>,
    /// The roles the mappings give the user.
    pub roles: Vec<RoleName>,
    /// Whether the provider is now verified.
    pub verified: bool,
}

/// Body of `POST /auth/providers/ldap/chain`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LdapChainRequest {
    /// The server, an `ldaps://` or `ldap://` URL.
    pub url: String,
    /// LDAPS, or `StartTLS` after the LDAP extended request; never plain.
    #[serde(default)]
    pub transport: LdapTransport,
}

/// One certificate of a fetched or pasted chain, as the confirmation screen shows it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChainCertificate {
    /// The subject.
    pub subject: String,
    /// The issuer.
    pub issuer: String,
    /// Valid from.
    pub not_before: Timestamp,
    /// Valid until.
    pub not_after: Timestamp,
    /// The key type (`RSA 2048`, `ECDSA P-256`).
    pub key_type: String,
    /// The subject alternative names.
    pub names: Vec<String>,
    /// The SHA-256 fingerprint, lower-case hexadecimal.
    pub fingerprint: String,
    /// Whether the certificate is a CA (above the server's own).
    pub ca: bool,
    /// The certificate, PEM, to send back as the confirmed trust.
    pub pem: String,
}

/// The answer of `POST /auth/providers/ldap/chain`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LdapChainResult {
    /// The chain as the server presented it, the server's certificate first.
    pub certificates: Vec<ChainCertificate>,
    /// Whether the chain verifies against the system trust store already.
    pub verifies: bool,
    /// The commands that print the fingerprints on a domain controller, for the
    /// comparison the administrator makes before confirming.
    pub compare_commands: Vec<String>,
}

/// A provider as the sign-in page sees it (`GET /auth/providers/public`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PublicProvider {
    /// The id.
    pub id: ProviderId,
    /// The text of the button.
    pub label: String,
    /// `oidc`, `ldap` or `negotiate`.
    pub kind: String,
    /// The name suffixes an LDAP provider takes (`@corp.example.test`, `CORP\`).
    #[serde(default)]
    pub suffixes: Vec<String>,
}

/// The answer of `GET /auth/providers/public`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PublicProviders {
    /// The verified providers, in the order of their names.
    pub items: Vec<PublicProvider>,
}

/// Query of `GET /auth/oidc/{id}/start`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct OidcStartParams {
    /// Where the browser goes after the sign-in: a path of the UI; `/` when absent or
    /// not a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// A test sign-in by an administrator: verifies the provider instead of creating a
    /// session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<bool>,
}

/// Query of `GET /auth/oidc/{id}/callback`, as the provider sends it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct OidcCallbackParams {
    /// The authorization code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The state of the flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The provider's error, when it refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[utoipa::path(
    get,
    path = "/auth/providers",
    tag = "auth",
    operation_id = "list_auth_providers",
    summary = "List the sign-in providers",
    description = "Reads the settings (administrators and operators). Every provider with its state, its last success and its last error; secrets as references.",
    responses(
        (status = 200, description = "The providers", body = Vec<ProviderItem>),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the settings", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    )
)]
async fn list_auth_providers(
    Svc(_service): Svc,
    State(app): State<AppState>,
    Ctx(cx): Ctx,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Settings))?;
    Err(not_implemented("GET", "/auth/providers"))
}

#[utoipa::path(
    post,
    path = "/auth/providers",
    tag = "auth",
    operation_id = "create_auth_provider",
    summary = "Create a sign-in provider",
    description = "Administrators, in an interactive session. The provider starts as a draft: it is offered on the sign-in page only after a test sign-in completed. An OIDC provider's discovery document is fetched now; plain LDAP is refused outside the Lab profile (TGL-34). Audited as `auth.provider.create`.",
    request_body(content = ProviderCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The provider", body = ProviderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`) or the settings are invalid (`auth.provider.invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the settings, or a token tries to", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A provider of the name exists (`auth.provider.exists`), or plain LDAP outside Lab (`auth.provider.plain_refused`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 502, description = "The provider's discovery document could not be fetched (`auth.oidc.discovery_failed`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn create_auth_provider(
    Svc(_service): Svc,
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    ApiJson(_body): ApiJson<ProviderCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::Settings),
    )?;
    Err(not_implemented("POST", "/auth/providers"))
}

#[utoipa::path(
    get,
    path = "/auth/providers/public",
    tag = "auth",
    operation_id = "list_public_auth_providers",
    summary = "The providers the sign-in page offers",
    description = "Public. The verified providers as buttons and name suffixes; nothing of their settings.",
    responses(
        (status = 200, description = "The providers", body = PublicProviders),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn list_public_auth_providers(Svc(_service): Svc) -> Result<Response, ApiError> {
    Err(not_implemented("GET", "/auth/providers/public"))
}

#[utoipa::path(
    post,
    path = "/auth/providers/ldap/chain",
    tag = "auth",
    operation_id = "fetch_ldap_chain",
    summary = "Fetch the certificate chain of an LDAP server",
    description = "Administrators, in an interactive session. Opens a TLS connection to the URL (LDAPS, or StartTLS after the LDAP extended request), reads the chain the server presents, sends no credential and no other request, and answers the certificates with their fingerprints and whether the chain verifies against the system trust store. Stores nothing: the pin is made by the provider's create or update call that carries the confirmed certificates (identity plan section 3.13).",
    request_body(content = LdapChainRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The chain, the server's certificate first", body = LdapChainResult),
        (status = 400, description = "The request is malformed (`sys.invalid_request`) or the URL is not an LDAP URL (`auth.provider.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the settings, or a token tries to", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The server could not be reached or presented no chain (`auth.provider.unavailable`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn fetch_ldap_chain(
    Svc(_service): Svc,
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    ApiJson(_body): ApiJson<LdapChainRequest>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::Settings),
    )?;
    Err(not_implemented("POST", "/auth/providers/ldap/chain"))
}

#[utoipa::path(
    get,
    path = "/auth/providers/{id}",
    tag = "auth",
    operation_id = "get_auth_provider",
    summary = "Get a sign-in provider",
    description = "Reads the settings (administrators and operators).",
    params(("id" = String, Path, description = "Provider identifier (UUID)")),
    responses(
        (status = 200, description = "The provider", body = ProviderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the settings", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The provider does not exist (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    )
)]
async fn get_auth_provider(
    Svc(_service): Svc,
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let _id = parse_provider(&id)?;
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Settings))?;
    Err(not_implemented("GET", "/auth/providers/{id}"))
}

#[utoipa::path(
    patch,
    path = "/auth/providers/{id}",
    tag = "auth",
    operation_id = "update_auth_provider",
    summary = "Change a sign-in provider",
    description = "Administrators, in an interactive session. New settings, a new secret, a new trust (the confirmed chain of `POST /auth/providers/ldap/chain`, a PEM bundle or the system store), or the state `disabled` or `draft`. A change of the settings withdraws the provider to `draft` until a test sign-in completes again. Audited as `auth.provider.update`.",
    params(("id" = String, Path, description = "Provider identifier (UUID)")),
    request_body(content = ProviderPatch, content_type = "application/json"),
    responses(
        (status = 200, description = "The provider", body = ProviderItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`) or the settings are invalid (`auth.provider.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the settings, or a token tries to", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The provider does not exist (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken (`auth.provider.exists`), plain LDAP outside Lab (`auth.provider.plain_refused`), or `verified` asked for directly (`auth.provider.unverified`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn update_auth_provider(
    Svc(_service): Svc,
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(_body): ApiJson<ProviderPatch>,
) -> Result<Response, ApiError> {
    let _id = parse_provider(&id)?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::Settings),
    )?;
    Err(not_implemented("PATCH", "/auth/providers/{id}"))
}

#[utoipa::path(
    delete,
    path = "/auth/providers/{id}",
    tag = "auth",
    operation_id = "delete_auth_provider",
    summary = "Delete a sign-in provider",
    description = "Administrators, in an interactive session. Deletes the provider, its mappings and its secret; the sessions signed in through it end at their next request; its users' records stay, disabled for sign-in. Audited as `auth.provider.delete`.",
    params(("id" = String, Path, description = "Provider identifier (UUID)")),
    responses(
        (status = 204, description = "The provider is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the settings, or a token tries to", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The provider does not exist (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn delete_auth_provider(
    Svc(_service): Svc,
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let _id = parse_provider(&id)?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::Settings),
    )?;
    Err(not_implemented("DELETE", "/auth/providers/{id}"))
}

#[utoipa::path(
    post,
    path = "/auth/providers/{id}/test",
    tag = "auth",
    operation_id = "test_auth_provider",
    summary = "Test an LDAP provider with a user name and password",
    description = "Administrators, in an interactive session. Finds the user with the service account (or binds as the user alone), checks the password with the user's own bind, reads the groups and shows the roles the mappings would give; a completed test verifies the provider. An OIDC provider is tested through its own flow (`GET /auth/oidc/{id}/start?test=1`). The password is used for the bind and forgotten. Audited as `auth.provider.verify`.",
    params(("id" = String, Path, description = "Provider identifier (UUID)")),
    request_body(content = ProviderTest, content_type = "application/json"),
    responses(
        (status = 200, description = "The user found, the groups and the roles", body = ProviderTestResult),
        (status = 400, description = "The request is malformed (`sys.invalid_request`), or the provider is not an LDAP provider (`auth.provider.invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token, or the directory refused the password (`auth.invalid_credentials`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the settings, a token tries to, no mapping matches (`auth.directory.no_mapping`), or the account is disabled (`auth.directory.account_disabled`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The provider does not exist (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 502, description = "The chain the server presents is not the pinned one (`auth.provider.chain_changed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The directory cannot be reached (`auth.provider.unavailable`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security(("session" = []))
)]
async fn test_auth_provider(
    Svc(_service): Svc,
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
    ApiJson(_body): ApiJson<ProviderTest>,
) -> Result<Response, ApiError> {
    let _id = parse_provider(&id)?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::Settings),
    )?;
    Err(not_implemented("POST", "/auth/providers/{id}/test"))
}

#[utoipa::path(
    get,
    path = "/auth/oidc/{id}/start",
    tag = "auth",
    operation_id = "start_oidc_login",
    summary = "Start an OpenID Connect sign-in",
    description = "Public. Creates the flow (state, nonce, PKCE verifier, the return path; ten minutes, single use), sets the flow cookie `tenko_oidc` (`HttpOnly; Secure; SameSite=Lax`) and redirects the browser to the provider's authorization endpoint (identity plan section 3.12).",
    params(("id" = String, Path, description = "Provider identifier (UUID)"), OidcStartParams),
    responses(
        (status = 303, description = "The redirect to the provider, with the flow cookie", headers(("Location" = String, description = "The provider's authorization endpoint"), ("Set-Cookie" = String, description = "The flow cookie `tenko_oidc`"))),
        (status = 404, description = "The provider does not exist or is not a verified OIDC provider (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn start_oidc_login(
    Svc(_service): Svc,
    Path(id): Path<String>,
    Query(_params): Query<OidcStartParams>,
) -> Result<Response, ApiError> {
    let _id = parse_provider(&id)?;
    Err(not_implemented("GET", "/auth/oidc/{id}/start"))
}

#[utoipa::path(
    get,
    path = "/auth/oidc/{id}/callback",
    tag = "auth",
    operation_id = "finish_oidc_login",
    summary = "Finish an OpenID Connect sign-in",
    description = "Public; the provider's redirect target. Matches the state and the flow cookie, exchanges the code with the client secret and the PKCE verifier, verifies the ID token (issuer, audience and `azp`, times, nonce, an algorithm of the allow-list, the key from the provider's JWKS), maps the claims onto roles and scopes, creates the session with its cookie (`__Host-tenko_session` over HTTPS) and answers a small page that moves the browser to the return path. No access or refresh token is kept.",
    params(("id" = String, Path, description = "Provider identifier (UUID)"), OidcCallbackParams),
    responses(
        (status = 200, description = "A page that moves the browser to the return path, with the session cookie", content_type = "text/html", headers(("Set-Cookie" = String, description = "The session cookie: `__Host-tenko_session` over HTTPS, `tenko_session` over plain HTTP (Lab)"))),
        (status = 400, description = "No flow matches the callback (`auth.oidc.flow_invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The ID token was refused (`auth.oidc.token_invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "No mapping matches the user (`auth.directory.no_mapping`), or the groups came as an overage marker (`auth.directory.overage`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The provider does not exist (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 502, description = "The provider answered an error (`auth.oidc.provider_error`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn finish_oidc_login(
    Svc(_service): Svc,
    Path(id): Path<String>,
    Query(_params): Query<OidcCallbackParams>,
) -> Result<Response, ApiError> {
    let _id = parse_provider(&id)?;
    Err(not_implemented("GET", "/auth/oidc/{id}/callback"))
}

#[utoipa::path(
    get,
    path = "/auth/negotiate",
    tag = "auth",
    operation_id = "negotiate_login",
    summary = "Sign in with Kerberos through the browser",
    description = "Public. Without a token answers `401` with `WWW-Authenticate: Negotiate`; with a SPNEGO token for `HTTP/<fqdn>` accepts it with the account's keys, answers the AP-REP in the header, maps the PAC's groups through the negotiate provider's mappings and creates the session (RFC 4559; identity plan section 3.14). Offered only while a negotiate provider is verified.",
    responses(
        (status = 200, description = "The session is created; the browser is moved to the UI", content_type = "text/html", headers(("Set-Cookie" = String, description = "The session cookie: `__Host-tenko_session` over HTTPS, `tenko_session` over plain HTTP (Lab)"), ("WWW-Authenticate" = String, description = "`Negotiate <AP-REP>`, the mutual authentication"))),
        (status = 401, description = "No token yet (`WWW-Authenticate: Negotiate`), or the token was refused (`auth.invalid_credentials`)", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "`Negotiate`"))),
        (status = 403, description = "No mapping matches the principal (`auth.directory.no_mapping`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No verified negotiate provider (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    ),
    security()
)]
async fn negotiate_login(Svc(_service): Svc) -> Result<Response, ApiError> {
    Err(not_implemented("GET", "/auth/negotiate"))
}

/// A provider id from the path.
fn parse_provider(raw: &str) -> Result<ProviderId, ApiError> {
    raw.parse().map_err(|_| {
        ApiError::from_coded_error(
            tenko_core::CodedError::new(
                tenko_core::error::codes::INVALID_REQUEST,
                400,
                "the identifier is not a UUID",
            )
            .with_title("Invalid request")
            .with_param("field", "id"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, header},
    };
    use serde_json::{Value, json};
    use tenko_core::Authorizer;
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use super::routes;
    use crate::{
        API_BASE,
        routes::tenancy::testkit::{Policy, Reply},
        state::AppState,
    };

    const ID: &str = "0190d1c2-0000-7000-8000-000000000001";

    fn router(policy: Arc<Policy>) -> Router {
        let state = AppState {
            authorizer: Some(policy as Arc<dyn Authorizer>),
            ..AppState::default()
        };
        let (router, _) = OpenApiRouter::<AppState>::new()
            .nest(API_BASE, routes())
            .split_for_parts();
        router.with_state(state)
    }

    async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> Reply {
        let builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE}{path}"));
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
            .map(|value| value.to_str().expect("text").to_owned())
            .unwrap_or_default();
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
            etag: None,
            body,
        }
    }

    /// Without the authentication service every route of the area answers 503
    /// `auth.unavailable` before any check, as the rest of the area does; the scope checks
    /// and the 501 of the stubs are reached only with the service, which the document tests
    /// of the area and `routes/tests.rs` cover with a whole installation.
    #[tokio::test]
    async fn without_the_service_every_route_answers_503_before_any_check() {
        let policy = Policy::new(true, true);
        let router = router(Arc::clone(&policy));
        let negotiate = json!({ "name": "Corp", "provider": { "kind": "negotiate", "realm": "corp.example.test" } });
        for (method, path, body) in [
            ("GET", "/auth/providers".to_owned(), None),
            ("POST", "/auth/providers".to_owned(), Some(negotiate)),
            ("GET", format!("/auth/providers/{ID}"), None),
            (
                "PATCH",
                format!("/auth/providers/{ID}"),
                Some(json!({ "state": "disabled" })),
            ),
            ("DELETE", format!("/auth/providers/{ID}"), None),
            (
                "POST",
                format!("/auth/providers/{ID}/test"),
                Some(json!({ "user_name": "alex", "password": "p" })),
            ),
            (
                "POST",
                "/auth/providers/ldap/chain".to_owned(),
                Some(json!({ "url": "ldaps://dc01.corp.example.test" })),
            ),
            ("GET", "/auth/providers/public".to_owned(), None),
            ("GET", format!("/auth/oidc/{ID}/start?next=/dns"), None),
            (
                "GET",
                format!("/auth/oidc/{ID}/callback?code=c&state=s"),
                None,
            ),
            ("GET", "/auth/negotiate".to_owned(), None),
        ] {
            send(&router, method, &path, body)
                .await
                .assert_problem(503, "auth.unavailable");
        }
        assert!(policy.asked().is_empty(), "{:?}", policy.asked());
    }
}
