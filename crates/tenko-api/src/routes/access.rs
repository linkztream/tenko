//! Scoped access: grants over VRFs, sites and prefixes, delegation, service accounts and
//! their scoped tokens, and the MFA policy per role (IAM-01, IAM-06, IAM-10).
//!
//! Area: access. Owner: WP3.2.
//! Requirements: IAM-01, IAM-06, IAM-10.
//!
//! Grants live in `auth.grants` and scoped tokens in `auth.scoped_tokens`, tables an older
//! build does not read, so a rollback refuses them instead of widening them (plan section
//! 2.1). Their changes reach the `admin` event topic through the `auth` namespace.
//!
//! The service decides who may do what (`tenko_auth::service::AuthService`), so the
//! handlers only translate. `docs/access.md` describes the behaviour.
//!
//! | Endpoint | Success | Notes |
//! |---|---|---|
//! | `GET /access/grants` | 200 page of `GrantView` | all for a caller who reads users, else the caller's own and those issued under them; `?subject=` |
//! | `POST /access/grants` | 201 `GrantView` | an administrator, or the holder of a delegable grant |
//! | `DELETE /access/grants/{id}` | 200 `GrantsRevoked` | revokes the grants issued under it in the same batch |
//! | `GET /access/subjects` | 200 page of `SubjectSummary` | people and service accounts a grant can name |
//! | `GET /access/service-accounts` | 200 page of `UserInfo` | |
//! | `POST /access/service-accounts` | 201 `UserInfo` | no password, passkey or session |
//! | `GET /access/service-accounts/{id}/tokens` | 200 page of `TokenInfo` | |
//! | `POST /access/service-accounts/{id}/tokens` | 201 `CreatedToken` | scoped tokens only; shown once |
//! | `DELETE /access/service-accounts/{id}/tokens/{token}` | 204 | |
//! | `GET /access/role-policies` | 200 page of `RolePolicyView` | |
//! | `PUT /access/role-policies/{role}` | 200 `RolePolicyView` | |
//! | `DELETE /access/role-policies/{role}` | 200 `RolePolicyView` | the role follows the profile again |

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tenko_auth::{
    model::GrantId,
    roles::RoleName,
    service::{
        GrantCreate, GrantView, GrantsRevoked, RolePolicyUpdate, RolePolicyView,
        ServiceAccountCreate, SubjectSummary, TokenInfo, TokenRequest, UserInfo,
    },
};
use tenko_core::{ApiTokenId, UserId};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::auth::{
    ApiJson, Forbidden, RouteError, Svc, Unauthenticated, Unavailable, page, secret_json,
};
use crate::{
    API_BASE, dto::Page, extract::Ctx, list::Filters, problem::ProblemDetails, state::AppState,
};

/// The routes of the area.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_grants, create_grant))
        .routes(routes!(revoke_grant))
        .routes(routes!(list_grant_subjects))
        .routes(routes!(list_service_accounts, create_service_account))
        .routes(routes!(
            list_service_account_tokens,
            create_service_account_token
        ))
        .routes(routes!(revoke_service_account_token))
        .routes(routes!(list_role_policies))
        .routes(routes!(set_role_policy, clear_role_policy))
}

/// A `201 Created` JSON answer with `Location`.
fn created<T: serde::Serialize>(location: &str, body: &T) -> Result<Response, RouteError> {
    let location = HeaderValue::from_str(&format!("{API_BASE}{location}"))
        .map_err(|_| tenko_auth::AuthError::internal("the location is not a valid header value"))?;
    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    response.headers_mut().insert(header::LOCATION, location);
    Ok(response)
}

/// Lists grants: every grant for a caller who reads users, otherwise the caller's own grants
/// and the grants issued under them. `subject` narrows the list to one holder. Ordered by
/// holder name, then age; not paginated.
#[utoipa::path(
    get,
    path = "/access/grants",
    tag = "access",
    operation_id = "list_grants",
    summary = "List scoped grants",
    params(("subject" = Option<String>, Query, description = "Only the grants of this user or service account")),
    responses(
        (status = 200, description = "The grants the caller may see", body = Page<GrantView>),
        (status = 400, description = "Unknown parameter (`sys.invalid_query`) or a subject that is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    )
)]
async fn list_grants(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    filters: Filters,
) -> Result<Json<Page<GrantView>>, RouteError> {
    filters.only(&["subject"])?;
    let subject = filters
        .get("subject")?
        .map(str::parse::<UserId>)
        .transpose()?;
    Ok(page(&app, service.list_grants(&ctx, subject).await?))
}

/// Grants a role over a VRF, a site or a prefix (with or without its subtree) to a person or
/// a service account. An administrator grants any scope; the holder of a delegable grant
/// grants a role no higher over a scope inside it, and the new grant is revoked with it.
/// Tokens never create grants. Audited as `auth.grant.create`.
#[utoipa::path(
    post,
    path = "/access/grants",
    tag = "access",
    operation_id = "create_grant",
    summary = "Create a scoped grant",
    request_body = GrantCreate,
    responses(
        (status = 201, description = "The grant", body = GrantView,
            headers(("Location" = String, description = "The URL of the grant"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The caller may not grant (`auth.forbidden`), the session is not strong enough (`auth.step_up_required`), or a delegation goes beyond the caller's grants (`auth.grant.exceeds_own`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user or service account (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The subject already holds this role over this scope (`auth.grant.duplicate`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The role is global-only (`auth.grant.invalid_role`) or the scope cannot be granted or does not exist (`auth.grant.invalid_scope`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The server has no IP address management to resolve scopes (`auth.scope.unavailable`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated
    ),
    security(("session" = []))
)]
async fn create_grant(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<GrantCreate>,
) -> Result<Response, RouteError> {
    let grant = service.create_grant(&ctx, &request).await?;
    created(&format!("/access/grants/{}", grant.id), &grant)
}

/// Revokes a grant and every grant issued under it, in one batch. An administrator revokes
/// any grant; a holder revokes its own grants and the grants issued under them. Audited as
/// `auth.grant.revoke`.
#[utoipa::path(
    delete,
    path = "/access/grants/{id}",
    tag = "access",
    operation_id = "revoke_grant",
    summary = "Revoke a grant and the grants issued under it",
    params(("id" = String, Path, description = "Grant identifier")),
    responses(
        (status = 200, description = "Every revoked grant, the requested one first", body = GrantsRevoked),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The session is not strong enough (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such grant, or one the caller does not see (`auth.grant.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn revoke_grant(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<Json<GrantsRevoked>, RouteError> {
    let id = id.parse::<GrantId>()?;
    Ok(Json(service.revoke_grant(&ctx, id).await?))
}

/// The people and service accounts a grant can name: every enabled account for an
/// administrator, the same list for the holder of a delegable grant.
#[utoipa::path(
    get,
    path = "/access/subjects",
    tag = "access",
    operation_id = "list_grant_subjects",
    summary = "List the accounts a grant can name",
    responses(
        (status = 200, description = "People and service accounts, ordered by name", body = Page<SubjectSummary>),
        Unauthenticated,
        Forbidden,
        Unavailable
    )
)]
async fn list_grant_subjects(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<SubjectSummary>>, RouteError> {
    Ok(page(&app, service.grant_subjects(&ctx).await?))
}

/// Lists the service accounts (IAM-10), ordered by name.
#[utoipa::path(
    get,
    path = "/access/service-accounts",
    tag = "access",
    operation_id = "list_service_accounts",
    summary = "List service accounts",
    responses(
        (status = 200, description = "Every service account", body = Page<UserInfo>),
        Unauthenticated,
        Forbidden,
        Unavailable
    )
)]
async fn list_service_accounts(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<UserInfo>>, RouteError> {
    Ok(page(&app, service.list_service_accounts(&ctx).await?))
}

/// Creates a service account: an account without password, passkey or session that holds
/// global roles or scoped grants and acts through scoped tokens only. Its owner is the
/// administrator who creates it.
#[utoipa::path(
    post,
    path = "/access/service-accounts",
    tag = "access",
    operation_id = "create_service_account",
    summary = "Create a service account",
    request_body = ServiceAccountCreate,
    responses(
        (status = 201, description = "The service account", body = UserInfo,
            headers(("Location" = String, description = "The URL of the account as a user"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the name or roles are invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The name is taken (`users.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn create_service_account(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<ServiceAccountCreate>,
) -> Result<Response, RouteError> {
    let account = service.create_service_account(&ctx, &request).await?;
    created(&format!("/users/{}", account.id), &account)
}

/// Lists the scoped tokens of a service account; secrets are never shown again.
#[utoipa::path(
    get,
    path = "/access/service-accounts/{id}/tokens",
    tag = "access",
    operation_id = "list_service_account_tokens",
    summary = "List the tokens of a service account",
    params(("id" = String, Path, description = "Service account identifier")),
    responses(
        (status = 200, description = "Every token of the account", body = Page<TokenInfo>),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such service account (`auth.service_account.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn list_service_account_tokens(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<Json<Page<TokenInfo>>, RouteError> {
    let id = id.parse::<UserId>()?;
    Ok(page(&app, service.list_account_tokens(&ctx, id).await?))
}

/// Creates a scoped token of a service account (IAM-10): its grants are a subset of the
/// account's, plus the special scopes `metrics` and `audit:read`; it acts with the
/// intersection of its grants and the account's at request time. The secret is shown once;
/// the expiry is capped by TGL-05, re-checked at every use.
#[utoipa::path(
    post,
    path = "/access/service-accounts/{id}/tokens",
    tag = "access",
    operation_id = "create_service_account_token",
    summary = "Create a scoped token of a service account, shown once",
    params(("id" = String, Path, description = "Service account identifier")),
    request_body = TokenRequest,
    responses(
        (status = 201, description = "The token: its secret (`tnk_...`, shown once) and its metadata", body = tenko_auth::service::CreatedToken),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the name or lifetime is invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The caller may not administer users (`auth.forbidden`), the session is not strong enough (`auth.step_up_required`), or a grant goes beyond the account's (`auth.grant.exceeds_own`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such service account (`auth.service_account.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The lifetime exceeds the maximum of the profile (`auth.token.lifetime_exceeded`), a grant names a global-only role (`auth.grant.invalid_role`) or a scope that cannot be granted (`auth.grant.invalid_scope`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn create_service_account_token(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
    ApiJson(request): ApiJson<TokenRequest>,
) -> Result<Response, RouteError> {
    let id = id.parse::<UserId>()?;
    secret_json(
        StatusCode::CREATED,
        None,
        &service.create_account_token(&ctx, id, &request).await?,
    )
}

/// Revokes one token of a service account. Audited as `auth.token.revoke`.
#[utoipa::path(
    delete,
    path = "/access/service-accounts/{id}/tokens/{token}",
    tag = "access",
    operation_id = "revoke_service_account_token",
    summary = "Revoke a token of a service account",
    params(
        ("id" = String, Path, description = "Service account identifier"),
        ("token" = String, Path, description = "Token identifier")
    ),
    responses(
        (status = 204, description = "The token was revoked"),
        (status = 400, description = "An identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such service account (`auth.service_account.not_found`) or token (`auth.token.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn revoke_service_account_token(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path((id, token)): Path<(String, String)>,
) -> Result<StatusCode, RouteError> {
    let id = id.parse::<UserId>()?;
    let token = token.parse::<ApiTokenId>()?;
    service.revoke_account_token(&ctx, id, token).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The MFA requirement of every role (IAM-06): the requirement in force, the profile's
/// (TGL-02, TGL-03) and the stored policy. A user must meet the strictest requirement of
/// every role it holds at any scope.
#[utoipa::path(
    get,
    path = "/access/role-policies",
    tag = "access",
    operation_id = "list_role_policies",
    summary = "List the MFA policy of every role",
    responses(
        (status = 200, description = "One policy per role", body = Page<RolePolicyView>),
        Unauthenticated,
        Forbidden,
        Unavailable
    )
)]
async fn list_role_policies(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<RolePolicyView>>, RouteError> {
    Ok(page(&app, service.role_policies(&ctx).await?))
}

/// Stores the MFA requirement of a role; a requirement weaker than the profile's has no
/// effect beyond it. Audited.
#[utoipa::path(
    put,
    path = "/access/role-policies/{role}",
    tag = "access",
    operation_id = "set_role_policy",
    summary = "Set the MFA policy of a role",
    params(("role" = String, Path, description = "Role name: `admin`, `operator`, `viewer` or `auditor`")),
    request_body = RolePolicyUpdate,
    responses(
        (status = 200, description = "The policy of the role", body = RolePolicyView),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the role is unknown (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The caller may not change settings (`auth.forbidden`) or the session is not strong enough (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn set_role_policy(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(role): Path<String>,
    ApiJson(request): ApiJson<RolePolicyUpdate>,
) -> Result<Json<RolePolicyView>, RouteError> {
    let role = role.parse::<RoleName>()?;
    Ok(Json(service.set_role_policy(&ctx, role, &request).await?))
}

/// Removes the stored MFA policy of a role, which then follows the profile again. Audited.
#[utoipa::path(
    delete,
    path = "/access/role-policies/{role}",
    tag = "access",
    operation_id = "clear_role_policy",
    summary = "Let a role follow the profile's MFA requirement again",
    params(("role" = String, Path, description = "Role name: `admin`, `operator`, `viewer` or `auditor`")),
    responses(
        (status = 200, description = "The policy of the role", body = RolePolicyView),
        (status = 400, description = "The role is unknown (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The caller may not change settings (`auth.forbidden`) or the session is not strong enough (`auth.step_up_required`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []))
)]
async fn clear_role_policy(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(role): Path<String>,
) -> Result<Json<RolePolicyView>, RouteError> {
    let role = role.parse::<RoleName>()?;
    Ok(Json(service.clear_role_policy(&ctx, role).await?))
}

#[cfg(test)]
mod tests;
