//! Login, sessions, authentication factors, recovery codes and personal tokens.
//!
//! Area: auth. Owner: WP1.2. Requirements: IAM-03, IAM-04, IAM-05, IAM-06, IAM-08, IAM-09,
//! IAM-10.
//!
//! Password login returns a session or a challenge with the remaining methods; `WebAuthn`
//! also covers break-glass. Sessions travel in the `tenko_session` cookie, personal tokens
//! as bearer tokens (shown once, expiry capped by TGL-05).

use utoipa_axum::{router::OpenApiRouter, routes};

use super::not_implemented;
use crate::{
    extract::Ctx,
    problem::{ApiError, ProblemDetails},
    state::AppState,
};

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

#[utoipa::path(
    post,
    path = "/auth/login/password",
    tag = "auth",
    operation_id = "login_password",
    summary = "Log in with a user name and password",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn login_password(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/login/password")
}

#[utoipa::path(
    post,
    path = "/auth/login/totp",
    tag = "auth",
    operation_id = "login_totp",
    summary = "Complete a login with a TOTP code",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn login_totp(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/login/totp")
}

#[utoipa::path(
    post,
    path = "/auth/login/recovery",
    tag = "auth",
    operation_id = "login_recovery",
    summary = "Complete a login with a recovery code",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn login_recovery(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/login/recovery")
}

#[utoipa::path(
    post,
    path = "/auth/webauthn/login/start",
    tag = "auth",
    operation_id = "webauthn_login_start",
    summary = "Start a WebAuthn login and return the challenge",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn webauthn_login_start(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/webauthn/login/start")
}

#[utoipa::path(
    post,
    path = "/auth/webauthn/login/finish",
    tag = "auth",
    operation_id = "webauthn_login_finish",
    summary = "Finish a WebAuthn login with the signed assertion",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn webauthn_login_finish(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/webauthn/login/finish")
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    operation_id = "logout",
    summary = "End the current session",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn logout(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/logout")
}

#[utoipa::path(
    get,
    path = "/auth/session",
    tag = "auth",
    operation_id = "get_session",
    summary = "Describe the current session: principal, roles, strength and expiry",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn get_session(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/auth/session")
}

#[utoipa::path(
    get,
    path = "/auth/sessions",
    tag = "auth",
    operation_id = "list_sessions",
    summary = "List the sessions of the current user",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_sessions(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/auth/sessions")
}

#[utoipa::path(
    delete,
    path = "/auth/sessions/{id}",
    tag = "auth",
    operation_id = "revoke_session",
    summary = "Revoke one session of the current user",
    params(("id" = String, Path, description = "Session identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn revoke_session(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/auth/sessions/{id}")
}

#[utoipa::path(
    post,
    path = "/auth/password",
    tag = "auth",
    operation_id = "change_password",
    summary = "Change the password of the current user",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn change_password(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/password")
}

#[utoipa::path(
    post,
    path = "/auth/password/check",
    tag = "auth",
    operation_id = "check_password",
    summary = "Check a candidate password against the live policy and breach lists",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn check_password(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/password/check")
}

#[utoipa::path(
    post,
    path = "/auth/totp/enroll/start",
    tag = "auth",
    operation_id = "totp_enroll_start",
    summary = "Start TOTP enrolment and return the provisioning data",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn totp_enroll_start(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/totp/enroll/start")
}

#[utoipa::path(
    post,
    path = "/auth/totp/enroll/finish",
    tag = "auth",
    operation_id = "totp_enroll_finish",
    summary = "Finish TOTP enrolment with a first code",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn totp_enroll_finish(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/totp/enroll/finish")
}

#[utoipa::path(
    delete,
    path = "/auth/totp",
    tag = "auth",
    operation_id = "remove_totp",
    summary = "Remove the TOTP factor of the current user",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn remove_totp(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/auth/totp")
}

#[utoipa::path(
    post,
    path = "/auth/webauthn/register/start",
    tag = "auth",
    operation_id = "webauthn_register_start",
    summary = "Start registering a WebAuthn credential and return the challenge",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn webauthn_register_start(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/webauthn/register/start")
}

#[utoipa::path(
    post,
    path = "/auth/webauthn/register/finish",
    tag = "auth",
    operation_id = "webauthn_register_finish",
    summary = "Finish registering a WebAuthn credential with the attestation",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn webauthn_register_finish(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/webauthn/register/finish")
}

#[utoipa::path(
    get,
    path = "/auth/webauthn/credentials",
    tag = "auth",
    operation_id = "list_webauthn_credentials",
    summary = "List the WebAuthn credentials of the current user",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_webauthn_credentials(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/auth/webauthn/credentials")
}

#[utoipa::path(
    delete,
    path = "/auth/webauthn/credentials/{id}",
    tag = "auth",
    operation_id = "delete_webauthn_credential",
    summary = "Delete one WebAuthn credential of the current user",
    params(("id" = String, Path, description = "Credential identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn delete_webauthn_credential(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/auth/webauthn/credentials/{id}")
}

#[utoipa::path(
    post,
    path = "/auth/recovery-codes",
    tag = "auth",
    operation_id = "regenerate_recovery_codes",
    summary = "Generate a new set of recovery codes, shown once",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn regenerate_recovery_codes(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/recovery-codes")
}

#[utoipa::path(
    get,
    path = "/auth/tokens",
    tag = "auth",
    operation_id = "list_tokens",
    summary = "List the personal API tokens of the current user",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_tokens(_ctx: Ctx) -> ApiError {
    not_implemented("GET", "/auth/tokens")
}

#[utoipa::path(
    post,
    path = "/auth/tokens",
    tag = "auth",
    operation_id = "create_token",
    summary = "Create a personal API token, shown once",
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn create_token(_ctx: Ctx) -> ApiError {
    not_implemented("POST", "/auth/tokens")
}

#[utoipa::path(
    delete,
    path = "/auth/tokens/{id}",
    tag = "auth",
    operation_id = "revoke_token",
    summary = "Revoke one personal API token",
    params(("id" = String, Path, description = "Token identifier")),
    responses(
        (status = 501, description = "Not implemented yet", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn revoke_token(_ctx: Ctx) -> ApiError {
    not_implemented("DELETE", "/auth/tokens/{id}")
}
