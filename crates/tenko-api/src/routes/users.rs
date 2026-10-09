//! Users, roles and break-glass access.
//!
//! Area: users. Owner: WP1.2. Requirements: IAM-05, IAM-09, IAM-19.
//!
//! Roles are global (`admin`, `operator`, `viewer`). Enabling break-glass access needs fresh
//! authentication (IAM-09).
//!
//! The service decides who may do what (the authorizer of the roles), so a caller without
//! the permission gets `403` from it, and the handlers only translate.
//!
//! | Endpoint | Success | Notes |
//! |---|---|---|
//! | `GET /users` | 200 page of `UserInfo` | not paginated |
//! | `POST /users` | 201 `UserInfo` with `Location` and `ETag` | |
//! | `GET /users/{id}` | 200 `UserInfo` with `ETag: "<revision>"` | |
//! | `PATCH /users/{id}` | 200 `UserInfo` | optional `If-Match` |
//! | `DELETE /users/{id}` | 204 | |
//! | `POST /users/{id}/unlock` | 200 `UserInfo` | |
//! | `DELETE /users/{id}/sessions` | 204 | |
//! | `PUT /users/{id}/roles` | 200 `UserInfo` | optional `If-Match` |
//! | `GET /roles` | 200 page of `RoleInfo` | any authenticated caller |
//! | `PUT /system/break-glass` | 200 `UserInfo` | needs a fresh, strong authentication |

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tenko_auth::service::{
    BreakGlassChange, RoleInfo, RolesUpdate, UserCreate, UserInfo, UserUpdate,
};
use tenko_core::UserId;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::auth::{
    ApiJson, Forbidden, RouteError, Svc, Unauthenticated, Unavailable, if_match, page, with_etag,
};
use crate::{API_BASE, dto::Page, extract::Ctx, problem::ProblemDetails, state::AppState};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_users, create_user))
        .routes(routes!(get_user, update_user, delete_user))
        .routes(routes!(unlock_user))
        .routes(routes!(revoke_user_sessions))
        .routes(routes!(set_user_roles))
        .routes(routes!(list_roles))
        .routes(routes!(set_break_glass))
}

/// A user as a response with the given status and the user's revision as `ETag`.
fn user_response(status: StatusCode, user: UserInfo) -> Response {
    let revision = user.revision;
    with_etag((status, Json(user)).into_response(), revision)
}

/// Lists every user, ordered by name. The list is small and not paginated: `next_cursor`
/// is always `null`.
#[utoipa::path(
    get,
    path = "/users",
    tag = "users",
    operation_id = "list_users",
    summary = "List users",
    responses(
        (status = 200, description = "Every user, ordered by name", body = Page<UserInfo>),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []), ("token" = []))
)]
async fn list_users(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(ctx): Ctx,
) -> Result<Json<Page<UserInfo>>, RouteError> {
    Ok(page(&app, service.list_users(&ctx).await?))
}

/// Creates a user with global roles and, optionally, an initial password that the user must
/// change at first login.
#[utoipa::path(
    post,
    path = "/users",
    tag = "users",
    operation_id = "create_user",
    summary = "Create a user",
    request_body = UserCreate,
    responses(
        (status = 201, description = "The user was created",  body = UserInfo,
            headers(
                ("Location" = String, description = "The URL of the new user"),
                ("ETag" = String, description = "The revision of the user, for `If-Match`")
            )),
        (status = 400, description = "The body is malformed (`sys.invalid_request`), or the name, roles or language are invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The user name is taken (`users.name_taken`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The initial password breaks the policy (`auth.password.policy`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn create_user(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<UserCreate>,
) -> Result<Response, RouteError> {
    let user = service.create_user(&ctx, &request).await?;
    let location = HeaderValue::from_str(&format!("{API_BASE}/users/{}", user.id))
        .map_err(|_| tenko_auth::AuthError::internal("the location is not a valid header value"))?;
    let mut response = user_response(StatusCode::CREATED, user);
    response.headers_mut().insert(header::LOCATION, location);
    Ok(response)
}

/// Reads one user.
#[utoipa::path(
    get,
    path = "/users/{id}",
    tag = "users",
    operation_id = "get_user",
    summary = "Get one user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 200, description = "The user", body = UserInfo,
            headers(("ETag" = String, description = "The revision of the user, for `If-Match`"))),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []), ("token" = []))
)]
async fn get_user(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, RouteError> {
    let id = id.parse::<UserId>()?;
    Ok(user_response(
        StatusCode::OK,
        service.get_user(&ctx, id).await?,
    ))
}

/// Changes the display name, the language or the disabled flag, or sets a new password that
/// the user must change at next login. Disabling an account or resetting its password ends
/// its sessions.
#[utoipa::path(
    patch,
    path = "/users/{id}",
    tag = "users",
    operation_id = "update_user",
    summary = "Update a user",
    params(
        ("id" = String, Path, description = "User identifier"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag`; a stale revision is refused with 409")
    ),
    request_body = UserUpdate,
    responses(
        (status = 200, description = "The user after the change", body = UserInfo,
            headers(("ETag" = String, description = "The new revision of the user"))),
        (status = 400, description = "The identifier is not a UUID or `If-Match` is malformed (`sys.invalid_value`), the body is malformed (`sys.invalid_request`), or a value is invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale (`auth.conflict`) or the change would leave no active administrator (`users.last_administrator`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The new password breaks the policy (`auth.password.policy`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn update_user(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<UserUpdate>,
) -> Result<Response, RouteError> {
    let id = id.parse::<UserId>()?;
    let expect = if_match(&headers)?;
    Ok(user_response(
        StatusCode::OK,
        service.update_user(&ctx, id, &request, expect).await?,
    ))
}

/// Deletes a user with the user's sessions, tokens and credentials. The audit records keep
/// the id. An administrator cannot delete their own account or the last administrator.
#[utoipa::path(
    delete,
    path = "/users/{id}",
    tag = "users",
    operation_id = "delete_user",
    summary = "Delete a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 204, description = "The user was deleted"),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`) or is the caller's own account (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The user is the last active administrator (`users.last_administrator`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn delete_user(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError> {
    let id = id.parse::<UserId>()?;
    service.delete_user(&ctx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Lifts the lockout of a user (IAM-05).
#[utoipa::path(
    post,
    path = "/users/{id}/unlock",
    tag = "users",
    operation_id = "unlock_user",
    summary = "Lift the lockout of a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 200, description = "The user after the unlock", body = UserInfo,
            headers(("ETag" = String, description = "The revision of the user"))),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn unlock_user(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, RouteError> {
    let id = id.parse::<UserId>()?;
    Ok(user_response(
        StatusCode::OK,
        service.unlock_user(&ctx, id).await?,
    ))
}

/// Ends every session of a user.
#[utoipa::path(
    delete,
    path = "/users/{id}/sessions",
    tag = "users",
    operation_id = "revoke_user_sessions",
    summary = "Revoke every session of a user",
    params(("id" = String, Path, description = "User identifier")),
    responses(
        (status = 204, description = "The sessions ended"),
        (status = 400, description = "The identifier is not a UUID (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn revoke_user_sessions(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError> {
    let id = id.parse::<UserId>()?;
    service.revoke_user_sessions(&ctx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Replaces the global roles of a user. The last active administrator cannot lose the
/// `admin` role, and the break-glass account is always `admin`.
#[utoipa::path(
    put,
    path = "/users/{id}/roles",
    tag = "users",
    operation_id = "set_user_roles",
    summary = "Replace the roles of a user",
    params(
        ("id" = String, Path, description = "User identifier"),
        ("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag`; a stale revision is refused with 409")
    ),
    request_body = RolesUpdate,
    responses(
        (status = 200, description = "The user after the change", body = UserInfo,
            headers(("ETag" = String, description = "The new revision of the user"))),
        (status = 400, description = "The identifier is not a UUID or `If-Match` is malformed (`sys.invalid_value`), the body is malformed (`sys.invalid_request`), or the roles are invalid (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale (`auth.conflict`) or the change would leave no active administrator (`users.last_administrator`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn set_user_roles(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RolesUpdate>,
) -> Result<Response, RouteError> {
    let id = id.parse::<UserId>()?;
    let expect = if_match(&headers)?;
    Ok(user_response(
        StatusCode::OK,
        service
            .set_user_roles(&ctx, id, &request.roles, expect)
            .await?,
    ))
}

/// Lists the global roles with what each grants. Any authenticated caller may read it. The
/// list is small and not paginated: `next_cursor` is always `null`.
#[utoipa::path(
    get,
    path = "/roles",
    tag = "users",
    operation_id = "list_roles",
    summary = "List the available roles",
    responses(
        (status = 200, description = "Every role with its description", body = Page<RoleInfo>),
        Unauthenticated,
        Unavailable
    ),
    security(("session" = []), ("token" = []))
)]
#[allow(clippy::unused_async, reason = "axum handlers are async functions")]
async fn list_roles(
    State(app): State<AppState>,
    Svc(service): Svc,
    Ctx(_ctx): Ctx,
) -> Result<Json<Page<RoleInfo>>, RouteError> {
    Ok(page(&app, service.roles()))
}

/// Designates or releases the break-glass account (IAM-09): it then logs in with an
/// attested, non-synced security key only, is rate limited instead of locked out, and
/// raises an alarm at every use. Needs a fresh, strong authentication of the administrator,
/// and the account must already hold a hardware security key.
#[utoipa::path(
    put,
    path = "/system/break-glass",
    tag = "users",
    operation_id = "set_break_glass",
    summary = "Configure break-glass access; needs fresh authentication",
    request_body = BreakGlassChange,
    responses(
        (status = 200, description = "The account after the change", body = UserInfo,
            headers(("ETag" = String, description = "The new revision of the user"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the account holds no hardware security key (`auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such user (`users.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The account is the last active administrator (`users.last_administrator`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn set_break_glass(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<BreakGlassChange>,
) -> Result<Response, RouteError> {
    Ok(user_response(
        StatusCode::OK,
        service.set_break_glass(&ctx, &request).await?,
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tenko_auth::testing::env::ADMIN;

    use super::super::auth::testkit::{Credential::*, Harness, Reply};

    const SOME_ID: &str = "0190d1c2-0000-7000-8000-000000000001";

    fn id(user: &Value) -> String {
        user["id"].as_str().expect("a user id").to_owned()
    }

    fn revision(user: &Value) -> u64 {
        user["revision"].as_u64().expect("a revision")
    }

    fn etag(revision: u64) -> String {
        format!("\"{revision}\"")
    }

    /// Creates a user; the answer is returned as it is.
    async fn create(harness: &Harness, admin: &str, body: Value) -> Reply {
        harness
            .call("POST", "/users", Cookie(admin), Some(&body))
            .await
    }

    /// The id of the administrator.
    async fn admin_id(harness: &Harness, admin: &str) -> String {
        let session = harness
            .call("GET", "/auth/session", Cookie(admin), None)
            .await;
        session.body["user"]["id"]
            .as_str()
            .expect("an id")
            .to_owned()
    }

    #[tokio::test]
    async fn users_are_created_read_and_listed() {
        let (harness, admin) = Harness::installed().await;
        let created = harness
            .call(
                "POST",
                "/users",
                Cookie(&admin),
                Some(&json!({
                    "name": "ada",
                    "display_name": "Ada L",
                    "password": "7391",
                    "roles": ["operator"],
                    "language": "sv"
                })),
            )
            .await;
        created.assert_status(201);
        let user = created.body.clone();
        let ada = id(&user);
        assert_eq!(
            created.header("location"),
            Some(format!("/api/v1/users/{ada}").as_str())
        );
        assert_eq!(created.header("etag"), Some(etag(revision(&user)).as_str()));
        assert_eq!(user["name"], "ada");
        assert_eq!(user["display_name"], "Ada L");
        assert_eq!(user["roles"], json!(["operator"]));
        assert_eq!(user["language"], "sv");
        assert_eq!(user["disabled"], false);
        assert_eq!(user["break_glass"], false);
        assert_eq!(user["factors"]["password"], true);
        assert_eq!(user["password_change_required"], true);
        assert!(user.get("lock").is_none());
        // The password is not part of any answer.
        assert!(!created.body.to_string().contains("7391"));

        let got = harness
            .call("GET", &format!("/users/{ada}"), Cookie(&admin), None)
            .await;
        got.assert_status(200);
        assert_eq!(got.body, user);
        assert_eq!(got.header("etag"), Some(etag(revision(&user)).as_str()));

        let list = harness.call("GET", "/users", Cookie(&admin), None).await;
        list.assert_status(200);
        assert_eq!(list.body["next_cursor"], Value::Null);
        assert!(list.body["revision"].is_u64());
        let names: Vec<&str> = list.body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["name"].as_str().expect("a name"))
            .collect();
        assert_eq!(names, ["ada", ADMIN]);

        // The new user can log in and has to change the password.
        let session = harness.login("ada", "7391").await;
        let described = harness
            .call("GET", "/auth/session", Cookie(&session), None)
            .await;
        assert_eq!(described.body["flags"]["password_change_required"], true);
        assert_eq!(described.body["roles"], json!(["operator"]));
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.user.create".to_owned())
        );
    }

    #[tokio::test]
    async fn a_taken_name_and_bad_values_are_refused() {
        let (harness, admin) = Harness::installed().await;
        harness
            .create_user(&admin, "ada", "7391", &["viewer"])
            .await;
        create(
            &harness,
            &admin,
            json!({ "name": "ada", "roles": ["viewer"] }),
        )
        .await
        .assert_problem(409, "users.name_taken");
        create(
            &harness,
            &admin,
            json!({ "name": "ADA", "roles": ["viewer"] }),
        )
        .await
        .assert_problem(409, "users.name_taken");
        let spaced = create(
            &harness,
            &admin,
            json!({ "name": "two words", "roles": ["viewer"] }),
        )
        .await;
        spaced.assert_problem(400, "auth.invalid_request");
        assert_eq!(spaced.body["params"]["field"], "name");
        create(&harness, &admin, json!({ "name": "bob", "roles": [] }))
            .await
            .assert_problem(400, "auth.invalid_request");
        create(
            &harness,
            &admin,
            json!({ "name": "bob", "roles": ["root"] }),
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        let missing = create(&harness, &admin, json!({ "name": "bob" })).await;
        missing.assert_problem(400, "sys.invalid_request");
        assert_eq!(missing.body["params"]["field"], "roles");
        let weak = create(
            &harness,
            &admin,
            json!({ "name": "bob", "roles": ["viewer"], "password": "ab" }),
        )
        .await;
        weak.assert_problem(422, "auth.password.policy");
        assert_ne!(weak.body["errors"].as_array().expect("violations").len(), 0);
        create(
            &harness,
            &admin,
            json!({ "name": "bob", "roles": ["viewer"], "language": "de" }),
        )
        .await
        .assert_problem(400, "auth.invalid_request");
        // A user without a password cannot log in with one.
        create(
            &harness,
            &admin,
            json!({ "name": "nopass", "roles": ["viewer"] }),
        )
        .await
        .assert_status(201);
        harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": "nopass", "password": "7391" })),
            )
            .await
            .assert_problem(401, "auth.invalid_credentials");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One flow through the conditional updates.
    async fn if_match_guards_updates() {
        let (harness, admin) = Harness::installed().await;
        let ada = harness
            .create_user(&admin, "ada", "7391", &["viewer"])
            .await;
        let path = format!("/users/{}", id(&ada));
        let first = revision(&ada);
        let rename = |name: &str| json!({ "display_name": name });

        let changed = harness
            .call_with(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&rename("Ada Lovelace")),
                &[("If-Match", &etag(first))],
            )
            .await;
        changed.assert_status(200);
        assert_eq!(changed.body["display_name"], "Ada Lovelace");
        let second = revision(&changed.body);
        assert!(second > first);
        assert_eq!(changed.header("etag"), Some(etag(second).as_str()));

        // The stale revision is refused and changes nothing.
        harness
            .call_with(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&rename("Stale")),
                &[("If-Match", &etag(first))],
            )
            .await
            .assert_problem(409, "auth.conflict");
        let current = harness.call("GET", &path, Cookie(&admin), None).await;
        assert_eq!(current.body["display_name"], "Ada Lovelace");
        assert_eq!(revision(&current.body), second);

        // Weak tags and bare numbers are read as revisions, a wildcard and no header mean no
        // precondition, nonsense is a 400.
        let weak = harness
            .call_with(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&rename("Weak")),
                &[("If-Match", &format!("W/{}", etag(second)))],
            )
            .await;
        weak.assert_status(200);
        let third = revision(&weak.body);
        let bare = harness
            .call_with(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&rename("Bare")),
                &[("If-Match", &third.to_string())],
            )
            .await;
        bare.assert_status(200);
        let any = harness
            .call_with(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&rename("Any")),
                &[("If-Match", "*")],
            )
            .await;
        any.assert_status(200);
        harness
            .call("PATCH", &path, Cookie(&admin), Some(&rename("None")))
            .await
            .assert_status(200);
        let bad = harness
            .call_with(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&rename("Bad")),
                &[("If-Match", "\"latest\"")],
            )
            .await;
        bad.assert_problem(400, "sys.invalid_value");
        assert_eq!(bad.body["params"]["kind"], "If-Match");

        // Other fields: language, a password reset and disabling.
        let language = harness
            .call(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&json!({ "language": "sv" })),
            )
            .await;
        assert_eq!(language.body["language"], "sv");
        let cleared = harness
            .call(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&json!({ "language": "" })),
            )
            .await;
        assert!(cleared.body.get("language").is_none());
        harness
            .call(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&json!({ "language": "de" })),
            )
            .await
            .assert_problem(400, "auth.invalid_request");
        let session = harness.login("ada", "7391").await;
        let reset = harness
            .call(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&json!({ "password": "6402" })),
            )
            .await;
        reset.assert_status(200);
        assert_eq!(reset.body["password_change_required"], true);
        // A reset ends the user's sessions and the new password works.
        harness
            .call("GET", "/auth/session", Cookie(&session), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        let session = harness.login("ada", "6402").await;
        let disabled = harness
            .call(
                "PATCH",
                &path,
                Cookie(&admin),
                Some(&json!({ "disabled": true })),
            )
            .await;
        assert_eq!(disabled.body["disabled"], true);
        harness
            .call("GET", "/auth/session", Cookie(&session), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": "ada", "password": "6402" })),
            )
            .await
            .assert_problem(401, "auth.invalid_credentials");

        // Unknown users, bad identifiers and the caller's own account.
        harness
            .call(
                "PATCH",
                &format!("/users/{SOME_ID}"),
                Cookie(&admin),
                Some(&rename("x")),
            )
            .await
            .assert_problem(404, "users.not_found");
        let own = admin_id(&harness, &admin).await;
        harness
            .call(
                "PATCH",
                &format!("/users/{own}"),
                Cookie(&admin),
                Some(&json!({ "disabled": true })),
            )
            .await
            .assert_problem(400, "auth.invalid_request");
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.user.update".to_owned())
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One flow through the role changes.
    async fn roles_are_replaced_and_the_last_administrator_is_protected() {
        let (harness, admin) = Harness::installed().await;
        let ada = harness
            .create_user(&admin, "ada", "7391", &["viewer"])
            .await;
        let ada_path = format!("/users/{}/roles", id(&ada));

        let replaced = harness
            .call_with(
                "PUT",
                &ada_path,
                Cookie(&admin),
                Some(&json!({ "roles": ["viewer", "operator", "viewer"] })),
                &[("If-Match", &etag(revision(&ada)))],
            )
            .await;
        replaced.assert_status(200);
        assert_eq!(replaced.body["roles"], json!(["operator", "viewer"]));
        assert_eq!(
            replaced.header("etag"),
            Some(etag(revision(&replaced.body)).as_str())
        );
        // The revision the client read is stale now.
        harness
            .call_with(
                "PUT",
                &ada_path,
                Cookie(&admin),
                Some(&json!({ "roles": ["viewer"] })),
                &[("If-Match", &etag(revision(&ada)))],
            )
            .await
            .assert_problem(409, "auth.conflict");
        harness
            .call_with(
                "PUT",
                &ada_path,
                Cookie(&admin),
                Some(&json!({ "roles": ["viewer"] })),
                &[("If-Match", "oops")],
            )
            .await
            .assert_problem(400, "sys.invalid_value");
        harness
            .call(
                "PUT",
                &ada_path,
                Cookie(&admin),
                Some(&json!({ "roles": [] })),
            )
            .await
            .assert_problem(400, "auth.invalid_request");
        harness
            .call(
                "PUT",
                &ada_path,
                Cookie(&admin),
                Some(&json!({ "roles": ["root"] })),
            )
            .await
            .assert_problem(400, "sys.invalid_request");
        harness
            .call(
                "PUT",
                &format!("/users/{SOME_ID}/roles"),
                Cookie(&admin),
                Some(&json!({ "roles": ["viewer"] })),
            )
            .await
            .assert_problem(404, "users.not_found");

        // The only administrator cannot give up the role...
        let own = admin_id(&harness, &admin).await;
        let own_path = format!("/users/{own}/roles");
        harness
            .call(
                "PUT",
                &own_path,
                Cookie(&admin),
                Some(&json!({ "roles": ["viewer"] })),
            )
            .await
            .assert_problem(409, "users.last_administrator");
        // ...until another one exists. Then the first loses the administration at once.
        harness
            .call(
                "PUT",
                &ada_path,
                Cookie(&admin),
                Some(&json!({ "roles": ["admin"] })),
            )
            .await
            .assert_status(200);
        harness
            .call(
                "PUT",
                &own_path,
                Cookie(&admin),
                Some(&json!({ "roles": ["viewer"] })),
            )
            .await
            .assert_status(200);
        harness
            .call("GET", "/users", Cookie(&admin), None)
            .await
            .assert_problem(403, "auth.forbidden");
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.user.roles".to_owned())
        );
    }

    #[tokio::test]
    async fn users_are_deleted_but_not_the_caller() {
        let (harness, admin) = Harness::installed().await;
        let ada = harness
            .create_user(&admin, "ada", "7391", &["viewer"])
            .await;
        let path = format!("/users/{}", id(&ada));
        let session = harness.login("ada", "7391").await;

        harness
            .call("DELETE", &path, Cookie(&admin), None)
            .await
            .assert_status(204);
        harness
            .call("GET", &path, Cookie(&admin), None)
            .await
            .assert_problem(404, "users.not_found");
        harness
            .call("DELETE", &path, Cookie(&admin), None)
            .await
            .assert_problem(404, "users.not_found");
        // The user's sessions went with the account, and the name is free again.
        harness
            .call("GET", "/auth/session", Cookie(&session), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .create_user(&admin, "ada", "7391", &["viewer"])
            .await;

        let own = admin_id(&harness, &admin).await;
        harness
            .call("DELETE", &format!("/users/{own}"), Cookie(&admin), None)
            .await
            .assert_problem(400, "auth.invalid_request");
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.user.delete".to_owned())
        );
    }

    #[tokio::test]
    async fn an_administrator_can_end_the_sessions_of_a_user() {
        let (harness, admin) = Harness::installed().await;
        let ada = harness
            .create_user(&admin, "ada", "7391", &["viewer"])
            .await;
        let first = harness.login("ada", "7391").await;
        let second = harness.login("ada", "7391").await;
        harness
            .call(
                "DELETE",
                &format!("/users/{}/sessions", id(&ada)),
                Cookie(&admin),
                None,
            )
            .await
            .assert_status(204);
        for session in [&first, &second] {
            harness
                .call("GET", "/auth/session", Cookie(session), None)
                .await
                .assert_problem(401, "auth.unauthenticated");
        }
        // The administrator's own session is not touched.
        harness
            .call("GET", "/auth/session", Cookie(&admin), None)
            .await
            .assert_status(200);
        harness
            .call(
                "DELETE",
                &format!("/users/{SOME_ID}/sessions"),
                Cookie(&admin),
                None,
            )
            .await
            .assert_problem(404, "users.not_found");
    }

    #[tokio::test]
    async fn a_locked_account_is_unlocked() {
        let (harness, admin) = Harness::installed().await;
        let ada = harness
            .create_user(&admin, "ada", "7391", &["viewer"])
            .await;
        harness
            .fail_logins_until_throttled("ada")
            .await
            .assert_problem(429, "auth.throttled");
        harness
            .call(
                "POST",
                "/auth/login/password",
                Anonymous,
                Some(&json!({ "user_name": "ada", "password": "7391" })),
            )
            .await
            .assert_problem(429, "auth.throttled");

        let unlocked = harness
            .call(
                "POST",
                &format!("/users/{}/unlock", id(&ada)),
                Cookie(&admin),
                None,
            )
            .await;
        unlocked.assert_status(200);
        assert_eq!(unlocked.body["name"], "ada");
        assert!(unlocked.body.get("lock").is_none());
        assert_eq!(
            unlocked.header("etag"),
            Some(etag(revision(&unlocked.body)).as_str())
        );
        harness.login("ada", "7391").await;
        harness
            .call(
                "POST",
                &format!("/users/{SOME_ID}/unlock"),
                Cookie(&admin),
                None,
            )
            .await
            .assert_problem(404, "users.not_found");
    }

    #[tokio::test]
    async fn a_viewer_cannot_administer() {
        let (harness, admin) = Harness::installed().await;
        let ada = harness.create_user(&admin, "ada", "7391", &["admin"]).await;
        let viewer = harness
            .create_user(&admin, "vera", "5826", &["viewer"])
            .await;
        let session = harness.login("vera", "5826").await;
        let (ada, own) = (id(&ada), id(&viewer));

        let attempts: Vec<(&str, String, Option<Value>)> = vec![
            ("GET", "/users".to_owned(), None),
            (
                "POST",
                "/users".to_owned(),
                Some(json!({ "name": "eve", "roles": ["admin"] })),
            ),
            ("GET", format!("/users/{ada}"), None),
            (
                "PATCH",
                format!("/users/{own}"),
                Some(json!({ "display_name": "Boss" })),
            ),
            ("DELETE", format!("/users/{ada}"), None),
            ("POST", format!("/users/{ada}/unlock"), None),
            ("DELETE", format!("/users/{ada}/sessions"), None),
            (
                "PUT",
                format!("/users/{own}/roles"),
                Some(json!({ "roles": ["admin"] })),
            ),
            (
                "PUT",
                "/system/break-glass".to_owned(),
                Some(json!({ "user_id": ada, "enabled": true })),
            ),
        ];
        for (method, path, body) in attempts {
            let reply: Reply = harness
                .call(method, &path, Cookie(&session), body.as_ref())
                .await;
            reply.assert_problem(403, "auth.forbidden");
            assert!(reply.body["params"]["kind"].is_string(), "{method} {path}");
        }
        // Nothing changed.
        let still = harness
            .call("GET", &format!("/users/{own}"), Cookie(&admin), None)
            .await;
        assert_eq!(still.body["roles"], json!(["viewer"]));
        assert_eq!(still.body["display_name"], "vera");
        // The role list is open to every authenticated caller.
        harness
            .call("GET", "/roles", Cookie(&session), None)
            .await
            .assert_status(200);
    }

    #[tokio::test]
    async fn roles_are_listed_for_any_authenticated_caller() {
        let (harness, admin) = Harness::installed().await;
        harness
            .create_user(&admin, "oscar", "7391", &["operator"])
            .await;
        let operator = harness.login("oscar", "7391").await;
        for session in [&admin, &operator] {
            let roles = harness.call("GET", "/roles", Cookie(session), None).await;
            roles.assert_status(200);
            assert_eq!(roles.body["next_cursor"], Value::Null);
            assert!(roles.body["revision"].is_u64());
            let names: Vec<&str> = roles.body["items"]
                .as_array()
                .expect("items")
                .iter()
                .map(|item| item["name"].as_str().expect("a name"))
                .collect();
            assert_eq!(names, ["admin", "operator", "viewer"]);
            assert!(
                roles.body["items"]
                    .as_array()
                    .expect("items")
                    .iter()
                    .all(|item| item["description"]
                        .as_str()
                        .is_some_and(|text| !text.is_empty()))
            );
        }
        harness
            .call("GET", "/roles", Anonymous, None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call("GET", "/roles", Cookie("nope"), None)
            .await
            .assert_problem(401, "auth.unauthenticated");
    }

    #[tokio::test]
    async fn break_glass_needs_a_strong_fresh_authentication_and_a_hardware_key() {
        let (harness, admin) = Harness::installed().await;
        let own = admin_id(&harness, &admin).await;
        let designate = json!({ "user_id": own, "enabled": true });

        // A PIN session is not strong enough, and the body is checked.
        harness
            .call(
                "PUT",
                "/system/break-glass",
                Cookie(&admin),
                Some(&designate),
            )
            .await
            .assert_problem(403, "auth.step_up_required");
        harness
            .call(
                "PUT",
                "/system/break-glass",
                Cookie(&admin),
                Some(&json!({ "enabled": true })),
            )
            .await
            .assert_problem(400, "sys.invalid_request");
        harness
            .call("PUT", "/system/break-glass", Anonymous, Some(&designate))
            .await
            .assert_problem(401, "auth.unauthenticated");

        // A passkey session is, but the account needs an attested hardware key first.
        let strong = harness.passkey_session(&admin, ADMIN).await;
        harness
            .call(
                "PUT",
                "/system/break-glass",
                Cookie(&strong),
                Some(&designate),
            )
            .await
            .assert_problem(400, "auth.invalid_request");
        harness
            .call(
                "PUT",
                "/system/break-glass",
                Cookie(&strong),
                Some(&json!({ "user_id": SOME_ID, "enabled": true })),
            )
            .await
            .assert_problem(404, "users.not_found");
        // Releasing an account that is not a break-glass account changes nothing: no write,
        // no audit record.
        let released = harness
            .call(
                "PUT",
                "/system/break-glass",
                Cookie(&strong),
                Some(&json!({ "user_id": own, "enabled": false })),
            )
            .await;
        released.assert_status(200);
        assert_eq!(released.body["break_glass"], false);
        assert_eq!(
            released.header("etag"),
            Some(etag(revision(&released.body)).as_str())
        );
        assert!(
            !harness
                .audit_actions()
                .await
                .contains(&"auth.break_glass.set".to_owned())
        );
    }

    #[tokio::test]
    async fn user_endpoints_refuse_malformed_ids_and_anonymous_callers() {
        let (harness, admin) = Harness::installed().await;
        let endpoints: [(&str, &str, Option<Value>); 6] = [
            ("GET", "", None),
            ("PATCH", "", Some(json!({ "display_name": "x" }))),
            ("DELETE", "", None),
            ("POST", "/unlock", None),
            ("DELETE", "/sessions", None),
            ("PUT", "/roles", Some(json!({ "roles": ["viewer"] }))),
        ];
        for (method, suffix, body) in endpoints {
            let malformed = format!("/users/not-a-uuid{suffix}");
            harness
                .call(method, &malformed, Cookie(&admin), body.as_ref())
                .await
                .assert_problem(400, "sys.invalid_value");
            let anonymous = format!("/users/{SOME_ID}{suffix}");
            harness
                .call(method, &anonymous, Anonymous, body.as_ref())
                .await
                .assert_problem(401, "auth.unauthenticated");
        }
        for (method, body) in [
            ("GET", None),
            ("POST", Some(json!({ "name": "x", "roles": ["viewer"] }))),
        ] {
            harness
                .call(method, "/users", Anonymous, body.as_ref())
                .await
                .assert_problem(401, "auth.unauthenticated");
        }
        // A token reads with the rights of its owner but never administers.
        let token = harness
            .call(
                "POST",
                "/auth/tokens",
                Cookie(&admin),
                Some(&json!({ "name": "ops" })),
            )
            .await;
        let token = token.body["token"].as_str().expect("a token").to_owned();
        harness
            .call("GET", "/users", Bearer(&token), None)
            .await
            .assert_status(200);
        harness
            .call("GET", "/roles", Bearer(&token), None)
            .await
            .assert_status(200);
        let own = admin_id(&harness, &admin).await;
        harness
            .call("GET", &format!("/users/{own}"), Bearer(&token), None)
            .await
            .assert_status(200);
        for (method, path, body) in [
            (
                "POST",
                "/users".to_owned(),
                Some(json!({ "name": "eve", "roles": ["admin"] })),
            ),
            (
                "PATCH",
                format!("/users/{own}"),
                Some(json!({ "display_name": "Mallory" })),
            ),
            ("DELETE", format!("/users/{SOME_ID}"), None),
            ("POST", format!("/users/{SOME_ID}/unlock"), None),
            ("DELETE", format!("/users/{SOME_ID}/sessions"), None),
            (
                "PUT",
                format!("/users/{own}/roles"),
                Some(json!({ "roles": ["viewer"] })),
            ),
        ] {
            harness
                .call(method, &path, Bearer(&token), body.as_ref())
                .await
                .assert_problem(403, "auth.forbidden");
        }
    }
}
