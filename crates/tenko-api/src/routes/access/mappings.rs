//! Directory mappings: directory groups onto roles and scopes (identity plan section 3.16
//! and 4.3; WP13.0 declares the routes, WP13.5 builds them on the directory service).
//!
//! Area: access. Owner: WP13.0 (the contracts). Requirements: IAM-12, IAM-01.
//!
//! A mapping is evaluated at sign-in and at each directory check and held on the session;
//! it is never written as a grant, so removing a user from a group takes effect at the
//! next sign-in or check (ID-Q14). The routes check the caller's right on the settings
//! (administrators; an interactive session for a change) and answer `501` with
//! `sys.not_implemented` until WP13.5 replaces them.
//!
//! | Endpoint | Check | Purpose |
//! |---|---|---|
//! | `GET /access/directory-mappings` | Read on settings | List the mappings, with the users last mapped by each |
//! | `POST /access/directory-mappings` | Update on settings, interactive | Create a mapping |
//! | `DELETE /access/directory-mappings/{id}` | Update on settings, interactive | Delete a mapping |

use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use serde::{Deserialize, Serialize};
use tenko_auth::{
    authz::anywhere,
    directory::{DirectoryMapping, GroupMatch, MappingId, ProviderId},
    roles::RoleName,
};
use tenko_core::{Action, ObjectKind, ScopeRule, Timestamp};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::Page,
    extract::Ctx,
    list::PageParams,
    problem::{ApiError, ProblemDetails},
    routes::{auth::ApiJson, not_implemented},
    state::AppState,
};

/// The routes of the directory mappings.
#[inline(never)]
pub(super) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_directory_mappings, create_directory_mapping))
        .routes(routes!(delete_directory_mapping))
}

/// Filters of `GET /access/directory-mappings`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct MappingFilters {
    /// Only the mappings of this provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
}

/// A user the mapping gave rights to at a sign-in or a check.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MappedUser {
    /// The user.
    pub user: tenko_core::UserId,
    /// The display name.
    pub display_name: String,
    /// When the mapping last applied to the user.
    pub at: Timestamp,
}

/// A mapping as the API shows it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MappingItem {
    /// The mapping.
    #[serde(flatten)]
    pub mapping: DirectoryMapping,
    /// The users the mapping applied to at their last sign-in or check.
    #[serde(default)]
    pub users: Vec<MappedUser>,
}

/// Body of `POST /access/directory-mappings`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MappingCreate {
    /// The provider.
    pub provider: ProviderId,
    /// The group: a SID, a DN or a claim value.
    pub group: GroupMatch,
    /// The role.
    pub role: RoleName,
    /// Where the role applies; absent for the whole installation. `admin` and `auditor`
    /// take none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<tenko_auth::service::types::ScopeRuleSchema>)]
    pub scope: Option<ScopeRule>,
}

#[utoipa::path(
    get,
    path = "/access/directory-mappings",
    tag = "access",
    operation_id = "list_directory_mappings",
    summary = "List the directory mappings",
    description = "Reads the settings (administrators and operators). The mappings of every provider, each with the users it applied to at their last sign-in or directory check.",
    params(PageParams, MappingFilters),
    responses(
        (status = 200, description = "A page of mappings by provider and group", body = Page<MappingItem>),
        (status = 400, description = "The request is malformed (`sys.invalid_query`, `sys.invalid_cursor`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not read the settings", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
async fn list_directory_mappings(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Query(_page): Query<PageParams>,
    Query(_filters): Query<MappingFilters>,
) -> Result<Response, ApiError> {
    app.authorize(&cx.principal, Action::Read, &anywhere(ObjectKind::Settings))?;
    Err(not_implemented("GET", "/access/directory-mappings"))
}

#[utoipa::path(
    post,
    path = "/access/directory-mappings",
    tag = "access",
    operation_id = "create_directory_mapping",
    summary = "Create a directory mapping",
    description = "Administrators, in an interactive session. A group of a provider onto a role, with a scope for `operator` and `viewer`. Audited as `auth.mapping.create`.",
    request_body(content = MappingCreate, content_type = "application/json"),
    responses(
        (status = 201, description = "The mapping", body = MappingItem),
        (status = 400, description = "The request is malformed (`sys.invalid_request`) or the mapping is invalid (`auth.directory.mapping_invalid`, parameters `field` and `reason`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the settings, or a token tries to", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The provider does not exist (`auth.provider.not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The same group, role and scope is mapped already (`auth.directory.mapping_duplicate`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn create_directory_mapping(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    ApiJson(_body): ApiJson<MappingCreate>,
) -> Result<Response, ApiError> {
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::Settings),
    )?;
    Err(not_implemented("POST", "/access/directory-mappings"))
}

#[utoipa::path(
    delete,
    path = "/access/directory-mappings/{id}",
    tag = "access",
    operation_id = "delete_directory_mapping",
    summary = "Delete a directory mapping",
    description = "Administrators, in an interactive session. The rights it gave end at the users' next sign-in or directory check. Audited as `auth.mapping.delete`.",
    params(("id" = String, Path, description = "Mapping identifier (UUID)")),
    responses(
        (status = 204, description = "The mapping is gone"),
        (status = 400, description = "The request is malformed (`sys.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "No valid session or token", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The principal may not change the settings, or a token tries to", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The mapping does not exist (`auth.directory.mapping_not_found`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 501, description = "Not built yet (`sys.not_implemented`)", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("session" = []))
)]
async fn delete_directory_mapping(
    State(app): State<AppState>,
    Ctx(cx): Ctx,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let _id: MappingId = id.parse().map_err(|_| {
        ApiError::from_coded_error(
            tenko_core::CodedError::new(
                tenko_core::error::codes::INVALID_REQUEST,
                400,
                "the identifier is not a UUID",
            )
            .with_title("Invalid request")
            .with_param("field", "id"),
        )
    })?;
    app.authorize(
        &cx.principal,
        Action::Update,
        &anywhere(ObjectKind::Settings),
    )?;
    Err(not_implemented("DELETE", "/access/directory-mappings/{id}"))
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
    use tenko_auth::authz::anywhere;
    use tenko_core::{Action, Authorizer, ObjectKind};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;

    use super::routes;
    use crate::{
        API_BASE,
        routes::tenancy::testkit::{Policy, Reply},
        state::AppState,
    };

    const ID: &str = "0190d1c2-0000-7000-8000-000000000001";
    const STUB: &str = "sys.not_implemented";

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

    fn mapping() -> Value {
        json!({
            "provider": ID,
            "group": { "kind": "sid", "sid": "S-1-5-21-1004336348-1177238915-682003330-1105" },
            "role": "operator"
        })
    }

    #[tokio::test]
    async fn every_route_checks_the_settings_then_answers_the_stub() {
        let policy = Policy::new(true, true);
        let router = router(Arc::clone(&policy));
        send(&router, "GET", "/access/directory-mappings", None)
            .await
            .assert_problem(501, STUB);
        send(
            &router,
            "POST",
            "/access/directory-mappings",
            Some(mapping()),
        )
        .await
        .assert_problem(501, STUB);
        send(
            &router,
            "DELETE",
            &format!("/access/directory-mappings/{ID}"),
            None,
        )
        .await
        .assert_problem(501, STUB);
        let settings = anywhere(ObjectKind::Settings);
        assert_eq!(
            policy.asked(),
            [
                (Action::Read, settings),
                (Action::Update, settings),
                (Action::Update, settings),
            ]
        );
    }

    #[tokio::test]
    async fn a_reader_is_refused_changes_and_a_bad_body_or_path_answers_first() {
        let policy = Policy::new(true, false);
        let router = router(Arc::clone(&policy));
        send(
            &router,
            "POST",
            "/access/directory-mappings",
            Some(mapping()),
        )
        .await
        .assert_problem(403, "auth.forbidden");
        let reply = send(
            &router,
            "POST",
            "/access/directory-mappings",
            Some(json!({ "provider": ID, "group": { "kind": "sid", "sid": "nope" }, "role": "operator" })),
        )
        .await;
        assert_eq!(reply.status.as_u16(), 400, "{}", reply.body);
        send(
            &router,
            "DELETE",
            "/access/directory-mappings/not-a-uuid",
            None,
        )
        .await
        .assert_problem(400, "sys.invalid_request");
        assert_eq!(policy.asked().len(), 1, "{:?}", policy.asked());
    }
}
