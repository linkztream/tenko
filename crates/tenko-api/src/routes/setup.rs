//! First-run setup (API-10).
//!
//! Area: setup. Owner: WP1.2. Open only before setup has completed: `GET /setup` reports
//! the state, `POST /setup` takes the one-time setup token, the profile, the first
//! administrator, the host name and the language, and returns a session.
//!
//! Both endpoints are public (they take no [`Ctx`](crate::extract::Ctx)): there is no user
//! yet. The one-time token printed at server start is the credential, and the service
//! throttles wrong tokens.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /setup` | 200 `SetupState`: `open`, and the profiles to choose from while open | 503 |
//! | `POST /setup` | 200 `SetupResponse` (the session plus `ca_fingerprint` in internal CA mode) with `Set-Cookie`: the first administrator is logged in | 400 `auth.setup.invalid_host_name`, `auth.invalid_request`, 401 `auth.setup.token_invalid`, 409 `auth.setup.closed`, 422 `auth.password.policy`, 429 `auth.throttled`, 503 |

use std::sync::Arc;

use axum::{Extension, Json, http::StatusCode, response::Response};
use serde::Serialize;
use tenko_auth::service::{SessionInfo, SetupRequest, SetupState};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::auth::{ApiJson, PublicCtx, RouteError, Svc, Unavailable, secret_json};
use super::system::CaRootSource;
use crate::{problem::ProblemDetails, state::AppState};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_setup, complete_setup))
}

/// Reports whether first-run setup is still open and, while it is, the security profiles
/// to choose from with their toggle values.
#[utoipa::path(
    get,
    path = "/setup",
    tag = "setup",
    operation_id = "get_setup",
    summary = "Report whether first-run setup is still open",
    responses(
        (status = 200, description = "The setup state; the profiles are listed while setup is open", body = SetupState),
        Unavailable
    )
)]
async fn get_setup(Svc(service): Svc) -> Result<Json<SetupState>, RouteError> {
    Ok(Json(service.setup_state().await?))
}

/// The answer of `POST /setup`: the administrator's new session, plus the SHA-256 fingerprint
/// of the internal CA root when the installation runs the internal CA, so that the wizard can
/// offer the root for installation and the fingerprint to compare it with.
#[derive(Debug, Serialize, ToSchema)]
pub struct SetupResponse {
    /// The session, with the members of `SessionInfo`.
    #[serde(flatten)]
    pub session: SessionInfo,
    /// SHA-256 fingerprint (hex) of the internal CA root; absent in the other TLS modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
}

/// Completes first-run setup: stores the settings of the chosen profile, creates the first
/// administrator and the installation record, closes setup and logs the administrator in.
#[utoipa::path(
    post,
    path = "/setup",
    tag = "setup",
    operation_id = "complete_setup",
    summary = "Complete first-run setup and start a session",
    request_body = SetupRequest,
    responses(
        (status = 200, description = "Setup is complete; the administrator is logged in", body = SetupResponse,
            headers(("Set-Cookie" = String, description = "The session cookie `tenko_session`"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`), or the host name, user name or language is invalid (`auth.setup.invalid_host_name`, `auth.invalid_request`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "The setup token is wrong (`auth.setup.token_invalid`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Setup has already been completed (`auth.setup.closed`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The password breaks the policy of the chosen profile (`auth.password.policy`, with the violations in `errors`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Too many wrong setup tokens (`auth.throttled`); `Retry-After` gives the seconds", body = ProblemDetails, content_type = "application/problem+json"),
        Unavailable
    )
)]
async fn complete_setup(
    Svc(service): Svc,
    PublicCtx { ctx, user_agent }: PublicCtx,
    ca_root: Option<Extension<Arc<CaRootSource>>>,
    ApiJson(request): ApiJson<SetupRequest>,
) -> Result<Response, RouteError> {
    let session = service
        .complete_setup(&ctx, user_agent.as_deref(), &request)
        .await?;
    let ca_fingerprint = ca_root
        .and_then(|Extension(source)| source.fingerprint())
        .map(|fingerprint| fingerprint.to_string());
    let answer = SetupResponse {
        session: session.info.clone(),
        ca_fingerprint,
    };
    secret_json(StatusCode::OK, Some(&session.set_cookie), &answer)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tenko_auth::testing::env::{ADMIN_PIN, HOST};

    use super::super::auth::testkit::{Credential::*, Harness};

    /// A setup request for the Home profile.
    fn body(token: &str) -> Value {
        json!({
            "setup_token": token,
            "profile": "home",
            "admin": { "name": "root", "display_name": "Root", "password": ADMIN_PIN },
            "host_name": HOST,
            "language": "sv"
        })
    }

    async fn token(harness: &Harness) -> String {
        harness
            .env
            .service
            .prepare_setup()
            .await
            .expect("prepare")
            .expect("setup is open")
            .expose()
            .to_owned()
    }

    #[tokio::test]
    async fn setup_is_open_before_and_closed_after() {
        let harness = Harness::fresh().await;
        let open = harness.call("GET", "/setup", Anonymous, None).await;
        open.assert_status(200);
        assert_eq!(open.body["open"], true);
        let profiles = open.body["profiles"].as_array().expect("profiles");
        let names: Vec<&str> = profiles
            .iter()
            .map(|profile| profile["profile"].as_str().expect("a profile"))
            .collect();
        assert_eq!(names, ["home", "standard", "hardened", "lab"]);
        assert_eq!(profiles[0]["settings"]["password_policy"]["preset"], "pin");
        assert_eq!(profiles[3]["banner"]["lab"], true);

        harness
            .env
            .setup(tenko_auth::settings::Profile::Home)
            .await
            .expect("setup");
        let closed = harness.call("GET", "/setup", Anonymous, None).await;
        closed.assert_status(200);
        assert_eq!(closed.body["open"], false);
        assert!(closed.body.get("profiles").is_none());
    }

    #[tokio::test]
    async fn setup_creates_the_administrator_and_logs_in() {
        let harness = Harness::fresh().await;
        let token = token(&harness).await;
        let reply = harness
            .call_with(
                "POST",
                "/setup",
                Anonymous,
                Some(&body(&token)),
                &[("User-Agent", "setup-test/1.0")],
            )
            .await;
        reply.assert_status(200);
        assert_eq!(reply.header("cache-control"), Some("no-store"));
        assert_eq!(reply.body["user"]["name"], "root");
        assert_eq!(reply.body["user"]["display_name"], "Root");
        assert_eq!(reply.body["roles"], json!(["admin"]));
        assert_eq!(reply.body["profile"], "home");
        assert_eq!(reply.body["strength"], "pin");
        assert_eq!(reply.body["default_language"], "sv");
        let cookies = reply.set_cookies();
        assert_eq!(cookies.len(), 1);
        for attribute in [
            "tenko_session=",
            "HttpOnly",
            "SameSite=Strict",
            "Secure",
            "Path=/",
        ] {
            assert!(
                cookies[0].contains(attribute),
                "{attribute} in {}",
                cookies[0]
            );
        }
        // Neither the token nor the PIN nor the cookie secret appears in the body.
        let text = reply.body.to_string();
        assert!(!text.contains(&token) && !text.contains(&reply.session_secret()));

        // The cookie is a working session of the new administrator.
        let secret = reply.session_secret();
        let session = harness
            .call("GET", "/auth/session", Cookie(&secret), None)
            .await;
        session.assert_status(200);
        assert_eq!(session.body["user"]["name"], "root");
        harness
            .call("GET", "/users", Cookie(&secret), None)
            .await
            .assert_status(200);
        // The administrator can log in again, and the settings are those of the profile.
        harness.login("root", ADMIN_PIN).await;
        let settings = harness
            .call("GET", "/settings/security", Cookie(&secret), None)
            .await;
        assert_eq!(settings.body["settings"]["profile"], "home");
        assert!(
            harness
                .audit_actions()
                .await
                .contains(&"auth.setup.complete".to_owned())
        );
        let installation = harness.env.service.installation().await.expect("read");
        assert_eq!(installation.expect("installed").host_name, HOST);
    }

    #[tokio::test]
    async fn setup_cannot_run_twice() {
        let harness = Harness::fresh().await;
        let token = token(&harness).await;
        harness
            .call("POST", "/setup", Anonymous, Some(&body(&token)))
            .await
            .assert_status(200);
        let again = harness
            .call("POST", "/setup", Anonymous, Some(&body(&token)))
            .await;
        again.assert_problem(409, "auth.setup.closed");
        assert_eq!(again.body["title"], "Setup is closed");
        assert_eq!(again.set_cookies().len(), 0);
        // Even a request with a wrong token only learns that setup is closed.
        harness
            .call(
                "POST",
                "/setup",
                Anonymous,
                Some(&body("AAAAA-AAAAA-AAAAA-AAAAA")),
            )
            .await
            .assert_problem(409, "auth.setup.closed");
    }

    #[tokio::test]
    async fn setup_refuses_a_wrong_token_a_bad_host_and_a_weak_password() {
        let harness = Harness::fresh().await;
        // Before the server prepared a token, none is right.
        harness
            .call(
                "POST",
                "/setup",
                Anonymous,
                Some(&body("AAAAA-AAAAA-AAAAA-AAAAA")),
            )
            .await
            .assert_problem(401, "auth.setup.token_invalid");
        let token = token(&harness).await;
        harness
            .call(
                "POST",
                "/setup",
                Anonymous,
                Some(&body("AAAAA-AAAAA-AAAAA-AAAAA")),
            )
            .await
            .assert_problem(401, "auth.setup.token_invalid");

        let mut bad_host = body(&token);
        bad_host["host_name"] = json!("192.0.2.10");
        let reply = harness
            .call("POST", "/setup", Anonymous, Some(&bad_host))
            .await;
        reply.assert_problem(400, "auth.setup.invalid_host_name");
        assert_eq!(reply.body["params"]["host_name"], "192.0.2.10");

        let mut weak = body(&token);
        weak["admin"]["password"] = json!("abc");
        let reply = harness.call("POST", "/setup", Anonymous, Some(&weak)).await;
        reply.assert_problem(422, "auth.password.policy");
        assert_ne!(
            reply.body["errors"].as_array().expect("violations").len(),
            0
        );
        assert!(!reply.body.to_string().contains("abc\""));

        let mut language = body(&token);
        language["language"] = json!("de");
        harness
            .call("POST", "/setup", Anonymous, Some(&language))
            .await
            .assert_problem(400, "auth.invalid_request");
        let mut name = body(&token);
        name["admin"]["name"] = json!("two words");
        harness
            .call("POST", "/setup", Anonymous, Some(&name))
            .await
            .assert_problem(400, "auth.invalid_request");

        // None of the failures closed setup, and the right request still works.
        let state = harness.call("GET", "/setup", Anonymous, None).await;
        assert_eq!(state.body["open"], true);
        harness
            .call("POST", "/setup", Anonymous, Some(&body(&token)))
            .await
            .assert_status(200);
    }

    #[tokio::test]
    async fn setup_refuses_malformed_bodies_with_problem_details() {
        let harness = Harness::fresh().await;
        let token = token(&harness).await;
        let reply = harness
            .call(
                "POST",
                "/setup",
                Anonymous,
                Some(&json!({ "setup_token": token })),
            )
            .await;
        reply.assert_problem(400, "sys.invalid_request");
        assert!(
            ["profile", "admin", "host_name"].contains(
                &reply.body["params"]["field"]
                    .as_str()
                    .expect("a missing field")
            )
        );
        assert!(!reply.body.to_string().contains(&token));
        let mut unknown = body(&token);
        unknown["profile"] = json!("secure");
        harness
            .call("POST", "/setup", Anonymous, Some(&unknown))
            .await
            .assert_problem(400, "sys.invalid_request");
        harness
            .call("POST", "/setup", Anonymous, None)
            .await
            .assert_problem(400, "sys.invalid_request");
    }

    #[tokio::test]
    async fn repeated_wrong_tokens_are_throttled() {
        let harness = Harness::fresh().await;
        let token = token(&harness).await;
        let mut throttled = None;
        for _ in 0..30 {
            let reply = harness
                .call(
                    "POST",
                    "/setup",
                    Anonymous,
                    Some(&body("AAAAA-AAAAA-AAAAA-AAAAA")),
                )
                .await;
            if reply.status.as_u16() == 429 {
                throttled = Some(reply);
                break;
            }
            reply.assert_problem(401, "auth.setup.token_invalid");
        }
        let reply = throttled.expect("wrong tokens are slowed down");
        reply.assert_problem(429, "auth.throttled");
        let retry = reply.body["params"]["retry_after"]
            .as_str()
            .expect("seconds");
        assert_eq!(reply.header("retry-after"), Some(retry));
        // The right token waits its turn as well.
        harness
            .call("POST", "/setup", Anonymous, Some(&body(&token)))
            .await
            .assert_problem(429, "auth.throttled");
    }

    #[tokio::test]
    async fn setup_is_unavailable_without_the_service() {
        for (method, request_body) in [
            ("GET", None),
            ("POST", Some(body("AAAAA-AAAAA-AAAAA-AAAAA"))),
        ] {
            let reply = super::super::auth::testkit::send_to(
                crate::router(),
                super::super::auth::testkit::request(
                    method,
                    "/setup",
                    Anonymous,
                    request_body.as_ref(),
                    &[],
                ),
            )
            .await;
            reply.assert_problem(503, "auth.unavailable");
        }
    }
}
