//! Security settings.
//!
//! Area: settings. Owner: WP1.2. Requirements: TGL-01, TGL-02, TGL-04, TGL-05.
//!
//! The security profile, its toggles and deviations. Every change is audited.
//!
//! | Endpoint | Success | Errors |
//! |---|---|---|
//! | `GET /settings/security` | 200 `SecuritySettingsView` with `ETag: "<revision>"` | 401, 403, 503 |
//! | `PATCH /settings/security` | 200 `SecuritySettingsView` with the new `ETag` | 400, 401, 403, 409 `auth.conflict` or `settings.pin_coupling`, 503 |
//! | `PUT /settings/default-language` | 200 `DefaultLanguage` | 400 `auth.invalid_request` (field `language`), 401, 403, 409, 503 |
//!
//! `PATCH` takes a `SettingsPatch`: a new profile resets every toggle first, explicit
//! toggles apply on top. `If-Match: "<revision>"` makes the change conditional on the
//! revision the client read (`W/"<revision>"` and the bare number are accepted too).

use axum::{
    Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use tenko_auth::{
    service::{DefaultLanguage, SecuritySettingsView},
    settings::SettingsPatch,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::auth::{
    ApiJson, Forbidden, RouteError, Svc, Unauthenticated, Unavailable, if_match, with_etag,
};
use crate::{extract::Ctx, problem::ProblemDetails, state::AppState};

pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_security_settings, update_security_settings))
        .routes(routes!(set_default_language))
}

/// The view as a response, with its revision as `ETag` once setup has stored settings.
fn view_response(view: SecuritySettingsView) -> Response {
    let revision = view.revision;
    let response = Json(view).into_response();
    match revision {
        Some(revision) => with_etag(response, revision),
        None => response,
    }
}

/// Reads the security profile, the values of the toggles TGL-01 to TGL-07, TGL-23 and
/// TGL-24 with their profile defaults and deviations, and the warning banner state.
#[utoipa::path(
    get,
    path = "/settings/security",
    tag = "settings",
    operation_id = "get_security_settings",
    summary = "Get the security profile, toggles and deviations",
    responses(
        (status = 200, description = "The settings, each toggle with its profile default and markers, and the banner", body = SecuritySettingsView,
            headers(("ETag" = String, description = "The revision of the settings, for `If-Match`"))),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []), ("token" = []))
)]
async fn get_security_settings(Svc(service): Svc, Ctx(ctx): Ctx) -> Result<Response, RouteError> {
    Ok(view_response(service.security_settings(&ctx).await?))
}

/// Changes the profile or single toggles. Every change is audited with the old and the new
/// value of each changed toggle.
#[utoipa::path(
    patch,
    path = "/settings/security",
    tag = "settings",
    operation_id = "update_security_settings",
    summary = "Change the security profile, toggles or deviations",
    params(("If-Match" = Option<String>, Header, description = "The revision the client read, as in the `ETag`; a stale revision is refused with 409")),
    request_body = SettingsPatch,
    responses(
        (status = 200, description = "The settings after the change", body = SecuritySettingsView,
            headers(("ETag" = String, description = "The new revision of the settings"))),
        (status = 400, description = "The body is malformed (`sys.invalid_request`), a value is invalid (`auth.invalid_request`) or `If-Match` is malformed (`sys.invalid_value`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "`If-Match` is stale (`auth.conflict`), or a PIN would be the only factor while the vault holds operator secrets (`settings.pin_coupling`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn update_security_settings(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    headers: HeaderMap,
    ApiJson(patch): ApiJson<SettingsPatch>,
) -> Result<Response, RouteError> {
    let expect = if_match(&headers)?;
    Ok(view_response(
        service
            .update_security_settings(&ctx, &patch, expect)
            .await?,
    ))
}

/// Sets the default UI language of the installation (API-21): a built-in language or an
/// active language pack. Users without a fixed language and the sign-in page use it.
#[utoipa::path(
    put,
    path = "/settings/default-language",
    tag = "settings",
    operation_id = "set_default_language",
    summary = "Set the default language of the installation",
    request_body = DefaultLanguage,
    responses(
        (status = 200, description = "The default language now in force", body = DefaultLanguage),
        (status = 400, description = "The body is malformed (`sys.invalid_request`) or the tag is not an active language (`auth.invalid_request`, field `language`)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "A concurrent change (`auth.conflict`)", body = ProblemDetails, content_type = "application/problem+json"),
        Unauthenticated,
        Forbidden,
        Unavailable
    ),
    security(("session" = []))
)]
async fn set_default_language(
    Svc(service): Svc,
    Ctx(ctx): Ctx,
    ApiJson(request): ApiJson<DefaultLanguage>,
) -> Result<Json<DefaultLanguage>, RouteError> {
    let language = service
        .set_default_language(&ctx, &request.language)
        .await?;
    Ok(Json(DefaultLanguage { language }))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tenko_core::audit::AuditDraft;

    use super::super::auth::testkit::{Credential::*, Harness, Reply};

    fn revision(body: &Value) -> u64 {
        body["revision"].as_u64().expect("a revision")
    }

    fn etag(revision: u64) -> String {
        format!("\"{revision}\"")
    }

    fn toggle<'a>(body: &'a Value, id: &str) -> &'a Value {
        body["toggles"]
            .as_array()
            .expect("toggles")
            .iter()
            .find(|toggle| toggle["id"] == id)
            .unwrap_or_else(|| panic!("toggle {id}"))
    }

    /// Patches the settings; the answer is returned as it is.
    async fn patch(harness: &Harness, admin: &str, body: Value) -> Reply {
        harness
            .call("PATCH", "/settings/security", Cookie(admin), Some(&body))
            .await
    }

    /// The audit records of settings changes.
    async fn settings_updates(harness: &Harness) -> Vec<AuditDraft> {
        harness
            .audit()
            .await
            .into_iter()
            .filter(|draft| draft.action.as_str() == "auth.settings.update")
            .collect()
    }

    async fn read(harness: &Harness, admin: &str) -> Reply {
        let reply = harness
            .call("GET", "/settings/security", Cookie(admin), None)
            .await;
        reply.assert_status(200);
        reply
    }

    #[tokio::test]
    async fn the_settings_are_read_with_toggles_and_an_etag() {
        let (harness, admin) = Harness::installed().await;
        let reply = read(&harness, &admin).await;
        assert_eq!(
            reply.header("etag"),
            Some(etag(revision(&reply.body)).as_str())
        );
        assert_eq!(reply.body["settings"]["profile"], "home");
        assert_eq!(reply.body["settings"]["password_policy"]["preset"], "pin");
        assert_eq!(reply.body["settings"]["mfa"], "optional");
        assert_eq!(reply.body["settings"]["lockout"], "progressive_delay");
        assert_eq!(reply.body["settings"]["breach_check"], "online");
        let toggles = reply.body["toggles"].as_array().expect("toggles");
        let ids: Vec<&str> = toggles
            .iter()
            .map(|toggle| toggle["id"].as_str().expect("an id"))
            .collect();
        assert_eq!(
            ids,
            [
                "TGL-01", "TGL-02", "TGL-03", "TGL-04", "TGL-05", "TGL-06", "TGL-07", "TGL-21",
                "TGL-23", "TGL-24"
            ]
        );
        for toggle in toggles {
            assert_eq!(toggle["deviates"], false, "{toggle}");
            assert_eq!(toggle["value"], toggle["profile_default"], "{toggle}");
        }
        assert_eq!(toggle(&reply.body, "TGL-07")["setting"], "lockout");
        assert_eq!(reply.body["banner"]["lab"], false);
        assert_eq!(reply.body["banner"]["weaker_than_home"], false);
        assert_eq!(reply.body["banner"]["deviations"], json!([]));
        assert!(reply.body["vault_has_operator_secrets"].is_boolean());
    }

    #[tokio::test]
    async fn a_change_is_applied_audited_and_versioned() {
        let (harness, admin) = Harness::installed().await;
        let before = read(&harness, &admin).await;
        let first = revision(&before.body);
        assert_eq!(settings_updates(&harness).await.len(), 0);

        let changed = harness
            .call_with(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&json!({ "lockout": "lock_until_unlock", "breach_check": "off" })),
                &[("If-Match", &etag(first))],
            )
            .await;
        changed.assert_status(200);
        let second = revision(&changed.body);
        assert!(second > first);
        assert_eq!(changed.header("etag"), Some(etag(second).as_str()));
        assert_eq!(changed.body["settings"]["lockout"], "lock_until_unlock");
        assert_eq!(changed.body["settings"]["breach_check"], "off");
        // The profile stays Home; the two toggles deviate, and one is weaker than Home.
        assert_eq!(changed.body["settings"]["profile"], "home");
        assert_eq!(toggle(&changed.body, "TGL-07")["deviates"], true);
        assert_eq!(
            toggle(&changed.body, "TGL-07")["profile_default"],
            "progressive_delay"
        );
        assert_eq!(toggle(&changed.body, "TGL-06")["weaker_than_home"], true);
        assert_eq!(toggle(&changed.body, "TGL-01")["deviates"], false);
        assert_eq!(changed.body["banner"]["weaker_than_home"], true);
        assert_eq!(
            changed.body["banner"]["deviations"],
            json!(["TGL-06", "TGL-07"])
        );

        // The change is what the next read says, and it is audited with old and new values.
        let after = read(&harness, &admin).await;
        assert_eq!(after.body, changed.body);
        let audit = settings_updates(&harness).await;
        assert_eq!(audit.len(), 1);
        let fields: Vec<&str> = audit[0]
            .details
            .changes
            .iter()
            .map(|change| change.field.as_str())
            .collect();
        assert_eq!(fields, ["TGL-06", "TGL-07"]);
        let lockout = audit[0]
            .details
            .changes
            .iter()
            .find(|change| change.field == "TGL-07")
            .expect("the lockout change");
        assert!(
            lockout
                .old
                .as_deref()
                .is_some_and(|old| old.contains("progressive_delay"))
        );
        assert!(
            lockout
                .new
                .as_deref()
                .is_some_and(|new| new.contains("lock_until_unlock"))
        );

        // A request that changes nothing is accepted and not audited.
        let same = harness
            .call(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&json!({})),
            )
            .await;
        same.assert_status(200);
        assert_eq!(revision(&same.body), second);
        assert_eq!(settings_updates(&harness).await.len(), 1);
    }

    #[tokio::test]
    async fn a_profile_replaces_the_toggles() {
        let (harness, admin) = Harness::installed().await;
        let changed = harness
            .call(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&json!({ "profile": "lab", "token_max_lifetime": "unlimited" })),
            )
            .await;
        changed.assert_status(200);
        assert_eq!(changed.body["settings"]["profile"], "lab");
        assert_eq!(changed.body["settings"]["lockout"], "off");
        assert_eq!(changed.body["settings"]["token_max_days"], Value::Null);
        assert_eq!(changed.body["banner"]["lab"], true);
        assert_eq!(changed.body["banner"]["deviations"], json!([]));
        let days = harness
            .call(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&json!({ "token_max_lifetime": { "days": 14 } })),
            )
            .await;
        days.assert_status(200);
        assert_eq!(days.body["settings"]["token_max_days"], 14);
        assert_eq!(toggle(&days.body, "TGL-05")["deviates"], true);
    }

    #[tokio::test]
    async fn if_match_guards_the_settings() {
        let (harness, admin) = Harness::installed().await;
        let first = revision(&read(&harness, &admin).await.body);
        let patch = |mode: &str| json!({ "lockout": mode });
        let second = harness
            .call_with(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&patch("off")),
                &[("If-Match", &etag(first))],
            )
            .await;
        second.assert_status(200);
        let second = revision(&second.body);

        harness
            .call_with(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&patch("lock_until_unlock")),
                &[("If-Match", &etag(first))],
            )
            .await
            .assert_problem(409, "auth.conflict");
        assert_eq!(
            read(&harness, &admin).await.body["settings"]["lockout"],
            "off",
            "the stale change did nothing"
        );
        let weak = harness
            .call_with(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&patch("lock_until_unlock")),
                &[("If-Match", &format!("W/{}", etag(second)))],
            )
            .await;
        weak.assert_status(200);
        let bad = harness
            .call_with(
                "PATCH",
                "/settings/security",
                Cookie(&admin),
                Some(&patch("off")),
                &[("If-Match", "the-latest")],
            )
            .await;
        bad.assert_problem(400, "sys.invalid_value");
        assert_eq!(bad.body["params"]["value"], "the-latest");
    }

    #[tokio::test]
    async fn invalid_changes_are_refused() {
        let (harness, admin) = Harness::installed().await;
        // Idle must not exceed absolute, lifetimes must be positive, a token maximum too.
        let reply = patch(
            &harness,
            &admin,
            json!({ "session": { "absolute_secs": 60, "idle_secs": 600 } }),
        )
        .await;
        reply.assert_problem(400, "auth.invalid_request");
        assert_eq!(reply.body["params"]["field"], "session");
        patch(
            &harness,
            &admin,
            json!({ "session": { "absolute_secs": 0, "idle_secs": 0 } }),
        )
        .await
        .assert_problem(400, "auth.invalid_request");
        patch(
            &harness,
            &admin,
            json!({ "token_max_lifetime": { "days": 0 } }),
        )
        .await
        .assert_problem(400, "auth.invalid_request");
        // Values the types do not know, and bodies that are not objects.
        patch(&harness, &admin, json!({ "profile": "nonsense" }))
            .await
            .assert_problem(400, "sys.invalid_request");
        patch(&harness, &admin, json!({ "lockout": "sometimes" }))
            .await
            .assert_problem(400, "sys.invalid_request");
        patch(&harness, &admin, json!([]))
            .await
            .assert_problem(400, "sys.invalid_request");
        // Nothing was applied.
        let reply = read(&harness, &admin).await;
        assert_eq!(reply.body["settings"]["profile"], "home");
        assert_eq!(reply.body["settings"]["session"]["idle_secs"], 7 * 86_400);
        assert!(
            !harness
                .audit_actions()
                .await
                .contains(&"auth.settings.update".to_owned())
        );
    }

    #[tokio::test]
    async fn only_administrators_change_the_settings() {
        let (harness, admin) = Harness::installed().await;
        harness
            .create_user(&admin, "vera", "5826", &["viewer"])
            .await;
        harness
            .create_user(&admin, "oscar", "7391", &["operator"])
            .await;
        let viewer = harness.login("vera", "5826").await;
        let operator = harness.login("oscar", "7391").await;

        harness
            .call("GET", "/settings/security", Cookie(&viewer), None)
            .await
            .assert_problem(403, "auth.forbidden");
        harness
            .call(
                "PATCH",
                "/settings/security",
                Cookie(&viewer),
                Some(&json!({ "lockout": "off" })),
            )
            .await
            .assert_problem(403, "auth.forbidden");
        // An operator may read the settings but not change them.
        harness
            .call("GET", "/settings/security", Cookie(&operator), None)
            .await
            .assert_status(200);
        harness
            .call(
                "PATCH",
                "/settings/security",
                Cookie(&operator),
                Some(&json!({ "lockout": "off" })),
            )
            .await
            .assert_problem(403, "auth.forbidden");
        harness
            .call("GET", "/settings/security", Anonymous, None)
            .await
            .assert_problem(401, "auth.unauthenticated");
        harness
            .call(
                "PATCH",
                "/settings/security",
                Anonymous,
                Some(&json!({ "lockout": "off" })),
            )
            .await
            .assert_problem(401, "auth.unauthenticated");
        assert_eq!(
            read(&harness, &admin).await.body["settings"]["lockout"],
            "progressive_delay"
        );
    }

    #[tokio::test]
    async fn a_personal_token_reads_the_settings_but_changing_them_needs_a_session() {
        let (harness, admin) = Harness::installed().await;
        let created = harness
            .call(
                "POST",
                "/auth/tokens",
                Cookie(&admin),
                Some(&json!({ "name": "ops" })),
            )
            .await;
        let token = created.body["token"].as_str().expect("a token").to_owned();
        let read = harness
            .call("GET", "/settings/security", Bearer(&token), None)
            .await;
        read.assert_status(200);
        assert_eq!(read.body["settings"]["profile"], "home");
        let refused = harness
            .call_with(
                "PATCH",
                "/settings/security",
                Bearer(&token),
                Some(&json!({ "lockout": "off" })),
                &[("If-Match", &etag(revision(&read.body)))],
            )
            .await;
        refused.assert_problem(403, "auth.forbidden");
        assert_eq!(
            self::read(&harness, &admin).await.body["settings"]["lockout"],
            "progressive_delay"
        );
    }
}
