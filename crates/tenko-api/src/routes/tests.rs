//! The security requirements of the OpenAPI document against the server: every operation
//! states one, only the operations listed here are public, an anonymous request is refused
//! everywhere else, and a personal token is refused exactly where the document asks for a
//! session (`docs/api/README.md`).

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::Extension;
use serde_json::{Value, json};
use tenko_auth::{settings::Profile, testing::TestEnv};
use tenko_core::Timestamp;
use tenko_ipam::IpamService;
use tenko_store::Store;

use super::auth::testkit::{Credential, Credential::*, Harness, Reply};
use crate::{API_BASE, modules::ModuleSet};

/// The operations anybody may call: their handlers take no `Ctx`.
const PUBLIC: [&str; 14] = [
    "GET /health",
    "GET /health/ready",
    "GET /i18n/languages",
    "GET /i18n/packs/{tag}",
    "GET /openapi.json",
    "GET /setup",
    "GET /system/ca-root",
    "POST /auth/login/password",
    "POST /auth/login/recovery",
    "POST /auth/login/totp",
    "POST /auth/webauthn/login/finish",
    "POST /auth/webauthn/login/start",
    "POST /nodes/enrol",
    "POST /setup",
];

/// The operations that are public until setup and need a session or a token after it.
const PUBLIC_UNTIL_SETUP: [&str; 1] = ["POST /auth/password/check"];

/// How an operation may be called, as its effective security requirement says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Requirement {
    Public,
    PublicUntilSetup,
    Session,
    SessionOrToken,
}

/// Every operation of the whole API, as `"METHOD /path"` relative to the API base, with its
/// requirement: its own `security`, else the document's.
fn operations() -> Vec<(String, Requirement, Value)> {
    let document = serde_json::to_value(crate::openapi()).expect("document");
    let default = document["security"].clone();
    let mut out = Vec::new();
    for (path, item) in document["paths"].as_object().expect("paths") {
        let relative = path.strip_prefix(API_BASE).expect("under the API base");
        for method in ["get", "put", "post", "delete", "patch"] {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let key = format!("{} {relative}", method.to_uppercase());
            let security = operation.get("security").unwrap_or(&default);
            let requirement = match serde_json::to_string(security).expect("json").as_str() {
                "[]" => Requirement::Public,
                r#"[{},{"session":[]},{"token":[]}]"# => Requirement::PublicUntilSetup,
                r#"[{"session":[]}]"# => Requirement::Session,
                r#"[{"session":[]},{"token":[]}]"# => Requirement::SessionOrToken,
                other => panic!("{key}: unexpected security requirement {other}"),
            };
            out.push((key, requirement, operation.clone()));
        }
    }
    out
}

fn with(requirement: Requirement) -> BTreeSet<String> {
    operations()
        .into_iter()
        .filter(|(_, found, _)| *found == requirement)
        .map(|(key, _, _)| key)
        .collect()
}

#[test]
fn every_operation_declares_its_security_requirement() {
    let document = serde_json::to_value(crate::openapi()).expect("document");
    assert_eq!(
        document["security"],
        json!([{ "session": [] }, { "token": [] }]),
        "the default is a session or a token"
    );
    let schemes = &document["components"]["securitySchemes"];
    assert_eq!(schemes["session"]["in"], "cookie");
    assert_eq!(schemes["token"]["scheme"], "bearer");

    let all = operations();
    assert_eq!(all.len(), 380, "every operation of the document");
    let public: BTreeSet<String> = PUBLIC.iter().map(|key| (*key).to_owned()).collect();
    assert_eq!(with(Requirement::Public), public, "the public operations");
    let until_setup: BTreeSet<String> = PUBLIC_UNTIL_SETUP
        .iter()
        .map(|key| (*key).to_owned())
        .collect();
    assert_eq!(with(Requirement::PublicUntilSetup), until_setup);
    assert_eq!(
        with(Requirement::Session).len(),
        66,
        "the session-only operations"
    );
}

/// The API as the server wires it, with every module and the IPAM service, and the secret
/// of the administrator's session.
async fn installation() -> (Harness, String) {
    let env = TestEnv::new().await;
    env.clock.set(Timestamp::now());
    let admin = env
        .setup(Profile::Home)
        .await
        .expect("setup succeeds")
        .secret
        .expose()
        .to_owned();
    let store: Arc<dyn Store> = env.store.clone();
    let ipam = IpamService::with_direct_jobs(store).expect("ipam");
    let harness = Harness::wired(env, move |state| {
        crate::api_with(state, ModuleSet::ALL)
            .0
            .layer(Extension(ipam))
    });
    (harness, admin)
}

/// `key` with every path parameter filled in: a number where the document says integer,
/// else a value of the parameter's shape.
fn concrete(key: &str, operation: &Value) -> (String, String) {
    let (method, template) = key.split_once(' ').expect("METHOD /path");
    let mut path = template.to_owned();
    for parameter in operation["parameters"].as_array().into_iter().flatten() {
        if parameter["in"] != "path" {
            continue;
        }
        let name = parameter["name"].as_str().expect("a name");
        let value = match (name, parameter["schema"]["type"].as_str()) {
            (_, Some("integer")) => "1",
            ("tag", _) => "en",
            ("role", _) => "viewer",
            ("key", _) => "owner",
            ("zone", _) => "example.test.",
            ("subject", _) => "198.51.100.10",
            _ => "0190d1c2-0000-7000-8000-000000000001",
        };
        path = path.replace(&format!("{{{name}}}"), value);
    }
    (method.to_owned(), path)
}

async fn call(harness: &Harness, key: &str, operation: &Value, as_: Credential<'_>) -> Reply {
    let (method, path) = concrete(key, operation);
    let body = operation.get("requestBody").map(|_| json!({}));
    tokio::time::timeout(
        Duration::from_secs(10),
        harness.call(&method, &path, as_, body.as_ref()),
    )
    .await
    .unwrap_or_else(|_| panic!("{key} does not answer"))
}

fn refused_as_unauthenticated(reply: &Reply) -> bool {
    reply.status.as_u16() == 401 && reply.body["code"] == "auth.unauthenticated"
}

#[tokio::test]
async fn an_anonymous_request_is_refused_on_every_operation_but_the_public_ones() {
    let (harness, _) = installation().await;
    let mut refused = 0_usize;
    for (key, requirement, operation) in operations() {
        let reply = call(&harness, &key, &operation, Anonymous).await;
        let label = format!("{key}: {} {}", reply.status, reply.text);
        match requirement {
            Requirement::Public | Requirement::PublicUntilSetup => {
                assert_ne!(reply.status.as_u16(), 401, "a public operation: {label}");
            }
            Requirement::Session | Requirement::SessionOrToken => {
                assert!(refused_as_unauthenticated(&reply), "{label}");
                refused += 1;
            }
        }
    }
    assert_eq!(refused, 380 - PUBLIC.len() - PUBLIC_UNTIL_SETUP.len());
}

/// Every operation without a request body called with a personal token of the
/// administrator: refused (401 `auth.unauthenticated` or 403 `auth.forbidden`) where the
/// document asks for a session, not refused for being a token where it accepts one. An
/// operation with a body is left out: its body is read before authorization.
#[tokio::test]
async fn a_personal_token_is_refused_exactly_on_the_session_only_operations_without_a_body() {
    let (harness, admin) = installation().await;
    let created = harness
        .call(
            "POST",
            "/auth/tokens",
            Cookie(&admin),
            Some(&json!({ "name": "openapi", "expires_in_days": 30 })),
        )
        .await;
    created.assert_status(201);
    let token = created.body["token"]
        .as_str()
        .expect("the token")
        .to_owned();
    let mut checked = 0_usize;
    let mut sessions_only = 0_usize;
    let mut wrong = Vec::new();
    for (key, requirement, operation) in operations() {
        // The stream never ends.
        if operation.get("requestBody").is_some() || key == "GET /events" {
            continue;
        }
        let reply = call(&harness, &key, &operation, Bearer(&token)).await;
        // A stub, or a service this installation does not wire: answered before
        // authorization, so it tells nothing.
        if matches!(reply.status.as_u16(), 501 | 503) {
            continue;
        }
        let label = format!("{key}: {} {}", reply.status, reply.text);
        let refused = refused_as_unauthenticated(&reply)
            || (reply.status.as_u16() == 403 && reply.body["code"] == "auth.forbidden");
        match requirement {
            Requirement::Session => {
                sessions_only += 1;
                if !refused {
                    wrong.push(format!("needs a session, yet a token passes: {label}"));
                }
            }
            Requirement::SessionOrToken | Requirement::PublicUntilSetup if refused => {
                wrong.push(format!(
                    "accepts a token, yet the token is refused: {label}"
                ));
            }
            _ => {}
        }
        checked += 1;
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(checked > 190, "only {checked} operations");
    assert!(
        sessions_only > 25,
        "only {sessions_only} session-only operations"
    );
}
