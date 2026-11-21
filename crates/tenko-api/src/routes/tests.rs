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
use tenko_auth::testing::approval::{ROOT_SHA256, Script};

/// The operations anybody may call: their handlers take no `Ctx`.
const PUBLIC: [&str; 22] = [
    "GET /auth/negotiate",
    "GET /auth/oidc/{id}/callback",
    "GET /auth/oidc/{id}/start",
    "GET /auth/providers/public",
    "GET /health",
    "GET /health/ready",
    "GET /i18n/languages",
    "GET /i18n/packs/{tag}",
    "GET /integrations/ca",
    "GET /openapi.json",
    "GET /setup",
    "GET /system/ca-root",
    "POST /auth/approvals",
    "POST /auth/approvals/{id}/collect",
    "POST /auth/login/password",
    "POST /auth/login/recovery",
    "POST /auth/login/totp",
    "POST /auth/webauthn/login/finish",
    "POST /auth/webauthn/login/start",
    "POST /integrations/enroll",
    "POST /nodes/enroll",
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
    /// The calling scoped token's own routes (IAM-20): a session has no token.
    Token,
    /// The integration certificate's own renewal: the handler takes no `Ctx` and refuses
    /// a connection without the certificate (`integrations.rs` tests that).
    Certificate,
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
                r#"[{"token":[]}]"# => Requirement::Token,
                r#"[{"certificate":[]}]"# => Requirement::Certificate,
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
    assert_eq!(all.len(), 466, "every operation of the document");
    let public: BTreeSet<String> = PUBLIC.iter().map(|key| (*key).to_owned()).collect();
    assert_eq!(with(Requirement::Public), public, "the public operations");
    let until_setup: BTreeSet<String> = PUBLIC_UNTIL_SETUP
        .iter()
        .map(|key| (*key).to_owned())
        .collect();
    assert_eq!(with(Requirement::PublicUntilSetup), until_setup);
    assert_eq!(
        with(Requirement::Session).len(),
        107,
        "the session-only operations"
    );
    assert_eq!(
        with(Requirement::Token),
        BTreeSet::from([
            "GET /access/token".to_owned(),
            "POST /access/token/renew".to_owned(),
            "PUT /migrate/mirrors/{id}/snapshot".to_owned()
        ]),
        "the token-only operations"
    );
    assert_eq!(schemes["certificate"]["type"], "mutualTLS");
    assert_eq!(
        with(Requirement::Certificate),
        BTreeSet::from(["POST /integrations/certificate/renew".to_owned()]),
        "the certificate-only operations"
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
    let ipam = IpamService::with_direct_jobs(Arc::clone(&store)).expect("ipam");
    let mirrors = Arc::new(tenko_migrate::mirror::MirrorService::new(
        store,
        Arc::clone(&env.service),
    ));
    let harness = Harness::wired(env, move |state| {
        crate::api_with(state, ModuleSet::ALL)
            .0
            .layer(Extension(ipam))
            .layer(Extension(mirrors))
    });
    (harness, admin)
}

/// ADR 0033 decision 3 (E73): a mirror's token is refused on every operation of the document
/// but the push of its own mirror. An operation with a body may refuse the body first, so
/// there it never succeeds; without a body it is refused as unauthenticated or forbidden.
#[tokio::test]
async fn a_mirror_token_is_refused_on_every_operation_but_its_push() {
    let (harness, admin) = installation().await;
    let created = harness
        .call(
            "POST",
            "/migrate/mirrors",
            Cookie(&admin),
            Some(&json!({ "name": "dc1", "kind": "windows-dhcp" })),
        )
        .await;
    created.assert_status(201);
    let token = created.body["token"]
        .as_str()
        .expect("the token")
        .to_owned();
    let mut wrong = Vec::new();
    let mut checked = 0_usize;
    for (key, requirement, operation) in operations() {
        if requirement == Requirement::Public
            || key == "GET /events"
            || key == "PUT /migrate/mirrors/{id}/snapshot"
        {
            continue;
        }
        let reply = call(&harness, &key, &operation, Bearer(&token)).await;
        let refused = refused_as_unauthenticated(&reply)
            || (reply.status.as_u16() == 403 && reply.body["code"] == "auth.forbidden");
        // A stub, or a service this installation does not wire, answers before it reads
        // the caller; every other operation, with a body or without, refuses the token.
        if !refused && !matches!(reply.status.as_u16(), 501 | 503) {
            wrong.push(format!("{key}: {} {}", reply.status, reply.text));
        }
        checked += 1;
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(checked > 400, "only {checked} operations");
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
            Requirement::Public => {
                assert_ne!(reply.status.as_u16(), 401, "a public operation: {label}");
            }
            // Refused by the handler without the certificate, not by authentication.
            Requirement::Certificate => {
                assert!(!reply.status.is_success(), "{label}");
            }
            // The installation has completed setup: refused before the body is read.
            Requirement::PublicUntilSetup => {
                assert!(refused_as_unauthenticated(&reply), "{label}");
            }
            Requirement::Session | Requirement::SessionOrToken | Requirement::Token => {
                assert!(refused_as_unauthenticated(&reply), "{label}");
                refused += 1;
            }
        }
    }
    assert_eq!(
        refused,
        466 - PUBLIC.len() - PUBLIC_UNTIL_SETUP.len() - with(Requirement::Certificate).len()
    );
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

/// The address the takeover script of the tests runs on.
const SCRIPT: &str = "192.0.2.10";

/// The API listener's router as the server builds it (its authentication layer, the
/// allow-list of delegated sessions in it), over an installation like [`installation`]'s,
/// with the internal authority's root of the test script's codes, and the secret of the
/// administrator's session.
async fn served() -> (TestEnv, String, axum::Router) {
    use tenko_cluster::ca::{TlsMode, TlsPolicy, TlsService};
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
    let ipam = IpamService::with_direct_jobs(Arc::clone(&store)).expect("ipam");
    let mirrors = Arc::new(tenko_migrate::mirror::MirrorService::new(
        store,
        Arc::clone(&env.service),
    ));
    let mut state = crate::state::AppState::new(env.store.clone());
    let authenticator: Arc<dyn tenko_core::Authenticator> = env.service.clone();
    state.auth = Some(authenticator);
    state.authorizer = Some(env.service.authorizer());
    let http = crate::middleware::HttpConfig {
        rate_limit: crate::middleware::RateLimitConfig {
            enabled: false,
            ..crate::middleware::RateLimitConfig::default()
        },
        ..crate::middleware::HttpConfig::default()
    };
    let root = crate::routes::system::CaRootSource::new(
        TlsService::new(TlsMode::InternalCa, TlsPolicy::default()).expect("tls"),
        "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n",
        tenko_auth::encoding::hex_encode(&ROOT_SHA256),
    );
    let app = crate::server::app(state, &http, &crate::ui::UiSource::Embedded)
        .expect("the application")
        .layer(Extension(ipam))
        .layer(Extension(mirrors))
        .layer(Extension(Arc::new(root)))
        .layer(Extension(Arc::clone(&env.service)));
    (env, admin, app)
}

/// A request over TLS from `address`, as the listener hands it on: the session cookie under
/// its HTTPS name, the origin of the installation, a body sent exactly as given.
fn from(
    address: &str,
    method: &str,
    path: &str,
    credential: Credential<'_>,
    body: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    use axum::http::header;
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(format!("{API_BASE}{path}"))
        .header(header::HOST, tenko_auth::testing::env::HOST)
        .header(header::ORIGIN, tenko_auth::testing::env::ORIGIN);
    builder = match credential {
        Anonymous => builder,
        Cookie(secret) => builder.header(
            header::COOKIE,
            format!("{}={secret}", tenko_auth::service::HOST_SESSION_COOKIE),
        ),
        Bearer(token) => builder.header(header::AUTHORIZATION, format!("Bearer {token}")),
    };
    let mut request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_owned())),
        None => builder.body(axum::body::Body::empty()),
    }
    .expect("a request");
    request
        .extensions_mut()
        .insert(crate::server::forwarded::ConnInfo {
            peer: std::net::SocketAddr::new(address.parse().expect("an address"), 50_000),
            tls: true,
            mode: Arc::new(tenko_cluster::ca::TlsMode::InternalCa),
            trusted: false,
            proxy: None,
            client: None,
        });
    request
}

async fn send(app: &axum::Router, request: axum::http::Request<axum::body::Body>) -> Reply {
    tokio::time::timeout(
        Duration::from_secs(10),
        super::auth::testkit::send_to(app.clone(), request),
    )
    .await
    .expect("an answer")
}

fn delegation_refused(reply: &Reply) -> bool {
    reply.status.as_u16() == 403 && reply.body["code"] == "auth.delegation.refused"
}

/// ADR 0038 (E145): within its first five minutes, a delegated session is refused on every
/// operation of the served document outside its allow-list, every `/auth/*` operation and
/// every account self-service operation among them, before any handler; a listed operation
/// is not refused for being delegated. Its own sign-out ends it.
#[tokio::test]
async fn a_delegated_session_reaches_its_allow_list_and_nothing_else() {
    let (env, admin, app) = served().await;
    let admin = env
        .ctx_for(&tenko_core::Credentials::Session(admin))
        .await
        .expect("the administrator");
    let session = env
        .delegate(
            &admin,
            &Script::default(),
            SCRIPT.parse().expect("an address"),
        )
        .await
        .expect("a delegated session");
    let secret = session.secret.expose().to_owned();
    let listed: BTreeSet<String> = tenko_auth::delegation::TAKEOVER
        .iter()
        .map(|entry| format!("{} {}", entry.method, entry.route))
        .collect();
    let all: BTreeSet<String> = operations().into_iter().map(|(key, _, _)| key).collect();
    assert!(listed.is_subset(&all), "every listed route is an operation");
    let mut wrong = Vec::new();
    let mut refused = 0_usize;
    for (key, _, operation) in operations() {
        if key == "POST /auth/logout" {
            continue;
        }
        let (method, path) = concrete(&key, &operation);
        let body = operation.get("requestBody").map(|_| "{}");
        let reply = send(&app, from(SCRIPT, &method, &path, Bearer(&secret), body)).await;
        match (listed.contains(&key), delegation_refused(&reply)) {
            (false, true) => refused += 1,
            (true, false) => {}
            _ => wrong.push(format!("{key}: {} {}", reply.status, reply.text)),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert_eq!(refused, all.len() - listed.len());
    // From another address it is an unknown session, on a listed operation too (a public one
    // answers as to anybody).
    let elsewhere = send(
        &app,
        from("192.0.2.99", "POST", "/auth/logout", Bearer(&secret), None),
    )
    .await;
    assert!(refused_as_unauthenticated(&elsewhere), "{}", elsewhere.text);
    send(
        &app,
        from(SCRIPT, "POST", "/auth/logout", Bearer(&secret), None),
    )
    .await
    .assert_status(204);
    let ended = send(
        &app,
        from(SCRIPT, "POST", "/auth/logout", Bearer(&secret), None),
    )
    .await;
    assert!(refused_as_unauthenticated(&ended), "{}", ended.text);
}

/// Without the server's middleware the extractor of every handler holds the allow-list too.
#[tokio::test]
async fn the_request_context_holds_the_allow_list_too() {
    let (harness, admin) = installation().await;
    let admin = harness
        .env
        .ctx_for(&tenko_core::Credentials::Session(admin))
        .await
        .expect("the administrator");
    let session = harness
        .env
        .delegate(
            &admin,
            &Script::default(),
            SCRIPT.parse().expect("an address"),
        )
        .await
        .expect("a delegated session");
    let mut request = super::auth::testkit::request(
        "GET",
        "/auth/session",
        Bearer(session.secret.expose()),
        None,
        &[],
    );
    request.extensions_mut().insert(crate::extract::ClientInfo {
        source_ip: Some(SCRIPT.parse().expect("an address")),
        ..crate::extract::ClientInfo::default()
    });
    harness
        .send(request)
        .await
        .assert_problem(403, "auth.delegation.refused");
}

/// ADR 0038 over HTTP: the request, the code, the approval, the collect, and the one listed
/// operation behind a recent sign-in, the mirror creation, for the plan's servers within five
/// minutes of the approval only.
#[tokio::test]
#[allow(clippy::too_many_lines)] // One script from its request to its mirrors.
async fn a_script_is_approved_collects_and_creates_its_mirrors_over_http() {
    let (env, admin, app) = served().await;
    let script = Script::default();
    let body = script.request();
    let ticket = send(
        &app,
        from(SCRIPT, "POST", "/auth/approvals", Anonymous, Some(&body)),
    )
    .await;
    ticket.assert_status(201);
    let ticket: tenko_auth::approval::ApprovalTicket = ticket.parse();
    let code = json!({ "code": script.code(&body, ticket.id) }).to_string();
    let wrong = json!({ "code": "0000-0000-0000-0000" }).to_string();
    let lookup = "/auth/approvals/lookup";
    send(
        &app,
        from(SCRIPT, "POST", lookup, Cookie(&admin), Some(&wrong)),
    )
    .await
    .assert_problem(403, "auth.approval.code");
    let found = send(
        &app,
        from(SCRIPT, "POST", lookup, Cookie(&admin), Some(&code)),
    )
    .await;
    found.assert_status(200);
    assert_eq!(found.body["plan"]["domain"], "corp.example.test");
    let approve = format!("/auth/approvals/{}/approve", ticket.id);
    let collect = format!("/auth/approvals/{}/collect", ticket.id);
    let signed = script.collect(&ticket);
    send(
        &app,
        from(SCRIPT, "POST", &collect, Anonymous, Some(&signed)),
    )
    .await
    .assert_problem(409, "auth.approval.pending");
    send(
        &app,
        from(SCRIPT, "POST", &approve, Cookie(&admin), Some(&code)),
    )
    .await
    .assert_status(200);
    send(
        &app,
        from("192.0.2.99", "POST", &collect, Anonymous, Some(&signed)),
    )
    .await
    .assert_problem(404, "auth.approval.not_found");
    let collected = send(
        &app,
        from(SCRIPT, "POST", &collect, Anonymous, Some(&signed)),
    )
    .await;
    collected.assert_status(200);
    assert_eq!(collected.header("cache-control"), Some("no-store"));
    send(
        &app,
        from(SCRIPT, "POST", &collect, Anonymous, Some(&signed)),
    )
    .await
    .assert_problem(409, "auth.approval.consumed");
    let secret = collected.body["secret"]
        .as_str()
        .expect("the secret")
        .to_owned();
    let mirror = |name: &str, prefix: &str| {
        json!({ "name": name, "kind": "windows-dhcp", "source_prefixes": [prefix] }).to_string()
    };
    let mirrors = "/migrate/mirrors";
    for outside in [
        mirror("dhcp9.corp.example.test", "192.0.2.30/32"),
        mirror("dhcp1.corp.example.test", "192.0.2.0/24"),
    ] {
        send(
            &app,
            from(SCRIPT, "POST", mirrors, Bearer(&secret), Some(&outside)),
        )
        .await
        .assert_problem(403, "auth.delegation.refused");
    }
    let inside = mirror("dhcp1.corp.example.test", "192.0.2.30/32");
    send(
        &app,
        from(SCRIPT, "POST", mirrors, Bearer(&secret), Some(&inside)),
    )
    .await
    .assert_status(201);
    // Six minutes after the approval, on Tenko's clock, the mirror creation is closed.
    let view = env
        .store
        .read(tenko_store::ReadConsistency::Local)
        .await
        .expect("a view");
    let hash = tenko_auth::secret::hash_secret(&secret);
    let (record, _) =
        tenko_store::ReadViewExt::get_typed(view.as_ref(), &tenko_auth::model::SESSIONS, &hash)
            .expect("read")
            .expect("the session");
    let approved_at = |at: Timestamp| {
        let mut record = record.clone();
        record.delegation.as_mut().expect("delegated").approved_at = at;
        let mut batch = tenko_store::WriteBatch::new(
            tenko_core::Principal::system(tenko_core::SystemComponent::Auth),
            Timestamp::now(),
        );
        batch
            .put_typed(&tenko_auth::model::SESSIONS, &hash, &record)
            .expect("encode");
        env.store.propose(batch)
    };
    let six_minutes_ago = Timestamp::now()
        .checked_sub(Duration::from_secs(360))
        .expect("a time");
    approved_at(six_minutes_ago).await.expect("commit");
    let second = mirror("dhcp2.corp.example.test", "192.0.2.30/32");
    send(
        &app,
        from(SCRIPT, "POST", mirrors, Bearer(&secret), Some(&second)),
    )
    .await
    .assert_problem(403, "auth.delegation.refused");
    // Within the window again: one mirror per DHCP server of the plan, two in all.
    approved_at(Timestamp::now()).await.expect("commit");
    send(
        &app,
        from(SCRIPT, "POST", mirrors, Bearer(&secret), Some(&second)),
    )
    .await
    .assert_status(201);
    send(
        &app,
        from(SCRIPT, "POST", mirrors, Bearer(&secret), Some(&inside)),
    )
    .await
    .assert_problem(403, "auth.delegation.refused");
}

/// The two public operations of the approval are bounded: a request body above 64 KiB and a
/// collect body above 1 KiB are refused, and one source asks at most once every ten seconds
/// while another source is not held up by it.
#[tokio::test]
async fn the_public_approval_operations_are_bounded_and_paced_per_source() {
    let (_env, _, app) = served().await;
    let large = format!(
        "{{{}}}",
        " ".repeat(tenko_auth::approval::MAX_REQUEST_BYTES)
    );
    send(
        &app,
        from(SCRIPT, "POST", "/auth/approvals", Anonymous, Some(&large)),
    )
    .await
    .assert_problem(413, "sys.body_too_large");
    let collect = format!(
        "/auth/approvals/{}/collect",
        tenko_core::ApprovalId::generate()
    );
    let signature = format!("{{\"signature\":\"{}\"}}", "A".repeat(1_024));
    send(
        &app,
        from(SCRIPT, "POST", &collect, Anonymous, Some(&signature)),
    )
    .await
    .assert_problem(413, "sys.body_too_large");
    let body = Script::default().request();
    let ask =
        |source: &'static str| from(source, "POST", "/auth/approvals", Anonymous, Some(&body));
    send(&app, ask("192.0.2.20")).await.assert_status(201);
    let again = send(&app, ask("192.0.2.20")).await;
    again.assert_problem(429, "auth.approval.limit");
    assert_eq!(again.body["params"]["limit"], "spacing");
    send(&app, ask("192.0.2.21")).await.assert_status(201);
}

/// The script's own shape of request: no `Origin`, HTTP/1.0, a bearer, from an IPv4 address
/// that reaches the listener as an IPv4-mapped IPv6 peer. The delegated session it collects
/// is refused on a `HEAD` of a listed `GET` and on a path that no route matches.
#[tokio::test]
async fn the_script_s_own_requests_are_answered_and_bounded() {
    use axum::http::{Version, header};
    let (env, admin, app) = served().await;
    let script = Script::default();
    let body = script.request();
    let mapped = "::ffff:192.0.2.10";
    let plain = |method: &str, path: &str, bearer: Option<&str>, body: Option<&str>| {
        let mut request = from(mapped, method, path, Anonymous, body);
        *request.version_mut() = Version::HTTP_10;
        request.headers_mut().remove(header::ORIGIN);
        if let Some(token) = bearer {
            request.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().expect("a header"),
            );
        }
        request
    };
    let ticket = send(&app, plain("POST", "/auth/approvals", None, Some(&body))).await;
    ticket.assert_status(201);
    let ticket: tenko_auth::approval::ApprovalTicket = ticket.parse();
    let admin = env
        .ctx_for(&tenko_core::Credentials::Session(admin))
        .await
        .expect("the administrator");
    let code = tenko_auth::service::SecretString::new(script.code(&body, ticket.id));
    env.service
        .approve(&admin, ticket.id, &code, &ROOT_SHA256)
        .await
        .expect("approved");
    let collect = format!("/auth/approvals/{}/collect", ticket.id);
    let signed = script.collect(&ticket);
    let collected = send(&app, plain("POST", &collect, None, Some(&signed))).await;
    collected.assert_status(200);
    let secret = collected.body["secret"]
        .as_str()
        .expect("the secret")
        .to_owned();
    send(&app, plain("GET", "/health", Some(&secret), None))
        .await
        .assert_status(200);
    // A HEAD answer has no body: the status says it.
    send(&app, plain("HEAD", "/health", Some(&secret), None))
        .await
        .assert_status(403);
    let slash = send(&app, plain("POST", "/auth/logout/", Some(&secret), None)).await;
    assert!(!slash.status.is_success(), "{}", slash.text);
    send(&app, plain("POST", "/auth/logout", Some(&secret), None))
        .await
        .assert_status(204);
}
