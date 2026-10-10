//! Route tests of the secrets area over the real authentication service, the vault and
//! IPAM on one `MemStore`: the lifecycle, authorization by role, the PIN coupling rule,
//! the reveal with its policy (TGL-24), audit and rate limit, and host credentials.

use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::Request,
};
use serde_json::{Value, json};
use tenko_auth::{
    service::{
        WebAuthnLoginFinish, WebAuthnLoginOptions, WebAuthnRegisterFinish, WebAuthnRegisterOptions,
    },
    settings::Profile,
    testing::{
        SoftAttestation, SoftAuthenticator, SoftKeyAlg, TestEnv,
        env::{ADMIN_PASSWORD, ADMIN_PIN, HOST, ORIGIN},
    },
};
use tenko_core::{Authenticator, Timestamp};
use tenko_ipam::IpamService;
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};
use tenko_vault::{Vault, operator::OperatorSecrets};
use tower::ServiceExt;

use crate::{
    routes::auth::testkit::{Credential, Reply, request, send_to},
    state::AppState,
};

/// A PIN for the users of the tests (PIN preset).
pub(crate) const USER_PIN: &str = "7391";
/// A passphrase for the users of the tests (other presets).
pub(crate) const USER_PASSPHRASE: &str = "marble comet violin saffron";

/// The API over the services of one installation, set up through `POST /setup` (so the
/// default tenant and VRF exist), with an administrator signed in with a passkey.
pub(crate) struct Harness {
    pub(crate) env: TestEnv,
    pub(crate) router: Router,
    /// The administrator's passkey session.
    pub(crate) admin: String,
    profile: Profile,
}

impl Harness {
    pub(crate) async fn new(profile: Profile) -> Self {
        let env = TestEnv::new().await;
        env.clock.set(Timestamp::now());
        let store = env.store.clone() as Arc<dyn Store>;
        let ipam = IpamService::with_direct_jobs(Arc::clone(&store)).expect("IPAM service");
        let secrets = Arc::new(OperatorSecrets::new(
            store,
            env.vault.clone() as Arc<dyn Vault>,
        ));
        let mut state = AppState::new(env.store.clone());
        state.auth = Some(env.service.clone() as Arc<dyn Authenticator>);
        state.authorizer = Some(env.service.authorizer());
        let router = crate::api(state)
            .0
            .layer(Extension(env.service.clone()))
            .layer(Extension(ipam))
            .layer(Extension(secrets));
        let token = env
            .service
            .prepare_setup()
            .await
            .expect("prepare")
            .expect("setup is open")
            .expose()
            .to_owned();
        let password = if profile.defaults().password_policy.is_pin() {
            ADMIN_PIN
        } else {
            ADMIN_PASSWORD
        };
        let body = json!({
            "setup_token": token,
            "profile": profile.as_str(),
            "admin": { "name": "admin", "password": password },
            "host_name": HOST,
            "language": "en"
        });
        let reply = send_to(
            router.clone(),
            request("POST", "/setup", Credential::Anonymous, Some(&body), &[]),
        )
        .await;
        reply.assert_status(200);
        let first = reply.session_secret();
        let mut harness = Self {
            env,
            router,
            admin: String::new(),
            profile,
        };
        harness.admin = harness.passkey_session(&first, "admin").await;
        harness
    }

    /// The password of new users under the profile.
    pub(crate) fn user_password(&self) -> &'static str {
        if self.profile.defaults().password_policy.is_pin() {
            USER_PIN
        } else {
            USER_PASSPHRASE
        }
    }

    pub(crate) async fn call(
        &self,
        method: &str,
        path: &str,
        credential: Credential<'_>,
        body: Option<&Value>,
    ) -> Reply {
        self.call_with(method, path, credential, body, &[]).await
    }

    pub(crate) async fn call_with(
        &self,
        method: &str,
        path: &str,
        credential: Credential<'_>,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Reply {
        send_to(
            self.router.clone(),
            request(method, path, credential, body, headers),
        )
        .await
    }

    /// A request answered with raw bytes (the `.rdp` file).
    pub(crate) async fn raw(
        &self,
        path: &str,
        credential: Credential<'_>,
    ) -> (u16, axum::http::HeaderMap, String) {
        let request: Request<Body> = request("GET", path, credential, None, &[]);
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("an answer");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    /// Logs in with a password and returns the session secret.
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

    /// Creates a user as the administrator and returns its id.
    pub(crate) async fn create_user(&self, name: &str, roles: &[&str]) -> String {
        let reply = self
            .call(
                "POST",
                "/users",
                Credential::Cookie(&self.admin),
                Some(&json!({ "name": name, "password": self.user_password(), "roles": roles })),
            )
            .await;
        reply.assert_status(201);
        reply.body["id"].as_str().expect("an id").to_owned()
    }

    /// Registers a software passkey for the user of `cookie` and logs `name` in with it.
    pub(crate) async fn passkey_session(&self, cookie: &str, name: &str) -> String {
        let mut authenticator = SoftAuthenticator::new(SoftKeyAlg::Es256, SoftAttestation::None);
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
        self.passkey_login(&mut authenticator, name).await
    }

    async fn passkey_login(&self, authenticator: &mut SoftAuthenticator, name: &str) -> String {
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
        login.session_secret()
    }

    /// A new passkey session of the administrator whose authentication is `age` old: the
    /// session record is moved back in the store, as if the sign-in happened then.
    pub(crate) async fn aged_admin_session(&self, age: Duration) -> String {
        let secret = self.passkey_session(&self.admin, "admin").await;
        let key = tenko_auth::secret::hash_secret(&secret);
        let view = self
            .env
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("a view");
        let (mut record, _) = view
            .get_typed(&tenko_auth::model::SESSIONS, &key)
            .expect("read")
            .expect("the session");
        let now = Timestamp::now();
        record.authenticated_at = Timestamp::from_unix_nanos(
            now.unix_nanos() - i128::try_from(age.as_nanos()).expect("a small age"),
        )
        .expect("a time");
        let mut batch = WriteBatch::new(
            tenko_core::Principal::system(tenko_core::SystemComponent::Auth),
            now,
        );
        batch
            .put_typed(&tenko_auth::model::SESSIONS, &key, &record)
            .expect("encode");
        self.env.store.propose(batch).await.expect("aged");
        secret
    }

    /// Creates an operator secret as the administrator and returns its id.
    pub(crate) async fn create_secret(&self, name: &str, username: &str, value: &str) -> String {
        let reply = self
            .call(
                "POST",
                "/secrets",
                Credential::Cookie(&self.admin),
                Some(&json!({
                    "name": name,
                    "kind": "password",
                    "username": username,
                    "tags": ["ssh"],
                    "value": value
                })),
            )
            .await;
        reply.assert_status(201);
        reply.body["id"].as_str().expect("an id").to_owned()
    }

    /// Creates a host `name` with the interface `eth0` and the address `ip` (with the DNS
    /// name `<name>.example.test` when `dns`), under the prefix `cidr`; returns the ids of the
    /// host and the interface.
    pub(crate) async fn create_host(
        &self,
        name: &str,
        cidr: &str,
        ip: &str,
        dns: bool,
    ) -> (String, String) {
        let interface = uuid::Uuid::now_v7().to_string();
        let prefix = self
            .call(
                "POST",
                "/prefixes",
                Credential::Cookie(&self.admin),
                Some(&json!({ "cidr": cidr })),
            )
            .await;
        assert!(
            prefix.status.as_u16() == 201 || prefix.body["code"] == "ipam.prefix.overlap",
            "{}",
            prefix.body
        );
        let host = self
            .call(
                "POST",
                "/hosts",
                Credential::Cookie(&self.admin),
                Some(&json!({
                    "name": name,
                    "interfaces": [{ "id": interface, "name": "eth0" }]
                })),
            )
            .await;
        host.assert_status(201);
        let host_id = host.body["item"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("a host id in {}", host.body))
            .to_owned();
        let mut address = json!({ "ip": ip, "interface": interface });
        if dns {
            address["dns_name"] = json!(format!("{name}.example.test"));
        }
        self.call(
            "POST",
            "/addresses",
            Credential::Cookie(&self.admin),
            Some(&address),
        )
        .await
        .assert_status(201);
        (host_id, interface)
    }

    /// Binds secrets to a host as the administrator.
    pub(crate) async fn bind(&self, host: &str, bindings: Value) -> Reply {
        self.call(
            "PUT",
            &format!("/hosts/{host}/credentials"),
            Credential::Cookie(&self.admin),
            Some(&json!({ "credentials": bindings })),
        )
        .await
    }

    /// Every audit draft as JSON, oldest first.
    pub(crate) async fn audit(&self) -> Vec<Value> {
        let view = self
            .env
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("a view");
        view.scan_typed(&tables::AUDIT, KeyRange::all(), 100_000, false)
            .expect("the audit table")
            .into_iter()
            .map(|(_, record, _)| serde_json::to_value(&record).expect("json"))
            .collect()
    }

    /// The audit drafts of an action.
    pub(crate) async fn audit_of(&self, action: &str) -> Vec<Value> {
        self.audit()
            .await
            .into_iter()
            .filter(|record| record["draft"]["action"] == action)
            .collect()
    }
}

fn reveal_path(id: &str) -> String {
    format!("/secrets/{id}/reveal")
}

#[tokio::test]
async fn an_administrator_creates_reads_changes_and_deletes_a_secret() {
    let h = Harness::new(Profile::Home).await;
    let admin = Credential::Cookie(&h.admin);
    let created = h
        .call(
            "POST",
            "/secrets",
            admin,
            Some(&json!({
                "name": "nas admin",
                "kind": "password",
                "username": "admin",
                "tags": ["SSH", "web"],
                "notes": "rack 4",
                "value": "example-secret-one"
            })),
        )
        .await;
    created.assert_status(201);
    let id = created.body["id"].as_str().expect("id").to_owned();
    let etag = created.header("etag").expect("an ETag").to_owned();
    assert_eq!(created.body["tags"], json!(["ssh", "web"]));
    assert_eq!(created.body["origin"], "manual");
    assert!(created.body.get("value").is_none());

    let list = h.call("GET", "/secrets", admin, None).await;
    list.assert_status(200);
    assert_eq!(list.body["items"].as_array().expect("items").len(), 1);
    let filtered = h
        .call("GET", "/secrets?tag=web&kind=password&q=NAS", admin, None)
        .await;
    assert_eq!(filtered.body["items"].as_array().expect("items").len(), 1);
    let none = h.call("GET", "/secrets?kind=token", admin, None).await;
    assert_eq!(none.body["items"], json!([]));
    h.call("GET", "/secrets?kind=nope", admin, None)
        .await
        .assert_problem(400, "sys.invalid_query");
    let large = "x".repeat(tenko_vault::MAX_SECRET_LEN + 1);
    h.call(
        "POST",
        "/secrets",
        admin,
        Some(&json!({ "name": "too large", "kind": "other", "value": large })),
    )
    .await
    .assert_problem(413, "vault.secret.too_large");

    let one = h.call("GET", &format!("/secrets/{id}"), admin, None).await;
    one.assert_status(200);
    assert_eq!(one.header("etag"), Some(etag.as_str()));

    let changed = h
        .call_with(
            "PATCH",
            &format!("/secrets/{id}"),
            admin,
            Some(&json!({ "name": "nas root", "notes": null, "value": "example-secret-two" })),
            &[("if-match", &etag)],
        )
        .await;
    changed.assert_status(200);
    assert_eq!(changed.body["name"], "nas root");
    assert!(changed.body.get("notes").is_none());
    assert_ne!(changed.header("etag"), Some(etag.as_str()));
    h.call_with(
        "PATCH",
        &format!("/secrets/{id}"),
        admin,
        Some(&json!({ "name": "stale" })),
        &[("if-match", &etag)],
    )
    .await
    .assert_problem(409, "vault.secret.conflict");
    h.call(
        "PATCH",
        &format!("/secrets/{id}"),
        admin,
        Some(&json!({ "name": "" })),
    )
    .await
    .assert_problem(422, "vault.secret.invalid");

    let revealed = h.call("POST", &reveal_path(&id), admin, None).await;
    revealed.assert_status(200);
    assert_eq!(revealed.body["value"], "example-secret-two");

    h.call("DELETE", &format!("/secrets/{id}"), admin, None)
        .await
        .assert_status(204);
    h.call("GET", &format!("/secrets/{id}"), admin, None)
        .await
        .assert_problem(404, "vault.secret.not_found");
}

#[tokio::test]
async fn values_appear_only_in_the_reveal_and_never_in_the_audit_log() {
    let h = Harness::new(Profile::Home).await;
    let admin = Credential::Cookie(&h.admin);
    let marker = format!("example-marker-{}", uuid::Uuid::now_v7());
    let id = h.create_secret("switch", "ops", &marker).await;
    for path in ["/secrets".to_owned(), format!("/secrets/{id}")] {
        let reply = h.call("GET", &path, admin, None).await;
        assert!(!reply.body.to_string().contains(&marker), "{path}");
    }
    let revealed = h
        .call(
            "POST",
            &reveal_path(&id),
            admin,
            Some(&json!({ "reason": "console login" })),
        )
        .await;
    revealed.assert_status(200);
    assert_eq!(revealed.body["value"], marker.as_str());
    assert_eq!(revealed.body["username"], "ops");
    assert_eq!(revealed.body["clear_after_secs"], 30);
    assert_eq!(revealed.header("cache-control"), Some("no-store"));

    let audit = h.audit().await;
    assert!(
        audit
            .iter()
            .all(|record| !record.to_string().contains(&marker)),
        "a value reached the audit log"
    );
    let reveals = h.audit_of("vault.secret.reveal").await;
    assert_eq!(reveals.len(), 1);
    let record = &reveals[0];
    assert_eq!(record["draft"]["outcome"]["kind"], "success", "{record}");
    assert_eq!(
        record["draft"]["details"]["context"]["reason"],
        "console login"
    );
    assert_eq!(record["principal"]["kind"], "user", "{record}");
    let after = h.call("GET", &format!("/secrets/{id}"), admin, None).await;
    assert_eq!(after.body["last_revealed"]["user_name"], "admin");
}

#[tokio::test]
async fn a_pin_session_never_stores_or_reveals_and_a_pin_only_revealer_blocks_the_vault() {
    let h = Harness::new(Profile::Home).await;
    // The administrator's first session was a PIN login.
    let pin_admin = h.login("admin", ADMIN_PIN).await;
    let body = json!({ "name": "x", "kind": "password", "value": "example-value" });
    let refused = h
        .call(
            "POST",
            "/secrets",
            Credential::Cookie(&pin_admin),
            Some(&body),
        )
        .await;
    refused.assert_problem(403, "auth.step_up_required");
    assert_eq!(refused.body["params"]["required"], "password");

    // An operator who signs in with a PIN alone keeps the vault from taking secrets.
    h.create_user("olga", &["operator"]).await;
    let blocked = h
        .call(
            "POST",
            "/secrets",
            Credential::Cookie(&h.admin),
            Some(&body),
        )
        .await;
    blocked.assert_problem(409, "vault.pin_coupling");
    assert_eq!(blocked.body["params"]["accounts"], "olga");
    // A viewer cannot reveal, so a PIN is fine for them.
    h.create_user("vera", &["viewer"]).await;
    let olga_pin = h.login("olga", USER_PIN).await;
    h.passkey_session(&olga_pin, "olga").await;
    let id = h
        .call(
            "POST",
            "/secrets",
            Credential::Cookie(&h.admin),
            Some(&body),
        )
        .await;
    id.assert_status(201);
    let id = id.body["id"].as_str().expect("id").to_owned();

    // Once the vault holds a secret, a PIN session reveals nothing.
    let refused = h
        .call(
            "POST",
            &reveal_path(&id),
            Credential::Cookie(&pin_admin),
            None,
        )
        .await;
    refused.assert_problem(403, "auth.step_up_required");
    assert_eq!(refused.body["params"]["required"], "password");
    let denied = h.audit_of("vault.secret.reveal").await;
    assert_eq!(denied.len(), 1, "the refusal is audited");
    assert_eq!(denied[0]["draft"]["outcome"]["kind"], "denied");
    assert_eq!(
        denied[0]["draft"]["details"]["context"]["code"],
        "auth.step_up_required"
    );
}

#[tokio::test]
async fn viewers_see_nothing_and_operators_read_and_reveal_but_do_not_manage() {
    let h = Harness::new(Profile::Home).await;
    h.create_user("olga", &["operator"]).await;
    h.create_user("vera", &["viewer"]).await;
    let olga = h
        .passkey_session(&h.login("olga", USER_PIN).await, "olga")
        .await;
    let vera = h.login("vera", USER_PIN).await;
    let id = h.create_secret("nas admin", "admin", "example-value").await;
    let (host, _) = h
        .create_host("nas01", "192.0.2.0/24", "192.0.2.10", true)
        .await;
    h.bind(&host, json!([{ "secret": id, "role": "admin" }]))
        .await
        .assert_status(200);

    let viewer = Credential::Cookie(&vera);
    let list = h.call("GET", "/secrets", viewer, None).await;
    list.assert_status(200);
    assert_eq!(list.body["items"], json!([]));
    h.call("GET", &format!("/secrets/{id}"), viewer, None)
        .await
        .assert_problem(403, "auth.forbidden");
    h.call("GET", &format!("/secrets/{id}/references"), viewer, None)
        .await
        .assert_problem(403, "auth.forbidden");
    h.call("GET", &format!("/hosts/{host}/credentials"), viewer, None)
        .await
        .assert_problem(403, "auth.forbidden");
    h.call("POST", &reveal_path(&id), viewer, None)
        .await
        .assert_problem(403, "auth.forbidden");

    let operator = Credential::Cookie(&olga);
    let list = h.call("GET", "/secrets", operator, None).await;
    assert_eq!(list.body["items"].as_array().expect("items").len(), 1);
    let credentials = h
        .call("GET", &format!("/hosts/{host}/credentials"), operator, None)
        .await;
    credentials.assert_status(200);
    assert_eq!(credentials.body["items"][0]["role"], "admin");
    let revealed = h.call("POST", &reveal_path(&id), operator, None).await;
    revealed.assert_status(200);
    assert_eq!(revealed.body["value"], "example-value");
    for (method, path, body) in [
        (
            "POST",
            "/secrets".to_owned(),
            Some(json!({ "name": "x", "kind": "token", "value": "example-value" })),
        ),
        (
            "PATCH",
            format!("/secrets/{id}"),
            Some(json!({ "name": "renamed" })),
        ),
        ("DELETE", format!("/secrets/{id}"), None),
        (
            "PUT",
            format!("/hosts/{host}/credentials"),
            Some(json!({ "credentials": [] })),
        ),
    ] {
        h.call(method, &path, operator, body.as_ref())
            .await
            .assert_problem(403, "auth.forbidden");
    }
}

#[tokio::test]
async fn a_personal_token_never_reveals() {
    let h = Harness::new(Profile::Home).await;
    let id = h.create_secret("nas admin", "admin", "example-value").await;
    let token = h
        .call(
            "POST",
            "/auth/tokens",
            Credential::Cookie(&h.admin),
            Some(&json!({ "name": "automation" })),
        )
        .await;
    token.assert_status(201);
    let token = token.body["token"].as_str().expect("a token").to_owned();
    h.call("GET", "/secrets", Credential::Bearer(&token), None)
        .await
        .assert_status(200);
    h.call("POST", &reveal_path(&id), Credential::Bearer(&token), None)
        .await
        .assert_problem(403, "auth.forbidden");
}

#[tokio::test]
async fn the_standard_profile_asks_for_a_sign_in_within_five_minutes() {
    let h = Harness::new(Profile::Standard).await;
    let id = h.create_secret("nas admin", "admin", "example-value").await;
    let stale = h.aged_admin_session(Duration::from_secs(600)).await;
    let refused = h
        .call("POST", &reveal_path(&id), Credential::Cookie(&stale), None)
        .await;
    refused.assert_problem(403, "auth.step_up_required");
    assert_eq!(refused.body["params"]["required"], "fresh");
    h.call(
        "POST",
        &reveal_path(&id),
        Credential::Cookie(&h.admin),
        None,
    )
    .await
    .assert_status(200);
}

#[tokio::test]
async fn the_hardened_profile_reveals_only_for_the_host_in_view_with_a_passkey() {
    let h = Harness::new(Profile::Hardened).await;
    let id = h.create_secret("nas admin", "admin", "example-value").await;
    let (host, _) = h
        .create_host("nas01", "192.0.2.0/24", "192.0.2.10", true)
        .await;
    let (other, _) = h
        .create_host("nas02", "192.0.2.0/24", "192.0.2.11", true)
        .await;
    h.bind(&host, json!([{ "secret": id, "role": "admin" }]))
        .await
        .assert_status(200);
    let admin = Credential::Cookie(&h.admin);
    h.call("POST", &reveal_path(&id), admin, None)
        .await
        .assert_problem(403, "vault.reveal.host_required");
    h.call(
        "POST",
        &reveal_path(&id),
        admin,
        Some(&json!({ "host": other })),
    )
    .await
    .assert_problem(403, "vault.reveal.not_bound");
    let revealed = h
        .call(
            "POST",
            &reveal_path(&id),
            admin,
            Some(&json!({ "host": host, "reason": "maintenance" })),
        )
        .await;
    revealed.assert_status(200);
    assert_eq!(revealed.body["value"], "example-value");
    let stale = h.aged_admin_session(Duration::from_secs(600)).await;
    let refused = h
        .call(
            "POST",
            &reveal_path(&id),
            Credential::Cookie(&stale),
            Some(&json!({ "host": host })),
        )
        .await;
    refused.assert_problem(403, "auth.step_up_required");
    assert_eq!(refused.body["params"]["required"], "passkey");
}

#[tokio::test]
async fn reveals_are_rate_limited_with_retry_after() {
    let h = Harness::new(Profile::Home).await;
    let id = h.create_secret("nas admin", "admin", "example-value").await;
    let admin = Credential::Cookie(&h.admin);
    for _ in 0..tenko_vault::operator::REVEALS_PER_WINDOW {
        h.call("POST", &reveal_path(&id), admin, None)
            .await
            .assert_status(200);
    }
    let limited = h.call("POST", &reveal_path(&id), admin, None).await;
    limited.assert_problem(429, "vault.reveal.rate_limited");
    assert!(limited.header("retry-after").is_some());
}

#[tokio::test]
async fn host_credentials_bind_unbind_and_keep_a_bound_secret_from_deletion() {
    let h = Harness::new(Profile::Home).await;
    let admin = Credential::Cookie(&h.admin);
    let a = h.create_secret("nas admin", "admin", "example-a").await;
    let b = h.create_secret("nas rdp", "rdpuser", "example-b").await;
    let (host, _) = h
        .create_host("nas01", "192.0.2.0/24", "192.0.2.10", true)
        .await;
    let empty = h
        .call("GET", &format!("/hosts/{host}/credentials"), admin, None)
        .await;
    empty.assert_status(200);
    let etag = empty.header("etag").expect("an ETag").to_owned();
    let bound = h
        .call_with(
            "PUT",
            &format!("/hosts/{host}/credentials"),
            admin,
            Some(&json!({ "credentials": [
                { "secret": a, "role": "admin" },
                { "secret": b, "role": "rdp" }
            ] })),
            &[("if-match", &etag)],
        )
        .await;
    bound.assert_status(200);
    assert_eq!(bound.body["items"].as_array().expect("items").len(), 2);
    h.call_with(
        "PUT",
        &format!("/hosts/{host}/credentials"),
        admin,
        Some(&json!({ "credentials": [] })),
        &[("if-match", &etag)],
    )
    .await
    .assert_problem(409, "vault.host_credentials.conflict");
    h.bind(
        &host,
        json!([{ "secret": a, "role": "admin" }, { "secret": a, "role": "ssh" }]),
    )
    .await
    .assert_problem(422, "vault.secret.invalid");
    h.bind(
        &host,
        json!([{ "secret": uuid::Uuid::now_v7().to_string(), "role": "admin" }]),
    )
    .await
    .assert_problem(422, "vault.host_credentials.secret_missing");
    let unknown = uuid::Uuid::now_v7().to_string();
    h.call("GET", &format!("/hosts/{unknown}/credentials"), admin, None)
        .await
        .assert_problem(404, "ipam.not_found");

    let references = h
        .call("GET", &format!("/secrets/{a}/references"), admin, None)
        .await;
    references.assert_status(200);
    assert_eq!(references.body["hosts"][0]["name"], "nas01");
    assert_eq!(references.body["hosts"][0]["role"], "admin");
    let in_use = h
        .call("DELETE", &format!("/secrets/{a}"), admin, None)
        .await;
    in_use.assert_problem(409, "vault.secret.in_use");
    assert_eq!(in_use.body["params"]["hosts"], "1");

    let listed = h
        .call("GET", &format!("/secrets?host={host}"), admin, None)
        .await;
    assert_eq!(listed.body["items"].as_array().expect("items").len(), 2);
    h.bind(&host, json!([{ "secret": b, "role": "rdp" }]))
        .await
        .assert_status(200);
    h.call("DELETE", &format!("/secrets/{a}"), admin, None)
        .await
        .assert_status(204);
    let audit = h.audit_of("vault.host.credentials").await;
    assert_eq!(audit.len(), 2);
}
