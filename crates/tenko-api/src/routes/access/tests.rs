//! The access routes and scoped access across the whole API (IAM-01, IAM-06, IAM-10): an
//! installation with authentication, IPAM, the anchors index and the scoped event filter
//! wired as the server wires them, two prefix trees, and principals whose grants cover one
//! of them.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
    Extension,
    body::Body,
    http::{Request, header},
};
use futures::StreamExt as _;
use serde_json::{Value, json};
use tenko_auth::{settings::Profile, testing::TestEnv};
use tenko_core::{Timestamp, UserId};
use tenko_ipam::{IpamService, scope::ScopeIndex};
use tenko_store::Store;
use tokio::sync::watch;
use tower::ServiceExt as _;

use super::super::auth::testkit::{Credential, Credential::*, Harness, Reply};
use crate::{API_BASE, sse::filter::ScopedEvents};

const PIN: &str = "7391";

/// The installation, its administrator and the objects in it.
struct Lab {
    harness: Harness,
    admin: String,
    /// 192.0.2.0/24, the parent of the granted prefix (context only).
    outer: String,
    /// 192.0.2.0/25, the prefix the scoped principals hold with its subtree.
    granted: String,
    /// 198.51.100.0/24, outside every grant.
    foreign: String,
    /// A host with an address in the granted prefix.
    inside_host: String,
    inside_address: String,
    inside_interface: String,
    /// A host with an address in the foreign prefix.
    foreign_host: String,
    foreign_address: String,
    foreign_interface: String,
    _stop: watch::Sender<bool>,
}

impl Lab {
    async fn new() -> Self {
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
        let scope = Arc::new(ScopeIndex::new());
        store
            .register_index(Arc::clone(&scope) as _)
            .expect("register the anchors index");
        env.service.set_anchor_resolver(Arc::clone(&scope) as _);
        let ipam = IpamService::with_direct_jobs(Arc::clone(&store)).expect("ipam");
        let (stop, stopped) = watch::channel(false);
        let authorizer = env.service.authorizer();
        let harness = Harness::wired(env, move |state| {
            state.events().set_filter(Box::new(ScopedEvents::new(
                authorizer,
                Arc::clone(&scope),
                Arc::clone(&store),
            )));
            state.events().spawn_tasks(Arc::clone(&store), stopped);
            crate::api(state)
                .0
                .layer(Extension(ipam))
                .layer(Extension(scope))
        });
        let mut lab = Self {
            harness,
            admin,
            outer: String::new(),
            granted: String::new(),
            foreign: String::new(),
            inside_host: String::new(),
            inside_address: String::new(),
            inside_interface: String::new(),
            foreign_host: String::new(),
            foreign_address: String::new(),
            foreign_interface: String::new(),
            _stop: stop,
        };
        lab.outer = lab
            .create(
                "/prefixes",
                json!({ "cidr": "192.0.2.0/24", "role": "supernet" }),
            )
            .await;
        lab.granted = lab
            .create("/prefixes", json!({ "cidr": "192.0.2.0/25" }))
            .await;
        lab.foreign = lab
            .create("/prefixes", json!({ "cidr": "198.51.100.0/24" }))
            .await;
        (lab.inside_host, lab.inside_interface, lab.inside_address) =
            lab.host("inside-host", "192.0.2.10").await;
        (lab.foreign_host, lab.foreign_interface, lab.foreign_address) =
            lab.host("foreign-host", "198.51.100.10").await;
        lab
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        as_: Credential<'_>,
        body: Option<&Value>,
    ) -> Reply {
        self.harness.call(method, path, as_, body).await
    }

    /// Creates an object as the administrator and returns its id.
    async fn create(&self, path: &str, body: Value) -> String {
        let reply = self
            .call("POST", path, Cookie(&self.admin), Some(&body))
            .await;
        reply.assert_status(201);
        reply.body["item"]["id"]
            .as_str()
            .expect("an item id")
            .to_owned()
    }

    /// A host with one interface and one address: the ids of the three.
    async fn host(&self, name: &str, ip: &str) -> (String, String, String) {
        let host = self
            .create(
                "/hosts",
                json!({ "name": name, "interfaces": [{ "name": "eth0" }] }),
            )
            .await;
        let interfaces = self
            .call(
                "GET",
                &format!("/hosts/{host}/interfaces"),
                Cookie(&self.admin),
                None,
            )
            .await;
        interfaces.assert_status(200);
        let interface = interfaces.body["items"][0]["id"]
            .as_str()
            .expect("an interface")
            .to_owned();
        let address = self
            .create("/addresses", json!({ "ip": ip, "interface": interface }))
            .await;
        (host, interface, address)
    }

    /// A user without global roles, signed in: its id and session secret.
    async fn person(&self, name: &str, roles: &[&str]) -> (String, String) {
        let user = self
            .harness
            .create_user(&self.admin, name, PIN, roles)
            .await;
        let id = user["id"].as_str().expect("an id").to_owned();
        let session = self.harness.login(name, PIN).await;
        (id, session)
    }

    /// Grants `role` over the granted prefix and its subtree to `subject`.
    async fn grant(&self, subject: &str, role: &str, delegable: bool) -> Value {
        let reply = self
            .call(
                "POST",
                "/access/grants",
                Cookie(&self.admin),
                Some(&json!({
                    "subject": subject,
                    "role": role,
                    "scope": { "kind": "prefix", "value": { "id": self.granted, "subtree": true } },
                    "delegable": delegable,
                })),
            )
            .await;
        reply.assert_status(201);
        reply.body
    }

    /// The scoped operator: no global role, operator over the granted subtree.
    async fn scoped_operator(&self) -> String {
        let (id, session) = self.person("scoped-operator", &[]).await;
        self.grant(&id, "operator", false).await;
        session
    }

    /// Everything a scoped principal must never see.
    fn foreign_marks(&self) -> Vec<&str> {
        vec![
            self.foreign.as_str(),
            self.foreign_host.as_str(),
            self.foreign_address.as_str(),
            self.foreign_interface.as_str(),
            "198.51.100.",
            "foreign-host",
        ]
    }
}

fn ids(reply: &Reply) -> BTreeSet<String> {
    reply.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("an id").to_owned())
        .collect()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn grants_are_created_listed_and_revoked_with_the_grants_issued_under_them() {
    let lab = Lab::new().await;
    let (delegate, delegate_session) = lab.person("delegate", &[]).await;
    let (holder, _) = lab.person("holder", &[]).await;

    // Without a body that fits the schema, and for a global-only role.
    lab.call(
        "POST",
        "/access/grants",
        Cookie(&lab.admin),
        Some(&json!({})),
    )
    .await
    .assert_problem(400, "sys.invalid_request");
    lab.call(
        "POST",
        "/access/grants",
        Cookie(&lab.admin),
        Some(&json!({
            "subject": delegate,
            "role": "admin",
            "scope": { "kind": "prefix", "value": { "id": lab.granted, "subtree": true } },
        })),
    )
    .await
    .assert_problem(422, "auth.grant.invalid_role");

    let parent = lab.grant(&delegate, "operator", true).await;
    let parent_id = parent["id"].as_str().expect("an id").to_owned();
    assert_eq!(parent["subject"]["name"], "delegate");
    assert_eq!(parent["scope"]["kind"], "prefix");
    assert_eq!(parent["delegable"], true);
    lab.call(
        "POST",
        "/access/grants",
        Cookie(&lab.admin),
        Some(&json!({
            "subject": delegate,
            "role": "operator",
            "scope": { "kind": "prefix", "value": { "id": lab.granted, "subtree": true } },
            "delegable": true,
        })),
    )
    .await
    .assert_problem(409, "auth.grant.duplicate");

    // The delegate grants a viewer role over the same subtree, never the foreign prefix.
    let child = lab
        .call(
            "POST",
            "/access/grants",
            Cookie(&delegate_session),
            Some(&json!({
                "subject": holder,
                "role": "viewer",
                "scope": { "kind": "prefix", "value": { "id": lab.granted, "subtree": true } },
            })),
        )
        .await;
    child.assert_status(201);
    assert!(
        child
            .header("location")
            .is_some_and(|l| l.starts_with(API_BASE))
    );
    assert_eq!(child.body["parent"], parent_id.as_str());
    let child_id = child.body["id"].as_str().expect("an id").to_owned();
    lab.call(
        "POST",
        "/access/grants",
        Cookie(&delegate_session),
        Some(&json!({
            "subject": holder,
            "role": "viewer",
            "scope": { "kind": "prefix", "value": { "id": lab.foreign, "subtree": true } },
        })),
    )
    .await
    .assert_problem(403, "auth.grant.exceeds_own");

    // The administrator sees both; the delegate its own and the one issued under it; the
    // subject filter narrows the list.
    let all = lab
        .call("GET", "/access/grants", Cookie(&lab.admin), None)
        .await;
    all.assert_status(200);
    assert_eq!(
        ids(&all),
        BTreeSet::from([parent_id.clone(), child_id.clone()])
    );
    let own = lab
        .call("GET", "/access/grants", Cookie(&delegate_session), None)
        .await;
    assert_eq!(
        ids(&own),
        BTreeSet::from([parent_id.clone(), child_id.clone()])
    );
    let narrowed = lab
        .call(
            "GET",
            &format!("/access/grants?subject={holder}"),
            Cookie(&lab.admin),
            None,
        )
        .await;
    assert_eq!(ids(&narrowed), BTreeSet::from([child_id.clone()]));
    lab.call("GET", "/access/grants?subject=x", Cookie(&lab.admin), None)
        .await
        .assert_status(400);
    lab.call("GET", "/access/grants?nope=1", Cookie(&lab.admin), None)
        .await
        .assert_problem(400, "sys.invalid_query");

    // The subjects of a grant, for the administrator and for a delegating holder.
    for session in [&lab.admin, &delegate_session] {
        let subjects = lab
            .call("GET", "/access/subjects", Cookie(session), None)
            .await;
        subjects.assert_status(200);
        let names: Vec<&str> = subjects.body["items"]
            .as_array()
            .expect("items")
            .iter()
            .filter_map(|subject| subject["name"].as_str())
            .collect();
        assert!(
            names.contains(&"holder") && names.contains(&"delegate"),
            "{names:?}"
        );
    }

    // Revoking the delegable grant revokes the one issued under it.
    let revoked = lab
        .call(
            "DELETE",
            &format!("/access/grants/{parent_id}"),
            Cookie(&lab.admin),
            None,
        )
        .await;
    revoked.assert_status(200);
    assert_eq!(revoked.body["revoked"], json!([parent_id, child_id]));
    let empty = lab
        .call("GET", "/access/grants", Cookie(&lab.admin), None)
        .await;
    assert_eq!(ids(&empty).len(), 0);
    lab.call(
        "DELETE",
        &format!("/access/grants/{parent_id}"),
        Cookie(&lab.admin),
        None,
    )
    .await
    .assert_problem(404, "auth.grant.not_found");
    lab.call(
        "DELETE",
        "/access/grants/not-a-uuid",
        Cookie(&lab.admin),
        None,
    )
    .await
    .assert_status(400);
    let actions = lab.harness.audit_actions().await;
    assert!(
        actions.iter().any(|action| action == "auth.grant.create"),
        "{actions:?}"
    );
    assert!(
        actions.iter().any(|action| action == "auth.grant.revoke"),
        "{actions:?}"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_service_account_acts_through_a_scoped_token_that_follows_its_grants() {
    let lab = Lab::new().await;
    let created = lab
        .call(
            "POST",
            "/access/service-accounts",
            Cookie(&lab.admin),
            Some(&json!({ "name": "sync-robot", "display_name": "Sync robot" })),
        )
        .await;
    created.assert_status(201);
    assert_eq!(created.body["kind"], "service");
    let account = created.body["id"].as_str().expect("an id").to_owned();
    assert_eq!(
        created.header("location"),
        Some(format!("{API_BASE}/users/{account}").as_str())
    );
    let listed = lab
        .call("GET", "/access/service-accounts", Cookie(&lab.admin), None)
        .await;
    listed.assert_status(200);
    assert_eq!(ids(&listed), BTreeSet::from([account.clone()]));

    // It has no password, so it cannot sign in.
    lab.call(
        "POST",
        "/auth/login/password",
        Anonymous,
        Some(&json!({ "user_name": "sync-robot", "password": PIN })),
    )
    .await
    .assert_status(401);

    let grant = lab.grant(&account, "viewer", false).await;
    let token = lab
        .call(
            "POST",
            &format!("/access/service-accounts/{account}/tokens"),
            Cookie(&lab.admin),
            Some(&json!({
                "name": "inventory",
                "grants": [{
                    "role": "viewer",
                    "scope": { "kind": "prefix", "value": { "id": lab.granted, "subtree": true } },
                }],
            })),
        )
        .await;
    token.assert_status(201);
    assert_eq!(token.header("cache-control"), Some("no-store"));
    let secret = token.body["token"].as_str().expect("the secret").to_owned();
    let token_id = token.body["info"]["id"]
        .as_str()
        .expect("a token id")
        .to_owned();
    let tokens = lab
        .call(
            "GET",
            &format!("/access/service-accounts/{account}/tokens"),
            Cookie(&lab.admin),
            None,
        )
        .await;
    tokens.assert_status(200);
    assert_eq!(tokens.body["items"][0]["scoped"], true);

    // A grant wider than the account's is refused.
    lab.call(
        "POST",
        &format!("/access/service-accounts/{account}/tokens"),
        Cookie(&lab.admin),
        Some(&json!({
            "name": "wider",
            "grants": [{
                "role": "viewer",
                "scope": { "kind": "prefix", "value": { "id": lab.foreign, "subtree": true } },
            }],
        })),
    )
    .await
    .assert_problem(403, "auth.grant.exceeds_own");

    // The token reads the granted subtree and nothing else.
    let prefixes = lab.call("GET", "/prefixes", Bearer(&secret), None).await;
    prefixes.assert_status(200);
    assert_eq!(ids(&prefixes), BTreeSet::from([lab.granted.clone()]));
    lab.call(
        "GET",
        &format!("/prefixes/{}", lab.foreign),
        Bearer(&secret),
        None,
    )
    .await
    .assert_problem(403, "auth.out_of_scope");
    lab.call(
        "PATCH",
        &format!("/prefixes/{}", lab.granted),
        Bearer(&secret),
        Some(&json!({ "description": "changed" })),
    )
    .await
    .assert_problem(403, "auth.forbidden");

    // When the account loses its grant, the token loses the right at once.
    let grant_id = grant["id"].as_str().expect("an id");
    lab.call(
        "DELETE",
        &format!("/access/grants/{grant_id}"),
        Cookie(&lab.admin),
        None,
    )
    .await
    .assert_status(200);
    let after = lab.call("GET", "/prefixes", Bearer(&secret), None).await;
    let refused = after.status.as_u16() == 403;
    assert!(refused || ids(&after).is_empty(), "{}", after.body);
    lab.call(
        "GET",
        &format!("/prefixes/{}", lab.granted),
        Bearer(&secret),
        None,
    )
    .await
    .assert_status(403);

    lab.call(
        "DELETE",
        &format!("/access/service-accounts/{account}/tokens/{token_id}"),
        Cookie(&lab.admin),
        None,
    )
    .await
    .assert_status(204);
    lab.call("GET", "/prefixes", Bearer(&secret), None)
        .await
        .assert_status(401);
    lab.call(
        "GET",
        &format!("/access/service-accounts/{}/tokens", UserId::generate()),
        Cookie(&lab.admin),
        None,
    )
    .await
    .assert_problem(404, "auth.service_account.not_found");
}

#[tokio::test]
async fn role_policies_are_read_set_and_cleared() {
    let lab = Lab::new().await;
    let listed = lab
        .call("GET", "/access/role-policies", Cookie(&lab.admin), None)
        .await;
    listed.assert_status(200);
    let roles: Vec<&str> = listed.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|policy| policy["role"].as_str())
        .collect();
    assert_eq!(roles, ["admin", "operator", "viewer", "auditor"]);

    let set = lab
        .call(
            "PUT",
            "/access/role-policies/operator",
            Cookie(&lab.admin),
            Some(&json!({ "mfa": "passkey" })),
        )
        .await;
    set.assert_status(200);
    assert_eq!(set.body["mfa"], "passkey");
    assert_eq!(set.body["stored"], "passkey");

    // A scoped operator now needs a passkey session for the operator's actions; a viewer
    // does not.
    let operator = lab.scoped_operator().await;
    lab.call(
        "PATCH",
        &format!("/prefixes/{}", lab.granted),
        Cookie(&operator),
        Some(&json!({ "description": "changed" })),
    )
    .await
    .assert_problem(403, "auth.step_up_required");
    let (viewer, viewer_session) = lab.person("scoped-viewer", &[]).await;
    lab.grant(&viewer, "viewer", false).await;
    lab.call(
        "GET",
        &format!("/prefixes/{}", lab.granted),
        Cookie(&viewer_session),
        None,
    )
    .await
    .assert_status(200);

    let cleared = lab
        .call(
            "DELETE",
            "/access/role-policies/operator",
            Cookie(&lab.admin),
            None,
        )
        .await;
    cleared.assert_status(200);
    assert_eq!(cleared.body["stored"], Value::Null);
    assert_eq!(cleared.body["mfa"], cleared.body["profile_default"]);
    lab.call(
        "PATCH",
        &format!("/prefixes/{}", lab.granted),
        Cookie(&operator),
        Some(&json!({ "description": "changed" })),
    )
    .await
    .assert_status(200);

    lab.call(
        "PUT",
        "/access/role-policies/nobody",
        Cookie(&lab.admin),
        Some(&json!({ "mfa": "passkey" })),
    )
    .await
    .assert_status(400);
    lab.call(
        "PUT",
        "/access/role-policies/viewer",
        Cookie(&operator),
        Some(&json!({ "mfa": "passkey" })),
    )
    .await
    .assert_problem(403, "auth.forbidden");
}

#[tokio::test]
async fn a_scoped_operator_sees_and_edits_only_its_subtree() {
    let lab = Lab::new().await;
    let operator = lab.scoped_operator().await;

    let prefixes = lab.call("GET", "/prefixes", Cookie(&operator), None).await;
    prefixes.assert_status(200);
    assert_eq!(ids(&prefixes), BTreeSet::from([lab.granted.clone()]));
    let hosts = lab.call("GET", "/hosts", Cookie(&operator), None).await;
    assert_eq!(ids(&hosts), BTreeSet::from([lab.inside_host.clone()]));
    let addresses = lab.call("GET", "/addresses", Cookie(&operator), None).await;
    assert_eq!(
        ids(&addresses),
        BTreeSet::from([lab.inside_address.clone()])
    );

    // The tree shows the parent of the granted prefix as a context row, CIDR only.
    let tree = lab
        .call("GET", "/prefixes/tree", Cookie(&operator), None)
        .await;
    tree.assert_status(200);
    assert!(!tree.text.contains("198.51.100."), "{}", tree.text);
    let context = tree.body["context"].as_array().expect("context rows");
    assert_eq!(context.len(), 1, "{}", tree.body);
    assert_eq!(context[0]["id"], lab.outer.as_str());
    assert_eq!(context[0]["cidr"], "192.0.2.0/24");

    for path in [
        format!("/prefixes/{}", lab.foreign),
        format!("/prefixes/{}", lab.outer),
        format!("/hosts/{}", lab.foreign_host),
        format!("/addresses/{}", lab.foreign_address),
        format!("/interfaces/{}", lab.foreign_interface),
    ] {
        lab.call("GET", &path, Cookie(&operator), None)
            .await
            .assert_problem(403, "auth.out_of_scope");
    }
    lab.call(
        "GET",
        &format!("/hosts/{}", lab.inside_host),
        Cookie(&operator),
        None,
    )
    .await
    .assert_status(200);

    // Writes inside the subtree pass; outside, or out of it, are refused.
    lab.call(
        "PATCH",
        &format!("/prefixes/{}", lab.granted),
        Cookie(&operator),
        Some(&json!({ "description": "mine" })),
    )
    .await
    .assert_status(200);
    lab.call(
        "PATCH",
        &format!("/prefixes/{}", lab.foreign),
        Cookie(&operator),
        Some(&json!({ "description": "theirs" })),
    )
    .await
    .assert_problem(403, "auth.out_of_scope");
    lab.call(
        "POST",
        "/addresses",
        Cookie(&operator),
        Some(&json!({ "ip": "192.0.2.20" })),
    )
    .await
    .assert_status(201);
    lab.call(
        "POST",
        "/prefixes",
        Cookie(&operator),
        Some(&json!({ "cidr": "198.51.100.0/25" })),
    )
    .await
    .assert_problem(403, "auth.out_of_scope");
    lab.call(
        "POST",
        "/addresses",
        Cookie(&operator),
        Some(&json!({ "ip": "198.51.100.20" })),
    )
    .await
    .assert_problem(403, "auth.out_of_scope");
    lab.call(
        "PATCH",
        &format!("/addresses/{}", lab.inside_address),
        Cookie(&operator),
        Some(&json!({ "ip": "198.51.100.30" })),
    )
    .await
    .assert_problem(403, "auth.out_of_scope");
    lab.call(
        "DELETE",
        &format!("/hosts/{}", lab.foreign_host),
        Cookie(&operator),
        None,
    )
    .await
    .assert_problem(403, "auth.out_of_scope");
    // Global-only kinds stay out of reach.
    lab.call("GET", "/users", Cookie(&operator), None)
        .await
        .assert_problem(403, "auth.forbidden");
}

/// Every operation of the document called by a scoped principal with the identifiers of
/// objects outside its scope: 403, another refusal or a filtered answer, never a server
/// error and never a foreign object (R24).
#[tokio::test]
async fn every_operation_answers_a_scoped_principal_without_foreign_objects() {
    let lab = Lab::new().await;
    let operator = lab.scoped_operator().await;
    let document = serde_json::to_value(crate::openapi()).expect("document");
    let paths = document["paths"].as_object().expect("paths");
    let marks = lab.foreign_marks();
    let mut called = 0_usize;
    for (template, item) in paths {
        for method in ["get", "post", "put", "patch", "delete"] {
            if item.get(method).is_none() {
                continue;
            }
            // The stream never ends, and ending the session would end the test's.
            if template == "/events"
                || template.starts_with("/auth/logout")
                || (method == "delete" && template.starts_with("/auth/sessions"))
            {
                continue;
            }
            let id = match template.split('/').nth(1).unwrap_or_default() {
                "prefixes" | "ranges" => lab.foreign.clone(),
                "hosts" | "users" | "access" => lab.foreign_host.clone(),
                "addresses" => lab.foreign_address.clone(),
                "interfaces" => lab.foreign_interface.clone(),
                _ => "0190d1c2-0000-7000-8000-000000000001".to_owned(),
            };
            let path = template
                .replace("{id}", &id)
                .replace("{prefix}", &lab.foreign)
                .replace("{host}", &lab.foreign_host)
                .replace("{token}", "0190d1c2-0000-7000-8000-000000000002")
                .replace("{role}", "viewer")
                .replace("{key}", "owner")
                .replace("{seq}", "1")
                .replace("{index}", "0")
                .replace("{subject}", "198.51.100.10");
            let upper = method.to_uppercase();
            let body = (method != "get" && method != "delete").then(|| json!({}));
            let reply = lab
                .call(&upper, &path, Cookie(&operator), body.as_ref())
                .await;
            called += 1;
            let status = reply.status.as_u16();
            let label = format!("{upper} {path}: {status} {}", reply.text);
            assert!(status < 500 || status == 501 || status == 503, "{label}");
            assert_ne!(status, 401, "{label}");
            if (200..300).contains(&status) {
                for mark in &marks {
                    assert!(!reply.text.contains(mark), "{mark} leaks in {label}");
                }
                let names_foreign = template.contains('{') && path.contains(&lab.foreign)
                    || path.contains(&lab.foreign_host)
                    || path.contains(&lab.foreign_address)
                    || path.contains(&lab.foreign_interface);
                assert!(
                    !(names_foreign && method != "get"),
                    "a write on a foreign object succeeded: {label}"
                );
            }
        }
    }
    assert!(called > 150, "only {called} operations");
}

/// Reads the event stream of `session` until `wanted` appears or two seconds pass; the
/// text of every data frame read.
async fn events_until(lab: &Lab, session: &str, wanted: &str) -> String {
    let request = Request::builder()
        .uri(format!("{API_BASE}/events?topics=ipam"))
        .header(header::COOKIE, format!("tenko_session={session}"))
        .body(Body::empty())
        .expect("request");
    let response = lab
        .harness
        .router()
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), 200);
    let mut stream = response.into_body().into_data_stream();
    let mut seen = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !seen.contains(wanted) {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => seen.push_str(&String::from_utf8_lossy(&chunk)),
            _ => break,
        }
    }
    seen
}

#[tokio::test]
async fn server_sent_events_carry_no_foreign_reference() {
    let lab = Lab::new().await;
    let operator = lab.scoped_operator().await;
    let watcher = {
        let session = operator.clone();
        let granted = lab.granted.clone();
        let lab = &lab;
        async move { events_until(lab, &session, &granted).await }
    };
    let writer = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        for prefix in [&lab.foreign, &lab.granted] {
            lab.call(
                "PATCH",
                &format!("/prefixes/{prefix}"),
                Cookie(&lab.admin),
                Some(&json!({ "description": "touched" })),
            )
            .await
            .assert_status(200);
        }
    };
    let (seen, ()) = tokio::join!(watcher, writer);
    assert!(
        seen.contains(&lab.granted),
        "the granted prefix's event arrives: {seen}"
    );
    for mark in lab.foreign_marks() {
        assert!(!seen.contains(mark), "{mark} leaks: {seen}");
    }
}

/// One commit that changes an object inside the scope and one outside: the scoped
/// subscriber receives the frame narrowed to its own reference, the administrator the
/// whole frame.
#[tokio::test]
async fn a_frame_with_foreign_and_own_references_is_narrowed() {
    let lab = Lab::new().await;
    let operator = lab.scoped_operator().await;
    let scoped = events_until(&lab, &operator, &lab.granted);
    let whole = events_until(&lab, &lab.admin, &lab.foreign);
    let writer = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let operations: Vec<Value> = [&lab.foreign, &lab.granted]
            .into_iter()
            .map(|id| {
                json!({ "op": "update_prefix", "args": { "id": id, "patch": { "description": "both" } } })
            })
            .collect();
        lab.call(
            "POST",
            "/prefixes/bulk",
            Cookie(&lab.admin),
            Some(&json!({ "operations": operations })),
        )
        .await
        .assert_status(200);
    };
    let (scoped, whole, ()) = tokio::join!(scoped, whole, writer);
    let frame = |text: &str, id: &str| {
        text.split("\n\n")
            .find(|frame| frame.contains(id))
            .map(str::to_owned)
            .unwrap_or_default()
    };
    let admin_frame = frame(&whole, &lab.foreign);
    assert!(
        admin_frame.contains(&lab.granted) && admin_frame.contains(&lab.foreign),
        "one frame names both: {whole}"
    );
    let operator_frame = frame(&scoped, &lab.granted);
    assert!(
        !operator_frame.is_empty(),
        "the narrowed frame arrives: {scoped}"
    );
    for mark in lab.foreign_marks() {
        assert!(!scoped.contains(mark), "{mark} leaks: {scoped}");
    }
}
