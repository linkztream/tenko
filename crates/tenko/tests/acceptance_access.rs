//! Scoped access against one real `tenko serve`, black-box through the public API:
//! IAM-01 (object-based roles scoped per prefix, with delegation), IAM-06 (the sign-in
//! requirement per role) and IAM-10 (service accounts and scoped API tokens), as
//! `docs/access.md` and ADR 0015 describe them.
//!
//! Every test starts its own node and builds the same small installation: a supernet
//! 192.0.2.0/24, the prefix 192.0.2.0/25 inside it that people are granted, and the prefix
//! 198.51.100.0/24 beside it that nobody but the administrator holds. The granted and the
//! foreign prefix each hold one host with one address. People sign in with a PIN the
//! administrator set and change it at the first sign-in, as every account created with a
//! password must.

mod serve_support;

use reqwest::Method;
use serde_json::{Value, json};
use serve_support::{
    Node, Proc,
    api::{Api, Reply},
    wait_for_setup_token,
};

/// The PIN the administrator gives a new person; an invented value, digits only as the Home
/// profile accepts.
const INITIAL_PIN: &str = "482917";

/// The PIN a person chooses at the first sign-in.
const CHOSEN_PIN: &str = "915372";

/// The installation of every test, with the administrator signed in.
struct Lab {
    _node: Node,
    server: Proc,
    admin: Api,
    /// 192.0.2.0/24, the parent of the granted prefix.
    outer: String,
    /// 192.0.2.0/25, the prefix people are granted with its subtree.
    granted: String,
    /// 198.51.100.0/24, outside every grant.
    foreign: String,
    /// The host and the address inside the granted prefix.
    inside_host: String,
    inside_address: String,
    /// The host and the address inside the foreign prefix.
    foreign_host: String,
    foreign_address: String,
}

impl Lab {
    #[track_caller]
    fn new() -> Self {
        let mut node = Node::new();
        let server = node.start();
        let token = wait_for_setup_token(&server);
        let mut admin = Api::new(&node);
        admin.setup(&token);
        let id = |reply: Reply| {
            reply.expect(201)["item"]["id"]
                .as_str()
                .expect("an id")
                .to_owned()
        };
        let outer = id(admin.post(
            "/prefixes",
            &json!({ "cidr": "192.0.2.0/24", "role": "supernet" }),
        ));
        let granted = id(admin.post("/prefixes", &json!({ "cidr": "192.0.2.0/25" })));
        let foreign = id(admin.post("/prefixes", &json!({ "cidr": "198.51.100.0/24" })));
        let (inside_host, inside_address) = host(&admin, "inside-host", "192.0.2.10");
        let (foreign_host, foreign_address) = host(&admin, "foreign-host", "198.51.100.10");
        Self {
            _node: node,
            server,
            admin,
            outer,
            granted,
            foreign,
            inside_host,
            inside_address,
            foreign_host,
            foreign_address,
        }
    }

    /// A person without global roles, signed in with the PIN they chose: the user id and
    /// their client.
    #[track_caller]
    fn person(&self, name: &str) -> (String, Api) {
        let created = self
            .admin
            .post(
                "/users",
                &json!({
                    "name": name,
                    "display_name": format!("{name} Example"),
                    "password": INITIAL_PIN,
                    "roles": [],
                }),
            )
            .expect(201);
        let id = created["id"].as_str().expect("a user id").to_owned();
        let mut api = self.admin.anonymous();
        sign_in(&mut api, name, INITIAL_PIN);
        api.post_unkeyed(
            "/auth/password",
            &json!({ "current_password": INITIAL_PIN, "new_password": CHOSEN_PIN }),
        )
        .ok();
        api.post_unkeyed("/auth/logout", &json!({})).ok();
        let mut api = self.admin.anonymous();
        sign_in(&mut api, name, CHOSEN_PIN);
        (id, api)
    }

    /// Grants `role` over the granted prefix and what is inside it.
    #[track_caller]
    fn grant(&self, subject: &str, role: &str, delegable: bool) -> Value {
        self.admin
            .post(
                "/access/grants",
                &json!({
                    "subject": subject,
                    "role": role,
                    "scope": { "kind": "prefix", "value": { "id": self.granted, "subtree": true } },
                    "delegable": delegable,
                }),
            )
            .expect(201)
    }

    /// A person who is operator over the granted prefix only.
    #[track_caller]
    fn scoped_operator(&self) -> Api {
        let (id, api) = self.person("casey");
        self.grant(&id, "operator", false);
        api
    }

    /// A service account without global roles: its user id.
    #[track_caller]
    fn service_account(&self, name: &str) -> String {
        let created = self
            .admin
            .post(
                "/access/service-accounts",
                &json!({ "name": name, "display_name": "Automation", "roles": [] }),
            )
            .expect(201);
        assert_eq!(created["kind"], "service", "{created}");
        created["id"].as_str().expect("an id").to_owned()
    }

    /// Creates a token of a service account as the administrator.
    fn service_token(&self, account: &str, body: &Value) -> Reply {
        self.admin
            .post(&format!("/access/service-accounts/{account}/tokens"), body)
    }

    /// A viewer token over the granted prefix: the secret.
    #[track_caller]
    fn viewer_token(&self, account: &str) -> String {
        self.service_token(
            account,
            &json!({
                "name": "reader",
                "grants": [{
                    "role": "viewer",
                    "scope": { "kind": "prefix", "value": { "id": self.granted, "subtree": true } },
                }],
            }),
        )
        .expect(201)["token"]
            .as_str()
            .expect("the secret")
            .to_owned()
    }

    /// A request with a bearer token and no session.
    fn bearer(&self, secret: &str, method: Method, path: &str, body: Option<&Value>) -> Reply {
        let mut headers = vec![("Authorization", format!("Bearer {secret}"))];
        let body = body.map(|value| {
            headers.push(("Idempotency-Key", uuid::Uuid::now_v7().to_string()));
            ("application/json", serde_json::to_vec(value).expect("JSON"))
        });
        self.admin.anonymous().send(method, path, body, &headers)
    }

    #[track_caller]
    fn finish(mut self) {
        self.server.stop().assert_graceful_shutdown();
    }
}

/// A host with one interface and one address, created by the administrator: the host id
/// and the address id.
#[track_caller]
fn host(admin: &Api, name: &str, ip: &str) -> (String, String) {
    let host = admin
        .post(
            "/hosts",
            &json!({ "name": name, "interfaces": [{ "name": "eth0" }] }),
        )
        .expect(201)["item"]["id"]
        .as_str()
        .expect("a host id")
        .to_owned();
    let interface = admin.get(&format!("/hosts/{host}/interfaces")).expect(200)["items"][0]["id"]
        .as_str()
        .expect("an interface")
        .to_owned();
    let address = admin
        .post("/addresses", &json!({ "ip": ip, "interface": interface }))
        .expect(201)["item"]["id"]
        .as_str()
        .expect("an address id")
        .to_owned();
    (host, address)
}

/// The password login of a person; keeps the session cookie.
#[track_caller]
fn sign_in(api: &mut Api, name: &str, pin: &str) {
    let reply = api.post_unkeyed(
        "/auth/login/password",
        &json!({ "user_name": name, "password": pin }),
    );
    let body = reply.expect(200);
    assert_eq!(body["status"], "authenticated", "{body}");
    let cookie = reply
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|text| text.split(';').next())
        .find(|pair| pair.starts_with("tenko_session="))
        .expect("the login set a session cookie")
        .to_owned();
    api.set_cookie(Some(cookie));
}

/// The ids of the items of a list answer, sorted.
#[track_caller]
fn ids(list: &Value) -> Vec<String> {
    let mut ids: Vec<String> = list["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a list answer: {list}"))
        .iter()
        .map(|item| item["id"].as_str().expect("an id").to_owned())
        .collect();
    ids.sort();
    ids
}

/// The CIDRs of the items of a prefix list, sorted.
#[track_caller]
fn cidrs(list: &Value) -> Vec<String> {
    let mut cidrs: Vec<String> = list["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a list answer: {list}"))
        .iter()
        .map(|item| item["cidr"].as_str().expect("a cidr").to_owned())
        .collect();
    cidrs.sort();
    cidrs
}

/// Asserts a refusal with the status and the stable code.
#[track_caller]
fn assert_refused(reply: &Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.text);
    assert_eq!(reply.code().as_deref(), Some(code), "{}", reply.text);
}

/// Asserts that an answer gives nothing away: a refusal (403), or a list with no item
/// (a list filters what the principal may not read).
#[track_caller]
fn assert_reaches_nothing(reply: &Reply, what: &str) {
    let empty_list = reply.status == 200
        && reply.json()["items"]
            .as_array()
            .is_some_and(std::vec::Vec::is_empty);
    assert!(
        reply.status == 403 || empty_list,
        "{what} must be refused or list nothing: HTTP {} {}",
        reply.status,
        reply.text
    );
}

/// The body text of a successful answer.
#[track_caller]
fn text(reply: &Reply) -> &str {
    assert_eq!(reply.status, 200, "{}", reply.text);
    &reply.text
}

/// IAM-01: a person who is operator over one prefix sees, in every list, in the search, in
/// the prefix tree and in the CSV exports, only what the grant covers; the parent prefix
/// shows in the tree as a context row with its CIDR alone.
#[test]
fn iam_01_a_scoped_operator_sees_only_what_the_grant_covers() {
    let lab = Lab::new();
    let casey = lab.scoped_operator();

    let everyone = lab.admin.get("/prefixes").expect(200);
    assert_eq!(
        ids(&everyone).len(),
        3,
        "the administrator sees all three prefixes: {everyone}"
    );
    let prefixes = casey.get("/prefixes").expect(200);
    assert_eq!(ids(&prefixes), vec![lab.granted.clone()], "{prefixes}");
    let hosts = casey.get("/hosts").expect(200);
    assert_eq!(ids(&hosts), vec![lab.inside_host.clone()], "{hosts}");
    let addresses = casey.get("/addresses").expect(200);
    assert_eq!(
        ids(&addresses),
        vec![lab.inside_address.clone()],
        "{addresses}"
    );

    // Search returns only hits in scope.
    let found = casey.get("/search?q=host").expect(200);
    let labels: Vec<&str> = found["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a search answer: {found}"))
        .iter()
        .filter_map(|hit| hit["label"].as_str())
        .collect();
    assert_eq!(
        labels,
        vec!["inside-host"],
        "search shows only hits in scope: {found}"
    );

    // The tree: the parent of the granted prefix is a context row with the CIDR and no
    // detail; the foreign prefix does not appear at all.
    let tree = casey.get("/prefixes/tree").expect(200);
    assert!(
        !tree.to_string().contains("198.51.100."),
        "the tree leaks the foreign prefix: {tree}"
    );
    let context = tree["context"].as_array().expect("context rows");
    assert_eq!(context.len(), 1, "{tree}");
    assert_eq!(context[0]["id"], lab.outer.as_str(), "{tree}");
    assert_eq!(context[0]["cidr"], "192.0.2.0/24", "{tree}");
    assert!(
        context[0].get("description").is_none() && context[0].get("role").is_none(),
        "a context row carries no detail: {tree}"
    );

    // CSV exports list only what is in scope.
    let hosts_csv = casey.get("/exports/hosts.csv");
    assert!(text(&hosts_csv).contains("inside-host"), "{hosts_csv:?}");
    assert!(!hosts_csv.text.contains("foreign-host"), "{hosts_csv:?}");
    let prefixes_csv = casey.get("/exports/prefixes.csv");
    assert!(
        text(&prefixes_csv).contains("192.0.2.0/25"),
        "{prefixes_csv:?}"
    );
    assert!(
        !prefixes_csv.text.contains("198.51.100."),
        "{prefixes_csv:?}"
    );

    lab.finish();
}

/// IAM-01: the same scoped operator changes objects inside the grant, and is refused with
/// 403 `auth.out_of_scope` when it reads, changes, creates or deletes outside it, or moves
/// an address out of it; kinds that are global-only stay closed (403 `auth.forbidden`).
#[test]
fn iam_01_a_scoped_operator_changes_inside_the_grant_and_is_refused_outside_it() {
    let lab = Lab::new();
    let casey = lab.scoped_operator();

    // Reads outside the scope, including the parent of the granted prefix.
    for path in [
        format!("/prefixes/{}", lab.foreign),
        format!("/prefixes/{}", lab.outer),
        format!("/prefixes/{}/history", lab.foreign),
        format!("/hosts/{}", lab.foreign_host),
        format!("/addresses/{}", lab.foreign_address),
    ] {
        assert_refused(&casey.get(&path), 403, "auth.out_of_scope");
    }
    casey
        .get(&format!("/hosts/{}", lab.inside_host))
        .expect(200);

    // Writes inside the scope pass.
    let revision =
        casey.get(&format!("/prefixes/{}", lab.granted)).expect(200)["meta"]["revision"].as_u64();
    let changed = casey
        .patch(
            &format!("/prefixes/{}", lab.granted),
            &json!({ "description": "mine" }),
            revision,
        )
        .expect(200);
    assert_eq!(changed["item"]["meta"]["description"], "mine", "{changed}");
    casey
        .post("/addresses", &json!({ "ip": "192.0.2.20" }))
        .expect(201);

    // Writes outside it, or out of it, are refused.
    assert_refused(
        &casey.patch(
            &format!("/prefixes/{}", lab.foreign),
            &json!({ "description": "theirs" }),
            None,
        ),
        403,
        "auth.out_of_scope",
    );
    assert_refused(
        &casey.post("/prefixes", &json!({ "cidr": "198.51.100.0/25" })),
        403,
        "auth.out_of_scope",
    );
    assert_refused(
        &casey.post("/addresses", &json!({ "ip": "198.51.100.20" })),
        403,
        "auth.out_of_scope",
    );
    assert_refused(
        &casey.patch(
            &format!("/addresses/{}", lab.inside_address),
            &json!({ "ip": "198.51.100.30" }),
            None,
        ),
        403,
        "auth.out_of_scope",
    );
    assert_refused(
        &casey.delete(&format!("/hosts/{}", lab.foreign_host), None),
        403,
        "auth.out_of_scope",
    );
    // The users of the installation are a global-only kind.
    assert_refused(&casey.get("/users"), 403, "auth.forbidden");

    // Nothing outside the scope changed.
    let foreign = lab
        .admin
        .get(&format!("/prefixes/{}", lab.foreign))
        .expect(200);
    assert_ne!(
        foreign["item"]["meta"]["description"], "theirs",
        "{foreign}"
    );
    lab.admin
        .get(&format!("/hosts/{}", lab.foreign_host))
        .expect(200);
    assert_eq!(
        cidrs(&lab.admin.get("/prefixes").expect(200)),
        vec!["192.0.2.0/24", "192.0.2.0/25", "198.51.100.0/24"]
    );

    lab.finish();
}

/// IAM-01: a viewer grant reads but does not write: the scoped viewer lists the granted
/// prefix, is refused a change inside it with 403 `auth.forbidden`, and a read outside it
/// with 403 `auth.out_of_scope`.
#[test]
fn iam_01_a_scoped_viewer_reads_inside_the_grant_and_cannot_write() {
    let lab = Lab::new();
    let (id, viewer) = lab.person("vera");
    lab.grant(&id, "viewer", false);

    let prefixes = viewer.get("/prefixes").expect(200);
    assert_eq!(ids(&prefixes), vec![lab.granted.clone()], "{prefixes}");
    assert_refused(
        &viewer.patch(
            &format!("/prefixes/{}", lab.granted),
            &json!({ "description": "mine" }),
            None,
        ),
        403,
        "auth.forbidden",
    );
    assert_refused(
        &viewer.get(&format!("/prefixes/{}", lab.foreign)),
        403,
        "auth.out_of_scope",
    );

    lab.finish();
}

/// IAM-01: delegation. The holder of a delegable grant hands a role out over a scope inside
/// its own, to another person; a scope beyond its own is refused with 403
/// `auth.grant.exceeds_own`; the holder of a grant that is not delegable cannot delegate;
/// revoking the delegating grant revokes the grant issued under it, and the person loses
/// the access at once.
#[test]
fn iam_01_a_delegable_grant_delegates_inside_its_scope_and_revoking_it_revokes_the_children() {
    let lab = Lab::new();
    let (casey_id, casey) = lab.person("casey");
    let parent = lab.grant(&casey_id, "operator", true);
    let parent_id = parent["id"].as_str().expect("a grant id").to_owned();
    let (dana_id, dana) = lab.person("dana");
    let inside = json!({ "kind": "prefix", "value": { "id": lab.granted, "subtree": true } });

    // Inside the delegating grant: a viewer over the same prefix.
    let child = casey
        .post(
            "/access/grants",
            &json!({ "subject": dana_id, "role": "viewer", "scope": inside }),
        )
        .expect(201);
    assert_eq!(child["parent"], parent_id.as_str(), "{child}");
    let child_id = child["id"].as_str().expect("a grant id").to_owned();
    let seen = dana.get("/prefixes").expect(200);
    assert_eq!(ids(&seen), vec![lab.granted.clone()], "{seen}");

    // Beyond it: another prefix, and the parent prefix.
    for prefix in [&lab.foreign, &lab.outer] {
        assert_refused(
            &casey.post(
                "/access/grants",
                &json!({
                    "subject": dana_id,
                    "role": "viewer",
                    "scope": { "kind": "prefix", "value": { "id": prefix, "subtree": true } },
                }),
            ),
            403,
            "auth.grant.exceeds_own",
        );
    }

    // Dana holds a grant that is not delegable: she hands out nothing.
    let refused = dana.post(
        "/access/grants",
        &json!({ "subject": casey_id, "role": "viewer", "scope": inside }),
    );
    assert_eq!(refused.status, 403, "{}", refused.text);

    // Revoking the parent revokes the child in the same batch.
    let revoked = lab
        .admin
        .delete(&format!("/access/grants/{parent_id}"), None)
        .expect(200);
    let revoked_ids: Vec<&str> = revoked["revoked"]
        .as_array()
        .expect("the revoked grants")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        revoked_ids.contains(&parent_id.as_str()) && revoked_ids.contains(&child_id.as_str()),
        "the answer lists the parent and the child: {revoked}"
    );
    let after = dana.get("/prefixes");
    assert!(
        after.status == 403 || ids(&after.json()).is_empty(),
        "dana keeps no access once the grant under it is gone: {}",
        after.text
    );

    lab.finish();
}

/// IAM-10: a service account has no login. An administrator creates it, it shares the name
/// space of users, and a sign-in with its name fails like one with an unknown name.
#[test]
fn iam_10_a_service_account_has_no_login_and_shares_the_name_space_of_users() {
    let lab = Lab::new();
    let account = lab.service_account("dns-sync");

    let listed = lab.admin.get("/access/service-accounts").expect(200);
    assert_eq!(ids(&listed), vec![account.clone()], "{listed}");
    let attempt = lab.admin.anonymous().post_unkeyed(
        "/auth/login/password",
        &json!({ "user_name": "dns-sync", "password": INITIAL_PIN }),
    );
    let unknown = lab.admin.anonymous().post_unkeyed(
        "/auth/login/password",
        &json!({ "user_name": "no-such-account", "password": INITIAL_PIN }),
    );
    assert_eq!(attempt.status, 401, "{}", attempt.text);
    assert_eq!(
        attempt.code(),
        unknown.code(),
        "a service account fails like an unknown account: {} against {}",
        attempt.text,
        unknown.text
    );
    assert_refused(
        &lab.admin.post(
            "/access/service-accounts",
            &json!({ "name": "dns-sync", "roles": [] }),
        ),
        409,
        "users.name_taken",
    );

    lab.finish();
}

/// IAM-10: a service account with a token scoped to one prefix works against the API as a
/// bearer token inside the scope and is refused outside it. The token reads and does not
/// write; the secret is shown once; revoking the token ends it at once.
#[test]
fn iam_10_a_scoped_token_reads_its_prefix_and_is_refused_elsewhere() {
    let lab = Lab::new();
    let account = lab.service_account("ipam-reader");
    // A token never exceeds its owner: the account holds the grant first.
    lab.grant(&account, "viewer", false);
    let created = lab.service_token(
        &account,
        &json!({
            "name": "reader",
            "grants": [{
                "role": "viewer",
                "scope": { "kind": "prefix", "value": { "id": lab.granted, "subtree": true } },
            }],
        }),
    );
    assert_eq!(created.status, 201, "{}", created.text);
    assert_eq!(created.header("cache-control").as_deref(), Some("no-store"));
    let body = created.json();
    let secret = body["token"].as_str().expect("the secret").to_owned();
    assert!(secret.starts_with("tnk_"), "the secret has the token form");
    assert_eq!(body["info"]["scoped"], true, "{body}");

    let tokens = lab
        .admin
        .get(&format!("/access/service-accounts/{account}/tokens"))
        .expect(200);
    assert_eq!(
        tokens["items"].as_array().map(Vec::len),
        Some(1),
        "{tokens}"
    );
    assert!(
        !tokens.to_string().contains(&secret),
        "the listing never shows the secret again: {tokens}"
    );

    let list = lab
        .bearer(&secret, Method::GET, "/prefixes", None)
        .expect(200);
    assert_eq!(ids(&list), vec![lab.granted.clone()], "{list}");
    lab.bearer(
        &secret,
        Method::GET,
        &format!("/prefixes/{}", lab.granted),
        None,
    )
    .expect(200);
    for path in [
        format!("/prefixes/{}", lab.foreign),
        format!("/hosts/{}", lab.foreign_host),
        format!("/addresses/{}", lab.foreign_address),
    ] {
        assert_refused(
            &lab.bearer(&secret, Method::GET, &path, None),
            403,
            "auth.out_of_scope",
        );
    }
    // A viewer token reads only, and it administers nothing.
    let write = lab.bearer(
        &secret,
        Method::POST,
        "/prefixes",
        Some(&json!({ "cidr": "192.0.2.128/25" })),
    );
    assert_eq!(write.status, 403, "{}", write.text);
    let users = lab.bearer(&secret, Method::GET, "/users", None);
    assert_eq!(users.status, 403, "{}", users.text);

    // Revoking the token ends it at once.
    let token_id = tokens["items"][0]["id"].as_str().expect("a token id");
    lab.admin
        .delete(
            &format!("/access/service-accounts/{account}/tokens/{token_id}"),
            None,
        )
        .expect(204);
    let gone = lab.bearer(&secret, Method::GET, "/prefixes", None);
    assert_eq!(gone.status, 401, "{}", gone.text);

    lab.finish();
}

/// IAM-10: a token cannot exceed the grants of its owner. A grant over a prefix the account
/// does not hold, over its parent prefix, with a role above the account's, or without a
/// scope is refused with 403 `auth.grant.exceeds_own`; a global-only role with 422
/// `auth.grant.invalid_role`; a token with neither grants nor scopes with 400; the same
/// grant as the account's is accepted.
#[test]
fn iam_10_a_token_scope_cannot_exceed_its_owners_grants() {
    let lab = Lab::new();
    let account = lab.service_account("ipam-reader");
    lab.grant(&account, "viewer", false);
    let token = |role: &str, prefix: &str| {
        lab.service_token(
            &account,
            &json!({
                "name": "wider",
                "grants": [{
                    "role": role,
                    "scope": { "kind": "prefix", "value": { "id": prefix, "subtree": true } },
                }],
            }),
        )
    };

    assert_refused(
        &token("viewer", &lab.foreign),
        403,
        "auth.grant.exceeds_own",
    );
    assert_refused(&token("viewer", &lab.outer), 403, "auth.grant.exceeds_own");
    assert_refused(
        &token("operator", &lab.granted),
        403,
        "auth.grant.exceeds_own",
    );
    assert_refused(
        &token("admin", &lab.granted),
        422,
        "auth.grant.invalid_role",
    );
    // A grant without a scope is the whole installation; the account holds no global role.
    let whole = lab.service_token(
        &account,
        &json!({ "name": "whole", "grants": [{ "role": "viewer" }] }),
    );
    assert_refused(&whole, 403, "auth.grant.exceeds_own");
    let empty = lab.service_token(&account, &json!({ "name": "empty" }));
    assert_eq!(empty.status, 400, "{}", empty.text);
    assert_eq!(
        lab.admin
            .get(&format!("/access/service-accounts/{account}/tokens"))
            .expect(200)["items"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "no refused request left a token behind"
    );
    token("viewer", &lab.granted).expect(201);

    lab.finish();
}

/// IAM-10: the effective right of a token is the intersection with its owner's grants at
/// that moment. A token does not gain what its owner gains later, and loses at once what
/// its owner loses.
#[test]
fn iam_10_a_token_loses_the_rights_its_owner_loses_and_gains_none() {
    let lab = Lab::new();
    let account = lab.service_account("ipam-reader");
    let grant = lab.grant(&account, "viewer", false);
    let secret = lab.viewer_token(&account);
    lab.bearer(&secret, Method::GET, "/prefixes", None)
        .expect(200);

    // The owner gains a grant over the foreign prefix: the token does not.
    lab.admin
        .post(
            "/access/grants",
            &json!({
                "subject": account,
                "role": "viewer",
                "scope": { "kind": "prefix", "value": { "id": lab.foreign, "subtree": true } },
            }),
        )
        .expect(201);
    assert_refused(
        &lab.bearer(
            &secret,
            Method::GET,
            &format!("/prefixes/{}", lab.foreign),
            None,
        ),
        403,
        "auth.out_of_scope",
    );

    // The owner loses the granted prefix: the token loses it with the commit.
    let grant_id = grant["id"].as_str().expect("a grant id");
    lab.admin
        .delete(&format!("/access/grants/{grant_id}"), None)
        .expect(200);
    let after = lab.bearer(
        &secret,
        Method::GET,
        &format!("/prefixes/{}", lab.granted),
        None,
    );
    assert_eq!(after.status, 403, "{}", after.text);
    let list = lab.bearer(&secret, Method::GET, "/prefixes", None);
    assert!(
        list.status == 403 || !cidrs(&list.json()).contains(&"192.0.2.0/25".to_owned()),
        "the token lists nothing of the lost grant: {}",
        list.text
    );

    lab.finish();
}

/// IAM-10: the token scope `metrics` reads the metrics endpoint and nothing else; the scope
/// `audit:read` reads the audit log and nothing else.
#[test]
fn iam_10_the_metrics_and_audit_scopes_read_their_own_route_only() {
    let lab = Lab::new();
    let account = lab.service_account("scraper");
    let scoped = |scope: &str| {
        lab.service_token(&account, &json!({ "name": scope, "scopes": [scope] }))
            .expect(201)["token"]
            .as_str()
            .expect("the secret")
            .to_owned()
    };
    let metrics = scoped("metrics");
    let audit = scoped("audit:read");

    let scrape = lab.bearer(&metrics, Method::GET, "/metrics", None);
    assert!(
        text(&scrape).contains("tenko_build_info"),
        "{}",
        scrape.text
    );
    for path in ["/prefixes", "/audit", "/users", "/hosts"] {
        let reply = lab.bearer(&metrics, Method::GET, path, None);
        assert_reaches_nothing(&reply, &format!("metrics token on {path}"));
    }
    lab.bearer(&audit, Method::GET, "/audit", None).expect(200);
    for path in ["/metrics", "/prefixes", "/users"] {
        let reply = lab.bearer(&audit, Method::GET, path, None);
        assert_reaches_nothing(&reply, &format!("audit token on {path}"));
    }
    let anonymous = lab.admin.anonymous().get("/metrics");
    assert_eq!(
        anonymous.status, 401,
        "the metrics endpoint needs a credential: {}",
        anonymous.text
    );

    lab.finish();
}

/// IAM-06: the sign-in requirement is set per role. A stored policy `passkey` for the
/// viewer role is listed beside the profile's value; a person who holds the viewer role
/// only through a grant is then refused with 403 `auth.step_up_required` on a password
/// session; clearing the policy lets the profile decide again and the person reads.
#[test]
fn iam_06_a_role_policy_raises_the_requirement_of_the_people_who_hold_the_role() {
    let lab = Lab::new();
    let (id, viewer) = lab.person("vera");
    lab.grant(&id, "viewer", false);
    let granted = format!("/prefixes/{}", lab.granted);
    viewer.get(&granted).expect(200);

    let set = lab
        .admin
        .put("/access/role-policies/viewer", &json!({ "mfa": "passkey" }))
        .expect(200);
    assert_eq!(set["stored"], "passkey", "{set}");
    assert_eq!(set["profile_default"], "optional", "{set}");
    let policies = lab.admin.get("/access/role-policies").expect(200);
    let listed = policies["items"]
        .as_array()
        .expect("the roles")
        .iter()
        .find(|policy| policy["role"] == "viewer")
        .unwrap_or_else(|| panic!("the viewer role is listed: {policies}"));
    assert_eq!(listed["mfa"], "passkey", "{policies}");

    let refused = viewer.get(&granted);
    assert_refused(&refused, 403, "auth.step_up_required");
    assert_eq!(
        refused.json()["params"]["required"],
        "passkey",
        "{}",
        refused.text
    );
    // A list gives nothing away either.
    assert_reaches_nothing(&viewer.get("/prefixes"), "a list on a too weak session");

    let cleared = lab
        .admin
        .delete("/access/role-policies/viewer", None)
        .expect(200);
    assert!(cleared["stored"].is_null(), "{cleared}");
    viewer.get(&granted).expect(200);

    lab.finish();
}
