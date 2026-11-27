//! A takeover run's window over the served router (ADR 0038, plan section 2.16.5): a person
//! with a fresh sign-in binds it to the configurations they were shown, it is refused until
//! the run is ready, and once it is bound the run creates no mirror and no zone.

use tenko_core::{
    ApiTokenId, DelegationId, MirrorId, Principal, Revision, SystemComponent,
    migrate::{
        Mirror,
        tables::{MIRRORS, RUNS},
    },
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt as _, WriteBatch};

use super::*;

/// The body the takeover script sends for a zone of its plan.
const ZONE: &str = include_str!("../fixtures/zone-create.json");

/// The plan's zones.
const ZONES: [&str; 3] = [
    "corp.example.test",
    "_msdcs.corp.example.test",
    "2.0.192.in-addr.arpa",
];

/// The mirror host of the test plan, the one address its mirror tokens are bound to.
const MIRROR_HOST: &str = "192.0.2.30";

/// The mirror creation of a delegated session for the plan's second DHCP server.
const DHCP2: &str = r#"{"name":"dhcp2.corp.example.test","kind":"windows-dhcp","source_prefixes":["192.0.2.30/32"]}"#;

/// A first snapshot of `server`, with a loss entry when `lossy`.
fn envelope(server: &str, lossy: bool) -> String {
    let losses = if lossy {
        json!([{ "location": { "sheet": "Get-DhcpServerv4Scope" }, "code": "import.cell.invalid_ip", "detail": "a value Tenko does not take" }])
    } else {
        json!([])
    };
    json!({
        "format": 1, "sequence": 1, "taken_at": "2026-11-01T08:00:00Z",
        "source": {
            "kind": "windows-dhcp", "server": server,
            "adapter": "Tenko-DhcpMirror.ps1", "adapter_version": "0.1.0"
        },
        "dhcp": {
            "server_options": [], "option_defs": [], "classes": [], "scopes": [],
            "superscopes": [], "policies": [], "filters": [], "failover": [], "leases": []
        },
        "losses": { "entries": losses }
    })
    .to_string()
}

/// A run whose two mirrors pushed once and are paired, with its plan's zones.
struct Ready {
    env: TestEnv,
    admin: String,
    app: axum::Router,
    secret: String,
    run: DelegationId,
    /// Each mirror's id and token, in the plan's order.
    mirrors: Vec<(String, String)>,
    zones: Vec<String>,
}

/// With `lossy`, the first mirror's push carries a loss entry; the plan keeps its first
/// `servers` DHCP servers.
async fn ready(lossy: bool, servers: usize) -> Ready {
    let (env, admin, app) = served().await;
    let store: Arc<dyn Store> = env.store.clone();
    let zones = ZoneService::with_direct_jobs(store, None, ZoneConfig::default());
    let app = app.layer(Extension(zones));
    let mut plan = tenko_auth::testing::approval::plan();
    (plan["dhcp_servers"].as_array_mut().expect("servers")).truncate(servers);
    let credentials = tenko_core::Credentials::Session(admin.clone());
    let person = env.ctx_for(&credentials).await.expect("the administrator");
    let source = SCRIPT.parse().expect("an address");
    let script = tenko_auth::testing::approval::Script::default();
    let session = env.delegate_for(&person, &script, source, &plan).await;
    let session = session.expect("a delegated session");
    let secret = session.secret.expose().to_owned();
    let mut ready = Ready {
        env,
        admin,
        app,
        run: session.delegation,
        secret,
        mirrors: Vec::new(),
        zones: Vec::new(),
    };
    for (body, server) in [
        (DHCP1, "dhcp1.corp.example.test"),
        (DHCP2, "dhcp2.corp.example.test"),
    ]
    .into_iter()
    .take(servers)
    {
        let created = ready.script("POST", "/migrate/mirrors", Some(body)).await;
        created.assert_status(201);
        let text = |field: &Value| field.as_str().expect("a string").to_owned();
        let mirror = (
            text(&created.body["mirror"]["id"]),
            text(&created.body["token"]),
        );
        let lost = lossy && ready.mirrors.is_empty();
        ready.mirrors.push(mirror);
        ready
            .push(ready.mirrors.len() - 1, &envelope(server, lost))
            .await;
    }
    if let [one, other] = ready.mirrors.as_slice() {
        let pair = json!({ "partner": other.0 }).to_string();
        let path = format!("/migrate/mirrors/{}", one.0);
        let paired = ready.script("PATCH", &path, Some(&pair)).await;
        paired.assert_status(200);
    }
    for name in ZONES {
        let mut body: Value = serde_json::from_str(ZONE).expect("JSON");
        body["name"] = json!(name);
        let created = (ready.script("POST", "/dns/zones", Some(&body.to_string()))).await;
        created.assert_status(201);
        let id = created.body["id"].as_str().expect("an id").to_owned();
        ready.zones.push(id);
    }
    ready
}

impl Ready {
    /// `method` on `path` through the run's delegated session.
    async fn script(&self, method: &str, path: &str, body: Option<&str>) -> Reply {
        let bearer = Bearer(&self.secret);
        send(&self.app, from(SCRIPT, method, path, bearer, body)).await
    }

    /// `method` on `path` through the person's session.
    async fn person(&self, method: &str, path: &str, body: Option<&str>) -> Reply {
        let cookie = Cookie(&self.admin);
        send(&self.app, from(SCRIPT, method, path, cookie, body)).await
    }

    /// Pushes `envelope` as the `index`th mirror's exporter does.
    async fn push(&self, index: usize, envelope: &str) {
        let (id, token) = &self.mirrors[index];
        let path = format!("/migrate/mirrors/{id}/snapshot");
        let push = from(MIRROR_HOST, "PUT", &path, Bearer(token), Some(envelope));
        send(&self.app, push).await.assert_status(200);
    }

    /// What the person is shown: each mirror's stored configuration hash.
    async fn shown(&self) -> Value {
        let mut mirrors = Vec::new();
        for (id, _) in &self.mirrors {
            let path = format!("/migrate/mirrors/{id}");
            let hash = self.person("GET", &path, None).await.body["last_hash"].clone();
            assert!(hash.is_string(), "{hash}");
            mirrors.push(json!({ "mirror": id, "hash": hash }));
        }
        json!({ "mirrors": mirrors })
    }

    async fn bind(&self, credential: Credential<'_>, body: &Value) -> Reply {
        let path = format!("/migrate/runs/{}/window", self.run);
        let request = from(SCRIPT, "POST", &path, credential, Some(&body.to_string()));
        send(&self.app, request).await
    }

    async fn view(&self) -> Arc<dyn ReadView> {
        let read = self.env.store.read(ReadConsistency::Local);
        read.await.expect("a view")
    }

    /// The revision of the run's row.
    async fn revision(&self) -> Revision {
        let row = self.view().await.get_typed(&RUNS, &self.run).expect("read");
        row.expect("the run").1
    }

    /// Writes the `index`th mirror's row back after `change`.
    async fn rewrite(&self, index: usize, change: impl FnOnce(&mut Mirror)) {
        let id: MirrorId = self.mirrors[index].0.parse().expect("an id");
        let row = self.view().await.get_typed(&MIRRORS, &id).expect("read");
        let (mut mirror, _) = row.expect("the mirror");
        change(&mut mirror);
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
        batch.put_typed(&MIRRORS, &id, &mirror).expect("encode");
        self.env.store.propose(batch).await.expect("commit");
    }

    /// The audit records of `action`.
    async fn audited(&self, action: &str) -> Vec<tenko_core::audit::AuditRecord> {
        let view = self.view().await;
        let audit = view.scan_typed(
            &tenko_store::tables::AUDIT,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        );
        (audit.expect("the audit").into_iter())
            .filter(|(_, record, _)| record.draft.action.as_str() == action)
            .map(|(_, record, _)| record)
            .collect()
    }
}

/// A person binds the run's window to the hashes shown: the person's and the session's read of
/// the run show it, it is audited, a hash that is not the stored and newest one binds nothing,
/// and a later bind replaces it.
#[tokio::test]
async fn a_person_binds_the_runs_window_to_the_hashes_shown() {
    let run = ready(false, 2).await;
    let shown = run.shown().await;
    run.bind(Cookie(&run.admin), &shown)
        .await
        .assert_status(204);
    let path = format!("/migrate/runs/{}", run.run);
    for read in [
        run.person("GET", &path, None).await,
        run.script("GET", &path, None).await,
    ] {
        read.assert_status(200);
        let window = &read.body["window"];
        assert_eq!(window["mirrors"], shown["mirrors"], "{}", read.text);
        assert_eq!(window["started_by"], tenko_auth::testing::env::ADMIN);
        assert!(window["started_at"].is_string(), "{}", read.text);
    }
    let audited = run.audited("migrate.run.window").await;
    assert_eq!(audited.len(), 1);
    let context = &audited[0].draft.details.context;
    assert_eq!(context["run"], run.run.to_string());
    let first = &shown["mirrors"][0];
    let text = |value: &Value| value.as_str().expect("a string").to_owned();
    let named = format!("{}:{}", text(&first["mirror"]), text(&first["hash"]));
    assert!(context["mirrors"].contains(&named), "{context:?}");
    // Another stored configuration: the hashes shown no longer bind, nor does the stored one
    // while it is not the newest push's; the hashes shown bind again once it is back.
    let stored = std::sync::Mutex::new(None);
    run.rewrite(0, |mirror| {
        let other = tenko_core::serde_util::HexBytes(vec![9; 32]);
        *stored.lock().expect("a lock") = mirror.last_hash.replace(other);
    })
    .await;
    let reply = run.bind(Cookie(&run.admin), &shown).await;
    reply.assert_problem(409, "migrate.run.binding");
    assert_eq!(reply.body["params"]["reason"], "hash", "{}", reply.text);
    let mut other = shown.clone();
    other["mirrors"][0]["hash"] = json!("09".repeat(32));
    let reply = run.bind(Cookie(&run.admin), &other).await;
    assert_eq!(reply.body["params"]["reason"], "hash", "{}", reply.text);
    let stored = stored.lock().expect("a lock").take();
    run.rewrite(0, |mirror| mirror.last_hash = stored).await;
    // A later bind replaces the window.
    run.bind(Cookie(&run.admin), &shown)
        .await
        .assert_status(204);
    assert_eq!(run.audited("migrate.run.window").await.len(), 2);
    let read = run.person("GET", &path, None).await;
    assert_eq!(read.body["window"]["mirrors"], shown["mirrors"]);
}

/// The window is refused until the run is ready, each refusal with what is not ready and
/// leaving the run as it was: a server without its run mirror, a hash that is not the stored
/// one, a mirror this controller holds no push of, the pair, a plan zone the run did not
/// create, the Hardened profile, open losses; a token, an old sign-in, the run's own session
/// and a run that does not exist.
#[tokio::test]
async fn the_window_is_refused_until_the_run_is_ready() {
    let run = ready(false, 2).await;
    let before = run.revision().await;
    let shown = run.shown().await;
    let refused = |reply: Reply, reason: &str, key: &str, name: &str| {
        reply.assert_problem(409, "migrate.run.binding");
        let params = &reply.body["params"];
        assert_eq!(params["reason"], reason, "{}", reply.text);
        assert_eq!(params[key], name, "{}", reply.text);
    };
    let (dhcp1, dhcp2) = ("dhcp1.corp.example.test", "dhcp2.corp.example.test");
    let mut other = shown.clone();
    other["mirrors"][1]["mirror"] = json!(MirrorId::generate());
    refused(
        run.bind(Cookie(&run.admin), &other).await,
        "missing",
        "server",
        dhcp2,
    );
    let mut wrong = shown.clone();
    wrong["mirrors"][0]["hash"] = json!("00".repeat(32));
    refused(
        run.bind(Cookie(&run.admin), &wrong).await,
        "hash",
        "server",
        dhcp1,
    );
    // No push of the mirror on this controller since its start: the token it took them with
    // is not the mirror's.
    let token = ApiTokenId::generate();
    let mut kept = None;
    run.rewrite(1, |mirror| {
        kept = Some(std::mem::replace(&mut mirror.token, token));
    })
    .await;
    let reply = run.bind(Cookie(&run.admin), &shown).await;
    let detail = reply.body["detail"].as_str().expect("a detail").to_owned();
    assert!(detail.contains("one push interval"), "{detail}");
    refused(reply, "hash", "server", dhcp2);
    run.rewrite(1, |mirror| mirror.token = kept.expect("the token"))
        .await;
    run.rewrite(1, |mirror| mirror.partner = None).await;
    refused(
        run.bind(Cookie(&run.admin), &shown).await,
        "pair",
        "server",
        dhcp1,
    );
    let partner = run.mirrors[0].0.parse().expect("an id");
    run.rewrite(1, |mirror| mirror.partner = Some(partner))
        .await;
    let zone = format!("/dns/zones/{}", run.zones[2]);
    run.person("DELETE", &zone, None).await.assert_status(204);
    let reply = run.bind(Cookie(&run.admin), &shown).await;
    refused(reply, "zones", "zone", "2.0.192.in-addr.arpa");
    // Under Hardened the domain controllers' unsigned transfers would be refused.
    let settings = &tenko_auth::model::SETTINGS;
    let (mut stored, _) = (run.view().await.get_typed(settings, &()).expect("read")).expect("it");
    let profile = std::mem::replace(&mut stored.profile, Profile::Hardened);
    let put = |stored: &tenko_auth::settings::SecuritySettings| {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
        batch.put_typed(settings, &(), stored).expect("encode");
        run.env.store.propose(batch)
    };
    put(&stored).await.expect("commit");
    let reply = run.bind(Cookie(&run.admin), &shown).await;
    reply.assert_problem(409, "migrate.run.profile");
    assert!(
        reply.body["detail"]
            .as_str()
            .expect("a detail")
            .contains("Standard")
    );
    stored.profile = profile;
    put(&stored).await.expect("commit");
    // Open losses, of a run otherwise ready.
    let lossy = ready(true, 2).await;
    let reply = lossy.bind(Cookie(&lossy.admin), &lossy.shown().await).await;
    refused(reply, "losses", "server", dhcp1);
    // Who may bind.
    let created = run
        .person(
            "POST",
            "/auth/tokens",
            Some(&json!({ "name": "window", "expires_in_days": 30 }).to_string()),
        )
        .await;
    created.assert_status(201);
    let token = created.body["token"].as_str().expect("a token").to_owned();
    let reply = run.bind(Bearer(&token), &shown).await;
    reply.assert_problem(403, "auth.forbidden");
    assert_refused(&run.bind(Bearer(&run.secret), &shown).await, "unlisted");
    let path = format!("/migrate/runs/{}/window", DelegationId::generate());
    let unknown = run.person("POST", &path, Some(&shown.to_string())).await;
    unknown.assert_problem(404, "migrate.run.not_found");
    let path = "/migrate/runs/not-an-id/window";
    let malformed = run.person("POST", path, Some(&shown.to_string())).await;
    malformed.assert_problem(400, "sys.invalid_request");
    signed_in_at(&run.env, &run.admin, six_minutes_ago()).await;
    let reply = run.bind(Cookie(&run.admin), &shown).await;
    reply.assert_problem(403, "auth.step_up_required");
    assert_eq!(run.revision().await, before);
    assert_eq!(run.audited("migrate.run.window").await.len(), 0);
}

/// The body names the run's mirrors and nothing else: a field an entry does not know is
/// refused, an entry for another mirror or a second entry for one is `extra`, and a mirror a
/// person deleted after the look is `missing`; nothing is bound.
#[tokio::test]
async fn the_window_binds_the_runs_mirrors_and_nothing_else() {
    let run = ready(false, 2).await;
    let before = run.revision().await;
    let shown = run.shown().await;
    let mut unknown = shown.clone();
    unknown["mirrors"][0]["server"] = json!("dhcp1.corp.example.test");
    let reply = run.bind(Cookie(&run.admin), &unknown).await;
    reply.assert_problem(400, "sys.invalid_request");
    let first = shown["mirrors"][0].clone();
    let other = json!({ "mirror": MirrorId::generate(), "hash": first["hash"] });
    for extra in [other, first] {
        let mut body = shown.clone();
        (body["mirrors"].as_array_mut().expect("entries")).push(extra);
        let reply = run.bind(Cookie(&run.admin), &body).await;
        reply.assert_problem(409, "migrate.run.binding");
        assert_eq!(reply.body["params"]["reason"], "extra", "{}", reply.text);
        assert_eq!(reply.body["params"]["servers"], "2", "{}", reply.text);
    }
    let mirror = format!("/migrate/mirrors/{}", run.mirrors[1].0);
    run.person("DELETE", &mirror, None).await.assert_status(204);
    let reply = run.bind(Cookie(&run.admin), &shown).await;
    reply.assert_problem(409, "migrate.run.binding");
    assert_eq!(reply.body["params"]["reason"], "missing", "{}", reply.text);
    assert_eq!(reply.body["params"]["server"], "dhcp2.corp.example.test");
    assert_eq!(run.revision().await, before);
}

/// A plan with one DHCP server binds its one mirror, with no pair to check.
#[tokio::test]
async fn a_plan_with_one_dhcp_server_binds_its_mirror() {
    let run = ready(false, 1).await;
    let shown = run.shown().await;
    run.bind(Cookie(&run.admin), &shown)
        .await
        .assert_status(204);
    let path = format!("/migrate/runs/{}", run.run);
    let read = run.person("GET", &path, None).await;
    assert_eq!(
        read.body["window"]["mirrors"], shown["mirrors"],
        "{}",
        read.text
    );
}

/// Once the window is bound, a later sitting creates no mirror, for a server whose mirror a
/// person deleted, and no zone, for a plan zone a person deleted: both 403 `condition`.
#[tokio::test]
async fn after_the_window_a_run_creates_no_mirror_and_no_zone() {
    let run = ready(false, 2).await;
    run.bind(Cookie(&run.admin), &run.shown().await)
        .await
        .assert_status(204);
    let mirror = format!("/migrate/mirrors/{}", run.mirrors[1].0);
    run.person("DELETE", &mirror, None).await.assert_status(204);
    let zone = format!("/dns/zones/{}", run.zones[2]);
    run.person("DELETE", &zone, None).await.assert_status(204);
    run.script("POST", "/auth/logout", None)
        .await
        .assert_status(204);
    let later = delegated(&run.env, &run.admin, "192.0.2.11").await;
    let bearer = Bearer(later.secret.expose());
    let create = |path: &str, body: &str| from("192.0.2.11", "POST", path, bearer, Some(body));
    let reply = send(&run.app, create("/migrate/mirrors", DHCP2)).await;
    assert_refused(&reply, "condition");
    let mut body: Value = serde_json::from_str(ZONE).expect("JSON");
    body["name"] = json!(ZONES[2]);
    let reply = send(&run.app, create("/dns/zones", &body.to_string())).await;
    assert_refused(&reply, "condition");
}

/// Moves the sign-in of the session `secret` to `at`.
async fn signed_in_at(env: &TestEnv, secret: &str, at: Timestamp) {
    use tenko_auth::model::SESSIONS;
    let view = (env.store.read(ReadConsistency::Local).await).expect("a view");
    let hash = tenko_auth::secret::hash_secret(secret);
    let (mut record, _) = (view.get_typed(&SESSIONS, &hash).expect("read")).expect("the session");
    record.authenticated_at = at;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
    batch.put_typed(&SESSIONS, &hash, &record).expect("encode");
    env.store.propose(batch).await.expect("commit");
}

mod flip;
