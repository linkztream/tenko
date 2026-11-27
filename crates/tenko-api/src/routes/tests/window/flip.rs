//! A takeover run's flip and its reads after the window, over the served router (ADR 0038, plan
//! section 2.16.1 phase 4): its session reads its zones' records and transfer state, has them
//! transferred, reads its mirrors' snapshots and flips its zones with its plan's values only,
//! once a person started the window; the flip to primary writes the run's access list and the
//! zone's transfer settings in one batch, never over a person's, and the flip back unserves
//! the zone.

use tenko_core::{
    DelegationId,
    dns::{AclId, ZoneKind, tables::ACLS},
    migrate::{run::RunWindow, tables::RUN_PLANS},
};
use tenko_dns::zone::secondary::{KeyLoader, SecondaryService, SecondarySettings};

use super::super::zones::{hold_copy, zone};
use super::*;

/// The flip to Tenko the plan implies.
fn to_primary() -> Value {
    let soa =
        json!({ "mname": "tenko.corp.example.test", "rname": "hostmaster.corp.example.test" });
    json!({ "to": "primary", "soa": soa, "ns": ["tenko.corp.example.test"] })
}

/// The flip back to the PDC emulator the plan implies.
fn back() -> Value {
    json!({ "to": "secondary", "primaries": [{ "address": "192.0.2.11" }] })
}

/// An operator's secondary zone.
const LAB: &str = r#"{"name":"lab.example.test","kind":"secondary","soa":{"mname":"ns1.lab.example.test","rname":"hostmaster.lab.example.test"},"source":{"primaries":[{"address":"192.0.2.53"}]}}"#;

/// A ready run whose zones hold their copies, with the window started when `bound`.
async fn copied(bound: bool) -> Ready {
    let run = ready(false, 2).await;
    for id in &run.zones {
        hold_copy(&run.env, id).await;
    }
    if bound {
        let shown = run.shown().await;
        run.bind(Cookie(&run.admin), &shown)
            .await
            .assert_status(204);
    }
    run
}

impl Ready {
    /// The run's session flips its `index`th zone with `body`.
    async fn flip(&self, index: usize, body: &Value) -> Reply {
        let path = format!("/dns/zones/{}/flip", self.zones[index]);
        self.script("POST", &path, Some(&body.to_string())).await
    }

    /// The run's access list, if any.
    async fn list(&self) -> Option<(tenko_core::dns::Acl, Revision)> {
        let id = AclId::from_uuid(self.run.uuid());
        self.view().await.get_typed(&ACLS, &id).expect("read")
    }

    /// Writes the run's plan back after `change`.
    async fn replan(&self, change: impl FnOnce(&mut Value)) {
        let mut plan = tenko_auth::testing::approval::plan();
        change(&mut plan);
        let plan: tenko_core::migrate::plan::TakeoverPlan =
            serde_json::from_value(plan).expect("a plan");
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
        batch
            .put_typed(&RUN_PLANS, &self.run, &plan)
            .expect("encode");
        self.env.store.propose(batch).await.expect("commit");
    }

    /// Stores the security profile `profile`.
    async fn profile(&self, profile: Profile) {
        let settings = &tenko_auth::model::SETTINGS;
        let row = self.view().await.get_typed(settings, &()).expect("read");
        let (mut stored, _) = row.expect("the settings");
        stored.profile = profile;
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
        batch.put_typed(settings, &(), &stored).expect("encode");
        self.env.store.propose(batch).await.expect("commit");
    }
}

/// Before the window the flip is refused (`condition`); after it a body other than the plan's
/// (another SOA primary name, name server or SOA timer) and a plan without the flip are refused
/// (`plan`); the plan's flip serves the zone with the run's list `takeover-<run>`, the plan's
/// domain controllers' addresses and nothing a caller sent, written in one batch with its own
/// audit record; the second zone takes the same list.
#[tokio::test]
async fn a_run_flips_its_zones_after_the_window_with_the_plans_values_only() {
    let run = copied(false).await;
    assert_refused(&run.flip(0, &to_primary()).await, "condition");
    let shown = run.shown().await;
    run.bind(Cookie(&run.admin), &shown)
        .await
        .assert_status(204);
    for (field, value) in [
        ("mname", json!("ns1.corp.example.test")),
        ("minimum", json!(1)),
    ] {
        let mut body = to_primary();
        body["soa"][field] = value;
        assert_refused(&run.flip(0, &body).await, "plan");
    }
    let mut body = to_primary();
    body["ns"] = json!(["tenko.corp.example.test", "ns1.corp.example.test"]);
    assert_refused(&run.flip(0, &body).await, "plan");
    run.replan(|plan| plan["operations"] = json!(["mirrors", "secondary_zones"]))
        .await;
    assert_refused(&run.flip(0, &to_primary()).await, "plan");
    run.replan(|_| {}).await;
    let flipped = run.flip(0, &to_primary()).await;
    flipped.assert_status(200);
    let flipped_zone = zone(&run.env, &run.zones[0]).await;
    assert_eq!(flipped_zone.kind, ZoneKind::Primary);
    assert!(flipped_zone.served);
    let id = AclId::from_uuid(run.run.uuid());
    let transfer = json!({
        "allow": [id],
        "notify": [{ "address": "192.0.2.11", "port": 53 }, { "address": "192.0.2.12", "port": 53 }],
        "require_tsig": false,
        "xot": false
    });
    assert_eq!(json!(flipped_zone.transfer), transfer);
    let (list, revision) = run.list().await.expect("the run's list");
    assert_eq!(list.name, format!("takeover-{}", run.run));
    let hosts = json!([
        { "kind": "prefix", "prefix": "192.0.2.11/32", "deny": false },
        { "kind": "prefix", "prefix": "192.0.2.12/32", "deny": false }
    ]);
    assert_eq!(json!(list.entries), hosts);
    // One batch: the list's row, the zone's and the report share one revision.
    assert_eq!(json!(revision), flipped.body["revision"]);
    let created = run.audited("dns.acl.create").await;
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].draft.details.context["name"], list.name);
    let flips = run.audited("dns.zone.flip").await;
    assert_eq!(flips[0].draft.details.context["transfer"], list.name);
    // A field the flip does not know reaches nothing: the list stays the plan's.
    let mut extra = to_primary();
    extra["allow"] = json!(["203.0.113.9/32"]);
    run.flip(1, &extra).await.assert_status(200);
    assert_eq!(
        json!(zone(&run.env, &run.zones[1]).await.transfer),
        transfer
    );
    assert_eq!(json!(run.list().await.expect("the list").0.entries), hosts);
    assert_eq!(run.audited("dns.acl.create").await.len(), 1);
}

/// An operator's zone and another run's zone answer the run's flip with the zone's 404, byte
/// for byte as a missing one, and another run's session does not reach this run's zone.
#[tokio::test]
async fn a_run_flips_its_own_zones_only() {
    let run = copied(true).await;
    let operators = run.person("POST", "/dns/zones", Some(LAB)).await;
    operators.assert_status(201);
    let mut theirs = zone(&run.env, &run.zones[2]).await;
    theirs.created.by = Principal::User {
        id: tenko_core::UserId::generate(),
        session: tenko_core::SessionId::generate(),
        strength: tenko_core::AuthStrength::Password,
        delegation: Some(DelegationId::generate()),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dns), Timestamp::now());
    let table = &tenko_core::dns::tables::ZONES;
    batch.put_typed(table, &theirs.id, &theirs).expect("encode");
    run.env.store.propose(batch).await.expect("commit");
    let body = Some(to_primary().to_string());
    let mut answers = Vec::new();
    for id in [
        operators.body["id"].as_str().expect("an id").to_owned(),
        run.zones[2].clone(),
        tenko_core::dns::ZoneId::generate().to_string(),
    ] {
        let path = format!("/dns/zones/{id}/flip");
        let reply = run.script("POST", &path, body.as_deref()).await;
        reply.assert_problem(404, "dns.zone.not_found");
        answers.push(reply.text);
    }
    assert!(
        answers.iter().all(|text| *text == answers[0]),
        "{answers:?}"
    );
    // A session of another run whose window started.
    let mut plan = tenko_auth::testing::approval::plan();
    plan["domain"] = json!("other.example.test");
    plan["forest_root"] = json!("other.example.test");
    plan["zones"] = json!(["other.example.test"]);
    plan["kerberos"]["realm"] = json!("OTHER.EXAMPLE.TEST");
    plan["kerberos"]["spns"] = json!(["DNS/tenko.other.example.test"]);
    let credentials = tenko_core::Credentials::Session(run.admin.clone());
    let person = run.env.ctx_for(&credentials).await.expect("the person");
    let script = tenko_auth::testing::approval::Script::default();
    let source = "192.0.2.12".parse().expect("an address");
    let other = run.env.delegate_for(&person, &script, source, &plan).await;
    let other = other.expect("another run's session");
    let row = run
        .view()
        .await
        .get_typed(&RUNS, &other.delegation)
        .expect("read");
    let (mut record, _) = row.expect("the other run");
    record.window = Some(RunWindow {
        started_by: "admin".to_owned(),
        started_at: Timestamp::now(),
        mirrors: Vec::new(),
    });
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
    batch
        .put_typed(&RUNS, &other.delegation, &record)
        .expect("encode");
    run.env.store.propose(batch).await.expect("commit");
    let path = format!("/dns/zones/{}/flip", run.zones[0]);
    let bearer = Bearer(other.secret.expose());
    let reply = send(
        &run.app,
        from("192.0.2.12", "POST", &path, bearer, body.as_deref()),
    )
    .await;
    reply.assert_problem(404, "dns.zone.not_found");
    assert_eq!(reply.text, answers[0]);
    assert_eq!(
        zone(&run.env, &run.zones[0]).await.kind,
        ZoneKind::Secondary
    );
}

/// The run's flip writes over no person's setting: a zone whose transfer settings a person
/// changed is refused (`migrate.run.transfer`) and the failing flip writes no list; a person's
/// list of the run's list's name and a list a person gave other entries are refused
/// (`migrate.run.acl`), a list a person only renamed is not; under Hardened the flip to
/// primary is refused (`migrate.run.profile`) and the flip back is not.
#[tokio::test]
async fn a_run_flip_writes_over_no_persons_settings() {
    let run = copied(true).await;
    let path = format!("/dns/zones/{}", run.zones[0]);
    let changed = json!({ "transfer": { "require_tsig": false } }).to_string();
    run.person("PATCH", &path, Some(&changed))
        .await
        .assert_status(200);
    let reply = run.flip(0, &to_primary()).await;
    reply.assert_problem(409, "migrate.run.transfer");
    assert_eq!(reply.body["params"]["zone"], "corp.example.test");
    assert_eq!(
        zone(&run.env, &run.zones[0]).await.kind,
        ZoneKind::Secondary
    );
    assert!(run.list().await.is_none());
    let defaults = json!({ "transfer": { "require_tsig": true } }).to_string();
    run.person("PATCH", &path, Some(&defaults))
        .await
        .assert_status(200);
    // A person's list that holds the run's list's name is named in the refusal.
    let name = format!("takeover-{}", run.run);
    let theirs =
        json!({ "name": name, "entries": [{ "kind": "prefix", "prefix": "192.0.2.11/32" }] });
    let created = run
        .person("POST", "/dns/acls", Some(&theirs.to_string()))
        .await;
    created.assert_status(201);
    let reply = run.flip(0, &to_primary()).await;
    reply.assert_problem(409, "migrate.run.acl");
    assert_eq!(reply.body["params"]["name"], name);
    let detail = reply.body["detail"].as_str().expect("a detail");
    assert!(detail.contains(&name), "{detail}");
    assert!(run.list().await.is_none());
    let theirs = format!("/dns/acls/{}", created.body["id"].as_str().expect("an id"));
    run.person("DELETE", &theirs, None).await.assert_status(204);
    run.flip(0, &to_primary()).await.assert_status(200);
    // A run's list a person renamed serves the run, named as stored in the flip's record.
    let list = format!("/dns/acls/{}", AclId::from_uuid(run.run.uuid()));
    let renamed = json!({ "name": "dc-transfers" }).to_string();
    run.person("PATCH", &list, Some(&renamed))
        .await
        .assert_status(200);
    run.flip(2, &to_primary()).await.assert_status(200);
    let flips = run.audited("dns.zone.flip").await;
    let record = &flips.last().expect("the flip").draft.details.context;
    assert_eq!(
        record.get("transfer").map(String::as_str),
        Some("dc-transfers")
    );
    let entries = json!({ "entries": [{ "kind": "prefix", "prefix": "203.0.113.9/32" }] });
    let edited = run.person("PATCH", &list, Some(&entries.to_string())).await;
    edited.assert_status(200);
    let reply = run.flip(1, &to_primary()).await;
    reply.assert_problem(409, "migrate.run.acl");
    assert_eq!(reply.body["params"]["name"], "dc-transfers");
    assert_eq!(
        zone(&run.env, &run.zones[1]).await.kind,
        ZoneKind::Secondary
    );
    run.profile(Profile::Hardened).await;
    let reply = run.flip(1, &to_primary()).await;
    reply.assert_problem(409, "migrate.run.profile");
    run.flip(0, &back()).await.assert_status(200);
}

/// The run's flip back unserves the zone, with the plan's primary only, so that its session
/// deletes the copy; a flip forward after it writes over the run's own transfer settings and
/// takes the run's list as it is.
#[tokio::test]
async fn a_run_flips_its_zones_back_unserved() {
    let run = copied(true).await;
    run.flip(0, &to_primary()).await.assert_status(200);
    let (_, revision) = run.list().await.expect("the run's list");
    let transfer = zone(&run.env, &run.zones[0]).await.transfer;
    let mut other = back();
    other["primaries"][0]["address"] = json!("192.0.2.12");
    assert_refused(&run.flip(0, &other).await, "plan");
    run.flip(0, &back()).await.assert_status(200);
    let unserved = zone(&run.env, &run.zones[0]).await;
    assert_eq!(unserved.kind, ZoneKind::Secondary);
    assert!(!unserved.served);
    let flips = run.audited("dns.zone.flip").await;
    let last = &flips.last().expect("the flip back").draft.details.context;
    assert_eq!(last.get("served").map(String::as_str), Some("false"));
    run.flip(0, &to_primary()).await.assert_status(200);
    let again = zone(&run.env, &run.zones[0]).await;
    assert!(again.served);
    assert_eq!(again.transfer, transfer);
    assert_eq!(run.list().await.expect("the run's list").1, revision);
    assert_eq!(run.audited("dns.acl.create").await.len(), 1);
    run.flip(0, &back()).await.assert_status(200);
    let path = format!("/dns/zones/{}", run.zones[0]);
    run.script("DELETE", &path, None).await.assert_status(204);
}

/// The run's zones' records and transfer state, a transfer and its mirrors' snapshots are
/// refused before the window (`condition`) and answered after it; another run's zone and
/// mirror answer their 404.
#[tokio::test]
async fn a_run_reads_records_snapshots_and_transfers_after_the_window_only() {
    let mut run = copied(false).await;
    let store: Arc<dyn Store> = run.env.store.clone();
    let zones = tenko_dns::zone::ZoneService::with_direct_jobs(store, None, ZoneConfig::default());
    let keys = Arc::new(KeyLoader::new(Arc::clone(&zones)));
    let secondaries = SecondaryService::new(zones, keys, SecondarySettings::default());
    run.app = run.app.layer(Extension(secondaries));
    let (zone_id, mirror) = (run.zones[0].clone(), run.mirrors[0].0.clone());
    let reads = [
        ("GET", format!("/dns/zones/{zone_id}/records"), 200),
        ("GET", format!("/dns/zones/{zone_id}/transfer"), 200),
        ("POST", format!("/dns/zones/{zone_id}/transfer"), 202),
        ("GET", format!("/migrate/mirrors/{mirror}/snapshot"), 200),
    ];
    for (method, path, _) in &reads {
        assert_refused(&run.script(method, path, None).await, "condition");
    }
    let shown = run.shown().await;
    run.bind(Cookie(&run.admin), &shown)
        .await
        .assert_status(204);
    for (method, path, status) in &reads {
        run.script(method, path, None).await.assert_status(*status);
    }
    let records = run.script("GET", &reads[0].1, None).await;
    assert_eq!(records.body["items"][0]["type"], "SOA", "{}", records.text);
    run.rewrite(0, |mirror| {
        mirror.created.by = Principal::system(SystemComponent::Auth);
    })
    .await;
    let reply = run.script("GET", &reads[3].1, None).await;
    reply.assert_problem(404, "migrate.mirror.not_found");
    let lab = run.person("POST", "/dns/zones", Some(LAB)).await;
    let path = format!(
        "/dns/zones/{}/records",
        lab.body["id"].as_str().expect("an id")
    );
    let reply = run.script("GET", &path, None).await;
    reply.assert_problem(404, "dns.zone.not_found");
}
