//! A takeover run's zones over the served router (ADR 0038): its delegated session lists the
//! zones its run created, creates its plan's zones as unserved secondaries with the one body
//! the server builds, and deletes an unserved zone of its run only; a run is not closed while
//! it holds an unserved zone; a person's zone routes stay as they were.

use tenko_core::{
    Principal, Revision, SystemComponent,
    dns::{Origin, Rdata, RecordData, RrSet, ScopeName, Zone, ZoneId, tables},
    ipam::Stamp,
};
use tenko_dns::zone::{ZoneConfig, ZoneService};
use tenko_store::{
    ChangeStream, Committed, DerivedIndex, Leadership, ReadConsistency, ReadView, ReadViewExt as _,
    StoreError, StoreStatus, WatchFilter, WriteBatch,
};

use super::*;

/// The body the takeover script sends for its plan's domain zone (the same file as
/// `deploy/windows/takeover/tests/fixtures/zone-create.json`).
const BODY: &str = include_str!("../fixtures/zone-create.json");

/// An operator's secondary zone.
const LAB: &str = r#"{"name":"lab.example.test","kind":"secondary","soa":{"mname":"ns1.lab.example.test","rname":"hostmaster.lab.example.test"},"source":{"primaries":[{"address":"192.0.2.53"}]}}"#;

/// [`served`] with the zone service.
async fn zones() -> (TestEnv, String, axum::Router) {
    let (env, admin, app) = served().await;
    let store: Arc<dyn Store> = env.store.clone();
    let zones = ZoneService::with_direct_jobs(store, None, ZoneConfig::default());
    (env, admin, app.layer(Extension(zones)))
}

/// [`BODY`] for the plan's zone `name`.
fn body(name: &str) -> String {
    let mut body: Value = serde_json::from_str(BODY).expect("JSON");
    body["name"] = json!(name);
    body.to_string()
}

/// The answer to `method` on `path` with `body` from the script's address.
async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    credential: Credential<'_>,
    body: Option<&str>,
) -> Reply {
    send(app, from(SCRIPT, method, path, credential, body)).await
}

/// Creates the plan's zone `name` through the session `secret`; returns its id.
async fn run_zone(app: &axum::Router, secret: &str, name: &str) -> String {
    let created = call(app, "POST", "/dns/zones", Bearer(secret), Some(&body(name))).await;
    created.assert_status(201);
    created.body["id"].as_str().expect("an id").to_owned()
}

async fn put_zone(env: &TestEnv, zone: &Zone) {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dns), Timestamp::now());
    batch
        .put_typed(&tables::ZONES, &zone.id, zone)
        .expect("encode");
    env.store.propose(batch).await.expect("commit");
}

async fn zone(env: &TestEnv, id: &str) -> Zone {
    let view = env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let id: ZoneId = id.parse().expect("an id");
    view.get_typed(&tables::ZONES, &id)
        .expect("read")
        .expect("the zone")
        .0
}

/// A person flips the zone `id` to primary, once it holds the copy a refresh writes (its SOA).
async fn flip(env: &TestEnv, app: &axum::Router, admin: &str, id: &str) -> Reply {
    let zone = zone(env, id).await;
    let soa = RecordData::Soa {
        mname: zone.soa.mname.clone(),
        rname: zone.soa.rname.clone(),
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 1_209_600,
        minimum: 60,
    };
    let set = RrSet {
        zone: zone.id,
        scope: ScopeName::DEFAULT,
        name: zone.name.clone(),
        rtype: soa.rtype(),
        ttl: 300,
        rdata: vec![Rdata::from_data(&soa)],
        origin: Origin::Manual,
        key: None,
        principal: None,
        updated: Stamp::new(Timestamp::now(), Principal::system(SystemComponent::Dns)),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dns), Timestamp::now());
    batch
        .put_typed(&tables::RRSETS, &set.key(), &set)
        .expect("encode");
    env.store.propose(batch).await.expect("commit");
    let to = json!({"to": "primary", "soa": {"mname": "tenko.corp.example.test", "rname": "hostmaster.corp.example.test"}, "ns": ["tenko.corp.example.test"]});
    let path = format!("/dns/zones/{id}/flip");
    call(app, "POST", &path, Cookie(admin), Some(&to.to_string())).await
}

/// The plan's zones only, each with exactly the body the server builds, and each unserved and
/// stamped with the run: another name, an added known field, a second primary or a key is
/// refused, an unknown field (`served` too) changes nothing, and a plan whose operations do not
/// hold `secondary_zones` creates none.
#[tokio::test]
async fn a_run_creates_its_plan_zones_unserved_and_nothing_else() {
    let (env, admin, app) = zones().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    for (field, value) in [
        ("name", json!("other.example.test")),
        ("transfer", json!({"notify": [{"address": "192.0.2.99"}]})),
        (
            "source",
            json!({"primaries": [{"address": "192.0.2.11"}, {"address": "192.0.2.12"}]}),
        ),
        (
            "source",
            json!({"primaries": [{"address": "192.0.2.11", "key": "xfr.corp.example.test"}]}),
        ),
    ] {
        let mut wrong: Value = serde_json::from_str(BODY).expect("JSON");
        wrong[field] = value;
        let wrong = wrong.to_string();
        let reply = call(&app, "POST", "/dns/zones", Bearer(&secret), Some(&wrong)).await;
        assert_refused(&reply, "plan");
    }
    let mut extra: Value = serde_json::from_str(BODY).expect("JSON");
    extra["served"] = json!(true);
    extra["name"] = json!("CORP.Example.Test.");
    let extra = extra.to_string();
    let created = call(&app, "POST", "/dns/zones", Bearer(&secret), Some(&extra)).await;
    created.assert_status(201);
    assert_eq!(created.body["name"], "corp.example.test");
    assert_eq!(created.body["served"], false);
    let stamp = &created.body["created"]["by"]["delegation"];
    assert_eq!(*stamp, session.delegation.to_string());
    let mut plan = tenko_auth::testing::approval::plan();
    plan["operations"] = json!(["mirrors", "flip"]);
    let plan: tenko_core::migrate::plan::TakeoverPlan =
        serde_json::from_value(plan).expect("a plan");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
    batch
        .put_typed(
            &tenko_core::migrate::tables::RUN_PLANS,
            &session.delegation,
            &plan,
        )
        .expect("encode");
    env.store.propose(batch).await.expect("commit");
    let msdcs = body("_msdcs.corp.example.test");
    let reply = call(&app, "POST", "/dns/zones", Bearer(&secret), Some(&msdcs)).await;
    assert_refused(&reply, "plan");
}

/// The session lists its run's zones only, and an operator's zone, another run's and a missing
/// one answer its delete with the same 404, byte for byte; only the audit says which.
#[tokio::test]
async fn a_delegated_session_reaches_its_runs_zones_only() {
    let (env, admin, app) = zones().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    run_zone(&app, &secret, "corp.example.test").await;
    let other = run_zone(&app, &secret, "_msdcs.corp.example.test").await;
    let mut theirs = zone(&env, &other).await;
    theirs.created.by = Principal::User {
        id: tenko_core::UserId::generate(),
        session: tenko_core::SessionId::generate(),
        strength: tenko_core::AuthStrength::Password,
        delegation: Some(tenko_core::DelegationId::generate()),
    };
    put_zone(&env, &theirs).await;
    let operators = call(&app, "POST", "/dns/zones", Cookie(&admin), Some(LAB)).await;
    operators.assert_status(201);
    let listed = call(&app, "GET", "/dns/zones", Bearer(&secret), None).await;
    listed.assert_status(200);
    let names: Vec<&str> = listed.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(names, ["corp.example.test"]);
    let operators = operators.body["id"].as_str().expect("an id");
    let mut answers = Vec::new();
    for id in [operators, &other] {
        let path = format!("/dns/zones/{id}");
        let reply = call(&app, "DELETE", &path, Bearer(&secret), None).await;
        reply.assert_problem(404, "dns.zone.not_found");
        answers.push(reply.text);
    }
    // A later sitting's first refusal is recorded on its own: a missing zone.
    send(
        &app,
        from(SCRIPT, "POST", "/auth/logout", Bearer(&secret), None),
    )
    .await
    .assert_status(204);
    let later = delegated(&env, &admin, "192.0.2.11").await;
    let path = format!("/dns/zones/{}", ZoneId::generate());
    let bearer = Bearer(later.secret.expose());
    let reply = send(&app, from("192.0.2.11", "DELETE", &path, bearer, None)).await;
    reply.assert_problem(404, "dns.zone.not_found");
    answers.push(reply.text);
    assert!(
        answers.iter().all(|text| *text == answers[0]),
        "{answers:?}"
    );
    assert_eq!(refusals_found(&env).await, ["missing", "outside_run"]);
}

/// The session deletes an unserved zone of its run, at the revision the server read: a served
/// one is refused with `served`, and a stale `If-Match` with 412.
#[tokio::test]
async fn a_served_run_zone_is_not_deleted_by_its_session() {
    let (env, admin, app) = zones().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let served = run_zone(&app, &secret, "corp.example.test").await;
    let unserved = run_zone(&app, &secret, "_msdcs.corp.example.test").await;
    flip(&env, &app, &admin, &served).await.assert_status(200);
    let path = format!("/dns/zones/{served}");
    let reply = call(&app, "DELETE", &path, Bearer(&secret), None).await;
    assert_refused(&reply, "served");
    let path = format!("/dns/zones/{unserved}");
    let mut stale = from(SCRIPT, "DELETE", &path, Bearer(&secret), None);
    stale.headers_mut().insert(
        axum::http::header::IF_MATCH,
        "\"1\"".parse().expect("a value"),
    );
    send(&app, stale)
        .await
        .assert_problem(412, "sys.store.precondition_failed");
    call(&app, "DELETE", &path, Bearer(&secret), None)
        .await
        .assert_status(204);
}

/// The zone service's store: once armed, it lets `skip` reads pass and commits the change
/// before the next one, as a person's write landing between two reads of one request.
struct Between {
    inner: Arc<dyn Store>,
    change: std::sync::Mutex<Option<(usize, WriteBatch)>>,
}

/// A boxed future, as `async_trait` desugars the async methods of [`Store`].
type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl Store for Between {
    fn propose<'life0, 'async_trait>(
        &'life0 self,
        batch: WriteBatch,
    ) -> Boxed<'async_trait, Result<Committed, StoreError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.propose(batch)
    }

    fn read<'life0, 'async_trait>(
        &'life0 self,
        consistency: ReadConsistency,
    ) -> Boxed<'async_trait, Result<Arc<dyn ReadView>, StoreError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let due = {
            let mut change = self.change.lock().expect("the change");
            match change.as_mut() {
                Some((0, _)) => change.take().map(|(_, batch)| batch),
                Some((skip, _)) => {
                    *skip -= 1;
                    None
                }
                None => None,
            }
        };
        Box::pin(async move {
            if let Some(batch) = due {
                self.inner.propose(batch).await?;
            }
            self.inner.read(consistency).await
        })
    }

    fn watch(
        &self,
        from: Option<Revision>,
        filter: WatchFilter,
    ) -> Result<ChangeStream, StoreError> {
        self.inner.watch(from, filter)
    }

    fn register_index(&self, index: Arc<dyn DerivedIndex>) -> Result<(), StoreError> {
        self.inner.register_index(index)
    }

    fn status(&self) -> StoreStatus {
        self.inner.status()
    }

    fn leadership(&self) -> tokio::sync::watch::Receiver<Option<Leadership>> {
        self.inner.leadership()
    }
}

/// A person serves the zone between the delete handler's read and the delete's own: the
/// delete runs at the revision the handler read, so it is refused with 412 and the zone stays.
#[tokio::test]
async fn a_zone_served_while_its_delete_runs_stays() {
    let (env, admin, app) = served().await;
    let store = Arc::new(Between {
        inner: env.store.clone(),
        change: std::sync::Mutex::new(None),
    });
    let zones = ZoneService::with_direct_jobs(store.clone(), None, ZoneConfig::default());
    let app = app.layer(Extension(zones));
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let id = run_zone(&app, &secret, "corp.example.test").await;
    let mut flipped = zone(&env, &id).await;
    flipped.served = true;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dns), Timestamp::now());
    batch
        .put_typed(&tables::ZONES, &flipped.id, &flipped)
        .expect("encode");
    *store.change.lock().expect("the change") = Some((1, batch));
    let path = format!("/dns/zones/{id}");
    call(&app, "DELETE", &path, Bearer(&secret), None)
        .await
        .assert_problem(412, "sys.store.precondition_failed");
    assert!(store.change.lock().expect("the change").is_none());
    assert!(zone(&env, &id).await.served);
}

/// A run is not closed while it holds an unserved zone, which the refusal names; a served zone
/// of the run is what the run produced and does not hold the close.
#[tokio::test]
async fn a_run_with_unserved_zones_is_not_closed() {
    let (env, admin, app) = zones().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let served = run_zone(&app, &secret, "corp.example.test").await;
    let unserved = run_zone(&app, &secret, "_msdcs.corp.example.test").await;
    flip(&env, &app, &admin, &served).await.assert_status(200);
    let close = format!("/migrate/runs/{}/close", session.delegation);
    let busy = call(&app, "POST", &close, Cookie(&admin), None).await;
    busy.assert_problem(409, "migrate.run.busy");
    assert_eq!(busy.body["params"]["zones"], "_msdcs.corp.example.test");
    assert_eq!(busy.body["params"]["mirrors"], "");
    let path = format!("/dns/zones/{unserved}");
    call(&app, "DELETE", &path, Bearer(&secret), None)
        .await
        .assert_status(204);
    call(&app, "POST", &close, Cookie(&admin), None)
        .await
        .assert_status(204);
}

/// A person creates a served zone as before, a change keeps a zone unserved, an unserved zone
/// never becomes a catalog zone, and a person's flip of an unserved run zone serves it and says
/// so in its audit record.
#[tokio::test]
async fn a_persons_zone_routes_are_unchanged() {
    let (env, admin, app) = zones().await;
    let created = call(&app, "POST", "/dns/zones", Cookie(&admin), Some(LAB)).await;
    created.assert_status(201);
    assert_eq!(created.body["served"], true);
    let session = delegated(&env, &admin, SCRIPT).await;
    let id = run_zone(&app, session.secret.expose(), "corp.example.test").await;
    let path = format!("/dns/zones/{id}");
    let described = json!({"description": "the copy"}).to_string();
    let changed = call(&app, "PATCH", &path, Cookie(&admin), Some(&described)).await;
    changed.assert_status(200);
    assert_eq!(changed.body["served"], false);
    let catalog = json!({"catalog": true}).to_string();
    let refused = call(&app, "PATCH", &path, Cookie(&admin), Some(&catalog)).await;
    refused.assert_problem(400, "dns.zone.invalid");
    assert_eq!(
        refused.body["params"]["field"], "served",
        "{}",
        refused.text
    );
    let flipped = flip(&env, &app, &admin, &id).await;
    flipped.assert_status(200);
    assert!(zone(&env, &id).await.served);
    let view = env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let audit = view
        .scan_typed(
            &tenko_store::tables::AUDIT,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("the audit");
    assert!(audit.iter().any(|(_, record, _)| {
        record.draft.action.as_str() == "dns.zone.flip"
            && record
                .draft
                .details
                .context
                .get("served")
                .map(String::as_str)
                == Some("true")
    }));
}
