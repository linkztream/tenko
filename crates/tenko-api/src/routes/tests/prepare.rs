//! A takeover run's prepare over the served router (ADR 0038, plan section 2.5): its delegated
//! session prepares a scope of its plan from its run's mirror as Tenko's own copy, switched
//! off, rebuilds it while nobody else touched it, and removes it within five minutes of an
//! approval; everything a push names is checked as a stranger's input, and a sitting never
//! removes or rebuilds what it prepared itself.

use std::{fmt::Debug, net::IpAddr, sync::Arc};

use serde::{Serialize, de::DeserializeOwned};
use tenko_core::{
    AddressId, Credentials, DelegationId, InterfaceId, PrefixId, Principal, RequestCtx, Revision,
    SystemComponent,
    codec::key::KeyCodec,
    dhcp::{
        Condition, ExclusionId, ExclusionRange, Join, LeaseTimes, Match, OptionData, OptionOwner,
        OptionSpace, PolicyAction, Term,
        tables::{EXCLUSIONS, FILTERS, LEASES, OPTION_SETS, SCOPES, SETTINGS},
    },
    ipam::{PrefixRole, RangeRole, Stamp},
    migrate::tables::SNAPSHOTS,
    table::TableDef,
};
use tenko_dhcp::config::{
    ConfigService,
    classes::NewPolicy,
    load,
    options::OptionInput,
    pools::PoolChange,
    scopes::{NewScope, ScopeChange},
};
use tenko_ipam::{
    IpamCommand, PlanOptions,
    tables::{ADDRESSES, PREFIXES, RANGES},
};
use tenko_store::{KeyRange, ReadConsistency, ReadView, ReadViewExt as _, WriteBatch};

use super::*;

/// The plan's scope in a path.
const CIDR: &str = "192.0.2.0%2F24";

/// The mirror host of the test plan, the one address its mirror tokens are bound to.
const MIRROR_HOST: &str = "192.0.2.30";

/// The snapshot's scope: one pool, an exclusion pushed twice, eight days, DDNS with a forward
/// zone and a TTL of its own, a router option.
fn scope() -> Value {
    let origin = json!({ "sheet": "Get-DhcpServerv4Scope", "column": "ScopeId=192.0.2.0" });
    json!({
        "cidr": "192.0.2.0/24", "name": "Office", "description": "pushed text", "active": true,
        "lease_secs": 691_200,
        "ranges": [{ "first": "192.0.2.100", "last": "192.0.2.199" }],
        "exclusions": [
            { "first": "192.0.2.100", "last": "192.0.2.109" },
            { "first": "192.0.2.100", "last": "192.0.2.109" }
        ],
        "reservations": [],
        "options": [{ "code": 3, "values": ["192.0.2.1"], "origin": origin }],
        "ddns": {
            "enabled": true, "forward_zone": "0190d1c2-0000-7000-8000-0000000000aa",
            "reverse": true, "ttl": 300, "conflict": "protect", "client_may_update_a": false,
            "legacy_clients": true, "refuse_foreign": false
        },
        "restricted": false, "delay_ms": 0, "origin": origin
    })
}

/// A snapshot at `sequence` of [`scope`] after `edit`.
fn envelope(sequence: u64, edit: impl FnOnce(&mut Value)) -> Value {
    let mut envelope = json!({
        "format": 1, "sequence": sequence, "taken_at": "2026-11-01T08:00:00Z",
        "source": {
            "kind": "windows-dhcp", "server": "dhcp1.corp.example.test",
            "adapter": "Tenko-DhcpMirror.ps1", "adapter_version": "0.1.0"
        },
        "dhcp": {
            "server_options": [], "option_defs": [], "classes": [], "scopes": [scope()],
            "superscopes": [], "policies": [], "filters": [], "failover": [], "leases": []
        },
        "losses": { "entries": [] }
    });
    edit(&mut envelope);
    envelope
}

/// Sets the one pool of a snapshot's scope.
fn pool(envelope: &mut Value, first: &str, last: &str) {
    envelope["dhcp"]["scopes"][0]["ranges"] = json!([{ "first": first, "last": last }]);
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// A run with its mirror of the plan's first server, which pushed [`scope`] once.
struct Run {
    env: TestEnv,
    admin: String,
    app: axum::Router,
    secret: String,
    id: DelegationId,
    mirror: String,
}

async fn run() -> Run {
    let (env, admin, app) = served().await;
    let session = delegated(&env, &admin, SCRIPT).await;
    let secret = session.secret.expose().to_owned();
    let create = from(
        SCRIPT,
        "POST",
        "/migrate/mirrors",
        Bearer(&secret),
        Some(DHCP1),
    );
    let created = send(&app, create).await;
    created.assert_status(201);
    let text = |field: &Value| field.as_str().expect("a string").to_owned();
    let mirror = text(&created.body["mirror"]["id"]);
    let token = text(&created.body["token"]);
    let body = envelope(1, |_| {}).to_string();
    let path = format!("/migrate/mirrors/{mirror}/snapshot");
    let push = from(MIRROR_HOST, "PUT", &path, Bearer(&token), Some(&body));
    send(&app, push).await.assert_status(200);
    Run {
        id: session.delegation,
        env,
        admin,
        app,
        secret,
        mirror,
    }
}

impl Run {
    async fn prepare(&self) -> Reply {
        let path = format!("/migrate/mirrors/{}/scopes/{CIDR}/prepare", self.mirror);
        let bearer = Bearer(&self.secret);
        send(&self.app, from(SCRIPT, "POST", &path, bearer, None)).await
    }

    async fn remove(&self, credential: Credential<'_>) -> Reply {
        let path = format!("/migrate/runs/{}/scopes/{CIDR}", self.id);
        send(&self.app, from(SCRIPT, "DELETE", &path, credential, None)).await
    }

    /// Stores `envelope` as the mirror's newer snapshot, as an accepted push leaves it.
    async fn store(&self, envelope: Value) {
        let id = self.mirror.parse().expect("an id");
        let view = self.view().await;
        let (mut stored, _) = (view.get_typed(&SNAPSHOTS, &id).expect("read")).expect("stored");
        stored.envelope = serde_json::from_value(envelope).expect("an envelope");
        stored.sequence = stored.envelope.sequence;
        stored.received = Timestamp::now();
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
        batch.put_typed(&SNAPSHOTS, &id, &stored).expect("encode");
        self.env.store.propose(batch).await.expect("commit");
    }

    /// A later sitting of the run: its session's approval is now, after what it prepared.
    async fn sit_again(&self) {
        approve_at(&self.env, &self.secret, Timestamp::now()).await;
    }

    async fn view(&self) -> Arc<dyn ReadView> {
        let read = self.env.store.read(ReadConsistency::Local);
        read.await.expect("a view")
    }

    fn revision(&self) -> Revision {
        self.env.store.status().revision
    }

    async fn person(&self) -> RequestCtx {
        let session = Credentials::Session(self.admin.clone());
        self.env.ctx_for(&session).await.expect("the administrator")
    }

    /// The run's own principal, as its session's requests carry it.
    async fn own(&self) -> RequestCtx {
        let bearer = Credentials::Bearer(self.secret.clone());
        let source = SCRIPT.parse().expect("an address");
        let session = self
            .env
            .service
            .authenticate_from(&bearer, Some(source), Timestamp::now());
        RequestCtx::new(session.await.expect("the session").principal)
    }

    fn config(&self) -> Arc<ConfigService> {
        ConfigService::with_direct_jobs(self.env.store.clone())
    }

    /// `commands` through IPAM as `cx`.
    async fn ipam(&self, cx: &RequestCtx, commands: &[IpamCommand]) {
        let ipam = IpamService::with_direct_jobs(self.env.store.clone()).expect("IPAM");
        let applied = ipam.execute(commands, cx, &PlanOptions::default()).await;
        applied.expect("written");
    }

    /// `commands`, in their JSON form, through IPAM as the person.
    async fn person_ipam(&self, commands: Value) {
        let commands: Vec<IpamCommand> = serde_json::from_value(commands).expect("commands");
        self.ipam(&self.person().await, &commands).await;
    }

    /// A person's prefix `cidr` of `role` in the default VRF.
    async fn person_prefix(&self, cidr: &str, role: PrefixRole) -> PrefixId {
        let id = PrefixId::generate();
        let args = json!({ "id": id, "cidr": cidr, "role": role });
        self.person_ipam(json!([{ "op": "create_prefix", "args": args }]))
            .await;
        id
    }

    /// A person's change of the scope of `prefix`.
    async fn person_changes(&self, prefix: PrefixId, change: ScopeChange) {
        let person = self.person().await;
        let config = self.config();
        let changed = config.update_scope(&person, prefix, change, None);
        changed.await.expect("a person's change");
    }

    /// The rows of the five kinds the prepare writes that the mirror's diff still shows.
    async fn written_rows(&self) -> Vec<String> {
        let path = format!("/migrate/mirrors/{}/scopes/{CIDR}/diff", self.mirror);
        let diff = send(
            &self.app,
            from(SCRIPT, "GET", &path, Cookie(&self.admin), None),
        )
        .await;
        diff.assert_status(200);
        let kinds = ["prefix", "pool", "exclusion", "lease_time", "ddns"];
        (diff.body["rows"].as_array().expect("rows").iter())
            .filter(|row| kinds.contains(&row["kind"].as_str().unwrap_or_default()))
            .map(ToString::to_string)
            .collect()
    }

    /// The lease time, the pools and the exclusions of the scope of `prefix`, as text.
    async fn scope_of(&self, prefix: PrefixId) -> String {
        let view = self.view().await;
        let (scope, _) = view
            .get_typed(&SCOPES, &prefix)
            .expect("read")
            .expect("a scope");
        let pools = load::ranges_of(view.as_ref(), prefix).expect("ranges");
        let pools: Vec<_> = pools
            .iter()
            .map(|(r, _)| format!("{}-{}", r.first, r.last))
            .collect();
        let exclusions = ConfigService::exclusions(view.as_ref(), prefix).expect("exclusions");
        let exclusions: Vec<_> = (exclusions.iter())
            .map(|row| format!("{}-{}", row.exclusion.first, row.exclusion.last))
            .collect();
        let lease = scope.lease.map(|lease| lease.default_secs);
        format!("{lease:?} {pools:?} {exclusions:?}")
    }
}

fn new_scope(prefix: PrefixId) -> NewScope {
    NewScope {
        prefix,
        enabled: None,
        lease: None,
        authoritative: None,
        server_id: None,
        ddns: None,
        shared_network: None,
        restricted: false,
        classes: Vec::new(),
        description: None,
        v6: None,
    }
}

/// A DNS server option.
fn dns_option() -> OptionInput {
    OptionInput {
        space: OptionSpace::dhcp4(),
        code: 6,
        data: None,
        typed: Some(OptionData::Ipv4 {
            values: vec!["192.0.2.53".parse().expect("an address")],
        }),
    }
}

fn prefix_of(reply: &Reply) -> PrefixId {
    reply.assert_status(200);
    let prefix = reply.body["prefix"].as_str().expect("a prefix");
    prefix.parse().expect("an id")
}

/// The rows of `table` that the run did not create (`by` names the creator).
fn not_ours<K: KeyCodec, V: Serialize + DeserializeOwned + Debug>(
    view: &dyn ReadView,
    table: &TableDef<K, V>,
    by: fn(&V) -> &Principal,
    run: DelegationId,
) -> Vec<String> {
    let rows = view.scan_typed(table, KeyRange::all(), usize::MAX, false);
    (rows.expect("read").into_iter())
        .filter(|(_, row, _)| by(row).delegation() != Some(run))
        .map(|(_, row, at)| format!("{row:?}@{at:?}"))
        .collect()
}

/// Every row of `view` that is not the run's: what a prepare leaves as it was.
fn others(view: &dyn ReadView, run: DelegationId) -> Vec<String> {
    let mut rows = not_ours(view, &PREFIXES, |row| &row.meta.created.by, run);
    rows.extend(not_ours(view, &RANGES, |row| &row.meta.created.by, run));
    rows.extend(not_ours(view, &SCOPES, |row| &row.created.by, run));
    let all = KeyRange::all;
    let sets = view.scan_typed(&OPTION_SETS, all(), usize::MAX, false);
    let filters = view.scan_typed(&FILTERS, all(), usize::MAX, false);
    rows.push(format!(
        "{sets:?} {filters:?} {:?}",
        view.get_typed(&SETTINGS, &())
    ));
    rows
}

/// The run's prefix, pool and disabled, non-authoritative scope with
/// the snapshot's lease time, DDNS flags and distinct exclusions, all stamped by the run, no
/// pushed forward zone, TTL or text; the five kinds of row are gone from the diff, the scope
/// is in no serving image, and every row a person made is as it was.
#[tokio::test]
async fn a_run_prepares_its_plan_scope_switched_off() {
    let run = run().await;
    let person = run.person().await;
    let config = run.config();
    let theirs = run
        .person_prefix("198.51.100.0/24", PrefixRole::Network)
        .await;
    let made = config.create_scope(&person, new_scope(theirs));
    made.await.expect("a person's scope");
    let server = config.set_option_set(&person, OptionOwner::Server, vec![dns_option()], None);
    server.await.expect("a person's server options");
    let before = others(run.view().await.as_ref(), run.id);

    let prefix = prefix_of(&run.prepare().await);
    let view = run.view().await;
    let own = |by: &Principal| assert_eq!(by.delegation(), Some(run.id));
    let (row, _) = view
        .get_typed(&PREFIXES, &prefix)
        .expect("read")
        .expect("a prefix");
    own(&row.meta.created.by);
    assert_eq!(row.cidr.to_string(), "192.0.2.0/24");
    assert_eq!(
        (row.role, row.meta.description),
        (PrefixRole::Network, None)
    );
    for (range, _) in load::ranges_of(view.as_ref(), prefix).expect("ranges") {
        own(&range.meta.created.by);
        assert_eq!(range.role, RangeRole::DhcpPool);
    }
    let (scope, _) = view
        .get_typed(&SCOPES, &prefix)
        .expect("read")
        .expect("a scope");
    own(&scope.created.by);
    assert!(!scope.enabled);
    assert_eq!(scope.authoritative, Some(false));
    assert_eq!((scope.ddns.forward_zone, scope.ddns.ttl), (None, None));
    assert!(scope.ddns.enabled && scope.ddns.legacy_clients);
    assert_eq!(scope.description, None);
    for row in ConfigService::exclusions(view.as_ref(), prefix).expect("exclusions") {
        own(&row.exclusion.created.by);
    }
    let expected = r#"Some(691200) ["192.0.2.100-192.0.2.199"] ["192.0.2.100-192.0.2.109"]"#;
    assert_eq!(run.scope_of(prefix).await, expected);
    let data = load::data(view.as_ref(), false).expect("rows");
    let built = tenko_dhcp::config::image::build(&data);
    assert!(
        built.image.scope(prefix).is_none(),
        "a prepared scope serves nothing"
    );
    assert!(built.image.scope(theirs).is_some());
    assert_eq!(run.written_rows().await, Vec::<String>::new());
    assert_eq!(others(view.as_ref(), run.id), before);
}

/// A scope outside the plan, or a plan without the prepare, answers 403 `plan`
/// before the snapshot is read; a person's mirror and a missing one answer the same 404 (and so
/// does another run's, by the allow-list's one check). A person's request answers 501.
#[tokio::test]
async fn a_prepare_outside_the_plan_or_the_run_is_refused() {
    let run = run().await;
    let before = run.revision();
    let prepare = |mirror: &str, cidr: &str, credential| {
        let path = format!("/migrate/mirrors/{mirror}/scopes/{cidr}/prepare");
        from(SCRIPT, "POST", &path, credential, None)
    };
    let bearer = Bearer(&run.secret);
    let outside = send(&run.app, prepare(&run.mirror, "198.51.100.0%2F24", bearer)).await;
    assert_refused(&outside, "plan");
    let lab = r#"{"name":"lab","kind":"windows-dhcp"}"#;
    let made = from(
        SCRIPT,
        "POST",
        "/migrate/mirrors",
        Cookie(&run.admin),
        Some(lab),
    );
    let created = send(&run.app, made).await;
    let operators = created.body["mirror"]["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let mut answers = Vec::new();
    for mirror in [
        operators.clone(),
        tenko_core::MirrorId::generate().to_string(),
    ] {
        let reply = send(&run.app, prepare(&mirror, CIDR, bearer)).await;
        reply.assert_problem(404, "migrate.mirror.not_found");
        answers.push(reply.text);
    }
    assert_eq!(answers[0], answers[1]);
    let person = send(&run.app, prepare(&operators, CIDR, Cookie(&run.admin))).await;
    person.assert_problem(501, "sys.not_implemented");
    // Without its snapshot the plan refuses first.
    let id = run.mirror.parse().expect("an id");
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch.delete_typed(&SNAPSHOTS, &id);
    let plans = &tenko_core::migrate::tables::RUN_PLANS;
    let (mut plan, _) = (run.view().await.get_typed(plans, &run.id).expect("read")).expect("plan");
    plan.operations
        .retain(|operation| *operation != tenko_core::migrate::plan::PlanOperation::Prepare);
    batch.put_typed(plans, &run.id, &plan).expect("encode");
    run.env.store.propose(batch).await.expect("commit");
    assert!(run.revision() > before);
    let before = run.revision();
    assert_refused(&run.prepare().await, "plan");
    assert_eq!(run.revision(), before);
}

/// An edit of a snapshot.
type Edit = fn(&mut Value);

/// The checks before any write: an open loss, a row to decide, two ranges and a lease
/// time Tenko refuses each answer 409 with what to do and its parameters, and the store is
/// as it was.
#[tokio::test]
async fn an_open_loss_a_decision_or_a_value_tenko_refuses_writes_nothing() {
    let run = run().await;
    let cases: [(Edit, &str, Value); 4] = [
        (
            |envelope| {
                let location =
                    json!({ "sheet": "Get-DhcpServerv4Policy", "column": "192.0.2.0:Printers" });
                let loss = json!({ "location": location, "code": "migrate.loss.policy", "detail": "not carried" });
                envelope["losses"]["entries"] = json!([loss]);
            },
            "migrate.takeover.losses",
            json!({ "scope": "192.0.2.0/24", "count": "1" }),
        ),
        (
            |envelope| {
                let option = &mut envelope["dhcp"]["scopes"][0]["options"][0];
                option["vendor_class"] = json!("Microsoft Windows 2000 Options");
            },
            "migrate.takeover.diff",
            json!({ "item": "scope:3@Microsoft Windows 2000 Options" }),
        ),
        (
            |envelope| {
                envelope["dhcp"]["scopes"][0]["ranges"] = json!([
                    { "first": "192.0.2.100", "last": "192.0.2.149" },
                    { "first": "192.0.2.150", "last": "192.0.2.199" }
                ]);
            },
            "migrate.takeover.diff",
            json!({ "item": "ranges" }),
        ),
        (
            |envelope| envelope["dhcp"]["scopes"][0]["lease_secs"] = json!(400 * 86_400),
            "migrate.takeover.diff",
            json!({ "item": "lease_secs" }),
        ),
    ];
    for (sequence, (edit, code, params)) in (2..).zip(cases) {
        run.store(envelope(sequence, edit)).await;
        let before = run.revision();
        let reply = run.prepare().await;
        reply.assert_problem(409, code);
        assert_eq!(reply.body["params"], params, "{}", reply.text);
        let detail = reply.body["detail"].as_str().expect("a detail");
        assert!(
            detail.contains("run the script again") && !detail.contains(code),
            "{detail}"
        );
        assert_eq!(run.revision(), before, "{code} {params}");
    }
    // Under Hardened, DDNS settings of `replace`, Windows' default without name protection.
    let replace = |envelope: &mut Value| {
        envelope["dhcp"]["scopes"][0]["ddns"]["conflict"] = json!("replace");
    };
    run.store(envelope(6, replace)).await;
    prefix_of(&run.prepare().await);
    let settings = &tenko_auth::model::SETTINGS;
    let (mut stored, _) =
        (run.view().await.get_typed(settings, &()).expect("read")).expect("settings");
    stored.profile = tenko_auth::settings::Profile::Hardened;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
    batch.put_typed(settings, &(), &stored).expect("encode");
    run.env.store.propose(batch).await.expect("commit");
    run.store(envelope(7, |envelope| {
        replace(envelope);
        pool(envelope, "192.0.2.100", "192.0.2.149");
    }))
    .await;
    let before = run.revision();
    let reply = run.prepare().await;
    reply.assert_problem(409, "migrate.takeover.diff");
    assert_eq!(reply.body["params"]["item"], "ddns", "{}", reply.text);
    assert_eq!(run.revision(), before);
}

/// A second prepare of the same snapshot writes nothing and names the same prefix.
#[tokio::test]
async fn a_second_prepare_of_the_same_snapshot_writes_nothing() {
    let run = run().await;
    let first = prefix_of(&run.prepare().await);
    let before = run.revision();
    let again = prefix_of(&run.prepare().await);
    assert_eq!((again, run.revision()), (first, before));
}

/// A person's network at, around or inside the plan's network, the run's scope a person
/// switched on and a person's scope on the run's prefix are refused, and nothing is written;
/// IPAM's refusal names no object of the person to the run's session, while a person's own
/// IPAM refusal keeps its parameters.
#[tokio::test]
async fn a_prepare_never_takes_or_overlaps_what_a_person_made() {
    for cidr in ["192.0.2.0/24", "192.0.0.0/16", "192.0.2.128/25"] {
        let run = run().await;
        run.person_prefix(cidr, PrefixRole::Network).await;
        let before = run.revision();
        let reply = run.prepare().await;
        reply.assert_problem(409, "ipam.prefix.overlap");
        let named = (&reply.body["params"], &reply.body["errors"]);
        assert_eq!(named, (&Value::Null, &Value::Null), "{}", reply.text);
        assert!(!reply.text.contains(cidr), "{}", reply.text);
        assert_eq!(run.revision(), before, "{cidr}");
    }
    let run = run().await;
    let prefix = prefix_of(&run.prepare().await);
    run.person_changes(prefix, switched(true)).await;
    run.store(envelope(2, |envelope| {
        pool(envelope, "192.0.2.100", "192.0.2.149");
    }))
    .await;
    let before = run.revision();
    let reply = run.prepare().await;
    reply.assert_problem(409, "migrate.takeover.scope_enabled");
    assert_eq!(run.revision(), before);
    let person = run.person().await;
    let config = run.config();
    config
        .delete_scope(&person, prefix, None)
        .await
        .expect("deleted");
    config
        .create_scope(&person, new_scope(prefix))
        .await
        .expect("theirs");
    let before = run.revision();
    run.prepare().await.assert_problem(409, "dhcp.scope.exists");
    assert_eq!(run.revision(), before);

    let run = self::run().await;
    prefix_of(&run.prepare().await);
    let address = json!({ "op": "create_address", "args": { "ip": "192.0.2.70" } });
    run.person_ipam(json!([address])).await;
    let reply = run.remove(Cookie(&run.admin)).await;
    reply.assert_problem(409, "ipam.in_use");
    assert_eq!(reply.body["params"]["count"], "1", "{}", reply.text);
}

fn switched(enabled: bool) -> ScopeChange {
    ScopeChange {
        enabled: Some(enabled),
        ..ScopeChange::default()
    }
}

fn described() -> ScopeChange {
    ScopeChange {
        description: Some("a person's".to_owned()),
        ..ScopeChange::default()
    }
}

/// A newer snapshot with an added exclusion, a changed range and another lease time
/// rebuilds the run's untouched scope in a later sitting, and the diff holds none of the five
/// kinds after it; the sitting that prepared it is refused the rebuild, and nothing is written.
#[tokio::test]
async fn a_newer_snapshot_rebuilds_the_runs_untouched_scope_in_a_later_sitting() {
    let run = run().await;
    let first = prefix_of(&run.prepare().await);
    run.store(envelope(2, |envelope| {
        pool(envelope, "192.0.2.100", "192.0.2.189");
        let scope = &mut envelope["dhcp"]["scopes"][0];
        scope["lease_secs"] = json!(86_400);
        let added = json!({ "first": "192.0.2.150", "last": "192.0.2.159" });
        scope["exclusions"]
            .as_array_mut()
            .expect("exclusions")
            .push(added);
    }))
    .await;
    let before = run.revision();
    assert_refused(&run.prepare().await, "condition");
    assert_eq!(run.revision(), before);
    run.sit_again().await;
    let second = prefix_of(&run.prepare().await);
    assert_ne!(second, first);
    let expected = r#"Some(86400) ["192.0.2.100-192.0.2.189"] ["192.0.2.100-192.0.2.109", "192.0.2.150-192.0.2.159"]"#;
    assert_eq!(run.scope_of(second).await, expected);
    assert_eq!(run.written_rows().await, Vec::<String>::new());
}

/// After a failure between the IPAM batch and the scope's batch, the prepare of a later
/// sitting (the operator's rerun) rebuilds the prefix from the newest snapshot and creates the
/// scope; the scope's batch of the first prepare, when it comes after that, answers 404
/// `ipam.not_found` and writes nothing, so one scope holds each exclusion once.
#[tokio::test]
async fn a_rerun_after_a_failure_between_the_batches_completes_the_scope() {
    let run = run().await;
    let own = run.own().await;
    let config = run.config();
    let crashed = prefix_of(&run.prepare().await);
    let failed = config.delete_scope(&own, crashed, None);
    failed.await.expect("the prefix without its scope");
    run.store(envelope(2, |envelope| {
        pool(envelope, "192.0.2.100", "192.0.2.149");
    }))
    .await;
    run.sit_again().await;
    let prefix = prefix_of(&run.prepare().await);
    assert_ne!(prefix, crashed);
    let exclusions = [(ip("192.0.2.100"), ip("192.0.2.109"))];
    let late = config.create_scope_with(&own, new_scope(crashed), &exclusions);
    let late = late.await.expect_err("the first prepare's second batch");
    assert!(late.is("ipam.not_found"), "{late:?}");
    let expected = r#"Some(691200) ["192.0.2.100-192.0.2.149"] ["192.0.2.100-192.0.2.109"]"#;
    assert_eq!(run.scope_of(prefix).await, expected);
    let view = run.view().await;
    assert!(view.get_typed(&SCOPES, &crashed).expect("read").is_none());
    assert_eq!(run.written_rows().await, Vec::<String>::new());
}

/// A change of the run's scope of `prefix` by someone else, by `how`.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per kind of change, read top to bottom"
)]
async fn touch(run: &Run, prefix: PrefixId, how: &str) {
    let person = run.person().await;
    let config = run.config();
    let view = run.view().await;
    let range = load::ranges_of(view.as_ref(), prefix).expect("ranges")[0]
        .0
        .id;
    let system = |batch: WriteBatch| run.env.store.propose(batch);
    let patch = |op: &str, id: Value| json!([{ "op": op, "args": { "id": id, "patch": { "description": "a person's" } } }]);
    match how {
        "option set" => {
            let set = config.set_option_set(
                &person,
                OptionOwner::Scope(prefix),
                vec![dns_option()],
                None,
            );
            set.await.expect("a person's options");
        }
        "exclusion" => {
            let made = config.create_exclusion(
                &person,
                prefix,
                ip("192.0.2.190"),
                ip("192.0.2.199"),
                None,
            );
            made.await.expect("a person's exclusion");
        }
        "exclusion deleted" => {
            let rows = ConfigService::exclusions(view.as_ref(), prefix).expect("exclusions");
            let deleted = config.delete_exclusion(&person, prefix, rows[0].exclusion.id, None);
            deleted.await.expect("the run's exclusion deleted");
        }
        "exclusion row" => {
            // Written outside the configuration service, which records it on the scope.
            let by = Principal::system(SystemComponent::Api);
            let exclusion = ExclusionRange {
                id: ExclusionId::generate(),
                scope: prefix,
                first: ip("192.0.2.190"),
                last: ip("192.0.2.199"),
                description: None,
                created: Stamp::new(Timestamp::now(), by.clone()),
            };
            let mut batch = WriteBatch::new(by, Timestamp::now());
            let key = (prefix, exclusion.id);
            batch
                .put_typed(&EXCLUSIONS, &key, &exclusion)
                .expect("encode");
            system(batch).await.expect("commit");
        }
        "described" => run.person_changes(prefix, described()).await,
        "switched" => {
            run.person_changes(prefix, switched(true)).await;
            run.person_changes(prefix, switched(false)).await;
        }
        "prefix described" => run.person_ipam(patch("update_prefix", json!(prefix))).await,
        "range described" => run.person_ipam(patch("update_range", json!(range))).await,
        "range deleted" => {
            let delete = IpamCommand::Delete {
                object: range.into(),
                expected: None,
                cascade: false,
            };
            run.ipam(&person, &[delete]).await;
        }
        "address" => {
            let args = json!({ "ip": "192.0.2.70" });
            run.person_ipam(json!([{ "op": "create_address", "args": args }]))
                .await;
        }
        "reserved host" => {
            let interface = InterfaceId::generate();
            let card = json!({ "id": interface, "name": "eth0", "mac": "00:00:5e:00:53:02" });
            let host = json!({ "name": "printer", "mode": "reserved", "interfaces": [card] });
            let address = json!({ "ip": "192.0.2.60", "interface": interface });
            run.person_ipam(json!([
                { "op": "create_host", "args": host },
                { "op": "create_address", "args": address }
            ]))
            .await;
        }
        "pool settings" => {
            let change = PoolChange {
                lease: Some(LeaseTimes::fixed(600)),
                ..PoolChange::default()
            };
            let set = config.set_pool(&person, range, change, None);
            set.await.expect("a person's pool settings");
        }
        "policy" => {
            let policy = NewPolicy {
                name: "uefi".to_owned(),
                scope: Some(prefix),
                order: None,
                enabled: None,
                condition: Condition {
                    join: Join::And,
                    terms: vec![Term::Match(Match::Architecture { code: 7 })],
                },
                action: PolicyAction::default(),
                description: None,
            };
            config
                .create_policy(&person, policy)
                .await
                .expect("a person's policy");
        }
        _ => {
            let (row, _) = view
                .get_typed(&PREFIXES, &prefix)
                .expect("read")
                .expect("a row");
            let now = Timestamp::now();
            let ends = now.checked_add(Duration::from_secs(86_400));
            let lease: tenko_core::dhcp::Lease = serde_json::from_value(json!({
                "addr": "192.0.2.120", "vrf": row.vrf, "scope": prefix,
                "client": { "htype": 1, "chaddr": "00005e005301" }, "state": "active",
                "cltt": now, "ends": ends.expect("a time"), "node": 1
            }))
            .expect("a lease");
            let key = (row.vrf, "192.0.2.120".parse().expect("an address"));
            let mut batch =
                WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
            batch.put_typed(&LEASES, &key, &lease).expect("encode");
            system(batch).await.expect("commit");
        }
    }
}

/// A scope someone else touched in any way the run did not write, the deletion of what the
/// run wrote included, is neither rebuilt nor removed by a later sitting of the run: each
/// answers 409 naming the kind of object, and nothing is written; a person removes it. A
/// person's addresses under a supernet move into the run's prefix and back.
#[tokio::test]
async fn a_scope_someone_else_touched_is_neither_rebuilt_nor_removed_by_the_run() {
    let run = run().await;
    run.person_prefix("192.0.0.0/16", PrefixRole::Supernet)
        .await;
    let cases = [
        ("option set", "option set"),
        ("exclusion", "scope"),
        ("exclusion deleted", "scope"),
        ("exclusion row", "exclusion"),
        ("described", "scope"),
        ("switched", "scope"),
        ("prefix described", "prefix"),
        ("range described", "range"),
        ("range deleted", "range"),
        ("address", "address"),
        ("reserved host", "address"),
        ("pool settings", "pool settings"),
        ("policy", "policy"),
        // Last: the lease stays when the scope goes.
        ("leased", "leases"),
    ];
    for (sequence, (how, item)) in (2_u64..).zip(cases) {
        let prefix = prefix_of(&run.prepare().await);
        run.sit_again().await;
        touch(&run, prefix, how).await;
        run.store(envelope(sequence, |envelope| {
            envelope["dhcp"]["scopes"][0]["lease_secs"] = json!(3_600 * sequence);
        }))
        .await;
        let before = run.revision();
        let rebuild = run.prepare().await;
        rebuild.assert_problem(409, "migrate.takeover.diff");
        assert_eq!(
            rebuild.body["params"]["item"], item,
            "{how}: {}",
            rebuild.text
        );
        let removal = run.remove(Bearer(&run.secret)).await;
        removal.assert_problem(409, "migrate.takeover.scope_enabled");
        assert_eq!(
            removal.body["params"]["item"], item,
            "{how}: {}",
            removal.text
        );
        assert_eq!(run.revision(), before, "{how}");
        run.remove(Cookie(&run.admin)).await.assert_status(204);
    }
}

/// The run removes its disabled, untouched scope with its prefix in a later sitting, not in
/// the one that prepared it, and a new prepare passes; a person's address under a supernet
/// moves into the run's prefix and back. Its session is refused an enabled scope, a person's
/// prefix (the 404 of a missing one) and past five minutes.
#[tokio::test]
async fn a_run_removes_its_switched_off_scope_only() {
    let run = run().await;
    let supernet = run
        .person_prefix("192.0.0.0/16", PrefixRole::Supernet)
        .await;
    let address = AddressId::generate();
    let input = json!({ "id": address, "ip": "192.0.2.50" });
    run.person_ipam(json!([{ "op": "create_address", "args": input }]))
        .await;
    let held_by = async || {
        let view = run.view().await;
        let (row, _) = view
            .get_typed(&ADDRESSES, &address)
            .expect("read")
            .expect("a row");
        (row.prefix, row.ip)
    };
    let prefix = prefix_of(&run.prepare().await);
    assert_eq!(held_by().await.0, prefix);
    let before = run.revision();
    assert_refused(&run.remove(Bearer(&run.secret)).await, "condition");
    assert_eq!(run.revision(), before);
    run.sit_again().await;
    run.remove(Bearer(&run.secret)).await.assert_status(204);
    assert_eq!(held_by().await, (supernet, ip("192.0.2.50")));
    let view = run.view().await;
    assert!(view.get_typed(&SCOPES, &prefix).expect("read").is_none());
    let (row, _) = view
        .get_typed(&PREFIXES, &prefix)
        .expect("read")
        .expect("a row");
    assert!(row.meta.is_deleted());

    let prefix = prefix_of(&run.prepare().await);
    run.sit_again().await;
    run.person_changes(prefix, switched(true)).await;
    for credential in [Bearer(&run.secret), Cookie(&run.admin)] {
        let reply = run.remove(credential).await;
        reply.assert_problem(409, "migrate.takeover.scope_enabled");
        let detail = reply.body["detail"].as_str().expect("a detail");
        assert!(detail.contains("switched on"), "{detail}");
    }
    let person = run.person().await;
    let config = run.config();
    config
        .delete_scope(&person, prefix, None)
        .await
        .expect("deleted");
    run.remove(Cookie(&run.admin)).await.assert_status(204);
    let missing = run.remove(Bearer(&run.secret)).await;
    missing.assert_problem(404, "dhcp.scope.not_found");
    run.person_prefix("192.0.2.0/24", PrefixRole::Network).await;
    let theirs = run.remove(Bearer(&run.secret)).await;
    assert_eq!(theirs.text, missing.text);
    approve_at(&run.env, &run.secret, six_minutes_ago()).await;
    assert_refused(&run.remove(Bearer(&run.secret)).await, "condition");
}
