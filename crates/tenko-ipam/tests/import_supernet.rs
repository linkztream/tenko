//! The import's supernet step (the owner's backlog): networks of an import inside an
//! existing network of the store turn that network into a supernet, as one update the
//! preview shows as a warning to acknowledge, instead of refusing each network with
//! `ipam.prefix.overlap`. A network that a DHCP scope serves, or one with ranges, stays a
//! network and the networks inside are left out with a loss entry.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use tenko_core::{
    AuthStrength, ImportId, JobId, PrefixId, Principal, RequestCtx, SessionId, UserId,
    dhcp::{Scope, tables::SCOPES},
    ipam::{Address, Prefix, PrefixRole, RangeRole, Stamp},
};
use tenko_ipam::{
    IpamCommand, IpamConfig, IpamService, PlanOptions,
    command::{AddressInput, PrefixInput, RangeInput},
    error::codes::{PLAN_UNACKNOWLEDGED, WARN_BECOMES_SUPERNET},
    import::{
        ApplyRequest, CredentialGate, ImportConfig, ImportPreview, ImportService, Upload, codes,
        reconcile::ItemAction,
    },
    jobs::register_steps,
    tables::{ADDRESS_IPS, ADDRESSES, PREFIX_CIDRS, PREFIXES},
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, RunnerHandle};
use tenko_store::{MemStore, ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};

struct Env {
    store: Arc<MemStore>,
    engine: JobEngine,
    imports: Arc<ImportService>,
    _runner: RunnerHandle,
}

fn env() -> Env {
    let store = Arc::new(MemStore::default());
    let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
    let mut engine = JobEngine::new(Arc::clone(&dyn_store), EngineConfig::default());
    register_steps(&mut engine);
    let ipam =
        IpamService::new(dyn_store, Arc::new(engine.clone()), IpamConfig::default()).expect("ipam");
    let imports = ImportService::new(
        ipam,
        engine.clone(),
        None,
        ImportConfig {
            staging_dir: std::env::temp_dir()
                .join(format!("tenko-import-test-{}", uuid::Uuid::now_v7())),
            ..ImportConfig::default()
        },
    )
    .expect("imports");
    let runner = engine.start().expect("runner");
    Env {
        store,
        engine,
        imports,
        _runner: runner,
    }
}

fn person() -> RequestCtx {
    RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Passkey,
    })
}

fn ipam(env: &Env) -> &IpamService {
    env.imports.ipam()
}

/// Creates the network `192.0.2.0/24` with the address `192.0.2.70` in the default VRF.
async fn existing_network(env: &Env, cx: &RequestCtx) -> PrefixId {
    let id = PrefixId::generate();
    let prefix = PrefixInput {
        id: Some(id),
        vrf: None,
        cidr: "192.0.2.0/24".parse().expect("cidr"),
        role: Some(PrefixRole::Network),
        status: None,
        vlan: None,
        site: None,
        alarm: None,
        alloc: None,
        tags: BTreeSet::default(),
        custom: BTreeMap::default(),
        description: Some("the home network".to_owned()),
    };
    let address = AddressInput {
        id: None,
        vrf: None,
        ip: "192.0.2.70".parse().expect("ip"),
        status: None,
        interface: None,
        dns_name: None,
        tags: BTreeSet::default(),
        custom: BTreeMap::default(),
        description: None,
    };
    ipam(env)
        .execute(
            &[
                IpamCommand::CreatePrefix(prefix),
                IpamCommand::CreateAddress(address),
            ],
            cx,
            &PlanOptions::default(),
        )
        .await
        .expect("existing network");
    id
}

fn sheet() -> Upload {
    Upload {
        name: "networks.csv".to_owned(),
        bytes: b"Network,Description\n192.0.2.0/26,servers\n192.0.2.64/26,clients\n".to_vec(),
    }
}

async fn preview_of(env: &Env, cx: &RequestCtx) -> (ImportId, ImportPreview) {
    let view = env.imports.upload(cx, vec![sheet()]).await.expect("upload");
    let preview = env
        .imports
        .preview(cx, view.id, None, &CredentialGate::Allowed)
        .await
        .expect("preview");
    (view.id, preview)
}

async fn wait(engine: &JobEngine, id: JobId) -> tenko_jobs::Job {
    for _ in 0..600 {
        let job = engine.job(id).await.expect("job");
        if job.state.is_terminal() {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("job {id:?} did not finish");
}

async fn view(store: &MemStore) -> Arc<dyn ReadView> {
    store.read(ReadConsistency::Local).await.expect("view")
}

fn prefix_at(view: &dyn ReadView, cidr: &str) -> Option<Prefix> {
    let vrfs = view
        .scan_typed(
            &PREFIX_CIDRS,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("scan");
    let cidr: ipnet::IpNet = cidr.parse().expect("cidr");
    vrfs.into_iter()
        .find(|((_, net), _, _)| *net == cidr)
        .and_then(|(_, id, _)| view.get_typed(&PREFIXES, &id).expect("get"))
        .map(|(prefix, _)| prefix)
}

fn address_prefix(view: &dyn ReadView, ip: &str) -> PrefixId {
    let ip: std::net::IpAddr = ip.parse().expect("ip");
    let rows = view
        .scan_typed(
            &ADDRESS_IPS,
            tenko_store::KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("scan");
    let id = rows
        .into_iter()
        .find(|((_, address), _, _)| *address == ip)
        .map(|(_, id, _)| id)
        .expect("address");
    let (address, _): (Address, _) = view.get_typed(&ADDRESSES, &id).expect("get").expect("row");
    address.prefix
}

fn count_of(preview: &ImportPreview, kind: &str, action: ItemAction) -> usize {
    preview
        .summary
        .counts
        .iter()
        .filter(|c| c.kind == kind && c.action == action)
        .map(|c| c.count)
        .sum()
}

#[tokio::test]
async fn networks_inside_an_existing_network_make_it_a_supernet_once_acknowledged() {
    let env = env();
    let cx = person();
    let home = existing_network(&env, &cx).await;
    let (id, preview) = preview_of(&env, &cx).await;

    assert_eq!(preview.plan_error, None, "no overlap refusal");
    let steps: Vec<_> = preview
        .warnings
        .iter()
        .filter(|w| w.code == WARN_BECOMES_SUPERNET)
        .collect();
    assert_eq!(
        steps.len(),
        1,
        "one step for the network: {:?}",
        preview.warnings
    );
    let step = steps[0];
    assert!(step.requires_ack && !step.acknowledged);
    assert_eq!(step.object, Some(home.into()));
    assert_eq!(step.params["cidr"], "192.0.2.0/24");
    assert_eq!(step.params["networks"], "2");
    assert_eq!(count_of(&preview, "prefix", ItemAction::Create), 2);
    assert_eq!(count_of(&preview, "prefix", ItemAction::Update), 1);
    assert!(!preview.can_apply);
    assert_eq!(preview.blockers, [PLAN_UNACKNOWLEDGED]);

    let refused = env
        .imports
        .apply(&cx, id, &ApplyRequest::default(), &CredentialGate::Allowed)
        .await
        .expect_err("not acknowledged");
    assert_eq!(refused.code_str(), codes::PLAN_BLOCKED);

    let request = ApplyRequest {
        acknowledge: vec![WARN_BECOMES_SUPERNET.to_owned()],
    };
    let job = env
        .imports
        .apply(&cx, id, &request, &CredentialGate::Allowed)
        .await
        .expect("apply");
    let job = wait(&env.engine, job).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);

    let view = view(&env.store).await;
    let home = prefix_at(view.as_ref(), "192.0.2.0/24").expect("home");
    assert_eq!(home.role, PrefixRole::Supernet);
    assert_eq!(home.meta.description.as_deref(), Some("the home network"));
    let clients = prefix_at(view.as_ref(), "192.0.2.64/26").expect("clients");
    assert_eq!(clients.role, PrefixRole::Network);
    assert!(prefix_at(view.as_ref(), "192.0.2.0/26").is_some());
    assert_eq!(
        address_prefix(view.as_ref(), "192.0.2.70"),
        clients.id,
        "the address moves to the new network"
    );

    // Importing the same sheet again plans nothing.
    let (_, again) = preview_of(&env, &cx).await;
    assert!(again.warnings.is_empty(), "{:?}", again.warnings);
    assert_eq!(count_of(&again, "prefix", ItemAction::Unchanged), 2);
    assert!(again.can_apply);
}

#[tokio::test]
async fn a_network_with_ranges_stays_a_network() {
    let env = env();
    let cx = person();
    let home = existing_network(&env, &cx).await;
    let range = RangeInput {
        id: None,
        prefix: home,
        first: "192.0.2.200".parse().expect("ip"),
        last: "192.0.2.220".parse().expect("ip"),
        role: RangeRole::Reserved,
        status: None,
        lease_secs: None,
        tags: BTreeSet::default(),
        custom: BTreeMap::default(),
        description: None,
    };
    ipam(&env)
        .execute(
            &[IpamCommand::CreateRange(range)],
            &cx,
            &PlanOptions::default(),
        )
        .await
        .expect("range");
    let (_, preview) = preview_of(&env, &cx).await;
    assert_left_out(&preview);
}

#[tokio::test]
async fn a_network_a_dhcp_scope_serves_stays_a_network() {
    let env = env();
    let cx = person();
    let home = existing_network(&env, &cx).await;
    let stamp = serde_json::to_value(Stamp::new(cx.now, cx.principal.clone())).expect("stamp");
    let scope: Scope = serde_json::from_value(serde_json::json!({
        "prefix": home,
        "created": stamp,
        "updated": stamp,
    }))
    .expect("scope");
    let mut batch = WriteBatch::for_request(&cx);
    batch.put_typed(&SCOPES, &home, &scope).expect("row");
    env.store.propose(batch).await.expect("scope written");

    let (_, preview) = preview_of(&env, &cx).await;
    assert_left_out(&preview);
}

/// The networks inside stay out with a loss entry each, the plan has no step and no error,
/// and the import applies.
fn assert_left_out(preview: &ImportPreview) {
    assert_eq!(preview.plan_error, None);
    assert!(
        preview
            .warnings
            .iter()
            .all(|w| w.code != WARN_BECOMES_SUPERNET),
        "{:?}",
        preview.warnings
    );
    let entries: Vec<_> = preview
        .loss
        .iter()
        .flat_map(|sheet| sheet.entries.iter())
        .filter(|entry| entry.code == codes::PREFIX_IN_NETWORK)
        .collect();
    assert_eq!(entries.len(), 2, "{:?}", preview.loss);
    assert!(entries[0].detail.contains("192.0.2.0/24"));
    assert_eq!(count_of(preview, "prefix", ItemAction::Create), 0);
    assert_eq!(count_of(preview, "prefix", ItemAction::Kept), 2);
    assert!(preview.can_apply, "{:?}", preview.blockers);
}
