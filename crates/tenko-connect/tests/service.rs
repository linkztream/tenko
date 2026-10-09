//! The connector service over an in-memory store and vault, with the sample plugin as a
//! bundled plugin: instance edits with validation and audit, supervision, runs on request
//! and on schedule, secret injection with its audit record, and a crashing plugin that
//! never affects the service.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use tenko_connect::{
    Health,
    host::{
        ConnectorHost, HostConfig,
        backoff::BackoffPolicy,
        launch::LaunchSpec,
        normalize::{ObservationBatch, ObservationSink},
        registry::{Bundled, PluginRegistry},
        service::{ConnectorPatch, NewConnector, RunOutcome, RunTrigger, tables},
        supervisor::{ProcessState, SupervisorConfig},
    },
    sample::{self, CREDENTIAL_TAG},
};
use tenko_core::{
    AuthStrength, CodedError, ConnectorId, JobId, Principal, RequestCtx, SessionId, UserId,
    audit::AuditRecord, observe::Observed, principal::SystemComponent, secret::SecretRef,
};
use tenko_jobs::{EngineConfig, JobEngine, JobState};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store};
use tenko_vault::{MemVault, SecretBytes, SecretPurpose, SecretSpec, Vault};
use tokio::sync::watch;

#[derive(Default)]
struct RecordingSink {
    batches: Mutex<Vec<ObservationBatch>>,
}

#[async_trait::async_trait]
impl ObservationSink for RecordingSink {
    async fn ingest(&self, batch: ObservationBatch) -> Result<(), CodedError> {
        self.batches.lock().expect("lock").push(batch);
        Ok(())
    }
}

struct Fixture {
    store: Arc<MemStore>,
    vault: Arc<MemVault>,
    host: Arc<ConnectorHost>,
    engine: JobEngine,
    sink: Arc<RecordingSink>,
    _runner: tenko_jobs::RunnerHandle,
}

fn sample_registry(mode: &str) -> PluginRegistry {
    let manifest = sample::manifest();
    PluginRegistry::new(
        vec![Bundled {
            manifest: manifest.clone(),
            launch: LaunchSpec {
                expected: Some(manifest),
                program: PathBuf::from(env!("CARGO_BIN_EXE_tenko-plugin-sample")),
                args: vec![OsString::from("--mode"), OsString::from(mode)],
                cwd: None,
                env: Vec::new(),
            },
        }],
        None,
    )
}

fn config(schedule: bool) -> HostConfig {
    HostConfig {
        supervisor: SupervisorConfig {
            ping_interval: Duration::from_millis(200),
            ping_timeout: Duration::from_millis(500),
            backoff: BackoffPolicy {
                initial: Duration::from_millis(100),
                max: Duration::from_millis(500),
                factor: 2,
                jitter_permille: 0,
                reset_after: Duration::from_secs(60),
            },
            ..SupervisorConfig::default()
        },
        first_run_delay: Duration::from_millis(200),
        schedule,
        ..HostConfig::default()
    }
}

fn fixture(mode: &str, schedule: bool) -> Fixture {
    let store = Arc::new(MemStore::default());
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
    let sink = Arc::new(RecordingSink::default());
    let host = ConnectorHost::new(
        Arc::clone(&dyn_store),
        Some(Arc::clone(&vault) as Arc<dyn Vault>),
        sample_registry(mode),
        config(schedule),
        Arc::clone(&sink) as Arc<dyn ObservationSink>,
    );
    let engine = JobEngine::new(dyn_store, EngineConfig::default());
    host.register_steps(&engine);
    let runner = engine.start().expect("runner");
    Fixture {
        store,
        vault,
        host,
        engine,
        sink,
        _runner: runner,
    }
}

fn admin() -> RequestCtx {
    RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Passkey,
    })
}

fn new_sample(name: &str) -> NewConnector {
    NewConnector {
        plugin: "sample".to_owned(),
        name: name.to_owned(),
        settings: serde_json::json!({ "hosts": 6, "page_size": 4, "site": "lab-b" }),
        secrets: BTreeMap::new(),
        poll_interval_secs: None,
        call_timeout_secs: Some(10),
        writes_enabled: false,
        enabled: true,
    }
}

async fn operator_secret(vault: &MemVault, value: &str) -> SecretRef {
    vault
        .put_operator(
            &admin(),
            SecretSpec::new(SecretPurpose::from_static("connect.api_key")).labelled("sample key"),
            SecretBytes::from(value.to_owned()),
        )
        .await
        .expect("secret")
}

async fn audit(store: &MemStore) -> Vec<AuditRecord> {
    let view = store.read(ReadConsistency::Local).await.expect("view");
    view.scan_typed(
        &tenko_store::tables::AUDIT,
        KeyRange::all(),
        usize::MAX,
        false,
    )
    .expect("audit")
    .into_iter()
    .map(|(_, record, _)| record)
    .collect()
}

async fn wait_running(host: &ConnectorHost, id: ConnectorId) {
    for _ in 0..100 {
        let view = host.get(id, None).await.expect("view");
        if view.health.process.is_running() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("connector {id} did not start");
}

async fn wait_job(engine: &JobEngine, id: JobId) -> tenko_jobs::Job {
    for _ in 0..200 {
        let job = engine.job(id).await.expect("job");
        if job.state.is_terminal() {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} did not finish");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario from creation to deletion"
)]
async fn instances_are_created_validated_run_and_deleted() {
    let fx = fixture("normal", false);
    let cx = admin();
    let key = operator_secret(&fx.vault, "value-of-the-sample-key").await;
    let mut new = new_sample("Lab inventory");
    new.secrets.insert("api_key".to_owned(), key);
    let view = fx.host.create(&cx, new).await.expect("create");
    let id = view.instance.id;
    assert!(view.instance.enabled);
    assert_eq!(
        view.instance.settings["endpoint"],
        "https://inventory.example.net"
    );
    assert_eq!(view.capabilities, [tenko_connect::Capability::Inventory]);
    wait_running(&fx.host, id).await;

    // A duplicate name, ignoring case, is refused.
    let duplicate = fx.host.create(&cx, new_sample("lab INVENTORY")).await;
    assert_eq!(
        duplicate.expect_err("duplicate").code(),
        "connect.instance.name_taken"
    );

    // A run on request is a job; it reads every page and hands the hosts on.
    let job = fx.host.run_now(&cx, id).await.expect("run");
    let job = wait_job(&fx.engine, job).await;
    assert_eq!(job.state, JobState::Succeeded, "{job:?}");
    let view = fx.host.get(id, None).await.expect("view");
    let run = view.last_run.expect("last run");
    assert_eq!(run.outcome, RunOutcome::Succeeded, "{run:?}");
    assert_eq!(run.trigger, RunTrigger::Manual);
    assert_eq!(run.job, Some(job.id));
    assert_eq!(run.observations, 6);
    assert_eq!(run.pages, 2);
    {
        let batches = fx.sink.batches.lock().expect("lock");
        let batch = batches.last().expect("a batch");
        assert!(batch.complete);
        assert_eq!(batch.connector, id);
        let Observed::Host(host) = &batch.observations[0].subject else {
            panic!("a host observation");
        };
        assert!(host.tags.contains(&CREDENTIAL_TAG.to_owned()), "{host:?}");
        assert!(host.tags.contains(&"lab-b".to_owned()));
    }

    // The injection was audited with the purpose and the reference, never the value.
    let records = audit(&fx.store).await;
    let injected: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| record.draft.action.as_str() == "connect.secret.inject")
        .collect();
    assert_ne!(injected.len(), 0, "no injection was audited");
    let record = injected[0];
    assert_eq!(
        record.principal,
        Principal::System {
            component: SystemComponent::Connector,
            on_behalf_of: cx.principal.user(),
        }
    );
    assert_eq!(record.draft.details.context["purposes"], "api_key");
    assert_eq!(record.draft.details.context["plugin"], "sample");
    assert!(
        record
            .draft
            .objects
            .contains(&tenko_core::ObjectRef::from(key.secret))
    );
    let printed = serde_json::to_string(&records).expect("json");
    assert!(!printed.contains("value-of-the-sample-key"));
    assert!(
        records
            .iter()
            .any(|record| record.draft.action.as_str() == "connect.instance.create")
    );

    // A remote check is kept as the health of the instance.
    let report = fx.host.check(id, None).await.expect("check");
    assert_eq!(report.health, Health::Healthy);
    let view = fx.host.get(id, None).await.expect("view");
    assert_eq!(view.health.remote.map(|r| r.health), Some(Health::Healthy));

    // Changing settings is audited field by field and does not restart the plugin.
    let before = fx.host.get(id, None).await.expect("view").health.process;
    let patch = ConnectorPatch {
        settings: Some(serde_json::json!({ "hosts": 3 })),
        ..ConnectorPatch::default()
    };
    let changed = fx.host.update(&cx, id, patch, None).await.expect("update");
    assert_eq!(changed.instance.settings["hosts"], 3);
    assert_eq!(changed.instance.settings["site"], "lab");
    assert_eq!(changed.health.process.state, before.state);
    let records = audit(&fx.store).await;
    let update = records
        .iter()
        .rev()
        .find(|record| record.draft.action.as_str() == "connect.instance.update")
        .expect("update audited");
    assert!(
        update
            .draft
            .details
            .changes
            .iter()
            .any(|change| change.field == "settings.hosts" && change.new.as_deref() == Some("3"))
    );

    // Disabling stops the plugin; a run is then refused.
    let disabled = fx.host.set_enabled(&cx, id, false).await.expect("disable");
    assert_eq!(disabled.health.process.state, ProcessState::Stopped);
    assert_eq!(
        fx.host.run_now(&cx, id).await.expect_err("disabled").code(),
        "connect.instance.disabled"
    );
    let enabled = fx.host.set_enabled(&cx, id, true).await.expect("enable");
    assert!(enabled.instance.enabled);
    wait_running(&fx.host, id).await;

    fx.host.delete(&cx, id).await.expect("delete");
    assert_eq!(
        fx.host.get(id, None).await.expect_err("gone").code(),
        "connect.instance.not_found"
    );
    // The name is free again.
    let again = fx
        .host
        .create(&cx, new_sample("Lab Inventory"))
        .await
        .expect("create");
    fx.host
        .delete(&cx, again.instance.id)
        .await
        .expect("delete");
    fx.host.shutdown().await;
}

#[tokio::test]
async fn invalid_requests_are_refused_with_precise_codes() {
    let fx = fixture("normal", false);
    let cx = admin();
    let code = |result: Result<_, tenko_connect::host::HostError>| {
        result
            .map(|_: tenko_connect::host::service::ConnectorView| ())
            .expect_err("refused")
            .code()
            .to_owned()
    };

    let mut unknown = new_sample("a");
    "nope".clone_into(&mut unknown.plugin);
    assert_eq!(
        code(fx.host.create(&cx, unknown).await),
        "connect.plugin.unknown"
    );

    let mut bad_settings = new_sample("b");
    bad_settings.settings = serde_json::json!({ "hosts": 500, "colour": "red" });
    let refused = fx
        .host
        .create(&cx, bad_settings)
        .await
        .expect_err("settings");
    assert_eq!(refused.code(), "connect.settings.invalid");
    let coded = refused.into_coded();
    assert_eq!(coded.status, 422);
    let fields: Vec<&str> = coded.errors.iter().map(|e| e.field.as_str()).collect();
    assert!(fields.contains(&"settings.hosts"), "{fields:?}");
    assert!(fields.contains(&"settings.colour"), "{fields:?}");

    let mut undeclared = new_sample("c");
    undeclared
        .secrets
        .insert("password".to_owned(), operator_secret(&fx.vault, "x").await);
    assert_eq!(
        code(fx.host.create(&cx, undeclared).await),
        "connect.secret.undeclared"
    );

    let system = fx
        .vault
        .put_system(
            &admin(),
            SecretSpec::new(SecretPurpose::from_static("auth.totp")),
            SecretBytes::from("system-only".to_owned()),
        )
        .await
        .expect("system secret");
    let mut system_secret = new_sample("d");
    system_secret.secrets.insert("api_key".to_owned(), system);
    assert_eq!(
        code(fx.host.create(&cx, system_secret).await),
        "connect.secret.not_operator"
    );

    let mut missing = new_sample("e");
    missing.secrets.insert(
        "api_key".to_owned(),
        SecretRef {
            secret: tenko_core::SecretId::generate(),
        },
    );
    assert_eq!(
        code(fx.host.create(&cx, missing).await),
        "connect.secret.not_found"
    );

    let mut fast = new_sample("f");
    fast.poll_interval_secs = Some(5);
    assert_eq!(
        code(fx.host.create(&cx, fast).await),
        "connect.instance.poll_interval"
    );

    assert_eq!(
        code(fx.host.create(&cx, new_sample("  ")).await),
        "connect.instance.name"
    );

    let view = fx.host.create(&cx, new_sample("g")).await.expect("create");
    let stale = fx
        .host
        .update(
            &cx,
            view.instance.id,
            ConnectorPatch {
                name: Some("h".to_owned()),
                ..ConnectorPatch::default()
            },
            Some(tenko_core::Revision(1)),
        )
        .await;
    assert_eq!(code(stale), "connect.instance.conflict");
    fx.host.shutdown().await;
}

#[tokio::test]
async fn the_schedule_reads_running_instances() {
    let fx = fixture("normal", true);
    let (stop_tx, stop) = watch::channel(false);
    let task = fx.host.start(stop);
    let view = fx
        .host
        .create(&admin(), new_sample("Scheduled"))
        .await
        .expect("create");
    let id = view.instance.id;
    let mut run = None;
    for _ in 0..100 {
        run = fx.host.get(id, None).await.expect("view").last_run;
        if run.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let run = run.expect("a scheduled run");
    assert_eq!(run.trigger, RunTrigger::Schedule);
    assert_eq!(run.outcome, RunOutcome::Succeeded);
    assert_eq!(run.observations, 6);
    // The remote check ran too.
    let mut checked = false;
    for _ in 0..50 {
        if fx
            .host
            .get(id, None)
            .await
            .expect("view")
            .health
            .remote
            .is_some()
        {
            checked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(checked);
    stop_tx.send(true).expect("stop");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("stops in time")
        .expect("task");
    let view = fx.host.get(id, None).await.expect("view");
    assert_eq!(view.health.process.state, ProcessState::Stopped);
}

#[tokio::test]
async fn a_crashing_plugin_never_affects_the_service() {
    let fx = fixture("crash-after-start", false);
    let cx = admin();
    let view = fx
        .host
        .create(&cx, new_sample("Crashing"))
        .await
        .expect("create");
    let id = view.instance.id;
    let mut restarts = 0;
    for _ in 0..100 {
        let started = std::time::Instant::now();
        let view = fx.host.get(id, None).await.expect("the service answers");
        let listed = fx.host.list(None).await.expect("the service answers");
        assert_eq!(listed.len(), 1);
        assert!(started.elapsed() < Duration::from_secs(1));
        restarts = view.health.process.restarts;
        if restarts >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(restarts >= 2, "the plugin was restarted {restarts} times");
    let view = fx.host.get(id, None).await.expect("view");
    assert!(view.health.process.last_error.is_some());
    // A run while the plugin is down is a failed run, not a broken service.
    let run = fx
        .host
        .run(id, RunTrigger::Manual, None, None)
        .await
        .expect("run");
    let _ = run.outcome;
    fx.host.shutdown().await;
}

#[tokio::test]
async fn edits_are_inline_jobs() {
    let fx = fixture("normal", false);
    let cx = admin();
    let view = fx
        .host
        .create(&cx, new_sample("Job"))
        .await
        .expect("create");
    let query = tenko_jobs::JobQuery {
        states: Vec::new(),
        kinds: vec![tenko_jobs::JobKind::from_static("connect.edit")],
        target: Some(tenko_core::ObjectRef::from(view.instance.id)),
        limit: 10,
        cursor: None,
        at_least: None,
    };
    let page = fx.engine.list(&query).await.expect("jobs");
    assert_eq!(page.items.len(), 1);
    let stored = fx
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("view")
        .get_typed(&tables::INSTANCES, &view.instance.id)
        .expect("read")
        .expect("stored");
    assert_eq!(stored.1, view.revision);
    fx.host.shutdown().await;
}
