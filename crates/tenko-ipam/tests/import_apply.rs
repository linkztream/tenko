//! The import end to end on `MemStore` with the job engine and `MemVault`: preview, apply
//! as a job in chunks, credentials as operator secrets, idempotent re-apply, rollback after
//! a failure in a later chunk, the credential refusal (IAM-07), and the round trip of E1
//! (import the fixture, export CSV, import the export into a fresh instance: zero changes).

use std::{path::PathBuf, sync::Arc, time::Duration};

use tenko_core::{
    Action, AuthStrength, Authorizer, Denied, DenyReason, ImportId, JobId, ObjectKind, ObjectRef,
    Principal, RequestCtx, ScopeFilter, SessionId, UserId,
};
use tenko_ipam::{
    IpamConfig, IpamService,
    export::{ExportKind, export_csv},
    import::{
        ApplyRequest, CredentialGate, ImportConfig, ImportPreview, ImportService, Upload, codes,
        credential_gate,
        job::{CHUNK_CHANGES, host_credential},
        mapping::CredentialPolicy,
        reconcile::ItemAction,
    },
    jobs::register_steps,
    tables::{ADDRESS_IPS, HOST_NAMES, HOSTS, PREFIX_CIDRS},
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, RunnerHandle, StepError, testing::Scripted};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadView, ReadViewExt, Store};
use tenko_vault::{MemVault, Vault};

struct Env {
    store: Arc<MemStore>,
    engine: JobEngine,
    imports: Arc<ImportService>,
    vault: Option<Arc<MemVault>>,
    _runner: RunnerHandle,
}

fn staging() -> PathBuf {
    std::env::temp_dir().join(format!("tenko-import-test-{}", uuid::Uuid::now_v7()))
}

fn env_with(vault: bool, config: ImportConfig) -> Env {
    let store = Arc::new(MemStore::default());
    let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
    let mut engine = JobEngine::new(Arc::clone(&dyn_store), EngineConfig::default());
    register_steps(&mut engine);
    let ipam =
        IpamService::new(dyn_store, Arc::new(engine.clone()), IpamConfig::default()).expect("ipam");
    let vault = vault.then(|| Arc::new(MemVault::with_store(Arc::clone(&store))));
    let imports = ImportService::new(
        ipam,
        engine.clone(),
        vault.clone().map(|v| v as Arc<dyn Vault>),
        config,
    )
    .expect("imports");
    let runner = engine.start().expect("runner");
    Env {
        store,
        engine,
        imports,
        vault,
        _runner: runner,
    }
}

fn fresh() -> Env {
    env_with(
        true,
        ImportConfig {
            staging_dir: staging(),
            ..ImportConfig::default()
        },
    )
}

fn person() -> RequestCtx {
    RequestCtx::new(Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Passkey,
    })
}

fn fixture(name: &str) -> Upload {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    Upload {
        name: name.rsplit('/').next().unwrap_or(name).to_owned(),
        bytes: std::fs::read(path).expect("fixture"),
    }
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

fn count<K: tenko_core::codec::KeyCodec, V: serde::Serialize + serde::de::DeserializeOwned>(
    view: &dyn ReadView,
    table: &tenko_core::table::TableDef<K, V>,
) -> usize {
    view.scan(table.name(), KeyRange::all(), usize::MAX, false)
        .expect("scan")
        .len()
}

/// Uploads, previews and applies; returns the import, its preview and the finished job.
async fn import(env: &Env, cx: &RequestCtx, uploads: Vec<Upload>) -> (ImportId, ImportPreview) {
    let view = env.imports.upload(cx, uploads).await.expect("upload");
    let preview = env
        .imports
        .preview(cx, view.id, None, &CredentialGate::Allowed)
        .await
        .expect("preview");
    (view.id, preview)
}

async fn apply(env: &Env, cx: &RequestCtx, id: ImportId) -> tenko_jobs::Job {
    let job = env
        .imports
        .apply(cx, id, &ApplyRequest::default(), &CredentialGate::Allowed)
        .await
        .expect("apply");
    wait(&env.engine, job).await
}

fn count_of(preview: &ImportPreview, kind: &str, action: ItemAction) -> usize {
    preview
        .summary
        .counts
        .iter()
        .find(|c| c.kind == kind && c.action == action)
        .map_or(0, |c| c.count)
}

async fn export_all(store: &MemStore) -> Vec<Upload> {
    let view = view(store).await;
    ExportKind::ALL
        .iter()
        .map(|kind| Upload {
            name: kind.file_name().to_owned(),
            bytes: export_csv(Arc::clone(&view), *kind).expect("export"),
        })
        .collect()
}

#[tokio::test]
async fn the_fixture_applies_as_a_job_with_credentials_in_the_vault() {
    let env = fresh();
    let cx = person();
    let (id, preview) = import(&env, &cx, vec![fixture("ip-plan.xlsx")]).await;
    assert!(
        preview.can_apply,
        "{:?} {:?}",
        preview.blockers, preview.plan_error
    );
    assert_eq!(count_of(&preview, "prefix", ItemAction::Create), 10);
    assert_eq!(count_of(&preview, "host", ItemAction::Create), 40);
    assert_eq!(count_of(&preview, "address", ItemAction::Create), 55);
    assert_eq!(count_of(&preview, "credential", ItemAction::Create), 9);
    assert_eq!(preview.credentials.hosts, 9);
    assert!(preview.credentials.allowed);
    assert!(preview.credentials.statement.contains("operator secret"));
    assert_eq!(preview.summary.rows.free, 234 + 121);
    assert_eq!(preview.proposals.len(), 2);
    let codes_seen: Vec<&str> = preview
        .loss
        .iter()
        .flat_map(|s| s.entries.iter().map(|e| e.code.as_str()))
        .collect();
    for code in [
        codes::ADDRESS_UNPARSABLE,
        codes::COLUMN_UNMAPPED,
        codes::CREDENTIAL_SUSPICIOUS,
        codes::ADDRESS_IS_NETWORK,
        codes::CREDENTIAL_NUMERIC,
        codes::PREFIX_UNLISTED,
        codes::SHEET_EMPTY,
    ] {
        assert!(
            codes_seen.contains(&code),
            "{code} missing from the preview"
        );
    }

    let job = apply(&env, &cx, id).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    assert_eq!(job.spec.kind.as_str(), "import.apply");

    let view = view(&env.store).await;
    assert_eq!(count(view.as_ref(), &PREFIX_CIDRS), 10);
    assert_eq!(count(view.as_ref(), &HOST_NAMES), 40);
    assert_eq!(count(view.as_ref(), &ADDRESS_IPS), 55);
    assert_eq!(
        count(view.as_ref(), &CHUNK_CHANGES),
        0,
        "the final step clears them"
    );
    let vault = env.vault.as_ref().expect("vault");
    assert!(vault.has_operator_secrets().await.expect("vault"));
    // The gateway's credential is one operator secret attached to the host.
    let gateway = host_id(view.as_ref(), "gateway");
    let reference = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential");
    let value = vault
        .get_system(&cx, reference.secret)
        .await
        .expect("secret");
    assert_eq!(
        std::str::from_utf8(value.expose()).expect("utf8"),
        r#"{"login":"admin","password":"example-gw-pass"}"#
    );
    let meta = vault
        .meta(reference.secret)
        .await
        .expect("meta")
        .expect("meta");
    assert_eq!(meta.owner, Some(ObjectRef::from(gateway)));
    assert_eq!(meta.class, tenko_core::secret::SecretClass::Operator);
    // No IPAM object carries a credential.
    let export = export_all(&env.store).await;
    for file in &export {
        let text = String::from_utf8_lossy(&file.bytes);
        assert!(!text.contains("example-gw-pass") && !text.contains("example-idrac-1"));
    }
    let state = env.imports.get(&cx, id).await.expect("get").state;
    assert_eq!(state, tenko_ipam::import::ImportState::Applied);

    assert_audit_counts_secrets(view.as_ref(), 9);
}

/// The audit trail counts the secrets and never carries a credential.
fn assert_audit_counts_secrets(view: &dyn ReadView, secrets: usize) {
    let records = view
        .scan_typed(
            &tenko_store::tables::AUDIT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("audit");
    let apply_record = records
        .iter()
        .map(|(_, record, _)| record)
        .find(|record| record.draft.action.as_str() == "import.apply")
        .expect("import.apply audit record");
    assert_eq!(
        apply_record
            .draft
            .details
            .context
            .get("secrets")
            .map(String::as_str),
        Some(secrets.to_string().as_str())
    );
    let created = records
        .iter()
        .filter(|(_, record, _)| record.draft.action.as_str() == "vault.secret.create")
        .count();
    assert_eq!(created, secrets);
    let printed = format!("{records:?}");
    for secret in [
        "example-gw-pass",
        "example-pve-pass",
        "example-idrac-1",
        "Acme SG-2448",
    ] {
        assert!(
            !printed.contains(secret),
            "the audit trail must not carry {secret}"
        );
    }
}

fn host_id(view: &dyn ReadView, name: &str) -> tenko_core::HostId {
    view.scan_typed(&HOSTS, KeyRange::all(), usize::MAX, false)
        .expect("hosts")
        .into_iter()
        .find(|(_, host, _)| host.name.as_str() == name)
        .map(|(id, _, _)| id)
        .expect("host")
}

#[tokio::test]
async fn applying_again_changes_nothing() {
    let env = fresh();
    let cx = person();
    let (id, _) = import(&env, &cx, vec![fixture("ip-plan.xlsx")]).await;
    assert_eq!(apply(&env, &cx, id).await.state, JobState::Succeeded);
    let before = export_all(&env.store).await;
    let preview = env
        .imports
        .preview(&cx, id, None, &CredentialGate::Allowed)
        .await
        .expect("preview");
    assert_eq!(
        preview.summary.lines,
        ["no changes"],
        "{:?}",
        preview.summary.counts
    );
    assert_eq!(preview.credentials.unchanged, 9);
    assert_eq!(preview.summary.plan.as_ref().map(|p| p.mutations), Some(0));
    let job = apply(&env, &cx, id).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    assert_eq!(export_all(&env.store).await, before);
    let view = view(&env.store).await;
    assert_eq!(count(view.as_ref(), &HOST_NAMES), 40);
}

#[tokio::test]
async fn a_failure_in_a_later_chunk_rolls_the_import_back() {
    let env = env_with(
        true,
        ImportConfig {
            staging_dir: staging(),
            chunk_bytes: 64 * 1024,
            ..ImportConfig::default()
        },
    );
    let failing = Scripted::new("import.test_fail").outcomes(vec![Err(StepError::Timeout)]);
    env.engine.clone().register(Arc::new(failing.clone()));
    let cx = person();
    let (id, preview) = import(&env, &cx, vec![fixture("ip-plan.xlsx")]).await;
    assert!(
        preview.summary.chunks > 2,
        "{} chunks",
        preview.summary.chunks
    );
    let mut spec = env
        .imports
        .prepare_apply(&cx, id, &ApplyRequest::default(), &CredentialGate::Allowed)
        .await
        .expect("prepare");
    let finish = spec.steps.pop().expect("finish step");
    spec.steps.push(tenko_jobs::testing::step(&failing.kind()));
    spec.steps.push(finish);
    let job = env.engine.submit(spec, &cx).await.expect("submit");
    let job = wait(&env.engine, job).await;
    assert_eq!(job.state, JobState::RolledBack, "{:?}", job.error);
    assert!(failing.executions() >= 1);

    let view = view(&env.store).await;
    assert_eq!(
        count(view.as_ref(), &PREFIX_CIDRS),
        0,
        "no live prefix stays"
    );
    assert_eq!(count(view.as_ref(), &HOST_NAMES), 0, "no live host stays");
    assert_eq!(
        count(view.as_ref(), &ADDRESS_IPS),
        0,
        "no live address stays"
    );
    assert_eq!(
        count(view.as_ref(), &CHUNK_CHANGES),
        0,
        "compensation clears them"
    );
    let vault = env.vault.as_ref().expect("vault");
    assert!(
        !vault.has_operator_secrets().await.expect("vault"),
        "the stored secrets are deleted again"
    );
    // After the rollback the import applies cleanly.
    let job = apply(&env, &cx, id).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    assert_eq!(count(view.as_ref(), &HOST_NAMES), 40);
}

/// Denies revealing secrets below a password-strength session, like the IAM-07 rule once
/// the vault holds operator secrets.
struct StepUp;

impl Authorizer for StepUp {
    fn check(
        &self,
        principal: &Principal,
        action: Action,
        object: &ObjectRef,
    ) -> Result<(), Denied> {
        match (principal, action) {
            (Principal::User { strength, .. }, Action::Reveal)
                if *strength < AuthStrength::Password =>
            {
                Err(Denied {
                    action,
                    object: *object,
                    reason: DenyReason::StepUpRequired {
                        required: AuthStrength::Password,
                    },
                })
            }
            _ => Ok(()),
        }
    }

    fn scope(&self, _: &Principal, _: Action, _: ObjectKind) -> ScopeFilter {
        ScopeFilter::All
    }
}

#[tokio::test]
async fn credential_columns_need_the_vault_and_a_strong_enough_account() {
    // No vault on the server.
    let env = env_with(
        false,
        ImportConfig {
            staging_dir: staging(),
            ..ImportConfig::default()
        },
    );
    let cx = person();
    let (id, preview) = import(&env, &cx, vec![fixture("ip-plan.xlsx")]).await;
    assert!(!preview.can_apply);
    assert!(
        preview
            .blockers
            .contains(&codes::CREDENTIALS_VAULT_REQUIRED.to_owned())
    );
    assert!(!preview.credentials.allowed);
    let error = env
        .imports
        .apply(&cx, id, &ApplyRequest::default(), &CredentialGate::Allowed)
        .await
        .expect_err("refused");
    assert!(error.is(codes::CREDENTIALS_VAULT_REQUIRED));
    assert_eq!(error.coded().status, 403);

    // A PIN session below the IAM-07 threshold.
    let env = fresh();
    let pin = Principal::User {
        id: UserId::generate(),
        session: SessionId::generate(),
        strength: AuthStrength::Pin,
    };
    let gate = credential_gate(Some(&StepUp), &pin);
    assert!(matches!(
        gate,
        CredentialGate::Denied {
            reason: "step_up_required",
            ..
        }
    ));
    let cx = RequestCtx::new(pin);
    let (id, _) = import(&env, &cx, vec![fixture("ip-plan.xlsx")]).await;
    let error = env
        .imports
        .apply(&cx, id, &ApplyRequest::default(), &gate)
        .await
        .expect_err("refused");
    assert!(error.is(codes::CREDENTIALS_VAULT_REQUIRED));
    assert_eq!(
        error.coded().params.get("required").map(String::as_str),
        Some("password")
    );

    // Leaving the credentials out lets the same account import the rest.
    let mut mapping = env.imports.get(&cx, id).await.expect("get").mapping;
    mapping.options.credentials = CredentialPolicy::Skip;
    env.imports
        .set_mapping(&cx, id, mapping)
        .await
        .expect("mapping");
    let preview = env
        .imports
        .preview(&cx, id, None, &gate)
        .await
        .expect("preview");
    assert!(preview.can_apply, "{:?}", preview.blockers);
    let skipped = preview
        .loss
        .iter()
        .flat_map(|s| &s.entries)
        .filter(|e| e.code == codes::CREDENTIAL_SKIPPED)
        .count();
    assert!(skipped >= 1);
    let job = env
        .imports
        .apply(&cx, id, &ApplyRequest::default(), &gate)
        .await
        .expect("apply");
    assert_eq!(wait(&env.engine, job).await.state, JobState::Succeeded);
    let vault = env.vault.as_ref().expect("vault");
    assert!(!vault.has_operator_secrets().await.expect("vault"));
}

/// E1: the export of an import, imported again, changes nothing; imported into a fresh
/// instance, it reproduces the same export.
#[tokio::test]
async fn the_csv_export_round_trips_with_zero_changes() {
    let first = fresh();
    let cx = person();
    let (id, _) = import(&first, &cx, vec![fixture("ip-plan.xlsx")]).await;
    assert_eq!(apply(&first, &cx, id).await.state, JobState::Succeeded);
    let exported = export_all(&first.store).await;

    // The export previews zero changes on the instance it came from.
    let (_, preview) = import(&first, &cx, exported.clone()).await;
    assert_eq!(
        preview.summary.lines,
        ["no changes"],
        "{:?}",
        preview.summary.counts
    );
    assert!(
        preview.loss.iter().all(|s| s.entries.is_empty()),
        "{:?}",
        preview.loss
    );
    assert_eq!(preview.summary.rows.free, 0);

    // Imported into a fresh instance, it reproduces the export exactly.
    let second = fresh();
    let (id, preview) = import(&second, &cx, exported.clone()).await;
    assert!(
        preview.can_apply,
        "{:?} {:?}",
        preview.blockers, preview.plan_error
    );
    assert_eq!(apply(&second, &cx, id).await.state, JobState::Succeeded);
    assert_eq!(export_all(&second.store).await, exported);
    let (_, preview) = import(&second, &cx, exported).await;
    assert_eq!(preview.summary.lines, ["no changes"]);
    assert_eq!(preview.summary.plan.as_ref().map(|p| p.mutations), Some(0));
}

#[tokio::test]
async fn sessions_belong_to_their_uploader_and_can_be_discarded() {
    let env = fresh();
    let cx = person();
    let (id, _) = import(&env, &cx, vec![fixture("ip-plan.ods")]).await;
    let stranger = person();
    let error = env.imports.get(&stranger, id).await.expect_err("hidden");
    assert!(error.is(codes::NOT_FOUND));
    env.imports.delete(&cx, id).await.expect("delete");
    assert!(
        env.imports
            .get(&cx, id)
            .await
            .expect_err("gone")
            .is(codes::NOT_FOUND)
    );
}

fn csv(name: &str, text: &str) -> Upload {
    Upload {
        name: name.to_owned(),
        bytes: text.as_bytes().to_vec(),
    }
}

/// A changed password replaces the host's secret; the old secret is deleted once the job
/// can no longer roll back.
#[tokio::test]
async fn a_changed_credential_replaces_the_secret() {
    let env = fresh();
    let cx = person();
    let first = "IP,Beteckning,Login,Pass\n192.0.2.1,gateway,admin,example-one\n";
    let (id, preview) = import(&env, &cx, vec![csv("lab.csv", first)]).await;
    assert_eq!(preview.proposals.len(), 1, "192.0.2.0/24 is proposed");
    assert_eq!(apply(&env, &cx, id).await.state, JobState::Succeeded);
    let view = view(&env.store).await;
    let gateway = host_id(view.as_ref(), "gateway");
    let old = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential");

    let second = "IP,Beteckning,Login,Pass\n192.0.2.1,gateway,admin,example-two\n";
    let (id, preview) = import(&env, &cx, vec![csv("lab.csv", second)]).await;
    assert_eq!(preview.credentials.changed, 1);
    assert_eq!(preview.summary.lines, ["1 credential updated"]);
    let job = apply(&env, &cx, id).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);

    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let new = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential");
    assert_ne!(new.secret, old.secret);
    let vault = env.vault.as_ref().expect("vault");
    let value = vault.get_system(&cx, new.secret).await.expect("secret");
    assert!(
        std::str::from_utf8(value.expose())
            .expect("utf8")
            .contains("example-two")
    );
    assert_eq!(
        vault.meta(old.secret).await.expect("meta"),
        None,
        "the old secret is gone"
    );
}

/// An upload expires after its time to live; the purge removes the record and the staged
/// files.
#[tokio::test]
async fn uploads_expire() {
    let dir = staging();
    let env = env_with(
        true,
        ImportConfig {
            staging_dir: dir.clone(),
            ttl: Duration::ZERO,
            ..ImportConfig::default()
        },
    );
    let cx = person();
    let view = env
        .imports
        .upload(&cx, vec![fixture("ip-plan.ods")])
        .await
        .expect("upload");
    assert_eq!(std::fs::read_dir(&dir).expect("dir").count(), 1);
    tokio::time::sleep(Duration::from_millis(5)).await;
    let later = RequestCtx {
        now: tenko_core::Timestamp::now(),
        ..cx.clone()
    };
    let error = env.imports.get(&later, view.id).await.expect_err("expired");
    assert!(error.is(codes::EXPIRED));
    assert_eq!(error.coded().status, 410);
    assert_eq!(std::fs::read_dir(&dir).expect("dir").count(), 0);

    let view = env
        .imports
        .upload(&cx, vec![fixture("ip-plan.ods")])
        .await
        .expect("upload");
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(env.imports.purge_expired().await.expect("purge"), 1);
    assert_eq!(std::fs::read_dir(&dir).expect("dir").count(), 0);
    assert!(env.imports.get(&cx, view.id).await.is_err());
}
