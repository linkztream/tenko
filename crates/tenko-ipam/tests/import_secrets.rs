//! Imported credentials as operator secrets of the shared model (WP2.1): the import writes a
//! record and an `admin` binding with each credential, a changed credential moves the
//! binding to the new secret, and a replaced credential that a person bound to another host
//! is kept.

use std::{sync::Arc, time::Duration};

use tenko_core::{
    AuthStrength, ConnectorId, HostId, ImportId, JobId, Principal, RequestCtx, SessionId, UserId,
    secret::SecretRef,
};
use tenko_ipam::{
    IpamConfig, IpamService,
    import::{
        ApplyRequest, CredentialGate, ImportConfig, ImportService, Upload, codes,
        connectors::{self, ConnectorSecrets},
        job::host_credential,
    },
    jobs::register_steps,
    tables::HOSTS,
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, RunnerHandle};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};
use tenko_vault::{
    MemVault, Vault,
    operator::{
        BindingRequest, CredentialRole, OperatorSecrets, RevealRequest, SecretOrigin, ValueFormat,
    },
};

struct Env {
    store: Arc<MemStore>,
    engine: JobEngine,
    imports: Arc<ImportService>,
    vault: Arc<MemVault>,
    secrets: OperatorSecrets,
    _runner: RunnerHandle,
}

fn env() -> Env {
    let store = Arc::new(MemStore::default());
    let dyn_store: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
    let mut engine = JobEngine::new(Arc::clone(&dyn_store), EngineConfig::default());
    register_steps(&mut engine);
    let ipam = IpamService::new(
        Arc::clone(&dyn_store),
        Arc::new(engine.clone()),
        IpamConfig::default(),
    )
    .expect("ipam");
    let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
    let imports = ImportService::new(
        ipam,
        engine.clone(),
        Some(Arc::clone(&vault) as Arc<dyn Vault>),
        ImportConfig {
            staging_dir: std::env::temp_dir()
                .join(format!("tenko-import-secrets-{}", uuid::Uuid::now_v7())),
            ..ImportConfig::default()
        },
    )
    .expect("imports");
    let secrets = OperatorSecrets::new(dyn_store, Arc::clone(&vault) as Arc<dyn Vault>);
    let runner = engine.start().expect("runner");
    Env {
        store,
        engine,
        imports,
        vault,
        secrets,
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

fn csv(text: &str) -> Upload {
    Upload {
        name: "lab.csv".to_owned(),
        bytes: text.as_bytes().to_vec(),
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

async fn import(env: &Env, cx: &RequestCtx, text: &str) -> ImportId {
    let view = env
        .imports
        .upload(cx, vec![csv(text)])
        .await
        .expect("upload");
    env.imports
        .preview(cx, view.id, None, &CredentialGate::Allowed)
        .await
        .expect("preview");
    let job = env
        .imports
        .apply(
            cx,
            view.id,
            &ApplyRequest::default(),
            &CredentialGate::Allowed,
        )
        .await
        .expect("apply");
    let job = wait(&env.engine, job).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    view.id
}

async fn view(store: &MemStore) -> Arc<dyn ReadView> {
    store.read(ReadConsistency::Local).await.expect("view")
}

fn host_id(view: &dyn ReadView, name: &str) -> HostId {
    view.scan_typed(&HOSTS, KeyRange::all(), usize::MAX, false)
        .expect("hosts")
        .into_iter()
        .find(|(_, host, _)| host.name.as_str() == name)
        .map(|(id, _, _)| id)
        .expect("host")
}

const FIRST: &str = "IP,Beteckning,Login,Pass\n192.0.2.1,gateway,admin,example-one\n";
const SECOND: &str = "IP,Beteckning,Login,Pass\n192.0.2.1,gateway,admin,example-two\n";

#[tokio::test]
async fn an_imported_credential_is_an_operator_secret_bound_to_its_host() {
    let env = env();
    let cx = person();
    import(&env, &cx, FIRST).await;
    let view = view(&env.store).await;
    let gateway = host_id(view.as_ref(), "gateway");
    let reference = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential");

    let secret = env
        .secrets
        .get(reference.secret.secret)
        .await
        .expect("secret");
    assert!(secret.revision.is_some(), "the import writes the record");
    assert_eq!(secret.record.name, "Login of gateway");
    assert_eq!(secret.record.username.as_deref(), Some("admin"));
    assert_eq!(secret.record.format, ValueFormat::LoginPassword);
    assert_eq!(secret.record.origin, SecretOrigin::Import);
    assert_eq!(secret.hosts, vec![(gateway, CredentialRole::Admin)]);

    let credentials = env.secrets.host_credentials(gateway).await.expect("host");
    assert_eq!(credentials.items.len(), 1);
    let revealed = env
        .secrets
        .reveal(
            &cx,
            reference.secret.secret,
            RevealRequest {
                host: Some(gateway),
                ..RevealRequest::default()
            },
        )
        .await
        .expect("revealed");
    assert_eq!(revealed.value.as_str(), "example-one");
    assert_eq!(revealed.username.as_deref(), Some("admin"));
    // Nothing to adopt: the import wrote the record itself.
    assert_eq!(env.secrets.adopt_unmanaged(&cx).await.expect("adopt"), 0);
}

#[tokio::test]
async fn a_changed_credential_moves_the_binding_to_the_new_secret() {
    let env = env();
    let cx = person();
    import(&env, &cx, FIRST).await;
    let view = view(&env.store).await;
    let gateway = host_id(view.as_ref(), "gateway");
    let old = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential")
        .secret;

    import(&env, &cx, SECOND).await;
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let new = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential")
        .secret;
    assert_ne!(new, old);
    let credentials = env.secrets.host_credentials(gateway).await.expect("host");
    let bound: Vec<_> = credentials
        .items
        .iter()
        .map(|item| (item.secret.record.id, item.role))
        .collect();
    assert_eq!(bound, vec![(new.secret, CredentialRole::Admin)]);
    assert!(
        env.secrets.get(old.secret).await.is_err(),
        "the old secret and its record are gone"
    );
    assert_eq!(env.vault.meta(old).await.expect("meta"), None);
}

#[tokio::test]
async fn a_replaced_credential_bound_to_another_host_is_kept() {
    let env = env();
    let cx = person();
    import(&env, &cx, FIRST).await;
    let view = view(&env.store).await;
    let gateway = host_id(view.as_ref(), "gateway");
    let old = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential")
        .secret;
    // A person binds the same login to another host as its RDP credential.
    let other = HostId::generate();
    env.secrets
        .set_host_credentials(
            &cx,
            other,
            &[BindingRequest {
                secret: old.secret,
                role: CredentialRole::Rdp,
            }],
            None,
        )
        .await
        .expect("bound elsewhere");

    import(&env, &cx, SECOND).await;
    let kept = env.secrets.get(old.secret).await.expect("kept");
    assert_eq!(kept.hosts, vec![(other, CredentialRole::Rdp)]);
    let revealed = env
        .secrets
        .reveal(&cx, old.secret, RevealRequest::default())
        .await
        .expect("still revealable");
    assert_eq!(revealed.value.as_str(), "example-one");
    let gateway_credentials = env.secrets.host_credentials(gateway).await.expect("host");
    assert_eq!(gateway_credentials.items.len(), 1);
    assert_ne!(gateway_credentials.items[0].secret.record.id, old.secret);
}

/// Writes a connector instance row whose secrets map holds `secret` under `purpose`.
async fn reference(env: &Env, cx: &RequestCtx, secret: tenko_core::SecretId) {
    let mut batch = WriteBatch::for_request(cx);
    batch
        .put_typed(
            &connectors::INSTANCES,
            &ConnectorId::generate(),
            &ConnectorSecrets {
                secrets: [("api_key".to_owned(), SecretRef { secret })].into(),
            },
        )
        .expect("instance");
    env.store.propose(batch).await.expect("write the instance");
}

#[tokio::test]
async fn a_replaced_credential_a_connector_references_is_kept() {
    let env = env();
    let cx = person();
    import(&env, &cx, FIRST).await;
    let view = view(&env.store).await;
    let gateway = host_id(view.as_ref(), "gateway");
    let old = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential")
        .secret;
    reference(&env, &cx, old.secret).await;

    import(&env, &cx, SECOND).await;
    let revealed = env
        .secrets
        .reveal(&cx, old.secret, RevealRequest::default())
        .await
        .expect("still revealable");
    assert_eq!(revealed.value.as_str(), "example-one");
    let view = env.store.read(ReadConsistency::Local).await.expect("view");
    let new = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential")
        .secret;
    assert_ne!(new, old);
    let credentials = env.secrets.host_credentials(gateway).await.expect("host");
    let bound: Vec<_> = credentials
        .items
        .iter()
        .map(|item| item.secret.record.id)
        .collect();
    assert_eq!(
        bound,
        vec![new.secret],
        "the host is bound to the new secret"
    );
}

#[tokio::test]
async fn a_reference_to_another_secret_keeps_nothing() {
    let env = env();
    let cx = person();
    import(&env, &cx, FIRST).await;
    let view = view(&env.store).await;
    let gateway = host_id(view.as_ref(), "gateway");
    let old = host_credential(view.as_ref(), gateway)
        .expect("read")
        .expect("credential")
        .secret;
    reference(&env, &cx, tenko_core::SecretId::generate()).await;

    import(&env, &cx, SECOND).await;
    assert!(
        env.secrets.get(old.secret).await.is_err(),
        "the old secret is gone"
    );
    assert_eq!(env.vault.meta(old).await.expect("meta"), None);
}

fn pin_coupling() -> CredentialGate {
    CredentialGate::Denied {
        reason: "pin_coupling",
        required: None,
        accounts: vec!["pat".to_owned()],
        detail: "the vault takes operator secrets only when every account that may reveal them has more than a PIN (IAM-07): pat sign in with a PIN alone".to_owned(),
    }
}

#[tokio::test]
async fn the_preview_names_the_accounts_that_sign_in_with_a_pin_alone() {
    let env = env();
    let cx = person();
    let upload = env
        .imports
        .upload(&cx, vec![csv(FIRST)])
        .await
        .expect("upload");
    let preview = env
        .imports
        .preview(&cx, upload.id, None, &pin_coupling())
        .await
        .expect("preview");
    assert!(!preview.credentials.allowed);
    assert_eq!(preview.credentials.reason.as_deref(), Some("pin_coupling"));
    assert!(
        preview
            .credentials
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("pat"))
    );
    assert!(
        preview
            .blockers
            .contains(&codes::CREDENTIALS_VAULT_REQUIRED.to_owned())
    );
}

#[tokio::test]
async fn an_apply_while_a_pin_only_account_may_reveal_is_refused_with_the_accounts() {
    let env = env();
    let cx = person();
    let upload = env
        .imports
        .upload(&cx, vec![csv(FIRST)])
        .await
        .expect("upload");
    env.imports
        .preview(&cx, upload.id, None, &pin_coupling())
        .await
        .expect("preview");
    let error = env
        .imports
        .apply(&cx, upload.id, &ApplyRequest::default(), &pin_coupling())
        .await
        .expect_err("refused");
    assert!(error.is(codes::CREDENTIALS_VAULT_REQUIRED));
    assert_eq!(error.coded().status, 403);
    let params = &error.coded().params;
    assert_eq!(
        params.get("reason").map(String::as_str),
        Some("pin_coupling")
    );
    assert_eq!(params.get("accounts").map(String::as_str), Some("pat"));
    assert_eq!(params.get("required"), None);
}
