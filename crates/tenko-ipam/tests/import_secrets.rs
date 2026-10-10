//! Imported credentials as operator secrets of the shared model (WP2.1): the import writes a
//! record and an `admin` binding with each credential, a changed credential moves the
//! binding to the new secret, and a replaced credential that a person bound to another host
//! is kept.

use std::{sync::Arc, time::Duration};

use tenko_core::{AuthStrength, HostId, ImportId, JobId, Principal, RequestCtx, SessionId, UserId};
use tenko_ipam::{
    IpamConfig, IpamService,
    import::{
        ApplyRequest, CredentialGate, ImportConfig, ImportService, Upload, job::host_credential,
    },
    jobs::register_steps,
    tables::HOSTS,
};
use tenko_jobs::{EngineConfig, JobEngine, JobState, RunnerHandle};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadView, ReadViewExt, Store};
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
