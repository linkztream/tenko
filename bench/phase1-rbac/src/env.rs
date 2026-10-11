//! The stack under test, in process: store, vault, authentication service, anchors index,
//! IPAM domain over the job engine, and the HTTP API router over them.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use axum::{Extension, Router};
use clap::ValueEnum;
use futures::StreamExt as _;
use tenko_api::{
    sse::{EventHub, filter::ScopedEvents},
    state::AppState,
};
use tenko_auth::{
    AuthConfig, AuthService, LoginOutcome,
    model::USERS,
    roles::RoleName,
    service::{
        GrantCreate, PasswordLogin, SetupAdmin, SetupRequest, UserCreate, types::SecretString,
    },
    settings::Profile,
};
use tenko_core::{
    Authenticator, Credentials, NodeId, PrefixId, Principal, RequestCtx, ScopeRule,
    SystemComponent, Timestamp, UserId,
};
use tenko_ipam::{IpamConfig, IpamService, scope::ScopeIndex};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::{
    MemStore, ReadConsistency, ReadViewExt as _, Store, WriteBatch,
    raft::{RaftStore, RaftStoreConfig},
};
use tenko_vault::{Vault, testing::MemVault};

/// The administrator's name.
pub const ADMIN: &str = "admin";
/// The administrator's invented passphrase (a six-digit PIN: the Home profile asks no second factor for administration).
pub const ADMIN_PASSPHRASE: &str = "739104";

/// Which store the stack runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StoreKind {
    /// `tenko_store::MemStore`.
    Mem,
    /// `tenko_store::raft::RaftStore`, a single voter in a scratch directory.
    Raft,
}

impl StoreKind {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Mem => "MemStore",
            Self::Raft => "RaftStore (openraft over redb, single voter, deferred durability)",
        }
    }
}

/// A scratch directory, removed when dropped.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(root: &Path) -> Result<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = root.join(format!("phase1-rbac-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The services, before any data.
pub struct Stack {
    pub store: Arc<dyn Store>,
    pub auth: Arc<AuthService>,
    pub scope: Arc<ScopeIndex>,
    pub ipam: Arc<IpamService>,
    /// The request context of the administrator.
    pub admin: RequestCtx,
    /// The secret of the administrator's session (from first-run setup).
    pub admin_secret: String,
    /// Where the store keeps its files, for the raft store.
    pub _scratch: Option<Scratch>,
}

/// Builds the stack and completes first-run setup with an administrator.
pub async fn build_stack(kind: StoreKind, data_root: &Path) -> Result<Stack> {
    let (store, vault_store, scratch): (Arc<dyn Store>, Arc<MemStore>, Option<Scratch>) = match kind
    {
        StoreKind::Mem => {
            let mem = Arc::new(MemStore::default());
            (mem.clone(), mem, None)
        }
        StoreKind::Raft => {
            let scratch = Scratch::new(data_root)?;
            let mut config = RaftStoreConfig::new(scratch.path().join("node-1"));
            config.fsync_probe_samples = 0;
            let raft = RaftStore::open(config).await?;
            // The vault of the test helpers is memory only; it holds the key-encryption key
            // and nothing else here, so it runs over a store of its own.
            (Arc::new(raft), Arc::new(MemStore::default()), Some(scratch))
        }
    };
    let vault: Arc<dyn Vault> = Arc::new(MemVault::with_store(vault_store));
    let auth = AuthService::new(Arc::clone(&store), vault, AuthConfig::default()).await?;

    // The anchors index: scoped grants cannot be created, and scoped principals are refused
    // everywhere, until the service has the resolver.
    let scope = Arc::new(ScopeIndex::new());
    store.register_index(scope.clone())?;
    auth.set_anchor_resolver(scope.clone());

    // The IPAM domain over the job engine, as `tenko serve` builds it (step `ipam`).
    let mut engine = JobEngine::new(
        Arc::clone(&store),
        EngineConfig {
            node: NodeId(1),
            ..EngineConfig::default()
        },
    );
    tenko_ipam::jobs::register_steps(&mut engine);
    let ipam = IpamService::new(
        Arc::clone(&store),
        Arc::new(engine.clone()),
        IpamConfig::default(),
    )?;
    let tree = Arc::clone(ipam.tree());
    engine.set_prefix_resolver(Arc::new(move |prefix| {
        tree.prefix(prefix).map(|(_, network)| network)
    }));

    // First-run setup under the Home profile: PINs, and no second factor for administration
    // (the Standard profile asks administrators for a step-up that a benchmark cannot give).
    let public = RequestCtx::system(SystemComponent::Api).at(Timestamp::now());
    let token = auth
        .prepare_setup()
        .await?
        .context("first-run setup is not open")?;
    let session = auth
        .complete_setup(
            &public,
            Some("phase1-rbac"),
            &SetupRequest {
                setup_token: SecretString::new(token.expose()),
                profile: Profile::Home,
                admin: SetupAdmin {
                    name: ADMIN.to_owned(),
                    display_name: Some("Benchmark Administrator".to_owned()),
                    password: SecretString::new(ADMIN_PASSPHRASE),
                },
                host_name: "tenko.example.test".to_owned(),
                language: "en".to_owned(),
            },
        )
        .await?;
    let admin_secret = session.secret.expose().to_owned();
    let admin = ctx_of(&auth, &admin_secret).await?;
    Ok(Stack {
        store,
        auth,
        scope,
        ipam,
        admin,
        admin_secret,
        _scratch: scratch,
    })
}

/// The request context of a session, as the API builds it.
pub async fn ctx_of(auth: &AuthService, secret: &str) -> Result<RequestCtx> {
    let now = Timestamp::now();
    let authenticated = auth
        .authenticate_credentials(&Credentials::Session(secret.to_owned()), now)
        .await?;
    Ok(RequestCtx::new(authenticated.principal).at(now))
}

/// The principal behind a session.
pub async fn principal_of(auth: &AuthService, secret: &str) -> Result<Principal> {
    Ok(ctx_of(auth, secret).await?.principal)
}

/// An invented PIN for operator number `n` (six digits, no run or repeat).
pub fn passphrase(n: usize) -> String {
    format!(
        "{:06}",
        100_000 + crate::common::Rng::new(n as u64 + 1).below(900_000)
    )
}

/// Creates a user without a global role, accepts its initial password (as if the user had
/// changed it) and grants `role`, with subtree, on each of `prefixes`.
pub async fn create_operator(
    stack: &Stack,
    name: &str,
    passphrase: &str,
    role: RoleName,
    prefixes: &[PrefixId],
) -> Result<()> {
    let user = stack
        .auth
        .create_user(
            &stack.admin,
            &UserCreate {
                name: name.to_owned(),
                display_name: Some(format!("Operator {name}")),
                password: Some(SecretString::new(passphrase)),
                roles: Vec::new(),
                language: None,
            },
        )
        .await
        .with_context(|| format!("create user {name}"))?;
    accept_password(stack.store.as_ref(), user.id).await?;
    for &prefix in prefixes {
        stack
            .auth
            .create_grant(
                &stack.admin,
                &GrantCreate {
                    subject: user.id,
                    role,
                    scope: ScopeRule::Prefix {
                        id: prefix,
                        subtree: true,
                    },
                    delegable: false,
                },
            )
            .await
            .with_context(|| format!("grant {name} on {prefix:?}"))?;
    }
    Ok(())
}

/// Clears `password_change_required` of a user: every route refuses an account whose
/// administrator-set password has not been replaced.
async fn accept_password(store: &dyn Store, user: UserId) -> Result<()> {
    let view = store.read(ReadConsistency::Local).await?;
    let (mut record, _) = view.get_typed(&USERS, &user)?.context("the user exists")?;
    if !record.password_change_required {
        return Ok(());
    }
    record.password_change_required = false;
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Auth), Timestamp::now());
    batch.put_typed(&USERS, &user, &record)?;
    store.propose(batch).await?;
    Ok(())
}

/// Signs in with the password and returns the session secret.
pub async fn login(auth: &AuthService, name: &str, passphrase: &str) -> Result<String> {
    let ctx = RequestCtx::system(SystemComponent::Api).at(Timestamp::now());
    let outcome = auth
        .login_password(
            &ctx,
            Some("phase1-rbac"),
            &PasswordLogin {
                user_name: name.to_owned(),
                password: SecretString::new(passphrase),
            },
        )
        .await
        .with_context(|| format!("sign in {name}"))?;
    match outcome {
        LoginOutcome::Session(session) => Ok(session.secret.expose().to_owned()),
        other @ LoginOutcome::SecondFactor { .. } => {
            bail!("sign-in of {name} did not produce a session: {other:?}")
        }
    }
}

/// The HTTP API over the stack.
pub struct Api {
    pub router: Router,
    pub state: AppState,
}

impl Api {
    /// The hub of server-sent events.
    pub fn hub(&self) -> EventHub {
        self.state.events().clone()
    }
}

/// Builds the router the way the server does (authenticator, authorizer, the scoped event
/// filter, and the IPAM, auth and anchors extensions). Build it after the data is loaded:
/// the event hub starts at the store's revision at this moment.
pub fn build_api(stack: &Stack) -> Api {
    let authenticator: Arc<dyn Authenticator> = stack.auth.clone();
    let mut state = AppState::new(Arc::clone(&stack.store));
    state.auth = Some(authenticator);
    state.authorizer = Some(stack.auth.authorizer());
    state.events().set_filter(Box::new(ScopedEvents::new(
        stack.auth.authorizer(),
        Arc::clone(&stack.scope),
        Arc::clone(&stack.store),
    )));
    let router = tenko_api::api(state.clone())
        .0
        .layer(Extension(Arc::clone(&stack.auth)))
        .layer(Extension(Arc::clone(&stack.ipam)))
        .layer(Extension(Arc::clone(&stack.scope)));
    Api { router, state }
}

/// Feeds the hub from the store journal. The server starts this task inside `serve`
/// (`EventHub::spawn_tasks` is crate-private); here it is the same loop reduced to its
/// core: follow `Store::watch` from the hub's position and publish every change set.
pub fn spawn_feeder(hub: EventHub, store: &Arc<dyn Store>) -> Result<tokio::task::JoinHandle<()>> {
    let from = hub.newest();
    let mut changes = store.watch(Some(from), tenko_store::WatchFilter::all())?;
    Ok(tokio::spawn(async move {
        while let Some(item) = changes.next().await {
            match item {
                Ok(change_set) => hub.publish_change_set(&change_set),
                Err(error) => {
                    eprintln!("event feeder stopped: {error:?}");
                    return;
                }
            }
        }
    }))
}
