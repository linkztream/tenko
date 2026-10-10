//! The connector service of the controller: connector instances in the store, one
//! supervised plugin process per enabled instance, the schedule of reads, runs as jobs,
//! secret injection with audit, and the typed calls other packages use.
//!
//! # Instances
//!
//! An instance names a plugin, carries settings that satisfy the plugin's settings schema
//! (with the defaults filled in) and references vault secrets by purpose; only purposes the
//! manifest declares, and only operator secrets. Every edit is an inline one-step job
//! (`connect.edit` with the step `connect.write`) that commits the change, the job record
//! and the audit record in one write. Instance names are unique, ignoring case.
//!
//! # Runtime
//!
//! [`ConnectorHost::sync`] reconciles the running plugins with the stored instances: an
//! enabled instance gets a [`SupervisorHandle`]; a disabled or deleted one is stopped.
//! The host follows the `connect.instances` table, so a change made through another
//! controller applies here too. Settings and secrets travel with every call, so changing
//! them never restarts the plugin.
//!
//! # Calls and secrets
//!
//! Every call waits for at most one of [`HostConfig::max_concurrent_calls`] slots of its
//! instance and has a timeout. When the call carries secrets, the host first writes an
//! audit record (`connect.secret.inject`, principal `system:connector`, the plugin, the
//! purposes and the secret references, never a value), then resolves the references from
//! the vault into the call's [`CallContext`], which wipes them when the call ends. A
//! secret whose purpose the manifest does not declare is never injected.
//!
//! # Schedule and runs
//!
//! Each running instance with the `inventory` or `network_controller` capability is read
//! every poll interval; a person can ask for a run at once (`connect.run`, a job in the
//! group `connect:<id>` with a limit of one). A run normalizes what the plugin reports into
//! observations ([`super::normalize`]) and hands them to the [`ObservationSink`]; its
//! outcome is the instance's last run (`connect.runs`). The remote system is also checked
//! every [`HostConfig::check_interval`]; the result is kept in memory and shown as health.
//!
//! # Health changes
//!
//! The process state and the remote health live in memory on this node, not in the store,
//! so no store write announces them. [`ConnectorHost::health_changes`] does: it names an
//! instance whenever its plugin process changes state (starting, running, backing off,
//! stopped), when a runtime starts or stops, and when the outcome of a remote check
//! changes. The server turns these into `connectors` events, so the views that show an
//! instance read it again.

mod calls;
pub mod model;
mod steps;

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock, PoisonError, RwLock},
    time::Duration,
};

use futures::StreamExt;
use tenko_core::{
    CodedError, ConnectorId, JobId, MessageKey, ObjectRef, Principal, RequestCtx, RequestId,
    Revision, Timestamp, UserId,
    audit::{AuditDraft, FieldChange},
    ipam::Stamp,
    principal::SystemComponent,
    secret::{SecretClass, SecretRef},
    serde_util::HexBytes,
};
use tenko_jobs::{GroupKey, JobEngine, JobKind, JobSpec, StepKind, StepSpec};
use tenko_store::{KeyRange, ReadConsistency, ReadViewExt, Store, WatchFilter, WriteBatch};
use tenko_vault::Vault;
use tokio::{
    sync::{broadcast, watch},
    task::JoinHandle,
    time::Instant,
};

pub use self::model::{
    ConnectorHealth, ConnectorInstance, ConnectorPatch, ConnectorView, HostError, LastRun,
    NewConnector, RunOutcome, RunTrigger, actions, bounds, kinds, tables,
};
use super::{
    normalize::{self, ObservationSink},
    registry::{PluginInfo, PluginRegistry},
    supervisor::{ProcessState, SupervisorConfig, SupervisorHandle, SupervisorStatus},
};
use crate::{
    CallContext, Capability, HealthReport, Secrets,
    host::client::PluginClient,
    manifest::{Manifest, ManifestProblem},
};

/// Settings of the connector service.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// How plugins are supervised (the log label is set per instance).
    pub supervisor: SupervisorConfig,
    /// Calls in flight per instance.
    pub max_concurrent_calls: usize,
    /// How long a call waits for a plugin that is starting.
    pub start_wait: Duration,
    /// Interval of remote checks of running instances.
    pub check_interval: Duration,
    /// Delay of the first scheduled read after an instance starts.
    pub first_run_delay: Duration,
    /// How often an incremental inventory poll is replaced by a full one.
    pub full_poll_interval: Duration,
    /// How old a network-controller plan may be when it is applied.
    pub plan_max_age: Duration,
    /// Whether the host reads instances on their schedule (off in tests that drive runs).
    pub schedule: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            supervisor: SupervisorConfig::default(),
            max_concurrent_calls: 4,
            start_wait: Duration::from_secs(10),
            check_interval: Duration::from_secs(900),
            first_run_delay: Duration::from_secs(5),
            full_poll_interval: Duration::from_secs(3600),
            plan_max_age: Duration::from_secs(600),
            schedule: true,
        }
    }
}

/// The remote health of an instance, kept in memory.
#[derive(Debug, Default)]
struct Remote {
    report: Option<HealthReport>,
    error: Option<CodedError>,
    checked: Option<Instant>,
    checking: bool,
}

/// One enabled instance on this node.
struct Runtime {
    id: ConnectorId,
    manifest: Option<Manifest>,
    instance: RwLock<ConnectorInstance>,
    supervisor: Option<SupervisorHandle>,
    problem: Option<CodedError>,
    calls: tokio::sync::Semaphore,
    run_lock: tokio::sync::Mutex<()>,
    remote: Mutex<Remote>,
    next_run: Mutex<Option<Instant>>,
}

impl Runtime {
    fn instance(&self) -> ConnectorInstance {
        self.instance
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn status(&self) -> SupervisorStatus {
        match (&self.supervisor, &self.problem) {
            (Some(supervisor), _) => supervisor.status(),
            (None, problem) => SupervisorStatus {
                state: ProcessState::Failed,
                restarts: 0,
                consecutive_failures: 0,
                last_error: problem.clone(),
                changed_at: Timestamp::now(),
            },
        }
    }

    fn has(&self, capability: Capability) -> bool {
        self.manifest
            .as_ref()
            .is_some_and(|manifest| manifest.has(capability))
    }

    fn poll_interval(&self) -> Duration {
        let instance = self.instance();
        model::poll_interval(
            instance.poll_interval_secs,
            self.manifest
                .as_ref()
                .and_then(|manifest| manifest.defaults.poll_interval_secs),
        )
    }

    fn call_timeout(&self) -> Duration {
        let instance = self.instance();
        model::call_timeout(
            instance.call_timeout_secs,
            self.manifest
                .as_ref()
                .and_then(|manifest| manifest.defaults.call_timeout_secs),
        )
    }

    async fn stop(&self) {
        if let Some(supervisor) = &self.supervisor {
            supervisor.stop().await;
        }
    }
}

/// The connector service. Shared as `Arc<ConnectorHost>`; the API reaches it as a request
/// extension.
pub struct ConnectorHost {
    store: Arc<dyn Store>,
    vault: Option<Arc<dyn Vault>>,
    registry: PluginRegistry,
    config: HostConfig,
    sink: Arc<dyn ObservationSink>,
    jobs: OnceLock<JobEngine>,
    runtimes: Mutex<HashMap<ConnectorId, Arc<Runtime>>>,
    sync_lock: tokio::sync::Mutex<()>,
    /// The instances whose process state or health changed ([`Self::health_changes`]).
    health: broadcast::Sender<ConnectorId>,
}

/// How many health changes a slow receiver may fall behind before it lags.
const HEALTH_CHANGES: usize = 256;

impl std::fmt::Debug for ConnectorHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorHost")
            .field("registry", &self.registry)
            .field("runtimes", &self.runtime_ids().len())
            .finish_non_exhaustive()
    }
}

impl ConnectorHost {
    /// A service over the store, the vault (without one, instances cannot reference
    /// secrets), the plugin registry and the sink of observations.
    pub fn new(
        store: Arc<dyn Store>,
        vault: Option<Arc<dyn Vault>>,
        registry: PluginRegistry,
        config: HostConfig,
        sink: Arc<dyn ObservationSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            vault,
            registry,
            config,
            sink,
            jobs: OnceLock::new(),
            runtimes: Mutex::new(HashMap::new()),
            sync_lock: tokio::sync::Mutex::new(()),
            health: broadcast::channel(HEALTH_CHANGES).0,
        })
    }

    /// A receiver of the instances whose plugin process or health changed on this node:
    /// a change of the process state, a runtime that starts or stops, and a remote check
    /// whose outcome differs from the one before. A receiver that falls behind gets
    /// [`broadcast::error::RecvError::Lagged`]; [`Self::supervised`] then names every
    /// instance that may have changed.
    pub fn health_changes(&self) -> broadcast::Receiver<ConnectorId> {
        self.health.subscribe()
    }

    /// The instances with a runtime on this node (enabled ones), in no particular order.
    pub fn supervised(&self) -> Vec<ConnectorId> {
        self.runtime_ids()
    }

    /// Announces a health change of `id` (nobody listening is fine).
    fn health_changed(&self, id: ConnectorId) {
        let _ = self.health.send(id);
    }

    /// Registers the job steps (`connect.write`, `connect.poll`) with the engine; edits then
    /// run as inline jobs and runs as background jobs. Without an engine, edits propose
    /// their batches directly and runs cannot be requested as jobs.
    pub fn register_steps(self: &Arc<Self>, engine: &JobEngine) {
        let mut registered = engine.clone();
        registered.register(Arc::new(steps::WriteStep));
        registered.register(Arc::new(steps::PollStep {
            host: Arc::downgrade(self),
        }));
        let _ = self.jobs.set(engine.clone());
    }

    /// The plugin registry.
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    /// The bundled and installed plugins.
    pub fn plugins(&self) -> Vec<PluginInfo> {
        self.registry.list()
    }

    /// The store revision this node has applied.
    pub fn revision(&self) -> Revision {
        self.store.status().revision
    }

    // -----------------------------------------------------------------------------------
    // Reading.

    /// Every instance with its health and last run, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn list(&self, at_least: Option<Revision>) -> Result<Vec<ConnectorView>, HostError> {
        let view = self.read(at_least).await?;
        let instances = view.scan_typed(&tables::INSTANCES, KeyRange::all(), usize::MAX, false)?;
        let mut views = Vec::with_capacity(instances.len());
        for (id, instance, revision) in instances {
            let last_run = view.get_typed(&tables::RUNS, &id)?.map(|(run, _)| run);
            views.push(self.view_of(instance, revision, last_run));
        }
        views.sort_by(|a, b| {
            a.instance
                .name
                .to_lowercase()
                .cmp(&b.instance.name.to_lowercase())
        });
        Ok(views)
    }

    /// One instance with its health and last run.
    ///
    /// # Errors
    ///
    /// `connect.instance.not_found`, or the store's error.
    pub async fn get(
        &self,
        id: ConnectorId,
        at_least: Option<Revision>,
    ) -> Result<ConnectorView, HostError> {
        let view = self.read(at_least).await?;
        let (instance, revision) = view
            .get_typed(&tables::INSTANCES, &id)?
            .ok_or_else(|| HostError::not_found(id))?;
        let last_run = view.get_typed(&tables::RUNS, &id)?.map(|(run, _)| run);
        Ok(self.view_of(instance, revision, last_run))
    }

    async fn read(
        &self,
        at_least: Option<Revision>,
    ) -> Result<Arc<dyn tenko_store::ReadView>, HostError> {
        let consistency = at_least.map_or(ReadConsistency::Local, ReadConsistency::AtLeast);
        Ok(self.store.read(consistency).await?)
    }

    fn view_of(
        &self,
        instance: ConnectorInstance,
        revision: Revision,
        last_run: Option<LastRun>,
    ) -> ConnectorView {
        let runtime = self.runtime(instance.id);
        let capabilities = self
            .registry
            .find(&instance.plugin)
            .and_then(|info| info.manifest)
            .map(|manifest| manifest.capabilities)
            .unwrap_or_default();
        let health = match &runtime {
            Some(runtime) => {
                let remote = runtime
                    .remote
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                ConnectorHealth {
                    process: runtime.status(),
                    remote: remote.report.clone(),
                    remote_error: remote.error.clone(),
                }
            }
            None => ConnectorHealth {
                process: SupervisorStatus {
                    state: ProcessState::Stopped,
                    restarts: 0,
                    consecutive_failures: 0,
                    last_error: None,
                    changed_at: instance.updated.at,
                },
                remote: None,
                remote_error: None,
            },
        };
        ConnectorView {
            instance,
            revision,
            capabilities,
            health,
            last_run,
        }
    }

    fn runtime(&self, id: ConnectorId) -> Option<Arc<Runtime>> {
        self.runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    fn runtime_ids(&self) -> Vec<ConnectorId> {
        self.runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    // -----------------------------------------------------------------------------------
    // Edits.

    /// Creates an instance.
    ///
    /// # Errors
    ///
    /// `connect.plugin.unknown` or `connect.plugin.unusable`, `connect.instance.name`,
    /// `connect.instance.name_taken`, `connect.settings.invalid`, the secret errors of
    /// [`validate_secrets`](Self::validate_secrets), `connect.instance.poll_interval`,
    /// `connect.instance.call_timeout`, or the store's error.
    pub async fn create(
        &self,
        cx: &RequestCtx,
        new: NewConnector,
    ) -> Result<ConnectorView, HostError> {
        let manifest = self.usable_manifest(&new.plugin)?;
        let name = valid_name(&new.name)?;
        let settings = manifest.validate_settings(&new.settings)?;
        self.validate_secrets(&manifest, &new.secrets).await?;
        let poll_interval_secs = valid_poll(new.poll_interval_secs)?;
        let call_timeout_secs = valid_timeout(new.call_timeout_secs)?;
        self.name_free(&name, None).await?;
        let id = ConnectorId::generate();
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let instance = ConnectorInstance {
            id,
            plugin: manifest.name.clone(),
            name,
            enabled: new.enabled,
            settings,
            secrets: new.secrets,
            poll_interval_secs,
            call_timeout_secs,
            writes_enabled: new.writes_enabled,
            created: stamp.clone(),
            updated: stamp,
        };
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::INSTANCES, &id, None);
        batch.put_typed(&tables::INSTANCES, &id, &instance)?;
        claim_name(&mut batch, &instance.name, id)?;
        let mut draft = AuditDraft::success(actions::CREATE, objects(&instance))
            .with_source_ip(cx.source_ip)
            .with_context("plugin", instance.plugin.clone())
            .with_context("name", instance.name.clone())
            .with_context("enabled", instance.enabled.to_string());
        if !instance.secrets.is_empty() {
            draft = draft.with_context("secret_purposes", purposes(&instance.secrets));
        }
        batch.audit(draft);
        let revision = self
            .commit(cx, id, format!("create connector {}", instance.name), batch)
            .await?;
        self.sync().await?;
        self.get(id, Some(revision)).await
    }

    /// Changes an instance. With `expect`, the change applies only to that revision.
    ///
    /// # Errors
    ///
    /// As [`create`](Self::create), plus `connect.instance.not_found` and
    /// `connect.instance.conflict` (the instance changed since `expect`).
    pub async fn update(
        &self,
        cx: &RequestCtx,
        id: ConnectorId,
        patch: ConnectorPatch,
        expect: Option<Revision>,
    ) -> Result<ConnectorView, HostError> {
        let (current, revision) = self.current(id).await?;
        if expect.is_some_and(|expect| expect != revision) {
            return Err(HostError::new(
                "connect.instance.conflict",
                409,
                "the connector instance changed since it was read; read it again and retry",
            ));
        }
        let mut next = current.clone();
        let mut changes = Vec::new();
        if let Some(name) = &patch.name {
            next.name = valid_name(name)?;
            self.name_free(&next.name, Some(id)).await?;
        }
        if patch.settings.is_some() || patch.secrets.is_some() {
            let manifest = self.usable_manifest(&current.plugin)?;
            if let Some(settings) = &patch.settings {
                next.settings = manifest.validate_settings(settings)?;
            }
            if let Some(secrets) = &patch.secrets {
                self.validate_secrets(&manifest, secrets).await?;
                next.secrets.clone_from(secrets);
            }
        }
        if let Some(poll) = patch.poll_interval_secs {
            next.poll_interval_secs = valid_poll((poll != 0).then_some(poll))?;
        }
        if let Some(timeout) = patch.call_timeout_secs {
            next.call_timeout_secs = valid_timeout((timeout != 0).then_some(timeout))?;
        }
        if let Some(writes) = patch.writes_enabled {
            next.writes_enabled = writes;
        }
        diff(&current, &next, &mut changes);
        if changes.is_empty() {
            return self.get(id, Some(revision)).await;
        }
        next.updated = Stamp::new(cx.now, cx.principal.clone());
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::INSTANCES, &id, Some(revision));
        batch.put_typed(&tables::INSTANCES, &id, &next)?;
        if name_key(&current.name) != name_key(&next.name) {
            batch.delete_typed(&tables::NAMES, &name_key(&current.name));
            claim_name(&mut batch, &next.name, id)?;
        }
        let mut draft = AuditDraft::success(actions::UPDATE, objects(&next))
            .with_source_ip(cx.source_ip)
            .with_context("plugin", next.plugin.clone());
        for change in changes {
            draft = draft.with_change(change);
        }
        batch.audit(draft);
        let revision = self
            .commit(cx, id, format!("change connector {}", next.name), batch)
            .await?;
        self.sync().await?;
        self.get(id, Some(revision)).await
    }

    /// Enables or disables an instance. Enabling an enabled instance whose plugin does not
    /// run starts it anew, with the plugin registry read again.
    ///
    /// # Errors
    ///
    /// `connect.instance.not_found`, `connect.instance.conflict` or the store's error.
    pub async fn set_enabled(
        &self,
        cx: &RequestCtx,
        id: ConnectorId,
        enabled: bool,
    ) -> Result<ConnectorView, HostError> {
        let (current, revision) = self.current(id).await?;
        if current.enabled == enabled {
            if enabled {
                self.restart_if_not_running(id).await?;
            }
            return self.get(id, Some(revision)).await;
        }
        let mut next = current.clone();
        next.enabled = enabled;
        next.updated = Stamp::new(cx.now, cx.principal.clone());
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::INSTANCES, &id, Some(revision));
        batch.put_typed(&tables::INSTANCES, &id, &next)?;
        let action = if enabled {
            actions::ENABLE
        } else {
            actions::DISABLE
        };
        batch.audit(
            AuditDraft::success(action, vec![ObjectRef::from(id)])
                .with_source_ip(cx.source_ip)
                .with_change(FieldChange {
                    object: None,
                    field: "enabled".to_owned(),
                    old: Some(current.enabled.to_string()),
                    new: Some(enabled.to_string()),
                }),
        );
        let verb = if enabled { "enable" } else { "disable" };
        let revision = self
            .commit(cx, id, format!("{verb} connector {}", next.name), batch)
            .await?;
        self.sync().await?;
        self.get(id, Some(revision)).await
    }

    /// Deletes an instance and its last run; its plugin stops. The vault secrets it
    /// referenced stay (they belong to the vault).
    ///
    /// # Errors
    ///
    /// `connect.instance.not_found`, `connect.instance.conflict` or the store's error.
    pub async fn delete(&self, cx: &RequestCtx, id: ConnectorId) -> Result<Revision, HostError> {
        let (current, revision) = self.current(id).await?;
        let mut batch = WriteBatch::for_request(cx);
        batch.expect_typed(&tables::INSTANCES, &id, Some(revision));
        batch.delete_typed(&tables::INSTANCES, &id);
        batch.delete_typed(&tables::NAMES, &name_key(&current.name));
        batch.delete_typed(&tables::RUNS, &id);
        batch.audit(
            AuditDraft::success(actions::DELETE, objects(&current))
                .with_source_ip(cx.source_ip)
                .with_context("plugin", current.plugin.clone())
                .with_context("name", current.name.clone()),
        );
        let revision = self
            .commit(cx, id, format!("delete connector {}", current.name), batch)
            .await?;
        self.sync().await?;
        Ok(revision)
    }

    /// Starts the plugin of an enabled instance anew when it does not run: the registry is
    /// read again, so a plugin version installed meanwhile is picked up.
    async fn restart_if_not_running(&self, id: ConnectorId) -> Result<(), HostError> {
        let stale = {
            let mut runtimes = self.runtimes.lock().unwrap_or_else(PoisonError::into_inner);
            let running = runtimes.get(&id).is_some_and(|runtime| {
                runtime
                    .supervisor
                    .as_ref()
                    .is_some_and(|supervisor| supervisor.status().is_running())
            });
            if running { None } else { runtimes.remove(&id) }
        };
        if let Some(runtime) = stale {
            runtime.stop().await;
        }
        self.sync().await
    }

    /// Fails when another instance has the name (ignoring case).
    async fn name_free(&self, name: &str, except: Option<ConnectorId>) -> Result<(), HostError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        match view.get_typed(&tables::NAMES, &name_key(name))? {
            Some((owner, _)) if Some(owner) != except => Err(HostError::new(
                "connect.instance.name_taken",
                409,
                format!("another connector is named `{name}`"),
            )
            .with_param("field", "name")),
            _ => Ok(()),
        }
    }

    async fn current(&self, id: ConnectorId) -> Result<(ConnectorInstance, Revision), HostError> {
        let view = self.store.read(ReadConsistency::Local).await?;
        view.get_typed(&tables::INSTANCES, &id)?
            .ok_or_else(|| HostError::not_found(id))
    }

    /// Commits an edit as an inline job (or directly without an engine) and returns its
    /// revision.
    async fn commit(
        &self,
        cx: &RequestCtx,
        id: ConnectorId,
        summary: String,
        batch: WriteBatch,
    ) -> Result<Revision, HostError> {
        let Some(engine) = self.jobs.get() else {
            return Ok(self.store.propose(batch).await?.revision);
        };
        let params = steps::WriteParams {
            connector: id,
            summary,
            batch,
        };
        let spec = JobSpec {
            kind: JobKind::from_static(kinds::EDIT_JOB),
            title: MessageKey::from_static(kinds::EDIT_TITLE),
            targets: vec![ObjectRef::from(id)],
            steps: vec![StepSpec {
                kind: StepKind::from_static(kinds::WRITE_STEP),
                params: HexBytes(tenko_core::codec::to_cbor(&params)?.to_vec()),
                timeout: None,
            }],
            timeout: Duration::from_secs(30),
            group: None,
            group_limit: None,
            idempotency: None,
        };
        let job = engine.run_inline(spec, cx).await?;
        Ok(job.revision)
    }

    /// The manifest of a plugin that can run here.
    fn usable_manifest(&self, plugin: &str) -> Result<Manifest, HostError> {
        let info = self.registry.find(plugin).ok_or_else(|| {
            HostError::invalid(
                "connect.plugin.unknown",
                "plugin",
                format!("no plugin `{plugin}` is bundled or installed"),
            )
        })?;
        match (info.usable, info.manifest) {
            (true, Some(manifest)) => Ok(manifest),
            _ => Err(HostError::invalid(
                "connect.plugin.unusable",
                "plugin",
                format!(
                    "plugin `{plugin}` cannot run here: {}",
                    render_problems(&info.problems)
                ),
            )),
        }
    }

    /// Checks secret references: only declared purposes, every required purpose present,
    /// and every reference an existing operator secret.
    ///
    /// # Errors
    ///
    /// `connect.secret.undeclared`, `connect.secret.missing`, `connect.secret.not_found`,
    /// `connect.secret.not_operator`, or `connect.vault_unavailable` when references are
    /// given to a service without a vault.
    pub async fn validate_secrets(
        &self,
        manifest: &Manifest,
        secrets: &BTreeMap<String, SecretRef>,
    ) -> Result<(), HostError> {
        for purpose in secrets.keys() {
            if manifest.secret(purpose).is_none() {
                return Err(HostError::invalid(
                    "connect.secret.undeclared",
                    &format!("secrets.{purpose}"),
                    format!(
                        "plugin `{}` declares no secret purpose `{purpose}`",
                        manifest.name
                    ),
                ));
            }
        }
        for decl in manifest.secrets.iter().filter(|decl| decl.required) {
            if !secrets.contains_key(&decl.purpose) {
                return Err(HostError::invalid(
                    "connect.secret.missing",
                    &format!("secrets.{}", decl.purpose),
                    format!(
                        "plugin `{}` needs the secret `{}`",
                        manifest.name, decl.purpose
                    ),
                ));
            }
        }
        if secrets.is_empty() {
            return Ok(());
        }
        let vault = self.vault.as_ref().ok_or_else(|| {
            HostError::new(
                "connect.vault_unavailable",
                503,
                "this connector service has no vault; secrets cannot be referenced",
            )
        })?;
        for (purpose, reference) in secrets {
            let field = format!("secrets.{purpose}");
            let meta = vault
                .meta(*reference)
                .await
                .map_err(|error| HostError::coded(&error))?
                .ok_or_else(|| {
                    HostError::invalid(
                        "connect.secret.not_found",
                        &field,
                        format!("the secret {} does not exist", reference.secret),
                    )
                })?;
            if meta.class != SecretClass::Operator {
                return Err(HostError::invalid(
                    "connect.secret.not_operator",
                    &field,
                    "only operator secrets can be given to a plugin; system secrets never leave Tenko",
                ));
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Runtime.

    /// Reconciles the running plugins with the stored instances.
    ///
    /// # Errors
    ///
    /// The store's error; running plugins are left as they were.
    pub async fn sync(&self) -> Result<(), HostError> {
        let _serial = self.sync_lock.lock().await;
        let view = self.store.read(ReadConsistency::Local).await?;
        let instances: Vec<ConnectorInstance> = view
            .scan_typed(&tables::INSTANCES, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, instance, _)| instance)
            .collect();
        let mut stopping = Vec::new();
        let mut starting = Vec::new();
        let mut changed = Vec::new();
        {
            let mut runtimes = self.runtimes.lock().unwrap_or_else(PoisonError::into_inner);
            let wanted: std::collections::HashSet<ConnectorId> = instances
                .iter()
                .filter(|instance| instance.enabled)
                .map(|instance| instance.id)
                .collect();
            let gone: Vec<ConnectorId> = runtimes
                .keys()
                .filter(|id| !wanted.contains(id))
                .copied()
                .collect();
            for id in gone {
                if let Some(runtime) = runtimes.remove(&id) {
                    stopping.push(runtime);
                }
            }
            for instance in instances.into_iter().filter(|instance| instance.enabled) {
                match runtimes.get(&instance.id) {
                    Some(runtime) if runtime.instance().plugin == instance.plugin => {
                        *runtime
                            .instance
                            .write()
                            .unwrap_or_else(PoisonError::into_inner) = instance;
                    }
                    Some(_) => {
                        if let Some(old) = runtimes.remove(&instance.id) {
                            stopping.push(old);
                        }
                        starting.push(instance);
                    }
                    None => starting.push(instance),
                }
            }
            for instance in starting {
                let runtime = self.start_runtime(instance);
                changed.push(runtime.id);
                runtimes.insert(runtime.id, runtime);
            }
        }
        futures::future::join_all(stopping.iter().map(|runtime| runtime.stop())).await;
        // A stopped runtime is gone from the map, so its instance now shows as stopped.
        changed.extend(stopping.iter().map(|runtime| runtime.id));
        for id in changed {
            self.health_changed(id);
        }
        Ok(())
    }

    fn start_runtime(&self, instance: ConnectorInstance) -> Arc<Runtime> {
        let id = instance.id;
        let (manifest, supervisor, problem) = match self.registry.launch_spec(&instance.plugin) {
            Ok((manifest, spec)) => {
                let mut config = self.config.supervisor.clone();
                config.launch.log_label = Some(format!("{}/{}", instance.plugin, instance.name));
                (
                    Some(manifest),
                    Some(SupervisorHandle::spawn(spec, config)),
                    None,
                )
            }
            Err(problems) => {
                tracing::error!(
                    connector = %id,
                    plugin = %instance.plugin,
                    "the plugin of connector `{}` cannot run: {}",
                    instance.name,
                    render_problems(&problems)
                );
                (
                    None,
                    None,
                    Some(
                        CodedError::new(
                            "connect.plugin.unusable",
                            503,
                            format!(
                                "plugin `{}` cannot run here: {}",
                                instance.plugin,
                                render_problems(&problems)
                            ),
                        )
                        .with_param("plugin", instance.plugin.clone()),
                    ),
                )
            }
        };
        if let Some(supervisor) = &supervisor {
            self.follow(id, supervisor.subscribe());
        }
        Arc::new(Runtime {
            id,
            manifest,
            instance: RwLock::new(instance),
            supervisor,
            problem,
            calls: tokio::sync::Semaphore::new(self.config.max_concurrent_calls.max(1)),
            run_lock: tokio::sync::Mutex::new(()),
            remote: Mutex::new(Remote::default()),
            next_run: Mutex::new(Some(Instant::now() + self.config.first_run_delay)),
        })
    }

    /// Announces every status the supervisor of `id` publishes, until it ends (its
    /// sender is dropped when the supervisor task ends, after the final `stopped`).
    fn follow(&self, id: ConnectorId, mut status: watch::Receiver<SupervisorStatus>) {
        let health = self.health.clone();
        status.borrow_and_update();
        tokio::spawn(async move {
            while status.changed().await.is_ok() {
                let _ = health.send(id);
            }
        });
    }

    /// Starts the service: reconciles the instances, follows their table, reads them on
    /// schedule and checks them, until `stop` turns true; then stops every plugin.
    pub fn start(self: &Arc<Self>, mut stop: watch::Receiver<bool>) -> JoinHandle<()> {
        let host = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = host.sync().await {
                tracing::error!(%error, "connector instances could not be loaded");
            }
            let filter = WatchFilter::tables([tables::INSTANCES.name().clone()]);
            let mut changes = host.store.watch(None, filter.clone()).ok();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    () = async {
                        let _ = stop.wait_for(|stopped| *stopped).await;
                    } => break,
                    change = next_change(&mut changes) => {
                        if !change {
                            changes = host.store.watch(None, filter.clone()).ok();
                        }
                        if let Err(error) = host.sync().await {
                            tracing::warn!(%error, "connector instances could not be reconciled");
                        }
                    }
                    _ = tick.tick() => host.schedule(&mut tasks),
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
            tasks.abort_all();
            host.shutdown().await;
        })
    }

    /// Stops every plugin gracefully.
    pub async fn shutdown(&self) {
        let runtimes: Vec<Arc<Runtime>> = self
            .runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, runtime)| runtime)
            .collect();
        futures::future::join_all(runtimes.iter().map(|runtime| runtime.stop())).await;
        if !runtimes.is_empty() {
            tracing::info!(plugins = runtimes.len(), "connector plugins stopped");
        }
    }

    /// Starts the reads and checks that are due.
    fn schedule(self: &Arc<Self>, tasks: &mut tokio::task::JoinSet<()>) {
        let runtimes: Vec<Arc<Runtime>> = self
            .runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        let now = Instant::now();
        for runtime in runtimes {
            let running = runtime
                .supervisor
                .as_ref()
                .is_some_and(|supervisor| supervisor.status().is_running());
            if !running {
                continue;
            }
            let check_due = {
                let mut remote = runtime
                    .remote
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let due = !remote.checking
                    && remote
                        .checked
                        .is_none_or(|checked| now >= checked + self.config.check_interval);
                if due {
                    remote.checking = true;
                }
                due
            };
            if check_due {
                let host = Arc::clone(self);
                let id = runtime.id;
                tasks.spawn(async move {
                    let _ = host.check(id, None).await;
                });
            }
            if !self.config.schedule
                || !(runtime.has(Capability::Inventory)
                    || runtime.has(Capability::NetworkController))
            {
                continue;
            }
            let run_due = {
                let mut next = runtime
                    .next_run
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                match *next {
                    Some(at) if now >= at => {
                        *next = None;
                        true
                    }
                    _ => false,
                }
            };
            if run_due {
                let host = Arc::clone(self);
                let id = runtime.id;
                tasks.spawn(async move {
                    if let Err(error) = host.run(id, RunTrigger::Schedule, None, None).await {
                        tracing::warn!(connector = %id, %error, "scheduled run did not start");
                    }
                });
            }
        }
    }

    // -----------------------------------------------------------------------------------
    // Runs.

    /// Asks for a run now, as a job in the instance's group.
    ///
    /// # Errors
    ///
    /// `connect.instance.not_found`, `connect.instance.disabled`,
    /// `connect.instance.nothing_to_run` (no capability that reads),
    /// `connect.jobs_unavailable`, or the job engine's error.
    pub async fn run_now(&self, cx: &RequestCtx, id: ConnectorId) -> Result<JobId, HostError> {
        let (instance, _) = self.current(id).await?;
        if !instance.enabled {
            return Err(HostError::new(
                "connect.instance.disabled",
                409,
                format!("connector `{}` is disabled", instance.name),
            ));
        }
        let manifest = self
            .registry
            .find(&instance.plugin)
            .and_then(|info| info.manifest);
        let reads = manifest.as_ref().is_some_and(|manifest| {
            manifest.has(Capability::Inventory) || manifest.has(Capability::NetworkController)
        });
        if !reads {
            return Err(HostError::new(
                "connect.instance.nothing_to_run",
                409,
                format!(
                    "plugin `{}` neither supplies an inventory nor reads a network controller",
                    instance.plugin
                ),
            ));
        }
        let engine = self.jobs.get().ok_or_else(|| {
            HostError::new(
                "connect.jobs_unavailable",
                503,
                "the job engine is not available",
            )
        })?;
        let timeout = model::call_timeout(
            instance.call_timeout_secs,
            manifest.and_then(|manifest| manifest.defaults.call_timeout_secs),
        );
        let spec = JobSpec {
            kind: JobKind::from_static(kinds::RUN_JOB),
            title: MessageKey::from_static(kinds::RUN_TITLE),
            targets: vec![ObjectRef::from(id)],
            steps: vec![StepSpec {
                kind: StepKind::from_static(kinds::POLL_STEP),
                params: HexBytes(
                    tenko_core::codec::to_cbor(&steps::PollParams { connector: id })?.to_vec(),
                ),
                timeout: None,
            }],
            // Pages and the topology each have the call timeout; a run gets room for many.
            timeout: timeout.saturating_mul(20).max(Duration::from_secs(300)),
            group: GroupKey::new(format!("connect:{id}")).ok(),
            group_limit: Some(1),
            idempotency: None,
        };
        Ok(engine.submit(spec, cx).await?)
    }

    /// Reads an instance once and hands the observations on; records and returns the run.
    /// Runs of one instance never overlap.
    ///
    /// # Errors
    ///
    /// `connect.instance.not_found` when the instance does not run on this node, or the
    /// store's error when the run cannot be recorded. A failing plugin is a run with the
    /// outcome `failed`, not an error.
    pub async fn run(
        &self,
        id: ConnectorId,
        trigger: RunTrigger,
        job: Option<JobId>,
        on_behalf_of: Option<UserId>,
    ) -> Result<LastRun, HostError> {
        let runtime = self.runtime(id).ok_or_else(|| {
            HostError::new(
                "connect.instance.disabled",
                409,
                format!("connector {id} is not enabled on this node"),
            )
        })?;
        let _serial = runtime.run_lock.lock().await;
        let started_at = Timestamp::now();
        let view = self.store.read(ReadConsistency::Local).await?;
        let previous = view.get_typed(&tables::RUNS, &id)?;
        let previous_run = previous.as_ref().map(|(run, _)| run.clone());
        let outcome = self
            .read_once(&runtime, previous_run.as_ref(), on_behalf_of)
            .await;
        let finished_at = Timestamp::now();
        let failures = previous_run
            .as_ref()
            .map_or(0, |run| run.consecutive_failures);
        let run = match outcome {
            Ok(read) => LastRun {
                trigger,
                job,
                started_at,
                finished_at,
                outcome: RunOutcome::Succeeded,
                observations: read.observations,
                pages: read.pages,
                warnings: read.warnings.into_iter().take(20).collect(),
                error: None,
                consecutive_failures: 0,
                last_success_at: Some(finished_at),
                cursor: read.cursor,
                last_full_at: if read.full {
                    Some(started_at)
                } else {
                    previous_run.as_ref().and_then(|run| run.last_full_at)
                },
            },
            Err(error) => {
                tracing::warn!(connector = %id, code = %error.code(), "connector run failed: {error}");
                LastRun {
                    trigger,
                    job,
                    started_at,
                    finished_at,
                    outcome: RunOutcome::Failed,
                    observations: 0,
                    pages: 0,
                    warnings: Vec::new(),
                    error: Some(error.into_coded()),
                    consecutive_failures: failures.saturating_add(1),
                    last_success_at: previous_run.as_ref().and_then(|run| run.last_success_at),
                    cursor: previous_run.as_ref().and_then(|run| run.cursor.clone()),
                    last_full_at: previous_run.as_ref().and_then(|run| run.last_full_at),
                }
            }
        };
        let principal = Principal::System {
            component: SystemComponent::Connector,
            on_behalf_of,
        };
        self.record_run(id, &run, principal, finished_at).await?;
        *runtime
            .next_run
            .lock()
            .unwrap_or_else(PoisonError::into_inner) =
            Some(Instant::now() + runtime.poll_interval());
        Ok(run)
    }

    /// Records a run, only while its instance exists: a run that ends after the instance
    /// was deleted leaves no record behind.
    async fn record_run(
        &self,
        id: ConnectorId,
        run: &LastRun,
        principal: Principal,
        at: Timestamp,
    ) -> Result<(), HostError> {
        for _ in 0..3 {
            let view = self.store.read(ReadConsistency::Local).await?;
            let Some((_, revision)) = view.get_typed(&tables::INSTANCES, &id)? else {
                return Ok(());
            };
            let mut batch = WriteBatch::new(principal.clone(), at);
            batch.expect_typed(&tables::INSTANCES, &id, Some(revision));
            batch.put_typed(&tables::RUNS, &id, run)?;
            match self.store.propose(batch).await {
                Ok(_) => return Ok(()),
                Err(tenko_store::StoreError::PreconditionFailed(_)) => {}
                Err(error) => {
                    tracing::warn!(connector = %id, %error, "the run could not be recorded");
                    return Ok(());
                }
            }
        }
        tracing::warn!(connector = %id, "the run could not be recorded: the instance kept changing");
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Calls.

    /// Builds the context of one call: the settings and the declared secrets, audited
    /// before they are resolved.
    async fn context(
        &self,
        runtime: &Runtime,
        call: &'static str,
        on_behalf_of: Option<UserId>,
    ) -> Result<CallContext, HostError> {
        let instance = runtime.instance();
        let mut secrets = Secrets::new();
        let declared: Vec<(&String, &SecretRef)> = instance
            .secrets
            .iter()
            .filter(|(purpose, _)| {
                runtime
                    .manifest
                    .as_ref()
                    .is_some_and(|manifest| manifest.secret(purpose).is_some())
            })
            .collect();
        if !declared.is_empty() {
            let vault = self.vault.as_ref().ok_or_else(|| {
                HostError::new(
                    "connect.vault_unavailable",
                    503,
                    "this connector service has no vault; the secrets cannot be resolved",
                )
            })?;
            let principal = Principal::System {
                component: SystemComponent::Connector,
                on_behalf_of,
            };
            let mut objects = vec![ObjectRef::from(instance.id)];
            objects.extend(
                declared
                    .iter()
                    .map(|(_, reference)| ObjectRef::from(reference.secret)),
            );
            let mut audit = WriteBatch::new(principal.clone(), Timestamp::now());
            audit.audit(
                AuditDraft::success(actions::SECRET_INJECT, objects)
                    .with_context("plugin", instance.plugin.clone())
                    .with_context(
                        "purposes",
                        declared
                            .iter()
                            .map(|(purpose, _)| purpose.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                    .with_context("call", call),
            );
            self.store.propose(audit).await.map_err(|error| {
                HostError::new(
                    "connect.audit_unavailable",
                    503,
                    format!(
                        "the secret injection could not be audited, so it did not happen: {error}"
                    ),
                )
            })?;
            let ctx = RequestCtx::new(principal);
            for (purpose, reference) in declared {
                let value = vault
                    .get_system(&ctx, *reference)
                    .await
                    .map_err(|error| HostError::coded(&error))?;
                secrets.insert(purpose.clone(), value.into_zeroizing());
            }
        }
        Ok(CallContext {
            instance: Some(instance.id),
            settings: instance.settings,
            secrets,
            request_id: RequestId::generate().to_string(),
        })
    }

    /// The client of a running instance, with a call slot held for the call.
    async fn client(&self, id: ConnectorId) -> Result<(Arc<Runtime>, PluginClient), HostError> {
        let runtime = self.runtime(id).ok_or_else(|| {
            HostError::new(
                "connect.instance.disabled",
                409,
                format!("connector {id} is not enabled on this node"),
            )
        })?;
        let Some(supervisor) = &runtime.supervisor else {
            return Err(HostError(Box::new(runtime.problem.clone().unwrap_or_else(
                || CodedError::new("connect.plugin.unusable", 503, "the plugin cannot run here"),
            ))));
        };
        let client = supervisor.client(self.config.start_wait).await?;
        Ok((Arc::clone(&runtime), client))
    }

    /// Checks the remote system of an instance now and keeps the result as its health.
    /// A remote system that answers with an error is a report (unreachable or degraded);
    /// only a plugin that cannot be asked is an error.
    ///
    /// # Errors
    ///
    /// `connect.instance.disabled`, `connect.plugin.unavailable`, `connect.timeout`, or the
    /// error of resolving the secrets.
    pub async fn check(
        &self,
        id: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> Result<HealthReport, HostError> {
        let outcome = self.check_inner(id, on_behalf_of).await;
        if let Some(runtime) = self.runtime(id) {
            let changed = {
                let mut remote = runtime
                    .remote
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let before = remote_outcome(&remote);
                remote.checked = Some(Instant::now());
                remote.checking = false;
                match &outcome {
                    Ok(report) => {
                        remote.report = Some(report.clone());
                        remote.error = None;
                    }
                    Err(error) => remote.error = Some((*error.0).clone()),
                }
                remote_outcome(&remote) != before
            };
            if changed {
                self.health_changed(id);
            }
        }
        outcome
    }

    async fn check_inner(
        &self,
        id: ConnectorId,
        on_behalf_of: Option<UserId>,
    ) -> Result<HealthReport, HostError> {
        let (runtime, client) = self.client(id).await?;
        let _slot = runtime.calls.acquire().await;
        let ctx = self.context(&runtime, "check", on_behalf_of).await?;
        match client.check(&ctx, runtime.call_timeout()).await {
            Ok(report) => Ok(report),
            Err(error) => calls::fold_into_report(error).map_err(HostError::from),
        }
    }
}

/// The outcome of one read of a plugin.
struct Read {
    observations: u32,
    pages: u32,
    warnings: Vec<String>,
    cursor: Option<String>,
    full: bool,
}

impl ConnectorHost {
    async fn read_once(
        &self,
        runtime: &Runtime,
        previous: Option<&LastRun>,
        on_behalf_of: Option<UserId>,
    ) -> Result<Read, HostError> {
        let (runtime_arc, client) = self.client(runtime.id).await?;
        let _slot = runtime_arc.calls.acquire().await;
        let timeout = runtime.call_timeout();
        let interval = runtime.poll_interval();
        let mut read = Read {
            observations: 0,
            pages: 0,
            warnings: Vec::new(),
            cursor: None,
            full: true,
        };
        if runtime.has(Capability::Inventory) {
            let full_due = previous.and_then(|run| run.last_full_at).is_none_or(|at| {
                Timestamp::now().saturating_since(at) >= self.config.full_poll_interval
            });
            let cursor = if full_due {
                None
            } else {
                previous
                    .and_then(|run| run.cursor.clone())
                    .map(crate::Cursor)
            };
            read.full = cursor.is_none();
            let ctx = self.context(runtime, "poll", on_behalf_of).await?;
            let polled = client.poll(&ctx, cursor, timeout).await?;
            drop(ctx);
            let (batch, warnings) =
                normalize::inventory(runtime.id, &polled.batch, Timestamp::now(), interval);
            read.observations = read
                .observations
                .saturating_add(u32::try_from(batch.observations.len()).unwrap_or(u32::MAX));
            read.pages = u32::try_from(polled.pages).unwrap_or(u32::MAX);
            read.warnings.extend(polled.warnings);
            read.warnings.extend(warnings);
            read.cursor = polled.batch.cursor.map(|cursor| cursor.0);
            self.sink
                .ingest(batch)
                .await
                .map_err(|error| HostError(Box::new(error)))?;
        }
        if runtime.has(Capability::NetworkController) {
            let ctx = self.context(runtime, "topology", on_behalf_of).await?;
            let topology = client.topology(&ctx, timeout).await?;
            drop(ctx);
            let (batch, warnings) =
                normalize::topology(runtime.id, &topology, Timestamp::now(), interval);
            read.observations = read
                .observations
                .saturating_add(u32::try_from(batch.observations.len()).unwrap_or(u32::MAX));
            read.pages = read.pages.saturating_add(1);
            read.warnings.extend(warnings);
            self.sink
                .ingest(batch)
                .await
                .map_err(|error| HostError(Box::new(error)))?;
        }
        Ok(read)
    }
}

/// What a remote check found, as far as the health of the instance shows it: the health
/// of the last report and the code of the last error (time and latency do not count).
fn remote_outcome(remote: &Remote) -> (Option<crate::Health>, Option<String>) {
    (
        remote.report.as_ref().map(|report| report.health),
        remote.error.as_ref().map(|error| error.code.to_string()),
    )
}

/// Waits for the next change set; `false` when the stream ended or failed (it is opened
/// again).
async fn next_change(changes: &mut Option<tenko_store::ChangeStream>) -> bool {
    if let Some(stream) = changes {
        matches!(stream.next().await, Some(Ok(_)))
    } else {
        tokio::time::sleep(Duration::from_secs(5)).await;
        false
    }
}

/// The objects of an instance's audit records: the instance and its secrets.
fn objects(instance: &ConnectorInstance) -> Vec<ObjectRef> {
    let mut objects = vec![ObjectRef::from(instance.id)];
    objects.extend(
        instance
            .secrets
            .values()
            .map(|reference| ObjectRef::from(reference.secret)),
    );
    objects
}

fn purposes(secrets: &BTreeMap<String, SecretRef>) -> String {
    secrets.keys().cloned().collect::<Vec<_>>().join(",")
}

/// The name index key: the name in lower case.
fn name_key(name: &str) -> String {
    name.to_lowercase()
}

fn claim_name(batch: &mut WriteBatch, name: &str, id: ConnectorId) -> Result<(), HostError> {
    batch.expect_typed(&tables::NAMES, &name_key(name), None);
    batch.put_typed(&tables::NAMES, &name_key(name), &id)?;
    Ok(())
}

fn valid_name(name: &str) -> Result<String, HostError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > bounds::MAX_NAME
        || name.chars().any(char::is_control)
    {
        return Err(HostError::invalid(
            "connect.instance.name",
            "name",
            format!(
                "a connector name has 1 to {} characters and no control characters",
                bounds::MAX_NAME
            ),
        ));
    }
    Ok(name.to_owned())
}

fn valid_poll(value: Option<u32>) -> Result<Option<u32>, HostError> {
    match value {
        Some(secs) if !(bounds::MIN_POLL_SECS..=bounds::MAX_POLL_SECS).contains(&secs) => {
            Err(HostError::invalid(
                "connect.instance.poll_interval",
                "poll_interval_secs",
                format!(
                    "the poll interval is {} to {} seconds",
                    bounds::MIN_POLL_SECS,
                    bounds::MAX_POLL_SECS
                ),
            ))
        }
        other => Ok(other),
    }
}

fn valid_timeout(value: Option<u32>) -> Result<Option<u32>, HostError> {
    match value {
        Some(secs) if !(bounds::MIN_CALL_SECS..=bounds::MAX_CALL_SECS).contains(&secs) => {
            Err(HostError::invalid(
                "connect.instance.call_timeout",
                "call_timeout_secs",
                format!(
                    "the call timeout is {} to {} seconds",
                    bounds::MIN_CALL_SECS,
                    bounds::MAX_CALL_SECS
                ),
            ))
        }
        other => Ok(other),
    }
}

/// The audited field changes between two versions of an instance. Secret references are
/// recorded by purpose without values.
fn diff(old: &ConnectorInstance, new: &ConnectorInstance, changes: &mut Vec<FieldChange>) {
    let mut change = |field: &str, before: Option<String>, after: Option<String>| {
        if before != after {
            changes.push(FieldChange {
                object: None,
                field: field.to_owned(),
                old: before,
                new: after,
            });
        }
    };
    change("name", Some(old.name.clone()), Some(new.name.clone()));
    let empty = serde_json::Map::new();
    let old_settings = old.settings.as_object().unwrap_or(&empty);
    let new_settings = new.settings.as_object().unwrap_or(&empty);
    let mut keys: Vec<&String> = old_settings.keys().chain(new_settings.keys()).collect();
    keys.sort();
    keys.dedup();
    for key in keys {
        change(
            &format!("settings.{key}"),
            old_settings.get(key).map(render_value),
            new_settings.get(key).map(render_value),
        );
    }
    let mut purposes: Vec<&String> = old.secrets.keys().chain(new.secrets.keys()).collect();
    purposes.sort();
    purposes.dedup();
    for purpose in purposes {
        change(
            &format!("secrets.{purpose}"),
            old.secrets.get(purpose).map(|r| r.secret.to_string()),
            new.secrets.get(purpose).map(|r| r.secret.to_string()),
        );
    }
    change(
        "poll_interval_secs",
        old.poll_interval_secs.map(|v| v.to_string()),
        new.poll_interval_secs.map(|v| v.to_string()),
    );
    change(
        "call_timeout_secs",
        old.call_timeout_secs.map(|v| v.to_string()),
        new.call_timeout_secs.map(|v| v.to_string()),
    );
    change(
        "writes_enabled",
        Some(old.writes_enabled.to_string()),
        Some(new.writes_enabled.to_string()),
    );
}

fn render_value(value: &serde_json::Value) -> String {
    let text = value.to_string();
    if text.chars().count() <= 200 {
        text
    } else {
        format!("{}...", text.chars().take(200).collect::<String>())
    }
}

fn render_problems(problems: &[ManifestProblem]) -> String {
    problems
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}
