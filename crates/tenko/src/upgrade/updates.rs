//! The in-app update service (OPS-24, TGL-23, R17): the scheduled check of the release
//! source, the stored manifest, the update status, the install job, uploads for air-gapped
//! installations, and the what's-new notes after an upgrade.
//!
//! | Store table | Key | Value |
//! |---|---|---|
//! | `sys.update_manifest` | `()` | the last manifest, where it came from and when ([`StoredManifest`]) |
//! | `sys.update_seen` | user id | the version whose notes the user saw last ([`Seen`]) |
//!
//! A changed manifest is written once, so the journal turns it into one `admin` event for
//! the UI. The check runs only when TGL-23 has it on and `updates.air_gapped` is off; it
//! sends nothing but the running version.
//!
//! An install is a job of kind `sys.update` with the steps of [`super::steps`]: fetch (not
//! for uploads), verify, check and switch. When it succeeds the server restarts through its
//! service manager into the new version, which is on probation ([`super::probation`]).

#![allow(
    clippy::result_large_err,
    reason = "the errors are the CodedError of the API, handed on to problem details as they are"
)]

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures::{StreamExt as _, future::BoxFuture};
use serde::{Deserialize, Serialize};
use tenko_api::{
    dto::{
        release::{
            Release, ReleaseAsset, ReleaseManifest, ReleaseVersion, current_platform,
            parse_changelog,
        },
        updates::{
            AttemptState, CheckOff, InstallAbility, InstallBlock, InstallPolicy, InstallStarted,
            ManifestInfo, ManifestOrigin, UpdateCheck, UpdateStatus, WhatsNew,
        },
    },
    routes::system::updates::{UpdateService, UploadBody},
};
use tenko_auth::settings::{UpdateInstall, UpdatePolicy};
use tenko_core::{
    CodedError, JobId, NodeId, Principal, RequestCtx, SystemComponent, Timestamp, UserId,
    audit::{AuditAction, AuditDetails, AuditDraft},
    table::TableDef,
};
use tenko_jobs::{JobEngine, JobState};
use tenko_store::{
    ReadConsistency, ReadViewExt as _, Store, StoreError, WriteBatch, raft::RaftStore,
};
use tokio::{sync::watch, task::JoinHandle};

use super::{
    layout::Layout,
    probation::{self, Attempt},
    restart::Restart,
    source::{Source, StagedWriter},
    steps,
};
use crate::config::UpdatesSection;

/// The stored manifest.
pub const MANIFEST: TableDef<(), StoredManifest> = TableDef::new("sys.update_manifest");

/// The version whose notes each user saw last.
pub const SEEN: TableDef<UserId, Seen> = TableDef::new("sys.update_seen");

/// The changelog compiled into this binary: the notes of this version and the earlier ones.
const CHANGELOG: &str = include_str!("../../../../CHANGELOG.md");

/// How long the first check waits after the start.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(60);

/// How long the restart after a successful install waits, so that the job's last event
/// reaches the UI.
const RESTART_DELAY: Duration = Duration::from_secs(2);

/// The stored manifest and its origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredManifest {
    /// The manifest.
    pub manifest: ReleaseManifest,
    /// Fetched or uploaded.
    pub origin: ManifestOrigin,
    /// When.
    pub at: Timestamp,
}

/// The version whose notes a user saw last.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// The version.
    pub version: ReleaseVersion,
    /// When.
    pub at: Timestamp,
}

/// TGL-23 and the step-up check, from the authentication service (or a fixed value in
/// tests).
pub trait Policy: Send + Sync + 'static {
    /// The effective TGL-23 value.
    fn policy(&self) -> UpdatePolicy;

    /// Checks that the session of `ctx` authenticated recently enough for an install.
    fn require_fresh<'a>(&'a self, ctx: &'a RequestCtx) -> BoxFuture<'a, Result<(), CodedError>>;
}

impl Policy for tenko_auth::AuthService {
    fn policy(&self) -> UpdatePolicy {
        self.settings().updates()
    }

    fn require_fresh<'a>(&'a self, ctx: &'a RequestCtx) -> BoxFuture<'a, Result<(), CodedError>> {
        Box::pin(async move {
            self.require_fresh_session(ctx)
                .await
                .map_err(|error| CodedError::from_coded(&error))
        })
    }
}

/// The deployment facts the service cannot learn from the store.
#[derive(Debug, Clone)]
pub struct Environment {
    /// The data directory.
    pub data_dir: PathBuf,
    /// This node's Raft id.
    pub node: NodeId,
    /// The running version.
    pub running: ReleaseVersion,
    /// The platform, `<os>-<arch>`.
    pub platform: String,
    /// A service manager restarts the process on exit status 12.
    pub supervised: bool,
    /// The process runs in a container.
    pub container: bool,
    /// The process runs from the `current` link layout.
    pub layout: bool,
}

impl Environment {
    /// The facts of this process.
    pub fn detect(data_dir: PathBuf, node: NodeId, section: &UpdatesSection) -> Self {
        let layout = Layout::new(&data_dir).runs_self();
        Self {
            node,
            running: super::running_version(),
            platform: current_platform(),
            supervised: super::restart::supervised(),
            container: section.in_container(),
            layout,
            data_dir,
        }
    }
}

#[derive(Debug, Default)]
struct CheckState {
    last_checked: Option<Timestamp>,
    last_error: Option<String>,
}

/// What the steps share with the service.
pub(crate) struct Inner {
    pub(crate) env: Environment,
    pub(crate) layout: Layout,
    pub(crate) section: UpdatesSection,
    pub(crate) store: Arc<dyn Store>,
    pub(crate) raft: Option<RaftStore>,
    pub(crate) policy: Arc<dyn Policy>,
    pub(crate) engine: JobEngine,
    pub(crate) restart: Restart,
    pub(crate) source: Source,
    check: Mutex<CheckState>,
    job: Mutex<Option<JobId>>,
    changelog: Vec<Release>,
    cluster: Box<dyn Fn() -> bool + Send + Sync>,
}

/// The update service behind `/system/updates`.
#[derive(Clone)]
pub struct Updates {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Updates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Updates")
            .field("running", &self.inner.env.running)
            .field("layout", &self.inner.env.layout)
            .finish_non_exhaustive()
    }
}

fn store_error(error: &StoreError) -> CodedError {
    CodedError::new(
        "update.store",
        503,
        format!("the store is unavailable: {error}"),
    )
}

fn blocked(reason: InstallBlock) -> CodedError {
    let name = serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    CodedError::new(
        "update.install_blocked",
        409,
        format!("this installation cannot install now: {name}"),
    )
    .with_param("reason", name)
}

/// The settings that the service needs besides its environment.
pub struct Parts {
    /// `[updates]` of `tenko.toml`.
    pub section: UpdatesSection,
    /// The store.
    pub store: Arc<dyn Store>,
    /// The Raft store, for the state copy of the dry run.
    pub raft: Option<RaftStore>,
    /// TGL-23 and step-up.
    pub policy: Arc<dyn Policy>,
    /// The job engine.
    pub engine: JobEngine,
    /// The restart handle of `tenko serve`.
    pub restart: Restart,
    /// Whether the store has more than one voter.
    pub cluster: Box<dyn Fn() -> bool + Send + Sync>,
}

impl Updates {
    /// The service.
    ///
    /// # Errors
    ///
    /// `update.fetch_failed` when the HTTP client cannot be built.
    pub fn new(env: Environment, parts: Parts) -> Result<Self, CodedError> {
        let source = Source::new(&parts.section.source_url)?;
        let changelog = match parse_changelog(CHANGELOG) {
            Ok(sections) => sections
                .iter()
                .filter_map(tenko_api::dto::release::ChangelogSection::to_release)
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "the compiled-in changelog does not parse");
                Vec::new()
            }
        };
        Ok(Self {
            inner: Arc::new(Inner {
                layout: Layout::new(&env.data_dir),
                env,
                section: parts.section,
                store: parts.store,
                raft: parts.raft,
                policy: parts.policy,
                engine: parts.engine,
                restart: parts.restart,
                source,
                check: Mutex::new(CheckState::default()),
                job: Mutex::new(None),
                changelog,
                cluster: parts.cluster,
            }),
        })
    }

    /// Registers the steps of the install job.
    pub fn register_steps(&self, engine: &mut JobEngine) {
        steps::register(engine, &self.inner);
    }

    /// Whether the scheduled check runs, and why not.
    fn check_off(&self) -> Option<CheckOff> {
        if self.inner.section.air_gapped {
            Some(CheckOff::AirGapped)
        } else if !self.inner.policy.policy().check {
            Some(CheckOff::Setting)
        } else {
            None
        }
    }

    /// Runs the scheduled check until `stop`: the first one a minute after the start, then
    /// every `updates.check_interval_hours`.
    pub fn spawn_checks(&self, mut stop: watch::Receiver<bool>) -> JoinHandle<()> {
        let service = self.clone();
        let interval = Duration::from_secs(service.inner.section.check_interval_hours * 3_600);
        tokio::spawn(async move {
            let mut wait = FIRST_CHECK_DELAY;
            loop {
                tokio::select! {
                    _ = stop.wait_for(|stopped| *stopped) => return,
                    () = tokio::time::sleep(wait) => {}
                }
                wait = interval;
                if service.check_off().is_some() {
                    continue;
                }
                if let Err(error) = service.check().await {
                    if service.source_has_answered().await {
                        tracing::warn!(code = %error.code, detail = %error.detail, "the update check failed");
                    } else {
                        tracing::info!(code = %error.code, detail = %error.detail, "the update check failed; no release source has answered yet");
                    }
                }
            }
        })
    }

    /// Whether a release source has answered on this installation: the stored manifest was
    /// fetched, not uploaded. A failed check is a warning only then; before that (a fresh
    /// node, no release published yet) it is expected and logged as a notice. A store that
    /// cannot be read counts as answered, so that the failure is not hidden.
    async fn source_has_answered(&self) -> bool {
        match self.stored_manifest().await {
            Ok(stored) => {
                stored.is_some_and(|(stored, _)| stored.origin == ManifestOrigin::Fetched)
            }
            Err(_) => true,
        }
    }

    /// Asks the source once and stores a changed manifest.
    ///
    /// # Errors
    ///
    /// The fetch or store error (also kept for the status).
    pub async fn check(&self) -> Result<(), CodedError> {
        let result = self.fetch_and_store().await;
        let mut state = self.check_state();
        state.last_checked = Some(Timestamp::now());
        state.last_error = result.as_ref().err().map(|error| error.code.to_string());
        result
    }

    async fn fetch_and_store(&self) -> Result<(), CodedError> {
        let manifest = self.inner.source.manifest().await?;
        let ctx = RequestCtx::system(SystemComponent::Api);
        self.store_manifest(&ctx, manifest, ManifestOrigin::Fetched)
            .await
    }

    fn check_state(&self) -> std::sync::MutexGuard<'_, CheckState> {
        self.inner
            .check
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    async fn stored_manifest(
        &self,
    ) -> Result<Option<(StoredManifest, tenko_core::Revision)>, CodedError> {
        let view = self
            .inner
            .store
            .read(ReadConsistency::Local)
            .await
            .map_err(|error| store_error(&error))?;
        view.get_typed(&MANIFEST, &())
            .map_err(|error| store_error(&error))
    }

    /// Stores `manifest` unless the stored one has the same releases; a new one is one
    /// `admin` event for the UI.
    async fn store_manifest(
        &self,
        ctx: &RequestCtx,
        manifest: ReleaseManifest,
        origin: ManifestOrigin,
    ) -> Result<(), CodedError> {
        let current = self.stored_manifest().await?;
        if let Some((stored, _)) = &current
            && stored.manifest == manifest
            && stored.origin == origin
        {
            return Ok(());
        }
        let latest = manifest
            .latest(self.inner.section.prereleases)
            .map(|release| release.version.to_string());
        let mut batch = WriteBatch::for_request(ctx);
        batch.expect_typed(
            &MANIFEST,
            &(),
            current.as_ref().map(|(_, revision)| *revision),
        );
        batch
            .put_typed(
                &MANIFEST,
                &(),
                &StoredManifest {
                    manifest,
                    origin,
                    at: ctx.now,
                },
            )
            .map_err(|error| store_error(&error))?;
        if origin == ManifestOrigin::Uploaded {
            let mut details = AuditDetails::default();
            if let Some(latest) = &latest {
                details.context.insert("latest".to_owned(), latest.clone());
            }
            batch.audit(AuditDraft {
                details,
                source_ip: ctx.source_ip,
                ..AuditDraft::success(AuditAction::from_static("sys.update.manifest"), Vec::new())
            });
        }
        self.inner
            .store
            .propose(batch)
            .await
            .map_err(|error| store_error(&error))?;
        tracing::info!(latest = ?latest, "stored a new release manifest");
        Ok(())
    }

    /// The releases this binary knows notes for: the compiled-in changelog, then the stored
    /// manifest for versions the changelog lacks.
    fn notes_between(
        &self,
        manifest: Option<&ReleaseManifest>,
        from: &ReleaseVersion,
        to: &ReleaseVersion,
    ) -> Vec<Release> {
        let mut releases: Vec<Release> = self
            .inner
            .changelog
            .iter()
            .filter(|release| &release.version > from && &release.version <= to)
            .cloned()
            .collect();
        if let Some(manifest) = manifest {
            for release in manifest.between(from, to) {
                if !releases
                    .iter()
                    .any(|known| known.version == release.version)
                {
                    releases.push(release.clone());
                }
            }
        }
        releases.sort_by(|a, b| b.version.cmp(&a.version));
        releases
    }

    fn attempt(&self) -> Option<Attempt> {
        probation::read(&self.inner.layout).ok().flatten()
    }

    fn in_progress(&self) -> bool {
        let job = *self
            .inner
            .job
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        job.is_some()
            || self
                .attempt()
                .is_some_and(|attempt| attempt.state == AttemptState::Restarting)
    }

    /// The block shared by both install paths.
    fn structural_block(&self) -> Option<InstallBlock> {
        let env = &self.inner.env;
        if env.container {
            Some(InstallBlock::Container)
        } else if (self.inner.cluster)() {
            Some(InstallBlock::Cluster)
        } else if !env.layout {
            Some(InstallBlock::LayoutMissing)
        } else if !env.supervised {
            Some(InstallBlock::Unsupervised)
        } else if self.in_progress() {
            Some(InstallBlock::InProgress)
        } else {
            None
        }
    }

    /// The status of `GET /system/updates`.
    ///
    /// # Errors
    ///
    /// `update.store` when the store cannot be read.
    pub async fn status_now(&self) -> Result<UpdateStatus, CodedError> {
        let inner = &self.inner;
        let env = &inner.env;
        let stored = self.stored_manifest().await?.map(|(stored, _)| stored);
        let manifest = stored.as_ref().map(|stored| &stored.manifest);
        let prereleases = inner.section.prereleases;
        let releases: Vec<Release> = manifest
            .map(|manifest| {
                manifest
                    .newer_than(&env.running, prereleases)
                    .into_iter()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let latest = manifest
            .and_then(|manifest| manifest.latest(prereleases))
            .map(|release| release.version.clone());
        let policy = inner.policy.policy();
        let off = self.check_off();
        let check_state = self.check_state();
        let check = UpdateCheck {
            enabled: off.is_none(),
            off_reason: off,
            source: inner.source.url().to_owned(),
            interval_hours: u32::try_from(inner.section.check_interval_hours).unwrap_or(u32::MAX),
            last_checked: check_state.last_checked,
            last_error: check_state.last_error.clone(),
        };
        drop(check_state);
        let newest = releases.first();
        let structural = self.structural_block();
        let from_source_blocked = structural
            .or_else(|| (!policy.install.allows_download()).then_some(InstallBlock::UploadOnly))
            .or_else(|| inner.section.air_gapped.then_some(InstallBlock::AirGapped))
            .or_else(|| newest.is_none().then_some(InstallBlock::UpToDate))
            .or_else(|| {
                // No release of the manifest has a file for this platform at all, or only the
                // newest one lacks it.
                let published = manifest.is_some_and(|manifest| {
                    manifest
                        .releases
                        .iter()
                        .any(|release| release.asset(&env.platform).is_some())
                });
                newest
                    .is_some_and(|release| release.asset(&env.platform).is_none())
                    .then_some(if published {
                        InstallBlock::NoAsset
                    } else {
                        InstallBlock::UnsupportedPlatform
                    })
            });
        let pull_command = env.container.then(|| {
            let tag = latest
                .as_ref()
                .map_or_else(|| "latest".to_owned(), ToString::to_string);
            format!("docker pull {}:{tag}", inner.section.image)
        });
        Ok(UpdateStatus {
            running: env.running.clone(),
            format: super::migrations::CURRENT,
            platform: env.platform.clone(),
            update_available: !releases.is_empty(),
            security: releases.iter().any(|release| release.security),
            requires_action: releases.iter().any(|release| release.requires_action),
            latest,
            manifest: stored.as_ref().map(|stored| ManifestInfo {
                origin: stored.origin,
                at: stored.at,
                releases: stored.manifest.releases.len(),
            }),
            releases,
            check,
            install: InstallAbility {
                policy: match policy.install {
                    UpdateInstall::Ui => InstallPolicy::Ui,
                    UpdateInstall::UiStepUp => InstallPolicy::UiStepUp,
                    UpdateInstall::UploadOnly => InstallPolicy::UploadOnly,
                },
                step_up: policy.install.needs_step_up(),
                from_source: from_source_blocked.is_none(),
                from_source_blocked,
                upload: structural.is_none(),
                upload_blocked: structural,
                pull_command,
                ready_timeout_secs: inner.section.ready_timeout_secs,
            },
            attempt: self.attempt().map(|attempt| attempt.to_dto()),
        })
    }

    /// The release and asset of `version` for this platform, newer than the running one.
    async fn release_for(
        &self,
        version: &ReleaseVersion,
    ) -> Result<(Release, ReleaseAsset), CodedError> {
        let stored = self.stored_manifest().await?.map(|(stored, _)| stored);
        let release = stored
            .as_ref()
            .and_then(|stored| stored.manifest.release(version))
            .cloned()
            .ok_or_else(|| {
                CodedError::new(
                    "update.version_unknown",
                    400,
                    format!("the release manifest has no version {version}"),
                )
            })?;
        if release.version <= self.inner.env.running {
            return Err(CodedError::new(
                "update.not_newer",
                400,
                format!(
                    "{version} is not newer than the running version {}",
                    self.inner.env.running
                ),
            ));
        }
        let asset = release
            .asset(&self.inner.env.platform)
            .cloned()
            .ok_or_else(|| blocked(InstallBlock::NoAsset))?;
        Ok((release, asset))
    }

    async fn require_admin_policy(&self, ctx: &RequestCtx) -> Result<UpdatePolicy, CodedError> {
        let policy = self.inner.policy.policy();
        if policy.install.needs_step_up() {
            self.inner.policy.require_fresh(ctx).await?;
        }
        Ok(policy)
    }

    /// Submits the install job, pinned to this controller (it downloaded or received the
    /// release and switches its own binary), and follows it.
    async fn start_job(
        &self,
        ctx: &RequestCtx,
        version: ReleaseVersion,
        asset: ReleaseAsset,
        fetch: bool,
    ) -> Result<InstallStarted, CodedError> {
        let mut spec = steps::job_spec(
            &version,
            &asset,
            fetch,
            self.inner.section.ready_timeout_secs,
        )?;
        spec.node = Some(self.inner.env.node);
        let job_id = self
            .inner
            .engine
            .submit(spec, ctx)
            .await
            .map_err(|error| CodedError::from_coded(&error))?;
        *self
            .inner
            .job
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(job_id);
        let installing = Attempt {
            state: AttemptState::Installing,
            ..Attempt::restarting(
                self.inner.env.running.clone(),
                version.clone(),
                Some(job_id),
                self.inner.section.ready_timeout_secs,
            )
        };
        if let Err(error) = probation::write(&self.inner.layout, &installing) {
            tracing::warn!(%error, "cannot record the install attempt");
        }
        let service = self.clone();
        let target = version.clone();
        tokio::spawn(async move { service.follow(job_id, target).await });
        tracing::info!(%version, job = %job_id, "the install job started");
        Ok(InstallStarted { job_id, version })
    }

    /// Waits for the install job; restarts into the new version when it succeeded.
    async fn follow(&self, job: JobId, version: ReleaseVersion) {
        let state = loop {
            match self.inner.engine.job(job).await {
                Ok(found) if found.state.is_terminal() => break Some(found),
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "cannot read the install job");
                    break None;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        *self
            .inner
            .job
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        match state {
            Some(found) if found.state == JobState::Succeeded => {
                tokio::time::sleep(RESTART_DELAY).await;
                self.inner
                    .restart
                    .request(format!("the update to {version} is installed"));
            }
            Some(found) => {
                let reason = found.error.map_or_else(
                    || "update.job_failed".to_owned(),
                    |error| error.code.to_string(),
                );
                let attempt = Attempt {
                    state: AttemptState::Failed,
                    reason: Some(reason),
                    job_id: Some(job),
                    ..Attempt::restarting(
                        self.inner.env.running.clone(),
                        version,
                        Some(job),
                        self.inner.section.ready_timeout_secs,
                    )
                };
                // A switch that already ran leaves its own record; never overwrite it.
                if self
                    .attempt()
                    .is_none_or(|current| current.state != AttemptState::Restarting)
                    && let Err(error) = probation::write(&self.inner.layout, &attempt)
                {
                    tracing::warn!(%error, "cannot record the failed install");
                }
            }
            None => {}
        }
    }

    /// Writes the audit record of the last attempt's outcome once, from the version that
    /// runs after it (the new one when confirmed, the previous one when switched back).
    pub async fn report_outcome(&self) {
        let layout = &self.inner.layout;
        let Some(mut attempt) = self.attempt() else {
            return;
        };
        let running = &self.inner.env.running;
        let action = match attempt.state {
            AttemptState::Confirmed if &attempt.to == running => "sys.update.confirm",
            AttemptState::RolledBack if &attempt.from == running => "sys.update.rollback",
            _ => return,
        };
        if attempt.reported {
            return;
        }
        let mut details = AuditDetails::default();
        details
            .context
            .insert("from".to_owned(), attempt.from.to_string());
        details
            .context
            .insert("to".to_owned(), attempt.to.to_string());
        if let Some(reason) = &attempt.reason {
            details.context.insert("reason".to_owned(), reason.clone());
        }
        if let Some(job) = attempt.job_id {
            details.context.insert("job".to_owned(), job.to_string());
        }
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Jobs), Timestamp::now());
        batch.audit(AuditDraft {
            details,
            ..AuditDraft::success(AuditAction::from_static(action), Vec::new())
        });
        match self.inner.store.propose(batch).await {
            Ok(_) => {
                attempt.reported = true;
                if let Err(error) = probation::write(layout, &attempt) {
                    tracing::warn!(%error, "cannot mark the update outcome as reported");
                }
            }
            Err(error) => tracing::warn!(%error, "cannot audit the update outcome"),
        }
        if attempt.state == AttemptState::Confirmed {
            let removed = layout.prune(self.inner.section.keep_versions);
            if !removed.is_empty() {
                tracing::info!(?removed, "removed old installed versions");
            }
        }
    }

    async fn upload_now(
        &self,
        ctx: &RequestCtx,
        version: ReleaseVersion,
        mut body: UploadBody,
    ) -> Result<InstallStarted, CodedError> {
        self.require_admin_policy(ctx).await?;
        if let Some(block) = self.structural_block() {
            return Err(blocked(block));
        }
        let (_, asset) = self.release_for(&version).await?;
        let part = steps::staged_path(&self.inner.layout, &version);
        let mut writer = StagedWriter::create(&part, asset.size)?;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|error| {
                let _ = std::fs::remove_file(&part);
                CodedError::new(
                    "update.upload_failed",
                    400,
                    format!("the upload broke off: {error}"),
                )
            })?;
            writer.write(&chunk)?;
        }
        let staged = writer.finish()?;
        if let Err(error) = steps::matches(&staged, &asset) {
            let _ = std::fs::remove_file(&part);
            return Err(error);
        }
        let mut details = AuditDetails::default();
        details
            .context
            .insert("version".to_owned(), version.to_string());
        details
            .context
            .insert("sha256".to_owned(), staged.sha256.clone());
        let mut batch = WriteBatch::for_request(ctx);
        batch.audit(AuditDraft {
            details,
            source_ip: ctx.source_ip,
            ..AuditDraft::success(AuditAction::from_static("sys.update.upload"), Vec::new())
        });
        self.inner
            .store
            .propose(batch)
            .await
            .map_err(|error| store_error(&error))?;
        self.start_job(ctx, version, asset, false).await
    }
}

impl UpdateService for Updates {
    fn status<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<UpdateStatus, CodedError>> {
        Box::pin(self.status_now())
    }

    fn check_now<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<UpdateStatus, CodedError>> {
        Box::pin(async move {
            if let Some(off) = self.check_off() {
                let reason = serde_json::to_value(off)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default();
                return Err(CodedError::new(
                    "update.check_off",
                    409,
                    "the update check is off on this installation",
                )
                .with_param("reason", reason));
            }
            self.check().await?;
            self.status_now().await
        })
    }

    fn put_manifest<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        manifest: ReleaseManifest,
    ) -> BoxFuture<'a, Result<UpdateStatus, CodedError>> {
        Box::pin(async move {
            self.store_manifest(ctx, manifest, ManifestOrigin::Uploaded)
                .await?;
            self.status_now().await
        })
    }

    fn install<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        version: ReleaseVersion,
    ) -> BoxFuture<'a, Result<InstallStarted, CodedError>> {
        Box::pin(async move {
            let policy = self.require_admin_policy(ctx).await?;
            if let Some(block) = self.structural_block() {
                return Err(blocked(block));
            }
            if !policy.install.allows_download() {
                return Err(blocked(InstallBlock::UploadOnly));
            }
            if self.inner.section.air_gapped {
                return Err(blocked(InstallBlock::AirGapped));
            }
            let (_, asset) = self.release_for(&version).await?;
            self.start_job(ctx, version, asset, true).await
        })
    }

    fn upload<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        version: ReleaseVersion,
        body: UploadBody,
    ) -> BoxFuture<'a, Result<InstallStarted, CodedError>> {
        Box::pin(self.upload_now(ctx, version, body))
    }

    fn whats_new<'a>(&'a self, ctx: &'a RequestCtx) -> BoxFuture<'a, Result<WhatsNew, CodedError>> {
        Box::pin(async move {
            let running = self.inner.env.running.clone();
            let Some(user) = ctx.principal.user() else {
                return Ok(WhatsNew {
                    running,
                    last_seen: None,
                    show: false,
                    releases: Vec::new(),
                });
            };
            let view = self
                .inner
                .store
                .read(ReadConsistency::Local)
                .await
                .map_err(|error| store_error(&error))?;
            let last_seen = view
                .get_typed(&SEEN, &user)
                .map_err(|error| store_error(&error))?
                .map(|(seen, _)| seen.version);
            let manifest = view
                .get_typed(&MANIFEST, &())
                .map_err(|error| store_error(&error))?
                .map(|(stored, _)| stored.manifest);
            drop(view);
            let show = last_seen.as_ref().is_some_and(|seen| seen < &running);
            let releases = match (&last_seen, show) {
                (Some(seen), true) => self.notes_between(manifest.as_ref(), seen, &running),
                _ => Vec::new(),
            };
            Ok(WhatsNew {
                running,
                last_seen,
                show,
                releases,
            })
        })
    }

    fn mark_seen<'a>(&'a self, ctx: &'a RequestCtx) -> BoxFuture<'a, Result<(), CodedError>> {
        Box::pin(async move {
            let Some(user) = ctx.principal.user() else {
                return Ok(());
            };
            let mut batch = WriteBatch::for_request(ctx);
            batch
                .put_typed(
                    &SEEN,
                    &user,
                    &Seen {
                        version: self.inner.env.running.clone(),
                        at: ctx.now,
                    },
                )
                .map_err(|error| store_error(&error))?;
            self.inner
                .store
                .propose(batch)
                .await
                .map(drop)
                .map_err(|error| store_error(&error))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tenko_api::dto::release::{ReleaseAsset, ReleaseManifest};
    use tenko_core::{AuthStrength, SessionId};
    use tenko_jobs::EngineConfig;
    use tenko_store::MemStore;

    use super::*;

    struct FixedPolicy {
        policy: UpdatePolicy,
        fresh: bool,
    }

    impl Policy for FixedPolicy {
        fn policy(&self) -> UpdatePolicy {
            self.policy
        }

        fn require_fresh<'a>(
            &'a self,
            _ctx: &'a RequestCtx,
        ) -> BoxFuture<'a, Result<(), CodedError>> {
            Box::pin(async move {
                if self.fresh {
                    Ok(())
                } else {
                    Err(CodedError::new(
                        "auth.step_up_required",
                        403,
                        "a fresh sign-in is needed",
                    ))
                }
            })
        }
    }

    fn version(text: &str) -> ReleaseVersion {
        text.parse().expect("version")
    }

    fn environment(running: &str) -> Environment {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let data_dir = std::env::temp_dir().join(format!(
            "tenko-updates-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        Environment {
            data_dir,
            node: NodeId(1),
            running: version(running),
            platform: "linux-x86_64".to_owned(),
            supervised: true,
            container: false,
            layout: true,
        }
    }

    fn service_with(
        store: &Arc<MemStore>,
        env: Environment,
        install: UpdateInstall,
        fresh: bool,
        section: UpdatesSection,
    ) -> Updates {
        let store_dyn: Arc<dyn Store> = Arc::clone(store) as Arc<dyn Store>;
        let engine = JobEngine::new(Arc::clone(&store_dyn), EngineConfig::default());
        Updates::new(
            env,
            Parts {
                section,
                store: store_dyn,
                raft: None,
                policy: Arc::new(FixedPolicy {
                    policy: UpdatePolicy::new(install),
                    fresh,
                }),
                engine,
                restart: Restart::new(),
                cluster: Box::new(|| false),
            },
        )
        .expect("service")
    }

    fn section() -> UpdatesSection {
        UpdatesSection {
            source_url: "http://127.0.0.1:9/releases.json".to_owned(),
            ..UpdatesSection::default()
        }
    }

    fn service(store: &Arc<MemStore>, install: UpdateInstall, fresh: bool) -> Updates {
        service_with(store, environment("0.1.0"), install, fresh, section())
    }

    fn manifest() -> ReleaseManifest {
        let asset = ReleaseAsset {
            platform: "linux-x86_64".to_owned(),
            name: "tenko-0.2.0-linux-x86_64".to_owned(),
            url: "tenko-0.2.0-linux-x86_64".to_owned(),
            sha256: "a".repeat(64),
            size: 1_024,
            signature: None,
        };
        let release = |text: &str, security: bool, notes: &str| Release {
            version: version(text),
            date: "2026-11-01".to_owned(),
            notes: notes.to_owned(),
            security,
            requires_action: false,
            action: None,
            format: Some(1),
            assets: vec![ReleaseAsset {
                name: format!("tenko-{text}-linux-x86_64"),
                url: format!("tenko-{text}-linux-x86_64"),
                ..asset.clone()
            }],
            image: None,
        };
        ReleaseManifest {
            schema: 1,
            project: "tenko".to_owned(),
            releases: vec![
                release("0.2.0", true, "### Security\n\n- A fix."),
                release("0.1.0", false, "### Added\n\n- The first release."),
            ],
        }
    }

    fn admin() -> RequestCtx {
        RequestCtx::new(Principal::User {
            id: UserId::generate(),
            session: SessionId::generate(),
            strength: AuthStrength::Password,
        })
    }

    #[test]
    fn the_compiled_in_changelog_parses() {
        let sections = parse_changelog(CHANGELOG).expect("CHANGELOG.md parses");
        // Right after a release cut the Unreleased section is empty, so it is the running
        // version's section that must list changes.
        let running: ReleaseVersion = env!("CARGO_PKG_VERSION")
            .parse()
            .expect("the crate's version is a release version");
        let own = sections
            .iter()
            .find(|section| section.version.as_ref() == Some(&running))
            .expect("CHANGELOG.md has the running version's section");
        assert!(own.entries > 0, "the running version's section lists changes");
    }

    #[tokio::test]
    async fn a_stored_manifest_offers_the_newer_release() {
        let store = Arc::new(MemStore::default());
        let updates = service(&store, UpdateInstall::Ui, true);
        let empty = updates.status_now().await.expect("status");
        assert!(!empty.update_available);
        assert_eq!(
            empty.install.from_source_blocked,
            Some(InstallBlock::UpToDate)
        );
        assert!(empty.manifest.is_none());

        let ctx = admin();
        updates
            .put_manifest(&ctx, manifest())
            .await
            .expect("upload");
        let revision = store.status().revision;
        updates.put_manifest(&ctx, manifest()).await.expect("again");
        assert_eq!(
            store.status().revision,
            revision,
            "the same manifest is not written twice"
        );
        let status = updates.status_now().await.expect("status");
        assert!(status.update_available);
        assert!(status.security);
        assert_eq!(status.latest, Some(version("0.2.0")));
        assert_eq!(
            status.releases.len(),
            1,
            "only releases newer than the running one"
        );
        assert!(status.install.from_source, "{:?}", status.install);
        assert!(status.install.upload);
        assert!(!status.install.step_up);
        assert_eq!(
            status.manifest.map(|info| info.origin),
            Some(ManifestOrigin::Uploaded)
        );
    }

    #[tokio::test]
    async fn a_failed_check_is_a_warning_only_once_a_source_has_answered() {
        let store = Arc::new(MemStore::default());
        let updates = service(&store, UpdateInstall::Ui, true);
        let ctx = admin();
        assert!(
            !updates.source_has_answered().await,
            "a fresh node has seen no manifest"
        );
        let error = updates
            .check()
            .await
            .expect_err("nothing listens on port 9");
        assert_eq!(error.code, "update.fetch_failed");
        assert!(!updates.source_has_answered().await);
        updates
            .put_manifest(&ctx, manifest())
            .await
            .expect("upload");
        assert!(
            !updates.source_has_answered().await,
            "an uploaded manifest is not an answer of the source"
        );
        updates
            .store_manifest(&ctx, manifest(), ManifestOrigin::Fetched)
            .await
            .expect("fetched");
        assert!(updates.source_has_answered().await);
        assert!(
            updates.check().await.is_err(),
            "the code and the detail of the failure are kept"
        );
    }

    #[tokio::test]
    async fn installs_from_the_ui_are_refused_on_a_cluster() {
        let store = Arc::new(MemStore::default());
        let store_dyn: Arc<dyn Store> = Arc::clone(&store) as Arc<dyn Store>;
        let engine = JobEngine::new(Arc::clone(&store_dyn), EngineConfig::default());
        let updates = Updates::new(
            environment("0.1.0"),
            Parts {
                section: section(),
                store: store_dyn,
                raft: None,
                policy: Arc::new(FixedPolicy {
                    policy: UpdatePolicy::new(UpdateInstall::Ui),
                    fresh: true,
                }),
                engine,
                restart: Restart::new(),
                cluster: Box::new(|| true),
            },
        )
        .expect("service");
        let ctx = admin();
        updates
            .put_manifest(&ctx, manifest())
            .await
            .expect("upload");
        let status = updates.status_now().await.expect("status");
        assert_eq!(
            status.install.from_source_blocked,
            Some(InstallBlock::Cluster)
        );
        let error = updates
            .install(&ctx, version("0.2.0"))
            .await
            .expect_err("a cluster");
        assert_eq!(error.code, "update.install_blocked");
        assert_eq!(
            error.params.get("reason").map(String::as_str),
            Some("cluster")
        );
    }

    #[tokio::test]
    async fn the_policy_and_the_deployment_block_installs() {
        let store = Arc::new(MemStore::default());
        let ctx = admin();
        let upload_only = service(&store, UpdateInstall::UploadOnly, true);
        upload_only
            .put_manifest(&ctx, manifest())
            .await
            .expect("upload");
        let status = upload_only.status_now().await.expect("status");
        assert_eq!(
            status.install.from_source_blocked,
            Some(InstallBlock::UploadOnly)
        );
        assert!(status.install.upload);
        assert!(status.install.step_up);
        let error = upload_only
            .install(&ctx, version("0.2.0"))
            .await
            .expect_err("upload only");
        assert_eq!(error.code, "update.install_blocked");
        assert_eq!(
            error.params.get("reason").map(String::as_str),
            Some("upload_only")
        );

        let stale = service(&store, UpdateInstall::UiStepUp, false);
        let error = stale
            .install(&ctx, version("0.2.0"))
            .await
            .expect_err("step-up");
        assert_eq!(error.code, "auth.step_up_required");

        let container = service_with(
            &store,
            Environment {
                container: true,
                ..environment("0.1.0")
            },
            UpdateInstall::Ui,
            true,
            section(),
        );
        let status = container.status_now().await.expect("status");
        assert_eq!(
            status.install.from_source_blocked,
            Some(InstallBlock::Container)
        );
        assert_eq!(status.install.upload_blocked, Some(InstallBlock::Container));
        assert_eq!(
            status.install.pull_command.as_deref(),
            Some("docker pull ghcr.io/linkztream/tenko:0.2.0")
        );

        for (env, block) in [
            (
                Environment {
                    layout: false,
                    ..environment("0.1.0")
                },
                InstallBlock::LayoutMissing,
            ),
            (
                Environment {
                    supervised: false,
                    ..environment("0.1.0")
                },
                InstallBlock::Unsupervised,
            ),
            (
                Environment {
                    platform: "linux-riscv64".to_owned(),
                    ..environment("0.1.0")
                },
                InstallBlock::UnsupportedPlatform,
            ),
        ] {
            let updates = service_with(&store, env, UpdateInstall::Ui, true, section());
            let status = updates.status_now().await.expect("status");
            assert_eq!(status.install.from_source_blocked, Some(block));
        }

        let air_gapped = service_with(
            &store,
            environment("0.1.0"),
            UpdateInstall::Ui,
            true,
            UpdatesSection {
                air_gapped: true,
                ..section()
            },
        );
        let status = air_gapped.status_now().await.expect("status");
        assert_eq!(status.check.off_reason, Some(CheckOff::AirGapped));
        assert_eq!(
            status.install.from_source_blocked,
            Some(InstallBlock::AirGapped)
        );
        let error = air_gapped.check_now(&ctx).await.expect_err("air-gapped");
        assert_eq!(error.code, "update.check_off");
    }

    #[tokio::test]
    async fn installs_name_a_known_newer_version_and_start_a_job() {
        let store = Arc::new(MemStore::default());
        let updates = service(&store, UpdateInstall::Ui, true);
        let mut engine = updates.inner.engine.clone();
        updates.register_steps(&mut engine);
        let ctx = admin();
        updates
            .put_manifest(&ctx, manifest())
            .await
            .expect("upload");
        let unknown = updates
            .install(&ctx, version("9.9.9"))
            .await
            .expect_err("unknown");
        assert_eq!(unknown.code, "update.version_unknown");
        let older = updates
            .install(&ctx, version("0.1.0"))
            .await
            .expect_err("not newer");
        assert_eq!(older.code, "update.not_newer");
        let started = updates
            .install(&ctx, version("0.2.0"))
            .await
            .expect("started");
        assert_eq!(started.version, version("0.2.0"));
        let job = updates.inner.engine.job(started.job_id).await.expect("job");
        let kinds: Vec<String> = job
            .spec
            .steps
            .iter()
            .map(|step| step.kind.as_str().to_owned())
            .collect();
        assert_eq!(
            kinds,
            [steps::FETCH, steps::VERIFY, steps::CHECK, steps::SWITCH]
        );
        assert_eq!(job.spec.node, Some(NodeId(1)), "pinned to this controller");
        let status = updates.status_now().await.expect("status");
        assert_eq!(
            status.install.from_source_blocked,
            Some(InstallBlock::InProgress)
        );
        let again = updates
            .install(&ctx, version("0.2.0"))
            .await
            .expect_err("one at a time");
        assert_eq!(again.code, "update.install_blocked");
    }

    #[tokio::test]
    async fn whats_new_shows_the_notes_once_per_user_after_an_upgrade() {
        let store = Arc::new(MemStore::default());
        let ctx = admin();
        let before = service(&store, UpdateInstall::Ui, true);
        before.put_manifest(&ctx, manifest()).await.expect("upload");
        let first = before.whats_new(&ctx).await.expect("what is new");
        assert_eq!(first.last_seen, None);
        assert!(!first.show, "a user who saw nothing yet starts from here");
        before.mark_seen(&ctx).await.expect("seen");
        assert!(!before.whats_new(&ctx).await.expect("again").show);

        // The same store after an upgrade to 0.2.0.
        let after = service_with(
            &store,
            environment("0.2.0"),
            UpdateInstall::Ui,
            true,
            section(),
        );
        let shown = after.whats_new(&ctx).await.expect("what is new");
        assert!(shown.show);
        assert_eq!(shown.last_seen, Some(version("0.1.0")));
        let versions: Vec<String> = shown
            .releases
            .iter()
            .map(|release| release.version.to_string())
            .collect();
        assert_eq!(versions, ["0.2.0"]);
        after.mark_seen(&ctx).await.expect("seen");
        assert!(!after.whats_new(&ctx).await.expect("once").show);
        // Another user has their own record.
        assert_eq!(
            after.whats_new(&admin()).await.expect("other").last_seen,
            None
        );
    }
}
