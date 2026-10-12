//! The backup service of `tenko serve` (ADR 0016 items 5, 7 and 9): backups through the API,
//! the settings, the status with its warnings, the schedule as the leader service
//! `backup.schedule`, and the record of a restore at the first start.
//!
//! A backup through the API or the schedule is written by the controller that runs it, into
//! its target directory, and then recorded with the inline job `backup.create`: its one step
//! `backup.record` stages the record in `backup.runs` with the audit record
//! `sys.backup.create`, so the record, the job and the audit commit in one write. A backup
//! that fails is recorded and audited as failed without a job. A scheduled backup's record
//! carries the leader epoch as a precondition, so a deposed leader cannot record one.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tenko_api::{
    dto::{
        backup::{
            BackupFailure, BackupOutcome, BackupReason, BackupRunView, BackupSettingsUpdate,
            BackupSettingsView, BackupStatusView, BackupSummaryView, RestoreNoticeView,
        },
        system::StatusWarning,
    },
    routes::backup::BackupService as BackupApi,
};
use tenko_auth::{model::INSTALLATION, settings::Profile};
use tenko_core::{
    Coded, CodedError, MessageKey, NodeId, RequestCtx, Revision, SystemComponent, Timestamp,
    audit::AuditDraft,
    cluster::{LEADER_EPOCH, LeaderService},
    codec::{from_cbor, to_cbor},
    serde_util::HexBytes,
};
use tenko_jobs::{
    JobEngine, JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome,
    StepPreview, StepSpec,
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadView, ReadViewExt as _, Store, StoreError, WriteBatch,
    raft::RaftStore,
};
use tenko_vault::StoreVault;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    BackupError,
    archive::{KdfParams, OriginRecord},
    create::{self, Extras, KeyLock, Target},
    keys::{Recipient, check_passphrase},
    model::{
        BackupRun, BackupSettings, MAX_INTERVAL_HOURS, MAX_KEEP, RestoreRecord, RunError,
        RunReason, actions, system_object, tables,
    },
    restore,
};

/// The job kind of a recorded backup.
pub const JOB_KIND: &str = "backup.create";
/// Its one step.
pub const STEP_KIND: &str = "backup.record";
/// The message key of the job title.
pub const JOB_TITLE: &str = "backup.job.create";
/// The message key of the step preview.
pub const STEP_PREVIEW: &str = "backup.job.record_preview";
/// The name of the leader service.
pub const SCHEDULE: &str = "backup.schedule";
/// How old the last good backup may be before Standard and Hardened warn.
pub const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
/// How often the schedule looks at the settings.
const TICK: Duration = Duration::from_secs(60);
/// How many records the status lists.
const RECENT: usize = 20;

/// The configuration file `tenko serve` was started with, for backups that include it.
static CONFIG_FILE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();

/// Remembers the configuration file of `tenko serve` (its `--config` or `TENKO_CONFIG`);
/// the first call wins.
pub fn remember_config_file(file: Option<PathBuf>) {
    let _ = CONFIG_FILE.set(file);
}

/// What the service needs from the server.
pub struct Config {
    /// This controller.
    pub node: NodeId,
    /// The data directory.
    pub data_dir: PathBuf,
    /// The default target directory of this host (`[backup] target_dir` or
    /// `<data_dir>/backups`).
    pub host_target: PathBuf,
    /// The imported TLS files (mode b).
    pub tls: Option<(PathBuf, PathBuf)>,
    /// The configuration file the server runs with.
    pub config_file: Option<PathBuf>,
    /// The Argon2id parameters of passphrase slots.
    pub kdf: KdfParams,
}

impl Config {
    /// The configuration of a controller as `tenko serve` resolved it.
    pub fn of(resolved: &crate::config::Resolved) -> Self {
        let tls = match &resolved.tls {
            crate::config::TlsSpec::Imported {
                cert_path,
                key_path,
            } => Some((cert_path.clone(), key_path.clone())),
            _ => None,
        };
        Self {
            node: resolved.node_id,
            data_dir: resolved.data_dir.clone(),
            host_target: resolved.backup_dir(),
            tls,
            config_file: CONFIG_FILE.get().cloned().flatten(),
            kdf: KdfParams::HARDENED,
        }
    }
}

/// The backup service of one controller.
pub struct BackupService {
    store: RaftStore,
    shared: Arc<dyn Store>,
    vault: Arc<StoreVault>,
    engine: JobEngine,
    config: Config,
    running: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for BackupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupService")
            .field("node", &self.config.node)
            .finish_non_exhaustive()
    }
}

/// An error as the API answers it (boxed: it is large).
type Failure = Box<CodedError>;

#[allow(
    clippy::unnecessary_box_returns,
    reason = "the boxed error keeps the results of the service small"
)]
fn coded(error: &(impl Coded + ?Sized)) -> Failure {
    Box::new(error.to_coded_error())
}

#[allow(
    clippy::unnecessary_box_returns,
    reason = "the boxed error keeps the results of the service small"
)]
fn store_error(error: &StoreError) -> Failure {
    coded(error)
}

impl BackupService {
    /// The service; registers the step `backup.record` with the job engine.
    pub fn new(
        store: RaftStore,
        vault: Arc<StoreVault>,
        engine: &JobEngine,
        config: Config,
    ) -> Arc<Self> {
        let mut engine = engine.clone();
        engine.register(Arc::new(RecordStep));
        Arc::new(Self {
            shared: Arc::new(store.clone()),
            store,
            vault,
            engine,
            config,
            running: tokio::sync::Mutex::new(()),
        })
    }

    async fn view(&self) -> Result<Arc<dyn ReadView>, StoreError> {
        self.shared.read(ReadConsistency::Local).await
    }

    fn target_dir(&self, settings: &BackupSettings) -> PathBuf {
        settings
            .target_dir
            .as_ref()
            .map_or_else(|| self.config.host_target.clone(), PathBuf::from)
    }

    /// Writes and records one backup; `epoch` fences the record of a scheduled one.
    async fn run(
        &self,
        ctx: &RequestCtx,
        reason: RunReason,
        passphrase: Option<Zeroizing<String>>,
        epoch: Option<u64>,
    ) -> Result<BackupRunView, Failure> {
        let Ok(_guard) = self.running.try_lock() else {
            return Err(coded(&BackupError::Running));
        };
        let view = self.view().await.map_err(|error| store_error(&error))?;
        let settings = read_settings(view.as_ref())
            .map_err(|error| store_error(&error))?
            .map(|(settings, _)| settings)
            .unwrap_or_default();
        drop(view);
        let mut locks = Vec::new();
        if let Some(recipient) = &settings.recipient {
            let recipient = Recipient::parse(recipient).map_err(|error| coded(&error))?;
            locks.push(KeyLock::Recipient(recipient));
        }
        if let Some(passphrase) = passphrase {
            check_passphrase(&passphrase).map_err(|error| coded(&error))?;
            locks.push(KeyLock::Passphrase(passphrase));
        }
        if locks.is_empty() {
            return Err(coded(&BackupError::NoKey(
                "set a recipient in the backup settings or give a passphrase".to_owned(),
            )));
        }
        let slots: Vec<String> = locks
            .iter()
            .map(|lock| match lock {
                KeyLock::Passphrase(_) => "passphrase".to_owned(),
                KeyLock::Recipient(_) => "recipient".to_owned(),
            })
            .collect();
        let target_dir = self.target_dir(&settings);
        let started_at = Timestamp::now();
        let by = ctx.principal.subject();
        let request = create::Request {
            locks,
            kdf: self.config.kdf,
            origin: OriginRecord {
                reason: reason.as_str().to_owned(),
                by: by.clone(),
            },
            extras: Extras {
                tls: self.config.tls.clone(),
                config: if settings.include_config {
                    self.config.config_file.clone()
                } else {
                    None
                },
            },
            target: Target::Dir(target_dir.clone()),
        };
        let ring = self.vault.ring();
        let written = create::from_live(&self.store, &ring, request).await;
        drop(ring);
        let run = BackupRun {
            reason,
            node: self.config.node.0,
            target_dir: target_dir.display().to_string(),
            file: None,
            bytes: None,
            revision: None,
            slots,
            started_at,
            finished_at: Timestamp::now(),
            by,
            job: None,
            error: None,
        };
        self.finish_run(ctx, run, written, epoch).await
    }

    /// Records a written backup through the inline job, or a failed one directly.
    async fn finish_run(
        &self,
        ctx: &RequestCtx,
        mut run: BackupRun,
        written: Result<create::Created, BackupError>,
        epoch: Option<u64>,
    ) -> Result<BackupRunView, Failure> {
        let id = Uuid::now_v7();
        match written {
            Ok(created) => {
                run.file = Some(created.file_name());
                run.bytes = Some(created.bytes);
                run.revision = Some(created.manifest.revision);
                tracing::info!(
                    file = %created.path.display(),
                    bytes = created.bytes,
                    revision = created.manifest.revision,
                    "backup written"
                );
                let params = RecordParams {
                    id,
                    run: run.clone(),
                    epoch,
                };
                let job = match self.record_job(ctx, &params).await {
                    Ok(job) => job,
                    Err(error) => {
                        // An unrecorded backup would be invisible to the status and the keep
                        // count (a deposed leader's, for one): it goes again.
                        let _ = std::fs::remove_file(&created.path);
                        return Err(error);
                    }
                };
                run.job = Some(job);
                Ok(run_view(id, &run))
            }
            Err(error) => {
                tracing::warn!(%error, "backup failed");
                run.error = Some(RunError {
                    code: error.code().to_owned(),
                    detail: error.to_string(),
                });
                let mut batch = record_batch(ctx, id, &run, epoch, Some(&error));
                if let Ok(view) = self.view().await {
                    purge_runs(view.as_ref(), &mut batch);
                }
                if let Err(record_error) = self.shared.propose(batch).await {
                    tracing::warn!(%record_error, "the failed backup could not be recorded");
                }
                Err(coded(&error))
            }
        }
    }

    async fn record_job(
        &self,
        ctx: &RequestCtx,
        params: &RecordParams,
    ) -> Result<tenko_core::JobId, Failure> {
        let encoded = to_cbor(params).map_err(|error| coded(&error))?;
        let spec = JobSpec {
            kind: JobKind::from_static(JOB_KIND),
            title: MessageKey::from_static(JOB_TITLE),
            targets: vec![system_object()],
            steps: vec![StepSpec {
                kind: StepKind::from_static(STEP_KIND),
                params: HexBytes(encoded.to_vec()),
                timeout: None,
            }],
            timeout: Duration::from_secs(30),
            group: None,
            group_limit: None,
            idempotency: None,
            node: None,
        };
        let job = self
            .engine
            .run_inline(spec, ctx)
            .await
            .map_err(|error| match error {
                tenko_jobs::JobError::Store(store) => coded(&store),
                other => coded(&other),
            })?;
        Ok(job.id)
    }

    async fn status_view(&self) -> Result<BackupStatusView, StoreError> {
        let view = self.view().await?;
        let (settings, revision) = match read_settings(view.as_ref())? {
            Some((settings, revision)) => (settings, Some(revision)),
            None => (BackupSettings::default(), None),
        };
        let recent = recent_runs(view.as_ref())?;
        let restored = view
            .get_typed(&tables::RESTORE, &())?
            .map(|(record, _)| record);
        let profile = view
            .get_typed(&tenko_auth::model::SETTINGS, &())?
            .map(|(settings, _)| settings.profile);
        let setup = view
            .get_typed(&INSTALLATION, &())?
            .map(|(installation, _)| installation.completed_at);
        drop(view);
        let now = Timestamp::now();
        let last_good = recent.iter().find(|(_, run)| run.is_good()).cloned();
        let last_failed = recent
            .iter()
            .find(|(_, run)| !run.is_good())
            .filter(|(_, failed)| {
                last_good
                    .as_ref()
                    .is_none_or(|(_, good)| failed.finished_at > good.finished_at)
            })
            .cloned();
        let age_seconds = last_good
            .as_ref()
            .map(|(_, run)| seconds_between(run.finished_at, now));
        let next_due_at = settings
            .enabled
            .then(|| next_due(&recent, settings.interval_hours, now));
        let restored = restored.filter(|record| {
            last_good
                .as_ref()
                .is_none_or(|(_, good)| good.finished_at < record.started_at)
        });
        let warnings = warnings(
            profile,
            setup,
            last_good.as_ref().map(|(_, run)| run),
            last_failed.as_ref().map(|(_, run)| run),
            restored.as_ref(),
            now,
        );
        Ok(BackupStatusView {
            settings: self.settings_view(&settings, revision),
            last_good: last_good.as_ref().map(|(id, run)| run_view(*id, run)),
            last_failed: last_failed.as_ref().map(|(id, run)| run_view(*id, run)),
            age_seconds,
            next_due_at,
            running: self.running.try_lock().is_err(),
            recent: recent.iter().map(|(id, run)| run_view(*id, run)).collect(),
            restored: restored.as_ref().map(restore_view),
            warnings,
        })
    }

    fn settings_view(
        &self,
        settings: &BackupSettings,
        revision: Option<Revision>,
    ) -> BackupSettingsView {
        BackupSettingsView {
            enabled: settings.enabled,
            interval_hours: settings.interval_hours,
            keep: settings.keep,
            target_dir: settings.target_dir.clone(),
            recipient: settings.recipient.clone(),
            include_config: settings.include_config,
            effective_target_dir: self.target_dir(settings).display().to_string(),
            revision,
        }
    }

    async fn store_settings(
        &self,
        ctx: &RequestCtx,
        update: BackupSettingsUpdate,
        expect: Option<Revision>,
    ) -> Result<BackupSettingsView, Failure> {
        let settings = validate(update).map_err(|error| coded(&error))?;
        let view = self.view().await.map_err(|error| store_error(&error))?;
        let current = read_settings(view.as_ref()).map_err(|error| store_error(&error))?;
        drop(view);
        let mut batch = WriteBatch::for_request(ctx);
        let current_revision = current.as_ref().map(|(_, revision)| *revision);
        batch.expect_typed(&tables::SETTINGS, &(), expect.or(current_revision));
        if expect.is_some() && expect != current_revision {
            return Err(coded(&StoreError::PreconditionFailed(Vec::new())));
        }
        batch
            .put_typed(&tables::SETTINGS, &(), &settings)
            .map_err(|error| store_error(&error))?;
        let mut draft = AuditDraft::success(actions::SETTINGS, vec![system_object()]);
        draft.details.context = settings_context(&settings);
        batch.audit(draft);
        let committed = self
            .shared
            .propose(batch)
            .await
            .map_err(|error| store_error(&error))?;
        Ok(self.settings_view(&settings, Some(committed.revision)))
    }

    /// The summary for `/system/status`.
    async fn summary_view(&self) -> (Option<BackupSummaryView>, Vec<StatusWarning>) {
        match self.status_view().await {
            Ok(status) => (
                Some(BackupSummaryView {
                    schedule_enabled: status.settings.enabled,
                    last_good_at: status.last_good.as_ref().map(|run| run.finished_at),
                    age_seconds: status.age_seconds,
                    last_failed_at: status.last_failed.as_ref().map(|run| run.finished_at),
                    restored_at: status.restored.as_ref().map(|notice| notice.restored_at),
                }),
                status.warnings,
            ),
            Err(error) => {
                tracing::debug!(%error, "the backup status could not be read");
                (None, Vec::new())
            }
        }
    }

    /// The leader service `backup.schedule`.
    pub fn schedule(self: &Arc<Self>) -> Arc<dyn LeaderService> {
        Arc::new(Schedule(Arc::clone(self)))
    }

    /// Records the restore notice the restore left in the data directory (the first start
    /// after a restore) and removes the file.
    ///
    /// # Errors
    ///
    /// The store's error; the file then stays for the next start.
    pub async fn record_restore(&self) -> Result<Option<RestoreRecord>, BackupError> {
        let Some(notice) = restore::take_notice(&self.config.data_dir)? else {
            return Ok(None);
        };
        let record = RestoreRecord {
            restored_at: notice.restored_at,
            started_at: Timestamp::now(),
            backup_created_at: notice.backup_created_at,
            file: notice.file,
            source_node: notice.source_node,
            source_voters: notice.source_voters,
            revision: notice.revision,
            node: self.config.node.0,
        };
        let ctx = RequestCtx::system(SystemComponent::Backup);
        let mut batch = WriteBatch::for_request(&ctx);
        batch.put_typed(&tables::RESTORE, &(), &record)?;
        let mut draft = AuditDraft::success(actions::RESTORE, vec![system_object()]);
        draft.details.context = BTreeMap::from([
            ("file".to_owned(), record.file.clone()),
            ("revision".to_owned(), record.revision.to_string()),
            ("source_node".to_owned(), record.source_node.to_string()),
            (
                "backup_created_at".to_owned(),
                record.backup_created_at.to_string(),
            ),
        ]);
        batch.audit(draft);
        self.shared.propose(batch).await?;
        restore::clear_notice(&self.config.data_dir);
        tracing::warn!(
            file = %record.file,
            revision = record.revision,
            "this installation was restored from a backup; take a new backup"
        );
        Ok(Some(record))
    }

    /// Deletes the oldest backup files of `dir` beyond `keep`; only names this module writes.
    fn prune(dir: &Path, keep: u32) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| create::is_backup_name(name))
            .collect();
        names.sort();
        let keep = usize::try_from(keep).unwrap_or(usize::MAX);
        let excess = names.len().saturating_sub(keep);
        let mut removed = 0;
        for name in names.into_iter().take(excess) {
            match std::fs::remove_file(dir.join(&name)) {
                Ok(()) => removed += 1,
                Err(error) => {
                    tracing::warn!(%error, file = %name, "an old backup could not be deleted");
                }
            }
        }
        removed
    }

    /// One look of the schedule: a backup when one is due.
    async fn tick(&self, epoch: u64) -> Result<(), String> {
        let view = self.view().await.map_err(|error| error.to_string())?;
        let Some((settings, _)) =
            read_settings(view.as_ref()).map_err(|error| error.to_string())?
        else {
            return Ok(());
        };
        if !settings.enabled || settings.recipient.is_none() {
            return Ok(());
        }
        let recent = recent_runs(view.as_ref()).map_err(|error| error.to_string())?;
        drop(view);
        let now = Timestamp::now();
        if next_due(&recent, settings.interval_hours, now) > now {
            return Ok(());
        }
        let ctx = RequestCtx::system(SystemComponent::Backup);
        match self
            .run(&ctx, RunReason::Scheduled, None, Some(epoch))
            .await
        {
            Ok(run) => {
                let removed = Self::prune(Path::new(&run.target_dir), settings.keep);
                if removed > 0 {
                    tracing::info!(removed, "old backups deleted (keep {})", settings.keep);
                }
                Ok(())
            }
            Err(error) if error.code == "backup.running" => Ok(()),
            Err(error) => {
                // Recorded as failed; the schedule tries again after an hour.
                tracing::warn!(code = %error.code, detail = %error.detail, "scheduled backup failed");
                Ok(())
            }
        }
    }
}

impl BackupApi for BackupService {
    fn status<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFuture<'a, Result<BackupStatusView, CodedError>> {
        Box::pin(async move {
            self.status_view()
                .await
                .map_err(|error| error.to_coded_error())
        })
    }

    fn create<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        passphrase: Option<String>,
    ) -> BoxFuture<'a, Result<BackupRunView, CodedError>> {
        Box::pin(async move {
            let passphrase = passphrase.map(Zeroizing::new);
            self.run(ctx, RunReason::Manual, passphrase, None)
                .await
                .map_err(|error| *error)
        })
    }

    fn update_settings<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        update: BackupSettingsUpdate,
        expect: Option<Revision>,
    ) -> BoxFuture<'a, Result<BackupSettingsView, CodedError>> {
        Box::pin(async move {
            self.store_settings(ctx, update, expect)
                .await
                .map_err(|error| *error)
        })
    }

    fn summary(&self) -> BoxFuture<'_, (Option<BackupSummaryView>, Vec<StatusWarning>)> {
        Box::pin(self.summary_view())
    }
}

/// The leader service: looks at the settings every minute and writes a backup when one is
/// due.
struct Schedule(Arc<BackupService>);

#[async_trait::async_trait]
impl LeaderService for Schedule {
    fn name(&self) -> &'static str {
        SCHEDULE
    }

    async fn run(&self, epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                _ = tick.tick() => {}
            }
            if let Err(error) = self.0.tick(epoch).await {
                tracing::warn!(%error, "the backup schedule could not run");
            }
        }
    }
}

fn read_settings(view: &dyn ReadView) -> Result<Option<(BackupSettings, Revision)>, StoreError> {
    view.get_typed(&tables::SETTINGS, &())
}

/// The newest records, newest first.
fn recent_runs(view: &dyn ReadView) -> Result<Vec<(Uuid, BackupRun)>, StoreError> {
    Ok(view
        .scan_typed(&tables::RUNS, KeyRange::all(), RECENT, true)?
        .into_iter()
        .map(|(id, run, _)| (id, run))
        .collect())
}

/// When the next scheduled backup is due: the interval after the last good scheduled one
/// (at once without one), but no sooner than an hour after a scheduled backup that failed.
fn next_due(recent: &[(Uuid, BackupRun)], interval_hours: u32, now: Timestamp) -> Timestamp {
    let scheduled = || {
        recent
            .iter()
            .map(|(_, run)| run)
            .filter(|run| run.reason == RunReason::Scheduled)
    };
    let base = scheduled()
        .filter(|run| run.is_good())
        .map(|run| add_hours(run.finished_at, interval_hours))
        .max()
        .unwrap_or(now);
    let retry = scheduled()
        .filter(|run| !run.is_good())
        .map(|run| add_hours(run.finished_at, 1))
        .max();
    retry.map_or(base, |retry| base.max(retry))
}

fn add_hours(at: Timestamp, hours: u32) -> Timestamp {
    Timestamp(at.0 + time::Duration::hours(i64::from(hours)))
}

fn seconds_between(from: Timestamp, to: Timestamp) -> u64 {
    u64::try_from((to.0 - from.0).whole_seconds()).unwrap_or(0)
}

fn warnings(
    profile: Option<Profile>,
    setup: Option<Timestamp>,
    last_good: Option<&BackupRun>,
    last_failed: Option<&BackupRun>,
    restored: Option<&RestoreRecord>,
    now: Timestamp,
) -> Vec<StatusWarning> {
    let mut warnings = Vec::new();
    let strict = matches!(profile, Some(Profile::Standard | Profile::Hardened));
    let since = last_good.map(|run| run.finished_at).or(setup);
    let stale_secs = STALE_AFTER.as_secs();
    if strict && since.is_some_and(|since| seconds_between(since, now) > stale_secs) {
        let mut params = BTreeMap::from([("days".to_owned(), "7".to_owned())]);
        if let Some(run) = last_good {
            params.insert("last_good_at".to_owned(), run.finished_at.to_string());
        }
        warnings.push(StatusWarning {
            code: "backup.stale".to_owned(),
            detail: match last_good {
                Some(_) => "the last good backup is more than 7 days old".to_owned(),
                None => "there has been no backup since setup, more than 7 days ago".to_owned(),
            },
            params,
        });
    }
    if let Some(run) = last_failed {
        let error = run.error.as_ref();
        warnings.push(StatusWarning {
            code: "backup.failed".to_owned(),
            detail: format!(
                "the last backup failed: {}",
                error.map_or("unknown cause", |error| error.detail.as_str())
            ),
            params: BTreeMap::from([
                ("at".to_owned(), run.finished_at.to_string()),
                (
                    "error".to_owned(),
                    error.map(|error| error.code.clone()).unwrap_or_default(),
                ),
            ]),
        });
    }
    if let Some(record) = restored {
        warnings.push(StatusWarning {
            code: "backup.restored".to_owned(),
            detail: format!(
                "this installation was restored from {}; take a new backup",
                record.file
            ),
            params: BTreeMap::from([
                ("file".to_owned(), record.file.clone()),
                ("restored_at".to_owned(), record.restored_at.to_string()),
            ]),
        });
    }
    warnings
}

fn validate(update: BackupSettingsUpdate) -> Result<BackupSettings, BackupError> {
    if !(1..=MAX_INTERVAL_HOURS).contains(&update.interval_hours) {
        return Err(BackupError::InvalidSettings(format!(
            "interval_hours must be 1 to {MAX_INTERVAL_HOURS}"
        )));
    }
    if !(1..=MAX_KEEP).contains(&update.keep) {
        return Err(BackupError::InvalidSettings(format!(
            "keep must be 1 to {MAX_KEEP}"
        )));
    }
    let target_dir = update
        .target_dir
        .map(|dir| dir.trim().to_owned())
        .filter(|dir| !dir.is_empty());
    if let Some(dir) = &target_dir
        && !Path::new(dir).is_absolute()
    {
        return Err(BackupError::InvalidSettings(format!(
            "target_dir: `{dir}` is not an absolute path"
        )));
    }
    let recipient = update
        .recipient
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty());
    if let Some(text) = &recipient {
        Recipient::parse(text)?;
    }
    if update.enabled && recipient.is_none() {
        return Err(BackupError::NoKey(
            "scheduled backups need a recipient: create one with `tenko backup keygen`".to_owned(),
        ));
    }
    Ok(BackupSettings {
        enabled: update.enabled,
        interval_hours: update.interval_hours,
        keep: update.keep,
        target_dir,
        recipient,
        include_config: update.include_config,
    })
}

fn settings_context(settings: &BackupSettings) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("enabled".to_owned(), settings.enabled.to_string()),
        (
            "interval_hours".to_owned(),
            settings.interval_hours.to_string(),
        ),
        ("keep".to_owned(), settings.keep.to_string()),
        (
            "target_dir".to_owned(),
            settings.target_dir.clone().unwrap_or_default(),
        ),
        (
            "recipient".to_owned(),
            settings.recipient.clone().unwrap_or_default(),
        ),
        (
            "include_config".to_owned(),
            settings.include_config.to_string(),
        ),
    ])
}

fn run_view(id: Uuid, run: &BackupRun) -> BackupRunView {
    BackupRunView {
        id,
        outcome: if run.is_good() {
            BackupOutcome::Succeeded
        } else {
            BackupOutcome::Failed
        },
        reason: match run.reason {
            RunReason::Manual => BackupReason::Manual,
            RunReason::Scheduled => BackupReason::Scheduled,
        },
        node: run.node,
        target_dir: run.target_dir.clone(),
        file: run.file.clone(),
        bytes: run.bytes,
        revision: run.revision.map(Revision),
        slots: run.slots.clone(),
        started_at: run.started_at,
        finished_at: run.finished_at,
        by: run.by.clone(),
        job: run.job,
        error: run.error.as_ref().map(|error| BackupFailure {
            code: error.code.clone(),
            detail: error.detail.clone(),
        }),
    }
}

fn restore_view(record: &RestoreRecord) -> RestoreNoticeView {
    RestoreNoticeView {
        restored_at: record.restored_at,
        started_at: record.started_at,
        backup_created_at: record.backup_created_at,
        file: record.file.clone(),
        source_node: record.source_node,
        revision: Revision(record.revision),
        node: record.node,
    }
}

/// The parameters of the step `backup.record`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordParams {
    id: Uuid,
    run: BackupRun,
    epoch: Option<u64>,
}

/// The write of a record: the record, the audit record, and the fence of a scheduled one.
fn record_batch(
    ctx: &RequestCtx,
    id: Uuid,
    run: &BackupRun,
    epoch: Option<u64>,
    error: Option<&BackupError>,
) -> WriteBatch {
    let mut batch = WriteBatch::for_request(ctx);
    if let Some(epoch) = epoch {
        batch.expect_counter(LEADER_EPOCH, epoch);
    }
    if let Err(encode) = batch.put_typed(&tables::RUNS, &id, run) {
        tracing::warn!(%encode, "a backup record does not encode");
    }
    let objects = vec![system_object()];
    let mut draft = match error {
        Some(error) => AuditDraft::failed(actions::CREATE, objects, error),
        None => AuditDraft::success(actions::CREATE, objects),
    };
    let mut context = BTreeMap::from([
        ("reason".to_owned(), run.reason.as_str().to_owned()),
        ("node".to_owned(), run.node.to_string()),
        ("target_dir".to_owned(), run.target_dir.clone()),
        ("slots".to_owned(), run.slots.join(",")),
    ]);
    if let Some(file) = &run.file {
        context.insert("file".to_owned(), file.clone());
    }
    if let Some(revision) = run.revision {
        context.insert("revision".to_owned(), revision.to_string());
    }
    draft.details.context = context;
    batch.audit(draft);
    batch
}

/// Deletes the records beyond [`super::model::KEEP_RUNS`].
fn purge_runs(view: &dyn ReadView, batch: &mut WriteBatch) {
    let Ok(rows) = view.scan_typed(
        &tables::RUNS,
        KeyRange::all(),
        super::model::KEEP_RUNS + 50,
        true,
    ) else {
        return;
    };
    for (id, _, _) in rows.into_iter().skip(super::model::KEEP_RUNS - 1) {
        batch.delete_typed(&tables::RUNS, &id);
    }
}

/// The step `backup.record`: stages the record of a written backup with its audit record.
struct RecordStep;

#[async_trait::async_trait]
impl StepHandler for RecordStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(STEP_KIND)
    }

    /// Not idempotent: the record is written once.
    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: RecordParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(STEP_PREVIEW),
            args: BTreeMap::from([(
                "file".to_owned(),
                params.run.file.clone().unwrap_or_default(),
            )]),
            changes: vec![system_object()],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let mut params: RecordParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        params.run.job = Some(cx.job);
        let mut batch = record_batch(&cx.request, params.id, &params.run, params.epoch, None);
        let view = cx.store.read(ReadConsistency::Local).await?;
        purge_runs(view.as_ref(), &mut batch);
        drop(view);
        tenko_jobs::stage(cx, batch)?;
        Ok(StepOutcome::Done { output: None })
    }

    async fn compensate(
        &self,
        _params: &[u8],
        _output: Option<&[u8]>,
        _cx: &StepContext,
    ) -> Result<(), StepError> {
        Err(StepError::NotCompensable)
    }
}

#[cfg(test)]
mod tests;
