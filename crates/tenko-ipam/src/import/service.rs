//! The import service: upload, mapping, preview and apply as a job (IPAM-11).
//!
//! # Flow
//!
//! 1. [`ImportService::upload`] reads the files (CSV, xlsx, xls, ods), stages them
//!    encrypted ([`staging`](super::staging)) and records a session that expires after 24
//!    hours. The answer is the [`ImportView`]: sheets, columns with shapes and samples, the
//!    suggested [`Mapping`].
//! 2. [`ImportService::set_mapping`] stores the user's mapping after checking it fits.
//! 3. [`ImportService::preview`] translates ([`translate`](super::translate)), reconciles
//!    with the store ([`reconcile`](super::reconcile)) and plans every command with the
//!    IPAM planner without writing: counts per entity and action, the first rows, the loss
//!    report by sheet, row and column, the proposed prefixes, the credential statement and
//!    whether apply is possible.
//! 4. [`ImportService::apply`] checks the same, freezes the model and submits an
//!    `import.apply` job ([`job`](super::job)) with one step per chunk. Each chunk
//!    reconciles its slice against the store as the earlier chunks left it, plans it with
//!    [`IpamService::plan`] and stages the batch so it commits with the step; a failure
//!    rolls the finished chunks back from history. Applying again plans nothing new.
//!
//! # Credentials
//!
//! Credential columns never become IPAM fields. Each host's login and password become
//! one operator secret attached to the host ([`Vault::stage_put`] in the chunk's batch,
//! IAM-15, IAM-16). Apply refuses them with `import.credentials.vault_required` when the
//! server has no vault or the account may not hold operator secrets at its current
//! authentication strength (IAM-07, see [`credential_gate`]).

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use ipnet::IpNet;
use tenko_core::{
    Action, Authorizer, Coded, DenyReason, ImportId, JobId, ObjectKind, ObjectRef, Principal,
    RequestCtx,
    audit::{AuditAction, AuditDraft, Digest},
    codec::canonical_sha256,
    ir::LossReport,
};
use tenko_jobs::{JobEngine, JobSpec, JobState};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, WriteBatch};
use tenko_vault::Vault;
use uuid::Uuid;

use super::{
    codes::{self, Severity},
    dto::{
        ActionCount, ApplyRequest, CredentialNotice, FileView, ImportPreview, ImportState,
        ImportView, LossCounts, LossItem, PlanProblem, PreviewRow, PreviewSummary, RowCounts,
        RowItem, SheetLoss, TargetInfo,
    },
    job,
    mapping::{self, CredentialPolicy, Mapping, SheetAnalysis},
    model::{CredentialValues, ImportModel},
    read::{self, ReadError, ReadLimits, SourceFile},
    reconcile::{self, ItemAction, ItemOutcome, Reconciled, WorkItem},
    staging::{Frozen, PREVIEWS, SESSIONS, Session, StagedFile, Stash, StoredPreview},
    translate::{self, ItemKey, Translation},
    vocab::Target,
};
use crate::{
    IpamService,
    error::{IpamError, IpamResult},
    plan::{IpamPlan, PlanOptions},
};

/// Settings of the import service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportConfig {
    /// Where releases before WP3.1b staged uploads on disk; the server empties it at start.
    /// Uploads are now staged in the store (see [`Stash`]).
    pub staging_dir: PathBuf,
    /// How long an upload stays staged.
    pub ttl: Duration,
    /// Largest upload in bytes, all files together.
    pub max_upload: usize,
    /// Target size of one chunk's write batch; chunks are cut with a safety margin so the
    /// batch stays under the store's batch limit.
    pub chunk_bytes: usize,
    /// Most commands in one chunk (the IPAM service plans at most 10,000).
    pub max_chunk_commands: usize,
    /// Rows a preview lists by default.
    pub preview_rows: usize,
    /// Limits of the readers.
    pub limits: ReadLimits,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            staging_dir: std::env::temp_dir().join("tenko-imports"),
            ttl: Duration::from_secs(24 * 60 * 60),
            max_upload: 20 * 1024 * 1024,
            chunk_bytes: 16 * 1024 * 1024,
            max_chunk_commands: 4_000,
            preview_rows: 200,
            limits: ReadLimits::default(),
        }
    }
}

/// One uploaded file.
#[derive(Clone, PartialEq, Eq)]
pub struct Upload {
    /// The file name as sent by the client.
    pub name: String,
    /// The content.
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upload")
            .field("name", &self.name)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// Whether the requesting account may store operator secrets now (IAM-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialGate {
    /// It may.
    Allowed,
    /// It may not.
    Denied {
        /// Machine-readable reason: `forbidden`, `step_up_required`, `unauthenticated` or
        /// `pin_coupling` (another account that may reveal secrets signs in with a PIN
        /// alone, the rule of `POST /secrets`).
        reason: &'static str,
        /// The weakest session strength that would do, for `step_up_required`.
        required: Option<String>,
        /// The accounts that sign in with a PIN alone, for `pin_coupling`; empty otherwise.
        accounts: Vec<String>,
        /// English explanation.
        detail: String,
    },
}

/// Why credentials cannot be stored now.
struct CredentialBlock {
    reason: &'static str,
    required: Option<String>,
    accounts: Vec<String>,
    detail: String,
}

/// Decides whether `principal` may store credentials of an import as operator secrets:
/// it must be allowed to create secrets and to reveal them, which is the IAM-07 threshold
/// once the vault holds an operator secret (a PIN alone no longer serves such an account).
/// Without an authorizer (development and tests) everything is allowed.
pub fn credential_gate(
    authorizer: Option<&dyn Authorizer>,
    principal: &Principal,
) -> CredentialGate {
    let Some(authorizer) = authorizer else {
        return CredentialGate::Allowed;
    };
    let object = ObjectRef::new(ObjectKind::Secret, Uuid::nil());
    for action in [Action::Create, Action::Reveal] {
        if let Err(denied) = authorizer.check(principal, action, &object) {
            return match denied.reason {
                DenyReason::StepUpRequired { required } => CredentialGate::Denied {
                    reason: "step_up_required",
                    required: Some(required.as_str().to_owned()),
                    accounts: Vec::new(),
                    detail: format!(
                        "storing operator secrets needs a session of at least `{}` (IAM-07); sign in with a stronger method or leave the credential columns out",
                        required.as_str()
                    ),
                },
                DenyReason::Unauthenticated => CredentialGate::Denied {
                    reason: "unauthenticated",
                    required: None,
                    accounts: Vec::new(),
                    detail: "storing operator secrets needs a signed-in person".to_owned(),
                },
                _ => CredentialGate::Denied {
                    reason: "forbidden",
                    required: None,
                    accounts: Vec::new(),
                    detail: "this account may not store or reveal operator secrets; leave the credential columns out or ask an administrator".to_owned(),
                },
            };
        }
    }
    CredentialGate::Allowed
}

/// What a prepared import holds for the apply job.
#[derive(Debug)]
pub(super) struct Prepared {
    pub(super) model: ImportModel,
    pub(super) credentials: CredentialValues,
    pub(super) mapping: Mapping,
    pub(super) items: Vec<WorkItem>,
}

/// The evaluation behind a preview and an apply.
struct Evaluation {
    view: Arc<dyn ReadView>,
    translation: Translation,
    items: Vec<WorkItem>,
    reconciled: Reconciled,
    plan: Result<IpamPlan, IpamError>,
}

/// The staging part that holds the rows of the latest preview.
const ROWS_PART: &str = "rows";

/// A page of the rows of a stored preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRows {
    /// The rows of the page.
    pub items: Vec<PreviewRow>,
    /// Rows in the whole preview.
    pub total_rows: usize,
    /// The store revision the preview was computed from.
    pub base_revision: u64,
    /// The mapping revision the preview was computed for (what a cursor carries).
    pub mapping_revision: u64,
    /// The position of the first row of the page.
    pub offset: usize,
}

/// The decoded rows of the preview paged last: import, mapping revision and rows.
type CachedRows = (ImportId, u64, Arc<Vec<PreviewRow>>);

/// Parsed uploads kept in memory.
const PARSED_CACHE: usize = 4;
/// Prepared models of running jobs kept in memory.
const PREPARED_CACHE: usize = 2;

/// The import service. Cheap to share as `Arc<ImportService>`.
pub struct ImportService {
    ipam: Arc<IpamService>,
    engine: JobEngine,
    vault: Option<Arc<dyn Vault>>,
    config: ImportConfig,
    stash: Stash,
    parsed: Mutex<VecDeque<(ImportId, Arc<Vec<SourceFile>>)>>,
    prepared: Mutex<VecDeque<(ImportId, Digest, Arc<Prepared>)>>,
    last_rows: Mutex<Option<CachedRows>>,
}

impl std::fmt::Debug for ImportService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportService")
            .field("config", &self.config)
            .field("vault", &self.vault.is_some())
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn not_found(id: ImportId) -> IpamError {
    IpamError::new(
        codes::NOT_FOUND,
        404,
        format!("import {} does not exist", id.0),
    )
    .titled("Import not found")
    .param("id", id.0)
}

fn state_conflict(detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::STATE_CONFLICT, 409, detail).titled("Import busy")
}

fn digest(model: &ImportModel) -> IpamResult<Digest> {
    canonical_sha256(model)
        .map(Digest)
        .map_err(|e| IpamError::new("sys.internal", 500, e.to_string()))
}

impl ImportService {
    /// Creates the service and registers its job steps (`import.chunk`, `import.finish`)
    /// with the engine. Start the engine's runner (`JobEngine::start`) for apply jobs to
    /// run.
    ///
    /// # Errors
    ///
    /// Returns an internal error when the staging directory cannot be created.
    pub fn new(
        ipam: Arc<IpamService>,
        engine: JobEngine,
        vault: Option<Arc<dyn Vault>>,
        config: ImportConfig,
    ) -> IpamResult<Arc<Self>> {
        let stash = Stash::new(Arc::clone(ipam.store()), vault.clone());
        let service = Arc::new_cyclic(|weak| {
            let mut registrar = engine.clone();
            job::register_steps(&mut registrar, weak.clone());
            Self {
                ipam,
                engine,
                vault,
                config,
                stash,
                parsed: Mutex::new(VecDeque::new()),
                prepared: Mutex::new(VecDeque::new()),
                last_rows: Mutex::new(None),
            }
        });
        Ok(service)
    }

    /// The settings.
    pub fn config(&self) -> &ImportConfig {
        &self.config
    }

    /// The IPAM service.
    pub fn ipam(&self) -> &Arc<IpamService> {
        &self.ipam
    }

    /// The job engine.
    pub fn engine(&self) -> &JobEngine {
        &self.engine
    }

    /// The vault, when the server has one.
    pub fn vault(&self) -> Option<&Arc<dyn Vault>> {
        self.vault.as_ref()
    }

    // ----- sessions ----------------------------------------------------------------------

    async fn view_at(&self, consistency: ReadConsistency) -> IpamResult<Arc<dyn ReadView>> {
        Ok(self.ipam.store().read(consistency).await?)
    }

    /// Loads a session the caller may see; expired sessions are removed and reported.
    async fn session(
        &self,
        cx: &RequestCtx,
        id: ImportId,
    ) -> IpamResult<(Session, tenko_core::Revision)> {
        let view = self.view_at(ReadConsistency::Local).await?;
        let Some((session, revision)) = view.get_typed(&SESSIONS, &id)? else {
            return Err(not_found(id));
        };
        if !session.visible_to(&cx.principal) {
            return Err(not_found(id));
        }
        if session.expires < cx.now {
            let _ = self
                .remove(cx, &session, Some(revision), "import.expire", None)
                .await;
            return Err(IpamError::new(
                codes::EXPIRED,
                410,
                "the upload expired; upload the file again",
            )
            .titled("Upload expired"));
        }
        Ok((session, revision))
    }

    async fn write_session(
        &self,
        cx: &RequestCtx,
        session: &Session,
        expect: Option<tenko_core::Revision>,
        action: &'static str,
        context: &[(&str, String)],
    ) -> IpamResult<tenko_core::Revision> {
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        batch.expect_typed(&SESSIONS, &session.id, expect);
        batch.put_typed(&SESSIONS, &session.id, session)?;
        // Audit context holds counts and identifiers only, never values or samples.
        let mut draft = AuditDraft::success(
            AuditAction::from_static(action),
            vec![ObjectRef::from(session.id)],
        )
        .with_source_ip(cx.source_ip);
        for (key, value) in context {
            draft = draft.with_context(*key, value.clone());
        }
        batch.audit(draft);
        match self.ipam.store().propose(batch).await {
            Ok(committed) => Ok(committed.revision),
            Err(tenko_store::StoreError::PreconditionFailed(_)) => Err(state_conflict(
                "the import changed at the same time; reload it and try again",
            )),
            Err(error) => Err(error.into()),
        }
    }

    async fn remove(
        &self,
        cx: &RequestCtx,
        session: &Session,
        expect: Option<tenko_core::Revision>,
        action: &'static str,
        fence: Option<u64>,
    ) -> IpamResult<()> {
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        if let Some(epoch) = fence {
            batch.preconditions.push(tenko_store::fence(epoch));
        }
        if expect.is_some() {
            batch.expect_typed(&SESSIONS, &session.id, expect);
        }
        batch.delete_typed(&SESSIONS, &session.id);
        self.stash.stage_remove(&mut batch, cx, session.id).await?;
        batch.audit(
            AuditDraft::success(
                AuditAction::from_static(action),
                vec![ObjectRef::from(session.id)],
            )
            .with_source_ip(cx.source_ip),
        );
        self.ipam.store().propose(batch).await?;
        self.forget(session.id);
        Ok(())
    }

    /// Drops what this controller keeps in memory of an import.
    fn forget(&self, id: ImportId) {
        self.stash.forget(id);
        lock(&self.parsed).retain(|(i, _)| *i != id);
        lock(&self.prepared).retain(|(i, _, _)| *i != id);
        let mut last = lock(&self.last_rows);
        if last.as_ref().is_some_and(|(i, _, _)| *i == id) {
            *last = None;
        }
    }

    /// The parsed files of a session (cached, else decrypted and read again).
    async fn files(&self, session: &Session) -> IpamResult<Arc<Vec<SourceFile>>> {
        if let Some((_, files)) = lock(&self.parsed).iter().find(|(id, _)| *id == session.id) {
            return Ok(Arc::clone(files));
        }
        let mut files = Vec::with_capacity(session.files.len());
        for (index, file) in session.files.iter().enumerate() {
            let bytes = self.stash.read(session.id, index, &file.stored_as).await?;
            files.push(
                read::read_file(&file.name, &bytes, &self.config.limits).map_err(read_error)?,
            );
        }
        let files = Arc::new(files);
        let mut cache = lock(&self.parsed);
        cache.push_back((session.id, Arc::clone(&files)));
        while cache.len() > PARSED_CACHE {
            cache.pop_front();
        }
        Ok(files)
    }

    async fn state(&self, session: &Session) -> ImportState {
        match session.job {
            Some(job) => match self.engine.job(job).await {
                Ok(job) => match job.state {
                    JobState::Succeeded => ImportState::Applied,
                    JobState::Failed | JobState::RolledBack | JobState::Cancelled => {
                        ImportState::Failed
                    }
                    _ => ImportState::Applying,
                },
                Err(_) => ImportState::Failed,
            },
            None if session.mapping.is_some() => ImportState::Mapped,
            None => ImportState::Uploaded,
        }
    }

    async fn render(
        &self,
        session: &Session,
        files: &[SourceFile],
        analyses: Vec<SheetAnalysis>,
        suggested: Mapping,
    ) -> IpamResult<ImportView> {
        let view = self.view_at(ReadConsistency::Local).await?;
        let mut targets: Vec<TargetInfo> = Target::FIXED
            .iter()
            .map(|target| TargetInfo {
                target: target.clone(),
                label: target.label(),
                credential: target.is_credential(),
            })
            .collect();
        for def in crate::query::custom_fields(view.as_ref())? {
            let target = Target::Custom(def.key.clone());
            targets.push(TargetInfo {
                label: target.label(),
                target,
                credential: false,
            });
        }
        Ok(ImportView {
            id: session.id,
            state: self.state(session).await,
            created: session.created,
            expires: session.expires,
            files: session
                .files
                .iter()
                .zip(files)
                .map(|(staged, file)| FileView {
                    name: staged.name.clone(),
                    format: staged.format,
                    size: staged.size,
                    text: file.text.clone(),
                })
                .collect(),
            sheets: analyses,
            mapped: session.mapping.is_some(),
            mapping: session.mapping.clone().unwrap_or(suggested),
            targets,
            job_id: session.job,
        })
    }

    // ----- the endpoints -----------------------------------------------------------------

    /// Reads, stages and records an upload (`POST /imports`).
    ///
    /// # Errors
    ///
    /// `import.upload.empty` (400), `import.upload.too_large` (413),
    /// `import.upload.unsupported` (415), `import.upload.unreadable` (422), or store
    /// errors.
    pub async fn upload(&self, cx: &RequestCtx, uploads: Vec<Upload>) -> IpamResult<ImportView> {
        if uploads.is_empty() || uploads.iter().all(|u| u.bytes.is_empty()) {
            return Err(
                IpamError::new(codes::UPLOAD_EMPTY, 400, "the upload holds no file")
                    .titled("No file"),
            );
        }
        let total: usize = uploads.iter().map(|u| u.bytes.len()).sum();
        if total > self.config.max_upload {
            return Err(too_large(total, self.config.max_upload));
        }
        let mut files = Vec::with_capacity(uploads.len());
        for upload in &uploads {
            files.push(
                read::read_file(&upload.name, &upload.bytes, &self.config.limits)
                    .map_err(read_error)?,
            );
        }
        let id = ImportId::generate();
        let mut staged = Vec::with_capacity(uploads.len());
        for (index, (upload, file)) in uploads.iter().zip(&files).enumerate() {
            let stored_as = match self.stash.write(cx, id, index, &upload.bytes).await {
                Ok(stored_as) => stored_as,
                Err(error) => {
                    self.discard(cx, id).await;
                    return Err(error);
                }
            };
            staged.push(StagedFile {
                name: upload.name.clone(),
                format: file.format,
                size: upload.bytes.len() as u64,
                sha256: Digest(sha256(&upload.bytes)),
                stored_as,
            });
        }
        let session = Session {
            id,
            owner: cx.principal.user(),
            owner_subject: cx.principal.subject(),
            created: cx.now,
            expires: cx.now.checked_add(self.config.ttl).unwrap_or(cx.now),
            files: staged,
            mapping: None,
            job: None,
            mapping_revision: 0,
            frozen: None,
        };
        if let Err(error) = self
            .write_session(
                cx,
                &session,
                None,
                "import.upload",
                &[
                    ("files", session.files.len().to_string()),
                    ("bytes", total.to_string()),
                ],
            )
            .await
        {
            self.discard(cx, id).await;
            return Err(error);
        }
        let files = Arc::new(files);
        {
            let mut cache = lock(&self.parsed);
            cache.push_back((id, Arc::clone(&files)));
            while cache.len() > PARSED_CACHE {
                cache.pop_front();
            }
        }
        let (analyses, suggested) = mapping::analyze(&files);
        self.render(&session, &files, analyses, suggested).await
    }

    /// The upload with its analysis and mapping (`GET /imports/{id}`).
    ///
    /// # Errors
    ///
    /// `import.not_found` (404), `import.expired` (410), `import.upload.lost` (410).
    pub async fn get(&self, cx: &RequestCtx, id: ImportId) -> IpamResult<ImportView> {
        let (session, _) = self.session(cx, id).await?;
        let files = self.files(&session).await?;
        let (analyses, suggested) = mapping::analyze(&files);
        self.render(&session, &files, analyses, suggested).await
    }

    /// Stores the user's mapping (`PUT /imports/{id}/mapping`).
    ///
    /// # Errors
    ///
    /// `import.mapping.invalid` (422) when it does not fit the upload,
    /// `import.state.conflict` (409) while an apply job runs, and the errors of
    /// [`get`](Self::get).
    pub async fn set_mapping(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        mapping: Mapping,
    ) -> IpamResult<ImportView> {
        let (mut session, revision) = self.session(cx, id).await?;
        if self.state(&session).await == ImportState::Applying {
            return Err(state_conflict(
                "the import is being applied; wait for its job to finish",
            ));
        }
        let files = self.files(&session).await?;
        let (analyses, suggested) = mapping::analyze(&files);
        mapping::validate(&mapping, &analyses).map_err(|e| {
            IpamError::new(codes::MAPPING_INVALID, 422, e.0)
                .titled("Mapping does not fit the upload")
        })?;
        session.mapping = Some(mapping);
        session.mapping_revision += 1;
        self.write_session(cx, &session, Some(revision), "import.mapping", &[])
            .await?;
        lock(&self.prepared).retain(|(i, _, _)| *i != id);
        self.render(&session, &files, analyses, suggested).await
    }

    /// Discards an upload (`DELETE /imports/{id}`).
    ///
    /// # Errors
    ///
    /// `import.state.conflict` (409) while an apply job runs, and the errors of
    /// [`get`](Self::get).
    pub async fn delete(&self, cx: &RequestCtx, id: ImportId) -> IpamResult<()> {
        let (session, revision) = self.session(cx, id).await?;
        if self.state(&session).await == ImportState::Applying {
            return Err(state_conflict(
                "the import is being applied; wait for its job to finish",
            ));
        }
        self.remove(cx, &session, Some(revision), "import.delete", None)
            .await
    }

    /// Removes expired sessions and the stash of imports without a session (the store
    /// part of the purge), then what this controller keeps in memory of imports that are
    /// gone (the local part); returns how many sessions were removed.
    ///
    /// # Errors
    ///
    /// Store errors.
    pub async fn purge_expired(&self) -> IpamResult<usize> {
        let removed = self.purge_store(None).await?;
        self.sweep_local().await?;
        Ok(removed)
    }

    /// The store part of the purge: removes expired sessions with their stash, and the
    /// stash of imports that have no session (see [`Stash::purge_orphans`]); returns how
    /// many sessions were removed. The leader runs it with the epoch of its term as
    /// `fence`, so a deposed leader's purge fails instead of racing the new leader's.
    ///
    /// # Errors
    ///
    /// Store errors, the precondition failure of a fenced batch among them.
    pub async fn purge_store(&self, fence: Option<u64>) -> IpamResult<usize> {
        let cx = RequestCtx::system(tenko_core::SystemComponent::Import);
        let view = self.view_at(ReadConsistency::Local).await?;
        let sessions =
            view.scan_typed(&SESSIONS, tenko_store::KeyRange::all(), usize::MAX, false)?;
        drop(view);
        let mut removed = 0;
        for (_, session, revision) in sessions {
            if session.expires < cx.now {
                self.remove(&cx, &session, Some(revision), "import.expire", fence)
                    .await?;
                removed += 1;
            }
        }
        self.stash.purge_orphans(cx.now, fence).await?;
        Ok(removed)
    }

    /// The local part of the purge, on every controller: drops the cached keys, parsed
    /// uploads and preview rows of imports whose sessions are gone; returns how many
    /// entries were dropped.
    ///
    /// # Errors
    ///
    /// Store errors.
    pub async fn sweep_local(&self) -> IpamResult<usize> {
        let view = self.view_at(ReadConsistency::Local).await?;
        let live: BTreeSet<ImportId> = view
            .scan_typed(&SESSIONS, tenko_store::KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        let gone: BTreeSet<ImportId> = lock(&self.parsed)
            .iter()
            .map(|(id, _)| *id)
            .chain(lock(&self.prepared).iter().map(|(id, _, _)| *id))
            .chain(lock(&self.last_rows).iter().map(|(id, _, _)| *id))
            .filter(|id| !live.contains(id))
            .collect();
        let forgotten_keys = self.stash.sweep(|id| live.contains(&id));
        for id in &gone {
            self.forget(*id);
        }
        Ok(gone.len() + forgotten_keys)
    }

    /// Removes what a failed upload staged, as far as it can; the purge removes the rest.
    async fn discard(&self, cx: &RequestCtx, id: ImportId) {
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        let staged = self.stash.stage_remove(&mut batch, cx, id).await;
        if staged.is_ok() {
            let _ = self.ipam.store().propose(batch).await;
        }
        self.forget(id);
    }

    // ----- preview and apply ---------------------------------------------------------------

    fn effective_mapping(session: &Session, files: &[SourceFile]) -> Mapping {
        session
            .mapping
            .clone()
            .unwrap_or_else(|| mapping::analyze(files).1)
    }

    fn plan_context(cx: &RequestCtx) -> RequestCtx {
        let mut plan_cx = cx.clone();
        plan_cx.idempotency = None;
        plan_cx
    }

    async fn evaluate(
        &self,
        cx: &RequestCtx,
        files: &[SourceFile],
        mapping: &Mapping,
        acknowledge: &BTreeSet<String>,
    ) -> IpamResult<Evaluation> {
        let view = self.view_at(ReadConsistency::Local).await?;
        let known = reconcile::known_prefixes(view.as_ref())?;
        let translation = translate::translate(files, mapping, &known, None);
        let items = reconcile::work_items(&translation.model, &mapping.options);
        let reconciled =
            reconcile::reconcile(view.as_ref(), &translation.model, &mapping.options, &items)?;
        let options = PlanOptions {
            acknowledge: mapping
                .options
                .acknowledge
                .iter()
                .chain(acknowledge)
                .cloned()
                .collect(),
            supernet_step: true,
            ..PlanOptions::default()
        };
        let plan = crate::plan::plan(
            view.as_ref(),
            &Self::plan_context(cx),
            &options,
            &reconciled.commands,
        );
        Ok(Evaluation {
            view,
            translation,
            items,
            reconciled,
            plan,
        })
    }

    /// Compares the credentials of the evaluation with the vault: new, changed,
    /// unchanged.
    async fn credential_counts(
        &self,
        cx: &RequestCtx,
        credentials: &CredentialValues,
        reconciled: &Reconciled,
    ) -> (usize, usize, usize) {
        let (mut new, mut changed, mut unchanged) = (0, 0, 0);
        for op in &reconciled.credentials {
            let Some(existing) = &op.existing else {
                new += 1;
                continue;
            };
            let Some(value) = credentials.0.get(&op.host) else {
                continue;
            };
            let same = match &self.vault {
                Some(vault) => vault
                    .get_system(cx, existing.secret)
                    .await
                    .is_ok_and(|stored| stored.expose() == value.to_secret_bytes().as_slice()),
                None => false,
            };
            if same {
                unchanged += 1;
            } else {
                changed += 1;
            }
        }
        (new, changed, unchanged)
    }

    /// Why credentials cannot be stored now, if they cannot.
    fn credential_block(&self, gate: &CredentialGate) -> Option<CredentialBlock> {
        if self.vault.is_none() {
            return Some(CredentialBlock {
                reason: "vault_unavailable",
                required: None,
                accounts: Vec::new(),
                detail: "this server has no vault for operator secrets".to_owned(),
            });
        }
        match gate {
            CredentialGate::Allowed => None,
            CredentialGate::Denied {
                reason,
                required,
                accounts,
                detail,
            } => Some(CredentialBlock {
                reason,
                required: required.clone(),
                accounts: accounts.clone(),
                detail: detail.clone(),
            }),
        }
    }

    /// The preview of an import (`GET /imports/{id}/preview`): nothing is written.
    ///
    /// # Errors
    ///
    /// The errors of [`get`](Self::get), or store errors. A plan that fails is reported
    /// in the preview (`plan_error`), not as an error.
    pub async fn preview(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        rows: Option<usize>,
        gate: &CredentialGate,
    ) -> IpamResult<ImportPreview> {
        let (session, _) = self.session(cx, id).await?;
        let files = self.files(&session).await?;
        let mapping = Self::effective_mapping(&session, &files);
        let evaluation = self
            .evaluate(cx, &files, &mapping, &BTreeSet::new())
            .await?;
        let limit = rows.unwrap_or(self.config.preview_rows);
        let (mut preview, all_rows) = self
            .build_preview(cx, id, &mapping, &evaluation, limit, gate)
            .await;
        preview.base_revision = self
            .store_rows(cx, &session, preview.base_revision, all_rows)
            .await?;
        Ok(preview)
    }

    /// Keeps every row of a preview in the staging area (encrypted like the upload), for
    /// paging with [`preview_rows`](Self::preview_rows) without computing the preview again.
    /// The record of where they are ([`PREVIEWS`]) replicates, so any controller pages
    /// them.
    async fn store_rows(
        &self,
        cx: &RequestCtx,
        session: &Session,
        base_revision: u64,
        rows: Vec<PreviewRow>,
    ) -> IpamResult<u64> {
        let bytes = tenko_core::codec::to_cbor(&rows)
            .map_err(|e| IpamError::new("sys.internal", 500, e.to_string()))?;
        let rows_sha256 = Some(Digest(sha256(&bytes)));
        // The same rows for the same mapping: the stored preview stands, with the revision
        // it was computed from. Staging them again would move the store revision, and a
        // second look at an unchanged import would seem to be a changed preview.
        let same = |stored: &StoredPreview| {
            stored.mapping_revision == session.mapping_revision
                && stored.rows_sha256 == rows_sha256
                && stored.total_rows == rows.len()
        };
        let view = self.view_at(ReadConsistency::Linearizable).await?;
        let previous = view.get_typed(&PREVIEWS, &session.id)?;
        let current = view
            .get_typed(&SESSIONS, &session.id)?
            .map(|(_, revision)| revision);
        drop(view);
        if let Some((stored, _)) = &previous
            && same(stored)
        {
            let base = stored.base_revision;
            *lock(&self.last_rows) = Some((session.id, session.mapping_revision, Arc::new(rows)));
            return Ok(base);
        }
        let stored_as = self
            .stash
            .write_part(cx, session.id, ROWS_PART, &bytes)
            .await?;
        let stored = StoredPreview {
            mapping_revision: session.mapping_revision,
            base_revision,
            total_rows: rows.len(),
            stored_as,
            rows_sha256,
        };
        let mut batch = WriteBatch::for_request(cx);
        batch.idempotency = None;
        // Only while the session exists: a preview of a discarded import leaves no row.
        batch.expect_typed(
            &SESSIONS,
            &session.id,
            current.or(Some(tenko_core::Revision::ZERO)),
        );
        batch.expect_typed(
            &PREVIEWS,
            &session.id,
            previous.as_ref().map(|(_, revision)| *revision),
        );
        batch.put_typed(&PREVIEWS, &session.id, &stored)?;
        if let Err(error) = self.ipam.store().propose(batch).await {
            let _ = self
                .stash
                .remove_part(cx, session.id, &stored.stored_as)
                .await;
            if !matches!(error, tenko_store::StoreError::PreconditionFailed(_)) {
                return Err(error.into());
            }
            // Another preview of the same import won the race: when it staged the same
            // rows, its record stands for this one too.
            return match self.stored_preview(session.id).await? {
                Some(winner) if same(&winner) => {
                    *lock(&self.last_rows) =
                        Some((session.id, session.mapping_revision, Arc::new(rows)));
                    Ok(winner.base_revision)
                }
                _ => Err(state_conflict(
                    "the import changed at the same time; preview it again",
                )),
            };
        }
        if let Some((previous, _)) = previous {
            let _ = self
                .stash
                .remove_part(cx, session.id, &previous.stored_as)
                .await;
        }
        *lock(&self.last_rows) = Some((session.id, session.mapping_revision, Arc::new(rows)));
        Ok(base_revision)
    }

    /// Where the latest preview of an import is staged: from this controller's view, or a
    /// linearizable one when the preview was computed moments ago through another
    /// controller.
    async fn stored_preview(&self, id: ImportId) -> IpamResult<Option<StoredPreview>> {
        let view = self.view_at(ReadConsistency::Local).await?;
        if let Some((stored, _)) = view.get_typed(&PREVIEWS, &id)? {
            return Ok(Some(stored));
        }
        drop(view);
        let view = self.view_at(ReadConsistency::Linearizable).await?;
        Ok(view.get_typed(&PREVIEWS, &id)?.map(|(stored, _)| stored))
    }

    /// A page of the rows of the stored preview (`GET /imports/{id}/rows`), from `offset`,
    /// at most `limit` rows. `mapping_revision` is the revision a cursor was made for.
    ///
    /// # Errors
    ///
    /// `import.preview.stale` (409) when no preview was computed for the current mapping,
    /// or the mapping changed since the cursor was made; and the errors of
    /// [`get`](Self::get).
    pub async fn preview_rows(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        mapping_revision: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> IpamResult<PreviewRows> {
        let (session, _) = self.session(cx, id).await?;
        let stale = |detail: &str| {
            IpamError::new(codes::PREVIEW_STALE, 409, detail.to_owned())
                .titled("Preview out of date")
                .param("mapping_revision", session.mapping_revision)
        };
        if mapping_revision.is_some_and(|revision| revision != session.mapping_revision) {
            return Err(stale(
                "the mapping changed since this page was listed; preview the import again",
            ));
        }
        let stored = self.stored_preview(id).await?.map(|stored| {
            (
                stored.mapping_revision,
                stored.base_revision,
                stored.total_rows,
                stored.stored_as,
            )
        });
        let Some((revision, base_revision, total_rows, stored_as)) = stored else {
            return Err(stale(
                "no preview was computed for the current mapping; preview the import first",
            ));
        };
        if revision != session.mapping_revision {
            return Err(stale(
                "the mapping changed since the preview; preview the import again",
            ));
        }
        let cached = lock(&self.last_rows)
            .as_ref()
            .filter(|(i, r, _)| *i == id && *r == revision)
            .map(|(_, _, rows)| Arc::clone(rows));
        let rows = if let Some(rows) = cached {
            rows
        } else {
            let bytes = self.stash.read_part(id, ROWS_PART, &stored_as).await?;
            let rows = Arc::new(
                tenko_core::codec::from_cbor::<Vec<PreviewRow>>(&bytes)
                    .map_err(|e| IpamError::new("sys.internal", 500, e.to_string()))?,
            );
            *lock(&self.last_rows) = Some((id, revision, Arc::clone(&rows)));
            rows
        };
        let items = rows.iter().skip(offset).take(limit).cloned().collect();
        Ok(PreviewRows {
            items,
            total_rows,
            base_revision,
            mapping_revision: revision,
            offset,
        })
    }

    #[allow(clippy::too_many_lines)] // One pass from the evaluation to the answer.
    async fn build_preview(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        mapping: &Mapping,
        evaluation: &Evaluation,
        limit: usize,
        gate: &CredentialGate,
    ) -> (ImportPreview, Vec<PreviewRow>) {
        let translation = &evaluation.translation;
        let reconciled = &evaluation.reconciled;
        let actions: BTreeMap<&ItemKey, ItemAction> = reconciled
            .outcomes
            .iter()
            .map(|o| (&o.key, o.action))
            .collect();

        // Credentials.
        let hosts = translation.model.credentials.len();
        let credentials_on = mapping.options.credentials == CredentialPolicy::Import && hosts > 0;
        let (new, changed, unchanged) = if credentials_on {
            self.credential_counts(cx, &translation.credentials, reconciled)
                .await
        } else {
            (0, 0, 0)
        };
        let block = credentials_on
            .then(|| self.credential_block(gate))
            .flatten();
        let statement =
            credential_statement(hosts, new, changed, unchanged, mapping.options.credentials);

        // Counts.
        let mut counts: BTreeMap<(String, ItemAction), usize> = BTreeMap::new();
        for outcome in &reconciled.outcomes {
            *counts
                .entry((kind_of(&outcome.key).to_owned(), outcome.action))
                .or_default() += 1;
        }
        if credentials_on {
            for (action, count) in [
                (ItemAction::Create, new),
                (ItemAction::Update, changed),
                (ItemAction::Unchanged, unchanged),
            ] {
                if count > 0 {
                    counts.insert(("credential".to_owned(), action), count);
                }
            }
        }
        let lines = summary_lines(&counts);
        let counts: Vec<ActionCount> = counts
            .into_iter()
            .map(|((kind, action), count)| ActionCount {
                kind,
                action,
                count,
            })
            .collect();

        // Rows.
        let mut row_counts = RowCounts::default();
        for row in &translation.rows {
            row_counts.total += 1;
            match row.status {
                translate::RowStatus::Free => row_counts.free += 1,
                translate::RowStatus::Imported => row_counts.imported += 1,
                translate::RowStatus::Skipped => row_counts.skipped += 1,
            }
        }
        let all_rows: Vec<PreviewRow> = translation
            .rows
            .iter()
            .map(|row| PreviewRow {
                location: row.location.clone(),
                status: row.status,
                items: row
                    .items
                    .iter()
                    .map(|key| RowItem {
                        key: key.clone(),
                        action: match key {
                            ItemKey::Credential { .. } if !credentials_on => ItemAction::Kept,
                            ItemKey::Credential { .. } => ItemAction::Create,
                            other => actions.get(other).copied().unwrap_or(ItemAction::Unchanged),
                        },
                    })
                    .collect(),
            })
            .collect();

        // Loss report: translation and reconcile issues, by sheet.
        let mut report = translation.loss.clone();
        report.entries.extend(reconciled.issues.iter().cloned());
        let (loss, loss_counts) = group_loss(&report);

        // Plan and blockers.
        let mut blockers = Vec::new();
        let (plan_summary, warnings, plan_error) = match &evaluation.plan {
            Ok(plan) => {
                if !plan.unacknowledged().is_empty() {
                    blockers.push(crate::error::codes::PLAN_UNACKNOWLEDGED.to_owned());
                }
                let mut warnings = plan.warnings.clone();
                // The supernet step names how many imported networks lie inside.
                for warning in &mut warnings {
                    if warning.code != crate::error::codes::WARN_BECOMES_SUPERNET {
                        continue;
                    }
                    let networks = reconciled
                        .supernet_steps
                        .iter()
                        .find(|(id, _)| warning.object == Some((**id).into()))
                        .map(|(_, count)| *count);
                    if let Some(networks) = networks {
                        warning
                            .params
                            .insert("networks".to_owned(), networks.to_string());
                    }
                }
                (Some(plan.summary()), warnings, None)
            }
            Err(error) => {
                blockers.push(error.code_str().to_owned());
                let coded = error.coded();
                (
                    None,
                    Vec::new(),
                    Some(PlanProblem {
                        code: coded.code.to_string(),
                        status: coded.status,
                        detail: coded.detail.clone(),
                        params: coded
                            .params
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    }),
                )
            }
        };
        if reconciled.blocked {
            blockers.push(codes::CONFLICT_KEPT.to_owned());
        }
        if block.is_some() {
            blockers.push(codes::CREDENTIALS_VAULT_REQUIRED.to_owned());
        }
        let chunks = job::cut_chunks(
            &evaluation.items,
            &translation.model,
            self.config.chunk_bytes,
            self.config.max_chunk_commands,
        )
        .len();
        let rows: Vec<PreviewRow> = all_rows.iter().take(limit).cloned().collect();
        let preview = ImportPreview {
            id,
            base_revision: evaluation.view.revision().0,
            summary: PreviewSummary {
                counts,
                lines,
                rows: row_counts.clone(),
                loss: loss_counts,
                plan: plan_summary,
                chunks,
            },
            sheets: translation.sheets.clone(),
            rows,
            total_rows: row_counts.total,
            loss,
            proposals: translation.proposals.clone(),
            credentials: CredentialNotice {
                hosts,
                new,
                changed,
                unchanged,
                statement,
                allowed: block.is_none(),
                reason: block.as_ref().map(|b| b.reason.to_owned()),
                detail: block.map(|b| b.detail),
            },
            warnings,
            plan_error,
            can_apply: blockers.is_empty(),
            blockers,
        };
        (preview, all_rows)
    }

    /// Refuses an apply that cannot go ahead: credential columns without the vault or
    /// below the IAM-07 threshold, a failed plan, unacknowledged warnings, conflicts under
    /// the `fail` policy.
    fn check_apply(
        &self,
        mapping: &Mapping,
        evaluation: &Evaluation,
        gate: &CredentialGate,
    ) -> IpamResult<()> {
        let model = &evaluation.translation.model;
        if mapping.options.credentials == CredentialPolicy::Import
            && !model.credentials.is_empty()
            && let Some(CredentialBlock {
                reason,
                required,
                accounts,
                detail,
            }) = self.credential_block(gate)
        {
            let mut error = IpamError::new(
                codes::CREDENTIALS_VAULT_REQUIRED,
                403,
                format!(
                    "{} hosts have credential columns, which become operator secrets in the vault: {detail}",
                    model.credentials.len()
                ),
            )
            .titled("Credentials need the vault")
            .param("reason", reason)
            .param("hosts", model.credentials.len());
            if let Some(required) = required {
                error = error.param("required", required);
            }
            if !accounts.is_empty() {
                error = error.param("accounts", accounts.join(","));
            }
            return Err(error);
        }
        let plan = evaluation.plan.as_ref().map_err(Clone::clone)?;
        let mut blocking = plan.unacknowledged();
        if evaluation.reconciled.blocked {
            blocking.push(codes::CONFLICT_KEPT.to_owned());
        }
        if blocking.is_empty() {
            return Ok(());
        }
        Err(IpamError::new(
            codes::PLAN_BLOCKED,
            409,
            format!("the import cannot be applied yet: {}", blocking.join(", ")),
        )
        .titled("Import blocked")
        .param("codes", blocking.join(",")))
    }

    /// Checks an import and builds its apply job without submitting it: the model is
    /// frozen in the session so every chunk sees the same items.
    ///
    /// # Errors
    ///
    /// `import.credentials.vault_required` (403), `import.plan.blocked` (409) with the
    /// blocking codes, the plan's own error, `import.state.conflict` (409) while a job
    /// runs, and the errors of [`get`](Self::get).
    pub async fn prepare_apply(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        request: &ApplyRequest,
        gate: &CredentialGate,
    ) -> IpamResult<JobSpec> {
        let (mut session, revision) = self.session(cx, id).await?;
        if self.state(&session).await == ImportState::Applying {
            return Err(state_conflict(
                "the import is being applied; wait for its job to finish",
            ));
        }
        let files = self.files(&session).await?;
        let mut mapping = Self::effective_mapping(&session, &files);
        mapping
            .options
            .acknowledge
            .extend(request.acknowledge.iter().cloned());
        let evaluation = self
            .evaluate(cx, &files, &mapping, &BTreeSet::new())
            .await?;
        let model = &evaluation.translation.model;
        self.check_apply(&mapping, &evaluation, gate)?;
        let model_digest = digest(model)?;
        let proposals: Vec<(String, IpNet)> = evaluation
            .translation
            .proposals
            .iter()
            .filter(|p| p.accepted)
            .map(|p| {
                (
                    translate::vrf_key(p.vrf.as_deref(), mapping.options.vrf.as_deref()),
                    p.cidr,
                )
            })
            .collect();
        let chunks = job::cut_chunks(
            &evaluation.items,
            model,
            self.config.chunk_bytes,
            self.config.max_chunk_commands,
        );
        let prepared = Arc::new(Prepared {
            model: evaluation.translation.model.clone(),
            credentials: evaluation.translation.credentials.clone(),
            mapping: mapping.clone(),
            items: evaluation.items.clone(),
        });
        {
            let mut cache = lock(&self.prepared);
            cache.retain(|(i, _, _)| *i != id);
            cache.push_back((id, model_digest, prepared));
            while cache.len() > PREPARED_CACHE {
                cache.pop_front();
            }
        }
        let secrets = if mapping.options.credentials == CredentialPolicy::Import {
            let (new, changed, _) = self
                .credential_counts(
                    cx,
                    &evaluation.translation.credentials,
                    &evaluation.reconciled,
                )
                .await;
            new + changed
        } else {
            0
        };
        let chunk_count = chunks.len();
        session.frozen = Some(Frozen {
            mapping,
            proposals,
            model: model_digest,
            rejected: Vec::new(),
            secrets: secrets as u64,
        });
        self.write_session(
            cx,
            &session,
            Some(revision),
            "import.prepare",
            &[
                ("chunks", chunk_count.to_string()),
                ("secrets", secrets.to_string()),
            ],
        )
        .await?;
        job::apply_job(id, model_digest, &chunks)
    }

    /// Applies an import as a job (`POST /imports/{id}/apply`); returns the job. While an
    /// apply job of the import runs, its identifier is returned again.
    ///
    /// # Errors
    ///
    /// The errors of [`prepare_apply`](Self::prepare_apply), or the engine's.
    pub async fn apply(
        &self,
        cx: &RequestCtx,
        id: ImportId,
        request: &ApplyRequest,
        gate: &CredentialGate,
    ) -> IpamResult<JobId> {
        {
            let (session, _) = self.session(cx, id).await?;
            if let Some(job) = session.job
                && self.state(&session).await == ImportState::Applying
            {
                return Ok(job);
            }
        }
        let spec = self.prepare_apply(cx, id, request, gate).await?;
        let job = self
            .engine
            .submit(spec, cx)
            .await
            .map_err(|e| IpamError::from_coded_error(e.to_coded_error()))?;
        let (mut session, revision) = self.session(cx, id).await?;
        session.job = Some(job);
        let secrets = session.frozen.as_ref().map_or(0, |f| f.secrets);
        self.write_session(
            cx,
            &session,
            Some(revision),
            "import.apply",
            &[("job", job.to_string()), ("secrets", secrets.to_string())],
        )
        .await?;
        Ok(job)
    }

    /// The prepared model of an apply job: cached, else read and translated again with the
    /// frozen mapping and proposals, and checked against the frozen digest.
    pub(super) async fn frozen(&self, id: ImportId, expected: Digest) -> IpamResult<Arc<Prepared>> {
        if let Some((_, _, prepared)) = lock(&self.prepared)
            .iter()
            .find(|(i, d, _)| *i == id && *d == expected)
        {
            return Ok(Arc::clone(prepared));
        }
        let view = self.view_at(ReadConsistency::Linearizable).await?;
        let Some((session, _)) = view.get_typed(&SESSIONS, &id)? else {
            return Err(IpamError::new(
                codes::UPLOAD_LOST,
                410,
                "the import was discarded while its job ran",
            ));
        };
        let Some(frozen) = session.frozen.clone() else {
            return Err(state_conflict("the import was not prepared for apply"));
        };
        let files = self.files(&session).await?;
        let known = reconcile::known_prefixes(view.as_ref())?;
        let translation =
            translate::translate(&files, &frozen.mapping, &known, Some(&frozen.proposals));
        if digest(&translation.model)? != expected {
            return Err(state_conflict(
                "the import no longer matches what was applied; preview and apply it again",
            ));
        }
        let items = reconcile::work_items(&translation.model, &frozen.mapping.options);
        let prepared = Arc::new(Prepared {
            model: translation.model,
            credentials: translation.credentials,
            mapping: frozen.mapping,
            items,
        });
        let mut cache = lock(&self.prepared);
        cache.push_back((id, expected, Arc::clone(&prepared)));
        while cache.len() > PREPARED_CACHE {
            cache.pop_front();
        }
        Ok(prepared)
    }
}

fn read_error(error: ReadError) -> IpamError {
    match error {
        ReadError::Unsupported => IpamError::new(
            codes::UPLOAD_UNSUPPORTED,
            415,
            "the file is not a CSV file or an xlsx, xls or ods workbook",
        )
        .titled("Unsupported file"),
        ReadError::Malformed(detail) => IpamError::new(
            codes::UPLOAD_UNREADABLE,
            422,
            format!("the file cannot be read: {detail}"),
        )
        .titled("Unreadable file"),
        ReadError::TooLarge(detail) => IpamError::new(
            codes::UPLOAD_TOO_LARGE,
            413,
            format!("the file exceeds a limit: {detail}"),
        )
        .titled("Upload too large"),
    }
}

/// `import.upload.too_large` for an upload of `size` bytes over `limit`.
pub fn too_large(size: usize, limit: usize) -> IpamError {
    IpamError::new(
        codes::UPLOAD_TOO_LARGE,
        413,
        format!("the upload has {size} bytes; the limit is {limit}"),
    )
    .titled("Upload too large")
    .param("limit", limit)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

/// The item kind of a key, for counts.
fn kind_of(key: &ItemKey) -> &'static str {
    match key {
        ItemKey::Vlan { .. } => "vlan",
        ItemKey::Prefix { .. } => "prefix",
        ItemKey::Host { .. } => "host",
        ItemKey::Interface { .. } => "interface",
        ItemKey::Address { .. } => "address",
        ItemKey::Credential { .. } => "credential",
    }
}

fn summary_lines(counts: &BTreeMap<(String, ItemAction), usize>) -> Vec<String> {
    let mut lines: Vec<String> = counts
        .iter()
        .filter(|((_, action), _)| *action != ItemAction::Unchanged)
        .map(|((kind, action), count)| {
            let noun = match (kind.as_str(), *count == 1) {
                (kind, true) => kind.to_owned(),
                ("address", false) => "addresses".to_owned(),
                ("prefix", false) => "prefixes".to_owned(),
                (kind, false) => format!("{kind}s"),
            };
            let verb = match action {
                ItemAction::Create => "created",
                ItemAction::Update => "updated",
                ItemAction::Unchanged => "unchanged",
                ItemAction::Kept => "kept as stored (conflict)",
            };
            format!("{count} {noun} {verb}")
        })
        .collect();
    if lines.is_empty() {
        lines.push("no changes".to_owned());
    }
    lines
}

fn credential_statement(
    hosts: usize,
    new: usize,
    changed: usize,
    unchanged: usize,
    policy: CredentialPolicy,
) -> String {
    if hosts == 0 {
        return "The file has no login or password columns with values.".to_owned();
    }
    let who = if hosts == 1 {
        "1 host has".to_owned()
    } else {
        format!("{hosts} hosts have")
    };
    if policy == CredentialPolicy::Skip {
        return format!(
            "{who} a login or password in the file. They are left out of this import and not stored anywhere."
        );
    }
    format!(
        "{who} a login or password in the file. They are not imported as IPAM fields: each host's login and password are stored encrypted in the vault as one operator secret attached to the host ({new} new, {changed} replaced, {unchanged} already stored). Revealing a secret is audited, exports never include them, and once the vault holds operator secrets a PIN alone no longer signs in to an account that can reveal them."
    )
}

fn group_loss(report: &LossReport) -> (Vec<SheetLoss>, LossCounts) {
    let mut counts = LossCounts::default();
    let mut groups: Vec<SheetLoss> = Vec::new();
    for entry in &report.entries {
        let severity = codes::severity(&entry.code);
        match severity {
            Severity::Info => counts.info += 1,
            Severity::Warning => counts.warning += 1,
            Severity::Error => counts.error += 1,
        }
        let item = LossItem {
            row: entry.location.row,
            column: entry.location.column.clone(),
            code: entry.code.to_string(),
            severity,
            detail: entry.detail.clone(),
        };
        match groups.iter_mut().find(|g| g.sheet == entry.location.sheet) {
            Some(group) => group.entries.push(item),
            None => groups.push(SheetLoss {
                sheet: entry.location.sheet.clone(),
                entries: vec![item],
            }),
        }
    }
    for group in &mut groups {
        group
            .entries
            .sort_by(|a, b| (a.row, a.column.as_deref()).cmp(&(b.row, b.column.as_deref())));
    }
    (groups, counts)
}

/// The outcomes of reconciling, for tests and tools.
pub fn outcomes_of(reconciled: &Reconciled) -> &[ItemOutcome] {
    &reconciled.outcomes
}

/// The cut of the items into chunks, for tests and tools.
pub fn chunk_ranges(
    model: &ImportModel,
    options: &mapping::ImportOptions,
    config: &ImportConfig,
) -> Vec<Range<usize>> {
    let items = reconcile::work_items(model, options);
    job::cut_chunks(&items, model, config.chunk_bytes, config.max_chunk_commands)
}
