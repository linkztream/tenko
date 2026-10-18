//! The compile job `dns.list.compile`: one step that reads a list's source, compiles it and
//! writes its next version.
//!
//! The source of a URL list is read through a [`ListFetcher`] (the process's HTTP client in
//! `tenko serve`) with the entity tag of the newest version; `304 Not Modified` ends the
//! step without a write. The source of an uploaded list is the file the upload route staged
//! in [`ListStaging`] for the job (in memory, like the zone file of an import: a file of up
//! to 64 MiB is no job parameter). The text is parsed and compiled on the blocking pool,
//! and the version, the removal of the one before and the audit record `dns.list.compile`
//! commit with the step.
//!
//! Every attempt leaves the list's [`FetchStatus`]: when it ran, and the stable code and
//! detail of a failure. A failure keeps the version the list has. The status lives in the
//! process that ran the job (on the single node of Phase 2 the one process; the job record
//! keeps the failure as well).

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, JobId, MessageKey, ObjectRef, RequestCtx, Timestamp,
    audit::{AuditAction, AuditDraft},
    codec::{from_cbor, to_cbor},
    dns::{BlockListId, ListSource, codes, tables::LISTS},
    serde_util::HexBytes,
};
use tenko_jobs::{
    JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
    StepSpec,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, WriteBatch};
use uuid::Uuid;

use super::{
    compile_text,
    service::{NewVersion, invalid, not_found, version_batch, versions},
};
use crate::zone::{ZoneError, ZoneResult, ZoneService, jobs::stage_or_propose};

/// Kind of the compile job.
pub const COMPILE_JOB: &str = "dns.list.compile";
/// Kind of its step.
pub const COMPILE_STEP: &str = "dns.list.compile";
/// Title of the job (a UI message key).
pub const COMPILE_TITLE: &str = "dns.job.list_compile";
/// Summary key of the step's preview.
pub const COMPILE_PREVIEW: &str = "dns.job.list_compile_step";
/// The code of a fetch that failed: the server could not be reached, answered an error, or
/// sent more than the limit.
pub const FETCH_FAILED: &str = "dns.list.fetch_failed";
/// The code of a step whose uploaded file is gone (the process restarted).
pub const UPLOAD_MISSING: &str = "dns.list.upload_missing";

/// What a fetch read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The source did not change since the entity tag (`304 Not Modified`).
    NotModified,
    /// The source's text.
    Changed {
        /// The body.
        body: Vec<u8>,
        /// Its entity tag.
        etag: Option<String>,
    },
}

/// Why a fetch failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct FetchFailure {
    /// English detail: the status the server answered, or why it could not be reached.
    pub detail: String,
}

/// Reads the source of a URL list.
#[async_trait::async_trait]
pub trait ListFetcher: Send + Sync + 'static {
    /// Fetches `url`, with `If-None-Match: etag` when given.
    ///
    /// # Errors
    ///
    /// [`FetchFailure`] when the source cannot be read.
    async fn fetch(&self, url: &str, etag: Option<&str>) -> Result<Fetched, FetchFailure>;
}

/// The files of uploaded lists, handed from the upload route to the compile step.
#[derive(Debug, Default)]
pub struct ListStaging {
    files: Mutex<HashMap<Uuid, Arc<Vec<u8>>>>,
}

impl ListStaging {
    fn put(&self, id: Uuid, file: Vec<u8>) {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Arc::new(file));
    }

    fn get(&self, id: Uuid) -> Option<Arc<Vec<u8>>> {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    fn take(&self, id: Uuid) {
        self.files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }
}

/// The last compile of a list in this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchStatus {
    /// When it ran.
    pub checked: Timestamp,
    /// The stable code of its failure.
    pub error: Option<String>,
    /// English detail of the failure.
    pub detail: Option<String>,
}

fn statuses() -> &'static Mutex<BTreeMap<BlockListId, FetchStatus>> {
    static STATUSES: OnceLock<Mutex<BTreeMap<BlockListId, FetchStatus>>> = OnceLock::new();
    STATUSES.get_or_init(Mutex::default)
}

/// The last compile of a list in this process, if one ran.
pub fn fetch_status(id: BlockListId) -> Option<FetchStatus> {
    statuses()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned()
}

fn record(id: BlockListId, error: Option<(&str, String)>) {
    let status = FetchStatus {
        checked: Timestamp::now(),
        error: error.as_ref().map(|(code, _)| (*code).to_owned()),
        detail: error.map(|(_, detail)| detail),
    };
    statuses()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id, status);
}

/// The parameters of `dns.list.compile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileParams {
    /// The list.
    pub list: BlockListId,
    /// The staged file of an upload; a URL list is fetched when absent.
    #[serde(default)]
    pub upload: Option<Uuid>,
}

/// What the step reports (CBOR output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileOutput {
    /// The version written; absent when the source did not change.
    #[serde(default)]
    pub version: Option<u64>,
    /// Names in the version.
    pub entries: u64,
    /// Lines that held no name.
    pub skipped: u64,
}

/// The handler of `dns.list.compile`.
pub struct CompileStep {
    fetcher: Option<Arc<dyn ListFetcher>>,
    staging: Arc<ListStaging>,
}

impl std::fmt::Debug for CompileStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompileStep")
            .field("fetcher", &self.fetcher.is_some())
            .finish_non_exhaustive()
    }
}

impl CompileStep {
    /// The step over `fetcher` (none: URL lists fail with `dns.list.fetch_failed`) and the
    /// staging of uploads.
    pub fn new(fetcher: Option<Arc<dyn ListFetcher>>, staging: Arc<ListStaging>) -> Self {
        Self { fetcher, staging }
    }
}

fn coded(code: &'static str, status: u16, detail: impl Into<String>) -> StepError {
    StepError::Coded(Box::new(CodedError::new(code, status, detail.into())))
}

fn zone_error(error: ZoneError) -> StepError {
    StepError::Coded(Box::new(error.into_coded()))
}

#[async_trait::async_trait]
impl StepHandler for CompileStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(COMPILE_STEP)
    }

    /// The step reads its source again and writes against the rows it reads.
    fn idempotent(&self) -> bool {
        true
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        let params: CompileParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepPreview {
            summary: MessageKey::from_static(COMPILE_PREVIEW),
            args: BTreeMap::from([("list".to_owned(), params.list.to_string())]),
            changes: vec![ObjectRef::from(params.list)],
            manual: None,
            warnings: Vec::new(),
        })
    }

    async fn execute(&self, params: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params: CompileParams =
            from_cbor(params).map_err(|error| StepError::InvalidParams(error.to_string()))?;
        let result = self.run(&params, cx).await;
        if let Some(upload) = params.upload
            && !matches!(&result, Err(StepError::Coded(error)) if error.code == "sys.store.precondition_failed")
        {
            self.staging.take(upload);
        }
        match &result {
            Ok(_) => record(params.list, None),
            Err(StepError::Coded(error)) => {
                record(params.list, Some((&error.code, error.detail.clone())));
            }
            Err(other) => record(params.list, Some((FETCH_FAILED, other.to_string()))),
        }
        result
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

impl CompileStep {
    async fn run(
        &self,
        params: &CompileParams,
        cx: &StepContext,
    ) -> Result<StepOutcome, StepError> {
        let view = cx.store.read(ReadConsistency::Local).await?;
        let (list, list_revision) = view
            .get_typed(&LISTS, &params.list)?
            .ok_or_else(|| zone_error(not_found(params.list)))?;
        let newest = versions(view.as_ref(), params.list, 1)
            .map_err(zone_error)?
            .into_iter()
            .next();
        drop(view);
        let (text, etag, source) = match (&list.source, params.upload) {
            (_, Some(upload)) => {
                let file = self.staging.get(upload).ok_or_else(|| {
                    coded(
                        UPLOAD_MISSING,
                        409,
                        "the uploaded file is only kept while the process that took it runs; \
                         upload it again",
                    )
                })?;
                ((*file).clone(), None, "upload")
            }
            (ListSource::Url { url }, None) => {
                let Some(fetcher) = &self.fetcher else {
                    return Err(coded(FETCH_FAILED, 502, "this process fetches no lists"));
                };
                let etag = newest.as_ref().and_then(|version| version.etag.as_deref());
                match fetcher.fetch(url, etag).await {
                    Ok(Fetched::NotModified) => {
                        let entries = newest.as_ref().map_or(0, |version| version.entries);
                        return output(&CompileOutput {
                            version: None,
                            entries,
                            skipped: 0,
                        });
                    }
                    Ok(Fetched::Changed { body, etag }) => (body, etag, "fetch"),
                    Err(failure) => return Err(coded(FETCH_FAILED, 502, failure.detail)),
                }
            }
            (ListSource::Upload, None) => {
                return Err(zone_error(invalid(
                    "source",
                    "an uploaded list is compiled from its file",
                )));
            }
        };
        let format = list.format;
        let fetched = Timestamp::now();
        let (compiled, skipped) = tokio::task::spawn_blocking(move || compile_text(&text, format))
            .await
            .map_err(|join| coded("sys.internal", 500, join.to_string()))?
            .map_err(|error| zone_error(invalid("source", &error.to_string())))?;
        let entries = compiled.entries;
        let view = cx.store.read(ReadConsistency::Local).await?;
        let (batch, version) = version_batch(
            view.as_ref(),
            &cx.request,
            params.list,
            list_revision,
            NewVersion {
                bytes: compiled.bytes,
                entries,
                skipped,
                fetched,
                etag,
                source,
            },
        )
        .map_err(zone_error)?;
        drop(view);
        stage_or_propose(cx, batch).await?;
        output(&CompileOutput {
            version: Some(version),
            entries,
            skipped,
        })
    }
}

fn output(output: &CompileOutput) -> Result<StepOutcome, StepError> {
    Ok(StepOutcome::Done {
        output: Some(to_cbor(output).map_err(|error| StepError::coded(&error))?),
    })
}

/// What starts a compile job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The leader service, on the list's interval: no audit record of its own.
    Schedule,
    /// `POST /dns/lists/{id}/fetch`: audited as `dns.list.fetch`.
    Fetch,
    /// `PUT /dns/lists/{id}/file`: audited as `dns.list.upload`.
    Upload,
}

impl ZoneService {
    /// Submits the compile job of a list: a fetch of a URL list, or the compile of an
    /// uploaded file (staged in `staging` for the job). A fetch or upload by hand writes its
    /// audit record first.
    ///
    /// # Errors
    ///
    /// `dns.list.not_found`; `dns.list.invalid` (409) for a fetch of an uploaded list or an
    /// upload to a URL list; or a store or job error.
    pub async fn start_list_compile(
        &self,
        cx: &RequestCtx,
        id: BlockListId,
        staging: &ListStaging,
        file: Option<Vec<u8>>,
        trigger: Trigger,
    ) -> ZoneResult<JobId> {
        let view = self.view(None).await?;
        let (list, _) = view.get_typed(&LISTS, &id)?.ok_or_else(|| not_found(id))?;
        drop(view);
        match (&list.source, file.is_some()) {
            (ListSource::Upload, false) => {
                return Err(conflict(
                    "an uploaded list has no URL to fetch; upload its file",
                ));
            }
            (ListSource::Url { .. }, true) => {
                return Err(conflict("a URL list is fetched from its URL, not uploaded"));
            }
            _ => {}
        }
        let upload_bytes = file.as_ref().map(Vec::len);
        let upload = file.map(|file| {
            let key = Uuid::now_v7();
            staging.put(key, file);
            key
        });
        let spec = JobSpec {
            kind: JobKind::from_static(COMPILE_JOB),
            title: MessageKey::from_static(COMPILE_TITLE),
            targets: vec![ObjectRef::from(id)],
            steps: vec![StepSpec {
                kind: StepKind::from_static(COMPILE_STEP),
                params: HexBytes(to_cbor(&CompileParams { list: id, upload })?.to_vec()),
                timeout: Some(Duration::from_secs(600)),
            }],
            timeout: Duration::from_secs(900),
            group: None,
            group_limit: None,
            idempotency: None,
            node: None,
        };
        // The request is audited before its job runs, so the record of the fetch or the
        // upload comes before the version's `dns.list.compile`.
        let action: Option<&AuditAction> = match trigger {
            Trigger::Schedule => None,
            Trigger::Fetch => Some(&tenko_core::dns::audit::LIST_FETCH),
            Trigger::Upload => Some(&tenko_core::dns::audit::LIST_UPLOAD),
        };
        if let Some(action) = action {
            let mut batch = WriteBatch::for_request(cx);
            batch.idempotency = None;
            let mut draft = AuditDraft::success(action.clone(), vec![ObjectRef::from(id)])
                .with_source_ip(cx.source_ip)
                .with_context("name", list.name.clone());
            if let Some(bytes) = upload_bytes {
                draft = draft.with_context("bytes", bytes.to_string());
            }
            batch.audit(draft);
            if let Err(error) = self.store().propose(batch).await {
                if let Some(upload) = upload {
                    staging.take(upload);
                }
                return Err(error.into());
            }
        }
        let job = match self.jobs().submit(spec, cx).await {
            Ok(job) => job,
            Err(error) => {
                if let Some(upload) = upload {
                    staging.take(upload);
                }
                return Err(error.into());
            }
        };
        Ok(job)
    }
}

fn conflict(reason: &str) -> ZoneError {
    ZoneError::new(codes::LIST_INVALID, 409, format!("source: {reason}"))
        .param("field", "source")
        .param("reason", reason)
}
