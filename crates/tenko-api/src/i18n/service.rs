//! Language packs in the replicated store (owner decision S3-Q8).
//!
//! Every controller sees the same packs: an upload, a preview, an activation or a removal is
//! one audited batch, and activation reaches every client through the `system` event of the
//! `i18n.*` tables, on which the UI reloads its languages. Per language tag:
//!
//! - [`SLOTS`] (`i18n.pack_slots`) holds the active version and the candidate (an uploaded
//!   version waiting for preview and activation), with their metadata and report summary;
//! - [`CONTENT`] (`i18n.pack_content`) holds each version's document, messages and report,
//!   keyed by the SHA-256 of the document;
//! - [`PACKS`] (`i18n.packs`, `tenko_core::i18n`) holds the summary the authorization index
//!   reads: a language is a valid user or installation language while its record is active.
//!
//! The life cycle: an upload validates the document ([`super::validate`]) and makes it the
//! candidate (replacing an earlier candidate); a preview marks it previewed and hands its
//! messages to the administrator's browser, which renders the UI in it for that session only;
//! an activation needs a previewed candidate and makes it the active version, which the public
//! `GET /i18n/packs/{tag}` serves. A pack with the tag of a built-in language overrides the
//! built-in messages key by key; removing everything uploaded for a tag reverts to the
//! built-in language, or retires a language that is not built in.
//!
//! Files in `<data_dir>/i18n/*.xlf` are imported at start as candidates uploaded by the system
//! ([`Languages::import_dir`]); a file is imported once, so a superseded file left in the
//! directory does not come back.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, OnceLock},
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;

use tenko_core::{
    FieldError, ObjectKind, ObjectRef, Principal, RequestCtx, Revision, SystemComponent,
    audit::{AuditAction, AuditDraft, AuditOutcome},
    i18n::{BUILT_IN_LANGUAGES, PACKS, PackRecord, PackState, is_language_tag},
    table::TableDef,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};

use super::{
    dto::{
        LanguageInfo, LanguageList, PackInfo, PackList, PackMessages, PackOrigin, PackStatus,
        PackUpload, PackVersion,
    },
    template,
    validate::{KeySet, Refusal, Report, Severity, validate},
    xliff::{self, Metadata},
};
use crate::{problem::ApiError, ui::AssetTable};

/// The active version and the candidate of a language, by tag.
pub const SLOTS: TableDef<String, Slots> = TableDef::new("i18n.pack_slots");
/// The document, messages and report of a version, by the SHA-256 of the document.
pub const CONTENT: TableDef<String, Content> = TableDef::new("i18n.pack_content");

/// The most file ids remembered per language as imported from the data directory.
const MAX_IMPORTED: usize = 32;

/// The versions of one language (table [`SLOTS`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slots {
    /// The version everyone sees.
    #[serde(default)]
    pub active: Option<PackVersion>,
    /// The version waiting for preview and activation.
    #[serde(default)]
    pub candidate: Option<PackVersion>,
    /// Ids of files imported from the data directory, newest last.
    #[serde(default)]
    pub imported: Vec<String>,
}

/// One version's content (table [`CONTENT`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Content {
    /// The tag.
    pub tag: String,
    /// The uploaded document, as text.
    pub document: String,
    /// The usable messages by key.
    pub messages: BTreeMap<String, String>,
    /// The report of the upload.
    pub report: Report,
}

/// A built-in language: its name and, for a translation, its messages (the targets of its
/// built-in document), which its template starts from.
#[derive(Debug, Clone)]
struct BuiltIn {
    tag: String,
    name: String,
    metadata: Metadata,
    messages: Option<BTreeMap<String, String>>,
}

/// The key set of the running UI and its built-in languages, with the operations on packs.
#[derive(Debug, Clone)]
pub struct Languages {
    keys: KeySet,
    built_in: Vec<BuiltIn>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn not_found(tag: &str) -> ApiError {
    ApiError::new(
        "i18n.pack.not_found",
        404,
        format!("there is no language pack {tag}"),
    )
    .with_param("tag", tag)
}

fn no_candidate(tag: &str) -> ApiError {
    ApiError::new(
        "i18n.pack.no_candidate",
        404,
        format!("the language {tag} has no uploaded version waiting for activation"),
    )
    .with_param("tag", tag)
}

fn unavailable() -> ApiError {
    ApiError::new(
        "i18n.unavailable",
        503,
        "this build has no embedded user interface, so it has no key set to check packs against",
    )
}

fn audit(
    cx: &RequestCtx,
    action: &'static str,
    tag: &str,
    context: &[(&str, String)],
) -> AuditDraft {
    let mut draft = AuditDraft {
        source_ip: cx.source_ip,
        ..AuditDraft::success(
            AuditAction::from_static(action),
            vec![ObjectRef::singleton(ObjectKind::Settings)],
        )
    };
    draft
        .details
        .context
        .insert("tag".to_owned(), tag.to_owned());
    for (key, value) in context {
        draft
            .details
            .context
            .insert((*key).to_owned(), value.clone());
    }
    draft
}

/// The summary record of the authorization index for the slots of a tag, or `None` when
/// nothing is uploaded.
fn record(tag: &str, slots: &Slots) -> Option<PackRecord> {
    if let Some(active) = &slots.active {
        return Some(PackRecord {
            tag: tag.to_owned(),
            state: PackState::Active,
            display_name: active.display_name.clone(),
        });
    }
    slots.candidate.as_ref().map(|candidate| PackRecord {
        tag: tag.to_owned(),
        state: if candidate.previewed_at.is_some() {
            PackState::Previewed
        } else {
            PackState::Uploaded
        },
        display_name: candidate.display_name.clone(),
    })
}

/// Adds the new slots of a tag and its summary record to a batch, guarded by the revision
/// the slots were read at.
fn stage_slots(
    batch: &mut WriteBatch,
    tag: &str,
    slots: &Slots,
    read_at: Option<Revision>,
) -> Result<(), ApiError> {
    let key = tag.to_owned();
    batch.expect_typed(&SLOTS, &key, read_at);
    if slots.active.is_none() && slots.candidate.is_none() && slots.imported.is_empty() {
        batch.delete_typed(&SLOTS, &key);
    } else {
        batch.put_typed(&SLOTS, &key, slots)?;
    }
    match record(tag, slots) {
        Some(record) => {
            batch.put_typed(&PACKS, &key, &record)?;
        }
        None => {
            batch.delete_typed(&PACKS, &key);
        }
    }
    Ok(())
}

/// The refusal of an upload as problem details: 422 `i18n.pack.invalid` (413 for a pack over
/// the size limit) with one entry in `errors` per problem.
fn refusal_error(refusal: &Refusal) -> ApiError {
    let status = if refusal.code == "i18n.pack.too_large" {
        413
    } else {
        422
    };
    let code = if status == 413 {
        "i18n.pack.too_large"
    } else {
        "i18n.pack.invalid"
    };
    let first = refusal
        .problems
        .first()
        .map_or_else(String::new, |p| p.detail.clone());
    let mut error = tenko_core::CodedError::new(
        code,
        status,
        format!("the language pack is refused: {first}"),
    )
    .with_param("reason", refusal.code);
    if let Some(tag) = &refusal.tag {
        error = error.with_param("tag", tag.clone());
    }
    for problem in refusal
        .problems
        .iter()
        .filter(|p| p.severity == Severity::Error)
    {
        let mut field = FieldError {
            field: problem.key.clone().unwrap_or_else(|| "file".to_owned()),
            code: Cow::Owned(problem.code.clone()),
            params: BTreeMap::new(),
        };
        field
            .params
            .insert("detail".to_owned(), problem.detail.clone());
        if let Some(line) = problem.line {
            field.params.insert("line".to_owned(), line.to_string());
        }
        error = error.with_field_error(field);
    }
    ApiError::from_coded_error(error)
}

/// Records a refused upload in the audit log; a failure to do so is logged.
async fn audit_refusal(store: &dyn Store, cx: &RequestCtx, refusal: &Refusal, error: &ApiError) {
    let mut draft = AuditDraft::success(
        AuditAction::from_static("i18n.pack.upload"),
        vec![ObjectRef::singleton(ObjectKind::Settings)],
    );
    draft.outcome = AuditOutcome::Failed {
        code: error.coded_error().code.clone(),
    };
    draft.source_ip = cx.source_ip;
    if let Some(tag) = &refusal.tag {
        draft.details.context.insert("tag".to_owned(), tag.clone());
    }
    draft
        .details
        .context
        .insert("reason".to_owned(), refusal.code.to_owned());
    let mut batch = WriteBatch::for_request(cx);
    batch.audit(draft);
    if let Err(audit_error) = store.propose(batch).await {
        tracing::warn!(error = %audit_error, "a refused language pack could not be audited");
    }
}

impl Languages {
    /// The languages of the UI embedded in this binary: the source document `i18n/en.xlf`
    /// and the built-in documents `i18n/<tag>.xlf` that the UI build emits. A build without
    /// the UI (`TENKO_UI_STUB=1`) has an empty key set: packs are served, uploads refused.
    pub fn embedded() -> Arc<Self> {
        static EMBEDDED: OnceLock<Arc<Languages>> = OnceLock::new();
        Arc::clone(EMBEDDED.get_or_init(|| {
            let table = AssetTable::embedded();
            let documents: Vec<(String, Bytes)> = BUILT_IN_LANGUAGES
                .iter()
                .filter_map(|tag| {
                    table
                        .get(&format!("i18n/{tag}.xlf"))
                        .map(|asset| ((*tag).to_owned(), asset.identity.clone()))
                })
                .collect();
            Arc::new(Self::from_documents_or_without_ui(&documents))
        }))
    }

    /// Languages without a key set (a build without the embedded UI).
    pub fn without_ui() -> Self {
        fn name(tag: &str) -> &str {
            match tag {
                "en" => "English",
                "sv" => "Svenska",
                other => other,
            }
        }
        Self {
            keys: KeySet::default(),
            built_in: BUILT_IN_LANGUAGES
                .iter()
                .map(|tag| BuiltIn {
                    tag: (*tag).to_owned(),
                    name: name(tag).to_owned(),
                    metadata: Metadata::default(),
                    messages: None,
                })
                .collect(),
        }
    }

    /// The languages of a UI build in a directory (`[server] ui_dir`): its `i18n/<tag>.xlf`
    /// documents, as [`Languages::embedded`] reads them from the embedded build.
    pub fn from_ui_dir(dir: &Path) -> Arc<Self> {
        let documents: Vec<(String, Bytes)> = BUILT_IN_LANGUAGES
            .iter()
            .filter_map(|tag| {
                std::fs::read(dir.join("i18n").join(format!("{tag}.xlf")))
                    .ok()
                    .map(|bytes| ((*tag).to_owned(), Bytes::from(bytes)))
            })
            .collect();
        Arc::new(Self::from_documents_or_without_ui(&documents))
    }

    fn from_documents_or_without_ui(documents: &[(String, Bytes)]) -> Self {
        if documents.is_empty() {
            return Self::without_ui();
        }
        Self::from_documents(documents).unwrap_or_else(|error| {
            tracing::error!(%error, "the language documents of the user interface cannot be read; language packs cannot be uploaded");
            Self::without_ui()
        })
    }

    /// Languages from built-in documents: the source language first (its units give the key
    /// set), then the translations. A language may have several documents in a row, its main
    /// document and then its fragments (`ui/i18n/<tag>.xlf` and `ui/i18n/<tag>.d/*.xlf`): the
    /// first definition of a key wins and the metadata comes from the first document, as the
    /// UI build merges them. The UI build emits one merged document per language.
    ///
    /// # Errors
    ///
    /// A document that cannot be read.
    pub fn from_documents(documents: &[(String, Bytes)]) -> Result<Self, String> {
        let mut languages: Vec<(&str, Vec<&[u8]>)> = Vec::new();
        for (tag, bytes) in documents {
            match languages
                .iter_mut()
                .find(|(known, _)| *known == tag.as_str())
            {
                Some((_, parts)) => parts.push(bytes.as_ref()),
                None => languages.push((tag.as_str(), vec![bytes.as_ref()])),
            }
        }
        let Some((_, source)) = languages.first() else {
            return Err("no source document".to_owned());
        };
        let keys = KeySet::from_source_documents(source)?;
        let mut built_in = Vec::with_capacity(languages.len());
        for (index, (tag, parts)) in languages.iter().enumerate() {
            let mut metadata: Option<Metadata> = None;
            let mut messages: BTreeMap<String, String> = BTreeMap::new();
            for bytes in parts {
                let document = xliff::read(bytes).map_err(|error| format!("{tag}: {error}"))?;
                if index > 0 {
                    for unit in document.units {
                        if unit.problem.is_some() {
                            continue;
                        }
                        if let Some(target) = unit.target {
                            messages.entry(unit.id).or_insert(target);
                        }
                    }
                }
                metadata.get_or_insert(document.metadata);
            }
            let metadata = metadata.unwrap_or_default();
            built_in.push(BuiltIn {
                tag: (*tag).to_owned(),
                name: if metadata.display_name.is_empty() {
                    (*tag).to_owned()
                } else {
                    metadata.display_name.clone()
                },
                metadata,
                messages: (index > 0).then_some(messages),
            });
        }
        Ok(Self { keys, built_in })
    }

    /// The key set of the running UI.
    pub fn keys(&self) -> &KeySet {
        &self.keys
    }

    fn built_in(&self, tag: &str) -> Option<&BuiltIn> {
        self.built_in.iter().find(|b| b.tag == tag)
    }

    async fn view(store: &dyn Store) -> Result<Arc<dyn ReadView>, ApiError> {
        Ok(store.read(ReadConsistency::Local).await?)
    }

    fn slots(view: &dyn ReadView, tag: &str) -> Result<(Slots, Option<Revision>), ApiError> {
        Ok(match view.get_typed(&SLOTS, &tag.to_owned())? {
            Some((slots, revision)) => (slots, Some(revision)),
            None => (Slots::default(), None),
        })
    }

    fn content(view: &dyn ReadView, id: &str) -> Result<Option<Content>, ApiError> {
        Ok(view
            .get_typed(&CONTENT, &id.to_owned())?
            .map(|(content, _)| content))
    }

    fn info(&self, tag: &str, slots: Slots) -> PackInfo {
        let built_in = self.built_in(tag);
        let status = match (&slots.active, &slots.candidate) {
            (Some(_), _) => PackStatus::Active,
            (None, Some(candidate)) if candidate.previewed_at.is_some() => PackStatus::Previewed,
            (None, Some(_)) => PackStatus::Uploaded,
            (None, None) => PackStatus::BuiltIn,
        };
        let name = slots
            .active
            .as_ref()
            .or(slots.candidate.as_ref())
            .map(|v| v.display_name.clone())
            .or_else(|| built_in.map(|b| b.name.clone()))
            .unwrap_or_else(|| tag.to_owned());
        PackInfo {
            tag: tag.to_owned(),
            name,
            built_in: built_in.is_some(),
            status,
            active: slots.active,
            candidate: slots.candidate,
        }
    }

    /// Every language with its versions: the built-in ones first, then the others by tag.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn list(&self, store: &dyn Store) -> Result<PackList, ApiError> {
        let view = Self::view(store).await?;
        let mut uploaded: BTreeMap<String, Slots> = view
            .scan_typed(&SLOTS, tenko_store::KeyRange::all(), 10_000, false)?
            .into_iter()
            .map(|(tag, slots, _)| (tag, slots))
            .collect();
        let mut packs = Vec::new();
        for built_in in &self.built_in {
            let slots = uploaded.remove(&built_in.tag).unwrap_or_default();
            packs.push(self.info(&built_in.tag, slots));
        }
        for (tag, slots) in uploaded {
            if slots.active.is_some() || slots.candidate.is_some() {
                packs.push(self.info(&tag, slots));
            }
        }
        Ok(PackList {
            packs,
            keys: u32::try_from(self.keys.len()).unwrap_or(u32::MAX),
        })
    }

    /// The languages everyone may choose: the built-in ones (with the hash of an active
    /// override), then the active uploaded ones by tag.
    ///
    /// # Errors
    ///
    /// A store error.
    pub async fn languages(
        &self,
        store: &dyn Store,
        default_language: Option<String>,
    ) -> Result<LanguageList, ApiError> {
        let list = self.list(store).await?;
        let languages = list
            .packs
            .into_iter()
            .filter(|pack| pack.built_in || pack.active.is_some())
            .map(|pack| LanguageInfo {
                name: pack
                    .active
                    .as_ref()
                    .filter(|_| !pack.built_in)
                    .map_or(pack.name.clone(), |active| active.display_name.clone()),
                hash: pack.active.map(|active| active.hash),
                built_in: pack.built_in,
                tag: pack.tag,
            })
            .collect();
        Ok(LanguageList {
            languages,
            default_language,
        })
    }

    async fn messages_of(
        store: &dyn Store,
        tag: &str,
        candidate: bool,
    ) -> Result<PackMessages, ApiError> {
        let view = Self::view(store).await?;
        let (slots, _) = Self::slots(view.as_ref(), tag)?;
        let version = if candidate {
            slots.candidate
        } else {
            slots.active
        };
        let Some(version) = version else {
            return Err(if candidate {
                no_candidate(tag)
            } else {
                not_found(tag)
            });
        };
        let content = Self::content(view.as_ref(), &version.id)?.ok_or_else(|| not_found(tag))?;
        Ok(PackMessages {
            tag: tag.to_owned(),
            hash: version.hash,
            messages: content.messages,
        })
    }

    /// The messages of the active version of a tag.
    ///
    /// # Errors
    ///
    /// 404 `i18n.pack.not_found` when the tag has no active uploaded version.
    pub async fn active_messages(
        &self,
        store: &dyn Store,
        tag: &str,
    ) -> Result<PackMessages, ApiError> {
        Self::messages_of(store, tag, false).await
    }

    /// The messages of the candidate of a tag, for a preview.
    ///
    /// # Errors
    ///
    /// 404 `i18n.pack.no_candidate` when the tag has no candidate.
    pub async fn candidate_messages(
        &self,
        store: &dyn Store,
        tag: &str,
    ) -> Result<PackMessages, ApiError> {
        Self::messages_of(store, tag, true).await
    }

    /// The report of the candidate of a tag, else of its active version.
    ///
    /// # Errors
    ///
    /// 404 `i18n.pack.not_found` when nothing is uploaded for the tag.
    pub async fn report(&self, store: &dyn Store, tag: &str) -> Result<Report, ApiError> {
        let view = Self::view(store).await?;
        let (slots, _) = Self::slots(view.as_ref(), tag)?;
        let version = slots
            .candidate
            .or(slots.active)
            .ok_or_else(|| not_found(tag))?;
        Ok(Self::content(view.as_ref(), &version.id)?
            .ok_or_else(|| not_found(tag))?
            .report)
    }

    /// Validates a document and makes it the candidate of its language. Uploading the
    /// active version or the candidate again changes nothing.
    ///
    /// # Errors
    ///
    /// 503 `i18n.unavailable` without a key set; 422 `i18n.pack.invalid` (413
    /// `i18n.pack.too_large`) when the document is refused, after auditing the refusal; a
    /// store error.
    pub async fn upload(
        &self,
        store: &dyn Store,
        cx: &RequestCtx,
        bytes: &[u8],
        origin: PackOrigin,
    ) -> Result<PackUpload, ApiError> {
        if self.keys.is_empty() {
            return Err(unavailable());
        }
        let validated = match validate(bytes, &self.keys) {
            Ok(validated) => validated,
            Err(refusal) => {
                let error = refusal_error(&refusal);
                audit_refusal(store, cx, &refusal, &error).await;
                return Err(error);
            }
        };
        let tag = validated.tag.clone();
        let id = hex(bytes);
        let view = Self::view(store).await?;
        let (mut slots, read_at) = Self::slots(view.as_ref(), &tag)?;
        let known = [&slots.active, &slots.candidate]
            .into_iter()
            .flatten()
            .any(|version| version.id == id);
        if known {
            let report = Self::content(view.as_ref(), &id)?.map_or(validated.report, |c| c.report);
            return Ok(PackUpload {
                pack: self.info(&tag, slots),
                report,
            });
        }
        drop(view);

        let messages_json = serde_json::to_vec(&validated.messages)
            .map_err(|error| ApiError::new("sys.internal", 500, error.to_string()))?;
        let report = validated.report;
        let version = PackVersion {
            id: id.clone(),
            hash: hex(&messages_json),
            display_name: report.display_name.clone(),
            author: report.author.clone(),
            version: report.version.clone(),
            translated: report.translated,
            total: report.total,
            percent: report.percent,
            origin,
            uploaded_at: cx.now,
            uploaded_by: cx.principal.clone(),
            previewed_at: None,
            previewed_by: None,
        };
        let document = String::from_utf8_lossy(
            bytes
                .strip_prefix(b"\xef\xbb\xbf".as_slice())
                .unwrap_or(bytes),
        )
        .into_owned();
        let mut batch = WriteBatch::for_request(cx);
        if let Some(old) = slots.candidate.take() {
            batch.delete_typed(&CONTENT, &old.id);
        }
        slots.candidate = Some(version);
        if origin == PackOrigin::DataDir {
            slots.imported.push(id.clone());
            let excess = slots.imported.len().saturating_sub(MAX_IMPORTED);
            slots.imported.drain(..excess);
        }
        batch.put_typed(
            &CONTENT,
            &id,
            &Content {
                tag: tag.clone(),
                document,
                messages: validated.messages,
                report: report.clone(),
            },
        )?;
        stage_slots(&mut batch, &tag, &slots, read_at)?;
        let action = if origin == PackOrigin::DataDir {
            "i18n.pack.import"
        } else {
            "i18n.pack.upload"
        };
        batch.audit(audit(
            cx,
            action,
            &tag,
            &[("version", id), ("percent", report.percent.to_string())],
        ));
        store.propose(batch).await?;
        Ok(PackUpload {
            pack: self.info(&tag, slots),
            report,
        })
    }

    /// Marks the candidate of a tag previewed by the caller; the browser then renders the
    /// UI in its messages for that session only.
    ///
    /// # Errors
    ///
    /// 404 `i18n.pack.no_candidate`; a store error.
    pub async fn preview(
        &self,
        store: &dyn Store,
        cx: &RequestCtx,
        tag: &str,
    ) -> Result<PackInfo, ApiError> {
        let view = Self::view(store).await?;
        let (mut slots, read_at) = Self::slots(view.as_ref(), tag)?;
        drop(view);
        let candidate = slots.candidate.as_mut().ok_or_else(|| no_candidate(tag))?;
        let id = candidate.id.clone();
        if candidate.previewed_at.is_none() {
            candidate.previewed_at = Some(cx.now);
            candidate.previewed_by = Some(cx.principal.clone());
        }
        let mut batch = WriteBatch::for_request(cx);
        stage_slots(&mut batch, tag, &slots, read_at)?;
        batch.audit(audit(cx, "i18n.pack.preview", tag, &[("version", id)]));
        store.propose(batch).await?;
        Ok(self.info(tag, slots))
    }

    /// Makes the previewed candidate of a tag its active version.
    ///
    /// # Errors
    ///
    /// 404 `i18n.pack.no_candidate`; 409 `i18n.pack.not_previewed` when nobody previewed the
    /// candidate yet; a store error.
    pub async fn activate(
        &self,
        store: &dyn Store,
        cx: &RequestCtx,
        tag: &str,
    ) -> Result<PackInfo, ApiError> {
        let view = Self::view(store).await?;
        let (mut slots, read_at) = Self::slots(view.as_ref(), tag)?;
        drop(view);
        let candidate = slots.candidate.take().ok_or_else(|| no_candidate(tag))?;
        if candidate.previewed_at.is_none() {
            return Err(ApiError::new(
                "i18n.pack.not_previewed",
                409,
                format!("preview the uploaded version of {tag} before activating it"),
            )
            .with_param("tag", tag));
        }
        let mut batch = WriteBatch::for_request(cx);
        let mut context = vec![("version", candidate.id.clone())];
        if let Some(old) = slots.active.take() {
            batch.delete_typed(&CONTENT, &old.id);
            context.push(("previous", old.id));
        }
        slots.active = Some(candidate);
        stage_slots(&mut batch, tag, &slots, read_at)?;
        batch.audit(audit(cx, "i18n.pack.activate", tag, &context));
        store.propose(batch).await?;
        Ok(self.info(tag, slots))
    }

    /// Discards the candidate of a tag; the active version stays.
    ///
    /// # Errors
    ///
    /// 404 `i18n.pack.no_candidate`; a store error.
    pub async fn discard(
        &self,
        store: &dyn Store,
        cx: &RequestCtx,
        tag: &str,
    ) -> Result<PackInfo, ApiError> {
        let view = Self::view(store).await?;
        let (mut slots, read_at) = Self::slots(view.as_ref(), tag)?;
        drop(view);
        let candidate = slots.candidate.take().ok_or_else(|| no_candidate(tag))?;
        let mut batch = WriteBatch::for_request(cx);
        batch.delete_typed(&CONTENT, &candidate.id);
        stage_slots(&mut batch, tag, &slots, read_at)?;
        batch.audit(audit(
            cx,
            "i18n.pack.discard",
            tag,
            &[("version", candidate.id)],
        ));
        store.propose(batch).await?;
        Ok(self.info(tag, slots))
    }

    /// Removes everything uploaded for a tag: a built-in language reverts to its built-in
    /// messages (the answer is the language), any other language is retired (`None`).
    ///
    /// # Errors
    ///
    /// 404 `i18n.pack.not_found` when nothing is uploaded for the tag; 409
    /// `i18n.pack.default_language` when a language that is not built in is the
    /// installation's default; a store error.
    pub async fn remove(
        &self,
        store: &dyn Store,
        cx: &RequestCtx,
        tag: &str,
        default_language: Option<&str>,
    ) -> Result<Option<PackInfo>, ApiError> {
        let view = Self::view(store).await?;
        let (mut slots, read_at) = Self::slots(view.as_ref(), tag)?;
        drop(view);
        if slots.active.is_none() && slots.candidate.is_none() {
            return Err(not_found(tag));
        }
        let built_in = self.built_in(tag).is_some();
        if !built_in && slots.active.is_some() && default_language == Some(tag) {
            return Err(ApiError::new(
                "i18n.pack.default_language",
                409,
                format!("{tag} is the default language of the installation; choose another default first"),
            )
            .with_param("tag", tag));
        }
        let mut batch = WriteBatch::for_request(cx);
        let mut context = Vec::new();
        for (name, version) in [
            ("active", slots.active.take()),
            ("candidate", slots.candidate.take()),
        ] {
            if let Some(version) = version {
                batch.delete_typed(&CONTENT, &version.id);
                context.push((name, version.id));
            }
        }
        stage_slots(&mut batch, tag, &slots, read_at)?;
        batch.audit(audit(cx, "i18n.pack.remove", tag, &context));
        store.propose(batch).await?;
        Ok(built_in.then(|| self.info(tag, Slots::default())))
    }

    /// The template of a language as an XLIFF 2.0 document: the running key set with the
    /// language's current messages as targets (its candidate, else its active version, else
    /// its built-in messages); for the source language every target is the English text.
    ///
    /// # Errors
    ///
    /// 503 `i18n.unavailable` without a key set; a store error.
    pub async fn template(&self, store: &dyn Store, tag: &str) -> Result<String, ApiError> {
        if self.keys.is_empty() {
            return Err(unavailable());
        }
        let view = Self::view(store).await?;
        let (slots, _) = Self::slots(view.as_ref(), tag)?;
        let uploaded = match slots.candidate.as_ref().or(slots.active.as_ref()) {
            Some(version) => {
                Self::content(view.as_ref(), &version.id)?.map(|content| (version, content))
            }
            None => None,
        };
        if let Some((version, content)) = uploaded {
            let metadata = Metadata {
                display_name: version.display_name.clone(),
                author: version.author.clone(),
                version: version.version.clone(),
                source_language: self.keys.language.clone(),
            };
            return Ok(template::render(
                &self.keys,
                tag,
                &metadata,
                Some(&content.messages),
            ));
        }
        if tag == self.keys.language {
            return Ok(template::render(&self.keys, tag, &self.keys.metadata, None));
        }
        let empty = BTreeMap::new();
        let (metadata, messages) = match self.built_in(tag) {
            Some(built_in) => (
                built_in.metadata.clone(),
                built_in.messages.as_ref().unwrap_or(&empty),
            ),
            None => (Metadata::default(), &empty),
        };
        Ok(template::render(&self.keys, tag, &metadata, Some(messages)))
    }

    /// Imports the `*.xlf` files of a directory (`<data_dir>/i18n`) as candidates uploaded
    /// by the system. A file imported before, or equal to a language's active version or
    /// candidate, is skipped; a refused file is logged and audited. A missing directory is
    /// not an error.
    ///
    /// # Errors
    ///
    /// Never for a single file; only the directory listing itself can fail.
    pub async fn import_dir(
        &self,
        store: &dyn Store,
        dir: &Path,
    ) -> std::io::Result<ImportSummary> {
        let mut summary = ImportSummary::default();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(summary),
            Err(error) => return Err(error),
        };
        let mut files: Vec<std::path::PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("xlf"))
            })
            .collect();
        files.sort();
        let cx = RequestCtx::new(Principal::system(SystemComponent::Languages));
        for path in files {
            let name = path.display().to_string();
            let bytes = match std::fs::metadata(&path) {
                Ok(meta)
                    if meta.len() > u64::try_from(super::MAX_PACK_BYTES).unwrap_or(u64::MAX) =>
                {
                    tracing::warn!(file = %name, "the language pack is over the size limit and was not imported");
                    summary.refused += 1;
                    continue;
                }
                _ => match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        tracing::warn!(file = %name, %error, "the language pack cannot be read");
                        summary.refused += 1;
                        continue;
                    }
                },
            };
            if self.already_imported(store, &bytes).await.unwrap_or(false) {
                summary.skipped += 1;
                continue;
            }
            match self.upload(store, &cx, &bytes, PackOrigin::DataDir).await {
                Ok(upload) => {
                    tracing::info!(file = %name, tag = %upload.pack.tag, percent = upload.report.percent, "imported a language pack as an uploaded version");
                    summary.imported += 1;
                }
                Err(error) => {
                    tracing::warn!(file = %name, code = error.coded_error().code.as_ref(), detail = %error.coded_error().detail, "the language pack was not imported");
                    summary.refused += 1;
                }
            }
        }
        Ok(summary)
    }

    /// Whether the document of a file was imported before, or is a current version.
    async fn already_imported(&self, store: &dyn Store, bytes: &[u8]) -> Result<bool, ApiError> {
        let Ok(document) = xliff::read(bytes) else {
            return Ok(false);
        };
        let Some(tag) = document.trg_lang.filter(|tag| is_language_tag(tag)) else {
            return Ok(false);
        };
        let id = hex(bytes);
        let view = Self::view(store).await?;
        let (slots, _) = Self::slots(view.as_ref(), &tag)?;
        Ok(slots.imported.contains(&id)
            || [&slots.active, &slots.candidate]
                .into_iter()
                .flatten()
                .any(|version| version.id == id))
    }
}

/// What [`Languages::import_dir`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// Files imported as candidates.
    pub imported: usize,
    /// Files imported before, or equal to a current version.
    pub skipped: usize,
    /// Files refused or unreadable.
    pub refused: usize,
}
