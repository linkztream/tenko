//! The zone file import (MIG-15's counterpart; DNS-01): a preview, then a background job.
//!
//! # Preview
//!
//! [`ZoneService::preview_import`] reads the whole file once against the store as it is:
//! it counts the records per type, the RRsets it would add, replace and (with `replace`)
//! remove, and lists the losses, without writing. A syntax error, `$INCLUDE` or a bad
//! `$GENERATE` stops it with `dns.zonefile.invalid` (422) and the line.
//!
//! # Apply
//!
//! [`ZoneService::start_import`] runs the preview, then submits the job `dns.import`: one
//! `dns.import.chunk` step per [`ZoneConfig::import_chunk`](super::ZoneConfig::import_chunk)
//! RRsets of the preview and a final `dns.import.finish`, so the job's steps show its
//! progress. The file is staged in memory on this controller ([`ImportStaging`]) and read
//! again by the steps, one owner name at a time; a chunk holds at most the RRsets of one
//! batch, which commits with its step record. The job record carries the import report
//! as the output of its final step, in JSON.
//!
//! The rules of the merge, per owner name of the file (records of one owner that follow
//! each other form a group; a name the file lists again later is merged into what the
//! import wrote before):
//!
//! - An RRset of the file replaces the stored RRset of its type; one the store already
//!   holds with the same TTL and records is not written; one the import itself wrote
//!   before takes the new records too.
//! - The import writes `manual` RRsets and never replaces an RRset of another origin; such
//!   an RRset is a loss (`dns.zonefile.origin`).
//! - Every RRset is checked with the rules of its type and every owner with the rules
//!   between its RRsets; a broken RRset or owner is a loss (`dns.zonefile.rule`).
//! - The apex SOA of the file is not written as a record: its values become the scope's
//!   SOA (and the zone's SOA settings for the default scope), and its serial is kept when
//!   it is newer than the scope's, else the serial moves by the zone's policy (once, at
//!   the end). An import that changes no RRset and no SOA value and brings no newer
//!   serial leaves the serial and the journal alone.
//! - With `replace`, the finish step deletes the `manual` RRsets of the scope the import
//!   did not write, except the apex SOA and, when the file has no apex NS set, the apex NS.
//!
//! The batches of the chunks do not expect the versions of what they replace: a change
//! made while an import runs may be overwritten by it. An import that one chunk holds and
//! that changes at most [`JOURNAL_RECORDS`] records leaves one journal entry; a larger one
//! resets the scope's journal, so a secondary asking for an older serial gets AXFR. When a
//! step fails (or the controller restarts and the staged file is gone), the chunks written
//! so far stay and the job ends rolled back with the error; importing again completes it.

use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tenko_core::{
    CodedError, JobId, MessageKey, ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    codec::{from_cbor, to_cbor},
    dns::{
        DnsName, JournalEntry, JournalRecord, Origin, RecordData, RrSet, RrSetKey, Rtype,
        ScopeName, SoaDefaults, Zone, ZoneId, audit, check_node,
        tables::{RRSETS, ZONES},
    },
    ipam::Stamp,
    serde_util::HexBytes,
};
use tenko_jobs::{
    JobKind, JobSpec, StepContext, StepError, StepHandler, StepKind, StepOutcome, StepPreview,
    StepSpec,
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, WriteBatch};
use uuid::Uuid;

use super::{
    ZoneError, ZoneResult, ZoneService, holds_data, journal, journal_records, node, records,
    rrset_range, serial, soa_rrset, soa_serial, stage_delete, stage_put,
    zonefile::{self, FileRecord, Item, Loss, Reader},
};

/// Kind of the import job.
pub const IMPORT_JOB: &str = "dns.import";
/// Kind of a chunk step.
pub const CHUNK_STEP: &str = "dns.import.chunk";
/// Kind of the final step.
pub const FINISH_STEP: &str = "dns.import.finish";
/// Title of the job (a UI message key).
pub const IMPORT_TITLE: &str = "dns.job.import";
/// Summary key of a chunk's preview.
pub const CHUNK_PREVIEW: &str = "dns.job.import_chunk";
/// Summary key of the final step's preview.
pub const FINISH_PREVIEW: &str = "dns.job.import_finish";
/// The code of a step whose staged file is gone (after a restart).
pub const STAGING_MISSING: &str = "dns.job.import_missing";
/// Losses listed in a report at most; the count covers all.
pub const MAX_LISTED_LOSSES: usize = 1_000;
/// The largest import that leaves one journal entry instead of resetting the journal.
pub const JOURNAL_RECORDS: usize = 10_000;

/// An import request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRequest {
    /// The zone.
    pub zone: ZoneId,
    /// The scope.
    pub scope: ScopeName,
    /// The zone file.
    pub text: String,
    /// Delete the scope's `manual` RRsets the file does not hold.
    pub replace: bool,
}

/// One loss of a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportLoss {
    /// The line, from 1.
    pub line: u32,
    /// The stable code.
    pub code: String,
    /// What was lost.
    pub detail: String,
}

/// What an import did or, in the preview, would do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    /// Nothing was written.
    pub dry_run: bool,
    /// RRsets added.
    pub added: u64,
    /// RRsets replaced.
    pub replaced: u64,
    /// RRsets removed (with `replace`).
    pub removed: u64,
    /// The records of the file per type.
    pub types: BTreeMap<Rtype, u64>,
    /// The first [`MAX_LISTED_LOSSES`] losses.
    pub losses: Vec<ReportLoss>,
    /// Every loss.
    pub lost: u64,
    /// The serial after the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    /// The revision of the final write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

impl ImportReport {
    fn lose(&mut self, loss: Loss) {
        self.lost += 1;
        if self.losses.len() < MAX_LISTED_LOSSES {
            self.losses.push(ReportLoss {
                line: u32::try_from(loss.line).unwrap_or(u32::MAX),
                code: loss.code.to_owned(),
                detail: loss.detail,
            });
        }
    }
}

/// The records of one owner name that follow each other in the file.
#[derive(Debug, Default)]
struct Group {
    line: usize,
    name: Option<DnsName>,
    sets: BTreeMap<Rtype, (u32, Vec<tenko_core::dns::Rdata>)>,
}

impl Group {
    fn push(&mut self, record: FileRecord) {
        if self.name.is_none() {
            self.line = record.line;
            self.name = Some(record.name.clone());
        }
        let entry = self
            .sets
            .entry(record.rtype)
            .or_insert((record.ttl, Vec::new()));
        if !entry.1.contains(&record.rdata) {
            entry.1.push(record.rdata);
        }
    }
}

/// The SOA the file brings for the scope.
#[derive(Debug, Clone)]
struct FileSoa {
    serial: u32,
    values: SoaDefaults,
}

/// Reads groups from a file: owner groups, the apex SOA, the counts per type and the
/// losses of the reader.
struct GroupReader {
    reader: Reader,
    apex: DnsName,
    pending: Option<FileRecord>,
    soa: Option<FileSoa>,
    apex_ns: bool,
    done: bool,
}

impl GroupReader {
    fn new(text: &str, apex: &DnsName, max_generate: u32) -> ZoneResult<Self> {
        Ok(Self {
            reader: Reader::new(text, apex, max_generate)?,
            apex: apex.clone(),
            pending: None,
            soa: None,
            apex_ns: false,
            done: false,
        })
    }

    /// The next group, or `None` at the end; losses and counts go to `report`.
    fn next_group(&mut self, report: &mut ImportReport) -> ZoneResult<Option<Group>> {
        let mut group = Group::default();
        if let Some(record) = self.pending.take() {
            group.push(record);
        }
        while !self.done {
            let Some(item) = self.reader.next_item()? else {
                self.done = true;
                break;
            };
            let record = match item {
                Item::Loss(loss) => {
                    report.lose(loss);
                    continue;
                }
                Item::Record(record) => record,
            };
            *report.types.entry(record.rtype).or_default() += 1;
            if record.rtype == Rtype::SOA {
                self.take_soa(&record, report);
                continue;
            }
            if record.rtype == Rtype::NS && record.name == self.apex {
                self.apex_ns = true;
            }
            match &group.name {
                Some(name) if name != &record.name => {
                    self.pending = Some(record);
                    return Ok(Some(group));
                }
                _ => group.push(record),
            }
        }
        Ok(group.name.is_some().then_some(group))
    }

    fn take_soa(&mut self, record: &FileRecord, report: &mut ImportReport) {
        let lose = |report: &mut ImportReport, detail: &str| {
            report.lose(Loss {
                line: record.line,
                code: zonefile::LOSS_SOA,
                detail: detail.to_owned(),
            });
        };
        if record.name != self.apex {
            return lose(report, "an SOA record stands at the zone apex only");
        }
        if self.soa.is_some() {
            return lose(report, "the file has a second SOA record");
        }
        let Ok(RecordData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }) = record.rdata.decode(Rtype::SOA)
        else {
            return lose(report, "the SOA data does not decode");
        };
        let values = SoaDefaults {
            mname,
            rname,
            refresh,
            retry,
            expire,
            minimum,
            ttl: record.ttl,
        };
        if let Err(error) = values.validate() {
            return lose(report, &format!("the SOA values are refused: {error}"));
        }
        self.soa = Some(FileSoa { serial, values });
    }
}

/// How a group is merged.
struct Merge<'a> {
    zone: &'a Zone,
    scope: &'a ScopeName,
    replace: bool,
    /// RRsets at or below this revision existed before the import.
    start: Revision,
    /// The file has an apex NS set (with `replace` the stored one goes).
    file_apex_ns: bool,
    stamp: &'a Stamp,
}

/// What one group writes: (stored, new) per RRset that changes, and the keys of every
/// RRset the file holds at the owner, changed or not (for the purge of `replace`).
struct GroupWrites {
    writes: Vec<(Option<RrSet>, RrSet)>,
    keys: Vec<u64>,
}

impl GroupWrites {
    fn none() -> Self {
        Self {
            writes: Vec::new(),
            keys: Vec::new(),
        }
    }
}

/// Whether a stored RRset already holds what the file brings: then nothing is written.
fn unchanged(old: &RrSet, new: &RrSet) -> bool {
    old.origin == Origin::Manual
        && old.key.is_none()
        && old.ttl == new.ttl
        && old.rdata.len() == new.rdata.len()
        && old.rdata.iter().all(|data| new.rdata.contains(data))
}

/// Merges a group with what the store holds at its owner name.
fn merge_group(
    view: &dyn ReadView,
    merge: &Merge<'_>,
    group: Group,
    report: &mut ImportReport,
) -> ZoneResult<GroupWrites> {
    let Some(name) = group.name.clone() else {
        return Ok(GroupWrites::none());
    };
    let stored: BTreeMap<Rtype, (RrSet, Revision)> = node(view, merge.zone.id, merge.scope, &name)?
        .into_iter()
        .map(|(rrset, revision)| (rrset.rtype, (rrset, revision)))
        .collect();
    let mut writes: Vec<(Option<RrSet>, RrSet, bool)> = Vec::new();
    for (rtype, (ttl, rdata)) in group.sets {
        let previous = stored.get(&rtype);
        if let Some((old, _)) = previous
            && old.origin != Origin::Manual
        {
            report.lose(Loss {
                line: group.line,
                code: zonefile::LOSS_ORIGIN,
                detail: format!(
                    "{name} {rtype} belongs to the origin {}; the import does not replace it",
                    records::origin_name(old.origin)
                ),
            });
            continue;
        }
        let mut new = RrSet {
            zone: merge.zone.id,
            scope: merge.scope.clone(),
            name: name.clone(),
            rtype,
            ttl,
            rdata,
            origin: Origin::Manual,
            key: None,
            updated: merge.stamp.clone(),
        };
        let again = previous.is_some_and(|(_, revision)| *revision > merge.start);
        if let Some((old, _)) = previous
            && again
        {
            // Written by this import before: the file lists the name again.
            new.ttl = old.ttl;
            let mut union = old.rdata.clone();
            for data in new.rdata {
                if !union.contains(&data) {
                    union.push(data);
                }
            }
            new.rdata = union;
        }
        if let Err(error) = new.check(&merge.zone.name) {
            report.lose(Loss {
                line: group.line,
                code: zonefile::LOSS_RULE,
                detail: error.to_string(),
            });
            continue;
        }
        writes.push((previous.map(|(old, _)| old.clone()), new, again));
    }
    // The owner as it will stand: what stays of the stored RRsets, then the new ones.
    let mut standing: BTreeMap<Rtype, RrSet> = BTreeMap::new();
    for (rtype, (old, revision)) in &stored {
        let stays = !merge.replace
            || old.origin != Origin::Manual
            || *revision > merge.start
            || *rtype == Rtype::SOA
            || (*rtype == Rtype::NS && name == merge.zone.name && !merge.file_apex_ns);
        if stays {
            standing.insert(*rtype, old.clone());
        }
    }
    for (_, new, _) in &writes {
        standing.insert(new.rtype, new.clone());
    }
    if let Err(error) = check_node(&merge.zone.name, standing.values()) {
        report.lose(Loss {
            line: group.line,
            code: zonefile::LOSS_RULE,
            detail: error.to_string(),
        });
        return Ok(GroupWrites::none());
    }
    let mut out = GroupWrites {
        writes: Vec::with_capacity(writes.len()),
        keys: Vec::with_capacity(writes.len()),
    };
    for (old, new, again) in writes {
        out.keys.push(key_hash(&new.name, new.rtype));
        match (&old, again) {
            (Some(old), _) if unchanged(old, &new) => continue,
            (_, true) => {}
            (Some(_), false) => report.replaced += 1,
            (None, false) => report.added += 1,
        }
        out.writes.push((old, new));
    }
    Ok(out)
}

fn key_hash(name: &DnsName, rtype: Rtype) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    rtype.hash(&mut hasher);
    hasher.finish()
}

/// Whether the finish step of a `replace` import deletes this stored RRset.
fn purged(zone: &Zone, rrset: &RrSet, file_apex_ns: bool) -> bool {
    rrset.origin == Origin::Manual
        && !(rrset.name == zone.name
            && (rrset.rtype == Rtype::SOA || (rrset.rtype == Rtype::NS && !file_apex_ns)))
}

fn check_target(zone: &Zone, scope: &ScopeName) -> ZoneResult<()> {
    // WP6.1: a secondary zone's records come from its transfers only.
    super::secondary::check_writable(zone)?;
    if !holds_data(zone.kind) {
        return Err(ZoneError::zone_invalid(
            "kind",
            "only primary and RPZ zones hold records in Tenko",
        ));
    }
    if !zone.has_scope(scope) {
        return Err(
            ZoneError::zone_invalid("scope", "the zone has no such scope")
                .param("scope", scope.as_str()),
        );
    }
    Ok(())
}

impl ZoneService {
    /// Reads a zone file against the store without writing: counts, losses, and the
    /// RRsets an import would add, replace and remove. Also gives the RRsets the apply
    /// writes, for its chunks.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.zone.invalid`, `dns.zonefile.invalid`, or the store's
    /// error.
    pub async fn preview_import(
        &self,
        cx: &RequestCtx,
        request: &ImportRequest,
    ) -> ZoneResult<ImportReport> {
        Ok(self.preview(cx, request).await?.0)
    }

    async fn preview(
        &self,
        cx: &RequestCtx,
        request: &ImportRequest,
    ) -> ZoneResult<(ImportReport, u64)> {
        if request.text.len() > self.config.max_zone_file_bytes {
            return Err(ZoneError::zone_file(
                1,
                format!(
                    "the file is larger than {} bytes",
                    self.config.max_zone_file_bytes
                ),
            ));
        }
        let view = self.view(None).await?;
        let zone = Self::zone(view.as_ref(), request.zone)?.zone;
        check_target(&zone, &request.scope)?;
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let mut report = ImportReport {
            dry_run: true,
            ..ImportReport::default()
        };
        let mut groups = GroupReader::new(&request.text, &zone.name, self.config.max_generate)?;
        let mut seen: HashSet<u64> = HashSet::new();
        let mut writes = 0u64;
        // The preview cannot know whether the file has an apex NS set before it ends, so
        // it merges as if it had; the finish step knows.
        let merge = Merge {
            zone: &zone,
            scope: &request.scope,
            replace: request.replace,
            start: view.revision(),
            file_apex_ns: true,
            stamp: &stamp,
        };
        while let Some(group) = groups.next_group(&mut report)? {
            let group = merge_group(view.as_ref(), &merge, group, &mut report)?;
            if request.replace {
                seen.extend(group.keys);
            }
            writes += group.writes.len() as u64;
        }
        if request.replace {
            let file_apex_ns = groups.apex_ns;
            let mut after: Option<Vec<u8>> = None;
            loop {
                let mut range = rrset_range(zone.id, Some(&request.scope), None);
                if let Some(after) = &after {
                    range = range.after(after.clone());
                }
                let rows = view.scan(RRSETS.name(), range, 4096, false)?;
                let exhausted = rows.len() < 4096;
                for (key, versioned) in rows {
                    after = Some(key.to_vec());
                    let rrset: RrSet = RRSETS.decode(&versioned.value)?;
                    if purged(&zone, &rrset, file_apex_ns)
                        && !seen.contains(&key_hash(&rrset.name, rrset.rtype))
                    {
                        report.removed += 1;
                    }
                }
                if exhausted {
                    break;
                }
            }
        }
        Ok((report, writes))
    }

    /// Checks the file with a preview, stages it and submits the import job; returns the
    /// job and the preview.
    ///
    /// # Errors
    ///
    /// The preview's errors, or the job engine's.
    pub async fn start_import(
        &self,
        cx: &RequestCtx,
        request: ImportRequest,
    ) -> ZoneResult<(JobId, ImportReport)> {
        let (preview, writes) = self.preview(cx, &request).await?;
        let chunk = self.config.import_chunk.max(1) as u64;
        let chunks = u32::try_from(writes.div_ceil(chunk).max(1)).unwrap_or(u32::MAX);
        let id = Uuid::now_v7();
        self.staging.put(
            id,
            ImportRun {
                request: request.clone(),
                chunk: self.config.import_chunk.max(1),
                journal: self.config.journal,
                max_generate: self.config.max_generate,
                state: None,
            },
        );
        let mut steps = Vec::with_capacity(chunks as usize + 1);
        for index in 0..chunks {
            steps.push(StepSpec {
                kind: StepKind::from_static(CHUNK_STEP),
                params: HexBytes(
                    to_cbor(&StepParams {
                        import: id,
                        chunk: index,
                        chunks,
                    })?
                    .to_vec(),
                ),
                timeout: None,
            });
        }
        steps.push(StepSpec {
            kind: StepKind::from_static(FINISH_STEP),
            params: HexBytes(
                to_cbor(&StepParams {
                    import: id,
                    chunk: chunks,
                    chunks,
                })?
                .to_vec(),
            ),
            timeout: None,
        });
        let spec = JobSpec {
            kind: JobKind::from_static(IMPORT_JOB),
            title: MessageKey::from_static(IMPORT_TITLE),
            targets: vec![ObjectRef::from(request.zone)],
            steps,
            timeout: Duration::from_secs(4 * 3600),
            group: None,
            group_limit: None,
            idempotency: None,
            node: None,
        };
        match self.jobs.submit(spec, cx).await {
            Ok(job) => Ok((job, preview)),
            Err(error) => {
                self.staging.take(id);
                Err(error.into())
            }
        }
    }
}

// ----- staging and steps ----------------------------------------------------------------

/// The zone files of running imports, by import, in memory on this controller.
#[derive(Default)]
pub struct ImportStaging {
    runs: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<ImportRun>>>>,
}

impl std::fmt::Debug for ImportStaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let runs = self
            .runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("ImportStaging")
            .field("runs", &runs)
            .finish()
    }
}

impl ImportStaging {
    fn put(&self, id: Uuid, run: ImportRun) {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Arc::new(tokio::sync::Mutex::new(run)));
    }

    fn get(&self, id: Uuid) -> Option<Arc<tokio::sync::Mutex<ImportRun>>> {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    fn take(&self, id: Uuid) {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }

    /// Imports staged now.
    pub fn len(&self) -> usize {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no import is staged.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A staged import.
struct ImportRun {
    request: ImportRequest,
    chunk: usize,
    journal: journal::JournalLimits,
    max_generate: u32,
    state: Option<RunState>,
}

/// What the steps of an import carry from one to the next.
struct RunState {
    groups: GroupReader,
    zone: Zone,
    start: Revision,
    report: ImportReport,
    next_chunk: u32,
    /// The records the chunks removed and added, while they fit one journal entry.
    journal: Option<(Vec<JournalRecord>, Vec<JournalRecord>)>,
    /// With `replace`, the RRsets the file holds (by key hash): the purge keeps them.
    file_keys: HashSet<u64>,
}

/// Parameters of the import steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct StepParams {
    import: Uuid,
    chunk: u32,
    chunks: u32,
}

/// The step handlers of an import.
pub(crate) fn step_handlers(staging: &Arc<ImportStaging>) -> Vec<Arc<dyn StepHandler>> {
    vec![
        Arc::new(ChunkStep(Arc::clone(staging))),
        Arc::new(FinishStep(Arc::clone(staging))),
    ]
}

fn missing() -> StepError {
    StepError::Coded(Box::new(CodedError::new(
        STAGING_MISSING,
        409,
        "the zone file of this import is no longer staged on this controller; import it again",
    )))
}

fn coded(error: ZoneError) -> StepError {
    StepError::Coded(Box::new(error.into_coded()))
}

fn params(raw: &[u8]) -> Result<StepParams, StepError> {
    from_cbor(raw).map_err(|error| StepError::InvalidParams(error.to_string()))
}

fn preview_of(raw: &[u8], key: &'static str) -> Result<StepPreview, StepError> {
    let params = params(raw)?;
    Ok(StepPreview {
        summary: MessageKey::from_static(key),
        args: BTreeMap::from([
            ("chunk".to_owned(), (params.chunk + 1).to_string()),
            ("chunks".to_owned(), params.chunks.to_string()),
        ]),
        changes: Vec::new(),
        manual: None,
        warnings: Vec::new(),
    })
}

/// `dns.import.chunk`: the next RRsets of the file, one batch.
struct ChunkStep(Arc<ImportStaging>);

#[async_trait::async_trait]
impl StepHandler for ChunkStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(CHUNK_STEP)
    }

    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        preview_of(params, CHUNK_PREVIEW)
    }

    async fn execute(&self, raw: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = params(raw)?;
        let run = self.0.get(params.import).ok_or_else(missing)?;
        let mut run = run.lock().await;
        let run = &mut *run;
        let view = cx.store.read(ReadConsistency::Local).await?;
        if run.state.is_none() {
            let zone = ZoneService::zone(view.as_ref(), run.request.zone)
                .map_err(coded)?
                .zone;
            check_target(&zone, &run.request.scope).map_err(coded)?;
            run.state = Some(RunState {
                groups: GroupReader::new(&run.request.text, &zone.name, run.max_generate)
                    .map_err(coded)?,
                zone,
                start: view.revision(),
                report: ImportReport::default(),
                next_chunk: 0,
                journal: Some((Vec::new(), Vec::new())),
                file_keys: HashSet::new(),
            });
        }
        let Some(state) = run.state.as_mut() else {
            return Err(missing());
        };
        if state.next_chunk != params.chunk {
            return Err(missing());
        }
        state.next_chunk += 1;
        let last = params.chunk + 1 == params.chunks;
        let stamp = Stamp::new(cx.request.now, cx.request.principal.clone());
        loop {
            let mut batch = WriteBatch::for_request(&cx.request);
            batch.idempotency = None;
            let mut count = 0usize;
            let view = cx.store.read(ReadConsistency::Local).await?;
            let merge = Merge {
                zone: &state.zone,
                scope: &run.request.scope,
                replace: run.request.replace,
                start: state.start,
                file_apex_ns: true,
                stamp: &stamp,
            };
            while count < run.chunk {
                let Some(group) = state.groups.next_group(&mut state.report).map_err(coded)? else {
                    break;
                };
                let group =
                    merge_group(view.as_ref(), &merge, group, &mut state.report).map_err(coded)?;
                if run.request.replace {
                    state.file_keys.extend(group.keys);
                }
                for (old, new) in group.writes {
                    if let Some((removed, added)) = &mut state.journal {
                        let item = records::Diff {
                            key: new.key(),
                            before: old.clone(),
                            after: Some(new.clone()),
                        };
                        let (r, a) = records::journal_diff(std::iter::once(&item));
                        removed.extend(r);
                        added.extend(a);
                        if removed.len() + added.len() > JOURNAL_RECORDS {
                            state.journal = None;
                        }
                    }
                    stage_put(&mut batch, old.as_ref(), &new).map_err(coded)?;
                    count += 1;
                }
            }
            drop(view);
            let more = !state.groups.done || state.groups.pending.is_some();
            if last && more {
                // More RRsets than the preview counted: write this batch now and go on.
                cx.store.propose(batch).await?;
                state.journal = None;
                continue;
            }
            if params.chunks > 1 {
                state.journal = None;
            }
            tracing::info!(
                zone = %state.zone.name,
                chunk = params.chunk + 1,
                chunks = params.chunks,
                rrsets = count,
                "zone file import chunk written"
            );
            let output = match super::jobs::stage_or_propose(cx, batch).await? {
                Some(committed) => {
                    Some(to_cbor(&committed).map_err(|error| StepError::coded(&error))?)
                }
                None => None,
            };
            return Ok(StepOutcome::Done { output });
        }
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

/// `dns.import.finish`: the purge of `replace`, the SOA, the journal and the audit record.
struct FinishStep(Arc<ImportStaging>);

#[async_trait::async_trait]
impl StepHandler for FinishStep {
    fn kind(&self) -> StepKind {
        StepKind::from_static(FINISH_STEP)
    }

    fn idempotent(&self) -> bool {
        false
    }

    async fn preview(&self, params: &[u8], _view: &dyn ReadView) -> Result<StepPreview, StepError> {
        preview_of(params, FINISH_PREVIEW)
    }

    async fn execute(&self, raw: &[u8], cx: &StepContext) -> Result<StepOutcome, StepError> {
        let params = params(raw)?;
        let shared = self.0.get(params.import).ok_or_else(missing)?;
        let result = finish(&shared, cx).await;
        self.0.take(params.import);
        let report = result?;
        let json = serde_json::to_vec(&report)
            .map_err(|error| StepError::InvalidParams(error.to_string()))?;
        Ok(StepOutcome::Done {
            output: Some(bytes::Bytes::from(json)),
        })
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

#[allow(
    clippy::too_many_lines,
    reason = "the purge, the SOA, the journal and the audit record of one import"
)]
async fn finish(
    shared: &Arc<tokio::sync::Mutex<ImportRun>>,
    cx: &StepContext,
) -> Result<ImportReport, StepError> {
    let mut run = shared.lock().await;
    let run = &mut *run;
    let Some(state) = run.state.as_mut() else {
        return Err(missing());
    };
    let scope = run.request.scope.clone();
    let file_apex_ns = state.groups.apex_ns;
    let stamp = Stamp::new(cx.request.now, cx.request.principal.clone());
    let mut removed_records: Vec<JournalRecord> = Vec::new();
    if run.request.replace {
        // Delete what the import did not write, in batches; the last one goes with the SOA.
        let mut after: Option<Vec<u8>> = None;
        loop {
            let view = cx.store.read(ReadConsistency::Local).await?;
            let mut range = rrset_range(state.zone.id, Some(&scope), None);
            if let Some(after) = &after {
                range = range.after(after.clone());
            }
            let rows = view.scan(RRSETS.name(), range, run.chunk, false)?;
            if rows.is_empty() {
                break;
            }
            let mut batch = WriteBatch::for_request(&cx.request);
            batch.idempotency = None;
            for (key, versioned) in &rows {
                after = Some(key.to_vec());
                let rrset: RrSet = RRSETS
                    .decode(&versioned.value)
                    .map_err(|error| StepError::coded(&error))?;
                if versioned.revision <= state.start
                    && purged(&state.zone, &rrset, file_apex_ns)
                    && !state
                        .file_keys
                        .contains(&key_hash(&rrset.name, rrset.rtype))
                {
                    if state.journal.is_some() {
                        removed_records.extend(journal_records(&rrset));
                    }
                    stage_delete(&mut batch, &rrset);
                    state.report.removed += 1;
                }
            }
            if !batch.mutations.is_empty() {
                cx.store.propose(batch).await?;
            }
        }
    }
    let view = cx.store.read(ReadConsistency::Local).await?;
    let row = ZoneService::zone(view.as_ref(), state.zone.id).map_err(coded)?;
    let mut zone = row.zone;
    let soa_key = RrSetKey {
        zone: zone.id,
        scope: scope.clone(),
        name: zone.name.clone(),
        rtype: Rtype::SOA,
    };
    let (old_soa, soa_revision) = view.get_typed(&RRSETS, &soa_key)?.ok_or_else(|| {
        coded(ZoneError::zone_invalid(
            "scope",
            "the zone scope has no SOA record",
        ))
    })?;
    let current = soa_serial(&old_soa).unwrap_or_default();
    let file_soa = state.groups.soa.clone();
    let values = file_soa
        .as_ref()
        .map_or_else(|| zone.soa.clone(), |soa| soa.values.clone());
    // An import that changes no RRset, no SOA value and brings no newer serial leaves the
    // serial and the journal alone, so importing an export again gives the same file.
    let file_serial = file_soa.as_ref().map(|soa| soa.serial);
    let same_soa = soa_rrset(&zone, &scope, &values, current, stamp.clone());
    let nothing = state.report.added == 0
        && state.report.replaced == 0
        && state.report.removed == 0
        && same_soa.ttl == old_soa.ttl
        && same_soa.rdata == old_soa.rdata
        && !file_serial.is_some_and(|serial| serial::newer(serial, current));
    let mut batch = WriteBatch::for_request(&cx.request);
    batch.idempotency = None;
    let to = if nothing {
        current
    } else {
        stage_serial(
            &mut batch,
            view.as_ref(),
            run.journal,
            state,
            &mut zone,
            row.revision,
            (&soa_key, &old_soa, soa_revision),
            &values,
            file_serial,
            &stamp,
            removed_records,
        )?
    };
    let report = &mut state.report;
    report.dry_run = false;
    report.serial = Some(to);
    batch.audit(
        AuditDraft::success(audit::RECORD_IMPORT, vec![ObjectRef::from(zone.id)])
            .with_source_ip(cx.request.source_ip)
            .with_context("zone", zone.name.as_str())
            .with_context("scope", scope.as_str())
            .with_context("added", report.added.to_string())
            .with_context("replaced", report.replaced.to_string())
            .with_context("removed", report.removed.to_string())
            .with_context("lost", report.lost.to_string())
            .with_context("serial", to.to_string()),
    );
    drop(view);
    // Proposed directly, not staged with the step record, so the report names its revision.
    let committed = cx.store.propose(batch).await?;
    report.revision = Some(committed.revision);
    Ok(report.clone())
}

/// Writes the scope's new SOA, the zone's SOA settings when the default scope's file SOA
/// changed them, and the journal entry or reset of a finished import; returns the serial.
#[allow(
    clippy::too_many_arguments,
    reason = "the parts of the final write of one import"
)]
fn stage_serial(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    limits: journal::JournalLimits,
    state: &mut RunState,
    zone: &mut Zone,
    zone_revision: Revision,
    (soa_key, old_soa, soa_revision): (&RrSetKey, &RrSet, Revision),
    values: &SoaDefaults,
    file_serial: Option<u32>,
    stamp: &Stamp,
    mut removed_records: Vec<JournalRecord>,
) -> Result<u32, StepError> {
    let scope = soa_key.scope.clone();
    let current = soa_serial(old_soa).unwrap_or_default();
    let to = serial::imported(zone.serial, current, file_serial, stamp.at);
    let new_soa = soa_rrset(zone, &scope, values, to, stamp.clone());
    batch.expect_typed(&RRSETS, soa_key, Some(soa_revision));
    stage_put(batch, Some(old_soa), &new_soa).map_err(coded)?;
    if scope == ScopeName::DEFAULT && file_serial.is_some() && &zone.soa != values {
        zone.soa = values.clone();
        zone.updated = stamp.clone();
        batch.expect_typed(&ZONES, &zone.id, Some(zone_revision));
        batch.put_typed(&ZONES, &zone.id, &*zone)?;
    }
    match state.journal.take() {
        Some((mut removed, mut added))
            if removed.len() + removed_records.len() + added.len() <= JOURNAL_RECORDS =>
        {
            let mut journal_removed: Vec<JournalRecord> = journal_records(old_soa).collect();
            journal_removed.append(&mut removed);
            journal_removed.append(&mut removed_records);
            let mut journal_added: Vec<JournalRecord> = journal_records(&new_soa).collect();
            journal_added.append(&mut added);
            journal::stage_append(
                batch,
                view,
                limits,
                &JournalEntry {
                    zone: zone.id,
                    scope: scope.clone(),
                    from_serial: current,
                    to_serial: to,
                    revision: view.revision(),
                    at: stamp.at,
                    removed: journal_removed,
                    added: journal_added,
                },
            )
            .map_err(coded)?;
        }
        _ => {
            journal::stage_reset(batch, view, zone.id, &scope).map_err(coded)?;
        }
    }
    Ok(to)
}

/// The report of a finished import job: the JSON output of its final step.
pub fn report_of(job: &tenko_jobs::Job) -> Option<ImportReport> {
    job.steps
        .iter()
        .rev()
        .find(|step| step.kind == StepKind::from_static(FINISH_STEP))
        .and_then(|step| step.output.as_ref())
        .and_then(|output| serde_json::from_slice(&output.0).ok())
}
