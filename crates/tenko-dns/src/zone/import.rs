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
//! **A Windows file** ([`ImportRequest::dialect`] `windows`, WP13.4, identity plan section
//! 3.6, MIG-07): an A, AAAA or PTR RRset all of whose records carry an aging mark
//! (`[AGE:n]`, the records Windows calls dynamic) is a candidate. A candidate is written
//! with the origin `ad` and without an owner, so that in a zone with ownership on only the
//! host it names (or a privileged principal) may claim it, only when the never-claimable
//! list lets it through, it matches the operator's rule, and the import carries the
//! operator's approval of exactly the set the preview listed ([`claim`]). Every other
//! RRset is `manual` as above: a static record of a controller or a server, an RRset that
//! mixes aged and static records, and every candidate of an import without an approval.
//! The preview lists the claimable RRsets by name, a page at a time, with the digest that
//! approves them, and the candidates it holds back with the reason. Such an import also
//! replaces the `ad` RRsets an earlier import wrote, and with `replace` purges them too; it
//! never replaces another origin. The RFC 1035 dialect, the default, writes `manual` only,
//! whatever the zone's settings: a deployment without Active Directory sees no change.
//!
//! The batches of the chunks do not expect the versions of what they replace: a change
//! made while an import runs may be overwritten by it. An import that one chunk holds and
//! that changes at most [`JOURNAL_RECORDS`] records leaves one journal entry; a larger one
//! resets the scope's journal, so a secondary asking for an older serial gets AXFR. When a
//! step fails (or the controller restarts and the staged file is gone), the chunks written
//! so far stay and the job ends rolled back with the error; importing again completes it.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::DefaultHasher},
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
    zonefile::{self, Dialect, FileRecord, Item, Loss, Reader},
};

pub mod claim;

pub use claim::{
    ClaimDigest, ClaimRequest, ClaimRule, ClaimableEntry, HeldEntry, HeldReason, claimable_type,
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
    // WP13.4
    /// The dialect of the file; [`Dialect::Windows`] makes the aged A, AAAA and PTR RRsets
    /// candidates.
    pub dialect: Dialect,
    /// The rule, the approval and the listing page of the claimable names of a Windows
    /// file; empty for every other import.
    pub claim: ClaimRequest,
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
    // WP13.4
    /// The RRsets a Windows file makes claimable (origin `ad`, no owner): in a preview,
    /// those an approval of [`ImportReport::claimable_digest`] would make claimable; after
    /// an import, those it made claimable.
    #[serde(default)]
    pub claimable: u64,
    /// The revision of the final write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
    /// The digest of the claimable set: what a preview asks the operator to approve, and
    /// what an import approved. Absent outside the Windows dialect and past
    /// [`claim::MAX_CANDIDATES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimable_digest: Option<String>,
    /// The claimable RRsets in name order: a page of the preview's listing, or the first
    /// [`claim::DEFAULT_PAGE`] an import made claimable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claimable_names: Vec<ClaimableEntry>,
    /// The cursor of the preview's next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimable_next: Option<String>,
    /// The file has more than [`claim::MAX_CANDIDATES`] candidates: none becomes claimable.
    #[serde(default)]
    pub claimable_overflow: bool,
    /// Candidates that stay static, every reason together.
    #[serde(default)]
    pub held_back: u64,
    /// The first [`claim::MAX_LISTED_HELD`] of them in name order, with the reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held_back_names: Vec<HeldEntry>,
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
    /// The types whose records all carried an aging mark (WP13.4).
    aged: BTreeMap<Rtype, bool>,
}

impl Group {
    fn push(&mut self, record: FileRecord) {
        if self.name.is_none() {
            self.line = record.line;
            self.name = Some(record.name.clone());
        }
        let aged = self.aged.entry(record.rtype).or_insert(record.aged);
        *aged = *aged && record.aged;
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
    /// The reader of an import's file.
    fn of(request: &ImportRequest, apex: &DnsName, max_generate: u32) -> ZoneResult<Self> {
        Self::new(&request.text, apex, max_generate, request.dialect)
    }

    fn new(text: &str, apex: &DnsName, max_generate: u32, dialect: Dialect) -> ZoneResult<Self> {
        Ok(Self {
            reader: Reader::with_dialect(text, apex, max_generate, dialect)?,
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
    /// The dialect of the file (WP13.4).
    dialect: Dialect,
    /// Which candidates may become claimable.
    claim: ClaimMode<'a>,
}

/// Which candidates of a Windows file a merge makes claimable.
#[derive(Clone, Copy)]
enum ClaimMode<'a> {
    /// None, and none is reported (the RFC 1035 dialect).
    Off,
    /// None: each candidate is held back for this reason (an import without an approval,
    /// a file with too many candidates).
    Hold(HeldReason),
    /// Those of the set (the plan's, or the approved one), unless the store holds another
    /// record at the name; the others the plan already holds back.
    Allowed(&'a HashMap<(DnsName, Rtype), ClaimableEntry>),
}

/// What became of a candidate RRset in a merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pick {
    /// Not a candidate, or one the plan already reports.
    Quiet,
    /// Claimable.
    Claimable,
    /// Held back for this reason.
    Held(HeldReason),
}

/// The candidates a merge made claimable or held back, in file order.
#[derive(Debug, Default)]
struct Tally {
    selected: Vec<(DnsName, Rtype)>,
    held: Vec<HeldEntry>,
}

impl Tally {
    /// Records what became of the RRset `new` (of the group at `line`).
    fn record(&mut self, pick: Pick, new: &RrSet, line: usize) {
        match pick {
            Pick::Claimable if new.origin == Origin::Ad => {
                self.selected.push((new.name.clone(), new.rtype));
            }
            Pick::Held(reason) => self.held.push(HeldEntry {
                name: new.name.clone(),
                rtype: new.rtype,
                line: u32::try_from(line).unwrap_or(u32::MAX),
                reason,
            }),
            Pick::Quiet | Pick::Claimable => {}
        }
    }
}

impl Merge<'_> {
    /// What becomes of an RRset of the file at a name that holds `stored`: whether it is
    /// claimable (WP13.4: an aged address or PTR RRset of a Windows file that the claim
    /// mode allows, at a name that holds nothing in the store of another origin than `ad`
    /// from before the import).
    fn pick(
        &self,
        name: &DnsName,
        rtype: Rtype,
        aged: bool,
        stored: &BTreeMap<Rtype, (RrSet, Revision)>,
    ) -> Pick {
        if !(self.dialect == Dialect::Windows && claimable_type(rtype) && aged) {
            return Pick::Quiet;
        }
        match self.claim {
            ClaimMode::Off => Pick::Quiet,
            ClaimMode::Hold(reason) => Pick::Held(reason),
            ClaimMode::Allowed(allowed) => {
                if !allowed.contains_key(&(name.clone(), rtype)) {
                    return Pick::Quiet;
                }
                let other = stored.values().any(|(rrset, revision)| {
                    *revision <= self.start && !matches!(rrset.origin, Origin::Ad | Origin::Dnssec)
                });
                if other {
                    Pick::Held(HeldReason::OtherData)
                } else {
                    Pick::Claimable
                }
            }
        }
    }

    /// An RRset of the file: `manual`, or (WP13.4) `ad` without an owner when it is
    /// claimable.
    fn rrset(
        &self,
        name: &DnsName,
        rtype: Rtype,
        ttl: u32,
        rdata: Vec<tenko_core::dns::Rdata>,
        claimable: bool,
    ) -> RrSet {
        RrSet {
            zone: self.zone.id,
            scope: self.scope.clone(),
            name: name.clone(),
            rtype,
            ttl,
            rdata,
            origin: if claimable {
                Origin::Ad
            } else {
                Origin::Manual
            },
            key: None,
            principal: None,
            updated: self.stamp.clone(),
        }
    }

    /// Whether the import writes over an RRset of `origin`: `manual`, and in the Windows
    /// dialect `ad` too.
    fn writes_over(&self, origin: Origin) -> bool {
        origin == Origin::Manual || (self.dialect == Dialect::Windows && origin == Origin::Ad)
    }
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
    old.origin == new.origin
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
    tally: &mut Tally,
) -> ZoneResult<GroupWrites> {
    let Some(name) = group.name.clone() else {
        return Ok(GroupWrites::none());
    };
    let stored: BTreeMap<Rtype, (RrSet, Revision)> = node(view, merge.zone.id, merge.scope, &name)?
        .into_iter()
        .map(|(rrset, revision)| (rrset.rtype, (rrset, revision)))
        .collect();
    let mut writes: Vec<(Option<RrSet>, RrSet, bool, Pick)> = Vec::new();
    for (rtype, (ttl, rdata)) in group.sets {
        let previous = stored.get(&rtype);
        if let Some((old, _)) = previous
            && !merge.writes_over(old.origin)
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
        let aged = group.aged.get(&rtype).copied().unwrap_or(false);
        let pick = merge.pick(&name, rtype, aged, &stored);
        let mut new = merge.rrset(&name, rtype, ttl, rdata, pick == Pick::Claimable);
        let again = previous.is_some_and(|(_, revision)| *revision > merge.start);
        if let Some((old, _)) = previous
            && again
        {
            // Written by this import before: the file lists the name again. A static
            // record of either listing keeps the RRset `manual`.
            new.ttl = old.ttl;
            if old.origin == Origin::Manual {
                new.origin = Origin::Manual;
            }
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
        writes.push((previous.map(|(old, _)| old.clone()), new, again, pick));
    }
    // The owner as it will stand: what stays of the stored RRsets, then the new ones.
    let mut standing: BTreeMap<Rtype, RrSet> = BTreeMap::new();
    for (rtype, (old, revision)) in &stored {
        let stays = !merge.replace
            || !merge.writes_over(old.origin)
            || *revision > merge.start
            || *rtype == Rtype::SOA
            || (*rtype == Rtype::NS && name == merge.zone.name && !merge.file_apex_ns);
        if stays {
            standing.insert(*rtype, old.clone());
        }
    }
    for (_, new, _, _) in &writes {
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
    for (old, new, again, pick) in writes {
        out.keys.push(key_hash(&new.name, new.rtype));
        // A name the file lists again is reported once, at its first listing; a listing
        // with a static record keeps the RRset `manual` (above), and the plan holds such a
        // name back anyway.
        if !again {
            tally.record(pick, &new, group.line);
        }
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
fn purged(zone: &Zone, rrset: &RrSet, file_apex_ns: bool, dialect: Dialect) -> bool {
    (rrset.origin == Origin::Manual || (dialect == Dialect::Windows && rrset.origin == Origin::Ad))
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

/// The 429 of an import while [`MAX_STAGED`] imports are staged.
fn busy() -> ZoneError {
    ZoneError::new(
        IMPORT_BUSY,
        429,
        format!(
            "{MAX_STAGED} zone file imports are running; start this one when one of them has ended"
        ),
    )
}

/// The 429 of an import of a zone that has one running.
fn zone_busy() -> ZoneError {
    ZoneError::new(
        IMPORT_BUSY,
        429,
        "an import of this zone is running; start this one when it has ended",
    )
}

impl ZoneService {
    /// Lets go of staged imports whose job has ended (succeeded, failed, rolled back,
    /// canceled, or gone), then refuses a new import of `zone` while one of it runs or
    /// while [`MAX_STAGED`] imports are staged.
    async fn check_staging(&self, zone: ZoneId) -> ZoneResult<()> {
        let staged = self.staging.jobs();
        if staged.iter().any(|(_, job)| job.is_some()) {
            let view = self.view(None).await?;
            for (id, job) in staged {
                let Some(job) = job else { continue };
                let ended = view
                    .get_typed(&tenko_jobs::tables::JOBS, &job)?
                    .is_none_or(|(job, _)| job.state.is_terminal());
                if ended {
                    self.staging.take(id);
                }
            }
        }
        if self.staging.holds_zone(zone) {
            return Err(zone_busy());
        }
        if self.staging.len() >= MAX_STAGED {
            return Err(busy());
        }
        Ok(())
    }
}

/// The code of [`busy`].
pub const IMPORT_BUSY: &str = "dns.import.busy";

/// The approved set of an import: each claimable RRset with its listing entry.
type ClaimSet = HashMap<(DnsName, Rtype), ClaimableEntry>;

/// What a preview gives the import that follows it.
struct Previewed {
    report: ImportReport,
    /// RRsets the chunks write.
    writes: u64,
    /// The digest of the claimable set and the set (a planned Windows file).
    approved: Option<(ClaimDigest, ClaimSet)>,
}

/// The claimable set an approval stands for: the preview's set when its digest is the
/// approved one.
fn approved_set(previewed: &mut Previewed, approval: ClaimDigest) -> ZoneResult<ClaimSet> {
    if previewed.report.claimable_overflow {
        return Err(ZoneError::new(
            claim::CLAIMABLE_TOO_MANY,
            422,
            format!(
                "the file has more than {} records with an aging mark; import it in parts to approve claimable names",
                claim::MAX_CANDIDATES
            ),
        ));
    }
    match previewed.approved.take() {
        Some((digest, set)) if digest == approval => Ok(set),
        _ => Err(ZoneError::new(
            claim::CLAIMABLE_CHANGED,
            409,
            "the claimable names of this file are not the ones approved: the file, the zone or its records changed since the preview; preview it again",
        )
        .param(
            "digest",
            previewed.report.claimable_digest.clone().unwrap_or_default(),
        )),
    }
}

/// Checks the claim part of a request: its bounds, and that only a Windows file has one.
fn check_claim(request: &ImportRequest) -> ZoneResult<()> {
    request.claim.check()?;
    if request.dialect != Dialect::Windows && !request.claim.is_empty() {
        return Err(ZoneError::new(
            claim::CLAIMABLE_INVALID,
            400,
            "claimable: only a file in the Windows dialect has claimable names",
        )
        .param("field", "dialect"));
    }
    Ok(())
}

/// The name servers the store names for a zone scope: the hosts of its apex NS RRset, the
/// MNAME of its SOA RRset and of the zone's SOA settings.
fn name_servers(
    view: &dyn ReadView,
    zone: &Zone,
    scope: &ScopeName,
) -> ZoneResult<HashSet<DnsName>> {
    let mut out = HashSet::from([zone.soa.mname.clone()]);
    for (rrset, _) in node(view, zone.id, scope, &zone.name)? {
        if !matches!(rrset.rtype, Rtype::NS | Rtype::SOA) {
            continue;
        }
        for record in rrset.records().unwrap_or_default() {
            match record {
                RecordData::Ns { host } => {
                    out.insert(host);
                }
                RecordData::Soa { mname, .. } => {
                    out.insert(mname);
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Fills the claimable part of a preview's report from the plan and the merge: the count,
/// the digest, the page of the listing and the candidates held back. Gives the digest and
/// the claimable set of a planned file.
fn finish_listing(
    report: &mut ImportReport,
    request: &ImportRequest,
    plan: Option<claim::Plan>,
    tally: Tally,
) -> Option<(ClaimDigest, ClaimSet)> {
    let Tally {
        selected,
        held: mut merge_held,
    } = tally;
    let selected: BTreeSet<(DnsName, Rtype)> = selected.into_iter().collect();
    report.claimable = selected.len() as u64;
    let mut approved = None;
    let mut held = Vec::new();
    if let Some(plan) = plan {
        report.claimable_overflow = plan.overflow;
        held = plan.held;
        if !plan.overflow {
            let digest = claim::digest_of(request.zone, &request.scope, &request.text, &selected);
            report.claimable_digest = Some(digest.to_string());
            let (names, next) = claim::page(&selected, &plan.allowed, &request.claim);
            report.claimable_names = names;
            report.claimable_next = next;
            let mut allowed = plan.allowed;
            allowed.retain(|key, _| selected.contains(key));
            approved = Some((digest, allowed));
        }
    }
    held.append(&mut merge_held);
    report.held_back = claim::list_held(&mut held);
    report.held_back_names = held;
    approved
}

/// Refuses an import after which the zone would hold more than [`MAX_ZONE_RRSETS`] RRsets
/// (`max`) over all its scopes. `remaining` is what a replacing import keeps of the scope; the
/// other scopes, and the whole scope of an import that does not replace, are counted.
async fn check_zone_bound(
    view: &dyn ReadView,
    zone: &Zone,
    scope: &ScopeName,
    report: &ImportReport,
    remaining: Option<u64>,
    max: u64,
) -> ZoneResult<()> {
    if report.added == 0 {
        return Ok(());
    }
    let mut held = 0u64;
    let mut after: Option<Vec<u8>> = None;
    loop {
        let mut range = rrset_range(zone.id, None, None);
        if let Some(after) = &after {
            range = range.after(after.clone());
        }
        let rows = view.scan(RRSETS.name(), range, 4096, false)?;
        let exhausted = rows.len() < 4096;
        for (key, versioned) in rows {
            after = Some(key.to_vec());
            if remaining.is_some() {
                let rrset: RrSet = RRSETS.decode(&versioned.value)?;
                if rrset.scope == *scope {
                    continue;
                }
            }
            held += 1;
        }
        if exhausted {
            break;
        }
        tokio::task::yield_now().await;
    }
    let total = held + remaining.unwrap_or(0) + report.added;
    if total > max {
        return Err(ZoneError::zone_file(
            1,
            format!("the zone would hold {total} RRsets after the import, more than {max}"),
        ));
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
        check_claim(request)?;
        Ok(self.preview(cx, request, true).await?.report)
    }

    /// The preview; with `plan`, a Windows file's candidates are planned and listed, else
    /// (an import without an approval) every candidate is held back as not approved.
    #[allow(
        clippy::too_many_lines,
        reason = "the merge read, the purge count, the bounds and the claimable listing of one preview"
    )]
    async fn preview(
        &self,
        cx: &RequestCtx,
        request: &ImportRequest,
        plan: bool,
    ) -> ZoneResult<Previewed> {
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
        // WP13.4: the plan of a Windows file's candidates, from two reads of the file.
        let windows = request.dialect == Dialect::Windows;
        let claim_plan = if windows && plan {
            let name_servers = name_servers(view.as_ref(), &zone, &request.scope)?;
            let checks = claim::Checks::new(&zone.name, &request.claim, name_servers);
            let max_generate = self.config.max_generate;
            let text = &request.text;
            let apex = &zone.name;
            Some(
                claim::plan(
                    || Reader::with_dialect(text, apex, max_generate, Dialect::Windows),
                    &checks,
                )
                .await?,
            )
        } else {
            None
        };
        let mode = match &claim_plan {
            _ if !windows => ClaimMode::Off,
            None => ClaimMode::Hold(HeldReason::NotApproved),
            Some(plan) if plan.overflow => ClaimMode::Hold(HeldReason::TooMany),
            Some(plan) => ClaimMode::Allowed(&plan.allowed),
        };
        let mut tally = Tally::default();
        let mut groups = GroupReader::of(request, &zone.name, self.config.max_generate)?;
        let mut seen: HashSet<u64> = HashSet::new();
        let mut writes = 0u64;
        let mut groups_read = 0u64;
        // The preview cannot know whether the file has an apex NS set before it ends, so
        // it merges as if it had; the finish step knows.
        let merge = Merge {
            zone: &zone,
            scope: &request.scope,
            replace: request.replace,
            start: view.revision(),
            file_apex_ns: true,
            stamp: &stamp,
            dialect: request.dialect,
            claim: mode,
        };
        while let Some(group) = groups.next_group(&mut report)? {
            // The preview runs on the API's runtime: a large file gives the other requests
            // their turn.
            groups_read += 1;
            if groups_read.is_multiple_of(YIELD_EVERY) {
                tokio::task::yield_now().await;
            }
            let group = merge_group(view.as_ref(), &merge, group, &mut report, &mut tally)?;
            if request.replace {
                seen.extend(group.keys);
            }
            writes += group.writes.len() as u64;
        }
        let approved = finish_listing(&mut report, request, claim_plan, tally);
        let mut remaining = None;
        if request.replace {
            let file_apex_ns = groups.apex_ns;
            let mut kept = 0u64;
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
                    if purged(&zone, &rrset, file_apex_ns, request.dialect)
                        && !seen.contains(&key_hash(&rrset.name, rrset.rtype))
                    {
                        report.removed += 1;
                    } else {
                        kept += 1;
                    }
                }
                if exhausted {
                    break;
                }
                tokio::task::yield_now().await;
            }
            remaining = Some(kept);
        }
        check_zone_bound(
            view.as_ref(),
            &zone,
            &request.scope,
            &report,
            remaining,
            MAX_ZONE_RRSETS,
        )
        .await?;
        Ok(Previewed {
            report,
            writes,
            approved,
        })
    }

    /// Checks the file with a preview, stages it and submits the import job; returns the
    /// job and the preview.
    ///
    /// A Windows file's candidates become claimable only with the request's approval
    /// ([`ClaimRequest::approval`]), and only when it is the digest of the set this
    /// preview gives (the file, the zone, the scope and the store as they are now); the
    /// chunks then make claimable exactly that set, less any name at which the store held a
    /// record of another origin than `ad` when the job started.
    ///
    /// # Errors
    ///
    /// The preview's errors, `dns.import.claimable_invalid` (400),
    /// `dns.import.claimable_changed` (409), `dns.import.claimable_too_many` (422), or the
    /// job engine's.
    pub async fn start_import(
        &self,
        cx: &RequestCtx,
        request: ImportRequest,
    ) -> ZoneResult<(JobId, ImportReport)> {
        check_claim(&request)?;
        self.check_staging(request.zone).await?;
        let approval = request.claim.approval;
        let mut previewed = self.preview(cx, &request, approval.is_some()).await?;
        let approved = match approval {
            None => None,
            Some(approval) => Some(Arc::new(approved_set(&mut previewed, approval)?)),
        };
        let preview = previewed.report;
        let writes = previewed.writes;
        self.check_staging(request.zone).await?;
        let chunk = self.config.import_chunk.max(1) as u64;
        let chunks = u32::try_from(writes.div_ceil(chunk).max(1)).unwrap_or(u32::MAX);
        let id = Uuid::now_v7();
        let held = if approved.is_some() {
            (preview.held_back, preview.held_back_names.clone())
        } else {
            (0, Vec::new())
        };
        self.staging.put(
            id,
            ImportRun {
                request: request.clone(),
                chunk: self.config.import_chunk.max(1),
                journal: self.config.journal,
                max_generate: self.config.max_generate,
                state: None,
                approved,
                held,
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
            Ok(job) => {
                self.staging.set_job(id, job);
                Ok((job, preview))
            }
            Err(error) => {
                self.staging.take(id);
                Err(error.into())
            }
        }
    }
}

/// RRsets a zone may hold after an import, every scope together: as many as one zone
/// transfer may carry.
pub const MAX_ZONE_RRSETS: u64 = 10_000_000;

/// Imports staged (checked and waiting for or running their job) at once on a controller;
/// each holds its zone file in memory until its job ends.
pub const MAX_STAGED: usize = 2;

/// The groups the preview reads between two yields to the runtime.
const YIELD_EVERY: u64 = 256;

// ----- staging and steps ----------------------------------------------------------------

/// The zone files of running imports, by import, in memory on this controller.
#[derive(Default)]
pub struct ImportStaging {
    runs: Mutex<HashMap<Uuid, Staged>>,
}

/// One staged import: its run, its zone and, once submitted, its job.
struct Staged {
    run: Arc<tokio::sync::Mutex<ImportRun>>,
    zone: ZoneId,
    job: Option<JobId>,
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
        let zone = run.request.zone;
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                id,
                Staged {
                    run: Arc::new(tokio::sync::Mutex::new(run)),
                    zone,
                    job: None,
                },
            );
    }

    fn get(&self, id: Uuid) -> Option<Arc<tokio::sync::Mutex<ImportRun>>> {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .map(|staged| Arc::clone(&staged.run))
    }

    fn set_job(&self, id: Uuid, job: JobId) {
        if let Some(staged) = self
            .runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&id)
        {
            staged.job = Some(job);
        }
    }

    /// The staged imports with their jobs.
    fn jobs(&self) -> Vec<(Uuid, Option<JobId>)> {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(id, staged)| (*id, staged.job))
            .collect()
    }

    fn holds_zone(&self, zone: ZoneId) -> bool {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .any(|staged| staged.zone == zone)
    }

    fn take(&self, id: Uuid) {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }

    /// Lets go of every staged import (tests).
    #[cfg(test)]
    fn take_all(&self) {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
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
    /// The approved claimable set; none for an import without an approval (WP13.4).
    approved: Option<Arc<ClaimSet>>,
    /// The candidates the preview of an approved import held back: the count and the
    /// listed ones.
    held: (u64, Vec<HeldEntry>),
}

/// What the steps of an import carry from one to the next.
struct RunState {
    /// The candidates the chunks made claimable or held back (WP13.4).
    tally: Tally,
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

    #[allow(
        clippy::too_many_lines,
        reason = "one chunk: the run state, the claim mode, the merge and the batch"
    )]
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
                groups: GroupReader::of(&run.request, &zone.name, run.max_generate)
                    .map_err(coded)?,
                zone,
                start: view.revision(),
                report: ImportReport::default(),
                next_chunk: 0,
                journal: Some((Vec::new(), Vec::new())),
                file_keys: HashSet::new(),
                tally: Tally::default(),
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
            let claim = match (run.request.dialect, &run.approved) {
                (Dialect::Rfc1035, _) => ClaimMode::Off,
                (Dialect::Windows, None) => ClaimMode::Hold(HeldReason::NotApproved),
                (Dialect::Windows, Some(approved)) => ClaimMode::Allowed(approved),
            };
            let merge = Merge {
                zone: &state.zone,
                scope: &run.request.scope,
                replace: run.request.replace,
                start: state.start,
                file_apex_ns: true,
                stamp: &stamp,
                dialect: run.request.dialect,
                claim,
            };
            while count < run.chunk {
                let Some(group) = state.groups.next_group(&mut state.report).map_err(coded)? else {
                    break;
                };
                let group = merge_group(
                    view.as_ref(),
                    &merge,
                    group,
                    &mut state.report,
                    &mut state.tally,
                )
                .map_err(coded)?;
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
                    && purged(&state.zone, &rrset, file_apex_ns, run.request.dialect)
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
    let mut draft = AuditDraft::success(audit::RECORD_IMPORT, vec![ObjectRef::from(zone.id)])
        .with_source_ip(cx.request.source_ip)
        .with_context("zone", zone.name.as_str())
        .with_context("scope", scope.as_str())
        .with_context("added", report.added.to_string())
        .with_context("replaced", report.replaced.to_string())
        .with_context("removed", report.removed.to_string())
        .with_context("lost", report.lost.to_string())
        .with_context("serial", to.to_string());
    if run.request.dialect == Dialect::Windows {
        draft = claim_report(
            report,
            &mut state.tally,
            run.approved.as_deref(),
            &mut run.held,
            &run.request,
            draft,
        );
    }
    batch.audit(draft);
    drop(view);
    // Proposed directly, not staged with the step record, so the report names its revision.
    let committed = cx.store.propose(batch).await?;
    report.revision = Some(committed.revision);
    Ok(report.clone())
}

/// Fills the claimable part of a finished Windows import's report, and gives its audit
/// record the count, the digest and the rule of what it made claimable and the first
/// [`claim::MAX_AUDITED_NAMES`] names with their types.
fn claim_report(
    report: &mut ImportReport,
    tally: &mut Tally,
    approved: Option<&ClaimSet>,
    held: &mut (u64, Vec<HeldEntry>),
    import: &ImportRequest,
    mut draft: AuditDraft,
) -> AuditDraft {
    let request = &import.claim;
    let selected: BTreeSet<(DnsName, Rtype)> =
        std::mem::take(&mut tally.selected).into_iter().collect();
    report.claimable = selected.len() as u64;
    report.claimable_digest = request.approval.map(|digest| digest.to_string());
    if let Some(approved) = approved {
        report.claimable_names = selected
            .iter()
            .filter_map(|key| approved.get(key).cloned())
            .take(claim::DEFAULT_PAGE)
            .collect();
    }
    let mut listed = std::mem::take(&mut held.1);
    let mut added = std::mem::take(&mut tally.held);
    let extra = claim::list_held(&mut added);
    listed.append(&mut added);
    let count = held.0 + extra;
    claim::list_held(&mut listed);
    report.held_back = count;
    report.held_back_names = listed;
    draft = draft
        .with_context("claimable", report.claimable.to_string())
        .with_context("held_back", report.held_back.to_string());
    if let Some(digest) = &report.claimable_digest {
        let names: Vec<String> = selected
            .iter()
            .take(claim::MAX_AUDITED_NAMES)
            .map(|(name, rtype)| format!("{name}/{rtype}"))
            .collect();
        draft = draft
            .with_context("claimable_digest", digest.clone())
            .with_context("claimable_rule", request.rule.describe())
            .with_context("file_sha256", claim::file_digest(&import.text))
            .with_context("claimable_names", names.join(" "));
        if selected.len() > claim::MAX_AUDITED_NAMES {
            draft = draft.with_context(
                "claimable_unlisted",
                (selected.len() - claim::MAX_AUDITED_NAMES).to_string(),
            );
        }
    }
    draft
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

#[cfg(test)]
mod tests;
