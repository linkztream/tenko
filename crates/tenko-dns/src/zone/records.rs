//! Batch changes of RRsets (DNS-01, API-04, API-09): a list of changes applied together or
//! not at all, with a dry run that returns the diff without writing.
//!
//! The changes run in order over the RRsets of the owner names they touch. Then every
//! changed RRset is checked with the rules of its type ([`RrSet::check`]), every touched
//! owner with the rules between its RRsets ([`check_node`]) and the apex with what it must
//! hold ([`check_apex`]). The SOA is not changed by a batch: it follows the zone settings
//! and its serial moves by the zone's policy, once per scope the batch touches, in the
//! same write, with one journal entry per scope.
//!
//! Origins (plan section 2.5): each change names the origin of its writer, and the RRsets
//! it writes carry it. The API, the UI and zone files write `manual`; the DNS actuator of
//! IPAM writes `ipam`. A change that would replace, shrink or delete an RRset of another
//! origin than its own is refused with `dns.record.origin` unless the change says
//! `take_over`; the RRset then takes the change's origin, and the audit record names it.
//! A `dhcp` change adds nothing at an owner name that holds data of another origin, of
//! any type, unless a `dhcp` DHCID already stands there or the data is `ipam` and the zone
//! lets dynamic writers replace it ([`check_dhcp_writer`], RFC 4703 section 5, ADR 0020
//! point 2); the writer's own removals are never held up. A batch with an `ipam` change is
//! audited as `dns.record.actuate`, any other as `dns.record.change`.

use std::collections::{BTreeMap, BTreeSet};

use tenko_core::{
    ObjectRef, Principal, RequestCtx, Revision, SystemComponent,
    audit::AuditDraft,
    dns::{
        DnsError, DnsName, JournalEntry, JournalRecord, MAX_TTL, Origin, Rdata, RecordData, RrSet,
        RrSetKey, Rtype, ScopeName, Zone, ZoneId, audit, check_apex, check_node, codes,
        tables::RRSETS,
    },
    ipam::Stamp,
};
use tenko_store::{ReadView, ReadViewExt, StoreError, WriteBatch};

use super::{
    JournalLimits, Planned, PlannedWrite, Written, ZoneError, ZoneResult, ZoneService, holds_data,
    journal, journal_records, node, serial, soa_rrset, soa_serial, stage_delete, stage_put,
};

/// What a change does to an RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Replace the RRset with these records (create it when absent).
    Set,
    /// Add these records to the RRset.
    Add,
    /// Remove these records; an RRset left empty is deleted.
    Remove,
    /// Delete the RRset.
    Delete,
}

/// One change of a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// What to do.
    pub op: Op,
    /// The scope.
    pub scope: ScopeName,
    /// The owner name.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The TTL; when absent the RRset keeps its TTL, and a new one takes the zone's
    /// default TTL (the SOA TTL).
    pub ttl: Option<u32>,
    /// The records of `Set`, `Add` and `Remove`.
    pub records: Vec<RecordData>,
    /// The change may replace an RRset of another origin.
    pub take_over: bool,
    /// The origin of the writer: the RRsets it writes carry it (`manual` for the API).
    pub origin: Origin,
}

/// The diff of one RRset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// The RRset.
    pub key: RrSetKey,
    /// Before; none when it is new.
    pub before: Option<RrSet>,
    /// After; none when it is deleted.
    pub after: Option<RrSet>,
}

/// The serial step of one scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialStep {
    /// The scope.
    pub scope: ScopeName,
    /// The serial before.
    pub from: u32,
    /// The serial after.
    pub to: u32,
}

/// What a batch did or, in a dry run, would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchOutcome {
    /// Nothing was written.
    pub dry_run: bool,
    /// The changed RRsets, by scope, name and type.
    pub diff: Vec<Diff>,
    /// The serial steps, by scope.
    pub serials: Vec<SerialStep>,
    /// The write; none for a dry run or a batch that changes nothing.
    pub written: Option<Written>,
}

impl BatchOutcome {
    /// The serial to report: the default scope's when the batch touched it, else the
    /// first scope's.
    pub fn serial(&self) -> Option<u32> {
        self.serials
            .iter()
            .find(|step| step.scope == ScopeName::DEFAULT)
            .or_else(|| self.serials.first())
            .map(|step| step.to)
    }
}

/// The RRsets of one owner name while a batch runs.
struct Node {
    before: BTreeMap<Rtype, (RrSet, Revision)>,
    after: BTreeMap<Rtype, RrSet>,
}

/// The planned batch: the diff, the serial steps and the write.
pub(crate) struct BatchPlan {
    pub(crate) diff: Vec<Diff>,
    pub(crate) serials: Vec<SerialStep>,
    pub(crate) batch: Option<WriteBatch>,
}

fn invalid(name: &DnsName, rtype: Rtype, reason: &str) -> ZoneError {
    DnsError::record_invalid(name, rtype, reason).into()
}

/// The data of a change, checked: each record of the change's type and valid, without
/// duplicates.
fn change_rdata(change: &Change) -> ZoneResult<Vec<Rdata>> {
    let mut rdata = Vec::with_capacity(change.records.len());
    for record in &change.records {
        if record.rtype() != change.rtype {
            return Err(invalid(
                &change.name,
                change.rtype,
                &format!(
                    "a record of type {} in a change of type {}",
                    record.rtype(),
                    change.rtype
                ),
            ));
        }
        record
            .validate()
            .map_err(|error| invalid(&change.name, change.rtype, error.reason))?;
        let data = Rdata::from_data(record);
        if !rdata.contains(&data) {
            rdata.push(data);
        }
    }
    Ok(rdata)
}

/// The DHCID record type (RFC 4701): the record by which a DHCP writer holds a name.
const DHCID: Rtype = Rtype(49);

/// The RRsets of one owner name in a scope, as a writer plans against them.
///
/// # Errors
///
/// The store's error.
pub fn node_rrsets(
    view: &dyn ReadView,
    zone: ZoneId,
    scope: &ScopeName,
    name: &DnsName,
) -> Result<Vec<RrSet>, StoreError> {
    Ok(view
        .scan_typed(
            &RRSETS,
            super::rrset_range(zone, Some(scope), Some(name)),
            usize::MAX,
            false,
        )?
        .into_iter()
        .map(|(_, rrset, _)| rrset)
        .collect())
}

/// The rule of a `dhcp` change that adds data at `name` (RFC 4703 section 5, ADR 0020
/// point 2): the name is the DHCP writer's when a `dhcp` DHCID stands there; otherwise it
/// may hold nothing of another origin, of any type, except the signer's rows and `ipam`
/// data in a zone that lets dynamic writers replace it. The check runs over the RRsets as
/// they were before the batch, so the writer cannot bring its own DHCID along.
fn check_dhcp_writer<'a>(
    zone: &Zone,
    name: &DnsName,
    before: impl IntoIterator<Item = &'a RrSet>,
) -> ZoneResult<()> {
    let before: Vec<&RrSet> = before.into_iter().collect();
    if before
        .iter()
        .any(|rrset| rrset.rtype == DHCID && rrset.origin == Origin::Dhcp)
    {
        return Ok(());
    }
    for rrset in before {
        let gives_way = match rrset.origin {
            Origin::Dhcp | Origin::Dnssec => true,
            Origin::Ipam => zone.update.may_replace_ipam,
            Origin::Manual | Origin::Dynamic | Origin::Ad | Origin::Transfer => false,
        };
        if !gives_way {
            return Err(ZoneError::new(
                codes::RECORD_ORIGIN,
                409,
                format!(
                    "{name} holds {} of the origin {}; a DHCP writer adds nothing beside it",
                    rrset.rtype,
                    origin_name(rrset.origin)
                ),
            )
            .param("name", name.as_str())
            .param("type", rrset.rtype.to_string())
            .param("origin", origin_name(rrset.origin)));
        }
    }
    Ok(())
}

/// Plans `changes` against `view`: the diff, the serial steps and the batch that writes
/// them (none when nothing changes): [`check`], then [`stage`].
///
/// # Errors
///
/// `dns.zone.invalid` for a zone without data or an unknown scope, `dns.record.invalid`,
/// `dns.record.conflict`, `dns.record.origin`, or the store's error.
pub(crate) fn plan(
    view: &dyn ReadView,
    zone: &Zone,
    changes: &[Change],
    cx: &RequestCtx,
    limits: JournalLimits,
    max_changes: usize,
) -> ZoneResult<BatchPlan> {
    let checked = check(view, zone, changes, cx, max_changes)?;
    stage(view, zone, changes, cx, limits, checked)
}

/// What [`check`] found: the diff, the revisions of the RRsets it read, and the RRsets
/// taken over.
pub(crate) struct Checked {
    diff: Vec<Diff>,
    before: BTreeMap<RrSetKey, Revision>,
    taken_over: Vec<String>,
}

/// Runs `changes` over the RRsets of `view` and checks the result with every rule of a
/// batch, without the serial step, the journal or the batch: what a write would refuse.
///
/// # Errors
///
/// As [`plan`].
#[allow(
    clippy::too_many_lines,
    reason = "the steps of one batch read best in order"
)]
pub(crate) fn check(
    view: &dyn ReadView,
    zone: &Zone,
    changes: &[Change],
    cx: &RequestCtx,
    max_changes: usize,
) -> ZoneResult<Checked> {
    // WP6.1: a secondary zone's records come from its transfers only.
    super::secondary::check_writable(zone)?;
    if !holds_data(zone.kind) {
        return Err(ZoneError::zone_invalid(
            "kind",
            "only primary and RPZ zones hold records in Tenko",
        ));
    }
    if changes.len() > max_changes {
        return Err(ZoneError::new(
            codes::RECORD_INVALID,
            400,
            format!(
                "{} changes exceed the limit of {max_changes}",
                changes.len()
            ),
        )
        .param("count", changes.len().to_string())
        .param("limit", max_changes.to_string()));
    }
    let stamp = Stamp::new(cx.now, cx.principal.clone());
    let mut nodes: BTreeMap<(ScopeName, DnsName), Node> = BTreeMap::new();
    let mut taken_over: Vec<String> = Vec::new();
    // The owner names at which a DHCP writer adds data; its removals are not held up.
    let mut dhcp_adds: BTreeSet<(ScopeName, DnsName)> = BTreeSet::new();
    for change in changes {
        if !zone.has_scope(&change.scope) {
            return Err(
                ZoneError::zone_invalid("scope", "the zone has no such scope")
                    .param("scope", change.scope.as_str()),
            );
        }
        if !change.name.is_subdomain_of(&zone.name) {
            return Err(invalid(
                &change.name,
                change.rtype,
                "the owner name is outside the zone",
            ));
        }
        if change.rtype == Rtype::SOA {
            return Err(invalid(
                &change.name,
                change.rtype,
                "the SOA follows the zone settings and is not changed by a batch",
            ));
        }
        if change.rtype.is_meta() {
            return Err(invalid(
                &change.name,
                change.rtype,
                "a meta type is not zone data",
            ));
        }
        if change.ttl.is_some_and(|ttl| ttl > MAX_TTL) {
            return Err(invalid(
                &change.name,
                change.rtype,
                "the TTL is above 2147483647 seconds",
            ));
        }
        let rdata = change_rdata(change)?;
        if matches!(change.op, Op::Set | Op::Add | Op::Remove) && rdata.is_empty() {
            return Err(invalid(
                &change.name,
                change.rtype,
                "the change lists no records",
            ));
        }
        let key = (change.scope.clone(), change.name.clone());
        if change.origin == Origin::Dhcp && matches!(change.op, Op::Set | Op::Add) {
            dhcp_adds.insert(key.clone());
        }
        if !nodes.contains_key(&key) {
            let before: BTreeMap<Rtype, (RrSet, Revision)> =
                node(view, zone.id, &change.scope, &change.name)?
                    .into_iter()
                    .map(|(rrset, revision)| (rrset.rtype, (rrset, revision)))
                    .collect();
            let after = before
                .iter()
                .map(|(rtype, (rrset, _))| (*rtype, rrset.clone()))
                .collect();
            nodes.insert(key.clone(), Node { before, after });
        }
        let Some(entry) = nodes.get_mut(&key) else {
            continue;
        };
        let existing = entry.after.get(&change.rtype).cloned();
        // WP6.1: what a transfer wrote (the members of a catalog zone) is read-only.
        if let Some(existing) = &existing
            && existing.origin == Origin::Transfer
            && change.origin != Origin::Transfer
        {
            return Err(super::secondary::read_only(zone));
        }
        // WP6.3: the rows of the signer, and the types it owns in a zone signed online,
        // are refused for every writer, `take_over` or not.
        if let Some(reason) = crate::dnssec::refused_change(
            zone,
            change.rtype,
            existing.as_ref().map(|rrset| rrset.origin),
        ) {
            return Err(ZoneError::new(
                codes::RECORD_ORIGIN,
                409,
                format!("{} {}: {reason}", change.name, change.rtype),
            )
            .param("name", change.name.as_str())
            .param("type", change.rtype.to_string())
            .param("origin", "dnssec"));
        }
        if let Some(existing) = &existing
            && existing.origin != change.origin
        {
            if !change.take_over {
                return Err(ZoneError::new(
                    codes::RECORD_ORIGIN,
                    409,
                    format!(
                        "{} {} belongs to the origin {}; the change needs take_over",
                        change.name,
                        change.rtype,
                        origin_name(existing.origin)
                    ),
                )
                .param("name", change.name.as_str())
                .param("type", change.rtype.to_string())
                .param("origin", origin_name(existing.origin)));
            }
            taken_over.push(format!(
                "{} {} {}",
                change.name,
                change.rtype,
                origin_name(existing.origin)
            ));
        }
        let ttl = change
            .ttl
            .or_else(|| existing.as_ref().map(|rrset| rrset.ttl))
            .unwrap_or(zone.soa.ttl);
        let fresh = |rdata: Vec<Rdata>| RrSet {
            zone: zone.id,
            scope: change.scope.clone(),
            name: change.name.clone(),
            rtype: change.rtype,
            ttl,
            rdata,
            origin: change.origin,
            key: None,
            principal: None,
            updated: stamp.clone(),
        };
        let next = match change.op {
            Op::Set => Some(fresh(rdata)),
            Op::Add => {
                let mut records = existing.map(|rrset| rrset.rdata).unwrap_or_default();
                for data in rdata {
                    if !records.contains(&data) {
                        records.push(data);
                    }
                }
                Some(fresh(records))
            }
            Op::Remove => {
                let mut records = existing.map(|rrset| rrset.rdata).unwrap_or_default();
                records.retain(|data| !rdata.contains(data));
                (!records.is_empty()).then(|| fresh(records))
            }
            Op::Delete => None,
        };
        match next {
            Some(rrset) => {
                entry.after.insert(change.rtype, rrset);
            }
            None => {
                entry.after.remove(&change.rtype);
            }
        }
    }

    let mut diff = Vec::new();
    for ((scope, name), entry) in &mut nodes {
        for (rtype, after) in &mut entry.after {
            if let Some((before, _)) = entry.before.get(rtype)
                && same_data(before, after)
            {
                // Unchanged: keep the stored row as it is.
                after.clone_from(before);
            }
        }
        let mut types: Vec<Rtype> = entry
            .before
            .keys()
            .chain(entry.after.keys())
            .copied()
            .collect();
        types.sort_unstable();
        types.dedup();
        for rtype in types {
            let before = entry.before.get(&rtype).map(|(rrset, _)| rrset);
            let after = entry.after.get(&rtype);
            if before == after {
                continue;
            }
            if let Some(after) = after {
                after.check(&zone.name)?;
            }
            diff.push(Diff {
                key: RrSetKey {
                    zone: zone.id,
                    scope: scope.clone(),
                    name: name.clone(),
                    rtype,
                },
                before: before.cloned(),
                after: after.cloned(),
            });
        }
        check_node(&zone.name, entry.after.values())?;
        if name == &zone.name {
            check_apex(&zone.name, entry.after.values())?;
        }
        if dhcp_adds.contains(&(scope.clone(), name.clone())) {
            check_dhcp_writer(zone, name, entry.before.values().map(|(rrset, _)| rrset))?;
        }
    }
    let before = nodes
        .into_iter()
        .flat_map(|((scope, name), node)| {
            node.before.into_iter().map(move |(rtype, (_, revision))| {
                let key = RrSetKey {
                    zone: zone.id,
                    scope: scope.clone(),
                    name: name.clone(),
                    rtype,
                };
                (key, revision)
            })
        })
        .collect();
    Ok(Checked {
        diff,
        before,
        taken_over,
    })
}

/// Stages what [`check`] found: the RRsets, the serial step and the journal entry of each
/// scope, and the audit record (none when nothing changes).
fn stage(
    view: &dyn ReadView,
    zone: &Zone,
    changes: &[Change],
    cx: &RequestCtx,
    limits: JournalLimits,
    checked: Checked,
) -> ZoneResult<BatchPlan> {
    let Checked {
        diff,
        before,
        taken_over,
    } = checked;
    if diff.is_empty() {
        return Ok(BatchPlan {
            diff,
            serials: Vec::new(),
            batch: None,
        });
    }
    let stamp = Stamp::new(cx.now, cx.principal.clone());
    let mut batch = WriteBatch::for_request(cx);
    for item in &diff {
        let revision = before.get(&item.key).copied();
        batch.expect_typed(&RRSETS, &item.key, revision);
        match (&item.before, &item.after) {
            (before, Some(after)) => stage_put(&mut batch, before.as_ref(), after)?,
            (Some(before), None) => stage_delete(&mut batch, before),
            (None, None) => {}
        }
    }
    let mut serials = Vec::new();
    let mut scopes: Vec<&ScopeName> = diff.iter().map(|item| &item.key.scope).collect();
    scopes.dedup();
    for scope in scopes {
        let (removed, added) = journal_diff(diff.iter().filter(|item| &item.key.scope == scope));
        let step = stage_serial_step(
            &mut batch, view, zone, scope, &stamp, limits, removed, added,
        )?;
        serials.push(step);
    }
    let action = if changes.iter().any(|change| change.origin == Origin::Ipam) {
        audit::RECORD_ACTUATE
    } else {
        audit::RECORD_CHANGE
    };
    let mut draft = AuditDraft::success(action, vec![ObjectRef::from(zone.id)])
        .with_source_ip(cx.source_ip)
        .with_context("zone", zone.name.as_str())
        .with_context("rrsets", diff.len().to_string());
    if let Some(step) = serials.first() {
        draft = draft.with_context("serial", step.to.to_string());
    }
    if !taken_over.is_empty() {
        draft = draft.with_context("take_over", taken_over.join(", "));
    }
    batch.audit(draft);
    Ok(BatchPlan {
        diff,
        serials,
        batch: Some(batch),
    })
}

/// Plans `changes` against `view` as a batch would, the serial step, the stored rows and the
/// journal entry included, and returns the diff without writing: the validation alone, for
/// tools and the fuzz target.
///
/// # Errors
///
/// The errors of a batch.
pub fn validate(
    view: &dyn ReadView,
    zone: &Zone,
    changes: &[Change],
    cx: &RequestCtx,
) -> ZoneResult<Vec<Diff>> {
    plan(
        view,
        zone,
        changes,
        cx,
        JournalLimits::default(),
        usize::MAX,
    )
    .map(|planned| planned.diff)
}

/// Whether two RRsets hold the same TTL, records, origin and key.
fn same_data(a: &RrSet, b: &RrSet) -> bool {
    a.ttl == b.ttl
        && a.origin == b.origin
        && a.key == b.key
        && a.rdata.len() == b.rdata.len()
        && a.rdata.iter().all(|data| b.rdata.contains(data))
}

/// The records a set of RRset diffs removes and adds: a TTL change removes the old
/// records and adds the new ones.
pub(crate) fn journal_diff<'a>(
    items: impl Iterator<Item = &'a Diff>,
) -> (Vec<JournalRecord>, Vec<JournalRecord>) {
    let mut removed = Vec::new();
    let mut added = Vec::new();
    for item in items {
        match (&item.before, &item.after) {
            (Some(before), Some(after)) if before.ttl == after.ttl => {
                removed.extend(
                    journal_records(before).filter(|record| !after.rdata.contains(&record.rdata)),
                );
                added.extend(
                    journal_records(after).filter(|record| !before.rdata.contains(&record.rdata)),
                );
            }
            (before, after) => {
                if let Some(before) = before {
                    removed.extend(journal_records(before));
                }
                if let Some(after) = after {
                    added.extend(journal_records(after));
                }
            }
        }
    }
    (removed, added)
}

/// Moves the serial of a scope in `batch` and appends its journal entry; returns the step.
#[allow(clippy::too_many_arguments, reason = "the parts of one serial step")]
pub(crate) fn stage_serial_step(
    batch: &mut WriteBatch,
    view: &dyn ReadView,
    zone: &Zone,
    scope: &ScopeName,
    stamp: &Stamp,
    limits: JournalLimits,
    removed: Vec<JournalRecord>,
    added: Vec<JournalRecord>,
) -> ZoneResult<SerialStep> {
    let key = RrSetKey {
        zone: zone.id,
        scope: scope.clone(),
        name: zone.name.clone(),
        rtype: Rtype::SOA,
    };
    let (old, revision) = view
        .get_typed(&RRSETS, &key)?
        .ok_or_else(|| invalid(&zone.name, Rtype::SOA, "the zone scope has no SOA record"))?;
    let from = soa_serial(&old).unwrap_or_default();
    let to = serial::next(zone.serial, from, stamp.at);
    let new = soa_rrset(zone, scope, &zone.soa, to, stamp.clone());
    batch.expect_typed(&RRSETS, &key, Some(revision));
    stage_put(batch, Some(&old), &new)?;
    let mut journal_removed: Vec<JournalRecord> = journal_records(&old).collect();
    journal_removed.extend(removed);
    let mut journal_added: Vec<JournalRecord> = journal_records(&new).collect();
    journal_added.extend(added);
    journal::stage_append(
        batch,
        view,
        limits,
        &JournalEntry {
            zone: zone.id,
            scope: scope.clone(),
            from_serial: from,
            to_serial: to,
            revision: view.revision(),
            at: stamp.at,
            removed: journal_removed,
            added: journal_added,
        },
    )?;
    Ok(SerialStep {
        scope: scope.clone(),
        from,
        to,
    })
}

/// Whether one part of DHCP's names may be written into `zone`: every change of the
/// origin `dhcp`, data added only where the zone takes DHCP updates, and the rules of a
/// batch ([`check`]).
fn dhcp_part(
    view: &dyn ReadView,
    zone: &Zone,
    part: &[Change],
    cx: &RequestCtx,
    allows_by_default: bool,
) -> ZoneResult<()> {
    if let Some(change) = part.iter().find(|change| change.origin != Origin::Dhcp) {
        return Err(ZoneError::new(
            codes::RECORD_ORIGIN,
            409,
            format!(
                "{} {} is not a change of the origin dhcp",
                change.name, change.rtype
            ),
        )
        .param("origin", origin_name(change.origin)));
    }
    let adds = part
        .iter()
        .any(|change| matches!(change.op, Op::Set | Op::Add));
    if adds && !zone.update.dhcp_allowed(allows_by_default) {
        return Err(ZoneError::new(
            codes::UPDATE_REFUSED,
            403,
            format!("the zone {} does not allow DHCP updates", zone.name),
        )
        .param("zone", zone.name.as_str()));
    }
    check(view, zone, part, cx, usize::MAX).map(drop)
}

/// The DHCP writer's hook on each attempt of its set ([`ZoneService::change_dhcp_names`]):
/// the attempt's view, the positions of the parts the zone refused, and the batch.
pub type DhcpRecord<'a> =
    &'a mut (dyn FnMut(&dyn ReadView, &[usize], &mut WriteBatch) -> ZoneResult<()> + Send);

/// The stable name of an origin.
pub fn origin_name(origin: Origin) -> &'static str {
    match origin {
        Origin::Manual => "manual",
        Origin::Ipam => "ipam",
        Origin::Dynamic => "dynamic",
        Origin::Dhcp => "dhcp",
        Origin::Ad => "ad",
        Origin::Transfer => "transfer",
        // WP6.3: the signer's rows.
        Origin::Dnssec => "dnssec",
    }
}

impl ZoneService {
    /// Applies a batch of changes to the RRsets of a zone, or with `dry_run` returns the
    /// diff without writing.
    ///
    /// # Errors
    ///
    /// `dns.zone.not_found`, `dns.zone.invalid`, `dns.record.invalid`,
    /// `dns.record.conflict`, `dns.record.origin`, or a store or job error.
    pub async fn change_records(
        &self,
        cx: &RequestCtx,
        zone: ZoneId,
        changes: &[Change],
        dry_run: bool,
    ) -> ZoneResult<BatchOutcome> {
        let limits = self.config.journal;
        let max_changes = self.config.max_changes;
        if dry_run {
            let view = self.view(None).await?;
            let row = Self::zone(view.as_ref(), zone)?;
            let planned = plan(view.as_ref(), &row.zone, changes, cx, limits, max_changes)?;
            return Ok(BatchOutcome {
                dry_run: true,
                diff: planned.diff,
                serials: planned.serials,
                written: None,
            });
        }
        Ok(self
            .write_records(cx, zone, &[changes], true, None, None)
            .await?
            .0)
    }

    /// Applies DHCP's name updates to a zone as [`ZoneService::change_records`] does, as one
    /// change set of `parts` (one list of changes per part of a lease). Each part is checked
    /// on the view the set is planned against, and a part the zone refuses is left out and
    /// returned with its reason: a change of another origin than `dhcp`, an addition to a
    /// zone that takes no DHCP updates (`allows_by_default` is the profile's default of the
    /// zone's switch), or a part the rules of a batch refuse; the writer's removals go
    /// wherever its names stand. With `fence`, the set commits only while the leader epoch
    /// is still that value ([`tenko_store::fence`]), so a writer that lost its office writes
    /// nothing. `record` is called on every attempt that writes, with that attempt's view,
    /// the positions of the parts refused and the batch, so the rows it stages commit with
    /// the set or not at all; its error fails the set. Made by the DHCP component itself, the change set runs
    /// without a job: a client can change its lease without limit, and so would the job
    /// rows. It keeps its audit record `dns.record.change` and its journal entry. Any
    /// other principal's change set is a job.
    ///
    /// # Errors
    ///
    /// As [`ZoneService::change_records`], for the set or a store error; a failed fence is
    /// `sys.store.precondition_failed` with status 412 at once, never planned again.
    pub async fn change_dhcp_names(
        &self,
        cx: &RequestCtx,
        zone: ZoneId,
        parts: &[Vec<Change>],
        allows_by_default: bool,
        fence: Option<u64>,
        record: DhcpRecord<'_>,
    ) -> ZoneResult<(BatchOutcome, Vec<(usize, ZoneError)>)> {
        let job = cx.principal != Principal::system(SystemComponent::Dhcp);
        let parts: Vec<&[Change]> = parts.iter().map(Vec::as_slice).collect();
        self.write_records(
            cx,
            zone,
            &parts,
            job,
            Some((allows_by_default, fence)),
            Some(record),
        )
        .await
    }

    async fn write_records(
        &self,
        cx: &RequestCtx,
        zone: ZoneId,
        parts: &[&[Change]],
        job: bool,
        dhcp: Option<(bool, Option<u64>)>,
        mut record: Option<DhcpRecord<'_>>,
    ) -> ZoneResult<(BatchOutcome, Vec<(usize, ZoneError)>)> {
        let limits = self.config.journal;
        let max_changes = self.config.max_changes;
        let ((diff, serials, refused), written) = self
            .execute(cx, |view| {
                let row = Self::zone(view, zone)?;
                let mut refused = Vec::new();
                let mut changes = Vec::new();
                for (index, part) in parts.iter().enumerate() {
                    if let Some((allows, _)) = dhcp
                        && let Err(error) = dhcp_part(view, &row.zone, part, cx, allows)
                    {
                        // A store error is the write's, not the part's.
                        if !error.coded().code.starts_with("dns.") {
                            return Err(error);
                        }
                        refused.push((index, error));
                        continue;
                    }
                    changes.extend_from_slice(part);
                }
                let mut planned = plan(view, &row.zone, &changes, cx, limits, max_changes)?;
                if let Some((_, Some(epoch))) = dhcp
                    && let Some(batch) = planned.batch.as_mut()
                {
                    batch.preconditions.push(tenko_store::fence(epoch));
                }
                if let (Some(record), Some(batch)) = (record.as_deref_mut(), planned.batch.as_mut())
                {
                    let positions: Vec<usize> = refused.iter().map(|(at, _)| *at).collect();
                    record(view, &positions, batch)?;
                }
                let result = (planned.diff, planned.serials, refused);
                Ok(match planned.batch {
                    Some(batch) => Planned {
                        result,
                        write: Some(PlannedWrite {
                            batch,
                            summary: format!(
                                "change {} RRsets of zone {}",
                                changes.len(),
                                row.zone.name
                            ),
                            targets: vec![ObjectRef::from(zone)],
                            job,
                        }),
                    },
                    None => Planned::nothing(result),
                })
            })
            .await?;
        let outcome = BatchOutcome {
            dry_run: false,
            diff,
            serials,
            written,
        };
        Ok((outcome, refused))
    }
}
