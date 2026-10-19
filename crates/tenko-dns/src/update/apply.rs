//! The change set of an update (RFC 2136 section 3.4, plan sections 2.4 and 2.5).
//!
//! The updates of one zone that wait together are planned in order against one view of
//! the store and committed as one write: each update sees the changes of those before it,
//! each is all or nothing (an update that fails leaves the plan as it was before it), and
//! the write holds every change, one serial step per scope, one journal entry per scope and
//! one `dns.update.apply` audit record per update that changed something. A write the
//! store refuses fails them all (SERVFAIL); nothing is written then.
//!
//! The update section, in order (3.4.2):
//!
//! - **Add** (the zone's class): the record joins its RRset with the update's TTL; a CNAME
//!   or DNAME replaces the one record of its set; a CNAME is ignored at a name that holds
//!   other data and other data at a name that holds a CNAME (3.4.2.2); an SOA is ignored,
//!   since Tenko writes the SOA from the zone settings and moves the serial itself.
//! - **Delete an RRset** (class ANY): the SOA and the NS set at the apex are kept (3.4.2.3).
//! - **Delete a name** (class ANY, type ANY): every RRset of the name; at the apex the SOA
//!   and the NS set stay; the signer's rows follow the change by themselves.
//! - **Delete a record** (class NONE): the last NS record at the apex and the SOA are kept
//!   (3.4.2.4); an RRset left empty is deleted.
//!
//! Every RRset an update changes carries the origin `dynamic` and the name of the update's
//! TSIG key. Origins (2.5): an RRset of origin `ipam` is changed only when the zone's
//! `may_replace_ipam` allows it, an RRset of origin `transfer` or `dnssec` never, and in a
//! zone signed online the types the signer writes are refused; such an update is REFUSED
//! with `dns.update.refused`, its extended error naming the first RRset. A model rule the
//! result breaks (a record set too large, a CNAME beside other data written another way)
//! fails the update: SERVFAIL with the rule in the extended error, nothing of it written.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use tenko_core::{
    ObjectRef, RequestCtx, Revision,
    audit::AuditDraft,
    dns::{
        DnsName, KeyName, Origin, Rdata, RrSet, RrSetKey, Rtype, ScopeName, Zone, ZoneId, audit,
        check_apex, check_node, tables::RRSETS,
    },
    ipam::Stamp,
};
use tenko_store::{ReadView, WriteBatch};

use super::{
    message::{Prerequisite, Update, UpdateMessage},
    policy::Refusal,
    prereq::{self, Records, Unmet},
};
use crate::zone::{
    JournalLimits, Planned, ZoneError, ZoneResult, ZoneService, node,
    records::{self, Diff, origin_name},
    stage_delete, stage_put,
};

/// One update of a group.
#[derive(Debug, Clone)]
pub struct Item<'a> {
    /// The parsed message.
    pub message: &'a UpdateMessage,
    /// The scope the client's view chose.
    pub scope: ScopeName,
    /// The TSIG key that signed it.
    pub key: Option<KeyName>,
    /// The client.
    pub client: IpAddr,
}

/// What became of one update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Applied (NOERROR once the index holds the write); the counts of records added and
    /// removed and of RRsets changed. All zero for an update that changed nothing.
    Applied {
        /// Records added.
        added: usize,
        /// Records removed.
        removed: usize,
        /// RRsets changed.
        rrsets: usize,
    },
    /// A prerequisite does not hold.
    Unmet(Unmet),
    /// Refused by the policy or the origin rules (REFUSED).
    Refused(String),
    /// A rule of the model broke mid-way (SERVFAIL); nothing of it is written.
    Failed(String),
    /// The zone is gone or is no primary zone of this node any more (NOTAUTH).
    NotAuth(String),
}

impl Outcome {
    /// Whether the update changed something.
    pub fn changed(&self) -> bool {
        matches!(self, Outcome::Applied { rrsets, .. } if *rrsets > 0)
    }
}

type NodeKey = (ScopeName, DnsName);

/// The RRsets of one owner name in one scope while the group is planned.
#[derive(Debug, Clone, Default)]
struct NodeState {
    before: BTreeMap<Rtype, (RrSet, Revision)>,
    after: BTreeMap<Rtype, RrSet>,
}

/// The planner of one group.
struct Planner<'v> {
    view: &'v dyn ReadView,
    zone: Zone,
    stamp: Stamp,
    nodes: BTreeMap<NodeKey, NodeState>,
    /// The RRsets the prerequisites read, with the revision the write expects.
    reads: BTreeMap<RrSetKey, Option<Revision>>,
}

/// The nodes of one scope, as the prerequisites see them.
struct ScopeNodes<'p> {
    nodes: &'p BTreeMap<NodeKey, NodeState>,
    scope: &'p ScopeName,
}

impl Records for ScopeNodes<'_> {
    fn rrset(&self, name: &DnsName, rtype: Rtype) -> Option<&[Rdata]> {
        self.nodes
            .get(&(self.scope.clone(), name.clone()))
            .and_then(|node| node.after.get(&rtype))
            .map(|rrset| rrset.rdata.as_slice())
    }

    fn name_in_use(&self, name: &DnsName) -> bool {
        self.nodes
            .get(&(self.scope.clone(), name.clone()))
            .is_some_and(|node| !node.after.is_empty())
    }
}

/// Why one update operation stops the update.
enum Stop {
    Refused(String),
    Store(ZoneError),
}

impl From<ZoneError> for Stop {
    fn from(error: ZoneError) -> Self {
        Stop::Store(error)
    }
}

fn is_dnssec_type(rtype: Rtype) -> bool {
    matches!(rtype, Rtype::RRSIG | Rtype::NSEC)
}

impl Planner<'_> {
    fn load(&mut self, scope: &ScopeName, name: &DnsName) -> ZoneResult<()> {
        let key = (scope.clone(), name.clone());
        if self.nodes.contains_key(&key) {
            return Ok(());
        }
        let before: BTreeMap<Rtype, (RrSet, Revision)> =
            node(self.view, self.zone.id, scope, name)?
                .into_iter()
                .map(|(rrset, revision)| (rrset.rtype, (rrset, revision)))
                .collect();
        let after = before
            .iter()
            .map(|(rtype, (rrset, _))| (*rtype, rrset.clone()))
            .collect();
        self.nodes.insert(key, NodeState { before, after });
        Ok(())
    }

    fn rrset_key(&self, scope: &ScopeName, name: &DnsName, rtype: Rtype) -> RrSetKey {
        RrSetKey {
            zone: self.zone.id,
            scope: scope.clone(),
            name: name.clone(),
            rtype,
        }
    }

    /// Notes what a prerequisite read, so that the write expects it unchanged.
    fn note_read(&mut self, scope: &ScopeName, prerequisite: &Prerequisite) {
        let name = prerequisite.name();
        let Some(node) = self.nodes.get(&(scope.clone(), name.clone())) else {
            return;
        };
        let mut reads = Vec::new();
        match prerequisite {
            Prerequisite::Exists { rtype, .. }
            | Prerequisite::Equals { rtype, .. }
            | Prerequisite::NotExists { rtype, .. } => {
                reads.push((
                    *rtype,
                    node.before.get(rtype).map(|(_, revision)| *revision),
                ));
            }
            Prerequisite::NameInUse { .. } | Prerequisite::NameNotInUse { .. } => {
                reads.extend(
                    node.before
                        .iter()
                        .map(|(rtype, (_, revision))| (*rtype, Some(*revision))),
                );
            }
        }
        for (rtype, revision) in reads {
            let key = self.rrset_key(scope, name, rtype);
            self.reads.entry(key).or_insert(revision);
        }
    }

    /// Whether the update may change `existing` (or create an RRset of `rtype` when none).
    fn may_change(
        &self,
        name: &DnsName,
        rtype: Rtype,
        existing: Option<&RrSet>,
    ) -> Result<(), Stop> {
        if let Some(reason) =
            crate::dnssec::refused_change(&self.zone, rtype, existing.map(|rrset| rrset.origin))
        {
            return Err(Stop::Refused(format!("{name} {rtype}: {reason}")));
        }
        let Some(existing) = existing else {
            return Ok(());
        };
        if existing.origin == Origin::Dynamic
            || Origin::Dynamic.may_replace(existing.origin, &self.zone.update)
        {
            return Ok(());
        }
        Err(Stop::Refused(match existing.origin {
            Origin::Ipam => format!(
                "{name} {rtype} belongs to IPAM; the zone's update policy does not let updates replace it"
            ),
            Origin::Transfer => {
                format!("{name} {rtype} comes from a zone transfer and is read-only")
            }
            other => format!(
                "{name} {rtype} belongs to the origin {} and updates do not replace it",
                origin_name(other)
            ),
        }))
    }

    fn fresh(
        &self,
        scope: &ScopeName,
        name: &DnsName,
        rtype: Rtype,
        ttl: u32,
        rdata: Vec<Rdata>,
        key: Option<&KeyName>,
    ) -> RrSet {
        RrSet {
            zone: self.zone.id,
            scope: scope.clone(),
            name: name.clone(),
            rtype,
            ttl,
            rdata,
            origin: Origin::Dynamic,
            key: key.cloned(),
            updated: self.stamp.clone(),
        }
    }

    /// Applies one operation to the nodes; `undo` collects the nodes it changes with
    /// their state before the update, for the rollback.
    fn apply_op(
        &mut self,
        item: &Item<'_>,
        op: &Update,
        undo: &mut BTreeMap<NodeKey, BTreeMap<Rtype, RrSet>>,
    ) -> Result<(), Stop> {
        let name = op.name();
        self.load(&item.scope, name)?;
        let key = (item.scope.clone(), name.clone());
        let Some(after) = self.nodes.get(&key).map(|node| node.after.clone()) else {
            return Ok(());
        };
        let mut next = after.clone();
        self.edit(item, op, &mut next)?;
        if next != after {
            undo.entry(key.clone()).or_insert(after);
            if let Some(node) = self.nodes.get_mut(&key) {
                node.after = next;
            }
        }
        Ok(())
    }

    /// One operation on the RRsets of its name.
    fn edit(
        &self,
        item: &Item<'_>,
        op: &Update,
        next: &mut BTreeMap<Rtype, RrSet>,
    ) -> Result<(), Stop> {
        let name = op.name();
        let apex = name == &self.zone.name;
        match op {
            Update::Add {
                rtype, ttl, rdata, ..
            } => self.add(item, name, *rtype, *ttl, rdata, next)?,
            Update::DeleteRrset { rtype, .. } => {
                if apex && matches!(*rtype, Rtype::SOA | Rtype::NS) {
                    return Ok(());
                }
                if let Some(existing) = next.get(rtype) {
                    self.may_change(name, *rtype, Some(existing))?;
                    next.remove(rtype);
                }
            }
            Update::DeleteName { .. } => {
                let types: Vec<Rtype> = next.keys().copied().collect();
                for rtype in types {
                    if apex && matches!(rtype, Rtype::SOA | Rtype::NS) {
                        continue;
                    }
                    let Some(existing) = next.get(&rtype) else {
                        continue;
                    };
                    if existing.origin == Origin::Dnssec {
                        continue;
                    }
                    self.may_change(name, rtype, Some(existing))?;
                    next.remove(&rtype);
                }
            }
            Update::DeleteRecord { rtype, rdata, .. } => {
                let Some(existing) = next.get(rtype) else {
                    return Ok(());
                };
                if *rtype == Rtype::SOA
                    || !existing.rdata.contains(rdata)
                    || (apex && *rtype == Rtype::NS && existing.rdata.len() == 1)
                {
                    return Ok(());
                }
                self.may_change(name, *rtype, Some(existing))?;
                let mut records = existing.rdata.clone();
                records.retain(|held| held != rdata);
                if records.is_empty() {
                    next.remove(rtype);
                } else {
                    let ttl = existing.ttl;
                    let rrset =
                        self.fresh(&item.scope, name, *rtype, ttl, records, item.key.as_ref());
                    next.insert(*rtype, rrset);
                }
            }
        }
        Ok(())
    }

    /// Adds a record (3.4.2.2): SOA ignored, the CNAME rules, CNAME and DNAME replaced.
    fn add(
        &self,
        item: &Item<'_>,
        name: &DnsName,
        rtype: Rtype,
        ttl: u32,
        rdata: &Rdata,
        next: &mut BTreeMap<Rtype, RrSet>,
    ) -> Result<(), Stop> {
        if rtype == Rtype::SOA {
            return Ok(());
        }
        let other_data = next
            .keys()
            .any(|held| *held != Rtype::CNAME && !is_dnssec_type(*held));
        if rtype == Rtype::CNAME && other_data {
            return Ok(());
        }
        if rtype != Rtype::CNAME && !is_dnssec_type(rtype) && next.contains_key(&Rtype::CNAME) {
            return Ok(());
        }
        let existing = next.get(&rtype);
        self.may_change(name, rtype, existing)?;
        let records = match existing {
            Some(existing) if !matches!(rtype, Rtype::CNAME | Rtype::DNAME) => {
                let mut records = existing.rdata.clone();
                if !records.contains(rdata) {
                    records.push(rdata.clone());
                }
                records
            }
            _ => vec![rdata.clone()],
        };
        let rrset = self.fresh(&item.scope, name, rtype, ttl, records, item.key.as_ref());
        next.insert(rtype, rrset);
        Ok(())
    }

    fn rollback(&mut self, undo: BTreeMap<NodeKey, BTreeMap<Rtype, RrSet>>) {
        for (key, after) in undo {
            if let Some(node) = self.nodes.get_mut(&key) {
                node.after = after;
            }
        }
    }

    /// Plans one update: its prerequisites, its operations, the model's rules.
    fn update(&mut self, item: &Item<'_>) -> ZoneResult<Outcome> {
        let message = item.message;
        for prerequisite in &message.prerequisites {
            self.load(&item.scope, prerequisite.name())?;
        }
        let checked = prereq::check(
            &message.prerequisites,
            &ScopeNodes {
                nodes: &self.nodes,
                scope: &item.scope,
            },
        );
        for prerequisite in &message.prerequisites {
            self.note_read(&item.scope, prerequisite);
        }
        if let Err(unmet) = checked {
            return Ok(Outcome::Unmet(unmet));
        }
        let mut undo = BTreeMap::new();
        for op in &message.updates {
            match self.apply_op(item, op, &mut undo) {
                Ok(()) => {}
                Err(Stop::Refused(reason)) => {
                    self.rollback(undo);
                    return Ok(Outcome::Refused(reason));
                }
                Err(Stop::Store(error)) => {
                    self.rollback(undo);
                    return Err(error);
                }
            }
        }
        match self.counts(&undo) {
            Ok((added, removed, rrsets)) => Ok(Outcome::Applied {
                added,
                removed,
                rrsets,
            }),
            Err(reason) => {
                self.rollback(undo);
                Ok(Outcome::Failed(reason))
            }
        }
    }

    /// The model's rules on what an update changed, and its counts of records added and
    /// removed and of RRsets changed.
    fn counts(
        &self,
        undo: &BTreeMap<NodeKey, BTreeMap<Rtype, RrSet>>,
    ) -> Result<(usize, usize, usize), String> {
        let (mut added, mut removed, mut rrsets) = (0, 0, 0);
        for (key, before) in undo {
            let Some(node) = self.nodes.get(key) else {
                continue;
            };
            let mut types: BTreeSet<Rtype> = before.keys().copied().collect();
            types.extend(node.after.keys().copied());
            for rtype in types {
                let old = before.get(&rtype);
                let new = node.after.get(&rtype);
                if old == new {
                    continue;
                }
                rrsets += 1;
                if let Some(new) = new {
                    new.check(&self.zone.name)
                        .map_err(|error| error.to_string())?;
                    added += new
                        .rdata
                        .iter()
                        .filter(|data| old.is_none_or(|old| !old.rdata.contains(data)))
                        .count();
                }
                if let Some(old) = old {
                    removed += old
                        .rdata
                        .iter()
                        .filter(|data| new.is_none_or(|new| !new.rdata.contains(data)))
                        .count();
                }
            }
            check_node(&self.zone.name, node.after.values())
                .and_then(|()| {
                    if key.1 == self.zone.name {
                        check_apex(&self.zone.name, node.after.values())
                    } else {
                        Ok(())
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        Ok((added, removed, rrsets))
    }

    /// The changed RRsets against the store's view.
    fn diff(&self) -> Vec<Diff> {
        let mut diff = Vec::new();
        for ((scope, name), node) in &self.nodes {
            let mut types: BTreeSet<Rtype> = node.before.keys().copied().collect();
            types.extend(node.after.keys().copied());
            for rtype in types {
                let before = node.before.get(&rtype).map(|(rrset, _)| rrset);
                let after = node.after.get(&rtype);
                if before == after {
                    continue;
                }
                diff.push(Diff {
                    key: self.rrset_key(scope, name, rtype),
                    before: before.cloned(),
                    after: after.cloned(),
                });
            }
        }
        diff
    }
}

/// The audit record of an applied update.
fn applied_audit(zone: &Zone, item: &Item<'_>, outcome: &Outcome) -> AuditDraft {
    let mut draft = AuditDraft::success(audit::UPDATE_APPLY, vec![ObjectRef::from(zone.id)])
        .with_source_ip(Some(item.client))
        .with_context("zone", zone.name.as_str())
        .with_context("client", item.client.to_string())
        .with_context("key", item.key.as_ref().map_or("none", KeyName::as_str))
        .with_context(
            "prerequisites",
            item.message.prerequisites.len().to_string(),
        )
        .with_context("updates", item.message.updates.len().to_string());
    if let Outcome::Applied {
        added,
        removed,
        rrsets,
    } = outcome
    {
        draft = draft
            .with_context("added", added.to_string())
            .with_context("removed", removed.to_string())
            .with_context("rrsets", rrsets.to_string());
    }
    if item.scope != ScopeName::DEFAULT {
        draft = draft.with_context("scope", item.scope.as_str());
    }
    draft
}

/// Plans the updates `items` of the zone `zone` against `view`: one outcome per update,
/// and the write of every change, or nothing when no update changed anything. `admit` runs
/// the policy again on the zone row of the view.
///
/// # Errors
///
/// The store's error (the whole group fails).
pub(crate) fn plan(
    view: &dyn ReadView,
    zone: ZoneId,
    items: &[Item<'_>],
    admit: &dyn Fn(&Zone, &Item<'_>) -> Result<(), Refusal>,
    cx: &RequestCtx,
    limits: JournalLimits,
) -> ZoneResult<Planned<Vec<Outcome>>> {
    let row = match ZoneService::zone(view, zone) {
        Ok(row) => row,
        Err(error) if error.is(tenko_core::dns::codes::ZONE_NOT_FOUND) => {
            let outcome = Outcome::NotAuth("the zone is not served here".to_owned());
            return Ok(Planned::nothing(vec![outcome; items.len()]));
        }
        Err(error) => return Err(error),
    };
    let mut planner = Planner {
        view,
        zone: row.zone,
        stamp: Stamp::new(cx.now, cx.principal.clone()),
        nodes: BTreeMap::new(),
        reads: BTreeMap::new(),
    };
    let mut outcomes = Vec::with_capacity(items.len());
    for item in items {
        if let Err(reason) = admit(&planner.zone, item) {
            outcomes.push(Outcome::Refused(reason.to_owned()));
            continue;
        }
        if !planner.zone.has_scope(&item.scope) {
            outcomes.push(Outcome::Failed(format!(
                "the zone has no scope {}",
                item.scope
            )));
            continue;
        }
        outcomes.push(planner.update(item)?);
    }
    let diff = planner.diff();
    if diff.is_empty() {
        return Ok(Planned::nothing(outcomes));
    }
    let mut batch = WriteBatch::for_request(cx);
    let mut expected: BTreeMap<RrSetKey, Option<Revision>> = planner.reads.clone();
    for item in &diff {
        let revision = planner
            .nodes
            .get(&(item.key.scope.clone(), item.key.name.clone()))
            .and_then(|node| node.before.get(&item.key.rtype))
            .map(|(_, revision)| *revision);
        expected.insert(item.key.clone(), revision);
    }
    for (key, revision) in &expected {
        batch.expect_typed(&RRSETS, key, *revision);
    }
    for item in &diff {
        match (&item.before, &item.after) {
            (before, Some(after)) => stage_put(&mut batch, before.as_ref(), after)?,
            (Some(before), None) => stage_delete(&mut batch, before),
            (None, None) => {}
        }
    }
    let mut scopes: Vec<&ScopeName> = diff.iter().map(|item| &item.key.scope).collect();
    scopes.sort();
    scopes.dedup();
    let mut serial = None;
    for scope in scopes {
        let (removed, added) =
            records::journal_diff(diff.iter().filter(|item| &item.key.scope == scope));
        let step = records::stage_serial_step(
            &mut batch,
            view,
            &planner.zone,
            scope,
            &planner.stamp,
            limits,
            removed,
            added,
        )?;
        if *scope == ScopeName::DEFAULT || serial.is_none() {
            serial = Some(step.to);
        }
    }
    for (item, outcome) in items.iter().zip(&outcomes) {
        if outcome.changed() {
            let mut draft = applied_audit(&planner.zone, item, outcome);
            if let Some(serial) = serial {
                draft = draft.with_context("serial", serial.to_string());
            }
            batch.audit(draft);
        }
    }
    let changed = outcomes.iter().filter(|outcome| outcome.changed()).count();
    Ok(Planned::write(
        outcomes,
        batch,
        format!(
            "dynamic update of zone {}: {changed} updates, {} RRsets",
            planner.zone.name,
            diff.len()
        ),
        vec![ObjectRef::from(zone)],
    ))
}
