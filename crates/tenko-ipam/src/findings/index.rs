//! The findings index: one derived, in-memory index over the sources, kept up to date from
//! the store's change sets.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use ipnet::IpNet;
use tenko_core::{
    JobId, ObjectRef, PrefixId, ProposalId, Revision, Timestamp, VrfId,
    serde_util::{from_hex, to_hex},
};
use tenko_jobs::tables::JOBS;
use tenko_store::{ChangeSet, KeyRange, ReadView, ReadViewExt, TableName};

use super::{
    map::{self, HealthItem, ViewFinding},
    model::{
        Finding, FindingArea, FindingCounts, FindingKind, FindingLevel, FindingSource,
        FindingsConfig, SubjectKind,
    },
};
use crate::{
    alarm::AlarmEvent,
    codes,
    error::{IpamError, IpamResult},
    net::{contains_ip, contains_net},
    proposals::model::{IntentProposalKind, OPEN_KEYS, PROPOSALS},
    reconcile::view,
    tables::ALARMS,
};

/// Largest page.
pub const MAX_LIMIT: usize = 1_000;
/// Page size when the caller gives none.
pub const DEFAULT_LIMIT: usize = 100;

/// One entry of the index.
#[derive(Debug, Clone)]
struct Entry {
    finding: Arc<Finding>,
    /// A conflict row of the view: hidden while an open conflict proposal is about this
    /// address, so the same conflict is listed and counted once.
    covered_by_conflict: Option<(VrfId, IpAddr)>,
    /// An open conflict proposal: the address it is about.
    conflict_subject: Option<(VrfId, IpAddr)>,
}

#[derive(Debug, Default)]
struct State {
    /// The newest store revision applied.
    revision: Revision,
    /// Every finding by identifier.
    entries: BTreeMap<String, Entry>,
    /// The addresses of open conflict proposals, with how many there are.
    conflicts: BTreeMap<(VrfId, IpAddr), u32>,
    /// When each health condition was first seen by this index.
    health_since: BTreeMap<String, Timestamp>,
    /// When each topology finding was first seen by this index.
    topology_since: BTreeMap<String, Timestamp>,
    /// The counts of every visible finding, until the next change.
    counts: Option<FindingCounts>,
}

impl State {
    fn visible(&self, entry: &Entry) -> bool {
        entry
            .covered_by_conflict
            .is_none_or(|address| !self.conflicts.contains_key(&address))
    }

    fn insert(&mut self, entry: Entry) {
        self.remove(&entry.finding.id.clone());
        if let Some(address) = entry.conflict_subject {
            *self.conflicts.entry(address).or_default() += 1;
        }
        self.entries.insert(entry.finding.id.clone(), entry);
        self.counts = None;
    }

    fn remove(&mut self, id: &str) -> bool {
        let Some(old) = self.entries.remove(id) else {
            return false;
        };
        if let Some(address) = old.conflict_subject
            && let Some(count) = self.conflicts.get_mut(&address)
        {
            *count -= 1;
            if *count == 0 {
                self.conflicts.remove(&address);
            }
        }
        self.counts = None;
        true
    }

    /// Removes every entry whose identifier starts with `prefix`.
    fn remove_prefixed(&mut self, prefix: &str) {
        let ids: Vec<String> = self
            .entries
            .range(prefix.to_owned()..)
            .take_while(|(id, _)| id.starts_with(prefix))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.remove(&id);
        }
    }

    fn put(&mut self, id: &str, finding: Option<Finding>, conflict: bool) -> bool {
        match finding {
            Some(finding) => {
                let conflict_subject = conflict
                    .then(|| finding.subject.vrf.zip(finding.subject.ip))
                    .flatten();
                let unchanged = self
                    .entries
                    .get(id)
                    .is_some_and(|entry| *entry.finding == finding);
                if !unchanged {
                    self.insert(Entry {
                        finding: Arc::new(finding),
                        covered_by_conflict: None,
                        conflict_subject,
                    });
                }
                !unchanged
            }
            None => self.remove(id),
        }
    }
}

/// What applying a change set changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// The source records whose findings appeared, changed or went away: proposals,
    /// prefixes (their alarms) and jobs.
    pub changed: Vec<ObjectRef>,
    /// Whether a table the reconciliation view reads changed, so the view's findings need a
    /// refresh.
    pub view_inputs: bool,
}

/// The tables the index follows record by record.
fn followed(table: &TableName) -> bool {
    table == PROPOSALS.name() || table == ALARMS.name() || table == JOBS.name()
}

/// Whether a table is an input of the reconciliation view: the IPAM intent and observation
/// tables, the DHCP configuration and leases, the probes' scopes. The alarms and the open
/// key rows are not; a proposal is (a rogue or an orphan links its proposal).
pub fn view_input(table: &TableName) -> bool {
    if table == ALARMS.name() || table == OPEN_KEYS.name() {
        return false;
    }
    matches!(table.namespace(), "ipam" | "dhcp" | "scan")
}

/// Filters and paging of the findings list. Empty lists match everything.
#[derive(Debug, Clone, Default)]
pub struct FindingQuery {
    /// Any of these severities.
    pub severities: Vec<FindingLevel>,
    /// Any of these kinds.
    pub kinds: Vec<FindingKind>,
    /// Any of these subject kinds.
    pub subjects: Vec<SubjectKind>,
    /// Any of these areas.
    pub areas: Vec<FindingArea>,
    /// Any of these sources.
    pub sources: Vec<FindingSource>,
    /// Findings inside any of these prefixes: the subject's prefix, or its address or
    /// network inside the prefix in the same VRF. A prefix filter gives one, a site filter
    /// the prefixes of the site; `None` filters nothing, an empty list matches nothing.
    pub within: Option<Vec<(PrefixId, VrfId, IpNet)>>,
    /// Text contained in the summary, the subject's label or the code (without case).
    pub text: Option<String>,
    /// Page size, 1 to [`MAX_LIMIT`]; [`DEFAULT_LIMIT`] when absent.
    pub limit: Option<usize>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// A page of findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPage {
    /// The findings: the most urgent first, then the newest, then by identifier.
    pub items: Vec<Finding>,
    /// Cursor of the next page.
    pub next_cursor: Option<String>,
    /// The revision the index has applied.
    pub revision: Revision,
}

fn invalid_filter(name: &str, detail: impl Into<String>) -> IpamError {
    IpamError::new(codes::INVALID_FILTER, 400, detail)
        .titled("Invalid filter")
        .param("name", name)
        .field(name, codes::INVALID_FILTER)
}

/// The sort key of a finding: severity, the newest first, identifier.
fn sort_key(finding: &Finding) -> Vec<u8> {
    let mut key = Vec::with_capacity(48);
    key.push(finding.severity as u8);
    // Signed nanoseconds in an order-preserving unsigned form, inverted: the newest first.
    let since = (finding.since.unix_nanos() ^ i128::MIN).cast_unsigned();
    key.extend_from_slice(&(!since).to_be_bytes());
    key.extend_from_slice(finding.id.as_bytes());
    key
}

fn within(finding: &Finding, prefixes: &[(PrefixId, VrfId, IpNet)]) -> bool {
    let subject = &finding.subject;
    prefixes.iter().any(|(id, vrf, cidr)| {
        subject.prefix == Some(*id)
            || subject.objects.contains(&ObjectRef::from(*id))
            || (subject.vrf.is_none_or(|own| own == *vrf)
                && (subject.ip.is_some_and(|ip| contains_ip(cidr, ip))
                    || subject.cidr.is_some_and(|net| contains_net(cidr, &net))))
    })
}

impl FindingQuery {
    fn matches(&self, finding: &Finding) -> bool {
        (self.severities.is_empty() || self.severities.contains(&finding.severity))
            && (self.kinds.is_empty() || self.kinds.contains(&finding.kind))
            && (self.subjects.is_empty() || self.subjects.contains(&finding.subject.kind))
            && (self.areas.is_empty() || self.areas.contains(&finding.area))
            && (self.sources.is_empty() || self.sources.contains(&finding.source))
            && self
                .within
                .as_ref()
                .is_none_or(|prefixes| within(finding, prefixes))
            && self.text.as_ref().is_none_or(|text| {
                let text = text.to_lowercase();
                finding.summary.to_lowercase().contains(&text)
                    || finding.subject.label.to_lowercase().contains(&text)
                    || finding.code.to_lowercase().contains(&text)
            })
    }
}

/// The findings index (the findings model of `docs/reconciliation.md`): proposals, alarms
/// and jobs are applied record by record from the change sets ([`FindingsIndex::apply`]);
/// the findings of the reconciliation view, which derives them from intent and observation
/// on read, are replaced as a whole when its inputs changed ([`FindingsIndex::refresh_view`],
/// rate limited by the caller); health conditions are set by the status
/// ([`FindingsIndex::set_health`]). A request reads the index, never the sources.
#[derive(Debug)]
pub struct FindingsIndex {
    config: FindingsConfig,
    state: RwLock<State>,
    // ADR 0031: the lease view the reconciliation view reads.
    leases: std::sync::OnceLock<std::sync::Arc<crate::observe::dhcp::LeaseFacts>>,
}

impl FindingsIndex {
    /// An empty index.
    pub fn new(config: FindingsConfig) -> Self {
        Self {
            config,
            state: RwLock::new(State::default()),
            leases: std::sync::OnceLock::new(),
        }
    }

    /// Gives the index the lease view the findings of the reconciliation view read (ADR
    /// 0031), once; without one they see no lease.
    pub fn set_leases(&self, leases: std::sync::Arc<crate::observe::dhcp::LeaseFacts>) {
        let _ = self.leases.set(leases);
    }

    /// The lease view, when the index has one.
    pub fn leases(&self) -> Option<&std::sync::Arc<crate::observe::dhcp::LeaseFacts>> {
        self.leases.get()
    }

    /// The settings.
    pub fn config(&self) -> &FindingsConfig {
        &self.config
    }

    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The newest store revision applied.
    pub fn revision(&self) -> Revision {
        self.read().revision
    }

    /// What a change set touches, without reading anything: whether it changes a record the
    /// index follows (a proposal, an alarm, a job), so [`Self::apply`] needs a read view,
    /// and whether it changes an input of the reconciliation view.
    pub fn touches(changes: &ChangeSet) -> (bool, bool) {
        let records = changes.changes.iter().any(|change| followed(&change.table));
        let inputs = changes
            .changes
            .iter()
            .any(|change| view_input(&change.table));
        (records, inputs)
    }

    /// Records that the index is current at `revision`, for a change set that touches no
    /// record it follows.
    pub fn advance(&self, revision: Revision) {
        let mut state = self.write();
        if revision > state.revision {
            state.revision = revision;
            // The cached counts stay valid; they carry the revision.
            if let Some(counts) = state.counts.as_mut() {
                counts.revision = revision;
            }
        }
    }

    /// Reads every followed source from `view` and replaces the proposals, alarms and jobs
    /// of the index; with `with_view`, the findings of the reconciliation view too.
    ///
    /// # Errors
    ///
    /// Store and decoding errors; the index is left as it was.
    pub fn load(&self, view: &dyn ReadView, now: Timestamp, with_view: bool) -> IpamResult<()> {
        let mut proposals = Vec::new();
        for (_, id, _) in view.scan_typed(&OPEN_KEYS, KeyRange::all(), usize::MAX, false)? {
            let id: ProposalId = id;
            if let Some((proposal, _)) = view.get_typed(&PROPOSALS, &id)? {
                proposals.push(proposal);
            }
        }
        let alarms: Vec<AlarmEvent> = view
            .scan_typed(&ALARMS, KeyRange::all(), usize::MAX, false)?
            .into_iter()
            .map(|(_, event, _)| event)
            .collect();
        let mut jobs = Vec::new();
        // Only jobs that wait can wait for a person: `jobs.by_state` names them.
        for state in [
            tenko_jobs::model::JobState::Waiting,
            tenko_jobs::model::JobState::RollingBack,
        ] {
            let range = KeyRange::prefix(tenko_core::codec::encode_key(&state));
            for ((_, id), (), _) in
                view.scan_typed(&tenko_jobs::tables::BY_STATE, range, usize::MAX, false)?
            {
                let id: JobId = id;
                if let Some((job, _)) = view.get_typed(&JOBS, &id)? {
                    jobs.push(job);
                }
            }
        }
        let derived = if with_view {
            Some(self.view_findings(view, now)?)
        } else {
            None
        };
        let mut state = self.write();
        for prefix in ["proposal:", "alarm:", "job:"] {
            state.remove_prefixed(prefix);
        }
        for proposal in &proposals {
            let id = map::finding_id(FindingSource::Proposal, &proposal.id.to_string());
            state.put(
                &id,
                map::of_proposal(proposal),
                proposal.kind == IntentProposalKind::Conflict,
            );
        }
        for event in &alarms {
            let id = map::finding_id(FindingSource::Alarm, &event.prefix.to_string());
            state.put(&id, map::of_alarm(event), false);
        }
        for job in &jobs {
            let id = map::finding_id(FindingSource::Job, &job.id.to_string());
            state.put(&id, map::of_job(job), false);
        }
        if let Some(derived) = derived {
            Self::replace_view(&mut state, derived);
        }
        state.revision = state.revision.max(view.revision());
        state.counts = None;
        Ok(())
    }

    /// Applies one change set, reading the changed records from `view` (at or after the
    /// change set's revision).
    ///
    /// # Errors
    ///
    /// Store and decoding errors; what was applied before the error stays.
    pub fn apply(&self, view: &dyn ReadView, changes: &ChangeSet) -> IpamResult<Applied> {
        let mut applied = Applied::default();
        let mut updates: Vec<(String, Option<Finding>, bool, ObjectRef)> = Vec::new();
        for change in &changes.changes {
            if view_input(&change.table) {
                applied.view_inputs = true;
            }
            if !followed(&change.table) {
                continue;
            }
            if &change.table == PROPOSALS.name() {
                let Ok(id) = PROPOSALS.decode_key(&change.key) else {
                    continue;
                };
                let proposal = view
                    .get_typed(&PROPOSALS, &id)?
                    .map(|(proposal, _)| proposal);
                let conflict = proposal
                    .as_ref()
                    .is_some_and(|proposal| proposal.kind == IntentProposalKind::Conflict);
                updates.push((
                    map::finding_id(FindingSource::Proposal, &id.to_string()),
                    proposal.as_ref().and_then(map::of_proposal),
                    conflict,
                    ObjectRef::from(id),
                ));
            } else if &change.table == ALARMS.name() {
                let Ok(prefix) = ALARMS.decode_key(&change.key) else {
                    continue;
                };
                let event = view.get_typed(&ALARMS, &prefix)?.map(|(event, _)| event);
                updates.push((
                    map::finding_id(FindingSource::Alarm, &prefix.to_string()),
                    event.as_ref().and_then(map::of_alarm),
                    false,
                    ObjectRef::from(prefix),
                ));
            } else {
                let Ok(id) = JOBS.decode_key(&change.key) else {
                    continue;
                };
                let job = view.get_typed(&JOBS, &id)?.map(|(job, _)| job);
                updates.push((
                    map::finding_id(FindingSource::Job, &id.to_string()),
                    job.as_ref().and_then(map::of_job),
                    false,
                    ObjectRef::from(id),
                ));
            }
        }
        let mut state = self.write();
        for (id, finding, conflict, object) in updates {
            if state.put(&id, finding, conflict) {
                applied.changed.push(object);
            }
        }
        state.revision = state.revision.max(changes.revision);
        Ok(applied)
    }

    fn view_findings(&self, view: &dyn ReadView, now: Timestamp) -> IpamResult<Vec<ViewFinding>> {
        let derived = view::findings_view(view, self.leases.get().map(AsRef::as_ref), now)?;
        let mut out: Vec<ViewFinding> = derived
            .rows
            .iter()
            .filter_map(|row| {
                map::of_row(
                    row,
                    derived.unseen_since.get(&row.key).copied(),
                    now,
                    &self.config,
                )
            })
            .collect();
        out.extend(derived.artifacts.iter().map(|artifact| ViewFinding {
            finding: map::of_artifact(artifact),
            covered_by_conflict: None,
        }));
        Ok(out)
    }

    fn replace_view(state: &mut State, derived: Vec<ViewFinding>) -> bool {
        let before: BTreeMap<String, Arc<Finding>> = state
            .entries
            .range("reconcile:".to_owned()..)
            .take_while(|(id, _)| id.starts_with("reconcile:"))
            .map(|(id, entry)| (id.clone(), Arc::clone(&entry.finding)))
            .collect();
        state.remove_prefixed("reconcile:");
        let mut after = BTreeMap::new();
        for item in derived {
            let finding = Arc::new(item.finding);
            after.insert(finding.id.clone(), Arc::clone(&finding));
            state.insert(Entry {
                finding,
                covered_by_conflict: item.covered_by_conflict,
                conflict_subject: None,
            });
        }
        before != after
    }

    /// Replaces the findings of the reconciliation view with what it derives from `view` at
    /// `now`. Answers whether they changed.
    ///
    /// # Errors
    ///
    /// Store and decoding errors; the index is left as it was.
    pub fn refresh_view(&self, view: &dyn ReadView, now: Timestamp) -> IpamResult<bool> {
        let derived = self.view_findings(view, now)?;
        let mut state = self.write();
        let changed = Self::replace_view(&mut state, derived);
        state.revision = state.revision.max(view.revision());
        Ok(changed)
    }

    /// Replaces the health findings with `items` as of `now`; a condition keeps the time it
    /// was first seen while it lasts. Answers whether they changed.
    pub fn set_health(&self, items: &[HealthItem], now: Timestamp) -> bool {
        let mut state = self.write();
        let ids: BTreeSet<String> = items.iter().map(HealthItem::id).collect();
        state.health_since.retain(|id, _| ids.contains(id));
        let mut changed = false;
        let gone: Vec<String> = state
            .entries
            .range("health:".to_owned()..)
            .take_while(|(id, _)| id.starts_with("health:"))
            .filter(|(id, _)| !ids.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in gone {
            changed |= state.remove(&id);
        }
        for item in items {
            let id = item.id();
            let since = *state.health_since.entry(id.clone()).or_insert(now);
            changed |= state.put(&id, Some(map::of_health(item, since)), false);
        }
        changed
    }

    /// Replaces the topology's findings (its root and the WLAN rules) with `findings` as of
    /// `now`; a finding keeps the time it was first seen while it lasts. Answers whether they
    /// changed.
    pub fn set_topology(&self, findings: Vec<Finding>, now: Timestamp) -> bool {
        const PREFIX: &str = "topology:";
        let mut state = self.write();
        let ids: BTreeSet<String> = findings.iter().map(|f| f.id.clone()).collect();
        state.topology_since.retain(|id, _| ids.contains(id));
        let mut changed = false;
        let gone: Vec<String> = state
            .entries
            .range(PREFIX.to_owned()..)
            .take_while(|(id, _)| id.starts_with(PREFIX))
            .filter(|(id, _)| !ids.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in gone {
            changed |= state.remove(&id);
        }
        for mut finding in findings {
            if !finding.id.starts_with(PREFIX) {
                continue;
            }
            finding.since = *state
                .topology_since
                .entry(finding.id.clone())
                .or_insert(now);
            let id = finding.id.clone();
            changed |= state.put(&id, Some(finding), false);
        }
        changed
    }

    /// One finding by identifier, if it is listed.
    pub fn get(&self, id: &str) -> Option<Finding> {
        let state = self.read();
        state
            .entries
            .get(id)
            .filter(|entry| state.visible(entry))
            .map(|entry| (*entry.finding).clone())
    }

    /// The counts of every listed finding. Cached until the next change, so a read costs a
    /// copy.
    pub fn counts(&self) -> FindingCounts {
        if let Some(counts) = self.read().counts {
            return counts;
        }
        let mut state = self.write();
        let counts = Self::count(&state, &|_| true);
        state.counts = Some(counts);
        counts
    }

    /// The counts of the listed findings that `keep` admits (a scoped reader).
    pub fn counts_where(&self, keep: &dyn Fn(&Finding) -> bool) -> FindingCounts {
        Self::count(&self.read(), keep)
    }

    fn count(state: &State, keep: &dyn Fn(&Finding) -> bool) -> FindingCounts {
        let mut counts = FindingCounts {
            revision: state.revision,
            ..FindingCounts::default()
        };
        for entry in state.entries.values() {
            if state.visible(entry) && keep(&entry.finding) {
                counts.add(&entry.finding);
            }
        }
        counts
    }

    /// Lists findings (see [`FindingQuery`]) that `keep` admits.
    ///
    /// # Errors
    ///
    /// `ipam.invalid_filter` for a limit out of range, `ipam.invalid_cursor`.
    pub fn list(
        &self,
        query: &FindingQuery,
        keep: &dyn Fn(&Finding) -> bool,
    ) -> IpamResult<FindingPage> {
        let limit = match query.limit {
            None => DEFAULT_LIMIT,
            Some(limit) if (1..=MAX_LIMIT).contains(&limit) => limit,
            Some(_) => {
                return Err(invalid_filter(
                    "limit",
                    format!("limit is 1 to {MAX_LIMIT}"),
                ));
            }
        };
        let after = query
            .cursor
            .as_deref()
            .map(|text| {
                from_hex(text).ok_or_else(|| {
                    IpamError::new(codes::INVALID_CURSOR, 400, "the cursor is malformed")
                        .titled("Invalid cursor")
                        .field("cursor", codes::INVALID_CURSOR)
                })
            })
            .transpose()?;
        let state = self.read();
        let mut rows: Vec<(Vec<u8>, Arc<Finding>)> = state
            .entries
            .values()
            .filter(|entry| state.visible(entry))
            .filter(|entry| query.matches(&entry.finding) && keep(&entry.finding))
            .map(|entry| (sort_key(&entry.finding), Arc::clone(&entry.finding)))
            .filter(|(key, _)| after.as_ref().is_none_or(|after| key > after))
            .collect();
        let revision = state.revision;
        drop(state);
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = if more {
            rows.last().map(|(key, _)| to_hex(key))
        } else {
            None
        };
        Ok(FindingPage {
            items: rows
                .into_iter()
                .map(|(_, finding)| (*finding).clone())
                .collect(),
            next_cursor,
            revision,
        })
    }

    /// How many findings the index holds, hidden ones included (tests and metrics).
    pub fn len(&self) -> usize {
        self.read().entries.len()
    }

    /// Whether the index holds no finding.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts a finding as if a source had produced it (tests and benchmarks).
    #[doc(hidden)]
    pub fn insert_for_test(&self, finding: Finding) {
        let id = finding.id.clone();
        let conflict =
            finding.source == FindingSource::Proposal && finding.kind == FindingKind::Conflict;
        self.write().put(&id, Some(finding), conflict);
    }

    /// Replaces the findings of the view (tests).
    #[cfg(test)]
    pub(crate) fn insert_view_for_test(&self, derived: Vec<ViewFinding>) {
        Self::replace_view(&mut self.write(), derived);
    }
}
