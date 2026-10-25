//! Decisions on proposals: approval by a person, adoption by a policy, rejection.
//!
//! An approval plans the proposal's commands as the approving person and applies them in
//! one batch together with the proposal's new state, inside the inline job of the change
//! (IPAM-17): the intent change, the accepted proposal and their audit records commit
//! together or not at all. An adoption does the same as `system:reconciler`, which the
//! planner treats as automation, so a locked host refuses it (IPAM-16). A rejection
//! records the reason and remembers the proposal's fingerprint: the reconciler does not
//! open the same subject again until its evidence changes.
//!
//! The commands applied are the proposal's as the intent stands at the decision
//! ([`current_commands`]): a VLAN that another decision created since the proposal opened is
//! not created twice, and the prefix link that would have named the new VLAN names the
//! existing one.

use serde::{Deserialize, Serialize};
use tenko_core::{
    Coded, JobId, ObjectRef, PrefixId, ProposalId, RequestCtx, Revision, VlanId,
    audit::{AuditAction, AuditDraft},
    ipam::{AssignmentMode, Stamp, Vlan},
    net::HostName,
};
use tenko_jobs::JobState;
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, WriteBatch};
use utoipa::ToSchema;

use super::model::{
    IntentProposal, IntentProposalKind, IntentProposalState, OPEN_KEYS, PROPOSALS, REJECTIONS,
    Rejection, actions, codes,
};
use crate::{
    command::IpamCommand,
    error::{IpamError, IpamResult},
    jobs::{WriteStepParams, committed_revision, edit_job, with_batch},
    plan::{PlanOptions, PlanView, PlanWarning},
    reconcile::names::{self, HostNameChoice, NameSource},
    service::IpamService,
    tables::{HOSTS, VLAN_VIDS, VLANS},
};

/// Longest rejection reason in bytes.
pub const MAX_REASON: usize = 1_024;

/// The answer of a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Decision {
    /// The proposal after the decision; on a dry run, as it is.
    pub proposal: IntentProposal,
    /// Whether this is a dry run.
    pub dry_run: bool,
    /// The revision that committed the decision; `null` on a dry run.
    #[schema(value_type = Option<u64>)]
    pub revision: Option<Revision>,
    /// The inline job that carried it (IPAM-17); `null` on a dry run.
    pub job_id: Option<JobId>,
    /// The objects the commands created or changed.
    pub results: Vec<ObjectRef>,
    /// Warnings of the plan.
    pub warnings: Vec<PlanWarning>,
    /// The plan (dry runs of an approval only).
    pub plan: Option<PlanView>,
}

/// Who applies a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applier {
    /// A person approves.
    Person,
    /// A prefix's policy adopts; hosts are created with `host_mode`.
    Policy {
        prefix: PrefixId,
        host_mode: AssignmentMode,
    },
}

/// Reads a proposal with its revision.
///
/// # Errors
///
/// `ipam.proposal.not_found`, store and decoding errors.
pub fn load(view: &dyn ReadView, id: ProposalId) -> IpamResult<IntentProposal> {
    let (mut proposal, revision) = view
        .get_typed(&PROPOSALS, &id)?
        .ok_or_else(|| not_found(id))?;
    proposal.revision = revision;
    Ok(proposal)
}

fn not_found(id: ProposalId) -> IpamError {
    IpamError::new(
        codes::NOT_FOUND,
        404,
        format!("proposal {id} does not exist"),
    )
    .titled("Proposal not found")
    .param("kind", "proposal")
    .param("id", id)
}

pub(crate) fn check(proposal: &IntentProposal, expected: Option<Revision>) -> IpamResult<()> {
    if let Some(expected) = expected
        && expected != proposal.revision
    {
        return Err(IpamError::new(
            codes::REVISION_MISMATCH,
            412,
            format!(
                "proposal {} is at revision {}, not {expected}",
                proposal.id, proposal.revision
            ),
        )
        .titled("The proposal changed since it was read")
        .param("id", proposal.id)
        .param("expected", expected)
        .param("actual", proposal.revision));
    }
    if !proposal.is_open() {
        return Err(IpamError::new(
            codes::NOT_OPEN,
            409,
            format!(
                "proposal {} is {}, not open",
                proposal.id,
                proposal.state.as_str()
            ),
        )
        .titled("The proposal is decided already")
        .param("id", proposal.id)
        .param("state", proposal.state.as_str()));
    }
    Ok(())
}

/// The revision of the open-key row of a proposal.
fn key_revision(view: &dyn ReadView, proposal: &IntentProposal) -> IpamResult<Option<Revision>> {
    Ok(view
        .get_typed(&OPEN_KEYS, &proposal.key)?
        .filter(|(id, _)| *id == proposal.id)
        .map(|(_, revision)| revision))
}

/// Closes the open-key row of a proposal in `batch`, if the row still names it.
pub(crate) fn close_key(
    view: &dyn ReadView,
    proposal: &IntentProposal,
    batch: &mut WriteBatch,
) -> IpamResult<()> {
    if let Some(revision) = key_revision(view, proposal)? {
        batch.delete_typed(&OPEN_KEYS, &proposal.key);
        batch.expect_typed(&OPEN_KEYS, &proposal.key, Some(revision));
    }
    Ok(())
}

fn store_failed(code: &str) -> bool {
    code == "sys.store.precondition_failed"
}

/// Runs `batch` as the inline one-step job of an edit (decision Q4) and returns the
/// committed revision and the job.
///
/// # Errors
///
/// `ipam.plan.stale` when a precondition failed, or the job's error.
pub(crate) async fn run_write(
    ipam: &IpamService,
    batch: WriteBatch,
    summary: Vec<String>,
    targets: Vec<ObjectRef>,
    cx: &RequestCtx,
) -> IpamResult<(Revision, Option<JobId>)> {
    let params = WriteStepParams {
        nonce: uuid::Uuid::now_v7(),
        summary,
        targets,
        mutations: u64::try_from(batch.mutations.len()).unwrap_or(u64::MAX),
        audit: u64::try_from(batch.audit.len()).unwrap_or(u64::MAX),
    };
    let spec = edit_job(&params)?;
    let job = match with_batch(&params, batch, ipam.jobs().run_inline(spec, cx)).await {
        Ok(job) if job.state == JobState::Succeeded => job,
        Ok(job) => {
            let error = job.error.unwrap_or_else(|| {
                tenko_core::CodedError::new(crate::codes::JOB_FAILED, 500, "the job failed")
            });
            return Err(if store_failed(&error.code) {
                IpamError::stale()
            } else {
                IpamError::from_coded_error(error)
            });
        }
        Err(error) => {
            let error = error.to_coded_error();
            return Err(if store_failed(&error.code) {
                IpamError::stale()
            } else {
                IpamError::from_coded_error(error)
            });
        }
    };
    let revision = committed_revision(&job).ok_or_else(|| {
        IpamError::new(
            crate::codes::JOB_FAILED,
            500,
            "the write step reported no result",
        )
    })?;
    Ok((revision, Some(job.id)))
}

/// A short pause before trying again after a stale plan.
pub(crate) async fn pause(attempt: u32) {
    let micros = 100u64 << attempt.min(8);
    tokio::time::sleep(std::time::Duration::from_micros(micros)).await;
}

/// The live VLAN with `vid` that a VLAN of `site` would duplicate: the site's own, or a
/// global one.
fn existing_vlan(
    view: &dyn ReadView,
    site: Option<tenko_core::SiteId>,
    vid: u16,
) -> IpamResult<Option<VlanId>> {
    let mut keys = vec![(site, vid)];
    if site.is_some() {
        keys.push((None, vid));
    }
    for key in keys {
        if let Some((id, _)) = view.get_typed(&VLAN_VIDS, &key)?
            && view
                .get_typed(&VLANS, &id)?
                .is_some_and(|(vlan, _): (Vlan, _)| !vlan.meta.is_deleted())
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// The commands of a proposal against the intent in `view`: a VLAN it would create that
/// exists by now (the same VLAN id at the same site, or a global one) is left out, and the
/// commands that name the VLAN it would have created name the existing one. Approving a
/// "VLAN discovered" proposal and the "prefix VLAN mismatch" proposal that creates the same
/// VLAN therefore works in either order.
///
/// # Errors
///
/// Store and decoding errors.
pub fn current_commands(
    view: &dyn ReadView,
    commands: &[IpamCommand],
) -> IpamResult<Vec<IpamCommand>> {
    let mut renamed: Vec<(VlanId, VlanId)> = Vec::new();
    let mut out = Vec::with_capacity(commands.len());
    for command in commands {
        if let IpamCommand::CreateVlan(input) = command
            && let Some(planned) = input.id
            && let Some(existing) = existing_vlan(view, input.site, input.vid)?
        {
            if existing != planned {
                renamed.push((planned, existing));
            }
            continue;
        }
        let mut command = command.clone();
        if let IpamCommand::UpdatePrefix(update) = &mut command
            && let Some(Some(vlan)) = update.patch.vlan
            && let Some((_, existing)) = renamed.iter().find(|(planned, _)| *planned == vlan)
        {
            update.patch.vlan = Some(Some(*existing));
        }
        out.push(command);
    }
    Ok(out)
}

/// The commands of a proposal as an applier runs them: a policy sets its host mode on the
/// hosts it creates.
fn commands_for(commands: Vec<IpamCommand>, applier: Applier) -> Vec<IpamCommand> {
    let mut commands = commands;
    if let Applier::Policy { host_mode, .. } = applier {
        for command in &mut commands {
            if let IpamCommand::CreateHost(input) = command {
                input.mode = Some(host_mode);
            }
        }
    }
    commands
}

/// Approves (or, with `dry_run`, previews) a proposal as `cx`: applies its commands and
/// marks it accepted in one batch.
///
/// # Errors
///
/// `ipam.proposal.not_found` (404), `ipam.proposal.revision_mismatch` (412) when
/// `expected` differs, `ipam.proposal.not_open` and `ipam.proposal.nothing_to_apply`
/// (409), the planner's errors (for example 409 `ipam.name_taken` or 423
/// `ipam.host.locked` for automation), `ipam.plan.unacknowledged`, `ipam.contended`.
pub async fn approve(
    ipam: &IpamService,
    id: ProposalId,
    cx: &RequestCtx,
    options: &PlanOptions,
    dry_run: bool,
    expected: Option<Revision>,
) -> IpamResult<Decision> {
    apply(
        ipam,
        id,
        cx,
        options,
        dry_run,
        expected,
        Applier::Person,
        &ApproveRequest::default(),
    )
    .await
}

/// Approves a proposal as [`approve`] does, with the operator's choice of name and what
/// to remember of it ([`ApproveRequest`]).
///
/// # Errors
///
/// Those of [`approve`], and 422 `ipam.proposal.choice_invalid` for a choice the proposal
/// does not offer; with `remember: source` also 422 `ipam.name_authority.invalid`.
pub async fn approve_with(
    ipam: &IpamService,
    id: ProposalId,
    cx: &RequestCtx,
    options: &PlanOptions,
    dry_run: bool,
    expected: Option<Revision>,
    request: &ApproveRequest,
) -> IpamResult<Decision> {
    apply(
        ipam,
        id,
        cx,
        options,
        dry_run,
        expected,
        Applier::Person,
        request,
    )
    .await
}

/// What the operator remembers of a choice of name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Remember {
    /// The host follows the chosen source from now on (a preference of the host).
    Host,
    /// The chosen source goes first in the name authority rule that decided (the site's
    /// rule, else the global one).
    Source,
}

/// The body of an approval: for a proposal that offers names (`choices`), which one the
/// host takes and what to remember. Every member is optional; without a body the proposed
/// name applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    /// One of the proposal's `choices` (compared without case); the proposed one when
    /// absent.
    #[serde(default)]
    pub choice: Option<String>,
    /// What to remember of the choice: `host` (the host follows the chosen source) or
    /// `source` (the source goes first in the name authority).
    #[serde(default)]
    pub remember: Option<Remember>,
}

/// The name an approval gives a host and the decision it records.
#[derive(Debug, Clone)]
struct Naming {
    host: tenko_core::HostId,
    /// The name the host takes.
    name: HostName,
    /// The host's name now, for a host of intent.
    current: Option<String>,
    /// The kind of source of the chosen name.
    source: Option<NameSource>,
    /// Every name on offer.
    offered: Vec<String>,
    /// The names not chosen.
    rejected: Vec<String>,
    remember: Option<Remember>,
    /// The site whose rule decided (`remember: source` puts the source first there).
    rule_site: Option<tenko_core::SiteId>,
}

fn choice_invalid(proposal: &IntentProposal, detail: impl Into<String>, choice: &str) -> IpamError {
    IpamError::new(codes::CHOICE_INVALID, 422, detail)
        .titled("The proposal does not offer that name")
        .param("id", proposal.id)
        .param("choice", choice)
}

impl Naming {
    /// The naming of an approval of `proposal` with `request`; `None` for a proposal that
    /// offers no names.
    fn of(
        view: &dyn ReadView,
        proposal: &IntentProposal,
        commands: &[IpamCommand],
        request: &ApproveRequest,
    ) -> IpamResult<Option<Self>> {
        let named = matches!(
            proposal.kind,
            IntentProposalKind::DiscoveredHost | IntentProposalKind::HostName
        ) && !proposal.choices.is_empty();
        let asked = request.choice.as_deref().map(str::trim);
        if !named {
            if request.choice.is_some() || request.remember.is_some() {
                return Err(choice_invalid(
                    proposal,
                    format!("proposal {} offers no names to choose from", proposal.id),
                    asked.unwrap_or_default(),
                ));
            }
            return Ok(None);
        }
        let chosen = match asked {
            None => &proposal.choices[0],
            Some(asked) => proposal
                .choices
                .iter()
                .find(|choice| choice.name.eq_ignore_ascii_case(asked))
                .ok_or_else(|| {
                    let offered: Vec<&str> = proposal
                        .choices
                        .iter()
                        .map(|choice| choice.name.as_str())
                        .collect();
                    choice_invalid(
                        proposal,
                        format!(
                            "proposal {} offers {}, not {asked}",
                            proposal.id,
                            offered.join(", ")
                        ),
                        asked,
                    )
                })?,
        };
        let mut host = None;
        let mut proposed_name = None;
        for command in commands {
            match command {
                IpamCommand::CreateHost(input) => {
                    host = input.id;
                    proposed_name = Some(input.name.clone());
                }
                IpamCommand::UpdateHost(update) => {
                    host = Some(update.id);
                    proposed_name.clone_from(&update.patch.name);
                }
                _ => {}
            }
        }
        let Some(host) = host else {
            return Ok(None);
        };
        // The proposed name is the command's own (it may carry a suffix that keeps it
        // unique); another choice is taken as it is offered.
        let name = match (chosen.proposed, proposed_name) {
            (true, Some(name)) => name,
            _ => names::host_name(&chosen.name).ok_or_else(|| {
                choice_invalid(
                    proposal,
                    format!("{} is no usable host name", chosen.name),
                    &chosen.name,
                )
            })?,
        };
        let current = view
            .get_typed(&HOSTS, &host)?
            .filter(|(record, _)| !record.meta.is_deleted())
            .map(|(record, _)| record.name.to_string());
        let rule_site = proposal
            .params
            .get("rule_site")
            .and_then(|site| site.parse().ok());
        Ok(Some(Self {
            host,
            current,
            source: chosen.sources.first().map(|source| source.source),
            offered: proposal
                .choices
                .iter()
                .map(|choice| choice.name.clone())
                .collect(),
            rejected: proposal
                .choices
                .iter()
                .filter(|choice| choice.name != chosen.name)
                .map(|choice| choice.name.clone())
                .collect(),
            name,
            remember: request.remember,
            rule_site,
        }))
    }

    /// The commands with the chosen name; a rename to the name the host has is left out.
    fn commands(&self, commands: Vec<IpamCommand>) -> Vec<IpamCommand> {
        commands
            .into_iter()
            .filter_map(|mut command| {
                match &mut command {
                    IpamCommand::CreateHost(input) => input.name = self.name.clone(),
                    IpamCommand::UpdateHost(update) => {
                        if self
                            .current
                            .as_deref()
                            .is_some_and(|current| current.eq_ignore_ascii_case(self.name.as_str()))
                        {
                            return None;
                        }
                        update.patch.name = Some(self.name.clone());
                    }
                    _ => {}
                }
                Some(command)
            })
            .collect()
    }

    /// Adds the decision (and, with `remember: source`, the rule) to `batch` and its
    /// context to the approval's audit record.
    fn stage(
        &self,
        view: &dyn ReadView,
        cx: &RequestCtx,
        batch: &mut WriteBatch,
        draft: AuditDraft,
    ) -> IpamResult<AuditDraft> {
        names::stage_choice(
            view,
            batch,
            &HostNameChoice {
                host: self.host,
                name: self.name.to_string(),
                offered: self.offered.clone(),
                source: self.source,
                prefer: self.remember == Some(Remember::Host),
                decided: Stamp::new(cx.now, cx.principal.clone()),
                revision: Revision::ZERO,
            },
        )?;
        let mut draft = draft
            .with_context("choice", self.name.to_string())
            .with_context("rejected", self.rejected.join(", "));
        if let Some(source) = self.source {
            draft = draft.with_context("source", source.as_str());
        }
        match self.remember {
            Some(Remember::Host) => draft = draft.with_context("remember", "host"),
            Some(Remember::Source) => {
                let Some(source) = self.source else {
                    return Ok(draft);
                };
                let (site, order) = names::rule_at(view, self.rule_site)?;
                let mut order: Vec<NameSource> =
                    order.into_iter().filter(|other| *other != source).collect();
                order.insert(0, source);
                names::stage_rule(view, cx, site, order, batch)?;
                draft = draft.with_context("remember", "source");
            }
            None => {}
        }
        Ok(draft)
    }
}

/// Accepts a name proposal whose chosen name the host has already: writes the decision
/// and the proposal's state, and changes no intent.
async fn keep_name(
    ipam: &IpamService,
    view: std::sync::Arc<dyn ReadView>,
    proposal: &IntentProposal,
    naming: &Naming,
    cx: &RequestCtx,
) -> IpamResult<Decision> {
    let mut accepted = proposal.clone();
    accepted.state = IntentProposalState::Accepted;
    accepted.decided = Some(Stamp::new(cx.now, cx.principal.clone()));
    accepted.updated = cx.now;
    accepted.revision = Revision::ZERO;
    let mut batch = WriteBatch::new(cx.principal.clone(), cx.now);
    batch.request = Some(cx.request);
    batch.put_typed(&PROPOSALS, &proposal.id, &accepted)?;
    batch.expect_typed(&PROPOSALS, &proposal.id, Some(proposal.revision));
    close_key(view.as_ref(), proposal, &mut batch)?;
    let draft = AuditDraft::success(
        AuditAction::from_static(actions::APPROVE),
        vec![ObjectRef::from(proposal.id), ObjectRef::from(naming.host)],
    )
    .with_source_ip(cx.source_ip)
    .with_context("kind", proposal.kind.as_str())
    .with_context("key", proposal.key.clone());
    let draft = naming.stage(view.as_ref(), cx, &mut batch, draft)?;
    batch.audit(draft);
    drop(view);
    let (revision, job_id) = run_write(
        ipam,
        batch,
        vec!["1 proposal approved".to_owned()],
        vec![ObjectRef::from(proposal.id)],
        cx,
    )
    .await?;
    accepted.revision = revision;
    Ok(Decision {
        proposal: accepted,
        dry_run: false,
        revision: Some(revision),
        job_id,
        results: Vec::new(),
        warnings: Vec::new(),
        plan: None,
    })
}

/// Applies a proposal for `applier` (see [`approve`]).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // One decision: plan, the proposal's state and the name.
pub(crate) async fn apply(
    ipam: &IpamService,
    id: ProposalId,
    cx: &RequestCtx,
    options: &PlanOptions,
    dry_run: bool,
    expected: Option<Revision>,
    applier: Applier,
    request: &ApproveRequest,
) -> IpamResult<Decision> {
    let attempts = ipam.config().max_attempts.max(1);
    for attempt in 0..attempts {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = ipam.store().read(consistency).await?;
        let proposal = load(view.as_ref(), id)?;
        check(&proposal, expected)?;
        let commands = current_commands(view.as_ref(), &proposal.commands)?;
        let naming = Naming::of(view.as_ref(), &proposal, &commands, request)?;
        let commands = match &naming {
            Some(naming) => naming.commands(commands),
            None => commands,
        };
        if commands.is_empty() {
            match naming {
                // The operator keeps the name the host has: only the decision is written.
                Some(naming) if !dry_run => {
                    match keep_name(ipam, view, &proposal, &naming, cx).await {
                        Err(error) if error.is(crate::codes::PLAN_STALE) => {
                            pause(attempt).await;
                            continue;
                        }
                        outcome => return outcome,
                    }
                }
                Some(_) => {
                    return Ok(Decision {
                        proposal,
                        dry_run: true,
                        revision: None,
                        job_id: None,
                        results: Vec::new(),
                        warnings: Vec::new(),
                        plan: None,
                    });
                }
                None => {
                    return Err(IpamError::new(
                        codes::NOTHING_TO_APPLY,
                        409,
                        format!(
                            "proposal {id} suggests no change; resolve it and reject it to close it"
                        ),
                    )
                    .titled("Nothing to apply")
                    .param("id", id));
                }
            }
        }
        let commands = commands_for(commands, applier);
        let mut plan = ipam.plan(view.as_ref(), cx, options, &commands)?;
        if dry_run {
            return Ok(Decision {
                proposal,
                dry_run: true,
                revision: None,
                job_id: None,
                results: plan.results.clone(),
                warnings: plan.warnings.clone(),
                plan: Some(plan.view()),
            });
        }
        let mut accepted = proposal.clone();
        accepted.state = IntentProposalState::Accepted;
        accepted.decided = Some(Stamp::new(cx.now, cx.principal.clone()));
        accepted.results = plan.results.clone();
        accepted.updated = cx.now;
        accepted.revision = Revision::ZERO;
        let (action, prefix) = match applier {
            Applier::Person => (actions::APPROVE, None),
            Applier::Policy { prefix, .. } => (actions::ADOPT, Some(prefix)),
        };
        accepted.adopted_by = prefix;
        let mut extra = WriteBatch::new(cx.principal.clone(), cx.now);
        extra.put_typed(&PROPOSALS, &id, &accepted)?;
        extra.expect_typed(&PROPOSALS, &id, Some(proposal.revision));
        close_key(view.as_ref(), &proposal, &mut extra)?;
        let mut objects = vec![ObjectRef::from(id)];
        objects.extend(plan.results.iter().copied());
        let mut draft = AuditDraft::success(AuditAction::from_static(action), objects)
            .with_source_ip(cx.source_ip)
            .with_context("kind", proposal.kind.as_str())
            .with_context("key", proposal.key.clone());
        if let Some(prefix) = prefix {
            draft = draft.with_context("policy_prefix", prefix.to_string());
        }
        if let Some(naming) = &naming {
            draft = naming.stage(view.as_ref(), cx, &mut extra, draft)?;
        }
        drop(view);
        plan.mutations.extend(extra.mutations);
        plan.audit.extend(extra.audit);
        plan.preconditions.extend(extra.preconditions);
        plan.audit.push(draft);
        match ipam.apply(&plan, cx).await {
            Ok(done) => {
                accepted.revision = done.revision;
                return Ok(Decision {
                    proposal: accepted,
                    dry_run: false,
                    revision: Some(done.revision),
                    job_id: done.job_id,
                    results: done.results,
                    warnings: done.warnings,
                    plan: None,
                });
            }
            Err(error) if error.is(crate::codes::PLAN_STALE) => {
                tracing::debug!(attempt, %id, "proposal plan stale; planning again");
                pause(attempt).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(IpamError::contended(attempts))
}

/// The reason of a rejection as it is recorded: trimmed, `None` when blank. A batch of
/// rejections checks it once before it starts.
///
/// # Errors
///
/// `ipam.validation` (400) for a reason over 1,024 bytes or with control characters other
/// than line breaks and tabs.
pub fn clean_reason(reason: Option<String>) -> IpamResult<Option<String>> {
    let reason = reason
        .map(|reason| reason.trim().to_owned())
        .filter(|reason| !reason.is_empty());
    if let Some(reason) = &reason
        && (reason.len() > MAX_REASON
            || reason
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'))
    {
        return Err(IpamError::invalid(
            "reason",
            format!("the reason has at most {MAX_REASON} bytes and no control characters"),
        ));
    }
    Ok(reason)
}

/// Rejects a proposal as `cx` with an optional reason, and remembers its fingerprint.
///
/// # Errors
///
/// `ipam.validation` (400) for a reason over 1,024 bytes or with control characters,
/// `ipam.proposal.not_found` (404), `ipam.proposal.revision_mismatch` (412),
/// `ipam.proposal.not_open` (409), `ipam.contended`.
pub async fn reject(
    ipam: &IpamService,
    id: ProposalId,
    reason: Option<String>,
    cx: &RequestCtx,
    expected: Option<Revision>,
) -> IpamResult<Decision> {
    let reason = clean_reason(reason)?;
    let attempts = ipam.config().max_attempts.max(1);
    for attempt in 0..attempts {
        let consistency = if attempt == 0 {
            ReadConsistency::Local
        } else {
            ReadConsistency::Linearizable
        };
        let view = ipam.store().read(consistency).await?;
        let proposal = load(view.as_ref(), id)?;
        check(&proposal, expected)?;
        let stamp = Stamp::new(cx.now, cx.principal.clone());
        let mut rejected = proposal.clone();
        rejected.state = IntentProposalState::Rejected;
        rejected.decided = Some(stamp.clone());
        rejected.reason.clone_from(&reason);
        rejected.updated = cx.now;
        rejected.revision = Revision::ZERO;
        let mut batch = WriteBatch::new(cx.principal.clone(), cx.now);
        batch.request = Some(cx.request);
        batch.put_typed(&PROPOSALS, &id, &rejected)?;
        batch.expect_typed(&PROPOSALS, &id, Some(proposal.revision));
        close_key(view.as_ref(), &proposal, &mut batch)?;
        let remembered = view
            .get_typed(&REJECTIONS, &proposal.key)?
            .map(|(_, revision)| revision);
        batch.put_typed(
            &REJECTIONS,
            &proposal.key,
            &Rejection {
                fingerprint: proposal.fingerprint,
                proposal: id,
                stamp,
                reason: reason.clone(),
                kept: None,
            },
        )?;
        batch.expect_typed(&REJECTIONS, &proposal.key, remembered);
        let mut draft = AuditDraft::success(
            AuditAction::from_static(actions::REJECT),
            vec![ObjectRef::from(id)],
        )
        .with_source_ip(cx.source_ip)
        .with_context("kind", proposal.kind.as_str())
        .with_context("key", proposal.key.clone());
        if let Some(reason) = &reason {
            draft = draft.with_context("reason", reason.clone());
        }
        batch.audit(draft);
        drop(view);
        match run_write(
            ipam,
            batch,
            vec!["1 proposal rejected".to_owned()],
            vec![ObjectRef::from(id)],
            cx,
        )
        .await
        {
            Ok((revision, job_id)) => {
                rejected.revision = revision;
                return Ok(Decision {
                    proposal: rejected,
                    dry_run: false,
                    revision: Some(revision),
                    job_id,
                    results: Vec::new(),
                    warnings: Vec::new(),
                    plan: None,
                });
            }
            Err(error) if error.is(crate::codes::PLAN_STALE) => pause(attempt).await,
            Err(error) => return Err(error),
        }
    }
    Err(IpamError::contended(attempts))
}

/// Records a failed adoption on the proposal, so the policy does not try it again until
/// the proposal is replaced. Best effort: a lost race is ignored.
///
/// # Errors
///
/// Store errors other than failed preconditions.
pub(crate) async fn record_adoption_failure(
    ipam: &IpamService,
    id: ProposalId,
    error: &IpamError,
    cx: &RequestCtx,
) -> IpamResult<()> {
    let view = ipam.store().read(ReadConsistency::Local).await?;
    let proposal = load(view.as_ref(), id)?;
    if !proposal.is_open() || proposal.adoption_error.is_some() {
        return Ok(());
    }
    let mut failed = proposal.clone();
    failed.adoption_error = Some(error.code_str().to_owned());
    failed.updated = cx.now;
    failed.revision = Revision::ZERO;
    let mut batch = WriteBatch::new(cx.principal.clone(), cx.now);
    batch.put_typed(&PROPOSALS, &id, &failed)?;
    batch.expect_typed(&PROPOSALS, &id, Some(proposal.revision));
    batch.audit(
        AuditDraft::failed(
            AuditAction::from_static(actions::ADOPT_FAILED),
            vec![ObjectRef::from(id)],
            error,
        )
        .with_context("key", proposal.key.clone())
        .with_context("detail", error.coded().detail.clone()),
    );
    drop(view);
    match ipam.store().propose(batch).await {
        Ok(_) | Err(tenko_store::StoreError::PreconditionFailed(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
