//! Plans: what a list of [`IpamCommand`]s does to the store, computed from a read view
//! without writing (ADR 0011).
//!
//! [`plan`] is a pure function of the view, the request context, the options and the
//! commands. Its [`IpamPlan`] carries everything the write needs (preconditions, physical
//! mutations, history rows and audit drafts) and everything a person needs to review it
//! (the changes with before and after, warnings and a summary). The same plan serves the
//! API dry run (`?dry_run=true`, API-09), the import preview of WP1.5 and the apply: the
//! service proposes exactly the previewed batch, and its preconditions make it fail as
//! stale if anything it read changed in the meantime.
//!
//! # Preconditions
//!
//! - A version precondition for every object and uniqueness key the plan read.
//! - The prefix-tree counter of each VRF whose prefix set the plan read
//!   ([`tree_counter`](crate::tables::tree_counter)), bumped when the set changes.
//! - The allocation counter of each prefix whose addresses or ranges the plan read
//!   ([`alloc_counter`](crate::tables::alloc_counter)), bumped when they change.
//! - The reference counter of objects a delete found unreferenced.

mod planner;
mod workspace;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tenko_core::{
    JobId, ObjectKind, ObjectRef, Principal, RequestCtx, RequestId, Revision, Timestamp,
    audit::{AuditDraft, Digest, FieldChange},
};
use tenko_store::{Mutation, Precondition, ReadView, WriteBatch};
use utoipa::ToSchema;

pub use planner::{is_automation, status_transition_allowed};

use crate::{command::IpamCommand, error::IpamResult, history::ChangeAction, object::IpamObject};

/// Options of one plan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlanOptions {
    /// Warning codes the caller acknowledges (IPAM-06): a plan with a warning that needs
    /// an acknowledgement applies only when its code is listed here.
    #[serde(default)]
    pub acknowledge: BTreeSet<String>,
}

impl PlanOptions {
    /// Options acknowledging the given warning codes.
    pub fn acknowledging<I, S>(codes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            acknowledge: codes.into_iter().map(Into::into).collect(),
        }
    }
}

/// A warning found while planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlanWarning {
    /// Stable code, for example `ipam.prefix.nibble_boundary`.
    pub code: String,
    /// English explanation.
    pub message: String,
    /// The object concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectRef>,
    /// Named parameters for the translated message.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// Whether the plan applies only after the code is acknowledged.
    #[serde(default)]
    pub requires_ack: bool,
    /// Whether the code was acknowledged in the options.
    #[serde(default)]
    pub acknowledged: bool,
}

/// One change of one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlannedChange {
    /// The object.
    pub object: ObjectRef,
    /// What happens.
    pub action: ChangeAction,
    /// The object before (`None` when created).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<IpamObject>,
    /// The object after (`None` when removed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<IpamObject>,
    /// Changed fields as text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldChange>,
    /// Whether the change follows from another one (an address moving to a new, more
    /// specific prefix, interfaces deleted with their host).
    #[serde(default)]
    pub derived: bool,
}

/// How many objects of a kind a plan changes in one way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SummaryCount {
    /// The object kind.
    pub kind: ObjectKind,
    /// The action.
    pub action: ChangeAction,
    /// How many.
    pub count: usize,
}

/// A human summary of a plan: counts per kind and action, warnings, and English lines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlanSummary {
    /// Counts per kind and action, ordered by kind and action.
    pub counts: Vec<SummaryCount>,
    /// Warning counts by code.
    pub warnings: BTreeMap<String, usize>,
    /// Warning codes that still need an acknowledgement.
    pub unacknowledged: Vec<String>,
    /// English lines such as `3 prefixes created`.
    pub lines: Vec<String>,
    /// Physical writes in the batch.
    pub mutations: usize,
    /// Preconditions in the batch.
    pub preconditions: usize,
}

/// The stored result of a request that carried an idempotency key (API-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Receipt {
    /// SHA-256 over the canonical CBOR of the commands (allocation hints removed).
    pub fingerprint: Digest,
    /// The primary object of each command, in command order.
    pub results: Vec<ObjectRef>,
    /// The request.
    pub request: RequestId,
    /// The request time.
    pub at: Timestamp,
    /// The revision that committed the request (filled when read).
    #[serde(default)]
    pub revision: Revision,
}

/// A plan: the reviewable changes and the write batch that makes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpamPlan {
    /// The revision of the view the plan was computed from.
    pub base: Revision,
    /// Who plans.
    pub principal: Principal,
    /// The request time, used for every stamp.
    pub at: Timestamp,
    /// The request.
    pub request: RequestId,
    /// The client address, carried into the audit drafts.
    #[serde(default)]
    pub source_ip: Option<std::net::IpAddr>,
    /// The commands as planned (allocation hints filled in).
    pub commands: Vec<IpamCommand>,
    /// The changes, in order.
    pub changes: Vec<PlannedChange>,
    /// Warnings.
    pub warnings: Vec<PlanWarning>,
    /// The primary object of each command, in command order.
    pub results: Vec<ObjectRef>,
    /// Version and counter preconditions.
    pub preconditions: Vec<Precondition>,
    /// Physical writes, history rows included.
    pub mutations: Vec<Mutation>,
    /// One audit draft per change.
    pub audit: Vec<AuditDraft>,
    /// The earlier result when the idempotency key was used before with the same
    /// commands; the plan then writes nothing.
    #[serde(default)]
    pub replay: Option<Receipt>,
}

impl IpamPlan {
    /// Whether the plan writes nothing.
    pub fn is_empty(&self) -> bool {
        self.mutations.is_empty()
    }

    /// The objects the plan changes, for the job's targets.
    pub fn targets(&self) -> Vec<ObjectRef> {
        let set: BTreeSet<ObjectRef> = self.changes.iter().map(|c| c.object).collect();
        set.into_iter().collect()
    }

    /// Warning codes that need an acknowledgement and did not get one.
    pub fn unacknowledged(&self) -> Vec<String> {
        let set: BTreeSet<&str> = self
            .warnings
            .iter()
            .filter(|w| w.requires_ack && !w.acknowledged)
            .map(|w| w.code.as_str())
            .collect();
        set.into_iter().map(str::to_owned).collect()
    }

    /// The write batch of the plan.
    pub fn to_batch(&self) -> WriteBatch {
        WriteBatch {
            principal: self.principal.clone(),
            proposed_at: self.at,
            request: Some(self.request),
            // Idempotency of IPAM requests is handled by `ipam.receipts`, because a
            // replayed request plans new identifiers and so a different batch.
            idempotency: None,
            preconditions: self.preconditions.clone(),
            mutations: self.mutations.clone(),
            audit: self.audit.clone(),
        }
    }

    /// Counts per kind and action, warnings and English summary lines.
    pub fn summary(&self) -> PlanSummary {
        let mut counts: BTreeMap<(ObjectKind, ChangeAction), usize> = BTreeMap::new();
        for change in &self.changes {
            *counts
                .entry((change.object.kind, change.action))
                .or_default() += 1;
        }
        let mut warnings: BTreeMap<String, usize> = BTreeMap::new();
        for warning in &self.warnings {
            *warnings.entry(warning.code.clone()).or_default() += 1;
        }
        let mut lines: Vec<String> = counts
            .iter()
            .map(|((kind, action), count)| {
                format!("{count} {} {}", noun(*kind, *count), action.past())
            })
            .collect();
        if lines.is_empty() {
            lines.push("no changes".to_owned());
        }
        for (code, count) in &warnings {
            lines.push(format!(
                "{count} warning{}: {code}",
                if *count == 1 { "" } else { "s" }
            ));
        }
        PlanSummary {
            counts: counts
                .into_iter()
                .map(|((kind, action), count)| SummaryCount {
                    kind,
                    action,
                    count,
                })
                .collect(),
            warnings,
            unacknowledged: self.unacknowledged(),
            lines,
            mutations: self.mutations.len(),
            preconditions: self.preconditions.len(),
        }
    }

    /// The reviewable part of the plan, for the API.
    pub fn view(&self) -> PlanView {
        PlanView {
            base_revision: self.base,
            summary: self.summary(),
            changes: self.changes.clone(),
            warnings: self.warnings.clone(),
            results: self.results.clone(),
        }
    }
}

/// The reviewable part of a plan: the dry-run answer of the API (API-09) and the import
/// preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlanView {
    /// The revision the plan was computed from.
    #[schema(value_type = u64)]
    pub base_revision: Revision,
    /// Counts, warnings and summary lines.
    pub summary: PlanSummary,
    /// Every change with before and after.
    pub changes: Vec<PlannedChange>,
    /// Warnings.
    pub warnings: Vec<PlanWarning>,
    /// The primary object of each command.
    pub results: Vec<ObjectRef>,
}

/// The outcome of applying a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Applied {
    /// The revision that committed the plan (the earlier one for a replay).
    #[schema(value_type = u64)]
    pub revision: Revision,
    /// The inline job that carried the change (Q4); `None` for a replay or an empty plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<JobId>,
    /// The primary object of each command.
    pub results: Vec<ObjectRef>,
    /// Whether an earlier result was returned for a repeated idempotency key.
    #[serde(default)]
    pub replayed: bool,
    /// Plans made before the one that committed (counter contention).
    #[serde(default)]
    pub retries: u32,
    /// Warnings of the committed plan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
}

fn noun(kind: ObjectKind, count: usize) -> String {
    let singular = match kind {
        ObjectKind::CustomField => "custom field",
        ObjectKind::Vrf => "VRF",
        ObjectKind::Vlan => "VLAN",
        other => other.as_str(),
    };
    if count == 1 {
        singular.to_owned()
    } else if singular.ends_with("ss") {
        format!("{singular}es")
    } else if let Some(stem) = singular.strip_suffix('x') {
        format!("{stem}xes")
    } else {
        format!("{singular}s")
    }
}

/// Plans `commands` against `view` for the request `cx` (see the module documentation).
///
/// Pure: reads only the view, writes nothing, and is deterministic for the same view,
/// context, options and commands (generated identifiers derive from the request id).
///
/// # Errors
///
/// Returns the first [`IpamError`](crate::IpamError) a command raises: validation,
/// references, conflicts (IPAM-23), revision mismatches, locks (IPAM-16).
pub fn plan(
    view: &dyn ReadView,
    cx: &RequestCtx,
    options: &PlanOptions,
    commands: &[IpamCommand],
) -> IpamResult<IpamPlan> {
    planner::Planner::new(view, cx, options).run(commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nouns_pluralize() {
        assert_eq!(noun(ObjectKind::Address, 2), "addresses");
        assert_eq!(noun(ObjectKind::Prefix, 3), "prefixes");
        assert_eq!(noun(ObjectKind::Prefix, 1), "prefix");
        assert_eq!(noun(ObjectKind::Vrf, 2), "VRFs");
        assert_eq!(noun(ObjectKind::CustomField, 2), "custom fields");
    }
}
