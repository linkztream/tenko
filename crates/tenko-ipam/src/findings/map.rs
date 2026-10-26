//! The mapping of every source to findings: kind, severity, area, subject, action and
//! since (the table in `docs/reconciliation.md`, "The findings model").

use std::{collections::BTreeMap, net::IpAddr};

use sha2::{Digest, Sha256};
use tenko_core::{ObjectKind, ObjectRef, Timestamp, VrfId};
use tenko_jobs::model::{Job, StepState};

use super::model::{
    Finding, FindingAction, FindingArea, FindingEvidence, FindingKind, FindingLevel, FindingSource,
    FindingSubject, FindingsConfig, SubjectKind,
};
use crate::{
    alarm::{AlarmEvent, AlarmLevel},
    proposals::model::{IntentProposal, IntentProposalKind},
    reconcile::{
        rule,
        view::{ReconcileKind, ReconcileRow, ScanArtifact},
    },
};

/// The audit action code of utilization alarms, the prefix of the alarm findings' codes.
const ALARM_CODE: &str = "ipam.prefix.alarm";

/// The prefix of the codes of findings from the reconciliation view.
pub const VIEW_CODE: &str = "ipam.reconcile.view";

/// The first 16 bytes of the SHA-256 of `text`, in hexadecimal: the stable suffix of the
/// identifier of a derived finding.
fn digest(text: &str) -> String {
    let hash = Sha256::digest(text.as_bytes());
    hash.iter()
        .take(16)
        .fold(String::with_capacity(32), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The identifier of a finding of `source` whose own identifier is `id`.
pub fn finding_id(source: FindingSource, id: &str) -> String {
    format!("{}:{id}", source.as_str())
}

/// The finding of an open proposal; none for a decided one. An open proposal waits for a
/// person's decision, so it is never information: a conflict is to act on, every other
/// kind to review. Every proposal belongs to the Discovery area, the inbox that lists them,
/// so that the badge and the inbox count the same.
pub fn of_proposal(proposal: &IntentProposal) -> Option<Finding> {
    if !proposal.is_open() {
        return None;
    }
    let (kind, action) = match proposal.kind {
        IntentProposalKind::Conflict => (FindingKind::Conflict, FindingAction::Resolve),
        IntentProposalKind::DiscoveredHost => (FindingKind::UnknownDevice, FindingAction::Adopt),
        IntentProposalKind::AddressMismatch => {
            (FindingKind::IntentDiffers, FindingAction::OpenHost)
        }
        IntentProposalKind::OutsidePrefixes => {
            (FindingKind::OutsidePrefixes, FindingAction::Decide)
        }
        IntentProposalKind::VlanDiscovered | IntentProposalKind::PrefixVlanMismatch => {
            (FindingKind::Vlan, FindingAction::Decide)
        }
        IntentProposalKind::HostName => (FindingKind::HostName, FindingAction::Decide),
        IntentProposalKind::OrphanedIntent => match proposal.rule.as_str() {
            rule::DNS_ORPHANED_RECORD => (FindingKind::OrphanedRecord, FindingAction::DeleteRecord),
            rule::ORPHANED_ADDRESS => (FindingKind::OrphanedAddress, FindingAction::Decide),
            _ => (FindingKind::Dns, FindingAction::Decide),
        },
    };
    let severity = if kind == FindingKind::Conflict {
        FindingLevel::Act
    } else {
        FindingLevel::Review
    };
    let subject = &proposal.subject;
    let host = subject
        .objects
        .iter()
        .find(|object| object.kind == ObjectKind::Host)
        .map(|object| tenko_core::HostId(object.id));
    let (subject_kind, label) = if let Some(ip) = subject.ip {
        (SubjectKind::Address, ip.to_string())
    } else if let Some(cidr) = subject.cidr {
        (SubjectKind::Prefix, cidr.to_string())
    } else if matches!(kind, FindingKind::OrphanedRecord | FindingKind::Dns)
        && let Some(name) = &subject.name
    {
        (SubjectKind::Record, name.clone())
    } else if let Some(mac) = subject.mac {
        (SubjectKind::Device, mac.to_string())
    } else if let (Some(name), Some(_)) = (&subject.name, host) {
        (SubjectKind::Host, name.clone())
    } else if let Some(name) = &subject.name {
        (SubjectKind::Record, name.clone())
    } else {
        (SubjectKind::Record, proposal.key.clone())
    };
    let mut params = proposal.params.clone();
    params.insert(
        "proposal_kind".to_owned(),
        proposal.kind.as_str().to_owned(),
    );
    Some(Finding {
        id: finding_id(FindingSource::Proposal, &proposal.id.to_string()),
        kind,
        severity,
        area: FindingArea::Discovery,
        subject: FindingSubject {
            kind: subject_kind,
            label,
            vrf: subject.vrf,
            ip: subject.ip,
            cidr: subject.cidr,
            mac: subject.mac,
            prefix: subject.prefix,
            host,
            objects: subject.objects.clone(),
        },
        summary: proposal.summary.clone(),
        code: proposal.rule.clone(),
        params,
        evidence: FindingEvidence {
            id: proposal.id.to_string(),
            path: format!("/proposals/{}", proposal.id),
        },
        action,
        since: proposal.created,
        source: FindingSource::Proposal,
    })
}

/// The finding of a prefix's alarm state; none below the warning threshold. Over the
/// critical threshold the network is about to run out (act); over the warning threshold it
/// is to review.
pub fn of_alarm(event: &AlarmEvent) -> Option<Finding> {
    let severity = match event.level {
        AlarmLevel::Normal => return None,
        AlarmLevel::Warning => FindingLevel::Review,
        AlarmLevel::Critical => FindingLevel::Act,
    };
    let percent = format!("{}.{}", event.permille / 10, event.permille % 10);
    let threshold = match event.level {
        AlarmLevel::Critical => event.crit_pct,
        _ => event.warn_pct,
    };
    let mut params = BTreeMap::from([
        ("cidr".to_owned(), event.cidr.to_string()),
        ("level".to_owned(), event.level.as_str().to_owned()),
        ("percent".to_owned(), percent.clone()),
        ("used".to_owned(), event.used.to_string()),
        ("capacity".to_owned(), event.capacity.to_string()),
    ]);
    if let Some(threshold) = threshold {
        params.insert("threshold".to_owned(), threshold.to_string());
    }
    let mut subject = FindingSubject::new(SubjectKind::Prefix, event.cidr.to_string());
    subject.vrf = Some(event.vrf);
    subject.cidr = Some(event.cidr);
    subject.prefix = Some(event.prefix);
    subject.objects = vec![ObjectRef::from(event.prefix)];
    Some(Finding {
        id: finding_id(FindingSource::Alarm, &event.prefix.to_string()),
        kind: FindingKind::Utilization,
        severity,
        area: FindingArea::Ipam,
        subject,
        summary: format!(
            "{} is {percent} % in use, over its {} threshold",
            event.cidr,
            event.level.as_str()
        ),
        code: format!("{ALARM_CODE}.{}", event.level.as_str()),
        params,
        evidence: FindingEvidence {
            id: event.prefix.to_string(),
            path: format!("/prefixes/{}", event.prefix),
        },
        action: FindingAction::OpenPrefix,
        since: event.at,
        source: FindingSource::Alarm,
    })
}

/// The finding of a job that waits for a person at a manual step (a task, or the undo task
/// of a rollback); none for any other job.
pub fn of_job(job: &Job) -> Option<Finding> {
    let (step, task) = job.steps.iter().find_map(|record| match &record.state {
        StepState::WaitingForManual { task, .. } => Some((record, task)),
        _ => None,
    })?;
    let kind = job.spec.kind.as_str().to_owned();
    let mut subject = FindingSubject::new(SubjectKind::Job, kind.clone());
    subject.objects.clone_from(&job.spec.targets);
    let mut params = BTreeMap::from([
        ("job_kind".to_owned(), kind.clone()),
        ("title".to_owned(), job.spec.title.as_str().to_owned()),
        ("step".to_owned(), step.index.to_string()),
        ("step_kind".to_owned(), step.kind.as_str().to_owned()),
        (
            "instruction".to_owned(),
            task.instruction.as_str().to_owned(),
        ),
        ("count".to_owned(), job.spec.targets.len().to_string()),
    ]);
    params.extend(
        task.args
            .iter()
            .map(|(key, value)| (format!("task.{key}"), value.clone())),
    );
    Some(Finding {
        id: finding_id(FindingSource::Job, &job.id.to_string()),
        kind: FindingKind::JobWaiting,
        severity: FindingLevel::Act,
        area: FindingArea::Jobs,
        subject,
        summary: format!(
            "the job {kind} waits for a person at step {} ({})",
            step.index + 1,
            step.kind.as_str()
        ),
        code: kind,
        params,
        evidence: FindingEvidence {
            id: job.id.to_string(),
            path: format!("/jobs/{}", job.id),
        },
        action: FindingAction::OpenManualStep,
        since: step.started.unwrap_or(job.created.at),
        source: FindingSource::Job,
    })
}

/// A finding derived from the reconciliation view, and the address whose open conflict
/// proposal covers it (a conflict row is listed once, as the proposal, while one is open).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewFinding {
    pub finding: Finding,
    pub covered_by_conflict: Option<(VrfId, IpAddr)>,
}

fn row_subject(row: &ReconcileRow) -> FindingSubject {
    let mut subject = FindingSubject::new(SubjectKind::Address, row.address.to_string());
    subject.vrf = row.vrf;
    subject.ip = Some(row.address);
    subject.prefix = row.prefix;
    subject.host = row.host;
    subject.mac = (row.macs.len() == 1).then(|| row.macs[0]);
    if let Some(prefix) = row.prefix {
        subject.objects.push(ObjectRef::from(prefix));
    }
    if let Some(host) = row.host {
        subject.objects.push(ObjectRef::from(host));
    }
    if let Some(address) = row.intent.as_ref().and_then(|intent| intent.address) {
        subject.objects.push(ObjectRef::from(address));
    }
    subject
}

fn view_path(row_prefix: Option<tenko_core::PrefixId>, kind: &str) -> String {
    match row_prefix {
        Some(prefix) => format!("/ipam/reconcile?prefix={prefix}&kind={kind}"),
        None => format!("/ipam/reconcile?kind={kind}"),
    }
}

/// The finding of a row of the reconciliation view at `now`; none for a row an open
/// proposal stands for (a rogue's discovered host, an orphan's orphaned record). The view
/// has no severities, so they are given here:
///
/// - `conflict`: act, while no open conflict proposal of the address lists it;
/// - `rogue` without an open proposal (a person rejected it): information;
/// - `orphan` of a record written by hand, `ptr_mismatch`: review;
/// - `ghost`: information until it has been unseen for
///   [`FindingsConfig::ghost_review_after`], then review with the action
///   [`FindingAction::Decommission`]. `unseen_since` is its last sighting, or the creation of
///   its address when it was never seen.
#[allow(clippy::too_many_lines, reason = "one arm per kind of row")]
pub(crate) fn of_row(
    row: &ReconcileRow,
    unseen_since: Option<Timestamp>,
    now: Timestamp,
    config: &FindingsConfig,
) -> Option<ViewFinding> {
    let since = row.last_seen.unwrap_or(now);
    let mut subject = row_subject(row);
    let host_name = row
        .intent
        .as_ref()
        .and_then(|intent| intent.host_name.clone());
    let macs = row
        .macs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut params = BTreeMap::from([
        ("ip".to_owned(), row.address.to_string()),
        ("rule".to_owned(), row.rule_id_text().to_owned()),
    ]);
    if !macs.is_empty() {
        params.insert("macs".to_owned(), macs.clone());
    }
    if let Some(name) = &host_name {
        params.insert("host".to_owned(), name.clone());
    }
    let mut covered = None;
    let (kind, severity, action, summary, since) = match row.kind {
        ReconcileKind::Conflict => {
            covered = row.vrf.map(|vrf| (vrf, row.address));
            (
                FindingKind::Conflict,
                FindingLevel::Act,
                FindingAction::Resolve,
                format!(
                    "{} is used by {}",
                    row.address,
                    if macs.is_empty() {
                        "a device the DHCP role abandoned the address for"
                    } else {
                        &macs
                    }
                ),
                since,
            )
        }
        ReconcileKind::Rogue => {
            if row.proposal.is_some() {
                return None;
            }
            subject.kind = if subject.mac.is_some() {
                SubjectKind::Device
            } else {
                SubjectKind::Address
            };
            (
                FindingKind::UnknownDevice,
                FindingLevel::Info,
                FindingAction::None,
                format!(
                    "{} is used by a device no intent knows ({}); its proposal was decided",
                    row.address,
                    if macs.is_empty() {
                        "no MAC address"
                    } else {
                        &macs
                    }
                ),
                since,
            )
        }
        ReconcileKind::Orphan => {
            if row.proposal.is_some() {
                return None;
            }
            let names = row
                .dns
                .as_ref()
                .map(|dns| {
                    dns.forward
                        .iter()
                        .chain(dns.ptr.iter())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            subject.kind = SubjectKind::Record;
            if !names.is_empty() {
                subject.label.clone_from(&names);
                params.insert("names".to_owned(), names.clone());
            }
            (
                FindingKind::OrphanedRecord,
                FindingLevel::Review,
                FindingAction::DeleteRecord,
                format!(
                    "the DNS records {names} of {} were written by hand and no host holds the address",
                    row.address
                ),
                since,
            )
        }
        ReconcileKind::PtrMismatch => {
            let ptr = row
                .dns
                .as_ref()
                .map(|dns| dns.ptr.join(", "))
                .unwrap_or_default();
            params.insert("ptr".to_owned(), ptr.clone());
            (
                FindingKind::PtrMismatch,
                FindingLevel::Review,
                FindingAction::FixPtr,
                format!(
                    "the PTR record of {} names {ptr}, not the address's name",
                    row.address
                ),
                since,
            )
        }
        ReconcileKind::Ghost => {
            let unseen = unseen_since.unwrap_or(now);
            params.insert("unseen_since".to_owned(), unseen.to_rfc3339());
            let aged = now.saturating_since(unseen) >= config.ghost_review_after();
            if let Some(name) = &host_name {
                subject.kind = SubjectKind::Host;
                subject.label.clone_from(name);
            }
            let label = match &host_name {
                Some(name) => format!("{} ({name})", row.address),
                None => row.address.to_string(),
            };
            if aged {
                (
                    FindingKind::Ghost,
                    FindingLevel::Review,
                    if row.host.is_some() {
                        FindingAction::Decommission
                    } else {
                        FindingAction::OpenHost
                    },
                    format!(
                        "{label} has not been seen since {}; decommission the host if it is gone",
                        unseen.to_rfc3339()
                    ),
                    unseen,
                )
            } else {
                (
                    FindingKind::Ghost,
                    FindingLevel::Info,
                    FindingAction::None,
                    format!(
                        "{label} has not been seen since {}; {}",
                        unseen.to_rfc3339(),
                        row.rule
                    ),
                    unseen,
                )
            }
        }
    };
    Some(ViewFinding {
        finding: Finding {
            id: finding_id(FindingSource::Reconcile, &digest(&row.key)),
            kind,
            severity,
            area: match kind {
                FindingKind::OrphanedRecord | FindingKind::PtrMismatch => FindingArea::Dns,
                _ => FindingArea::Ipam,
            },
            subject,
            summary,
            code: format!("{VIEW_CODE}.{}", row.kind.as_str()),
            params,
            evidence: FindingEvidence {
                id: row.key.clone(),
                path: view_path(row.prefix, row.kind.as_str()),
            },
            action,
            since,
            source: FindingSource::Reconcile,
        },
        covered_by_conflict: covered,
    })
}

/// The finding of a scan artifact: information, never a conflict (the guard rail).
pub(crate) fn of_artifact(artifact: &ScanArtifact) -> Finding {
    let mut subject = FindingSubject::new(SubjectKind::Address, artifact.address.to_string());
    subject.vrf = Some(artifact.vrf);
    subject.ip = Some(artifact.address);
    subject.prefix = Some(artifact.prefix);
    subject.mac = (artifact.macs.len() == 1).then(|| artifact.macs[0]);
    subject.objects = vec![ObjectRef::from(artifact.prefix)];
    let macs = artifact
        .macs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let params = BTreeMap::from([
        ("ip".to_owned(), artifact.address.to_string()),
        ("edge".to_owned(), artifact.edge.as_str().to_owned()),
        ("macs".to_owned(), macs.clone()),
        ("sources".to_owned(), artifact.sources.join(", ")),
    ]);
    let key = format!("artifact/{}/{}", artifact.vrf, artifact.address);
    Finding {
        id: finding_id(FindingSource::Reconcile, &digest(&key)),
        kind: FindingKind::ScanArtifact,
        severity: FindingLevel::Info,
        area: FindingArea::Ipam,
        subject,
        summary: format!(
            "scan artifact on {} of its network: {} answered at {}, which no device holds",
            artifact.edge.text(),
            if macs.is_empty() { "a device" } else { &macs },
            artifact.address
        ),
        code: format!("{VIEW_CODE}.scan_artifact"),
        params,
        evidence: FindingEvidence {
            id: key,
            path: format!("/ipam/reconcile?prefix={}", artifact.prefix),
        },
        action: FindingAction::None,
        since: artifact.first_seen,
        source: FindingSource::Reconcile,
    }
}

/// A health condition as the status reports it, with the severity and area the caller
/// gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthItem {
    /// Stable code, such as `sys.tls.certificate_expiring`.
    pub code: String,
    /// English explanation.
    pub detail: String,
    /// Parameters of the explanation.
    pub params: BTreeMap<String, String>,
    /// The severity: an error is to act on, a warning to review, an informational state is
    /// information.
    pub level: FindingLevel,
}

impl HealthItem {
    /// The identifier of its finding: the code and its parameters, so two conditions of one
    /// code (two zones) are two findings and the same condition keeps its identifier.
    pub fn id(&self) -> String {
        let mut key = self.code.clone();
        for (name, value) in &self.params {
            key.push('\u{1f}');
            key.push_str(name);
            key.push('=');
            key.push_str(value);
        }
        finding_id(FindingSource::Health, &digest(&key))
    }
}

/// The finding of a health condition first seen at `since`.
pub fn of_health(item: &HealthItem, since: Timestamp) -> Finding {
    Finding {
        id: item.id(),
        kind: FindingKind::Health,
        severity: item.level,
        area: FindingArea::of_code(&item.code),
        subject: FindingSubject::new(SubjectKind::Node, item.code.clone()),
        summary: item.detail.clone(),
        code: item.code.clone(),
        params: item.params.clone(),
        evidence: FindingEvidence {
            id: item.code.clone(),
            path: "/system/status".to_owned(),
        },
        action: FindingAction::OpenStatus,
        since,
        source: FindingSource::Health,
    }
}

impl ReconcileRow {
    /// The `snake_case` name of the row's rule.
    fn rule_id_text(&self) -> &'static str {
        match self.rule_id {
            crate::reconcile::view::WinRule::IntentManaged => "intent_managed",
            crate::reconcile::view::WinRule::LeaseDynamic => "lease_dynamic",
            crate::reconcile::view::WinRule::NewestSighting => "newest_sighting",
            crate::reconcile::view::WinRule::NeverAutomatic => "never_automatic",
            crate::reconcile::view::WinRule::OrphanRule => "orphan_rule",
            crate::reconcile::view::WinRule::ManualRecord => "manual_record",
            crate::reconcile::view::WinRule::ForwardRecord => "forward_record",
        }
    }
}
