//! `tenko cluster upgrade-check` (OPS-08, OPS-24): before a rolling upgrade, run the new
//! binary with this command against the cluster. It lists every member's version,
//! protocol majors, Raft wire version and the data formats its binary knows, checks that
//! this binary can take a member's place, and prints the rolling order: learners, then the
//! followers one at a time, then `tenko cluster step-down` and the old leader.
//!
//! This binary can take a member's place when
//!
//! * it speaks the Raft wire version of every member (an openraft upgrade changes it and
//!   needs a planned full-cluster change, R19);
//! * it shares a protocol major with every member;
//! * it knows the format the cluster's data is in.
//!
//! A newer data format of this binary is not a problem: the cluster keeps the old format
//! until every voter runs a binary that knows the new one, and the leader migrates then
//! (`crate::upgrade::rolling`). Exit status 0 when this binary fits, 11 when it does not.

use std::fmt::Write as _;

use clap::Args;
use serde::Serialize;
use tenko_api::dto::system::{PendingMigration, SystemStatus};
use tenko_cluster::admin::{ClusterView, MemberRole};
use tenko_core::NodeId;

use crate::{
    client::{ClientOpts, Failure, Output, Target, table},
    exit,
};

/// Arguments of `tenko cluster upgrade-check`.
#[derive(Debug, Clone, Args)]
pub struct UpgradeCheckArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// What a binary brings to the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryInfo {
    /// The software version.
    pub version: String,
    /// The protocol majors it speaks with nodes.
    pub protocol_majors: Vec<u32>,
    /// The wire version of its Raft messages.
    pub raft_wire: String,
    /// The data formats it can open, oldest first.
    pub formats: Vec<u32>,
}

impl BinaryInfo {
    /// This binary.
    pub fn this() -> Self {
        Self {
            version: crate::version().to_owned(),
            protocol_majors: tenko_cluster::version::SUPPORTED_MAJORS.to_vec(),
            raft_wire: tenko_cluster::wire::RAFT_WIRE.to_owned(),
            formats: (crate::upgrade::migrations::INITIAL..=crate::upgrade::migrations::CURRENT)
                .collect(),
        }
    }
}

/// One member as the check sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberCheck {
    /// The node id.
    pub node: NodeId,
    /// Its name.
    pub name: Option<String>,
    /// `voter` or `learner`.
    pub role: &'static str,
    /// Whether it leads.
    pub leader: bool,
    /// The version it reported.
    pub version: Option<String>,
    /// Its protocol majors; empty when not reported.
    pub protocol_majors: Vec<u32>,
    /// Its Raft wire version, when reported.
    pub raft_wire: Option<String>,
    /// The data formats its binary knows; empty when not reported.
    pub formats: Vec<u32>,
    /// Why this binary cannot take its place, if it cannot.
    pub problems: Vec<String>,
}

/// The answer of `tenko cluster upgrade-check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpgradeReport {
    /// The binary that ran the check.
    pub binary: BinaryInfo,
    /// The format the cluster's data is in, when the controller reports it.
    pub stored_format: Option<u32>,
    /// A migration that waits for voters with older binaries.
    pub pending: Option<PendingMigration>,
    /// The members, in node order.
    pub members: Vec<MemberCheck>,
    /// The order to upgrade them in: learners, followers, the leader last.
    pub order: Vec<NodeId>,
    /// Problems of the whole cluster (the data format).
    pub problems: Vec<String>,
    /// Whether this binary can replace every member.
    pub compatible: bool,
}

/// Runs `tenko cluster upgrade-check`.
///
/// # Errors
///
/// The [`Failure`] of a request.
pub async fn run(args: &UpgradeCheckArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let client = target.client()?;
    let view: ClusterView = client.get("/cluster/members").await?;
    let status: SystemStatus = client.get("/system/status").await?;
    let report = evaluate(&view, &status, &BinaryInfo::this());
    let mut output = if target.json {
        Output::json(&report)
    } else {
        Output::text(render(&report))
    };
    if !report.compatible {
        output.status = exit::UPGRADE_REFUSED;
    }
    Ok(output)
}

/// Checks `binary` against the cluster.
pub fn evaluate(view: &ClusterView, status: &SystemStatus, binary: &BinaryInfo) -> UpgradeReport {
    let format = status.data_format.as_ref();
    let stored_format = format.map(|format| format.stored);
    let mut problems = Vec::new();
    if let Some(stored) = stored_format
        && !binary.formats.contains(&stored)
    {
        problems.push(format!(
            "the cluster's data is in format {stored}; this binary knows formats {}",
            formats_text(&binary.formats)
        ));
    }
    let members: Vec<MemberCheck> = view
        .members
        .iter()
        .map(|member| {
            let mut found = Vec::new();
            if let Some(wire) = &member.raft_wire
                && *wire != binary.raft_wire
            {
                found.push(format!(
                    "speaks the Raft wire {wire}, this binary {}: a change of the Raft wire \
                     needs a planned stop of the whole cluster",
                    binary.raft_wire
                ));
            }
            if !member.protocol_majors.is_empty()
                && !member
                    .protocol_majors
                    .iter()
                    .any(|major| binary.protocol_majors.contains(major))
            {
                found.push(format!(
                    "speaks protocol major(s) {}, this binary {}",
                    numbers(&member.protocol_majors),
                    numbers(&binary.protocol_majors)
                ));
            }
            MemberCheck {
                node: member.node,
                name: member.name.clone(),
                role: match member.role {
                    MemberRole::Voter => "voter",
                    MemberRole::Learner => "learner",
                },
                leader: member.leader,
                version: member.version.clone(),
                protocol_majors: member.protocol_majors.clone(),
                raft_wire: member.raft_wire.clone(),
                formats: member.formats.clone(),
                problems: found,
            }
        })
        .collect();
    let compatible = problems.is_empty() && members.iter().all(|member| member.problems.is_empty());
    UpgradeReport {
        binary: binary.clone(),
        stored_format,
        pending: format.and_then(|format| format.pending.clone()),
        order: order(view),
        members,
        problems,
        compatible,
    }
}

/// The rolling order: learners, then the voters that follow, then the leader.
fn order(view: &ClusterView) -> Vec<NodeId> {
    let rank = |member: &tenko_cluster::admin::MemberView| match (member.role, member.leader) {
        (MemberRole::Learner, _) => 0,
        (MemberRole::Voter, false) => 1,
        (MemberRole::Voter, true) => 2,
    };
    let mut members: Vec<_> = view.members.iter().collect();
    members.sort_by_key(|member| (rank(member), member.node));
    members.into_iter().map(|member| member.node).collect()
}

fn numbers(values: &[u32]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `1 to 3`, `2`, or `1, 3`.
fn formats_text(formats: &[u32]) -> String {
    match formats {
        [] => "-".to_owned(),
        [one] => one.to_string(),
        [first, .., last] if formats.windows(2).all(|pair| pair[1] == pair[0] + 1) => {
            format!("{first} to {last}")
        }
        _ => numbers(formats),
    }
}

fn or_dash(text: Option<&str>) -> String {
    text.map_or_else(|| "-".to_owned(), str::to_owned)
}

/// The report as text.
pub fn render(report: &UpgradeReport) -> String {
    let rows: Vec<Vec<String>> = report
        .members
        .iter()
        .map(|member| {
            vec![
                member.node.to_string(),
                or_dash(member.name.as_deref()),
                if member.leader {
                    format!("{} (leader)", member.role)
                } else {
                    member.role.to_owned()
                },
                or_dash(member.version.as_deref()),
                if member.protocol_majors.is_empty() {
                    "-".to_owned()
                } else {
                    numbers(&member.protocol_majors)
                },
                or_dash(member.raft_wire.as_deref()),
                formats_text(&member.formats),
                if member.problems.is_empty() {
                    "ok".to_owned()
                } else {
                    "REFUSED".to_owned()
                },
            ]
        })
        .collect();
    let mut text = table(
        &[
            "NODE",
            "NAME",
            "ROLE",
            "VERSION",
            "MAJORS",
            "RAFT WIRE",
            "FORMATS",
            "THIS BINARY",
        ],
        &rows,
    );
    let binary = &report.binary;
    let _ = writeln!(
        text,
        "\nthis binary: version {}, protocol major(s) {}, Raft wire {}, formats {}",
        binary.version,
        numbers(&binary.protocol_majors),
        binary.raft_wire,
        formats_text(&binary.formats)
    );
    match report.stored_format {
        Some(stored) => {
            let _ = writeln!(text, "the cluster's data is in format {stored}");
        }
        None => text.push_str("the controller does not report the data format\n"),
    }
    if let Some(pending) = &report.pending {
        if pending.blocked_by.is_empty() {
            let _ = writeln!(
                text,
                "the leader is migrating the data to format {}",
                pending.target
            );
        } else {
            let _ = writeln!(
                text,
                "the migration to format {} waits for controller(s) {}",
                pending.target,
                pending
                    .blocked_by
                    .iter()
                    .map(|blocker| blocker.node.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if report
        .members
        .iter()
        .any(|member| member.formats.is_empty())
    {
        text.push_str(
            "a member without majors, wire or formats has not reported them since it joined; \
             it does after its next start\n",
        );
    }
    render_verdict(report, &mut text);
    text
}

/// The problems, or the rolling order when there are none.
fn render_verdict(report: &UpgradeReport, text: &mut String) {
    let problems: Vec<String> = report
        .problems
        .iter()
        .cloned()
        .chain(report.members.iter().flat_map(|member| {
            member
                .problems
                .iter()
                .map(move |problem| format!("node {}: {problem}", member.node))
        }))
        .collect();
    if problems.is_empty() {
        text.push_str("\nthis binary can replace every member. Rolling order, one at a time:\n");
        for (index, node) in report.order.iter().enumerate() {
            let leader = report
                .members
                .iter()
                .any(|member| member.node == *node && member.leader);
            if leader {
                let _ = writeln!(
                    text,
                    "  {}. node {node} (the leader): run `tenko cluster step-down` first, then \
                     upgrade it",
                    index + 1
                );
            } else {
                let _ = writeln!(text, "  {}. node {node}", index + 1);
            }
        }
        text.push_str(
            "wait for each member to be ready and caught up (`tenko cluster members`) before \
             the next one\n",
        );
    } else {
        text.push_str("\nthis binary cannot replace every member:\n");
        for problem in problems {
            let _ = writeln!(text, "  - {problem}");
        }
    }
}

#[cfg(test)]
mod tests {
    use tenko_api::dto::system::{DataFormatStatus, FormatBlocker};
    use tenko_cluster::admin::{MemberView, QuorumKind, QuorumView};

    use super::*;

    fn member(node: u64, role: MemberRole, leader: bool, version: &str) -> MemberView {
        MemberView {
            node: NodeId(node),
            name: Some(format!("controller-{node}")),
            address: Some(format!("controller-{node}.example.test:8444")),
            role,
            leader,
            matched: Some(10),
            lag_entries: Some(0),
            last_contact_ms: Some(20),
            version: Some(version.to_owned()),
            data_format: Some(2),
            joined_at: None,
            protocol_majors: vec![1],
            raft_wire: Some("openraft-0.9/cbor-1".to_owned()),
            formats: vec![1, 2],
        }
    }

    fn view(members: Vec<MemberView>) -> ClusterView {
        ClusterView {
            node: NodeId(1),
            leader: Some(NodeId(1)),
            term: 3,
            quorum: QuorumView {
                state: QuorumKind::Healthy,
                since: None,
                last_contact: None,
                applied: None,
            },
            changing: false,
            members,
            job_id: None,
        }
    }

    fn status(stored: u32, pending: Option<PendingMigration>) -> SystemStatus {
        let mut status: SystemStatus = serde_json::from_value(serde_json::json!({
            "version": "0.1.0",
            "started_at": "2026-10-12T08:00:00Z",
            "uptime_seconds": 1,
            "node": { "id": 1, "roles": ["controller"] },
            "store": {
                "role": "leader", "leader": 1, "revision": 1, "lag": null,
                "audit_head": 0, "journal_oldest": null, "journal_len": 0,
                "data_bytes": 0, "disk_bytes": null
            },
            "tls": null,
            "ui": { "stub": false, "from_directory": false },
            "warnings": []
        }))
        .expect("status");
        status.data_format = Some(DataFormatStatus {
            stored,
            binary: 2,
            pending,
        });
        status
    }

    fn binary(formats: Vec<u32>, wire: &str) -> BinaryInfo {
        BinaryInfo {
            version: "0.2.0".to_owned(),
            protocol_majors: vec![1],
            raft_wire: wire.to_owned(),
            formats,
        }
    }

    fn three() -> ClusterView {
        view(vec![
            member(1, MemberRole::Voter, true, "0.1.0"),
            member(1001, MemberRole::Voter, false, "0.1.0"),
            member(1002, MemberRole::Voter, false, "0.1.0"),
            member(1003, MemberRole::Learner, false, "0.1.0"),
        ])
    }

    #[test]
    fn a_newer_binary_fits_and_the_leader_goes_last() {
        let report = evaluate(
            &three(),
            &status(2, None),
            &binary(vec![1, 2, 3], "openraft-0.9/cbor-1"),
        );
        assert!(report.compatible, "{report:?}");
        assert_eq!(
            report.order,
            vec![NodeId(1003), NodeId(1001), NodeId(1002), NodeId(1)]
        );
        let text = render(&report);
        assert!(text.contains("4. node 1 (the leader): run `tenko cluster step-down` first"));
        assert!(text.contains("formats 1 to 3"), "{text}");
        assert!(text.contains("the cluster's data is in format 2"), "{text}");
    }

    #[test]
    fn a_binary_that_does_not_know_the_data_is_refused() {
        let report = evaluate(
            &three(),
            &status(3, None),
            &binary(vec![1, 2], "openraft-0.9/cbor-1"),
        );
        assert!(!report.compatible);
        assert_eq!(report.problems.len(), 1);
        assert!(render(&report).contains("cannot replace every member"));
    }

    #[test]
    fn another_raft_wire_or_major_is_refused_per_member() {
        let mut members = three();
        members.members[1].protocol_majors = vec![2];
        let report = evaluate(
            &members,
            &status(2, None),
            &binary(vec![1, 2], "openraft-0.10/cbor-1"),
        );
        assert!(!report.compatible);
        assert_eq!(report.members[0].problems.len(), 1);
        assert_eq!(report.members[1].problems.len(), 2);
        let text = render(&report);
        assert!(
            text.contains("node 1001: speaks protocol major(s) 2"),
            "{text}"
        );
        assert!(text.contains("REFUSED"));
    }

    #[test]
    fn unreported_members_and_a_blocked_migration_are_explained() {
        let mut members = three();
        members.members[2].protocol_majors.clear();
        members.members[2].raft_wire = None;
        members.members[2].formats.clear();
        let pending = PendingMigration {
            target: 3,
            blocked_by: vec![FormatBlocker {
                node: NodeId(1002),
                version: Some("0.1.0".to_owned()),
                data_format: Some(2),
            }],
        };
        let report = evaluate(
            &members,
            &status(2, Some(pending)),
            &binary(vec![1, 2, 3], "openraft-0.9/cbor-1"),
        );
        assert!(report.compatible);
        let text = render(&report);
        assert!(text.contains("waits for controller(s) 1002"), "{text}");
        assert!(
            text.contains("has not reported them since it joined"),
            "{text}"
        );
        let json = serde_json::to_value(&report).expect("json");
        assert_eq!(json["pending"]["target"], 3);
        assert_eq!(json["order"][3], 1);
    }

    #[test]
    fn formats_read_as_ranges() {
        assert_eq!(formats_text(&[]), "-");
        assert_eq!(formats_text(&[2]), "2");
        assert_eq!(formats_text(&[1, 2, 3]), "1 to 3");
        assert_eq!(formats_text(&[1, 3]), "1, 3");
    }

    #[test]
    fn this_binary_reports_its_own_details() {
        let this = BinaryInfo::this();
        assert_eq!(this.raft_wire, "openraft-0.9/cbor-1");
        assert_eq!(
            this.formats.last().copied(),
            Some(crate::upgrade::migrations::CURRENT)
        );
        assert!(this.protocol_majors.contains(&1));
    }
}
