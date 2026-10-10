//! `tenko cluster status|members|promote|remove|step-down|verify`: the client commands of
//! the controller cluster (OPS-03). Each one calls an endpoint of `/cluster/*` with the
//! stored token and prints the answer; `--json` prints the document of the API instead.
//!
//! | Command | Endpoint | Output |
//! |---|---|---|
//! | `status` | `GET /cluster/members` | this controller, the leader, the term, the quorum state and the member count |
//! | `members` | `GET /cluster/members` | one row per member with its role and replication state |
//! | `promote <ID>` | `POST /cluster/members/{id}/promote` | the members after the change |
//! | `remove <ID> --yes` | `DELETE /cluster/members/{id}` | the members after the change |
//! | `step-down` | `POST /cluster/step-down` | who led and who leads now |
//! | `verify` | `GET /cluster/digests` | one row per member with its digest; exit status 9 when they differ |

use std::fmt::Write as _;

use clap::Args;
use serde::Serialize;
use tenko_cluster::admin::{
    ClusterView, DigestReport, MemberRole, MemberView, PromoteRequest, QuorumKind, StepDown,
};
use tenko_core::NodeId;

use crate::{
    client::{ClientOpts, Failure, Output, Target, table},
    exit,
};

/// Arguments of `tenko cluster status`.
#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of `tenko cluster members`.
#[derive(Debug, Clone, Args)]
pub struct MembersArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of `tenko cluster promote`.
#[derive(Debug, Clone, Args)]
pub struct PromoteArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The node id of the learner to promote.
    #[arg(value_name = "ID", value_parser = node_id)]
    pub id: u64,
    /// Promote although the result has an even number of voters or the learner has not
    /// caught up.
    #[arg(long)]
    pub force: bool,
    /// A voter to remove in the same change: replaces a dead voter without passing through
    /// an even number of voters.
    #[arg(long, value_name = "ID", value_parser = node_id)]
    pub replace: Option<u64>,
}

/// Arguments of `tenko cluster remove`.
#[derive(Debug, Clone, Args)]
pub struct RemoveArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The node id of the member to remove.
    #[arg(value_name = "ID", value_parser = node_id)]
    pub id: u64,
    /// Confirm the removal: the member leaves the cluster and its certificates are revoked.
    #[arg(long)]
    pub yes: bool,
}

/// Arguments of `tenko cluster step-down`.
#[derive(Debug, Clone, Args)]
pub struct StepDownArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Arguments of `tenko cluster verify`.
#[derive(Debug, Clone, Args)]
pub struct VerifyArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
    /// The revision to compare the members at; the newest one the controller applied when
    /// absent.
    #[arg(long, value_name = "N")]
    pub revision: Option<u64>,
}

/// A node id on the command line: a positive number.
fn node_id(raw: &str) -> Result<u64, String> {
    raw.trim()
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| format!("`{raw}` is not a node id (a positive number)"))
}

/// Runs `tenko cluster status`.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn status(args: &StatusArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let view = fetch_view(&target).await?;
    Ok(if target.json {
        Output::json(&view)
    } else {
        Output::text(render_status(&view))
    })
}

/// Runs `tenko cluster members`.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn members(args: &MembersArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let view = fetch_view(&target).await?;
    Ok(if target.json {
        Output::json(&view)
    } else {
        Output::text(render_members(&view))
    })
}

/// Runs `tenko cluster promote`.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn promote(args: &PromoteArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let request = PromoteRequest {
        force: args.force,
        replace: args.replace.map(NodeId),
    };
    let view: ClusterView = target
        .client()?
        .post(
            &format!("/cluster/members/{}/promote", args.id),
            &request,
            None,
        )
        .await?;
    let output = if target.json {
        Output::json(&view)
    } else {
        Output::text(render_members(&view))
    };
    Ok(output.note(format!("promoted node {} to a voter", args.id)))
}

/// Runs `tenko cluster remove`.
///
/// The API answers a removal with the cluster after the change, which the typed client
/// does not hand over for `DELETE`, so the command reads the members once more.
///
/// # Errors
///
/// A usage failure without `--yes`, or the [`Failure`] of the request.
pub async fn remove(args: &RemoveArgs) -> Result<Output, Failure> {
    confirm_removal(args)?;
    let target = Target::resolve(&args.client, true)?;
    let client = target.client()?;
    client
        .delete(&format!("/cluster/members/{}", args.id), None)
        .await?;
    let note = format!("removed node {} and revoked its certificates", args.id);
    match fetch_view(&target).await {
        Ok(view) if target.json => Ok(Output::json(&view).note(note)),
        Ok(view) => Ok(Output::text(render_members(&view)).note(note)),
        // The change is done; only the picture afterwards is missing (the controller that
        // answered may be the one that left).
        Err(failure) => {
            let text = format!("removed node {}\n", args.id);
            Ok(Output::text(text).note(format!(
                "the members after the change are not available: {}",
                failure.message
            )))
        }
    }
}

/// Refuses a removal that was not confirmed, and says what it does.
fn confirm_removal(args: &RemoveArgs) -> Result<(), Failure> {
    if args.yes {
        return Ok(());
    }
    Err(Failure::new(
        exit::USAGE,
        format!(
            "removing node {id} takes it out of the controller cluster and revokes its \
             certificates, so it can only come back with a new enrolment; nothing was \
             changed. Run `tenko cluster remove {id} --yes` to remove it",
            id = args.id
        ),
    ))
}

/// Runs `tenko cluster step-down`.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn step_down(args: &StepDownArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let moved: StepDown = target
        .client()?
        .post("/cluster/step-down", &serde_json::json!({}), None)
        .await?;
    Ok(if target.json {
        Output::json(&moved)
    } else {
        Output::text(render_step_down(&moved))
    })
}

/// The query of `GET /cluster/digests`.
#[derive(Serialize)]
struct DigestQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<u64>,
}

/// Runs `tenko cluster verify`: exit status 9 when the members do not agree.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn verify(args: &VerifyArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let query = DigestQuery {
        revision: args.revision,
    };
    let report: DigestReport = target
        .client()?
        .get_query("/cluster/digests", &query)
        .await?;
    let mut output = if target.json {
        Output::json(&report)
    } else {
        Output::text(render_verify(&report))
    };
    if !report.agree {
        output.status = exit::INTEGRITY;
    }
    Ok(output)
}

async fn fetch_view(target: &Target) -> Result<ClusterView, Failure> {
    Ok(target.client()?.get("/cluster/members").await?)
}

/// `1 voter`, `2 voters`.
fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn role_name(role: MemberRole) -> &'static str {
    match role {
        MemberRole::Voter => "voter",
        MemberRole::Learner => "learner",
    }
}

/// A number or text that may be unknown.
fn known(value: Option<impl ToString>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// Lines of `key  value` with the values in one column.
fn key_values(lines: &[(&str, String)]) -> String {
    let width = lines
        .iter()
        .map(|(key, _)| key.len())
        .max()
        .unwrap_or_default();
    let mut out = String::new();
    for (key, value) in lines {
        let _ = writeln!(out, "{key:<width$}  {value}");
    }
    out
}

/// The text of `tenko cluster status`.
fn render_status(view: &ClusterView) -> String {
    let voters = view
        .members
        .iter()
        .filter(|member| member.role == MemberRole::Voter)
        .count();
    let learners = view.members.len() - voters;
    let leader = match view.leader {
        Some(leader) if leader == view.node => format!("{leader} (this controller)"),
        Some(leader) => leader.to_string(),
        None => "none known".to_owned(),
    };
    let since = |what: &str| match view.quorum.since {
        Some(since) => format!("{what} since {since}"),
        None => what.to_owned(),
    };
    let quorum = match view.quorum.state {
        QuorumKind::Single => "single (the only voter)".to_owned(),
        QuorumKind::Healthy => "healthy".to_owned(),
        QuorumKind::Electing => since("electing"),
        QuorumKind::Isolated => since("isolated"),
    };
    let mut lines = vec![
        ("controller", view.node.to_string()),
        ("leader", leader),
        ("term", view.term.to_string()),
        ("quorum", quorum),
    ];
    if view.quorum.state == QuorumKind::Isolated {
        lines.push((
            "last contact",
            view.quorum
                .last_contact
                .map_or_else(|| "never".to_owned(), |at| at.to_string()),
        ));
        if let Some(applied) = view.quorum.applied {
            lines.push(("applied", format!("revision {applied}")));
        }
    }
    if view.changing {
        lines.push(("change", "a membership change is in progress".to_owned()));
    }
    lines.push((
        "members",
        format!(
            "{} ({}, {})",
            view.members.len(),
            counted(voters, "voter"),
            counted(learners, "learner")
        ),
    ));
    key_values(&lines)
}

/// One row of the members table.
fn member_row(member: &MemberView) -> Vec<String> {
    vec![
        member.node.to_string(),
        known(member.name.as_deref()),
        role_name(member.role).to_owned(),
        if member.leader { "*" } else { "" }.to_owned(),
        known(member.address.as_deref()),
        known(member.matched),
        known(member.lag_entries),
        known(member.last_contact_ms),
        known(member.version.as_deref()),
    ]
}

/// The members table of `tenko cluster members`, `promote` and `remove`.
fn render_members(view: &ClusterView) -> String {
    let rows: Vec<Vec<String>> = view.members.iter().map(member_row).collect();
    table(
        &[
            "NODE",
            "NAME",
            "ROLE",
            "LEADER",
            "ADDRESS",
            "MATCHED",
            "LAG",
            "CONTACT (MS)",
            "VERSION",
        ],
        &rows,
    )
}

/// The text of `tenko cluster step-down`.
fn render_step_down(moved: &StepDown) -> String {
    format!(
        "leadership moved from node {} to node {} (term {})\n",
        moved.previous, moved.leader, moved.term
    )
}

/// The text of `tenko cluster verify`: one row per member, then the result.
fn render_verify(report: &DigestReport) -> String {
    let rows: Vec<Vec<String>> = report
        .members
        .iter()
        .map(|member| {
            vec![
                member.node.to_string(),
                known(member.revision),
                member.sha256.as_deref().map_or_else(
                    || "-".to_owned(),
                    |digest| digest.chars().take(16).collect(),
                ),
                member.error.clone().unwrap_or_default(),
            ]
        })
        .collect();
    let mut out = table(&["NODE", "REVISION", "DIGEST", "ERROR"], &rows);
    let result = if report.agree {
        format!(
            "the {} agree at revision {}",
            counted(report.members.len(), "member"),
            report.revision
        )
    } else {
        format!(
            "the members DISAGREE at revision {}: compare the digests above",
            report.revision
        )
    };
    let _ = writeln!(out, "result: {result}");
    out
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use tenko_cluster::admin::{MemberDigest, QuorumView};
    use tenko_core::{Revision, Timestamp};

    use super::*;

    #[derive(Debug, Parser)]
    struct Promote {
        #[command(flatten)]
        args: PromoteArgs,
    }

    #[derive(Debug, Parser)]
    struct Remove {
        #[command(flatten)]
        args: RemoveArgs,
    }

    #[derive(Debug, Parser)]
    struct Verify {
        #[command(flatten)]
        args: VerifyArgs,
    }

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    fn member(node: u64, name: &str, role: MemberRole, leader: bool) -> MemberView {
        MemberView {
            node: NodeId(node),
            name: Some(name.to_owned()),
            address: Some(format!("{name}.example.test:8444")),
            role,
            leader,
            matched: Some(120),
            lag_entries: Some(0),
            last_contact_ms: Some(40),
            version: Some("0.0.1".to_owned()),
            data_format: Some(3),
            joined_at: Some(at("2026-10-10T08:00:00Z")),
        }
    }

    fn view() -> ClusterView {
        let mut learner = member(1002, "controller-3", MemberRole::Learner, false);
        learner.lag_entries = Some(57);
        learner.matched = Some(63);
        learner.last_contact_ms = None;
        learner.version = None;
        ClusterView {
            node: NodeId(1001),
            leader: Some(NodeId(1)),
            term: 3,
            quorum: QuorumView {
                state: QuorumKind::Healthy,
                since: None,
                last_contact: None,
                applied: None,
            },
            changing: false,
            members: vec![
                member(1, "controller-1", MemberRole::Voter, true),
                member(1001, "controller-2", MemberRole::Voter, false),
                learner,
            ],
            job_id: None,
        }
    }

    fn digest(node: u64, sha256: Option<&str>, error: Option<&str>) -> MemberDigest {
        MemberDigest {
            node: NodeId(node),
            revision: sha256.map(|_| Revision(42)),
            sha256: sha256.map(str::to_owned),
            tables: sha256.map(|_| 31),
            entries: sha256.map(|_| 900),
            error: error.map(str::to_owned),
        }
    }

    const SAME: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn status_shows_the_controller_the_leader_and_the_member_counts() {
        assert_eq!(
            render_status(&view()),
            "controller  1001\n\
             leader      1\n\
             term        3\n\
             quorum      healthy\n\
             members     3 (2 voters, 1 learner)\n"
        );
    }

    #[test]
    fn status_marks_this_controller_as_the_leader() {
        let mut view = view();
        view.node = NodeId(1);
        let text = render_status(&view);
        assert!(text.contains("leader      1 (this controller)\n"), "{text}");
    }

    #[test]
    fn status_of_a_single_controller() {
        let view = ClusterView {
            node: NodeId(1),
            leader: Some(NodeId(1)),
            term: 1,
            quorum: QuorumView {
                state: QuorumKind::Single,
                since: None,
                last_contact: None,
                applied: None,
            },
            changing: false,
            members: vec![member(1, "controller-1", MemberRole::Voter, true)],
            job_id: None,
        };
        assert_eq!(
            render_status(&view),
            "controller  1\n\
             leader      1 (this controller)\n\
             term        1\n\
             quorum      single (the only voter)\n\
             members     1 (1 voter, 0 learners)\n"
        );
    }

    #[test]
    fn status_says_since_when_the_controller_elects_or_is_isolated() {
        let mut electing = view();
        electing.leader = None;
        electing.quorum = QuorumView {
            state: QuorumKind::Electing,
            since: Some(at("2026-10-10T08:05:00Z")),
            last_contact: None,
            applied: None,
        };
        let text = render_status(&electing);
        assert!(text.contains("leader      none known\n"), "{text}");
        assert!(
            text.contains("quorum      electing since 2026-10-10T08:05:00Z\n"),
            "{text}"
        );

        let mut isolated = view();
        isolated.changing = true;
        isolated.quorum = QuorumView {
            state: QuorumKind::Isolated,
            since: Some(at("2026-10-10T08:10:00Z")),
            last_contact: Some(at("2026-10-10T08:09:30Z")),
            applied: Some(Revision(77)),
        };
        assert_eq!(
            render_status(&isolated),
            "controller    1001\n\
             leader        1\n\
             term          3\n\
             quorum        isolated since 2026-10-10T08:10:00Z\n\
             last contact  2026-10-10T08:09:30Z\n\
             applied       revision 77\n\
             change        a membership change is in progress\n\
             members       3 (2 voters, 1 learner)\n"
        );
    }

    #[test]
    fn members_render_as_a_table_with_the_leader_marked() {
        assert_eq!(
            render_members(&view()),
            "NODE  NAME          ROLE     LEADER  ADDRESS                         MATCHED  LAG  CONTACT (MS)  VERSION\n\
             1     controller-1  voter    *       controller-1.example.test:8444  120      0    40            0.0.1\n\
             1001  controller-2  voter            controller-2.example.test:8444  120      0    40            0.0.1\n\
             1002  controller-3  learner          controller-3.example.test:8444  63       57   -             -\n"
        );
    }

    #[test]
    fn members_without_figures_show_dashes() {
        let mut view = view();
        view.members = vec![MemberView {
            node: NodeId(1001),
            name: None,
            address: None,
            role: MemberRole::Voter,
            leader: false,
            matched: None,
            lag_entries: None,
            last_contact_ms: None,
            version: None,
            data_format: None,
            joined_at: None,
        }];
        let text = render_members(&view);
        let row = text.lines().nth(1).expect("row");
        assert_eq!(
            row.split_whitespace().collect::<Vec<_>>(),
            ["1001", "-", "voter", "-", "-", "-", "-", "-"]
        );
    }

    #[test]
    fn step_down_says_who_leads_now() {
        let moved = StepDown {
            previous: NodeId(1),
            leader: NodeId(1001),
            term: 4,
        };
        assert_eq!(
            render_step_down(&moved),
            "leadership moved from node 1 to node 1001 (term 4)\n"
        );
    }

    #[test]
    fn verify_prints_one_line_per_member_and_the_result() {
        let report = DigestReport {
            revision: Revision(42),
            agree: true,
            members: vec![
                digest(1, Some(SAME), None),
                digest(1001, Some(SAME), None),
                digest(1002, Some(SAME), None),
            ],
        };
        assert_eq!(
            render_verify(&report),
            "NODE  REVISION  DIGEST            ERROR\n\
             1     42        0123456789abcdef\n\
             1001  42        0123456789abcdef\n\
             1002  42        0123456789abcdef\n\
             result: the 3 members agree at revision 42\n"
        );
    }

    #[test]
    fn verify_shows_a_difference_and_a_member_that_did_not_answer() {
        let other = "fedcba9876543210".repeat(4);
        let report = DigestReport {
            revision: Revision(42),
            agree: false,
            members: vec![
                digest(1, Some(SAME), None),
                digest(1001, Some(&other), None),
                digest(1002, None, Some("cluster.member.starting")),
            ],
        };
        let text = render_verify(&report);
        assert!(
            text.contains("1001  42        fedcba9876543210\n"),
            "{text}"
        );
        assert!(
            text.contains("1002  -         -                 cluster.member.starting\n"),
            "{text}"
        );
        assert!(
            text.ends_with(
                "result: the members DISAGREE at revision 42: compare the digests above\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_removal_needs_confirmation_and_says_what_it_does() {
        let args = RemoveArgs {
            client: ClientOpts::default(),
            id: 1002,
            yes: false,
        };
        let failure = confirm_removal(&args).expect_err("refused");
        assert_eq!(failure.status, exit::USAGE);
        assert!(failure.message.contains("revokes its certificates"));
        assert!(failure.message.contains("tenko cluster remove 1002 --yes"));
        assert!(confirm_removal(&RemoveArgs { yes: true, ..args }).is_ok());
    }

    #[test]
    fn node_ids_are_positive_numbers() {
        assert_eq!(node_id("1002"), Ok(1002));
        assert!(node_id("0").is_err());
        assert!(node_id("-1").is_err());
        assert!(node_id("one").is_err());
        assert!(node_id("").is_err());
    }

    #[test]
    fn arguments_parse() {
        let parsed =
            Promote::try_parse_from(["t", "1002", "--force", "--replace", "1"]).expect("promote");
        assert_eq!(parsed.args.id, 1002);
        assert!(parsed.args.force);
        assert_eq!(parsed.args.replace, Some(1));
        let plain = Promote::try_parse_from(["t", "1002"]).expect("promote");
        assert!(!plain.args.force);
        assert_eq!(plain.args.replace, None);
        assert!(Promote::try_parse_from(["t", "0"]).is_err());
        assert!(Promote::try_parse_from(["t", "1002", "--replace", "x"]).is_err());
        assert!(Promote::try_parse_from(["t"]).is_err());

        assert!(!Remove::try_parse_from(["t", "7"]).expect("remove").args.yes);
        assert!(
            Remove::try_parse_from(["t", "7", "--yes"])
                .expect("remove")
                .args
                .yes
        );
        assert!(Remove::try_parse_from(["t", "--yes"]).is_err());

        assert_eq!(
            Verify::try_parse_from(["t", "--revision", "9"])
                .expect("verify")
                .args
                .revision,
            Some(9)
        );
        assert_eq!(
            Verify::try_parse_from(["t"]).expect("verify").args.revision,
            None
        );
        assert!(Verify::try_parse_from(["t", "--revision", "x"]).is_err());
    }

    #[test]
    fn the_digest_query_leaves_out_an_absent_revision() {
        assert_eq!(
            serde_json::to_value(DigestQuery { revision: None }).expect("json"),
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::to_value(DigestQuery { revision: Some(7) }).expect("json"),
            serde_json::json!({ "revision": 7 })
        );
    }
}
