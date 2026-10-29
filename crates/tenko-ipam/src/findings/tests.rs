//! Tests of the findings model: the mapping per source and severity, the ghost ageing, the
//! counts per area, the conflict listed once, and the cost of the counts.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use tenko_core::{
    JobId, MessageKey, PrefixId, Principal, ProposalId, Revision, SystemComponent, Timestamp,
    VrfId, audit::Digest, ipam::Stamp,
};
use tenko_jobs::{
    MANUAL,
    model::{Job, JobState, ManualTask, StepRecord, StepState},
    testing,
};

use super::{
    map::{self, HealthItem},
    *,
};
use crate::{
    alarm::{AlarmEvent, AlarmLevel},
    proposals::model::{
        IntentProposal, IntentProposalKind, IntentProposalState, ProposalSeverity, ProposalSubject,
    },
    reconcile::{
        rule,
        view::{IntentTruth, ReconcileKind, ReconcileRow, WinRule},
    },
};

fn at(text: &str) -> Timestamp {
    text.parse().expect("time")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn proposal(kind: IntentProposalKind, rule: &str) -> IntentProposal {
    let created = at("2026-10-26T08:00:00Z");
    IntentProposal {
        id: ProposalId::generate(),
        kind,
        rule: rule.to_owned(),
        key: format!("{}/x", kind.as_str()),
        subject: ProposalSubject {
            ip: Some(ip("192.0.2.10")),
            vrf: Some(VrfId::generate()),
            ..ProposalSubject::default()
        },
        severity: ProposalSeverity::Info,
        state: IntentProposalState::Open,
        summary: "summary".to_owned(),
        params: BTreeMap::new(),
        evidence: Vec::new(),
        commands: Vec::new(),
        choices: Vec::new(),
        fingerprint: Digest([0; 32]),
        created,
        updated: created,
        decided: None,
        reason: None,
        adopted_by: None,
        results: Vec::new(),
        superseded_by: None,
        adoption_error: None,
        revision: Revision::ZERO,
    }
}

/// IPAM-15, IPAM-23: every open proposal as a finding.
#[test]
fn every_open_proposal_is_a_finding_to_act_on_or_review_in_discovery() {
    let cases = [
        (
            IntentProposalKind::Conflict,
            rule::CONFLICT_SHARED_ADDRESS,
            FindingKind::Conflict,
            FindingLevel::Act,
            FindingAction::Resolve,
        ),
        (
            IntentProposalKind::Conflict,
            rule::DNS_RECORD_HELD,
            FindingKind::Conflict,
            FindingLevel::Act,
            FindingAction::Resolve,
        ),
        (
            IntentProposalKind::DiscoveredHost,
            rule::DISCOVERED_MAC,
            FindingKind::UnknownDevice,
            FindingLevel::Review,
            FindingAction::Adopt,
        ),
        (
            IntentProposalKind::OrphanedIntent,
            rule::DNS_ORPHANED_RECORD,
            FindingKind::OrphanedRecord,
            FindingLevel::Review,
            FindingAction::DeleteRecord,
        ),
        (
            IntentProposalKind::OrphanedIntent,
            rule::ORPHANED_ADDRESS,
            FindingKind::OrphanedAddress,
            FindingLevel::Review,
            FindingAction::Decide,
        ),
        (
            IntentProposalKind::OrphanedIntent,
            rule::DNS_NO_ZONE,
            FindingKind::Dns,
            FindingLevel::Review,
            FindingAction::Decide,
        ),
        (
            IntentProposalKind::AddressMismatch,
            rule::ADDRESS_MISMATCH,
            FindingKind::IntentDiffers,
            FindingLevel::Review,
            FindingAction::OpenHost,
        ),
        (
            IntentProposalKind::OutsidePrefixes,
            rule::OUTSIDE_PREFIXES,
            FindingKind::OutsidePrefixes,
            FindingLevel::Review,
            FindingAction::Decide,
        ),
        (
            IntentProposalKind::VlanDiscovered,
            rule::VLAN_DISCOVERED,
            FindingKind::Vlan,
            FindingLevel::Review,
            FindingAction::Decide,
        ),
        (
            IntentProposalKind::PrefixVlanMismatch,
            rule::PREFIX_VLAN_DIFFERS,
            FindingKind::Vlan,
            FindingLevel::Review,
            FindingAction::Decide,
        ),
        (
            IntentProposalKind::HostName,
            "ipam.reconcile.host_name",
            FindingKind::HostName,
            FindingLevel::Review,
            FindingAction::Decide,
        ),
    ];
    for (kind, code, expected, level, action) in cases {
        let source = proposal(kind, code);
        let finding = of_proposal(&source).expect("open");
        assert_eq!(finding.kind, expected, "{code}");
        assert_eq!(finding.severity, level, "{code}");
        assert_eq!(finding.action, action, "{code}");
        assert_eq!(finding.area, FindingArea::Discovery, "{code}");
        assert_eq!(finding.source, FindingSource::Proposal);
        assert_eq!(finding.id, format!("proposal:{}", source.id));
        assert_eq!(finding.code, code);
        assert_eq!(finding.since, source.created);
        assert_eq!(finding.evidence.path, format!("/proposals/{}", source.id));
        assert_eq!(finding.subject.kind, SubjectKind::Address);
    }
    let mut decided = proposal(IntentProposalKind::Conflict, rule::CONFLICT_SHARED_ADDRESS);
    decided.state = IntentProposalState::Rejected;
    assert_eq!(
        of_proposal(&decided),
        None,
        "a decided proposal is no finding"
    );
}

fn alarm(level: AlarmLevel) -> AlarmEvent {
    AlarmEvent {
        prefix: PrefixId::generate(),
        vrf: VrfId::generate(),
        cidr: "192.0.2.0/24".parse().expect("cidr"),
        level,
        previous: AlarmLevel::Normal,
        permille: 925,
        used: 235,
        reserved: 0,
        capacity: 254,
        warn_pct: Some(80),
        crit_pct: Some(90),
        at: at("2026-10-26T09:00:00Z"),
    }
}

/// IPAM-10: the utilization alarms as findings.
#[test]
fn an_alarm_over_its_critical_threshold_is_to_act_on_and_over_its_warning_to_review() {
    assert_eq!(of_alarm(&alarm(AlarmLevel::Normal)), None);
    let warning = of_alarm(&alarm(AlarmLevel::Warning)).expect("warning");
    assert_eq!(warning.severity, FindingLevel::Review);
    assert_eq!(warning.params["threshold"], "80");
    let critical = alarm(AlarmLevel::Critical);
    let finding = of_alarm(&critical).expect("critical");
    assert_eq!(finding.kind, FindingKind::Utilization);
    assert_eq!(finding.severity, FindingLevel::Act);
    assert_eq!(finding.action, FindingAction::OpenPrefix);
    assert_eq!(finding.area, FindingArea::Ipam);
    assert_eq!(finding.subject.kind, SubjectKind::Prefix);
    assert_eq!(finding.subject.prefix, Some(critical.prefix));
    assert_eq!(finding.params["percent"], "92.5");
    assert_eq!(finding.params["threshold"], "90");
    assert_eq!(finding.code, "ipam.prefix.alarm.critical");
    assert_eq!(finding.id, format!("alarm:{}", critical.prefix));
}

fn job(state: StepState) -> Job {
    let created = at("2026-10-26T10:00:00Z");
    Job {
        id: JobId::generate(),
        spec: testing::spec(vec![testing::manual("jobs.test.reconfigure", None, None)]),
        state: JobState::Waiting,
        steps: vec![StepRecord {
            index: 0,
            kind: MANUAL,
            state,
            attempts: 1,
            started: Some(at("2026-10-26T10:01:00Z")),
            finished: None,
            output: None,
        }],
        created: Stamp::new(created, Principal::system(SystemComponent::Ipam)),
        started: Some(created),
        runner: None,
        revision: Revision::ZERO,
        cancel_requested: None,
        error: None,
        finished: None,
    }
}

/// IPAM-19: a job waiting for a person.
#[test]
fn a_job_waiting_for_a_person_is_to_act_on_and_other_jobs_are_none() {
    let task = ManualTask {
        instruction: MessageKey::from_static("jobs.test.reconfigure"),
        args: BTreeMap::from([("host".to_owned(), "printer-1".to_owned())]),
        undo: None,
    };
    let waiting = job(StepState::WaitingForManual {
        task,
        deadline: None,
    });
    let finding = of_job(&waiting).expect("waiting");
    assert_eq!(finding.kind, FindingKind::JobWaiting);
    assert_eq!(finding.severity, FindingLevel::Act);
    assert_eq!(finding.action, FindingAction::OpenManualStep);
    assert_eq!(finding.area, FindingArea::Jobs);
    assert_eq!(finding.subject.kind, SubjectKind::Job);
    assert_eq!(finding.subject.objects, waiting.spec.targets);
    assert_eq!(finding.code, "jobs.test");
    assert_eq!(finding.params["instruction"], "jobs.test.reconfigure");
    assert_eq!(finding.params["task.host"], "printer-1");
    assert_eq!(
        finding.since,
        at("2026-10-26T10:01:00Z"),
        "the step's start"
    );
    assert_eq!(finding.evidence.path, format!("/jobs/{}", waiting.id));
    assert_eq!(of_job(&job(StepState::Running)), None);
    assert_eq!(of_job(&job(StepState::Done)), None);
}

fn row(kind: ReconcileKind, rule_id: WinRule) -> ReconcileRow {
    ReconcileRow {
        key: format!("{}/key", kind.as_str()),
        kind,
        vrf: Some(VrfId::generate()),
        address: ip("192.0.2.30"),
        prefix: Some(PrefixId::generate()),
        host: None,
        intent: None,
        lease: None,
        dns: None,
        scan: None,
        macs: vec!["00:00:5e:00:53:30".parse().expect("mac")],
        os: None,
        vendors: Vec::new(),
        winner: None,
        rule_id,
        rule: rule_id.text().to_owned(),
        proposal: None,
        last_seen: Some(at("2026-10-01T00:00:00Z")),
    }
}

/// IPAM-21, IPAM-23: the rows of the reconciliation view as findings.
#[test]
fn the_rows_of_the_view_get_their_severities_and_proposals_are_not_listed_twice() {
    let config = FindingsConfig::default();
    let now = at("2026-10-26T12:00:00Z");
    let cases = [
        (
            ReconcileKind::Conflict,
            WinRule::NeverAutomatic,
            FindingKind::Conflict,
            FindingLevel::Act,
            FindingAction::Resolve,
            FindingArea::Ipam,
        ),
        (
            ReconcileKind::Rogue,
            WinRule::NewestSighting,
            FindingKind::UnknownDevice,
            FindingLevel::Info,
            FindingAction::None,
            FindingArea::Ipam,
        ),
        (
            ReconcileKind::Orphan,
            WinRule::ManualRecord,
            FindingKind::OrphanedRecord,
            FindingLevel::Review,
            FindingAction::DeleteRecord,
            FindingArea::Dns,
        ),
        (
            ReconcileKind::PtrMismatch,
            WinRule::ForwardRecord,
            FindingKind::PtrMismatch,
            FindingLevel::Review,
            FindingAction::FixPtr,
            FindingArea::Dns,
        ),
    ];
    for (kind, rule_id, expected, level, action, area) in cases {
        let source = row(kind, rule_id);
        let derived = map::of_row(&source, None, now, &config).expect("finding");
        assert_eq!(derived.finding.kind, expected, "{kind:?}");
        assert_eq!(derived.finding.severity, level, "{kind:?}");
        assert_eq!(derived.finding.action, action, "{kind:?}");
        assert_eq!(derived.finding.area, area, "{kind:?}");
        assert_eq!(derived.finding.source, FindingSource::Reconcile);
        assert!(derived.finding.id.starts_with("reconcile:"));
        assert_eq!(derived.finding.evidence.id, source.key);
        assert_eq!(
            derived.covered_by_conflict.is_some(),
            kind == ReconcileKind::Conflict
        );
    }
    for kind in [ReconcileKind::Rogue, ReconcileKind::Orphan] {
        let mut linked = row(kind, WinRule::NewestSighting);
        linked.proposal = Some(ProposalId::generate());
        assert_eq!(
            map::of_row(&linked, None, now, &config),
            None,
            "the proposal stands for the {kind:?} row"
        );
    }
}

/// IPAM-21: the ghost ageing.
#[test]
fn a_ghost_is_info_until_the_review_age_then_review_with_decommission() {
    let config = FindingsConfig::default();
    let mut ghost = row(ReconcileKind::Ghost, WinRule::IntentManaged);
    ghost.host = Some(tenko_core::HostId::generate());
    ghost.intent = Some(IntentTruth {
        host_name: Some("printer".to_owned()),
        ..IntentTruth::default()
    });
    let unseen = at("2026-09-01T00:00:00Z");
    let young = map::of_row(
        &ghost,
        Some(unseen),
        unseen
            .checked_add(Duration::from_secs(29 * 86_400))
            .expect("time"),
        &config,
    )
    .expect("ghost")
    .finding;
    assert_eq!(young.severity, FindingLevel::Info);
    assert_eq!(young.action, FindingAction::None);
    assert_eq!(young.since, unseen);
    let old = map::of_row(
        &ghost,
        Some(unseen),
        unseen
            .checked_add(config.ghost_review_after())
            .expect("time"),
        &config,
    )
    .expect("ghost")
    .finding;
    assert_eq!(old.severity, FindingLevel::Review);
    assert_eq!(old.action, FindingAction::Decommission);
    assert_eq!(old.id, young.id);
    assert_eq!(old.subject.kind, SubjectKind::Host);
    assert_eq!(old.subject.label, "printer");
    // A shorter age applies as configured.
    let short = FindingsConfig {
        ghost_review_after_secs: 86_400,
        ..FindingsConfig::default()
    };
    let aged = map::of_row(
        &ghost,
        Some(unseen),
        unseen
            .checked_add(Duration::from_secs(2 * 86_400))
            .expect("time"),
        &short,
    )
    .expect("ghost")
    .finding;
    assert_eq!(aged.severity, FindingLevel::Review);
}

/// The health conditions of the status as findings (OPS-05).
#[test]
fn health_conditions_keep_their_identity_and_their_area() {
    let item = |code: &str, level: FindingLevel| HealthItem {
        code: code.to_owned(),
        detail: format!("{code} detail"),
        params: BTreeMap::from([("zone".to_owned(), "example.test".to_owned())]),
        level,
    };
    let now = at("2026-10-26T12:00:00Z");
    let dns = of_health(&item("dns.role.lagging", FindingLevel::Review), now);
    assert_eq!(dns.area, FindingArea::Dns);
    assert_eq!(dns.kind, FindingKind::Health);
    assert_eq!(dns.action, FindingAction::OpenStatus);
    assert_eq!(
        of_health(
            &item("sys.tls.certificate_expiring", FindingLevel::Review),
            now
        )
        .area,
        FindingArea::Settings
    );
    assert_eq!(
        of_health(&item("dhcp.role.not_serving", FindingLevel::Act), now).area,
        FindingArea::Dhcp
    );
    assert_eq!(
        of_health(&item("cluster.quorum.lost", FindingLevel::Act), now).area,
        FindingArea::Nodes
    );

    let index = FindingsIndex::new(FindingsConfig::default());
    let first = [item("dns.role.lagging", FindingLevel::Review)];
    assert!(index.set_health(&first, now));
    let later = now.checked_add(Duration::from_secs(60)).expect("time");
    assert!(!index.set_health(&first, later), "unchanged");
    let listed = index.get(&first[0].id()).expect("listed");
    assert_eq!(listed.since, now, "the condition keeps its first sighting");
    assert!(index.set_health(&[], later));
    assert!(index.get(&first[0].id()).is_none());
}

fn finding(id: &str, level: FindingLevel, area: FindingArea, source: FindingSource) -> Finding {
    Finding {
        id: id.to_owned(),
        kind: FindingKind::Health,
        severity: level,
        area,
        subject: FindingSubject::new(SubjectKind::Node, id),
        summary: format!("{id} summary"),
        code: id.to_owned(),
        params: BTreeMap::new(),
        evidence: FindingEvidence {
            id: id.to_owned(),
            path: "/system/status".to_owned(),
        },
        action: FindingAction::OpenStatus,
        since: at("2026-10-26T12:00:00Z"),
        source,
    }
}

/// U7: the topology's findings are replaced as a whole, keep their first sighting while they
/// last, count under the source topology and leave every other finding alone.
#[test]
fn the_topology_findings_are_replaced_as_a_whole_and_keep_their_first_sighting() {
    let index = FindingsIndex::new(FindingsConfig::default());
    index.insert_for_test(finding(
        "health:x",
        FindingLevel::Review,
        FindingArea::Settings,
        FindingSource::Health,
    ));
    let topology = |id: &str| Finding {
        kind: FindingKind::WlanClass,
        action: FindingAction::MoveHost,
        ..finding(
            id,
            FindingLevel::Review,
            FindingArea::Topology,
            FindingSource::Topology,
        )
    };
    let now = at("2026-10-29T12:00:00Z");
    let later = now.checked_add(Duration::from_secs(60)).expect("time");
    assert!(index.set_topology(
        vec![topology("topology:wlan:a"), topology("topology:wlan:b")],
        now
    ));
    assert!(
        !index.set_topology(
            vec![topology("topology:wlan:a"), topology("topology:wlan:b")],
            later
        ),
        "unchanged"
    );
    assert_eq!(index.get("topology:wlan:a").expect("listed").since, now);
    let counts = index.counts();
    assert_eq!(counts.sources.topology, 2);
    assert_eq!(counts.areas.topology.review, 2);
    // A finding of another source is never taken in, and a gone one is removed.
    assert!(index.set_topology(
        vec![topology("topology:wlan:b"), topology("health:y")],
        later
    ));
    assert!(index.get("topology:wlan:a").is_none());
    assert!(index.get("health:y").is_none());
    assert!(index.get("health:x").is_some(), "other sources stay");
    assert_eq!(index.counts().sources.topology, 1);
}

/// IPAM-21: the counts per severity, area and source, and the list's order and paging.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture, then the counts and the list"
)]
fn the_counts_are_per_severity_area_and_source_and_info_is_never_a_problem() {
    let index = FindingsIndex::new(FindingsConfig::default());
    index.insert_for_test(finding(
        "a",
        FindingLevel::Act,
        FindingArea::Ipam,
        FindingSource::Alarm,
    ));
    index.insert_for_test(finding(
        "b",
        FindingLevel::Review,
        FindingArea::Ipam,
        FindingSource::Reconcile,
    ));
    index.insert_for_test(finding(
        "c",
        FindingLevel::Info,
        FindingArea::Ipam,
        FindingSource::Reconcile,
    ));
    index.insert_for_test(finding(
        "d",
        FindingLevel::Review,
        FindingArea::Discovery,
        FindingSource::Proposal,
    ));
    index.insert_for_test(finding(
        "e",
        FindingLevel::Act,
        FindingArea::Jobs,
        FindingSource::Job,
    ));
    index.insert_for_test(finding(
        "f",
        FindingLevel::Info,
        FindingArea::Settings,
        FindingSource::Health,
    ));
    let counts = index.counts();
    assert_eq!(
        counts.total,
        LevelCounts {
            act: 2,
            review: 2,
            info: 2
        }
    );
    assert_eq!(counts.problems, 4);
    assert_eq!(
        counts.areas.ipam,
        LevelCounts {
            act: 1,
            review: 1,
            info: 1
        }
    );
    assert_eq!(counts.areas.discovery.problems(), 1);
    assert_eq!(counts.areas.jobs.act, 1);
    assert_eq!(
        counts.areas.settings,
        LevelCounts {
            act: 0,
            review: 0,
            info: 1
        }
    );
    assert_eq!(counts.areas.dns, LevelCounts::default());
    assert_eq!(
        counts.sources,
        SourceCounts {
            topology: 0,
            proposal: 1,
            alarm: 1,
            reconcile: 2,
            job: 1,
            health: 1
        }
    );
    let scoped = index.counts_where(&|finding| finding.area == FindingArea::Ipam);
    assert_eq!(scoped.problems, 2);

    // The list: the most urgent first, filtered and paged.
    let page = index
        .list(
            &FindingQuery {
                limit: Some(2),
                ..FindingQuery::default()
            },
            &|_| true,
        )
        .expect("page");
    assert_eq!(
        page.items.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        ["a", "e"]
    );
    let next = index
        .list(
            &FindingQuery {
                limit: Some(2),
                cursor: page.next_cursor.clone(),
                ..FindingQuery::default()
            },
            &|_| true,
        )
        .expect("page");
    assert_eq!(
        next.items.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
        ["b", "d"]
    );
    let filtered = index
        .list(
            &FindingQuery {
                severities: vec![FindingLevel::Info],
                text: Some("F SUMMARY".to_owned()),
                ..FindingQuery::default()
            },
            &|_| true,
        )
        .expect("page");
    assert_eq!(filtered.items.len(), 1);
    assert_eq!(filtered.items[0].id, "f");
    assert!(
        index
            .list(
                &FindingQuery {
                    limit: Some(0),
                    ..FindingQuery::default()
                },
                &|_| true,
            )
            .is_err()
    );
}

/// IPAM-23: a conflict is listed and counted once.
#[test]
fn a_conflict_row_is_hidden_while_its_conflict_proposal_is_open() {
    let index = FindingsIndex::new(FindingsConfig::default());
    let conflict = proposal(IntentProposalKind::Conflict, rule::CONFLICT_SHARED_ADDRESS);
    let row_finding = map::of_row(
        &ReconcileRow {
            vrf: conflict.subject.vrf,
            address: conflict.subject.ip.expect("ip"),
            ..row(ReconcileKind::Conflict, WinRule::NeverAutomatic)
        },
        None,
        at("2026-10-26T12:00:00Z"),
        index.config(),
    )
    .expect("row");
    assert!(row_finding.covered_by_conflict.is_some());
    index.insert_view_for_test(vec![row_finding]);
    assert_eq!(index.counts().total.act, 1, "the row alone");
    index.insert_for_test(of_proposal(&conflict).expect("open"));
    let counts = index.counts();
    assert_eq!(counts.total.act, 1, "listed once, as the proposal");
    assert_eq!(counts.sources.proposal, 1);
    assert_eq!(counts.sources.reconcile, 0);
}

/// IPAM-21: the budget of `GET /findings/counts` on 10,000 open proposals: 50 ms for the first,
/// uncached count; a cached count is a copy.
#[test]
fn the_counts_of_ten_thousand_proposals_stay_within_budget() {
    let index = FindingsIndex::new(FindingsConfig::default());
    for n in 0..10_000u32 {
        let kind = if n % 10 == 0 {
            IntentProposalKind::Conflict
        } else {
            IntentProposalKind::DiscoveredHost
        };
        let mut source = proposal(kind, rule::DISCOVERED_MAC);
        let [_, _, high, low] = n.to_be_bytes();
        source.subject.ip = Some(IpAddr::from([198, 51, high, low]));
        index.insert_for_test(of_proposal(&source).expect("open"));
    }
    let started = Instant::now();
    let counts = index.counts();
    let first = started.elapsed();
    let started = Instant::now();
    for _ in 0..100 {
        assert_eq!(index.counts(), counts);
    }
    let cached = started.elapsed() / 100;
    assert_eq!(counts.sources.proposal, 10_000);
    assert_eq!(counts.areas.discovery.problems(), 10_000);
    assert_eq!(counts.total.act, 1_000);
    assert!(
        first < Duration::from_millis(50),
        "first count took {first:?}"
    );
    assert!(
        cached < Duration::from_millis(1),
        "a cached count took {cached:?}"
    );
}
