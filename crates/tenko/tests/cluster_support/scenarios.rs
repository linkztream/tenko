//! Scenarios of the cluster lab that more than one test file runs: the weekly lab job
//! (`cluster_failover.rs`, `cluster_partition.rs`) and the exit run (`acceptance_cluster.rs`,
//! `acceptance_partition.rs`). Each scenario is a plain function that panics, with the lab's
//! diagnostics, when a claim does not hold, and returns a small summary the callers print.

use std::{
    collections::BTreeSet,
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::{ClusterLab, LoadReport, WriteRecord, sse::SseRecord};

/// The M3 threshold: writes resume within this time after the leader is killed.
pub const RESUME_LIMIT: Duration = Duration::from_secs(15);

/// How long one scenario may take, the lab's start included.
pub const SCENARIO_LIMIT: Duration = Duration::from_secs(600);

/// Prints the report of a load.
pub fn print_report(what: &str, report: &LoadReport) {
    println!("{what}: {}", report.summary());
}

/// What the leader-killed scenario measured.
#[derive(Debug, Clone)]
pub struct LeaderKilled {
    /// The controller that was killed.
    pub old_leader: u64,
    /// The controller that leads after the kill.
    pub new_leader: u64,
    /// Time from the kill until a new leader was known.
    pub elected: Duration,
    /// Time from the kill until the first write committed again.
    pub resumed: Duration,
    /// The last revision a write of the load committed.
    pub committed_revision: u64,
    /// The revision at which the digests of the survivors agreed.
    pub agreed_revision: u64,
    /// The controllers that agreed (the survivors).
    pub agreed_members: Vec<u64>,
    /// The connections of the event stream, in order.
    pub stream_connections: Vec<String>,
    /// How long the whole scenario took, the lab's start included.
    pub took: Duration,
}

/// The leader of a lab of three is killed under 100 writes per second (E9, OPS-03, OPS-04):
/// writes resume within [`RESUME_LIMIT`], the survivors agree and show every committed write,
/// the event stream and a probe move to a survivor, and the old leader rejoins.
///
/// # Panics
/// When any claim does not hold.
#[allow(clippy::too_many_lines, reason = "one scenario, step by step")]
pub fn leader_killed_under_load() -> LeaderKilled {
    let mut lab = ClusterLab::start(3);
    let leader = lab.leader();
    let followers = lab.followers();
    let target = followers[0];

    // An event stream and a probe on the leader, so both must move elsewhere.
    let events = lab.sse_client(leader, "ipam");
    let probe = lab.probe(leader);
    lab.wait_for("the probe connected", Duration::from_secs(60), || {
        lab.node_view(leader, probe.id)
            .is_some_and(|view| view["connected"] == true)
    });

    let load = lab.start_load(target, 100);
    thread::sleep(Duration::from_secs(5));
    let killed = Instant::now();
    lab.kill(leader);
    probe.inject(None);
    let new_leader = lab.leader();
    assert_ne!(new_leader, leader);
    let elected = killed.elapsed();
    thread::sleep(Duration::from_secs(20));
    let report = load.stop();
    print_report("kill the leader at 100 writes/s", &report);

    let resumed = report
        .resumed_after(killed)
        .unwrap_or_else(|| panic!("no write committed after the kill\n{}", lab.diagnostics()));
    println!(
        "new leader {new_leader} after {elected:?}; writes resumed {resumed:?} after the kill"
    );
    assert!(
        resumed < RESUME_LIMIT,
        "writes resumed {resumed:?} after the kill, more than {RESUME_LIMIT:?}"
    );

    // No committed write lost: the survivors agree at the last committed revision and
    // show every address the load created.
    let last = report.committed_revision();
    let agreement = lab.digests_agree(last);
    println!(
        "survivors {:?} agree at revision {} (load committed up to {last})",
        agreement.members, agreement.revision
    );
    for survivor in lab.ids() {
        let missing = lab.missing_creates(&report, survivor);
        assert!(
            missing.is_empty(),
            "controller {survivor} lost {} committed creates: {missing:?}",
            missing.len()
        );
    }

    // The event stream reconnected elsewhere and has every committed write's event, or
    // was told to reload.
    let committed: Vec<u64> = report
        .committed()
        .filter_map(WriteRecord::revision)
        .collect();
    events.wait_for(
        &lab,
        "every committed write on the event stream, or a reset",
        Duration::from_secs(60),
        |seen| {
            let ids: BTreeSet<u64> = seen
                .iter()
                .filter_map(|event| event.id.as_deref()?.parse().ok())
                .collect();
            seen.iter().any(|event| event.event == "reset")
                || committed.iter().all(|revision| ids.contains(revision))
        },
    );
    let connections = events.connections();
    println!(
        "event stream: {} events, {} resets, connections {connections:?}",
        events.events().len(),
        events.resets()
    );
    assert!(
        connections.len() >= 2 && connections.last() != Some(&lab.url(leader)),
        "the event stream did not move to a survivor: {connections:?}"
    );

    // The probe reconnects to a survivor and its buffer drains.
    lab.wait_for(
        "the probe's batch at a survivor and an empty buffer",
        Duration::from_secs(90),
        || lab.probe_facts(new_leader, probe.id) == Some(2) && probe.buffered() == 0,
    );
    lab.wait_for("the probe connected again", Duration::from_secs(60), || {
        lab.node_view(new_leader, probe.id)
            .is_some_and(|view| view["connected"] == true)
    });

    // The old leader comes back as a follower and catches up.
    lab.restart(leader);
    lab.wait_for_members(3);
    lab.digests_agree(last);
    let took = lab.elapsed();
    assert!(took < SCENARIO_LIMIT, "took {took:?}");
    LeaderKilled {
        old_leader: leader,
        new_leader,
        elected,
        resumed,
        committed_revision: last,
        agreed_revision: agreement.revision,
        agreed_members: agreement.members,
        stream_connections: connections,
        took,
    }
}

/// The states of the `cluster.quorum` events of a stream, in order.
pub fn quorum_states(events: &[SseRecord]) -> Vec<String> {
    events
        .iter()
        .filter(|event| event.data["kind"] == "cluster.quorum")
        .filter_map(|event| {
            let params = &event.data["params"];
            params["state"].as_str().map(str::to_owned)
        })
        .collect()
}

/// What a split scenario checks beyond the queue and the digests.
#[derive(Debug, Clone, Copy, Default)]
pub struct SplitOptions {
    /// Also check what the web UI's cluster banner and stale status item read: the quorum
    /// state in `GET /system/status`, the `Tenko-Staleness` header of the minority and its
    /// absence on the majority and after the heal, the `cluster.quorum` events with their
    /// `since` and `applied`, and the settled changes that wait for a decision.
    pub banner_data: bool,
}

/// What the split scenario measured.
#[derive(Debug, Clone)]
pub struct Split {
    /// Time from the cut until the minority counted itself isolated.
    pub isolated_after: Duration,
    /// Time from the heal until the minority was healthy again.
    pub healthy_after: Duration,
    /// The `cluster.quorum` states on the minority's event stream, in order.
    pub quorum_states: Vec<String>,
    /// How long the whole scenario took, the lab's start included.
    pub took: Duration,
}

/// Parses `since=<RFC 3339>; revision=<n>` of the `Tenko-Staleness` header.
fn staleness_fields(header: &str) -> (Option<String>, Option<u64>) {
    let field = |name: &str| {
        header.split(';').find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
        })
    };
    (
        field("since"),
        field("revision").and_then(|v| v.parse().ok()),
    )
}

/// What the UI reads of the isolated minority: the banner (`store.quorum` of the status and
/// the staleness header) and the stale status item (the age and the revision of the copy).
#[track_caller]
fn check_isolated_banner_data(
    lab: &ClusterLab,
    minority: u64,
    majority: &[u64],
    copy_revision: u64,
) {
    let status = lab.api(minority).get("/system/status");
    let body = status.expect(200);
    let quorum = &body["store"]["quorum"];
    assert_eq!(
        quorum["state"], "isolated",
        "the status of the minority says it is isolated, which the banner shows: {body}"
    );
    let since = quorum["since"]
        .as_str()
        .unwrap_or_else(|| panic!("the isolated quorum has a `since` for the banner: {quorum}"));
    let applied = quorum["applied"].as_u64().unwrap_or_else(|| {
        panic!("the isolated quorum has the revision `applied` for the status bar: {quorum}")
    });
    assert!(
        applied >= copy_revision,
        "the isolated copy is at least at revision {copy_revision}: {quorum}"
    );

    // Every answer of the minority carries the staleness header; its fields agree with the
    // quorum the status reports, so the status bar shows the same age and revision.
    let header = status
        .header("tenko-staleness")
        .expect("the staleness header on the status of the minority");
    let (header_since, header_revision) = staleness_fields(&header);
    assert_eq!(
        header_since.as_deref(),
        Some(since),
        "`since` of the header is `since` of the banner: {header}"
    );
    assert_eq!(
        header_revision,
        Some(applied),
        "`revision` of the header is the `applied` revision of the status: {header}"
    );

    // The majority shows neither a banner nor a stale item.
    for id in majority {
        let reply = lab.api(*id).get("/system/status");
        let body = reply.expect(200);
        assert_eq!(
            body["store"]["quorum"]["state"], "healthy",
            "a controller of the majority shows no banner: {body}"
        );
        assert!(
            reply.header("tenko-staleness").is_none(),
            "a controller of the majority sends no staleness header"
        );
    }
}

/// Two controllers against one (OPS-26): the relays cut every link between the minority and
/// the majority. The minority refuses writes with 503 `cluster.no_quorum` once
/// `isolation_after_ms` has passed, serves reads with the staleness header and queues IPAM
/// changes; the majority commits. After the heal the queue drains (one change applied, one a
/// conflict), the digests agree and the `cluster.quorum` events arrive on the `cluster` topic.
///
/// # Panics
/// When any claim does not hold.
#[allow(clippy::too_many_lines, reason = "one scenario, step by step")]
pub fn split_two_against_one(options: SplitOptions) -> Split {
    let lab = ClusterLab::start(3);
    let leader = lab.leader();
    let minority = lab.followers()[0];
    let other = lab.followers()[1];
    let majority = [leader, other];
    let on_leader = lab.api(leader);
    let on_minority = lab.api(minority);

    // 1. A prefix and two addresses; the minority applies them.
    on_leader
        .post("/prefixes", &json!({ "cidr": "198.51.100.0/24" }))
        .expect(201);
    let a = on_leader
        .post("/addresses", &json!({ "ip": "198.51.100.10" }))
        .expect(201);
    let b = on_leader
        .post("/addresses", &json!({ "ip": "198.51.100.11" }))
        .expect(201);
    let a_id = a["item"]["id"].as_str().expect("an id").to_owned();
    let b_id = b["item"]["id"].as_str().expect("an id").to_owned();
    let created = b["revision"].as_u64().expect("a revision");
    on_minority
        .get(&format!("/addresses/{b_id}?at_least={created}"))
        .expect(200);
    let events = lab.sse_client(minority, "cluster");

    // 2. Cut every link between the minority and the majority.
    let cut = Instant::now();
    lab.partition(&[minority], &majority);
    let isolated = lab.wait_until(
        "the minority isolated and the majority healthy",
        Duration::from_secs(60),
        || {
            let state = lab.quorum(minority)?;
            let majority_ok = majority.iter().all(|id| {
                lab.quorum(*id).as_deref() == Some("healthy")
                    && lab
                        .members(*id)
                        .is_some_and(|view| view["leader"].as_u64() == Some(leader))
            });
            (state == "isolated" && majority_ok).then(|| cut.elapsed())
        },
    );
    println!("the minority {minority} counted itself isolated {isolated:?} after the cut");

    // 3. Reads with the staleness header, a refused write.
    let read = on_minority.get("/addresses");
    read.expect(200);
    let staleness = read
        .header("tenko-staleness")
        .expect("the staleness header on a read of the minority");
    assert!(staleness.contains("revision="), "{staleness}");
    if options.banner_data {
        let (since, revision) = staleness_fields(&staleness);
        assert!(
            since.is_some_and(|since| !since.is_empty()),
            "the staleness header names when the contact was lost: {staleness}"
        );
        assert!(
            revision.is_some_and(|revision| revision >= created),
            "the staleness header names the revision of the copy, at least {created}: {staleness}"
        );
        check_isolated_banner_data(&lab, minority, &majority, created);
    }
    let refused = on_minority.patch(
        &format!("/addresses/{a_id}"),
        &json!({ "description": "refused" }),
        None,
    );
    let problem = refused.expect(503);
    assert_eq!(problem["code"], "cluster.no_quorum", "{problem}");
    assert_eq!(problem["params"]["queueable"], "true", "{problem}");
    assert!(refused.header("retry-after").is_some(), "a retry hint");
    if options.banner_data {
        // The dialog of a refused write reads `since` of the problem.
        assert!(
            problem["params"]["since"]
                .as_str()
                .is_some_and(|since| !since.is_empty()),
            "the refusal names when the contact was lost: {problem}"
        );
        assert!(
            refused.header("tenko-staleness").is_some(),
            "the refusal carries the staleness header"
        );
    }

    // 4. Two changes go into the minority's queue.
    for id in [&a_id, &b_id] {
        on_minority
            .post(
                "/queue",
                &json!({
                    "method": "PATCH",
                    "path": format!("/addresses/{id}"),
                    "body": { "description": "queued on the minority" },
                }),
            )
            .expect(201);
    }
    let queued = on_minority.get("/queue").expect(200);
    assert_eq!(
        queued["items"].as_array().map(Vec::len),
        Some(2),
        "{queued}"
    );

    // 5. The majority commits, and changes B meanwhile.
    let changed = on_leader
        .patch(
            &format!("/addresses/{b_id}"),
            &json!({ "description": "changed on the majority" }),
            None,
        )
        .expect(200);
    let majority_revision = changed["revision"].as_u64().expect("a revision");
    let load = lab.write_load(other, 20, Duration::from_secs(3));
    assert!(
        load.failed_writes() == 0 && load.committed_count() > 0,
        "the majority refused writes: {}",
        load.summary()
    );

    // 6. Heal: the minority catches up and drains its queue.
    let healed = Instant::now();
    lab.heal();
    lab.wait_for(
        "the minority healthy again",
        Duration::from_secs(60),
        || lab.quorum(minority).as_deref() == Some("healthy"),
    );
    let rejoined = healed.elapsed();
    lab.wait_for(
        "the minority's queue drained",
        Duration::from_secs(90),
        || {
            lab.get(minority, "/queue").is_some_and(|reply| {
                reply.status == 200 && reply.json()["items"].as_array().is_some_and(Vec::is_empty)
            })
        },
    );
    println!("the minority was healthy {rejoined:?} after the heal");

    // 7. The author finds both outcomes on the majority.
    let list = lab.wait_until("both settled records", Duration::from_secs(60), || {
        let reply = lab.get(leader, "/queue/conflicts")?;
        let body = reply.json();
        (reply.status == 200
            && body["items"]
                .as_array()
                .is_some_and(|items| items.len() == 2))
        .then_some(body)
    });
    let record = |id: &str| -> Value {
        list["items"]
            .as_array()
            .and_then(|items| {
                items.iter().find(|item| {
                    item["request"]["path"]
                        .as_str()
                        .is_some_and(|path| path.ends_with(id))
                })
            })
            .cloned()
            .unwrap_or_else(|| panic!("no record for {id} in {list}"))
    };
    assert_eq!(record(&a_id)["state"], "applied", "{list}");
    let conflict = record(&b_id);
    assert_eq!(conflict["state"], "conflict", "{conflict}");
    assert_eq!(
        conflict["conflict"]["code"], "queue.plan_changed",
        "{conflict}"
    );

    // 8. Equal state on all three.
    let settled = list["revision"].as_u64().unwrap_or(0);
    let at_least = settled
        .max(majority_revision)
        .max(load.committed_revision());
    let agreement = lab.digests_agree(at_least);
    assert_eq!(agreement.members.len(), 3);
    let a_now = lab
        .api(minority)
        .get(&format!("/addresses/{a_id}?at_least={at_least}"))
        .expect(200);
    assert_eq!(a_now["meta"]["description"], "queued on the minority");

    if options.banner_data {
        // The banner is gone with the quorum: the status says healthy and the minority
        // sends no staleness header any more. What is left for the author is one settled
        // change that waits for a decision (the conflict), which is what the banner counts.
        let status = lab.api(minority).get("/system/status");
        let body = status.expect(200);
        assert_eq!(
            body["store"]["quorum"]["state"], "healthy",
            "the banner has no isolation to show after the heal: {body}"
        );
        let read = lab.api(minority).get("/addresses");
        read.expect(200);
        assert!(
            read.header("tenko-staleness").is_none(),
            "the minority still sends the staleness header after the heal"
        );
        let waiting = list["items"].as_array().map_or(0, |items| {
            items
                .iter()
                .filter(|item| item["state"] != "applied")
                .count()
        });
        assert_eq!(
            waiting, 1,
            "one settled change waits for the person's decision: {list}"
        );
    }

    // 9. The minority told its event stream about losing and regaining its quorum.
    events.wait_for(
        &lab,
        "cluster.quorum events for isolated and healthy",
        Duration::from_secs(30),
        |seen| {
            let states = quorum_states(seen);
            let isolated_at = states.iter().position(|state| state == "isolated");
            isolated_at.is_some_and(|at| states[at..].iter().any(|state| state == "healthy"))
        },
    );
    let seen = events.events();
    let states = quorum_states(&seen);
    println!("cluster.quorum states on the minority's stream: {states:?}");
    if options.banner_data {
        // The banner is fed by these events: the isolated one names `since` and `applied`.
        let event = seen
            .iter()
            .find(|event| {
                event.data["kind"] == "cluster.quorum"
                    && event.data["params"]["state"] == "isolated"
            })
            .expect("a cluster.quorum event for isolated");
        let params = &event.data["params"];
        assert!(
            params["since"]
                .as_str()
                .is_some_and(|since| !since.is_empty()),
            "the isolated event names when the contact was lost: {params}"
        );
        assert!(
            params["applied"]
                .as_str()
                .is_some_and(|applied| applied.parse::<u64>().is_ok())
                || params["applied"].is_u64(),
            "the isolated event names the revision of the copy: {params}"
        );
    }
    let took = lab.elapsed();
    assert!(took < SCENARIO_LIMIT, "took {took:?}");
    Split {
        isolated_after: isolated,
        healthy_after: rejoined,
        quorum_states: states,
        took,
    }
}
