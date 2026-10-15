//! A split of two controllers against one with real processes (WP3.1c with WP3.9, OPS-26):
//! the relays cut every link between the minority and the majority. The minority refuses
//! writes with 503 `cluster.no_quorum` once `isolation_after_ms` has passed, serves reads
//! with the staleness header and queues IPAM changes; the majority commits. After the heal
//! the queue drains (one change applied, one a conflict), the digests agree, and the
//! `cluster.quorum` events arrive on the `cluster` topic. `partition.rs` checks the same
//! in one process.

mod cluster_support;
mod serve_support;

use std::time::{Duration, Instant};

use cluster_support::ClusterLab;
use serde_json::{Value, json};

/// How long one scenario may take, the lab's start included.
const SCENARIO_LIMIT: Duration = Duration::from_secs(600);

/// The states of the `cluster.quorum` events of a stream, in order.
fn quorum_states(events: &[cluster_support::sse::SseRecord]) -> Vec<String> {
    events
        .iter()
        .filter(|event| event.data["kind"] == "cluster.quorum")
        .filter_map(|event| {
            let params = &event.data["params"];
            params["state"].as_str().map(str::to_owned)
        })
        .collect()
}

#[test]
#[ignore = "slow lab scenario, nightly"]
#[allow(clippy::too_many_lines, reason = "one scenario, step by step")]
fn a_split_two_against_one_queues_on_the_minority_and_settles_after_the_heal() {
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
    let refused = on_minority.patch(
        &format!("/addresses/{a_id}"),
        &json!({ "description": "refused" }),
        None,
    );
    let problem = refused.expect(503);
    assert_eq!(problem["code"], "cluster.no_quorum", "{problem}");
    assert_eq!(problem["params"]["queueable"], "true", "{problem}");
    assert!(refused.header("retry-after").is_some(), "a retry hint");

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
    println!(
        "cluster.quorum states on the minority's stream: {:?}",
        quorum_states(&events.events())
    );
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}
