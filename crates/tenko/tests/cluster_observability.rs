//! Observability across controllers (WP3.1c, the end-to-end tests WP3.5b and WP3.5c left
//! for the lab): the `metrics` topic on a follower carries one sample per controller and
//! their cluster sum, and a write through a follower yields one trace whose request span on
//! the follower is an ancestor of the `tenko.store.propose` span on the leader.

mod cluster_support;
mod serve_support;

use std::{
    collections::{BTreeSet, HashMap},
    time::Duration,
};

use cluster_support::{ClusterLab, LabOptions};
use opentelemetry_proto::tonic::trace::v1::Span;
use serde_json::{Value, json};
use serve_support::otlp::{Receiver, attribute, span_attribute};

/// How long one scenario may take, the lab's start included.
const SCENARIO_LIMIT: Duration = Duration::from_secs(600);

/// The figure at `path` of a sample as a number (0 when absent).
fn figure(sample: &Value, path: &[&str]) -> f64 {
    path.iter()
        .fold(sample, |value, key| &value[*key])
        .as_f64()
        .unwrap_or(0.0)
}

/// Whether a `metrics.snapshot` names exactly `ids`, every sample current, and the cluster
/// sum adds up the per-controller rates and sizes.
fn complete_snapshot(snapshot: &Value, ids: &BTreeSet<u64>) -> bool {
    let Some(nodes) = snapshot["nodes"].as_array() else {
        return false;
    };
    let named: BTreeSet<u64> = nodes
        .iter()
        .filter_map(|node| node["node"].as_u64())
        .collect();
    let current = nodes
        .iter()
        .all(|node| node["stale"] != true && node["interval_ms"].as_u64().unwrap_or(0) > 0);
    if named != *ids || nodes.len() != ids.len() || !current {
        return false;
    }
    let cluster = &snapshot["cluster"];
    [
        &["api", "requests_per_second"][..],
        &["store", "data_bytes"][..],
        &["sse", "subscribers"][..],
    ]
    .iter()
    .all(|path| {
        let sum: f64 = nodes.iter().map(|node| figure(node, path)).sum();
        let merged = figure(cluster, path);
        (merged - sum).abs() <= 0.01 + sum.abs() * 0.01
    }) && cluster.get("node").is_none_or(Value::is_null)
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn the_metrics_topic_of_a_follower_shows_every_controller_and_the_sum() {
    let lab = ClusterLab::start(3);
    let follower = lab.followers()[0];
    let events = lab.sse_client(follower, "metrics");
    let ids: BTreeSet<u64> = lab.ids().into_iter().collect();
    let snapshot = lab.wait_until(
        "a metrics snapshot with every controller and the cluster sum",
        Duration::from_secs(60),
        || {
            // Some traffic on every controller, so the rates are not all zero.
            for id in &ids {
                let _ = lab.get(*id, "/cluster/members");
            }
            events
                .events()
                .iter()
                .rev()
                .filter(|event| event.data["kind"] == "metrics.snapshot")
                .map(|event| event.data["metrics"].clone())
                .find(|snapshot| complete_snapshot(snapshot, &ids))
        },
    );
    let nodes = snapshot["nodes"].as_array().expect("samples");
    assert_eq!(
        nodes[0]["node"].as_u64(),
        Some(follower),
        "the publishing controller comes first: {snapshot}"
    );
    println!(
        "metrics on follower {follower}: {} samples, cluster requests/s {}, store bytes {}",
        nodes.len(),
        figure(&snapshot["cluster"], &["api", "requests_per_second"]),
        figure(&snapshot["cluster"], &["store", "data_bytes"])
    );
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}

/// Every span received, with the `service.instance.id` of the controller that sent it.
fn spans_by_instance(receiver: &Receiver) -> Vec<(String, Span)> {
    receiver
        .resource_spans()
        .into_iter()
        .flat_map(|resource| {
            let instance = resource
                .resource
                .as_ref()
                .and_then(|resource| attribute(&resource.attributes, "service.instance.id"))
                .unwrap_or_default();
            resource
                .scope_spans
                .into_iter()
                .flat_map(|scope| scope.spans)
                .map(move |span| (instance.clone(), span))
        })
        .collect()
}

/// Whether `ancestor` is on the parent chain of `span` among `spans` (one trace).
fn descends_from(span: &Span, ancestor: &Span, by_id: &HashMap<Vec<u8>, &Span>) -> bool {
    let mut parent = span.parent_span_id.clone();
    for _ in 0..64 {
        if parent.is_empty() {
            return false;
        }
        if parent == ancestor.span_id {
            return true;
        }
        match by_id.get(&parent) {
            Some(next) => parent.clone_from(&next.parent_span_id),
            None => return false,
        }
    }
    false
}

#[test]
#[ignore = "slow lab scenario, nightly"]
fn a_write_through_a_follower_is_one_trace_across_controllers() {
    let receiver = Receiver::start();
    let lab = ClusterLab::start_with(
        3,
        LabOptions {
            config: receiver.config(1.0),
            ..LabOptions::default()
        },
    );
    let leader = lab.leader();
    let follower = lab.followers()[0];
    lab.api(follower)
        .post(
            "/prefixes",
            &json!({ "cidr": "203.0.113.0/24", "description": "traced through a follower" }),
        )
        .expect(201);
    let (request, propose) = lab.wait_until(
        "the follower's request span and the leader's propose span in one trace",
        Duration::from_secs(60),
        || {
            let spans = spans_by_instance(&receiver);
            let requests = spans.iter().filter(|(instance, span)| {
                *instance == follower.to_string()
                    && span.name == "http.server.request"
                    && span_attribute(span, "http.request.method").as_deref() == Some("POST")
            });
            for (_, request) in requests {
                let trace: Vec<&Span> = spans
                    .iter()
                    .map(|(_, span)| span)
                    .filter(|span| span.trace_id == request.trace_id)
                    .collect();
                let by_id: HashMap<Vec<u8>, &Span> = trace
                    .iter()
                    .map(|span| (span.span_id.clone(), *span))
                    .collect();
                let found = spans.iter().find(|(instance, span)| {
                    *instance == leader.to_string()
                        && span.name == "tenko.store.propose"
                        && span.trace_id == request.trace_id
                        && descends_from(span, request, &by_id)
                });
                if let Some((_, propose)) = found {
                    return Some((request.clone(), propose.clone()));
                }
            }
            None
        },
    );
    let spans = spans_by_instance(&receiver);
    let in_trace: Vec<String> = spans
        .iter()
        .filter(|(_, span)| span.trace_id == request.trace_id)
        .map(|(instance, span)| format!("{}@{instance}", span.name))
        .collect();
    println!(
        "one trace across controllers: request on {follower}, propose on {leader}; spans {in_trace:?}"
    );
    assert_eq!(propose.trace_id, request.trace_id);
    assert!(lab.elapsed() < SCENARIO_LIMIT, "took {:?}", lab.elapsed());
}
