//! The diff of a scan run (SCAN-09): what the probes reported for the run, compared with
//! the facts of the target from before the scan.
//!
//! The results of a run are the batches tagged with its commands (`scan.run_results`).
//! Each sighting becomes the fact key the ingest gives it (source `probe:<node>:<method>`,
//! subject as the reconciler keys it, addresses in the VRF the ingest chose). A fact is
//! **new** when the baseline did not have it, **changed** when its attributes differ,
//! **unchanged** when they do not, and **gone** when the baseline had it as current, from
//! a method and a probe of this run whose command finished, and the scan did not see it.

use std::collections::{BTreeMap, BTreeSet};

use tenko_cluster::node_sync::commands::RunResult;
use tenko_core::{NodeId, Timestamp, VrfId, observe::Observed};
use tenko_ipam::observe::{FactSubject, source_key};

use super::model::{
    Baseline, BaselineFact, DiffCounts, DiffItem, FactChange, MAX_DIFF_ITEMS, ScanDiff,
};

/// What the scan saw, by (source key, subject key): the fact type and the attributes.
pub type Seen = BTreeMap<(String, String), (String, Observed)>;

/// The facts the results of a run stand for. `vrf_of` gives the VRF the ingest put a
/// node's addresses in when its batch names none; results of a node without one are
/// left out.
pub fn seen(
    results: &[RunResult],
    vrf_of: impl Fn(NodeId) -> Option<VrfId>,
    now: Timestamp,
) -> Seen {
    let mut out = Seen::new();
    for result in results {
        let Some(vrf) = result.batch.vrf.or_else(|| vrf_of(result.node)) else {
            continue;
        };
        let (source, observations) = result
            .batch
            .clone()
            .into_observations(result.node, vrf, now);
        let source = source_key(&source);
        for observation in observations {
            let subject = FactSubject::of(&observation.subject);
            out.insert(
                (source.clone(), subject.key()),
                (subject.type_name().to_owned(), observation.subject),
            );
        }
    }
    out
}

/// Compares what the scan saw with the baseline. `finished` are the source keys whose
/// absence counts: the methods of the run on the probes whose command finished.
pub fn compare(baseline: &Baseline, seen: &Seen, finished: &BTreeSet<String>) -> ScanDiff {
    let before: BTreeMap<(String, String), &BaselineFact> = baseline
        .facts
        .iter()
        .map(|fact| ((fact.source.clone(), fact.subject.clone()), fact))
        .collect();
    let mut counts: BTreeMap<String, DiffCounts> = BTreeMap::new();
    let mut items = Vec::new();
    let mut truncated = baseline.truncated;
    let mut push = |item: DiffItem, items: &mut Vec<DiffItem>| {
        if items.len() < MAX_DIFF_ITEMS {
            items.push(item);
        } else {
            truncated = true;
        }
    };
    for ((source, subject), (fact_type, observed)) in seen {
        let entry = counts.entry(fact_type.clone()).or_default();
        match before.get(&(source.clone(), subject.clone())) {
            None => {
                entry.new += 1;
                push(
                    DiffItem {
                        change: FactChange::New,
                        fact_type: fact_type.clone(),
                        subject: subject.clone(),
                        source: source.clone(),
                        before: None,
                        after: Some(observed.clone()),
                    },
                    &mut items,
                );
            }
            Some(fact) if fact.observed != *observed => {
                entry.changed += 1;
                push(
                    DiffItem {
                        change: FactChange::Changed,
                        fact_type: fact_type.clone(),
                        subject: subject.clone(),
                        source: source.clone(),
                        before: Some(fact.observed.clone()),
                        after: Some(observed.clone()),
                    },
                    &mut items,
                );
            }
            Some(_) => entry.unchanged += 1,
        }
    }
    for fact in &baseline.facts {
        let key = (fact.source.clone(), fact.subject.clone());
        if fact.current && finished.contains(&fact.source) && !seen.contains_key(&key) {
            counts.entry(fact.fact_type.clone()).or_default().gone += 1;
            push(
                DiffItem {
                    change: FactChange::Gone,
                    fact_type: fact.fact_type.clone(),
                    subject: fact.subject.clone(),
                    source: fact.source.clone(),
                    before: Some(fact.observed.clone()),
                    after: None,
                },
                &mut items,
            );
        }
    }
    ScanDiff {
        counts,
        items,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use tenko_cluster::probe::{ProbeBatch, Sighting, SightingSubject};
    use tenko_core::observe::ProbeMethod;

    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().expect("time")
    }

    fn services(ip: &str, ports: Vec<u16>) -> Sighting {
        Sighting {
            observed_at: at("2026-10-10T08:00:00Z"),
            ttl_secs: Some(600),
            subject: SightingSubject::Services {
                ip: ip.parse().expect("ip"),
                open_tcp: ports,
                tls_tcp: Vec::new(),
            },
        }
    }

    fn result(node: u64, sightings: Vec<Sighting>) -> RunResult {
        RunResult {
            node: NodeId(node),
            batch: ProbeBatch {
                method: ProbeMethod::TcpConnect,
                vrf: None,
                complete: false,
                collected_at: at("2026-10-10T08:00:01Z"),
                sightings,
            },
            left_out: 0,
            ingested_at: at("2026-10-10T08:00:02Z"),
        }
    }

    #[test]
    fn new_changed_unchanged_and_gone_facts_are_told_apart() {
        let vrf = VrfId::generate();
        let now = at("2026-10-10T08:00:03Z");
        let seen = seen(
            &[result(
                1001,
                vec![
                    services("192.0.2.10", vec![22, 443]),
                    services("192.0.2.11", vec![80]),
                    services("192.0.2.12", vec![22]),
                ],
            )],
            |_| Some(vrf),
            now,
        );
        assert_eq!(seen.len(), 3);
        let source = "probe:1001:tcp_connect".to_owned();
        let observed = |ip: &str, ports: Vec<u16>| Observed::Services {
            ip: ip.parse().expect("ip"),
            open_tcp: ports,
            tls_tcp: Vec::new(),
        };
        let fact = |ip: &str, ports: Vec<u16>, current: bool| BaselineFact {
            source: source.clone(),
            subject: format!("services:{ip}"),
            fact_type: "services".to_owned(),
            observed: observed(ip, ports),
            current,
        };
        let baseline = Baseline {
            facts: vec![
                fact("192.0.2.11", vec![80], true),
                fact("192.0.2.12", vec![22, 3389], true),
                fact("192.0.2.13", vec![445], true),
                fact("192.0.2.14", vec![445], false),
            ],
            truncated: false,
        };
        let finished = BTreeSet::from([source.clone()]);
        let diff = compare(&baseline, &seen, &finished);
        let counts = diff.counts["services"];
        assert_eq!(
            (counts.new, counts.changed, counts.unchanged, counts.gone),
            (1, 1, 1, 1)
        );
        assert_eq!(diff.items.len(), 3);
        let gone = diff
            .items
            .iter()
            .find(|item| item.change == FactChange::Gone)
            .expect("gone");
        assert_eq!(gone.subject, "services:192.0.2.13");
        // A probe whose command did not finish says nothing about absence.
        let diff = compare(&baseline, &seen, &BTreeSet::new());
        assert_eq!(diff.counts["services"].gone, 0);
    }

    #[test]
    fn results_without_a_vrf_are_left_out() {
        let seen = seen(
            &[result(1001, vec![services("192.0.2.10", vec![22])])],
            |_| None,
            at("2026-10-10T08:00:03Z"),
        );
        // Services facts carry no VRF, but the observation needs one to be built.
        assert!(seen.is_empty());
    }
}
