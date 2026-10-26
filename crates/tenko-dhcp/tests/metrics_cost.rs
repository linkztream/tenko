//! The cost of the DHCPv4 metrics on the DORA path in isolation (M33's stand-in, WP9.5).
//!
//! Neither `tenko serve` nor the example server has a switch that turns the role's
//! counters off, so M33 as the plan states it (M26 with the metrics on and off) cannot run
//! yet. This measurement does the metrics work of one DORA exchange on one thread, as the
//! worker and the committer do it (`crates/tenko-dhcp/src/server/mod.rs`): the DISCOVER
//! counted and its DISCOVER-to-OFFER time read and recorded, the REQUEST counted, its
//! commit time and its REQUEST-to-ACK time read and recorded. The results file sets the
//! time per exchange against the CPU time of an exchange.
//!
//! `TENKO_METRICS_ROUNDS` (default 5) rounds of `TENKO_METRICS_EXCHANGES` (default
//! 5,000,000) exchanges; one line `METRICS ...` per round and one with the median.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use tenko_dhcp::v4::{
    MessageType,
    engine::{Action, Answer, metrics::WorkerMetrics},
};

fn micros(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// The metrics work of `exchanges` DORA exchanges on `metrics`.
fn run(metrics: &WorkerMetrics, exchanges: u64) -> Duration {
    let discover = Answer {
        request: Some(MessageType::Discover),
        action: Action::Commit,
        selector: None,
    };
    let request = Answer {
        request: Some(MessageType::Request),
        action: Action::Commit,
        selector: None,
    };
    let start = Instant::now();
    for _ in 0..exchanges {
        let received = Instant::now();
        metrics.count(black_box(&discover));
        metrics.exchange[0].record(micros(received));
        let received = Instant::now();
        metrics.count(black_box(&request));
        let handed_off = Instant::now();
        metrics.commit.record(micros(handed_off));
        metrics.exchange[1].record(micros(received));
    }
    start.elapsed()
}

/// The same counters and histograms with a fixed duration: the atomics without the clock.
fn run_without_clock(metrics: &WorkerMetrics, exchanges: u64) -> Duration {
    let discover = Answer {
        request: Some(MessageType::Discover),
        action: Action::Commit,
        selector: None,
    };
    let request = Answer {
        request: Some(MessageType::Request),
        action: Action::Commit,
        selector: None,
    };
    let start = Instant::now();
    for i in 0..exchanges {
        let micros = black_box(i & 0x3ff);
        metrics.count(black_box(&discover));
        metrics.exchange[0].record(micros);
        metrics.count(black_box(&request));
        metrics.commit.record(micros);
        metrics.exchange[1].record(micros);
    }
    start.elapsed()
}

/// E32 and OPS-21 (M33's stand-in): the metrics work of one DORA exchange, in nanoseconds.
/// It includes the clock reads that only the histograms need.
#[test]
#[ignore = "a measurement; run in release, the results file records it"]
#[allow(
    clippy::cast_precision_loss,
    reason = "nanoseconds per exchange shown as a decimal"
)]
fn e32_ops_21_the_metrics_of_one_dora_exchange_cost_in_isolation() {
    let rounds: usize = std::env::var("TENKO_METRICS_ROUNDS")
        .ok()
        .and_then(|rounds| rounds.parse().ok())
        .unwrap_or(5);
    let exchanges: u64 = std::env::var("TENKO_METRICS_EXCHANGES")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(5_000_000);
    let metrics = WorkerMetrics::default();
    // Warm up the cache lines and the clock.
    run(&metrics, exchanges / 10);
    let mut per = Vec::with_capacity(rounds);
    let mut atomics = Vec::with_capacity(rounds);
    for round in 1..=rounds {
        let took = run(&metrics, exchanges);
        let ns = took.as_nanos() as f64 / exchanges as f64;
        let bare = run_without_clock(&metrics, exchanges).as_nanos() as f64 / exchanges as f64;
        println!(
            "METRICS round={round} exchanges={exchanges} ns_per_exchange={ns:.1} \
             without_clock={bare:.1}"
        );
        per.push(ns);
        atomics.push(bare);
    }
    per.sort_by(f64::total_cmp);
    atomics.sort_by(f64::total_cmp);
    println!(
        "METRICS median_ns_per_exchange={:.1} median_without_clock={:.1} build={}",
        per[per.len() / 2],
        atomics[atomics.len() / 2],
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    let snapshot = WorkerMetrics::total(std::slice::from_ref(&metrics));
    assert!(
        snapshot.packets("discover", "answered") > 0,
        "the counters moved"
    );
}
