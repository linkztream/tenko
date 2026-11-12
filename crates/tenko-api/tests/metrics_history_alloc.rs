//! The fold of the dashboard's history allocates nothing (M82, OPS-21), as a test: a counting
//! global allocator (`stats_alloc`, as the DNS and DHCP allocation tests use it) wraps the
//! system allocator, and `History::fold` must not allocate over two hours of simulated ticks
//! with every role, uneven intervals, gaps and a clock that jumps back. The first check proves
//! that the counter sees an allocation, so a pass means something.
//!
//! The allocator counts every thread of the process, so the binary is its own harness
//! (`harness = false` in Cargo.toml), for the reason `crates/tenko-dns/tests/alloc.rs` gives:
//! libtest's main thread allocates right after it has spawned the test thread. The binary
//! speaks what nextest and `cargo test` send: `--list` names the test, a name filter selects it.
//!
//! The time of a fold, and of the rest of a tick of the sampler (the registry snapshot, the
//! sample and its encoding; without the server's status reads) over 600 ticks taken back to
//! back, whose intervals are under a millisecond so that they fold nothing, are printed, not
//! asserted: a debug build on a shared workstation measures nothing of M81, which runs on the
//! released binary. Run with `--nocapture`.

use std::{alloc::System, hint::black_box, time::Instant};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tenko_api::{
    dto::events::{
        MetricsDhcp, MetricsDns, MetricsDnsConnections, MetricsDnsRecursion, MetricsHost,
        MetricsSample,
    },
    sse::metrics::{History, NoSources, Sampler},
    state::AppState,
};
use tenko_core::Timestamp;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const TEST_NAME: &str = "the_fold_allocates_nothing";
/// Flags of libtest that take a value, which is not a name filter.
const VALUED_FLAGS: [&str; 5] = ["--format", "--test-threads", "--color", "--skip", "-Z"];

/// A whole hour since the Unix epoch, in milliseconds.
const T0: i64 = 1_792_998_000_000;

/// Samples with every role, two hours of uneven ticks with gaps and a clock that jumps back,
/// built before the measured section.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "made-up figures"
)]
fn samples() -> Vec<MetricsSample> {
    let mut at = T0;
    (0..7_200u32)
        .map(|i| {
            let interval = 700 + u64::from(i * 7_919 % 700);
            at += i64::try_from(interval).expect("small") + if i % 600 == 0 { 30_000 } else { 0 };
            if i % 1_801 == 0 {
                at -= 20_000;
            }
            let value = f64::from(i % 97) / 97.0;
            let time = Timestamp::from_unix_nanos(i128::from(at) * 1_000_000).expect("a time");
            let mut sample = MetricsSample::empty(None, time);
            sample.interval_ms = interval;
            sample.api.requests_per_second = value * 900.0;
            sample.store.commit_p99_ms = (value > 0.3).then_some(value * 40.0);
            let mut dns = MetricsDns {
                queries_per_second: value * 5_000.0,
                ..MetricsDns::default()
            };
            dns.cache.hits_per_second = value * 300.0;
            dns.cache.misses_per_second = 50.0;
            dns.recursion = Some(MetricsDnsRecursion::default());
            dns.connections = Some(MetricsDnsConnections::default());
            sample.dns = Some(dns);
            sample.dhcp = Some(MetricsDhcp::default());
            let total: u64 = 1 << 33;
            sample.host = Some(MetricsHost {
                cpu_percent: Some(value * 100.0),
                memory_total: Some(total),
                memory_available: Some((total as f64 * (1.0 - value * 0.9)) as u64),
                disk_total: Some(total),
                disk_available: Some((total as f64 * 0.5) as u64),
            });
            sample
        })
        .collect()
}

fn the_fold_allocates_nothing() {
    let samples = samples();
    let mut history = History::new(Timestamp::now());

    // The counter sees an allocation.
    let region = Region::new(GLOBAL);
    black_box(vec![0_u8; 64]);
    assert!(region.change().allocations > 0, "the counter counts");

    let region = Region::new(GLOBAL);
    let started = Instant::now();
    for sample in &samples {
        history.fold(black_box(sample));
    }
    let elapsed = started.elapsed();
    let change = region.change();
    assert_eq!(
        (change.allocations, change.reallocations),
        (0, 0),
        "History::fold allocated {} bytes over {} folds",
        change.bytes_allocated,
        samples.len()
    );
    println!(
        "metrics history: {} folds of 25 figures in {elapsed:.2?}, {:.1} µs a fold (this build)",
        samples.len(),
        elapsed.as_secs_f64() * 1e6 / f64::from(u32::try_from(samples.len()).expect("small"))
    );
    assert!(history.at().is_some());
}

/// Prints the time of 600 ticks of a sampler taken back to back: the median and the 99th
/// percentile.
fn tick_cost() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let mut times = runtime.block_on(async {
        let sampler = Sampler::new(AppState::default(), std::sync::Arc::new(NoSources));
        let mut times = Vec::with_capacity(600);
        for _ in 0..600 {
            let started = Instant::now();
            black_box(sampler.take().await);
            times.push(started.elapsed());
        }
        times
    });
    times.sort_unstable();
    println!(
        "metrics history: a tick of the sampler: p50 {:.2?}, p99 {:.2?} over 600 (this build)",
        times[300], times[593]
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--list") {
        if !args.iter().any(|arg| arg == "--ignored") {
            println!("{TEST_NAME}: test");
        }
        return;
    }
    let exact = args.iter().any(|arg| arg == "--exact");
    let mut after_valued = false;
    let mut filters = Vec::new();
    for arg in &args {
        if after_valued {
            after_valued = false;
        } else if arg.starts_with('-') {
            after_valued = VALUED_FLAGS.contains(&arg.as_str());
        } else {
            filters.push(arg.as_str());
        }
    }
    let selected = filters.is_empty()
        || filters.iter().any(|filter| {
            (exact && *filter == TEST_NAME) || (!exact && TEST_NAME.contains(filter))
        });
    if !selected {
        println!("\nrunning 0 tests\n\ntest result: ok. 0 passed; 1 filtered out\n");
        return;
    }
    println!("\nrunning 1 test");
    the_fold_allocates_nothing();
    tick_cost();
    println!("test {TEST_NAME} ... ok\n\ntest result: ok. 1 passed; 0 failed\n");
}
