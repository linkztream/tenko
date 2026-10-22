//! Two figures of the lease path (WP7.2 acceptance), on the Raft store:
//!
//! - **The rebuild.** A store with 100,000 lease rows (and their client index rows) is
//!   closed and opened again, and the role's table is rebuilt from it
//!   (`rebuild_from_view`): the plan asks for under 5 seconds. Debug builds use 20,000
//!   rows unless `TENKO_REBUILD_LEASES` says otherwise; the figure in the results file
//!   comes from the release build with 100,000.
//! - **The commit latency** (ignored by default; `crash-test.sh` runs it in release):
//!   renewals at a paced rate (`TENKO_LATENCY_RATE`, default 1,000 per second, for
//!   `TENKO_LATENCY_SECS`, default 10) through the production lease store, timed from the
//!   hand-off to the completion that releases the ACK.
//!
//! Each prints one line (`REBUILD ...`, `LATENCY ...`) and appends it to the file
//! `TENKO_LEASE_FIGURES` names, when set.

mod lease_support;

use std::{
    collections::HashMap,
    io::Write as _,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};

use lease_support::{NODE, change, from_now};
use tenko_core::{
    PrefixId, Principal, SystemComponent, Timestamp, VrfId,
    dhcp::{BindingState, LeaseEventKind, LeaseRef, tables},
};
use tenko_dhcp::{
    lease::{CommitSettings, LeaseIndex, LeaseTable, SharedLeases, StoreLeases, rebuild_from_view},
    store::{LeaseStore, Ticket},
};
use tenko_store::{
    ReadConsistency, Store, WriteBatch,
    raft::{RaftStore, RaftStoreConfig},
};
use tokio_util::sync::CancellationToken;

fn figure(line: &str) {
    println!("{line}");
    if let Some(path) = std::env::var_os("TENKO_LEASE_FIGURES")
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

fn config(dir: &std::path::Path) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.fsync_probe_samples = 0;
    config
}

/// The address of lease `i`: 100,000 distinct keys. These are table keys of the test, not
/// addresses on any network; the leases fill VRFs of 250 rows each.
fn key_of(i: u32, vrfs: &[VrfId]) -> (VrfId, Ipv4Addr) {
    let vrf = vrfs[(i / 250) as usize];
    (
        vrf,
        Ipv4Addr::new(192, 0, 2, u8::try_from(i % 250).expect("small")),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_table_rebuilds_from_the_store_in_time() {
    let count: u32 = std::env::var("TENKO_REBUILD_LEASES")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) {
            20_000
        } else {
            100_000
        });
    let dir = tempfile::tempdir().expect("a directory");
    let data = dir.path().join("data");
    let vrfs: Vec<VrfId> = (0..count.div_ceil(250))
        .map(|_| VrfId::generate())
        .collect();
    let scope = PrefixId::generate();
    let filling = Instant::now();
    {
        let raft = RaftStore::open(config(&data))
            .await
            .expect("the store opens");
        let now = Timestamp::now();
        let mut i = 0;
        while i < count {
            let mut batch = WriteBatch::new(Principal::system(SystemComponent::Dhcp), now);
            for _ in 0..1_000 {
                if i == count {
                    break;
                }
                let (vrf, addr) = key_of(i, &vrfs);
                let lease = change(
                    LeaseEventKind::Granted,
                    vrf,
                    scope,
                    addr,
                    i + 256,
                    BindingState::Active,
                    now,
                    from_now(3_600),
                )
                .to_lease(NODE, None);
                batch
                    .put_typed(&tables::LEASES, &(vrf, addr), &lease)
                    .expect("encodes");
                batch
                    .put_typed(
                        &tables::LEASES_BY_CLIENT,
                        &(scope, lease.client.identity()),
                        &LeaseRef { vrf, addr },
                    )
                    .expect("encodes");
                i += 1;
            }
            raft.propose(batch).await.expect("written");
        }
        raft.shutdown().await.expect("the store shuts down");
    }
    let filled = filling.elapsed();

    let opening = Instant::now();
    let raft = RaftStore::open(config(&data))
        .await
        .expect("the store reopens");
    let opened = opening.elapsed();
    let view = raft.read(ReadConsistency::Local).await.expect("a view");
    let rebuilding = Instant::now();
    let table = rebuild_from_view(view.as_ref()).expect("the table rebuilds");
    let rebuilt = rebuilding.elapsed();
    assert_eq!(table.len(), count as usize);
    let (vrf, addr) = key_of(count - 1, &vrfs);
    assert!(table.get(vrf, addr).is_some());
    assert_eq!(table.client_index().len(), count as usize);
    figure(&format!(
        "REBUILD leases={count} rebuild_ms={} open_ms={} fill_ms={} build={}",
        rebuilt.as_millis(),
        opened.as_millis(),
        filled.as_millis(),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    ));
    assert!(
        rebuilt < Duration::from_secs(5),
        "the rebuild of {count} leases took {rebuilt:?}"
    );
    drop(view);
    raft.shutdown().await.expect("the store shuts down");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement; bench/phase3-dhcp/scripts/crash-test.sh runs it in release"]
#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    reason = "one paced run read top to bottom; rates and counts shown as decimals"
)]
async fn commit_latency_at_a_paced_rate() {
    let rate: u64 = std::env::var("TENKO_LATENCY_RATE")
        .ok()
        .and_then(|rate| rate.parse().ok())
        .unwrap_or(1_000);
    let secs: u64 = std::env::var("TENKO_LATENCY_SECS")
        .ok()
        .and_then(|secs| secs.parse().ok())
        .unwrap_or(10);
    // The store's snapshot cadence in entries, to tell the snapshots' share of the tail
    // from the commit path's.
    let snapshot_every: Option<u64> = std::env::var("TENKO_LATENCY_SNAPSHOT_EVERY")
        .ok()
        .and_then(|every| every.parse().ok());
    let dir = tempfile::tempdir().expect("a directory");
    let mut store_config = config(&dir.path().join("data"));
    if let Some(every) = snapshot_every {
        store_config.snapshot.every_entries = every;
    }
    let raft = Arc::new(
        RaftStore::open(store_config)
            .await
            .expect("the store opens"),
    );
    let store: Arc<dyn Store> = raft.clone();
    let leases = SharedLeases::new(LeaseIndex::new());
    let (lease_store, committer) =
        StoreLeases::new(store, leases.clone(), NODE, CommitSettings::default());
    let stop = CancellationToken::new();
    let task = tokio::spawn(committer.run(stop.clone()));
    // 720 leases over the three documentation networks, renewed in turn.
    let vrf = VrfId::generate();
    let scope = PrefixId::generate();
    let addrs: Vec<Ipv4Addr> = [[192, 0, 2], [198, 51, 100], [203, 0, 113]]
        .iter()
        .flat_map(|[a, b, c]| (10..250u8).map(move |d| Ipv4Addr::new(*a, *b, *c, d)))
        .collect();
    let total = rate * secs;
    let mut sent: HashMap<Ticket, Instant> = HashMap::new();
    let mut latencies: Vec<Duration> = Vec::with_capacity(usize::try_from(total).expect("fits"));
    let mut failed = 0u64;
    let mut done = Vec::new();
    let started = Instant::now();
    let period = Duration::from_secs(1).as_nanos() / u128::from(rate);
    let mut next = 0u64;
    while (latencies.len() as u64) + failed < total {
        // Send what is due by now.
        let due = u64::try_from(started.elapsed().as_nanos() / period).unwrap_or(u64::MAX);
        while next < total && next <= due {
            let i = usize::try_from(next).expect("small") % addrs.len();
            let client = u32::try_from(i).expect("small") + 256;
            let pending = change(
                if next < addrs.len() as u64 {
                    LeaseEventKind::Granted
                } else {
                    LeaseEventKind::Renewed
                },
                vrf,
                scope,
                addrs[i],
                client,
                BindingState::Active,
                Timestamp::now(),
                from_now(3_600),
            );
            next += 1;
            if lease_store.submit(&pending, Ticket(next)).is_ok() {
                sent.insert(Ticket(next), Instant::now());
            } else {
                failed += 1;
            }
        }
        let _ = tokio::time::timeout(Duration::from_micros(500), lease_store.completed()).await;
        lease_store.completions(&mut done);
        for completion in done.drain(..) {
            let Some(at) = sent.remove(&completion.ticket) else {
                continue;
            };
            if completion.outcome.is_ok() {
                latencies.push(at.elapsed());
            } else {
                failed += 1;
            }
        }
    }
    let elapsed = started.elapsed();
    let stats = raft.engine_stats();
    stop.cancel();
    task.await.expect("the committer");
    let slow = latencies
        .iter()
        .filter(|latency| **latency > Duration::from_millis(50))
        .count();
    latencies.sort_unstable();
    let pick = |q: f64| {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            reason = "an index into the sorted latencies"
        )]
        let index = ((latencies.len() as f64 - 1.0) * q).round() as usize;
        latencies[index].as_secs_f64() * 1_000.0
    };
    figure(&format!(
        "LATENCY rate={rate} secs={secs} committed={} failed={failed} achieved_per_s={:.0} p50_ms={:.2} p90_ms={:.2} p99_ms={:.2} p999_ms={:.2} max_ms={:.2} over_50ms={slow} entries={} snapshots={} snapshot_every={} build={}",
        latencies.len(),
        latencies.len() as f64 / elapsed.as_secs_f64(),
        pick(0.5),
        pick(0.9),
        pick(0.99),
        pick(0.999),
        pick(1.0),
        stats.entries_proposed,
        stats.snapshots_built,
        snapshot_every.map_or_else(|| "default".to_owned(), |every| every.to_string()),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    ));
    assert_eq!(failed, 0);
    assert_eq!(leases.read().len(), addrs.len());
    raft.shutdown().await.expect("the store shuts down");
}
