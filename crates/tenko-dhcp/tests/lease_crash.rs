//! The crash test (E24 single-node stand-in, M32; WP7.2 content 6): a node under load is
//! killed (`SIGKILL` on Unix, `TerminateProcess` on Windows) and restarted, over and over,
//! and after every kill the committed rows, the table rebuilt from them and the ACKs the
//! clients received are compared: no acknowledged lease lost, no address on two clients.
//!
//! The `dhcp` role does not exist in the binary yet (WP7.5), so the node is a child process
//! of this test binary that drives the lease path through its library entry points: the
//! Raft store on a data directory, the table rebuilt from it, the reference allocator over
//! one scope of 192.0.2.0/24 with the offer hold, the production lease store with its
//! committer, and a load of 200 clients that request, renew and release (the shape of a
//! perfdhcp run, at a few thousand changes per second). The child writes one line per ACK
//! to its standard output only after the ticket completed, which is after the durable
//! commit: a line the parent has read is an ACK a client received. The parent kills the
//! child at a pseudo-random moment, reads what reached the pipe, opens the data directory
//! and checks:
//!
//! 1. every ACK is in the rows: the row of its address was written at the ACK's revision or
//!    later, and at that revision it is the ACK's client, state and end;
//! 2. every ACK's history row is there once the start's catch-up ran (ADR 0030: the history
//!    is written by the asynchronous writer, and the catch-up rebuilds what the kill lost
//!    from the lease rows), except for an ACK that a later ACK of the same address
//!    superseded within the lost interval: those are counted as lost, as the ADR says;
//! 3. the table rebuilt from the store equals the rows and the stored client index, and the
//!    index is the one the rows imply;
//! 4. the history never shows an address granted to a client while another client's
//!    binding on it had not ended, and no client holds two bound rows in the scope.
//!
//! `TENKO_CRASH_KILLS` sets the number of kills (default 3; the results file runs 20 with
//! `bench/phase3-dhcp/scripts/crash-test.sh`), `TENKO_CRASH_REPORT` a file for the figures.
//!
//! The store runs with the default deferred durability of the state machine (one durable
//! checkpoint of `sm.redb` a second, the Raft log durable before every ACK), so a kill
//! falls between a log commit and the state machine's next durable commit nearly every
//! time: the restart replays the log from the last applied index of the durable state, and
//! check 1 holds only because it does (WP9.6, point (f) of the package).

mod lease_support;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
    io::{BufRead, BufReader, Write as _},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use ipnet::Ipv4Net;
use lease_support::{NODE, client_id, mac};
use tenko_core::{
    PrefixId, RangeId, Revision, Timestamp, VrfId,
    dhcp::{
        BindingState, DdnsPolicy, LeaseEventKind, LeaseTimes, lease::MAX_IDENTITY, tables,
        write_identity,
    },
};
use tenko_dhcp::{
    allocator::{AdmitAll, Allocator, ReferenceAllocator, Request, SingleNode},
    image::{ConfigImage, ImageBuilder, PoolImage, ScopeImage},
    lease::{
        CommitSettings, LeaseTable, MemLeaseTable, OfferTable, PendingChange, SharedLeases,
        StoreLeases, batch::NoObservations, derived, rebuild_from_view,
    },
    store::{LeaseStore, Ticket},
};
use tenko_store::{
    KeyRange, ReadConsistency, ReadViewExt, Store,
    raft::{RaftStore, RaftStoreConfig},
};
use tokio_util::sync::CancellationToken;

const CHILD: &str = "TENKO_LEASE_CRASH_CHILD";
const SEED: &str = "TENKO_LEASE_CRASH_SEED";
const CLIENTS: u32 = 200;
const OUTSTANDING: usize = 64;
const LEASE_SECS: u64 = 3_600;

fn scope_id() -> PrefixId {
    "0190b7b2-0000-7000-8000-00000000d4c2"
        .parse()
        .expect("an id")
}

fn vrf_id() -> VrfId {
    "0190b7b2-0000-7000-8000-00000000d4c1"
        .parse()
        .expect("an id")
}

fn image() -> ConfigImage {
    let mut builder = ImageBuilder::new(Revision::ZERO);
    builder.scope(ScopeImage {
        prefix: scope_id(),
        vrf: vrf_id(),
        network: "192.0.2.0/24".parse::<Ipv4Net>().expect("a network"),
        authoritative: true,
        restricted: false,
        server_id: None,
        lease: LeaseTimes::fixed(u32::try_from(LEASE_SECS).expect("small")),
        shared_network: None,
        pools: vec![PoolImage {
            range: "0190b7b2-0000-7000-8000-00000000d4c3"
                .parse::<RangeId>()
                .expect("an id"),
            first: Ipv4Addr::new(192, 0, 2, 10),
            last: Ipv4Addr::new(192, 0, 2, 249),
            lease: LeaseTimes::fixed(u32::try_from(LEASE_SECS).expect("small")),
            classes: Vec::new(),
            options: Vec::new(),
        }],
        excluded: Vec::new(),
        options: Vec::new(),
        classes: Vec::new(),
        ddns: DdnsPolicy::default(),
    });
    builder.build()
}

fn identity(client: u32) -> Vec<u8> {
    let mut out = [0u8; MAX_IDENTITY];
    let len = write_identity(1, &mac(client), client_id(client).as_deref(), &mut out);
    out[..len].to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A small deterministic generator (`SplitMix64`).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn store_config(dir: &Path) -> RaftStoreConfig {
    let mut config = RaftStoreConfig::new(dir);
    config.fsync_probe_samples = 0;
    config
}

// ---------------------------------------------------------------------------------------
// The node (child process)

#[test]
#[ignore = "the node of the crash test, started by the_node_loses_no_acknowledged_lease"]
fn child_node() {
    let Some(dir) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let seed = std::env::var(SEED)
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(node(dir, seed));
}

#[allow(
    clippy::too_many_lines,
    reason = "the node's load loop, read top to bottom"
)]
async fn node(dir: PathBuf, seed: u64) {
    let started = Instant::now();
    let raft = Arc::new(
        RaftStore::open(store_config(&dir))
            .await
            .expect("the store opens"),
    );
    let opened = started.elapsed();
    let view = raft.read(ReadConsistency::Local).await.expect("a view");
    let rebuilding = Instant::now();
    let table = rebuild_from_view(view.as_ref()).expect("the table rebuilds");
    let rebuilt = rebuilding.elapsed();
    let rows = table.len();
    drop(view);
    let recent: Vec<_> = table.sorted_rows().into_values().collect();
    let leases = SharedLeases::new(table);
    let store: Arc<dyn Store> = raft.clone();
    let (lease_store, committer) = StoreLeases::new(
        Arc::clone(&store),
        leases.clone(),
        NODE,
        CommitSettings::default(),
    );
    let stop = CancellationToken::new();
    tokio::spawn(committer.run(stop.clone()));
    // ADR 0030: the start rebuilds the history a kill lost, as the role does.
    derived::catch_up(
        store.as_ref(),
        recent,
        &NoObservations,
        lease_store.derived(),
    )
    .await
    .expect("the catch-up");
    let image = image();
    let scope = image.scope(scope_id()).expect("the scope").clone();
    let offers = OfferTable::new(Duration::from_secs(10), 4_096);
    let identities: Vec<Vec<u8>> = (0..CLIENTS).map(identity).collect();
    let mut rng = Rng(seed);
    let mut outstanding: HashMap<Ticket, (u32, PendingChange)> = HashMap::new();
    let mut ticket = 0u64;
    let mut done = Vec::new();
    let stdout = std::io::stdout();
    {
        let mut out = stdout.lock();
        writeln!(
            out,
            "READY rows={rows} open_ms={} rebuild_ms={}",
            opened.as_millis(),
            rebuilt.as_millis()
        )
        .expect("stdout");
        out.flush().expect("stdout");
    }
    loop {
        while outstanding.len() < OUTSTANDING {
            let client = u32::try_from(rng.below(u64::from(CLIENTS))).expect("small");
            if outstanding.values().any(|(busy, _)| *busy == client) {
                break;
            }
            let id = &identities[client as usize];
            let now = Timestamp::now();
            let ends = now
                .checked_add(Duration::from_secs(LEASE_SECS))
                .expect("a time");
            let change = {
                let table = leases.read();
                match table.by_client(scope.prefix, id) {
                    Some(lease) if lease.is_bound(now) => {
                        let (kind, state, ends) = if rng.below(100) < 15 {
                            (LeaseEventKind::Released, BindingState::Released, now)
                        } else {
                            (LeaseEventKind::Renewed, BindingState::Active, ends)
                        };
                        PendingChange::new(
                            kind,
                            scope.vrf,
                            scope.prefix,
                            lease.addr,
                            1,
                            &mac(client),
                            client_id(client).as_deref(),
                            state,
                            now,
                            ends,
                        )
                    }
                    _ => {
                        let request = Request {
                            image: &image,
                            scope: &scope,
                            identity: id,
                            hardware: id,
                            admission: &AdmitAll,
                            requested: None,
                            leases: &*table,
                            offers: &offers,
                            ownership: &SingleNode,
                            now,
                        };
                        let Some(choice) = ReferenceAllocator.pick(&request) else {
                            break;
                        };
                        if !offers.hold(scope.prefix, choice.addr(), id, now) {
                            break;
                        }
                        PendingChange::new(
                            LeaseEventKind::Granted,
                            scope.vrf,
                            scope.prefix,
                            choice.addr(),
                            1,
                            &mac(client),
                            client_id(client).as_deref(),
                            BindingState::Active,
                            now,
                            ends,
                        )
                    }
                }
            };
            ticket += 1;
            if lease_store.submit(&change, Ticket(ticket)).is_ok() {
                outstanding.insert(Ticket(ticket), (client, change));
            } else {
                break;
            }
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), lease_store.completed()).await;
        lease_store.completions(&mut done);
        if done.is_empty() {
            continue;
        }
        let mut out = stdout.lock();
        for completion in done.drain(..) {
            let Some((client, change)) = outstanding.remove(&completion.ticket) else {
                continue;
            };
            offers.release(change.scope, change.addr);
            if let Ok(revision) = completion.outcome {
                writeln!(
                    out,
                    "ACK {} {:?} {} {} {:?} {} {}",
                    revision.0,
                    change.kind,
                    change.addr,
                    hex(&identities[client as usize]),
                    change.state,
                    change.ends.unix_nanos(),
                    change.cltt.unix_nanos(),
                )
                .expect("stdout");
            }
        }
        out.flush().expect("stdout");
    }
}

// ---------------------------------------------------------------------------------------
// The harness (parent)

#[derive(Debug, Clone)]
struct Ack {
    revision: u64,
    kind: String,
    addr: Ipv4Addr,
    identity: String,
    state: String,
    ends: i128,
}

fn parse_ack(line: &str) -> Option<Ack> {
    let mut parts = line.strip_prefix("ACK ")?.split(' ');
    Some(Ack {
        revision: parts.next()?.parse().ok()?,
        kind: parts.next()?.to_owned(),
        addr: parts.next()?.parse().ok()?,
        identity: parts.next()?.to_owned(),
        state: parts.next()?.to_owned(),
        ends: parts.next()?.parse().ok()?,
    })
}

/// One run of the node: started, killed after `after`, its lines collected.
struct Run {
    ready: String,
    acks: Vec<Ack>,
}

fn run_node(dir: &Path, seed: u64, after: Duration) -> Run {
    let mut child = Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "child_node",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD, dir)
        .env(SEED, seed.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the node starts");
    let stdout = child.stdout.take().expect("piped");
    let (lines, received) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let ready = loop {
        let line = received
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("the node reports ready");
        // libtest writes "test child_node ... " before the node's first line.
        if let Some(at) = line.find("READY") {
            break line[at..].to_owned();
        }
    };
    std::thread::sleep(after);
    // The kill of the node's own pid: SIGKILL on Unix, TerminateProcess on Windows.
    child.kill().expect("the node is killed");
    child.wait().expect("the node is gone");
    reader.join().expect("the reader");
    let acks = received
        .try_iter()
        .filter_map(|line| parse_ack(&line))
        .collect();
    Run { ready, acks }
}

/// The start's catch-up of the derived rows on a reopened store (ADR 0030), as the role
/// runs it, through a writer flushed before it returns.
async fn catch_up(raft: &RaftStore) -> derived::CatchUp {
    let store: Arc<dyn Store> = Arc::new(raft.clone());
    let view = raft.read(ReadConsistency::Local).await.expect("a view");
    let table = rebuild_from_view(view.as_ref()).expect("the table rebuilds");
    drop(view);
    let (writer, flusher) =
        derived::DerivedWriter::new(Arc::clone(&store), derived::DerivedSettings::default());
    let stop = CancellationToken::new();
    let task = tokio::spawn(flusher.run(stop.clone()));
    let rebuilt = derived::catch_up(
        store.as_ref(),
        table.sorted_rows().into_values(),
        &NoObservations,
        &writer,
    )
    .await
    .expect("the catch-up");
    writer.flush().await;
    stop.cancel();
    task.await.expect("the flusher");
    rebuilt
}

/// Checks the data directory against every ACK received so far; `gaps` collects the
/// addresses whose history a kill cut (the catch-up rebuilt their last row). Returns the
/// rows, the history rows and the ACKs whose history row a later change superseded.
#[allow(clippy::too_many_lines, reason = "the four checks, read top to bottom")]
async fn verify(dir: &Path, acks: &[Ack], gaps: &mut HashSet<Ipv4Addr>) -> (usize, usize, usize) {
    let raft = RaftStore::open(store_config(dir))
        .await
        .expect("the store reopens");
    gaps.extend(
        catch_up(&raft)
            .await
            .addresses
            .into_iter()
            .map(|(_, addr)| addr),
    );
    let view = raft.read(ReadConsistency::Local).await.expect("a view");
    let mut rows = BTreeMap::new();
    let mut revisions = BTreeMap::new();
    for (key, lease, revision) in view
        .scan_typed(&tables::LEASES, KeyRange::all(), usize::MAX, false)
        .expect("the leases")
    {
        rows.insert(key, lease);
        revisions.insert(key, revision);
    }
    let index: BTreeMap<_, _> = view
        .scan_typed(
            &tables::LEASES_BY_CLIENT,
            KeyRange::all(),
            usize::MAX,
            false,
        )
        .expect("the index")
        .into_iter()
        .map(|(key, value, _)| (key, value))
        .collect();
    let history = view
        .scan_typed(&tables::HISTORY, KeyRange::all(), usize::MAX, false)
        .expect("the history");

    // 1. No acknowledged lease lost.
    let vrf = vrf_id();
    for ack in acks {
        let key = (vrf, ack.addr);
        let row = rows
            .get(&key)
            .unwrap_or_else(|| panic!("the row of {ack:?} is lost"));
        let revision = revisions[&key];
        assert!(
            revision.0 >= ack.revision,
            "{ack:?} regressed to revision {revision}"
        );
        if revision.0 == ack.revision {
            assert_eq!(hex(&row.client.identity()), ack.identity, "{ack:?}");
            assert_eq!(format!("{:?}", row.state), ack.state, "{ack:?}");
            assert_eq!(row.ends.unix_nanos(), ack.ends, "{ack:?}");
        }
    }
    // 2. Every ACK's history row is there, or a later ACK of its address superseded it
    // within the interval the kill lost (ADR 0030). A rebuilt row records the state of the
    // lease row; a renewal's rebuilt row reads as a grant.
    let events: HashSet<(Ipv4Addr, String, i128, String)> = history
        .iter()
        .map(|(_, event, _)| {
            (
                event.addr,
                hex(&event.client.identity()),
                event.ends.unix_nanos(),
                format!("{:?}", event.kind),
            )
        })
        .collect();
    let mut lost = 0;

    for ack in acks {
        let kinds = if ack.kind == "Renewed" {
            vec![ack.kind.clone(), "Granted".to_owned()]
        } else {
            vec![ack.kind.clone()]
        };
        let found = kinds
            .into_iter()
            .any(|kind| events.contains(&(ack.addr, ack.identity.clone(), ack.ends, kind)));
        if found {
            continue;
        }
        // A later commit of the address (acknowledged or not before the kill) took the
        // lease row on; the catch-up rebuilt its history row only.
        let superseded = revisions[&(vrf, ack.addr)].0 > ack.revision;
        assert!(superseded, "the history row of {ack:?} is missing");
        lost += 1;
        assert!(
            gaps.contains(&ack.addr),
            "{ack:?} lost its history row outside a cut"
        );
    }
    // 3. The rebuilt table equals the rows and the index.
    let table = rebuild_from_view(view.as_ref()).expect("rebuilt");
    assert_eq!(table.sorted_rows(), rows);
    assert_eq!(table.client_index(), index);
    let implied = MemLeaseTable::from_rows(rows.values().cloned());
    for ((scope, identity), target) in &index {
        let lease = implied.by_client(*scope, identity).expect("indexed");
        assert_eq!((lease.vrf, lease.addr), (target.vrf, target.addr));
    }
    // 4. No address on two clients, read from the history of every address whose history
    // has no lost row (an address with a gap is held to checks 1 and the bound rows).
    let mut holder: HashMap<Ipv4Addr, (Vec<u8>, BindingState, Timestamp)> = HashMap::new();
    for (_, event, _) in history
        .iter()
        .filter(|(_, event, _)| !gaps.contains(&event.addr))
    {
        let identity = event.client.identity();
        if event.state.holds_address()
            && let Some((held, state, ends)) = holder.get(&event.addr)
        {
            assert!(
                !(state.holds_address() && *held != identity && *ends > event.at),
                "{} was given to a second client while the first held it: {event:?}",
                event.addr
            );
        }
        holder.insert(event.addr, (identity, event.state, event.ends));
    }
    let now = Timestamp::now();
    let mut bound: HashMap<(PrefixId, Vec<u8>), usize> = HashMap::new();
    for lease in rows.values().filter(|lease| lease.is_bound(now)) {
        *bound
            .entry((lease.scope, lease.client.identity()))
            .or_default() += 1;
    }
    assert!(
        bound.values().all(|count| *count == 1),
        "a client holds two bound rows"
    );
    let counts = (rows.len(), history.len(), lost);
    drop(view);
    raft.shutdown().await.expect("the store shuts down");
    counts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_loses_no_acknowledged_lease() {
    let kills: u64 = std::env::var("TENKO_CRASH_KILLS")
        .ok()
        .and_then(|kills| kills.parse().ok())
        .unwrap_or(3);
    let dir = tempfile::tempdir().expect("a directory");
    let data = dir.path().join("data");
    let mut rng = Rng(0x00E2_4C4A);
    let mut acks: Vec<Ack> = Vec::new();
    let mut gaps: HashSet<Ipv4Addr> = HashSet::new();
    let mut report = String::new();
    for kill in 1..=kills {
        let after = Duration::from_millis(if kill % 5 == 0 {
            20
        } else {
            300 + rng.below(1_200)
        });
        let seed = rng.next();
        let data_dir = data.clone();
        let run = tokio::task::spawn_blocking(move || run_node(&data_dir, seed, after))
            .await
            .expect("the run");
        acks.extend(run.acks.iter().cloned());
        let (rows, history, lost) = verify(&data, &acks, &mut gaps).await;
        let line = format!(
            "kill {kill}: after {} ms, {} ACKs (total {}), {} rows, {} history rows, \
             {lost} superseded history rows lost; {}",
            after.as_millis(),
            run.acks.len(),
            acks.len(),
            rows,
            history,
            run.ready
        );
        println!("{line}");
        report.push_str(&line);
        report.push('\n');
    }
    assert!(!acks.is_empty(), "the load produced ACKs");
    let summary = format!(
        "CRASH OK: {kills} kills, {} ACKs checked, none lost, no address on two clients",
        acks.len()
    );
    println!("{summary}");
    report.push_str(&summary);
    report.push('\n');
    if let Some(path) = std::env::var_os("TENKO_CRASH_REPORT") {
        std::fs::write(path, report).expect("the report");
    }
}

/// The check after a power-off (the lab VM runs of M32, the owner's step): the node ran as
/// `child_node` on the VM with its standard output kept on another host, the VM was powered
/// off and on again, and this checks the data directory `TENKO_LEASE_CRASH_VERIFY` against
/// the ACK lines in the file `TENKO_LEASE_CRASH_ACKS` (the procedure is in
/// `bench/phase3-dhcp/results/`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "the check of a power-off run; run by hand on the lab VM"]
async fn verify_after_power_off() {
    let (Some(dir), Some(acks)) = (
        std::env::var_os("TENKO_LEASE_CRASH_VERIFY").map(PathBuf::from),
        std::env::var_os("TENKO_LEASE_CRASH_ACKS").map(PathBuf::from),
    ) else {
        return;
    };
    let text = std::fs::read_to_string(&acks).expect("the ACK file");
    let acks: Vec<Ack> = text
        .lines()
        .filter_map(|line| line.find("ACK ").and_then(|at| parse_ack(&line[at..])))
        .collect();
    let (rows, history, lost) = verify(&dir, &acks, &mut HashSet::new()).await;
    println!(
        "POWER-OFF OK: {} ACKs checked, {rows} rows, {history} history rows ({lost} superseded lost), none lost, no address on two clients",
        acks.len()
    );
}
