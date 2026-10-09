# Spike A: openraft + redb for a DNS zone of more than 1 million records

This crate is the go/no-go measurement for [ADR 0002](../../docs/adr/0002-storage-and-replication.md) (status: Proposed). The ADR proposes to keep DNS zone data, IPAM data and configuration in an embedded, Raft-replicated store (`openraft`) on top of an embedded key-value store (`redb`), to answer DNS queries from an in-memory index that is built from the local copy, and to keep DHCP leases outside Raft. The project owner's condition is that this design must work with more than 1 million records in a single DNS zone. Spike A loads 1 million and 5 million records into a real openraft cluster and measures whether the design stays inside the limits listed below.

The results of the published runs are in [`results/2026-10-09-windows.md`](results/2026-10-09-windows.md). This README does not repeat any measured numbers. Where a number could not be measured, the results file says so.

## What is measured

1. **Bulk load.** Records are proposed through the leader in batches (default 10,000 records per Raft entry, 4 entries in flight) until every voter has applied the last entry. Reported: wall time, records per second, process RSS (sampled every 100 ms), `log.redb` and `sm.redb` file sizes per node with redb statistics, bytes written by the process (OS I/O counters), number of entries in the serving index and a computed estimate of its heap size.
2. **Learner catch-up.** A snapshot is built on the leader, the leader's log is purged up to the snapshot, and a new learner is added. Reported: snapshot build time and size, in-process transfer time, install time (redb load plus index rebuild), total catch-up time, and snapshot bytes divided by 125 MB/s as the lower bound for a 1 Gbit/s link.
3. **Steady state.** Per round: 60 s of baseline lookups (50,000 per second, open loop, against a follower's index), then 60 s with 1,000 single-record updates per second through Raft plus the same lookups. The service time of each lookup goes into an HDR histogram. 3 rounds by default. A separate closed-loop probe measures the rate of one Raft entry per write (the "per-entry ceiling").
4. **Change feed.** Time to enumerate the last 10,000 changes from the `journal` table of a follower and, for comparison, from the Raft log of the leader.
5. **Offline compaction (optional).** `redb::Database::compact()` on one `sm.redb` after the cluster has shut down: file size before and after, and time.

Before each run a small fsync probe (200 tiny redb commits with `Durability::Immediate`) measures the fsync cost of the data disk. It is reported as a note, because that cost bounds Raft log appends.

### Pass criteria

The criteria are evaluated and printed as PASS or FAIL separately for every data disk (`--disk-label`) that has the relevant results. A criterion that no run measured at all is printed as "not measured" and counts as FAIL.

| # | Criterion | Threshold | Evaluated on |
|---|---|---|---|
| 1 | Peak RSS of one node | < 2 GB (2,000,000,000 bytes) at >= 5M forward-zone records | Bulk-load phase of the single-voter run (`--voters 1`), because three in-process nodes share one process |
| 2 | Learner catch-up, in-process | < 5 min | `add_learner` until the learner has applied the leader's last log index |
| 3 | Snapshot transfer at 1 Gbit/s | snapshot bytes / 125 MB/s < 5 min | Snapshot size of the catch-up run |
| 4 | Lookup p99 under write load, relative | < 2x baseline p99 | Median over the rounds, largest steady-state run |
| 5 | Lookup p99 under write load, absolute | < 1 ms | Every round, largest steady-state run |

## How it works

### Cluster and network

`src/cluster.rs` starts a real openraft 0.9.25 cluster inside one process: `--voters` nodes (default 3) with ids 1..N, node 1 initializes the membership. Each node has its own directory `<data-dir>/load-<records>-v<voters>/node-<id>/` with `log.redb` (Raft log and vote), `sm.redb` (state machine) and a `snapshots/` directory. Snapshots are only taken when the benchmark triggers them (`SnapshotPolicy::Never`).

`src/network.rs` is an in-process network. Each node runs one RPC task fed by tokio mpsc channels. AppendEntries and Vote messages are moved between nodes, not serialized. A snapshot is streamed as 1 MiB chunks through a bounded channel into a file in the receiving node's `snapshots/` directory and then installed with `Raft::install_full_snapshot`.

### Log store: group commit

`src/log_store.rs` implements the Raft log on redb. A synchronous fsync per `append()` would cap a leader at one write per fsync, so `append()` only encodes the entries, makes them readable from an in-memory pending map and queues them to a dedicated writer thread. The writer drains everything queued (up to 4096 operations) and commits it in ONE redb write transaction with `Durability::Immediate` (fsync). Only then does it fire the flush callbacks. Vote, truncate and purge go through the same FIFO queue, so all log I/O stays serialized.

### State machine and change journal

`src/state_machine.rs` keeps three redb tables in `sm.redb`:

- `records`: record key -> postcard `StoredRRset`.
- `journal`: change sequence number -> record with key, old value, new value and Raft log index. This is the IXFR source. It is trimmed to `--journal-retain` records (default 100,000).
- `sm_meta`: last applied log id, membership, next journal sequence number.

`apply()` writes the records, the journal records and the meta rows of all entries it receives in one redb transaction (durability set by `--sm-durability`, default `immediate`), commits, and then updates the serving index. Bulk-load entries are not journaled (a zone import has no IXFR history); update entries are, one journal record per changed RRset.

### Serving index

`src/index.rs` is a sharded in-memory map: 64 shards of `RwLock<HashMap<Box<[u8]>, Arc<[u8]>>>`. It holds the compact serving form of an RRset (TTL plus RDATA in wire format), not the management metadata (timestamps, source, IPAM reference, comment). Lookups never touch redb or Raft. Applying a batch write-locks only the shards it touches.

### Snapshots

A snapshot is built from a redb read transaction (MVCC, so applies continue while it is written) into a flat file: magic `DDISNAP1`, then length-prefixed key/value pairs. Install runs one redb write transaction that replaces the `records` table (and resets the `journal` table), then clears the serving index and rebuilds it from the file. A real server would build a new index and swap it in. The spike does not.

### Steady-state write path and the coalescer

openraft 0.9.25 awaits each log flush inline before it handles the next client request (`RaftCore::append_to_log`). With one Raft entry per client write, a leader is therefore capped at roughly one write per fsync, whatever the group-commit writer does. The steady-state test puts the updates through a coalescer instead: it packs whatever single-record updates have arrived (up to `--max-coalesce`) into one Raft entry, with `--proposals-inflight` proposals outstanding. Every update is still an individual change with its own journal record. Its latency is measured from enqueue until it is applied on the leader. The closed-loop per-entry ceiling probe reports the rate without coalescing, so both numbers are available.

### Data model and synthetic data

Key: `zone_id (u32 BE) | lower-case owner name relative to the zone | 0x00 | rtype (u16 BE)`. Value: postcard of `StoredRRset { ttl, rdata: Vec<wire rdata>, meta: { created, modified, source, ipam_ref, comment } }`.

`src/gen.rs` generates records deterministically from `(--records, --ptr-percent, --seed)`:

- `--records N` creates N A RRsets `host-<n>` in the single forward zone `example.test`. Addresses rotate over the three RFC 5737 /24 networks. These are only 768 addresses, so A RDATA repeats on purpose; the benchmark needs many distinct owner names, not many distinct addresses.
- `--ptr-percent P` (default 20) adds P PTR RRsets per 100 hosts in the three reverse zones `2.0.192.in-addr.arpa`, `100.51.198.in-addr.arpa` and `113.0.203.in-addr.arpa`. Because of the 768-address limit, PTR owners use RFC 2317-style sub-labels `<octet>.<block>` to stay unique.
- The average encoded entry (key plus value) is about 150 bytes.

So `--records 5000000` means 5,000,000 RRsets in one zone and 6,000,000 RRsets in total.

## How to run

### Build

```
export PATH="/c/Users/plm/.cargo/bin:$PATH"   # Git Bash on the Windows workstation; Rust is in C:\Users\plm\.cargo\bin
cd bench/spike-a-raft
cargo build --release
```

The binary is `target/release/spike-a-raft.exe`. The crate is standalone (empty `[workspace]` table), uses edition 2024 and `#![forbid(unsafe_code)]`. Dependencies are pinned in `Cargo.toml` and `Cargo.lock` (openraft 0.9.25, redb 4.3.0, tokio, clap, serde, postcard, serde_bytes, serde_json, sysinfo, hdrhistogram, rand, anyhow, tracing). The report lists the exact resolved versions.

### Before you start

- Put `--data-dir` on an SSD. The default (`data`, relative to the working directory) is on whatever disk holds the repository. On the Windows workstation that is a 5400 rpm SMR hard disk, where Raft log fsyncs dominate everything.
- Check free space. Plan for roughly 4x the raw record bytes per node for `log.redb` plus `sm.redb` before compaction, plus one snapshot file per snapshot (about the raw size). The results file lists the measured sizes; a 3-voter run at 5M records with `--catch-up` needs well over 15 GB to be safe. Sizes scale roughly with the record count.
- The run directory (`<data-dir>/load-<records>-v<voters>/`) is wiped at the start of every run.
- Do not run anything else heavy on the machine while a benchmark runs.

### Subcommands

`spike-a-raft --help` and `spike-a-raft <subcommand> --help` list every option.

- `load`: one run in one process. `--records N` (default 1,000,000), `--voters` (default 3), and the flags `--steady`, `--catch-up`, `--compact` select the extra phases. `--steady` needs at least 2 voters. Steady-state options: `--rounds 3 --seconds 60 --write-rate 1000 --lookup-rate 50000 --change-feed 10000 --max-coalesce 1000 --proposals-inflight 4 --ceiling-seconds 10 --ceiling-concurrency 16`. Common options: `--data-dir data --disk-label "..." --batch 10000 --ptr-percent 20 --log-cache-mb 64 --sm-cache-mb 256 --sm-durability immediate|none --max-payload-entries 4 --inflight 4 --producers 4 --journal-retain 100000 --heartbeat-ms 1000 --election-min-ms 5000 --rss-interval-ms 100 --seed 42 --json-out FILE`.
- `all`: the standard suite, each phase in a fresh child process so that peak RSS is per phase. For each size in `--sizes` (default `1000000,5000000`) it runs a 3-voter load with catch-up and compaction; the size equal to `--steady-records` (default 5,000,000) also runs steady state and the change feed. Then it runs a single-voter load at the largest size for per-node RSS. It writes `results/2026-10-09-windows.json` and `.md`. Options: `--append`, `--skip-single-node`, `--skip-steady`, `--extra FILE` (Markdown inserted verbatim right after the pass-criteria summary, for example the methodology notes and the recommendation).
- `report --json results/2026-10-09-windows.json --out results/2026-10-09-windows.md [--extra FILE]`: renders the Markdown again from a saved JSON.
- `collect --input FILE[::DISK-LABEL] ... [--json ...] [--out ...] [--extra FILE]`: assembles the report from individual `load --json-out` files. The optional `::DISK-LABEL` supplies a label for files that did not record one.

### Examples

The commands below are the ones used for the published results. Replace `<ssd-dir>` and `<disk>` with a directory on an SSD and a description of that disk.

```
# 1M forward-zone records, 3 voters: load, steady state, change feed, learner catch-up, compaction
target/release/spike-a-raft load --records 1000000 --voters 3 --steady --catch-up --compact --data-dir <ssd-dir> --disk-label "<disk>" --json-out data/phase-nvme-1m-v3.json

# 5M, one node per process (per-node RSS) + learner catch-up + compaction
target/release/spike-a-raft load --records 5000000 --voters 1 --catch-up --compact --data-dir <ssd-dir> --disk-label "<disk>" --json-out data/phase-nvme-5m-v1.json

# 5M, 3 voters: steady state, change feed, learner catch-up, compaction
target/release/spike-a-raft load --records 5000000 --voters 3 --steady --catch-up --compact --data-dir <ssd-dir> --disk-label "<disk>" --json-out data/phase-nvme-5m-v3.json

# assemble the report (the last input is a run on the hard disk, kept for comparison)
target/release/spike-a-raft collect --input data/phase-nvme-1m-v3.json --input data/phase-nvme-5m-v3.json --input data/phase-nvme-5m-v1.json --input "data/phase-hdd-1m-v3.json::D: Seagate ST4000DM004 SATA HDD (SMR)" --extra results/recommendation-2026-10-09.md
```

The `all` subcommand runs a similar suite in one command: `target/release/spike-a-raft all --data-dir <ssd-dir> --disk-label "<disk>"`.

### Output

- Progress and the tables of each phase go to the terminal; the pass criteria are printed at the end.
- `--json-out FILE` writes the result of one `load` run as JSON. `data/` is git-ignored.
- `all`, `collect` and `report` write `results/2026-10-09-windows.json` and `.md` (paths can be changed with `--json` and `--out`).

## Caveats

Read these before drawing conclusions from the numbers.

- **In-process network.** Nodes talk through channels. Messages are moved, not serialized, and there is no network latency, loss or bandwidth limit. The cost of encoding and decoding entries on the wire is not measured. The 1 Gbit/s snapshot criterion is the line-rate lower bound (snapshot bytes / 125 MB/s), not a measured transfer.
- **Shared process and disk.** All voters share one process, one set of CPUs, one allocator and one disk. Per-node RSS therefore comes from the separate single-voter run, and its peak includes the load generator and the redb page caches. Disk contention is about three times what a real deployment sees, where each node has its own disk.
- **RSS measurement.** RSS is the Windows working set read through `sysinfo` every 100 ms. A short peak between two samples can be missed.
- **Bytes written.** The "bytes written" figure comes from the OS I/O counters of the process. It counts bytes passed to write calls, not what the device physically wrote.
- **Coalescer.** The steady-state writes are coalesced into Raft entries because openraft 0.9 handles one log flush at a time (see above). The reported update latency includes the time an update waits in the coalescer queue. A client that cannot be batched would be limited by the per-entry ceiling, which is reported separately.
- **Lookups.** A lookup is a call into the in-memory index from one thread, paced open loop. The recorded time is the service time of that call. There is no UDP, no DNS message parsing and no multi-threaded query load, so the p99 criteria say something about the index and its lock behavior under apply, not about end-to-end DNS latency.
- **Timeouts.** openraft 0.9 uses the heartbeat interval as the timeout of an AppendEntries RPC. A follower that needs longer than `--heartbeat-ms` to append and fsync a batch makes the RPC time out. The benchmark runs with a heartbeat of 1000 ms and an election timeout of 5000 to 10000 ms; a production configuration needs its own tuning and testing.
- **Snapshot install.** The install clears the serving index and rebuilds it in place. Lookups on the installing node would miss during the rebuild. A real server must build the new index aside and swap it in. The install also resets the `journal` table, so a node that joined by snapshot has no change history older than the snapshot.
- **Journal on bulk import.** Bulk-load entries are not journaled, so the change feed measurement covers only the update entries written by the steady-state phase.
- **No recovery tests.** Crash and restart recovery, leader failover under load, membership changes other than adding one learner, and the log replay that `--sm-durability none` relies on after a crash are not tested.
- **Index size is computed.** The index size in the report is an estimate from entry sizes and table capacity. The measured memory figure is the process RSS.
- **Noise.** Other processes on the workstation can add noise. The runs were not isolated from them.
- **One machine.** The results come from one Windows workstation. The `D:` drive (where this repository lives) is a 5400 rpm SMR SATA hard disk with idle fsync latency of tens of milliseconds. The main measurements therefore used a directory on an NVMe SSD, and one 1M run on the hard disk is kept for comparison. Always put `--data-dir` on an SSD. Other hardware, operating systems and file systems will give different numbers.

## Files

```
Cargo.toml, Cargo.lock   Standalone crate, pinned dependencies
src/main.rs              CLI (load, all, report, collect), pass criteria, child-process orchestration
src/bench.rs             Benchmark phases: bulk load, catch-up, steady state, per-entry ceiling, change feed, compaction, fsync probe
src/cluster.rs           Starts and drives the in-process openraft cluster
src/network.rs           In-process Raft network (mpsc channels, chunked snapshot streaming)
src/log_store.rs         Raft log and vote on redb (log.redb) with group commit
src/state_machine.rs     State machine on redb (sm.redb): records, journal, meta; snapshot build and install
src/index.rs             Sharded in-memory serving index
src/model.rs             Key and value encoding, serving form
src/gen.rs               Deterministic synthetic record generator
src/raft_types.rs        openraft type configuration, Request and RecordBatch
src/measure.rs           RSS sampler, HDR latency recorder, open-loop pacing, disk sizes, formatting, machine info
src/results.rs           Result structures (JSON)
src/report.rs            Markdown rendering of the results
results/                 Published results (Markdown and JSON) and the written recommendation
data/                    Phase JSON files, logs and scratch data (git-ignored)
```
