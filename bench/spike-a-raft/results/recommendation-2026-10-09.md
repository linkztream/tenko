## How these numbers were produced (read this first)

- **Replication mode: real openraft.** Every number comes from an openraft 0.9.25 cluster
  (3 voters, plus 1 learner for the catch-up test; 1 voter plus 1 learner for the per-node RSS
  run) running in one process over an in-process channel network. The simulated-replication
  fallback was not needed and was not used.
- **Data disk.** The repository drive `D:` is a Seagate ST4000DM004 (4 TB, 5400 rpm, SMR SATA
  HDD). Its idle fsync cost, measured with 200 small redb commits, was p50 44.5 ms / p99 207 ms.
  A 1M-record bulk load there took 500.8 s (2,396 records/s), about 93 times slower than the
  same load on an NVMe SSD (5.36 s). With every Raft log append and every
  state-machine apply waiting for an fsync, this disk measures the disk, not the design. The
  main runs therefore put `--data-dir` in a temporary directory on `C:` (Samsung 960 EVO NVMe
  SSD, fsync p50 1.7 to 3.6 ms in the probes). The 1M HDD run is kept in the tables (rows
  labelled `D: ...`) for comparison. Nothing at 5M was run on the HDD. Exploratory runs on the
  HDD at 120,000 RRsets (not in the tables) reached 2 writes/s with one Raft entry per write,
  and the leader lost leadership when 1,000 uncoalesced writes/s were offered, because openraft
  queued them faster than the disk could flush.
- **Record counts.** `--records N` is the number of A RRsets in the single forward zone
  `example.test`. Each run adds 20 % PTR RRsets in three reverse zones. "5M" therefore means
  5,000,000 RRsets in one zone and 6,000,000 RRsets in total. The encoded key plus value
  averages 150.7 bytes (key, TTL, wire-format RDATA and DDI management metadata).
- **Per-node RSS.** Three in-process voters share one process, so the 2 GB per-node criterion
  is judged on a single-voter process (`Voters = 1` row). The whole 3-voter process is shown
  for reference. RSS is the Windows working set, sampled every 100 ms, and it includes the redb
  page caches (64 MiB for `log.redb` + 256 MiB for `sm.redb` per node).
- **Shared machine.** Other benchmark processes ran on the workstation during these
  measurements. The steady-state table shows how many logical CPUs other processes kept busy in
  each window (9 to 23 of 32 in the 5M run). One earlier 1M run (not in the tables) had
  baseline lookup p99 values of 17.6 to 26.5 us during heavy outside load, while its
  under-write windows measured 1.3 to 19.6 us. Single-window p99 values at the microsecond level
  are therefore noisy on this machine. That is why the criterion uses the median of 3 rounds.
- **Writes are coalesced.** openraft 0.9.25 awaits each log flush inline before it handles the
  next client request (`RaftCore::append_to_log`). One Raft entry per update therefore caps a
  leader at about one write per fsync: 120 writes/s at 6M RRsets on the NVMe disk, measured
  with 16 closed-loop writers. The steady-state writer offered 1,000 single-record updates/s
  into a coalescer, which packed whatever had arrived into one entry (14 to 30 updates per entry
  on average). Each update still has its own journal record, and its latency is measured from
  enqueue to "applied on the leader". The log store's group commit batches on followers but not
  on the leader: the leader made 10,415 fsynced log commits for 10,413 entries.
- **Change-feed log scan, 5M row.** The Raft-log figure in the 5M row came from an earlier scan
  that decoded the last 10,000 Raft entries, which held about 180,000 coalesced changes, before
  it counted 10,000. The scan was then changed to stop after 10,000 changes, and the 1M row
  uses the corrected scan: 0.9 ms, faster than the journal (2.6 ms), because one coalesced entry
  carries about 13 changes. The journal figures are not affected.
- **Commands used** (binary built with `cargo build --release`, data dir on the NVMe disk):
  - `spike-a-raft load --records 1000000 --voters 3 --steady --catch-up --compact --data-dir <nvme> --disk-label "C: Samsung 960 EVO NVMe SSD" --json-out data/phase-nvme-1m-v3.json`
  - `spike-a-raft load --records 5000000 --voters 3 --steady --catch-up --compact ... --json-out data/phase-nvme-5m-v3.json`
  - `spike-a-raft load --records 5000000 --voters 1 --catch-up --compact ... --json-out data/phase-nvme-5m-v1.json`
  - `spike-a-raft load --records 1000000 --voters 3 --catch-up --compact --data-dir data --json-out data/phase-hdd-1m-v3.json` (on `D:`)
  - `spike-a-raft collect --input ... --extra results/recommendation-2026-10-09.md`

## Observations about redb

These come from the measured tables: disk usage, compaction and bytes written.

- **Write amplification.** During the 6M-RRset bulk load the process wrote 4.18 times the raw
  key+value bytes per voter (11.3 GB written for 862 MiB of raw data on 3 voters). The single
  voter wrote 4.21 times. Roughly, one copy goes to the Raft log, one to the state-machine
  B-tree, and the rest is copy-on-write page rewrites and commit metadata.
- **File size.** After an incremental load, `sm.redb` is 2.01 GiB for 862 MiB of stored
  key+value bytes (2.38x; 3.02x at 1.2M RRsets). redb's own statistics count 1.10 GiB of it as
  fragmented, meaning free or partly used pages. `log.redb` is 1.25 GiB (1.49x raw), because
  every 10,000-record entry (about 1.5 MB) is a large value. Per node that comes to 3.26 GiB of
  redb files for 862 MiB of zone data, before any snapshot files.
- **Compaction.** `Database::compact()` needs exclusive access: no open transactions and a
  `&mut Database`. In practice that means the node is offline for the state-machine file.
  Offline compaction shrank the incrementally loaded 6M `sm.redb` only from 2.01 GiB to
  1.71 GiB, and it took 49.9 s. The 1.2M file went from 514 MiB to 349 MiB in 9.8 s. Compaction
  moves pages but does not repack half-full B-tree pages. A file built by a snapshot install is
  much denser: the learner's `sm.redb` was 1.00 GiB (1.19x raw) right after install, because
  the snapshot is written in key order in one transaction. Compacting that file reclaimed only
  75 MiB (third compaction row: in the single-voter run the compacted node is the learner).
  Re-seeding a node from a snapshot is therefore the effective way to "compact" it.
- **MVCC read transactions** made snapshot building cheap and non-blocking. 6M RRsets
  (897 MiB) were streamed to a file in 3.6 to 4.5 s while applies continued.
- The redb page caches are part of RSS and need an explicit size. The default is 1 GiB per
  database file, and a node has two files.

## What would change at 20M records

This section is a linear extrapolation from the measured per-entry figures. It was not
measured. 20M forward-zone records plus 20 % PTR is 24M RRsets, four times the 6M runs.

- **Memory.** The serving index costs about 139 bytes per RRset (computed estimate: 795 MiB at
  6M). The measured single-node RSS was 1.17 GiB at 6M including 320 MiB of redb cache. At 24M
  that extrapolates to about 3.1 GiB of index and about 3.7 GiB (4.0 GB) RSS per node. That is
  above the 2 GB budget. The current `HashMap<Box<[u8]>, Arc<[u8]>>` layout uses two heap
  allocations per RRset. A packed layout (arena or sorted arrays with offsets, about 60 to
  80 bytes per RRset) or serving very large zones from redb plus a cache would be needed.
- **Disk.** About 13 GiB of redb files per node before compaction, plus 3.5 GiB per snapshot
  file.
- **Catch-up.** A snapshot of about 3.5 GiB would take about 30 s at 1 Gbit/s. The measured
  in-process install rate was about 340,000 RRsets/s (17.6 s for 6M), so roughly 70 to 90 s
  plus transfer, still well under 5 minutes if it stays near linear.
- **Bulk load.** At the measured 73,000 records/s for 3 voters on one shared NVMe disk, a full
  24M-RRset import takes about 5.5 minutes.
- **Change feed.** Journal reads do not depend on zone size: 10,000 changes took 1.8 ms at 6M
  and 2.6 ms at 1.2M.

## Fallback: Raft for configuration only, zone data via built-in IXFR/NOTIFY

What the fallback gains:

- Zone data no longer pays for Raft. There is no second full copy in the Raft log (1.25 GiB per
  node at 6M), and updates are not serialized behind openraft's per-entry flush.
- Secondaries replicate with standard DNS mechanisms (AXFR/IXFR/NOTIFY). This interoperates
  with third-party secondaries and is well understood operationally.
- Zone serving does not depend on cluster quorum. Secondaries keep answering from their last
  copy.

What it loses or must rebuild:

- **One writer per zone.** A single primary per zone means primary failover needs its own
  election, which Raft gives for free.
- **Consistency.** IPAM and DNS changes are no longer committed atomically across nodes. Read
  your own writes on another node becomes eventual.
- **Two replication systems.** Raft remains for configuration and IPAM, plus zone transfer, so
  there are two mechanisms to operate and test.
- **Journal still needed.** The IXFR journal has to exist either way. The spike's journal table
  is cheap (10,000 changes enumerated in about 2 ms) and works the same under both designs.
- **New nodes.** Bootstrapping a new node from an AXFR of a 6M-RRset zone moves about the same
  bytes as the measured 897 MiB snapshot, so catch-up time does not improve.

## Recommendation

**GO WITH CONDITIONS** for the Raft (openraft) + redb design at the measured scale (5M records
in one zone, 6M RRsets per node), on SSD storage.

All gate criteria passed on the NVMe disk at 6M RRsets:

- **Per-node peak RSS:** 1.17 GiB (1,254,023,168 bytes), against < 2 GB.
- **Learner catch-up:** 19.1 s in-process, and the 897 MiB snapshot takes 7.5 s at 1 Gbit/s,
  against < 5 min for each.
- **Follower lookup p99 under 1,000 updates/s:** median 1.6 us against a baseline of 1.4 us
  (1.14x), worst round 1.7 us, against < 2x baseline and < 1 ms.

Conditions:

1. **SSD/NVMe storage is a hard requirement.** On the SMR HDD a 1M-record load was about 93
   times slower than on NVMe, and per-entry fsyncs made consensus writes unusable.
2. **Write batching is required with openraft 0.9.** Updates must be coalesced into Raft
   entries (group commit at the proposal layer), as the spike did. One entry per update
   saturates at about 120 writes/s per cluster on this disk. Coalesced writes reached
   1,000 updates/s with p50 58 to 133 ms and p99 154 to 202 ms end-to-end latency (3 voters on
   one shared disk). Re-check this when a stable openraft release pipelines log IO.
3. **The memory budget holds to roughly 9-11M RRsets per node with the current index layout.**
   This is an extrapolation. Above that, or for the 20M case, a compact index layout is needed
   before the 2 GB budget can be met.
4. **Plan disk for about 4x raw zone size per node** (log + state machine), plus snapshot files.
   Treat snapshot re-seeding, rather than `compact()`, as the way to reclaim space. Make the
   log purge policy explicit: snapshot plus purge regularly so `log.redb` does not keep a full
   second copy.
5. **Production gaps the spike does not cover.** The serving index must be rebuilt off to the
   side and swapped in during a snapshot install; the spike clears it in place. Crash and
   restart recovery and a real network transport also have to be built and measured.
