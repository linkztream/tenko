# ADR 0002: Storage and replication

- Status: Accepted with conditions (Spike A gate passed 2026-10-09)
- Date: 2026-10-09

## Context

The control plane holds configuration, IPAM data, DNS zones and views/policies. It must run on a single node at home and as a 3-node (or 5-node) controller cluster that survives the loss of a controller (OPS-03). The data plane must never depend on the control plane: DNS and DHCP nodes keep serving from a durable local copy when controllers are down (OPS-02).

Zones of more than 1 million records must work. Write rates are low: 100k AD clients re-registering every 24 hours produce about 1.2 updates per second. Bulk operations such as an AXFR import of a large zone are the exception.

DHCP leases behave differently: every DORA exchange is a write, so leases are hot data with a local scope (one failover pair).

Precedent: etcd recommends staying below 8 GB per cluster, and TiKV and CockroachDB run terabytes through multi-Raft. Several 1M-record zones remain far below the etcd guideline.

## Decision

1. **Embedded Raft over an embedded KV store.** `openraft` (0.9) is the Raft implementation and `redb` the KV store; both were confirmed by Spike A. Raft replicates changes, not data: the state lives in the KV store.
2. **One Raft group** holds configuration, IPAM, zones and policies. It is split into more groups only if later measurements point that way.
3. **Serving never touches Raft.** Each DNS node answers from an in-memory index built from its local copy; the Raft log is never in the query path.
4. **All writes are batched into Raft entries.** Bulk imports use large entries (10k records per entry). Steady-state updates are coalesced into entries as well, because openraft 0.9 awaits each log flush before taking the next client request; one entry per update saturates at about 120 writes per second. Snapshots are streamed to new nodes in chunks, and the log is purged behind the latest snapshot.
5. **DHCP leases stay outside Raft.** Leases are written to a local WAL on each DHCP node and synchronized between failover partners with the DHCP failover protocol (DHCP-07, DHCP-12).
6. **Every node keeps a local durable cache** of the data its roles need, so serving survives a controller outage.
7. **The store requires SSD or NVMe storage.** Rotating and SMR disks are unsupported for the data directory (OPS-19).

### Gate result (Spike A, 2026-10-09)

Measured in `bench/spike-a-raft` on an i9-13900K with 32 logical CPUs, a real in-process openraft cluster of 3 voters over redb, with 5,000,000 A records in one zone plus 20 percent PTR records (6,000,000 RRsets in total, 150.7 bytes per key and value on average). Data on a Samsung 960 EVO NVMe. Other benchmarks ran concurrently.

| Criterion | Threshold | Measured | Result |
|---|---|---|---|
| Peak RSS of one node at 5 M records | below 2 GB | 1.17 GiB (single-node process); 3.40 GiB for all three nodes in one process | Pass |
| Learner catch-up, in process | below 5 min | 19.1 s (snapshot build 3.6 s, install 17.6 s of which index rebuild 4.4 s) | Pass |
| Snapshot transfer at 1 Gbit/s | below 5 min | 896.6 MiB, 7.5 s at 125 MB/s | Pass |
| Lookup p99 under 1,000 updates/s, relative | below 2x baseline | 1.6 us against 1.4 us (1.14x), median of 3 rounds, 50,000 lookups/s on a follower | Pass |
| Lookup p99 under 1,000 updates/s, absolute | below 1 ms | 1.6 us median, 1.7 us worst round | Pass |

Recorded for reference:

- Bulk load of 6 M RRsets into 3 voters: 82 s (73k records/s); into a single voter: 26 s (228k records/s). 1.2 M RRsets into 3 voters: 5.4 s.
- Write latency under 1,000 coalesced updates/s: p50 58 to 133 ms, p99 154 to 202 ms, no errors. Entries carried 14 to 30 updates each.
- Disk per node at 6 M RRsets: `log.redb` 1.25 GiB, `sm.redb` 2.01 GiB after incremental load (2.4x raw), 1.00 GiB after a snapshot install (1.19x raw). Offline `compact()` reclaimed only 2.01 to 1.71 GiB in 50 s. Write amplification about 4.2x raw per voter.
- Change feed: the last 10,000 changes from a journal table in 1.8 to 2.6 ms (2.8 MiB), which is what an IXFR delta needs.
- Index memory: about 139 bytes per RRset (computed estimate), so one node holds roughly 9 to 11 M RRsets within the 2 GB budget; 24 M RRsets would need about 3.7 GiB.
- Same load on a Seagate ST4000DM004 SMR hard disk: 1.2 M RRsets took 501 s instead of 5.4 s (93x slower, fsync p50 44.5 ms, p99 207 ms), and the leader lost leadership under write load. This is the reason for condition 7.

### Conditions and follow-ups

- SSD or NVMe is mandatory for the store (decision 7); the first-run wizard warns when the data directory is on a rotating disk.
- Updates are coalesced into Raft entries (decision 4); the DNS UPDATE path returns to the client after the entry is applied, so dynamic-update latency is expected in the 50 to 200 ms range under heavy load.
- Disk usage is managed by an explicit snapshot-and-purge log policy and by re-seeding a node from a snapshot when `sm.redb` has grown past about 2x raw, rather than by online compaction.
- A compact index layout is needed before zones beyond about 10 M RRsets per node are supported.
- Still to build and measure in Phase 1: swapping the index in atomically during a snapshot install instead of clearing it, crash and restart recovery, failover, and a real network transport with serialization.

### Fallback (not needed)

If the gate had failed, Raft would hold only configuration, IPAM and policies, and zone data would be replicated between DDI nodes with built-in IXFR/NOTIFY in a primary/secondary arrangement (DNS-09). It is kept here for reference: it would avoid the Raft log copy of zone data and the per-entry flush serialization, but lose atomic IPAM and DNS commits across nodes and require a second replication system with its own per-zone primary election. The IXFR journal is needed in either design and is cheap.

## Consequences

- No external database to install, operate or secure; the home-lab profile stays a single process.
- One consistency model for all control-plane data, with linearizable writes and snapshot-based catch-up.
- Data plane independence follows directly: DNS and DHCP serve from local copies, and only configuration changes need a controller quorum.
- Two replication paths exist by design: Raft for control-plane state, and the failover protocol for leases. Backup and restore must be consistent across both, plus the vault keys (OPS-07).
- Raft membership changes, snapshot streaming, log purging and the write coalescer are DDI's responsibility rather than a database vendor's.
- The store needs about 4x the raw data size on disk per node and about 200 bytes of RAM per RRset including the index; capacity planning documents both.
- Home-lab hardware with only rotating disks must place the data directory on an SSD, or run the store on another node.

## Alternatives considered

- **PostgreSQL as the source of truth.** Mature and well understood, but it adds an external dependency with its own HA design (replication, failover tooling), raises the footprint well above the home-lab target, and would still need a local serving copy on every data-plane node to meet OPS-02.
- **SQLite now, clustering later.** Simple for a single node, but retrofitting replication changes consistency semantics and the data model late in the project, and a 3-node cluster that survives controller loss is already a Phase 1 exit criterion.
- **Multi-Raft from the start.** Scales further, but the expected data sizes do not justify the complexity. The single group can be split later if measurements require it.
- **Leases in Raft.** Rejected: every DORA would become a cluster-wide consensus write, adding latency to the DHCP path and coupling it to controller availability.
- **RocksDB instead of redb.** Not measured. redb met every criterion, is pure Rust and needs no C++ toolchain on Windows; RocksDB remains the alternative if redb's write amplification or lack of online compaction becomes a problem at larger scale.
