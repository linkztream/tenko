# ADR 0002: Storage and replication

- Status: Proposed
- Date: 2026-10-09

## Context

The control plane holds configuration, IPAM data, DNS zones and views/policies. It must run on a single node at home and as a 3-node (or 5-node) controller cluster that survives the loss of a controller (OPS-03). The data plane must never depend on the control plane: DNS and DHCP nodes keep serving from a durable local copy when controllers are down (OPS-02).

Zones of more than 1 million records must work. Write rates are low: 100k AD clients re-registering every 24 hours produce about 1.2 updates per second, while Raft on a LAN sustains thousands of writes per second. Bulk operations such as an AXFR import of a large zone are the exception.

DHCP leases behave differently: every DORA exchange is a write, so leases are hot data with a local scope (one failover pair).

Precedent: etcd recommends staying below 8 GB per cluster, and TiKV and CockroachDB run terabytes through multi-Raft. Several 1M-record zones remain far below the etcd guideline.

## Decision

Proposed, pending the Phase 0 gate below:

1. **Embedded Raft over an embedded KV store.** `openraft` is the Raft candidate; `redb` (pure Rust) or RocksDB is the KV candidate. Raft replicates changes, not data: the state lives in the KV store, roughly 150 to 300 MB on disk per 1 M records.
2. **One Raft group** holds configuration, IPAM, zones and policies. It is split into more groups only if the gate measurements point that way.
3. **Serving never touches Raft.** Each DNS node answers from an in-memory index built from its local copy; the Raft log is never in the query path.
4. **Bulk writes are batched.** An AXFR of 1 M records becomes about 100 log entries of 10k records each, not 1 M entries. Snapshots are streamed to new nodes in chunks, and the log is compacted behind the latest snapshot.
5. **DHCP leases stay outside Raft.** Leases are written to a local WAL on each DHCP node and synchronized between failover partners with the DHCP failover protocol (DHCP-07, DHCP-12).
6. **Every node keeps a local durable cache** of the data its roles need, so serving survives a controller outage.

### Gate (Spike A, Phase 0)

Load a zone with 1 M records and with 5 M records. Measure import time, RSS, catch-up time for a new node, IXFR delta generation, and p99 query latency under 1k updates per second.

| Criterion | Pass threshold |
|---|---|
| RSS at 5 M records | below 2 GB |
| New node catch-up | below 5 minutes over 1 Gbit |
| p99 query latency under 1k updates/s | unaffected |

If the gate passes, this ADR moves to Accepted with the measured results added. If it fails, a new ADR records the fallback and supersedes this one.

### Fallback

Raft holds only configuration, IPAM and policies. Zone data is replicated between DDI nodes with built-in IXFR/NOTIFY in a primary/secondary arrangement, which DDI must implement anyway for interop with BIND and Windows (DNS-09).

## Consequences

- No external database to install, operate or secure; the home-lab profile stays a single process.
- One consistency model for all control-plane data, with linearizable writes and snapshot-based catch-up.
- Data plane independence follows directly: DNS and DHCP serve from local copies, and only configuration changes need a controller quorum.
- Two replication paths exist by design: Raft for control-plane state, and the failover protocol for leases. Backup and restore must be consistent across both, plus the vault keys (OPS-07).
- Large imports depend on batching and chunked snapshots being implemented correctly; Spike A tests exactly this.
- Raft membership changes, snapshot streaming and log compaction become DDI's responsibility rather than a database vendor's.

## Alternatives considered

- **PostgreSQL as the source of truth.** Mature and well understood, but it adds an external dependency with its own HA design (replication, failover tooling), raises the footprint well above the home-lab target, and would still need a local serving copy on every data-plane node to meet OPS-02.
- **SQLite now, clustering later.** Simple for a single node, but retrofitting replication changes consistency semantics and the data model late in the project, and a 3-node cluster that survives controller loss is already a Phase 1 exit criterion.
- **Multi-Raft from the start.** Scales further, but the expected data sizes do not justify the complexity. The single group can be split later if measurements require it.
- **Leases in Raft.** Rejected: every DORA would become a cluster-wide consensus write, adding latency to the DHCP path and coupling it to controller availability.
