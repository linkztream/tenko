# Tenko DDI Architecture

Tenko DDI is a DNS, DHCP and IPAM stack written in Rust with an embedded SolidJS web UI. It replaces Active Directory-integrated Windows DNS and DHCP and scales from a single home-lab box to an enterprise deployment with controller clusters, anycast DNS and DHCP failover pairs. This document describes the runtime architecture: roles, storage and replication, the intent and reconciliation model, the connector framework, the device move job, the repository layout and the engineering rules.

Requirements and design constraints are cited by ID and defined in [REQUIREMENTS.md](REQUIREMENTS.md). Security profile toggles are defined in [SECURITY-PROFILES.md](SECURITY-PROFILES.md), migration sources and runbooks in [MIGRATION.md](MIGRATION.md), RFC targets in [CONFORMANCE.md](CONFORMANCE.md) and phases with their done-when criteria in [ROADMAP.md](ROADMAP.md). Decisions are recorded as ADRs:

| ADR | Decision | Status |
|---|---|---|
| [ADR 0001](adr/0001-implementation-language.md) | Implementation language: Rust | Accepted |
| [ADR 0002](adr/0002-storage-and-replication.md) | Storage and replication: embedded Raft over embedded KV | Proposed, pending the Spike A gate |
| [ADR 0003](adr/0003-embedded-spa-ui.md) | Embedded SPA UI: SolidJS + TypeScript | Accepted |
| [ADR 0004](adr/0004-single-binary-roles.md) | Single binary with roles | Accepted |
| [ADR 0005](adr/0005-ipam-intent-hub.md) | IPAM as intent hub | Accepted |
| [ADR 0006](adr/0006-connector-architecture.md) | Connector architecture | Accepted |
| [ADR 0007](adr/0007-delivery-order.md) | Delivery order: platform and IPAM, then DNS, DHCP, AD integration and migration, enterprise | Accepted |

## Overview and principles

Tenko separates three concerns, all of them roles of one binary (ADR 0004):

- **Control plane** (`controller` role): API, UI, Raft membership, authentication, vault, IPAM logic and scheduler. It holds the replicated state, makes decisions and runs jobs.
- **Data plane** (`dns` and `dhcp` roles): answers DNS queries and serves DHCP leases from durable local copies of zones, leases and configuration.
- **Discovery** (`probe` role): passive and active scanning and SNMP polling inside one network segment. It reports observations to the controllers.

```
  UI (SolidJS SPA)     tenko CLI    Terraform, Ansible, webhooks (Phase 5)
         |                 |                      |
         +-----------------+----------------------+
                           | public REST API (OpenAPI, SSE)
                           v
  +--------------------------------------------------------------+
  | CONTROL PLANE (role: controller)                             |      connectors
  |  +--------------+  +--------------+  +--------------+        |
  |  | controller 1 |  | controller 2 |  | controller 3 |        | ->  UniFi Network Application
  |  +--------------+  +--------------+  +--------------+        | ->  Proxmox VE
  |  Raft group: config, IPAM, zones, policies                   | ->  Home Assistant
  +--------------------------------------------------------------+
                           | gRPC over mTLS (internal CA)
          +----------------+-------------------+
          |                                    |
  +-----------------------+          +--------------------------------+
  | DATA PLANE            |          | DATA PLANE                     |
  | dns node              |          | dhcp node  <->  dhcp node      |
  | local zone copy,      |          | local config, lease WAL,       |
  | in-memory index       |          | failover protocol              |
  +-----------------------+          +--------------------------------+
     keeps serving when every controller is down (OPS-02)

  +------------------+   +------------------+   +------------------+
  | probe: LAN A     |   | probe: LAN B     |   | probe: DMZ       |   one probe per segment,
  +------------------+   +------------------+   +------------------+   DMZ is its own trust zone
  DISCOVERY: ARP/ND, mDNS, LLDP, SNMPv3, active scans -> observations to the controllers
```

Design principles:

- **The data plane survives the control plane** (OPS-02). dns and dhcp nodes serve from local copies when controllers are down.
- **API first** (API-01, API-02). Every capability is in the public REST API. The UI and the CLI use only that API.
- **IPAM is the intent hub** (ADR 0005). Intent recorded in IPAM propagates to DHCP, DNS and network controllers; observations flow back.
- **Every change is a job** (IPAM-17). Each job has a preview, steps, a status, a timeout and rollback. Nothing happens silently.
- **Security profiles are toggle bundles, not code paths.** A single implementation serves all profiles; profiles only set toggle values.
- **Secrets are envelope-encrypted** (IAM-15), with a DEK per secret and a KEK from the OS key store.
- **Memory safety** (ADR 0001, API-16). Rust throughout, `unsafe` forbidden except where an ADR allows it, and a fuzz target for every network parser (API-15).
- **Performance is I/O bound** (CON-01). The design invests in socket sharding, batching and lock-free caches, not in hand-tuned CPU code.
- **Measure before assuming.** Phase 0 spikes A, B and C decide the replication design, the DNS library and I/O strategy, and the embedded UI approach before later phases build on them.
- **Language.** Code, comments and documentation are in English and the repository is written as if it were public (API-13). The UI is available in Swedish and English, follows the browser language with English as fallback, and accepts additional languages as XLIFF 2.0 packs at runtime (API-08, API-21).'

## Single binary and roles

`tenko` is one statically linked binary that runs any combination of roles on a node (ADR 0004, OPS-01). The `tenko` crate orchestrates the roles inside the process and integrates with the Windows Service Control Manager or systemd.

### Roles and modules

Roles and modules answer two different questions. **Roles** say where a component runs: `controller` is the management plane (API, UI, store, authentication, vault, jobs), `dns` and `dhcp` are the data plane, `probe` is discovery; any node runs any combination, so DHCP can sit on its own node apart from DNS and the controller (OPS-01). **Modules** say which parts of the product an installation has at all: IPAM, DNS, DHCP and Discovery can each be switched off (OPS-25). A disabled module registers no routes, no UI area and no tasks, and the integrations between modules (reverse zones from IPAM, DDNS from DHCP, reservations from intent, observations into IPAM) exist only when both sides are enabled. The controller role is therefore not "the IPAM": a DNS-only installation is `controller` plus `dns` on one node with the DNS module alone, and a DHCP-only installation the same with DHCP. Slimmer binaries through compile-time features are possible later but not planned; the runtime switch is enough for memory, because a disabled module allocates nothing.

| Role | Responsibility |
|---|---|
| `controller` | API, UI, Raft member, authentication, vault, IPAM logic, scheduler |
| `dns` | Authoritative server plus forwarder/cache (recursion in Phase 5), local zone copy |
| `dhcp` | DHCPv4 and DHCPv6 server, failover partner, local lease WAL |
| `probe` | Passive and active scanning, SNMP polling in its segment |

ARP and ND do not cross routers, so one probe is needed per network segment (SCAN-01). Active scanning needs raw sockets: CAP_NET_RAW on Linux, Npcap on Windows, and explicit configuration inside an unprivileged LXC container (SCAN-04).

### Deployment shapes

| Shape | Layout |
|---|---|
| Home | All roles in one process on one box. Target: idle below 100 MB RSS with all roles (OPS-15). |
| Enterprise | 3 to 5 controllers, N `dns` nodes behind anycast, `dhcp` nodes in failover pairs per site, one probe per segment. |
| Reference home-lab environment (three LANs plus a DMZ) | One node with all roles plus one probe per segment. The DMZ probe is its own trust zone (SCAN-01). |

DNS clients do not balance load themselves (CON-04), so replication between `dns` nodes is not load distribution. Anycast with health-based route withdrawal arrives in Phase 5 (OPS-17). DHCP "load balancing" means the failover protocol between partners (CON-05).

### Platform integration

- **Windows:** runs as a Windows service with Service Control Manager integration and Windows Event Log output (OPS-10). From Phase 4 it runs as a gMSA or domain account so that Kerberos works (OPS-11).
- **Linux:** systemd unit, capabilities instead of root, seccomp, non-root user (OPS-13).
- **Containers:** Docker bridge NAT breaks DHCP broadcast and DNS source addresses. Macvlan or host networking is required, and the deployment files document it with examples (OPS-14).

## Data plane independence

The data plane never depends on the control plane (OPS-02). This is the central availability property of the design.

- Each `dns` and `dhcp` node keeps a durable local copy of zones, leases and configuration.
- Nodes keep answering queries and serving leases when the database, the UI or all controllers are down.
- There is no database round trip in the DHCP DORA path or in the DNS query path. The Raft log is never in the query path.
- Configuration changes require a controller quorum. Serving does not.

Expected behavior under failure:

| Failure | Effect |
|---|---|
| One controller of three is lost | The cluster keeps its quorum. Configuration changes continue and `dns` and `dhcp` nodes are unaffected (OPS-03). |
| Quorum is lost | Configuration changes are refused. `dns` and `dhcp` nodes keep answering and keep allocating and renewing leases from their local state (OPS-02). |
| A DHCP failover partner is lost | The surviving partner continues under the failover protocol's partner-down state (DHCP-12). |
| A probe is lost | No new observations arrive from its segment. Serving is unaffected. |

Verification: in a 3-node cluster one controller is killed and the `dns` and `dhcp` nodes must continue to serve (OPS-03).

## Storage and replication

Status: **Accepted with conditions** (ADR 0002). The Spike A gate passed on 2026-10-09; the measured result and the conditions are summarized below.

The design is an embedded Raft store (`openraft`) over an embedded KV store (`redb`), confirmed with more than 1 M records in a single zone. One Raft group carries configuration, IPAM, zones and policies. It is split into more groups only if later measurements point that way. Four design choices are built in from the start.

1. **Raft replicates changes, not data.** State lives in an embedded KV store (`redb`). Measured: 6 M RRsets are 862 MiB of raw key and value data, 2.0 GiB in `sm.redb` after an incremental load and 1.0 GiB after a snapshot re-seed. Serving uses an in-memory index per node (about 139 bytes per RRset), so the Raft log is never in the query path.
2. **All writes are batched into Raft entries.** An AXFR of 1 M records becomes about 100 log entries of 10k records, not 1 M entries, and steady-state updates are coalesced too: openraft 0.9 awaits each log flush before the next client request, so one entry per update saturates at about 120 writes/s, while coalesced entries sustain 1,000 updates/s with p99 write latency around 200 ms. Snapshots are streamed in chunks to new nodes and the log is purged behind the snapshot.
3. **The write rate is low.** 100k AD clients re-registering every 24 h produce about 1.2 updates per second, three orders of magnitude below what the coalesced write path sustained in Spike A.
4. **DHCP leases do not go through global Raft.** They are hot, because every DORA is a write. They are synchronized between failover partners with the failover protocol (DHCP-12) and kept in a local WAL per node (DHCP-07).

Precedent: etcd recommends staying under 8 GB per cluster, and TiKV and CockroachDB run terabytes through multi-Raft. Tenko stays far below the etcd limit even with several zones of 1 M records.

### What lives where

| Data | Lives in | Replication |
|---|---|---|
| Configuration, IPAM, zones, policies | Embedded KV store (`redb`), on SSD or NVMe only (OPS-19) | Raft group (one; writes coalesced into entries) |
| DHCP leases | Local WAL on each `dhcp` node | Synchronized between failover partners, not through Raft |
| Serving data | In-memory index per node, built from the local copy | Not replicated itself; derived from the replicated state |

Every node also keeps a local cache of the state it needs, which is what makes data plane independence possible.

### Phase 0 gate (Spike A): passed

A real in-process openraft cluster of three voters over redb was loaded with 5 M A records in one zone plus 20 percent PTR records (6 M RRsets) on an NVMe SSD. Results against the thresholds:

| Measurement | Pass criterion | Measured |
|---|---|---|
| Import time | Recorded | 82 s into 3 voters (73k records/s); 26 s into one voter |
| RSS at 5 M records | Below 2 GB | 1.17 GiB per node |
| Catch-up time of a new node | Below 5 minutes on 1 Gbit | 19.1 s in process; 896.6 MiB snapshot, 7.5 s at 1 Gbit/s |
| IXFR delta computation | Recorded | Last 10,000 changes from the journal table in about 2 ms |
| p99 query latency under 1k updates per second | Unaffected | 1.6 us against a 1.4 us baseline (1.14x) |

Conditions that follow from the measurements (details in ADR 0002):

- The store runs on SSD or NVMe only. On an SMR hard disk the same load was 93 times slower and the leader lost leadership under write load (OPS-19).
- Writes are coalesced into Raft entries; dynamic updates return to the client after apply, so update latency of 50 to 200 ms under heavy load is expected.
- Disk usage is about 4x raw per node; space is reclaimed by snapshot-and-purge and by re-seeding a node from a snapshot, not by online compaction.
- A compact index layout is needed before zones beyond about 10 M RRsets per node are supported.
- Still to build and measure in Phase 1: atomic index swap during snapshot install, crash and restart recovery, failover, and a real network transport.

Scripts and results live in `bench/spike-a-raft/`. The fallback (Raft for configuration only, zone data via built-in IXFR/NOTIFY) was not needed and is kept in ADR 0002 for reference.

## Cluster communication

Node-to-node communication uses gRPC over mTLS with an internal CA (`tenko-cluster`) and enrollment tokens. The mechanism is identical for Docker, LXC and native installs (OPS-04). Nodes negotiate the protocol version so that a cluster can be upgraded one node at a time (OPS-08).

mTLS between nodes is structural. It is not a security-profile toggle, and no profile disables it. TLS on the API and UI is a separate matter and is a toggle (TGL-08).

## Views and policies model

One model covers split horizon in all its forms (DNS-20):

```
view = name + match rules + zone scope + weight
```

Match rules can test the client subnet, the transport, the interface IP address the query arrived on, the QTYPE, the time of day and the FQDN. A view selects a zone scope, which is a variant of a zone's content. The weight is the selection weight between zone scopes, as in weighted Windows Query Resolution Policies.

The same model expresses Windows zone scopes with Query Resolution Policies, BIND views and the simple internal/external split, so migration maps constructs directly instead of translating them.

| Source construct | Tenko construct |
|---|---|
| Windows zone scope | Zone scope |
| Windows client subnet | Client-subnet match rule |
| Windows Query Resolution Policy | View (match rules + zone scope + weight) |
| BIND `view` | View |
| BIND `acl` | Client-subnet match rule |
| Simple internal/external split | Two views matched on client subnet |

Details of the migration mapping are in [MIGRATION.md](MIGRATION.md).

## Security profiles as toggles

Security profiles (Home, Standard, Hardened, Lab) are bundles of toggle values, not separate code paths (API-10). The first-run wizard selects a profile, and every toggle can be changed individually afterwards. Insecure settings are loudly visible in the UI.

The Lab profile may disable everything except secrets encryption at rest (NEVER-01), the audit log (NEVER-02) and admin action attribution (NEVER-03). Lab means permissive configuration for testing and training; it never adds attack tooling (CON-09). The toggle matrix and the never-off list are in [SECURITY-PROFILES.md](SECURITY-PROFILES.md).

## Secrets and the vault

The vault (`tenko-vault`) uses envelope encryption (IAM-15, IAM-16):

- A data encryption key (DEK) protects each secret.
- A key encryption key (KEK) protects the DEKs. The KEK comes from the OS key store: DPAPI on Windows, TPM or keyring on Linux.
- PKCS#11, cloud KMS and external secrets managers are KEK provider options from Phase 5 (IAM-17).
- Secrets can be rotated, are zeroized in memory after use, and every reveal is written to the audit log.

| Secret | Used by |
|---|---|
| TSIG keys | Zone transfers and dynamic updates (DNS-09, DNS-11) |
| DHCP failover secrets | Failover protocol between partners (DHCP-12) |
| SNMPv3 credentials | Switch polling by probes (SCAN-05) |
| DDNS credentials | DNS updates issued by DHCP (DHCP-13) |
| Connector credentials | Proxmox API token, UniFi account, Home Assistant token (CONN-03, CONN-04, CONN-07) |

Vault contents are coupled to the authentication policy (CON-07). A 4-digit PIN protecting a vault that holds domain-admin credentials is not defensible. A PIN is allowed as the sole factor only while the vault is empty or disabled. Once it holds secrets, at least a passkey is required, or the PIN becomes a second factor (IAM-07).

## Network I/O design

Performance is I/O bound, not CPU bound (CON-01). Hand-written assembly was considered and rejected: DNS and DHCP parsers receive unfiltered packets from the network, which is exactly where the BIND, Kea and dnsmasq vulnerabilities have lived. Rust delivers C-class throughput without garbage-collection tails, and the remaining performance work is in how packets reach the parser, not in the parser's instruction selection.

| Technique | Platform | Status after Spike B (ADR 0009) |
|---|---|---|
| Dedicated blocking worker threads for UDP | All | Decided. A multi-threaded tokio runtime on the UDP path was the slowest arrangement from 8 workers up |
| tokio runtime | All | Everything except the UDP fast path: TCP, DoT, DoH, DoQ, control plane, connectors, API |
| `SO_REUSEPORT` sharding | Linux | Decided. One socket per worker thread; 4.04 M QPS at 32 workers against 3.28 M for a shared socket (loopback, WSL2). Balances by flow hash, so BPF steering is a later option |
| One shared socket | Windows | Decided. Windows has no `SO_REUSEPORT` load distribution; threads and tokio tasks measured the same, plateau around 8 to 16 workers |
| Zero-copy wire parsing, zero allocations per query | All | Decided. `domain` parses and builds without allocating; enforced by a counting-allocator bench in CI |
| `recvmmsg`, UDP GSO | Linux | Not yet measured; later optimizations |
| RIO | Windows | Not yet measured; later optimization |
| `io_uring` (`tokio-uring`) | Linux | A measurable option, not an assumption |
| Lock-free cache and index | All | No lock contention on the hot path (ADR 0002) |
| SIMD | All | Only where profiling justifies it |

**Spike B** (Phase 0) measured UDP DNS throughput on Windows and Linux (WSL2) and compared the `domain` and `hickory-proto` crates; the results and the decision are in ADR 0009. Headline figures, loopback on an i9-13900K: `domain` reached 148k QPS on one Windows worker (159k per core) and 204k on one Linux worker, 750k on Windows at 8 to 16 workers, and 4.04 M on Linux with `SO_REUSEPORT` at 32 workers (262k per core). `domain` beat `hickory-proto` by 6 to 17 percent end to end and by 2.5 to 3.5 times in parse-plus-build, with zero allocations per query against 6 to 10. The per-core target of more than 100k QPS (DNS-27) is met with margin on loopback; a two-host measurement over a real link is a Phase 2 exit criterion before absolute numbers are published. DNS latency usually sits upstream, so autoscaling is handled by orchestrator hooks and metrics outside the core (CON-06).

`unsafe` code is allowed only where an ADR permits it, which is expected to be limited to the I/O layer (API-16).

## Observability without a hot-path tax

The UI shows live gauges (queries per second, latency percentiles, cache hit ratio, RCODE mix, DHCP lease rate, pool utilization, store size, Raft health) per node and for the cluster (OPS-20). The rule is that measuring must not cost the data plane anything measurable, so the design follows four principles (OPS-21):

1. **Counters are per shard, not shared.** Every worker (one per core in the sharded I/O design) owns its own set of plain counters and fixed-bucket latency histograms in its own cache line. Incrementing one is a single relaxed atomic add to memory that no other core touches: no locks, no contention, no allocation, and the branch is unconditional so it is predictable. Nothing in the query, DORA or renew path formats, logs or sends anything.
2. **Aggregation happens off the hot path.** A collector task sums the per-shard counters once per second (or when `/metrics` is scraped) and derives rates and percentiles from the deltas. The UI gauge is this one-per-second snapshot pushed over the existing SSE channel (ADR 0008), so a thousand dashboards cost one aggregation, not a thousand.
3. **Expensive gauges are lazy and cached.** Store size on disk, index memory, zone and lease counts and Raft lag are computed on a timer (default every 30 s) or when a UI asks and the cached value is older than the timer, never on request. The same goes for per-zone and per-scope breakdowns, which are summed from per-shard tables only when that view is open.
4. **Per-query logging is a separate, opt-in, asynchronous feature.** Query logs and dnstap (DNS-26) write a fixed-size record into a per-shard ring buffer; a dedicated thread drains, formats and ships it. When the ring is full, records are dropped and the drop counter rises, so the data plane is never blocked by a slow disk or collector. Logging is off by default and supports sampling (1 in N), and its cost is shown as a gauge of its own, which is also where the GDPR controls (OPS-06) live.

The overhead budget is a measured number, not an intention: Spike B's load generator runs with metrics on and off, and the difference at saturation must stay below 2 percent throughput and must not move p99 latency. The result is recorded in `bench/` and tracked per release (OPS-15 covers idle resources, OPS-21 the hot-path cost).

What the first dashboard shows, per node and cluster-wide, is deliberately small: a QPS gauge with a 60 s sparkline, p50/p99 latency, cache hit ratio, RCODE mix, DHCP leases per second and pool utilization per scope, store size on disk and in memory, Raft role and replication lag, and the drop counters of the logging rings. Everything on it is also available at `/metrics` for Prometheus and Grafana, so the built-in view is a convenience for the home user and a first look for the enterprise operator, never the only way to see the numbers.

## IPAM as the intent hub

IPAM is the hub of the system (ADR 0005). Intent recorded in IPAM propagates to DHCP, DNS and network controllers through actuators, and observations from DHCP, DNS, scans, hypervisors and network controllers flow back. The address model itself (tenants and VRFs, the supernet, prefix, range and address tree, VLANs, sites, tags) is specified in [REQUIREMENTS.md](REQUIREMENTS.md). The `tenko-ipam` crate holds the address tree and reconciliation logic, and the `tenko-jobs` crate holds the job engine.

### Intent and observation

All data in IPAM is split into two layers stored as separate tables (IPAM-12):

- **Intent** is what is wanted: host X has IP Y in network Z, with an assignment mode, a DNS name and a VLAN.
- **Observation** is what is actually seen: DHCP leases, DNS records, scan results, hypervisor inventory and network-controller client tables.

### Reconciler

A reconciler compares the two layers continuously and drives actuators until they match (IPAM-13). The mechanism is the same in both directions: a change in IPAM lands in DHCP and DNS, and a change in DHCP or DNS shows up in IPAM. The reconciler produces jobs. Actuators and inventory sources are pluggable drivers behind common traits (ADR 0006).

### Actuators

| Actuator | Does | Drivers and phase |
|---|---|---|
| DHCP | Creates, moves and deletes reservations, keyed by MAC or client-id for DHCPv4 and by DUID for DHCPv6 | Tenko DHCP in Phase 3. External drivers (Windows DHCP via PowerShell, Kea via Control Agent) only in Phase 4, for coexistence (CONN-12) |
| DNS | Creates A, AAAA, PTR and CNAME records according to intent | Tenko DNS in Phase 2. External drivers (RFC 2136, Windows DNS via PowerShell) only in Phase 4 (CONN-13) |
| Network controller | Creates VLANs and networks, port profiles, per-client VLAN assignments | UniFi in Phase 1, more controllers later (CONN-16) |
| Hypervisor | Sets the guest IP for LXC containers (`pct set`) and cloud-init VMs | Proxmox in Phase 5 (CONN-15) |

External DHCP and DNS actuators do not exist in Phase 1. The Tenko engines of Phase 2 and 3 become the actuators, and the Windows connector arrives in Phase 4.

### Assignment modes

The assignment mode of a host decides what IPAM may do in DHCP and DNS (IPAM-14). Without it there is no way to know whether an IP change should become a reservation or only a DNS record.

| Mode | Behavior |
|---|---|
| `reserved` | An IP change in IPAM creates or moves the DHCP reservation and updates DNS |
| `static` | Only DNS is updated. The job adds a manual task: reconfigure the device |
| `dynamic` | IPAM only observes |
| `unmanaged` | Nothing touches the host |

### Proposals

Observations without intent create proposals, never intent (IPAM-15). An unknown MAC in a lease becomes a "discovered host", and a DNS record without a host becomes an "orphaned record". A proposal is approved with one click, or the operator sets the rule "auto-adopt in network Z".

### Precedence and lock

Intent wins for managed hosts (IPAM-16). A per-host `lock` flag stops all automation for that host.

### Jobs

Every change is a job with steps, a status, a timeout and rollback, visible in the UI and the API (IPAM-17). Nothing happens silently. Migration uses the same job engine (MIG-03). If a MAC address (DHCPv4) or DUID (DHCPv6) is missing, IPAM warns before a reservation can be created (IPAM-18).

### Example: changing the IP of a reserved host

1. The operator changes the intended IP in IPAM. The change is recorded in the immutable history (IPAM-09).
2. The reconciler sees that the DHCP reservation and the DNS records no longer match the intent and creates a job.
3. The job drives the DHCP actuator to move the reservation and the DNS actuator to update the A, AAAA and PTR records.
4. The new lease and the updated records appear as observations. When observation matches intent the job completes. Otherwise it times out and rolls back.

For a `static` host the job updates only DNS and adds the manual task. For a `dynamic` host IPAM only observes, and nothing touches an `unmanaged` host.

### Reconciliation views

In Phase 3, when Tenko DHCP exists, a unified view compares the four truths: IPAM intent, DHCP leases, DNS records and scans (IPAM-21). It provides ghost, rogue, orphan and PTR-mismatch views, together with "who wins" rules for resolving each kind of conflict.

## Device move job

Moving devices between networks is the central workflow that exercises the whole intent model (IPAM-19). The scenario: the operator selects N devices and drags them to the network "IoT".

Drag and drop moves nothing physically (CON-10). Without L2 control a device stays in its old VLAN and receives the old scope's address, whatever IPAM and DHCP say. A network-controller connector (UniFi first) is therefore a prerequisite for this workflow, not an extra.

### Preview

Before anything happens, a preview shows for each device the old IP and the new IP, the DNS change, the L2 action and any manual steps. An illustrative preview:

| Device | Mode | Old IP | New IP | DNS change | L2 action | Manual steps |
|---|---|---|---|---|---|---|
| thermostat-1 (wireless) | `reserved` | 192.0.2.57 | 198.51.100.57 | A and PTR updated | Per-client VLAN on the AP | None |
| printer-1 (wired) | `static` | 192.0.2.60 | 198.51.100.60 | A and PTR updated | Port profile changed | Reconfigure the device |

### Steps

On confirmation one move job runs per device:

1. **Choose the new IP.** Keep the same host part (the last octet, or the interface ID for IPv6) if it is free in the target network. Otherwise take the next free address according to the network's policy.
2. **Create the reservation** in the target network's scope. The old reservation is kept until the move is observed.
3. **Update DNS** (A, AAAA and PTR). On a name collision a new name is proposed.
4. **L2 move via UniFi.** For a wired device the port profile is changed. For a wireless device the per-client VLAN is set, or the device is moved to an SSID that carries the VLAN. Devices that cannot be controlled get a manual step.
5. **Wait for observation.** Either a lease in the new scope from the right MAC, or ARP or ping in the new network. The timeout is configurable.
6. **Clean up.** Remove the old reservation, release the old lease and remove the old DNS records.
7. **Roll back** if steps 4 and 5 do not succeed within the timeout. Steps 2 to 4 are reverted and the device is marked "move failed" with a reason.

### Which component performs each step

| Step | Performed by | Phase 1 |
|---|---|---|
| 1. Choose the new IP | IPAM, using the network's policy | Automatic |
| 2. Create the reservation | DHCP actuator | Manual task |
| 3. Update DNS | DNS actuator | Manual task |
| 4. L2 move | `NetworkController` driver (UniFi) | Automatic |
| 5. Wait for observation | Reconciler, fed by probe observations (ARP, ping) and, from Phase 3, DHCP leases | Automatic |
| 6. Clean up | DHCP and DNS actuators | Manual task |
| 7. Roll back | Job engine, reversing steps 2 to 4 | Reverts step 4 automatically |

### Why the job waits for observation

Devices pick up their new address only on a link flap or a lease renewal. DHCP FORCERENEW is not supported by clients in practice (CON-10). A move is therefore a job that waits for observation, not an action that is complete when the button is pressed. The old reservation, lease and DNS records stay in place until the new state has been seen.

### Guardrails

- The job never touches the port or VLAN through which IPAM or the UniFi controller itself is reached, and never touches uplinks (CONN-09).
- Bulk moves run with configurable parallelism, so that 60 IoT devices do not overwhelm DHCP or the controller (CONN-09).

### Behavior by phase

| Phase | Behavior |
|---|---|
| Phase 1 | The job performs the IPAM intent change, the UniFi L2 move and the observation. The reservation and DNS steps appear as manual tasks. |
| Phase 2 | The DNS step becomes automatic (Tenko DNS is the DNS actuator). |
| Phase 3 | The job is fully automatic for `reserved` hosts (Tenko DHCP is the DHCP actuator and leases are observations without polling). The IoT move becomes one click. |
| Phase 5 | The hypervisor actuator (Proxmox `pct set` and cloud-init) moves `static` LXC and VM hosts automatically (CONN-15). |

`static` hosts keep a manual reconfiguration step until a hypervisor actuator can perform it.

## VLANs and network controllers

A VLAN is a first-class object in IPAM (id, name, site) linked to prefixes (IPAM-03). Creating a network and its VLAN in IPAM can create the matching UniFi network in the same job, with UniFi's own DHCP either disabled or relaying to Tenko (CONN-06).

### Deployment detection

The reference controller is a self-hosted UniFi Network Application. Its API is reached directly on port 8443 without the `/proxy/network/` prefix, and login for the classic API uses `/api/login` with a local account. The connector also autodetects UDM, UCG and Cloud Key deployments, which use the proxy prefix, so that other environments work (CONN-07).

### API families

The connector speaks two API families:

| Family | Path and authentication | Provides | Caveats |
|---|---|---|---|
| Integration API | `/proxy/network/integration/v1`, `X-API-Key` header | Official and versioned. Reads sites, devices, clients and networks. Creating networks and VLANs is probably possible. | CRUD is reported by the community, but only GET is verified in the official documentation. Its location on a self-hosted installation is unconfirmed. |
| Classic API | `/api/s/{site}/rest/...` | Port profiles (`rest/portconf`) and per-client VLAN override (`rest/user`) exist only here. | The per-client override uses `network_id` set to the network's `_id`, not the VLAN number. Whether an API key works on classic endpoints varies between controllers. The fallback is a local admin account stored in the vault. |

A Phase 1 spike against the reference controller decides which writes go through which family and where the Integration API lives on a self-hosted installation.

### Write safety

- **Verify before write** (CONN-08): the connector never writes anything it has not first read back and diffed.
- All writes are previewed, written to the audit log and can run as a dry-run.
- Write access is a security-profile toggle (TGL-20).
- Guardrails protect the management path and uplinks (CONN-09).

## Topology

The topology map is a graph (IPAM-20):

- **Nodes:** router, switch, AP, host, VM or container, hypervisor.
- **Edges:** port, wireless association, uplink, VM-to-host.

| Source | Contributes |
|---|---|
| UniFi | Devices, uplinks, client-to-AP and client-to-port associations (CONN-05) |
| LLDP, CDP and bridge tables via SNMP | Links for third-party switches (SCAN-05) |
| Hypervisor connectors | VM-to-host edges |
| ARP and ND from probes | Hosts and their addresses (SCAN-02) |

The UI shows an interactive map with filters per VLAN and site. Clicking a node opens the host view, a path can be highlighted, and a port can be queried for what is connected to it. The graph library is chosen in a Phase 1 spike: sigma.js with graphology for WebGL rendering at thousands of nodes, and ELK for hierarchical layout.

## Inventory sources

All inventory sources implement one `InventorySource` interface (CONN-02). A source provides observed hosts with name, MAC addresses, IP addresses, OS, platform, parent host and tags. Sources are polled on a schedule, and webhooks are used where the platform offers them.

| Source | Phase | Method |
|---|---|---|
| Proxmox VE (CONN-03) | 1 | API token. `/cluster/resources`, QEMU guest agent `network-get-interfaces`, config and `interfaces` for LXC, SDN vnets |
| Home Assistant (CONN-04) | 1 | REST and WebSocket API with a long-lived token. The device registry provides MAC, IP, manufacturer and model for IoT devices that nmap cannot fingerprint |
| Hyper-V (CONN-10) | 4 | WinRM and PowerShell: `Get-VM`, `Get-VMNetworkAdapter` (MAC, and IP via integration services) |
| VMware vSphere (CONN-11) | 4 | vSphere REST API, guest IP via VMware Tools |
| Docker/Podman, Kubernetes, Incus/LXD (CONN-14) | 5 | Socket or API for containers and pods that have their own addresses |

Proxmox VE runs no DNS of its own, so it is an inventory source. A DNS server running in a VM or container on Proxmox is imported through its own migration adapter (see [MIGRATION.md](MIGRATION.md)). Observations from inventory sources also catch fixed IP addresses that never appear in DHCP. In Phase 5, a NetBox-compatible API lets Proxmox SDN use Tenko as its IPAM plugin (CONN-17).

## Connector framework and plugins

All integrations plug into one framework with four traits (ADR 0006, CONN-01):

**Connectors are plugins (ADR 0012).** The four interfaces are the contract; they are expressed as a versioned gRPC protocol in `tenko-connect`, which is the plugin SDK (protocol, host runner, Rust helper library, manifest schema, conformance test). Tenko starts each plugin as its own process (handshake over stdio, gRPC over a local socket or named pipe), supervises it (health, restart with backoff, timeouts) and keeps every policy decision on its side: verify-before-write, guardrails, rate limits, parallelism, observation normalization. A plugin never sees the vault; the host injects the secrets its manifest declares, per call, and audits it. The manifest also carries a JSON Schema for the plugin's settings, from which the UI builds the configuration form. The reference plugins (UniFi, Proxmox, Home Assistant; later the migration sources) are built on the same SDK and bundled in the binary as `tenko plugin run <name>`, so the home user installs nothing extra while third parties can write plugins in any language that speaks gRPC. A WebAssembly transport and a hub with signed packages follow in Phase 5 (CONN-21).

| Trait | Purpose | Example drivers |
|---|---|---|
| `InventorySource` | Produces observations of hosts | Proxmox, Home Assistant, Hyper-V, vSphere |
| `Actuator` | Applies intent to a system | Tenko DHCP, Tenko DNS, external Windows DHCP and DNS, Kea Control Agent, RFC 2136, Proxmox as hypervisor |
| `MigrationSource` | Produces the canonical intermediate representation (IR) plus a loss report | Windows DNS and DHCP, BIND, OPNsense, dnsmasq, Kea |
| `NetworkController` | Reads topology and performs L2 writes | UniFi |

The traits live in `tenko-connect` and drivers live in `tenko-connect-*` crates. One driver can implement several traits. `tenko-connect-proxmox` is an inventory source in Phase 1 and gains a hypervisor actuator later. `tenko-connect-windows` is a migration source and a coexistence actuator in Phase 4. The `NetworkController` drivers cover both topology reads and the L2 writes behind the network-controller actuator.

The migration pipeline (`plan`, `apply`, `verify`) lives in `tenko-migrate` on top of the connectors, and it runs on the job engine (MIG-01, MIG-03). IR, loss reports, coexistence modes and runbooks are in [MIGRATION.md](MIGRATION.md).

## API and UI

The platform is API first (ADR 0003, API-01 to API-05):

- REST with an OpenAPI specification derived from the Rust types (`utoipa`).
- The CLI shares its client library with the UI (API-03).
- Bulk operations and idempotency keys (API-04).
- Server-Sent Events carry live updates to the UI (API-05).
- The UI uses only the public API (API-02). Phase 5 adds webhooks, a Terraform provider and an Ansible collection (API-06, API-07).

The UI is a SolidJS and TypeScript SPA built with Vite and embedded in the binary as a `build.rs`-generated `include_bytes!` table with pre-compressed variants (ADR 0008). **Spike C** (Phase 0) measured the embedded SPA together with SSE: 17 ms cold start, 10.8 MiB idle working set and about 37 KiB of private memory per SSE client; details in `bench/spike-c-embed/results/`.

UI behavior for changes (API-08, API-09):

- Multiselect and drag and drop.
- A preview before every apply.
- A job panel with status per item.
- Undo where possible.
- Keyboard-driven bulk grids, dark mode, Swedish and English, WCAG accessibility.

Remote access to hosts starts with URI handoff: the UI produces `.rdp` files or `ssh://` URIs with host, port and user, and copies the password from the vault to the clipboard with an audit entry (API-11). An HTML5 RDP/SSH gateway is an opt-in module in Phase 5 (API-12).

## Libraries under evaluation

These choices are candidates, to be confirmed in the Phase 0 spikes. Final choices are recorded in ADRs.

| Concern | Candidates | Notes |
|---|---|---|
| DNS wire format, zone files, TSIG, DNSSEC record types | `domain` (NLnet Labs) behind an internal `Codec` trait; `hickory-proto` kept as the second implementation for differential tests | Decided in ADR 0009 after Spike B |
| DHCPv4 and DHCPv6 wire format | `dhcproto` | Kea is the semantic reference |
| Raft | `openraft` 0.9 | Confirmed by Spike A (ADR 0002); writes coalesced into entries |
| Embedded KV store | `redb` | Confirmed by Spike A (ADR 0002); SSD or NVMe required |
| Kerberos and GSS-TSIG | `cross-krb5` (Linux) and `sspi-rs` (Windows) | Phase 4 (DNS-28) |
| LDAP | `ldap3` | AD reads for migration |
| TLS, QUIC, HTTP | `rustls` with `aws-lc-rs`; `quinn` (DoQ); `hyper` and `h3` (DoH) | |
| Web framework | `axum`, `utoipa`, `tower` | |
| UI embedding and static serving | `build.rs` with `include_bytes!`, `brotli`, `flate2` | Decided in ADR 0008 after Spike C |
| Authentication | `webauthn-rs`, `argon2`, a TOTP library | |
| Scanning | `pnet`, `rasn-snmp` | |
| Windows service | `windows-service` | |
| Fuzzing | `cargo-fuzz` | On every parser |

Policy: no `unsafe` code without an ADR.

## Repository layout

```
tenko/
  Cargo.toml                 # workspace
  LICENSE                    # placeholder until the license decision
  docs/
    README.md                # entry point
    REQUIREMENTS.md          # living requirements specification
    ARCHITECTURE.md          # this document
    SECURITY-PROFILES.md     # toggle matrix and the never-off list
    MIGRATION.md             # connector table, coexistence modes, runbooks
    CONFORMANCE.md           # RFC matrix per phase
    ROADMAP.md               # phases, deliverables, done-when criteria
    adr/                     # architecture decision records
  crates/
    tenko-core/              # data model (IPAM, zones, leases, policies), IR for migration
    tenko-store/             # Raft + KV, snapshots, local cache
    tenko-cluster/           # gRPC/mTLS, enrollment, internal CA
    tenko-auth/              # users, passkeys, TOTP, password policy, RBAC, sessions
    tenko-vault/             # envelope encryption, KEK providers
    tenko-ipam/              # address tree, reconciliation, import/export
    tenko-scan/              # probe role, passive/active discovery, SNMP
    tenko-dns/               # authoritative, forwarder, cache, RPZ, XFR, views
    tenko-dhcp/              # v4/v6, failover, relay, DDNS
    tenko-jobs/              # job engine: steps, state, timeouts, rollback
    tenko-connect/           # plugin SDK: protocol, host runner, helper library, manifest, conformance test
    tenko-connect-proxmox/   # reference plugin: inventory (Phase 1), hypervisor actuator (later)
    tenko-connect-unifi/     # reference plugin: read topology and SSIDs, write VLANs and port profiles
    tenko-connect-windows/   # Phase 4: DNS/DHCP via PowerShell remoting + LDAP, migration source and coexistence actuator
    tenko-connect-hass/      # reference plugin: Home Assistant inventory source
    tenko-connect-*/         # migration-source plugins: bind, opnsense, dnsmasq, kea, hyperv, vmware (Phase 4 to 5)
    tenko-migrate/           # plan/apply/verify pipeline on top of connectors
    tenko-api/               # axum, OpenAPI, SSE
    tenko-cli/               # `tenko` CLI, shares the client with the UI
    tenko-server/            # the binary, role orchestration, Windows SCM / systemd
  ui/                        # SolidJS + TypeScript + Vite, embedded via build.rs (ADR 0008)
  fuzz/                      # cargo-fuzz targets per parser
  bench/                     # Phase 0 spikes, dnsperf/perfdhcp scenarios
  deploy/                    # Dockerfile, compose with macvlan, LXC notes, systemd unit, MSI
  .github/workflows/         # lint, test, audit, fuzz smoke, release
```

## Engineering rules

- **Commits:** conventional commit messages and small commits. Commit hooks are never bypassed.
- **Memory safety:** `#![forbid(unsafe_code)]` in every crate, except where an ADR allows `unsafe` (the I/O layer) (API-16).
- **Fuzzing:** every parser of network data has a `cargo-fuzz` target before it is merged (API-15). Targets live in `fuzz/`, and CI runs a fuzz smoke job.
- **Dependency and license hygiene:** `cargo-deny` (licenses, advisories, duplicates) and `cargo-audit` run in CI and fail the build when they find problems (API-14). Clippy (pedantic) and the test suite are part of the same gate.
- **Secrets:** never committed to the repository. A `.env.example` file documents the variables instead.
- **Test data:** uses documentation ranges only: RFC 5737 (IPv4) and RFC 3849 (IPv6) addresses, with the RFC 7042 documentation MAC range and RFC 2606 reserved names (see CONFORMANCE.md).
- **Licensing and publication:** license headers are left empty until the license decision (API-20). All code is written as if the repository is public (API-13).
