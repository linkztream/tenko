# Tenko DDI Roadmap

Every choice in this roadmap is ranked by one order: security, then performance, then usability, then features ([CONTRIBUTING.md](../CONTRIBUTING.md), "Non-negotiable rules"). Work that moves an earlier item forward goes before work that only adds to a later one; that is why high availability of the data plane and directory identity come before the remaining features.

Tenko DDI is delivered in six phases (Phase 0 to 5), in the order recorded in [ADR 0007](adr/0007-delivery-order.md): platform and IPAM first, then DNS, DHCP, AD integration and migration, and finally enterprise features. The order follows dependencies. IPAM replaces the existing IPAM spreadsheet immediately and builds the intent model that the engines act on later. The DNS and DHCP engines then become the actuators of that model. AD integration and migration need both engines in place.

The reference home-lab environment (three LANs plus a DMZ, Active Directory, a self-hosted UniFi Network Application, Proxmox VE, Home Assistant) is the first acceptance environment. The Phase 1 to 3 criteria below are stated in terms of it. Phase 4 acceptance uses a separate Windows Server test domain.

Per-requirement phase assignments live in [REQUIREMENTS.md](REQUIREMENTS.md). Its Phase column is authoritative. Requirement IDs cited in this document are pointers, not a complete list per phase. Architecture is described in [ARCHITECTURE.md](ARCHITECTURE.md), migration design and runbooks in [MIGRATION.md](MIGRATION.md), and per-RFC targets in [CONFORMANCE.md](CONFORMANCE.md).

## Where we are (2026-10-23)

| Phase | State | Where to read |
|---|---|---|
| 0 Foundation and spikes | Complete | `bench/`, ADR 0002 |
| 1 Platform and IPAM | Complete | [phase-1-status.md](plans/phase-1-status.md), [phase-1-exit.md](plans/phase-1-exit.md) |
| 2 DNS | Complete, two measurements carried over (M23 idle memory, deviations 145 and 146) | [phase-2-status.md](plans/phase-2-status.md), [phase-2-exit.md](plans/phase-2-exit.md) |
| 3 DHCP | In progress: the DHCPv4 engine, the `dhcp` role, reservations from intent, DDNS, classes and policies, conflict detection, the UI and the Kea export (DHCPv4) are merged; DHCPv6 (WP9.1, WP9.2, WP9.4) and the exit (WP9.5) are open | [phase-3-plan.md](plans/phase-3-plan.md), [phase-3-status.md](plans/phase-3-status.md) |
| Recursion (Slice 10, beside Phase 3) | In progress: the contracts and the iterative engine with the lab root are merged; validation (WP10.2) is being built; WP10.3 to WP10.5 are open | [dns-recursion-plan.md](plans/dns-recursion-plan.md), [dns-recursion-status.md](plans/dns-recursion-status.md) |
| High availability of the data plane (Slice 12, after Phase 3) | Planned: the plan is accepted and ADR 0025 is Accepted (2026-10-25); WP12.0 to WP12.8 are open | [ha-plan.md](plans/ha-plan.md), [ADR 0025](adr/0025-dhcp-failover-and-data-plane-ha.md) |
| 4 AD integration and migration | Not started | [MIGRATION.md](MIGRATION.md) |
| 5 Enterprise and ecosystem | Not started | this page, section "Phase 5" |

The latest release is on the [releases page](https://github.com/linkztream/tenko/releases); [QUICKSTART.md](QUICKSTART.md) gets a node running. The status documents list every work package with its state; a package marked in progress has a builder, so ask in an issue before starting on one.

### Help wanted

Packages that stand on their own and are free to take, with where their specification lives:

- **DHCPv6**: WP9.1 (the codec and the server: IA_NA, relay, RFC 6939, RFC 4704), then WP9.2 (IA_PD and the RA check) and WP9.4 (the UI): [phase-3-plan.md](plans/phase-3-plan.md) section 4, `docs/dhcp.md`, `docs/dhcp-contracts.md`.
- **Recursion after WP10.2**: WP10.3 (QNAME minimisation, the denial cache, RFC 8020 and RFC 9520) and WP10.4 (the API, the CLI and the UI): [dns-recursion-plan.md](plans/dns-recursion-plan.md) section 4. RFC 5011 key revocation in Tenko's own signer is a small package of its own once WP10.2 lands.
- **Migration connectors** that need no AD: BIND (MIG-09), OPNsense (MIG-10), dnsmasq and Pi-hole (MIG-11), Kea and ISC dhcpd (MIG-12), NetBox and phpIPAM (MIG-13): [MIGRATION.md](MIGRATION.md) and the IR in `docs/dhcp-contracts.md` section 11; the Kea export in `crates/tenko-dhcp/src/export/` is the mirror image of MIG-12.
- **Measurements that fail their threshold**: M23, idle memory of the musl binary with the home zones and a full cache, 100.05 MiB against 100 MB ([phase-2-exit.md](plans/phase-2-exit.md), deviation 145); M31, the DDNS answer latency from DHCP, p99 699 ms against 250 ms (`bench/phase3-dhcp/results/2026-10-22-m31-ddns.md`). Each needs a profile first and a measured fix second.
- **Sign-in with OIDC** (IAM-11, Phase 5, but self-contained): a design note as an ADR first, then the provider flow, the group claim mapping onto the roles and the UI.
- **Smaller**: the UI test suite is flaky under a loaded machine (one failure in about 4,300 tests per full gate; a worker-count or timing fix with evidence); the weekly lab workflows run on hosted runners since 2026-10-22 and their first runs need watching.

To take one: open an issue with the feature-request form naming the package, and you get the package's brief there (the plan section, the files it owns, what done looks like, the checks). Then the rules of [CONTRIBUTING.md](../CONTRIBUTING.md): one branch per package, Conventional Commits in English, the checks before the pull request, a result file behind every performance claim, the Contributor License Agreement, and never a real network's names or addresses in the repository.

## Overview

| Phase | Name | Theme | Exit gate |
|---|---|---|---|
| 0 | Foundation and spikes | Decide with measurements before committing to the architecture | All three spikes have reproducible data in `bench/`; the Raft gate decision is recorded in ADR 0002 |
| 1 | Platform and IPAM | Control plane, IPAM as intent hub, discovery, connectors | The existing IPAM spreadsheet is replaced; all four networks are scanned; UniFi VLANs and a manual-step IoT move work |
| 2 | DNS | Authoritative, forwarder/cache and DNSSEC engines | A home network sends all queries through Tenko; BIND interop works in both directions |
| 3 | DHCP | DHCPv4/v6, failover, Tenko as IPAM actuator | The failover pair survives the chaos test; the reference environment runs DHCP through Tenko |
| 4 | AD integration and migration | Secure AD updates and hands-off migration | A Windows Server test domain is migrated without manual intervention |
| 5 | Enterprise and ecosystem | Own resolver, SSO, ecosystem, publication | Exit criteria are defined when Phase 4 completes |

### Phase dependencies

- Phase 0 gates Phase 1 storage work: the Raft store goes into operation only after the Spike A decision is recorded in ADR 0002.
- Network-controller control (UniFi first, Phase 1) is a prerequisite for moving devices between networks (CON-10). Without L2 control a device stays in its old VLAN and receives an address from the old scope, whatever IPAM and DHCP say.
- DDNS from DHCP (Phase 3) builds on RFC 2136 updates and the authoritative engine from Phase 2.
- GSS-TSIG and aging (Phase 4) build on the Phase 2 DNS engine. Migration of Windows DHCP builds on the Phase 3 DHCP engine.
- Standard-format exports, the exit strategy, arrive together with the data they cover: CSV in Phase 1 (MIG-14), zone files in Phase 2 (MIG-15) and Kea-compatible JSON in Phase 3 (MIG-16).

### Move job progression

The move job (IPAM-19) is introduced in Phase 1 and gains automation as the engines arrive. A device only takes its new address on link flap or lease renewal, so the job waits for observation instead of completing immediately (CON-10).

| Phase | Move job behavior |
|---|---|
| 1 | IPAM intent, UniFi L2 move and observation. Reservation and DNS steps are manual tasks. |
| 2 | The DNS step becomes automatic. |
| 3 | The reservation step becomes automatic for `reserved` hosts. The IoT move is one click. |
| 5 | `static` hosts can be moved automatically through hypervisor actuators (CONN-15). |

## Phase 0: Foundation and spikes

### Deliverables

- Repository skeleton per the repository layout in ARCHITECTURE.md.
- CI with clippy (pedantic), tests, `cargo-deny`, `cargo-audit` and a fuzz smoke run (API-14).
- ADR 0001 to 0004 (language, storage, UI, roles). ADR 0005 to 0007 (IPAM as intent hub, connector architecture, delivery order) are recorded at the same time.
- Conformance matrix in CONFORMANCE.md (API-17).
- Spikes A, B and C below, with data and scripts in `bench/`.

### Initial work order

1. The repository is initialized with the workspace skeleton, `.gitignore` and a placeholder `LICENSE`.
2. The core documents (REQUIREMENTS.md, ARCHITECTURE.md, MIGRATION.md) and ADR 0001 to 0004 are written.
3. Spikes A, B and C are run.
4. The CI pipeline is set up.

### Spike A: Raft storage gate (passed)

This spike decided ADR 0002, now Accepted with conditions. The embedded Raft store was conditional on zones with more than 1 M records working.

Procedure: load a zone with 1 M records and with 5 M records (plus 20 percent PTR records in reverse zones), and measure import time, RSS, catch-up time for a new node, IXFR delta generation and p99 query latency under 1k updates/s.

**Result (2026-10-09, Windows, NVMe, real in-process openraft cluster of 3 voters over redb):**

| Measure | Threshold | Measured |
|---|---|---|
| RSS at 5 M records (6 M RRsets) | Below 2 GB | 1.17 GiB per node |
| New node caught up over 1 Gbit | Below 5 minutes | 19.1 s in process; 896.6 MiB snapshot, 7.5 s at 1 Gbit/s |
| p99 query latency under 1k updates/s | Unaffected | 1.6 us against 1.4 us baseline |

Conditions recorded in ADR 0002: SSD or NVMe is mandatory for the store (an SMR hard disk was 93x slower and lost leadership under load), updates are coalesced into Raft entries (openraft 0.9 saturates at about 120 single-entry writes/s), disk usage is about 4x raw per node and is reclaimed by snapshot re-seeding, and a compact index layout is needed beyond about 10 M RRsets per node. Phase 1 must add the atomic index swap on snapshot install, crash and restart recovery, failover tests and a real network transport. Results and scripts: `bench/spike-a-raft/`.

The fallback (Raft for configuration, IPAM and policies only, zone data via built-in IXFR/NOTIFY) was not needed.

### Spike B: UDP throughput and DNS wire-format crate (done)

- Measured UDP DNS throughput on Windows (native) and Linux (WSL2, not bare metal) with a shared socket and, on Linux, one `SO_REUSEPORT` socket per worker; compared blocking worker threads with tokio tasks.
- Compared `domain` (NLnet Labs) with `hickory-proto` behind one `Codec` trait, end to end and in criterion micro-benchmarks with a counting allocator.
- `recvmmsg`, UDP GSO, RIO and io_uring were not measured and remain later optimizations.

**Result (2026-10-09, loopback on an i9-13900K):** `domain` wins on every measure: zero allocations per query against 6 to 10, parse-plus-build 2.5 to 3.5 times faster, 6 to 17 percent more QPS end to end, 16 instead of 50 transitive dependencies, 0.3 MB smaller binary. One worker: 148k QPS on Windows, 204k on Linux. Peak: about 750k on Windows (shared socket, 8 to 16 workers), 4.04 M on Linux with `SO_REUSEPORT` at 32 workers (262k per core) against 3.28 M with a shared socket. A multi-threaded tokio runtime on the UDP path was the slowest arrangement. Decision in ADR 0009: `domain` behind a `Codec` trait, blocking UDP workers, `SO_REUSEPORT` per worker on Linux, one shared socket on Windows, tokio for everything else. Results: `bench/spike-b-udp/results/`.

### Spike C: Embedded SPA

Serve the SPA from the binary together with SSE, and measure cold start and bundle size.

**Result (2026-10-09, Windows):** all targets met. Cold start 17 ms (target below 200 ms), idle working set 10.8 MiB (target below 30 MB), about 27,900 SSE clients per GiB (target at least 10,000). The embedding mechanism, caching rules and SSE pattern are decided in ADR 0008; results in `bench/spike-c-embed/results/2026-10-09-windows.md`. Linux and multi-host runs are pending.

### Done when

- All three spikes have measurement data with reproducible scripts in `bench/`. (Done 2026-10-09: Spike A in `bench/spike-a-raft`, Spike B in `bench/spike-b-udp`, Spike C in `bench/spike-c-embed`.)
- The gate decision is documented in ADR 0002, with status Accepted, or in a superseding ADR that records the fallback. (Done: ADR 0002 is Accepted with conditions; ADR 0008 and ADR 0009 record the Spike C and Spike B decisions.)

**Phase 0 completed on 2026-10-09.**

## Phase 1: Platform and IPAM

Replaces the existing IPAM spreadsheet.

### Deliverables

- **Authentication**: Argon2id password hashing with policy presets (PIN, Standard, Hardened, and custom with regex, length and HIBP check), TOTP, passkeys (WebAuthn), recovery codes, lockout, sessions and a break-glass account (IAM-03 to IAM-09).
- **Authorization, audit and secrets**: RBAC with object scope, a hash-chained audit log, and a vault with a DPAPI or keyring-held KEK (IAM-01, IAM-15, IAM-18).
- **Cluster**: Raft store in operation as a single node and as a 3-node cluster, node enrollment and mTLS (OPS-03, OPS-04).
- **IPAM**: tenant/VRF, tree, VLAN, site, status, tags, next free, history and utilization alarms. CSV/Excel import with column mapping in the UI (IPAM-11).
- **Scanner**: probe role; passive discovery (ARP/ND, mDNS, LLDP); active scanning (ICMP, TCP ports, OS fingerprinting); SNMPv3 switch polling; schedules and rate limits. A host view shows open ports and OS (SCAN-01 to SCAN-08).
- **RDP/SSH button**: generates an `.rdp` file or `ssh://` URI with host, port and username. The password is copied to the clipboard from the vault, with audit (API-11).
- **UI shell**: navigation, keyboard-driven grids, dark mode, Swedish and English, and a first-run wizard with security profile selection (API-08, API-10).
- **Deployment**: Docker with a macvlan example, a systemd unit and a Windows service (OPS-10, OPS-13, OPS-14).
- **Intent/observation model, reconciler and job engine**: proposals, lock flag and audit (IPAM-12 to IPAM-17).
- **Connectors**: the plugin SDK and host runner first (ADR 0012: process plugins over gRPC, manifest, supervision, secret injection, conformance test), then the bundled reference plugins: UniFi (read topology and SSIDs, write VLANs, port profiles and per-client VLAN with guardrails), Proxmox inventory, Home Assistant inventory (CONN-01 to CONN-09).
- **VLAN objects, topology map and move job** with preview and rollback (IPAM-03, IPAM-19, IPAM-20).
- **Releases and upgrades**: a data-directory format version with migrations and `tenko upgrade check`, release builds with checksums per tag, a compatibility test against the previous release, and in-app update notices with release notes and single-node installation from the UI (OPS-23, OPS-24).
- **Partition behaviour**: isolated controllers refuse writes visibly, serve reads with a staleness indicator, queue changes as proposals and catch up without merging (OPS-26).

In Phase 1 the move job performs the IPAM intent change, the UniFi L2 move and the observation. The reservation and DNS steps are manual tasks until Tenko's own engines exist (Phase 2 to 3), at which point the same job becomes fully automatic.

### Spike: UniFi API families and topology graph library

UniFi API families, against the self-hosted reference controller:

- Which writes go through the Integration API and which through the classic API.
- Where the Integration API lives on a self-hosted installation.
- Whether the API key works on classic endpoints.

Background (CONN-07, CONN-08): the Integration API (`/proxy/network/integration/v1`, `X-API-Key`) is official and versioned. Network and VLAN creation is expected to work there, but only GET is verified in the official documentation. Port profiles (`rest/portconf`) and per-client VLAN override (`rest/user`, with the network `_id` rather than the VLAN number) exist only in the classic API. If the API key does not work on classic endpoints, the fallback is a local admin account stored in the vault. The connector never writes anything it has not first read back and diffed.

Topology graph library: the candidates are sigma.js with graphology (WebGL, thousands of nodes) and ELK (hierarchical layout). The spike selects the library.

### Done when

- The existing IPAM spreadsheet is imported.
- All four networks (three LANs plus the DMZ) are scanned, with one probe per segment.
- Proxmox and Home Assistant inventory is visible in IPAM.
- The topology map shows the UniFi switches and APs with connected clients.
- A VLAN created in IPAM exists in UniFi.
- An IoT device can be moved to a new VLAN by drag and drop, with manual DHCP and DNS steps.
- A 3-node cluster survives loss of a controller.
- Login with a passkey works.
- The OpenAPI specification is published.

## Phase 2: DNS

Execution plan: [plans/phase-2-plan.md](plans/phase-2-plan.md) (accepted on 2026-10-17 with its section 7 decisions; Phase 2 builds and measures a single node, section 2.10).

### Deliverables

- **Authoritative engine**: all common RR types plus unknown types, TCP and UDP, EDNS0, Cookies, RRL, minimal-responses and ANY minimization (DNS-01, DNS-05 to DNS-07, DNS-17, DNS-18).
- **Dynamic updates and transfers**: RFC 2136 dynamic updates with TSIG and ACL; XFR in and out (AXFR, IXFR, NOTIFY, TSIG, XoT); catalog zones (DNS-09 to DNS-11).
- **Views and reverse zones**: the views/policies model for split horizon (DNS-20), and reverse zones created automatically from IPAM, including RFC 2317 (DNS-22).
- **Forwarder and cache**: conditional forwarders, upstream DoT/DoH, serve-stale, prefetch, RPZ and blocklists (DNS-02, DNS-15, DNS-21, DNS-23).
- **DNSSEC and encrypted transport**: signing with automatic rollover (DNS-12); DoT and DoH as server (DNS-14).
- **Node role**: the `dns` role serves from a local copy of the zones. Metrics, dnstap and a query log with GDPR retention (DNS-26, OPS-06).

From this phase the move job's DNS step is automatic.

### Done when

- dnsperf numbers are documented.
- A home network sends all of its queries through Tenko.
- BIND as secondary receives Tenko's zones, and the reverse direction works too.
- Fuzz targets for wire format, zone file and TSIG run in CI.

## Phase 3: DHCP

### Deliverables

- **DHCPv4**: scopes, pools, exclusions, reservations, options at all levels, classes and policies, relay and option 82, shared networks, PXE/UEFI, conflict detection, MAC filter, lease WAL and lease history (DHCP-01 to DHCP-08).
- **DHCPv6**: IA_NA, IA_PD, DUID, relay and RFC 6939 correlation (DHCP-09, DHCP-11).
- **Failover** (Slice 12): pairs in load balance (hash split) or hot standby, a node in several pairs, MCLT, partner-down on evidence or by hand, and lease sync over the cluster port (DHCP-12).
- **DDNS**: option 81, DHCID and name protection, PTR records, and updates on commit, expire and release (DHCP-13).
- **IPAM reconciliation**: leases, DNS, scans and intent in one view with conflict rules (IPAM-21). Fingerprinting from options 55 and 60 feeds the OS field (DHCP-14).
- **Tenko DHCP as actuator**: reservations are created directly from IPAM intent, and leases become observations without polling (DHCP-16).
- **Recursive resolver** (Slice 10, the owner's decision REC-Q1 of 2026-10-22, moved here from Phase 5): Tenko's own recursive resolver from the root hints with DNSSEC validation, QNAME minimization, aggressive NSEC and RFC 5011 trust anchor maintenance (DNS-03, DNS-13, DNS-34), planned in [dns-recursion-plan.md](plans/dns-recursion-plan.md) and ADR 0021; until it ships, recursion is served by the forwarder, cache and RPZ combination from Phase 2.
- **High availability of the data plane** (Slice 12, the owner's decisions HA-Q1 to HA-Q15 of 2026-10-25, moved here from Phase 5): `dns` and `dhcp` nodes without a controller, fed by node sync into a node store; leases held by the serving node and published to the controllers; DHCP failover pairs; the health hooks of OPS-17; split scopes beside Windows DHCP (DHCP-07, DHCP-12, DHCP-18, OPS-17, OPS-26), planned in [ha-plan.md](plans/ha-plan.md) and ADR 0025.

The move job becomes fully automatic for `reserved` hosts (the DNS step was already automatic in Phase 2). This is where the IoT move becomes one click.

### Done when

- kea perfdhcp numbers are documented.
- The failover pair passes the chaos test: a partner is killed mid-load and no duplicate leases result (DHCP-18).
- The reference home-lab environment runs DHCP through Tenko for all four networks via relay.
- The reference home-lab environment resolves through Tenko alone, with no upstream resolver, with DNSSEC validation on (the recursion plan's Internet smoke).

## Phase 4: AD integration and migration

### Deliverables

- **GSS-TSIG**: TKEY exchange via SSPI on Windows and krb5 on Linux, computer account and SPN setup in a wizard, ownership per RRset, and a "secure only" mode per zone (DNS-28).
- **AD behaviors**: aging and scavenging with Windows semantics (DNS-29), DC locator validation of SRV records in `_msdcs` and `_sites` (DNS-30), and AD Sites and Services sync with IPAM sites (IPAM-22).
- **Migration connectors** as specified in MIGRATION.md: Windows DNS (cmdlets, LDAP and `.dns` files), Windows DHCP (XML and cmdlets), BIND, OPNsense, dnsmasq and Pi-hole, Kea and dhcpd, and NetBox and phpIPAM. Proxmox inventory already exists from Phase 1 (MIG-01, MIG-06 to MIG-13).
- **Migration pipeline**: `tenko migrate plan`, `tenko migrate apply` and `tenko migrate verify`; coexistence modes (secondary, forward, flip); query-replay parity; runbooks in MIGRATION.md (MIG-03 to MIG-05, MIG-17).
- **Inventory sources**: Hyper-V and VMware vSphere (CONN-10, CONN-11).
- **External actuators for coexistence**: DHCP (CONN-12) and DNS (CONN-13).
- **Windows interop lab**: a Windows Server 2016 or later test domain (API-18).

### Coexistence and verification

Migration runs through one pipeline for every source. Each source adapter produces the canonical intermediate representation plus a loss report that lists what could not be mapped (MIG-01). AXFR is the universal baseline for DNS data (MIG-02). The adapters add what AXFR drops: ownership, timestamps, forwarders, views and policies, and DHCP.

Coexistence modes are selected per zone or scope (MIG-04):

1. Secondary: Tenko is an AXFR secondary and stays in sync until the flip, with a nightly parity diff.
2. Forward: Tenko forwards some zones to the old server while it takes over others.
3. Flip: Tenko becomes primary and the old server becomes its secondary, or is switched off after a rollback window.

Verification is by query replay (MIG-05): live queries are sampled from dnstap or the query log, asked of both servers, and the RCODE and answers are diffed with TTL drift ignored. No AD-backed zone storage mode is built (CON-11).

### Done when

- A Windows Server test domain (2016 or later) with Query Resolution Policies, zone scopes, aging and DHCP failover is migrated in the lab without manual intervention (MIG-18).
- Domain join, GPO processing and DC locator work against Tenko.
- Windows DNS is switched off and clients notice nothing.

## Phase 5: Enterprise and ecosystem

### Deliverables

- **Multi-node data plane**: the cluster labs on VMs (E9, M2, M4 and M7 of Phase 1, deviation 74 of its exit document), the single-node figures of Phases 2 and 3 compared against the cluster (owner's direction of 2026-10-17: single node first).
- **Multi-site ownership**: site-local Raft groups for the objects a site owns, so a cut-off site keeps changing its own prefixes, scopes and zones (OPS-27).
- **Identity**: OIDC and SAML, LDAP group mapping, SPNEGO and SCIM; PKCS#11 and KMS support for the KEK (IAM-11 to IAM-14, IAM-17).
- **Scaling hooks**: anycast health hooks (BGP withdrawal) and autoscaling hooks for the Kubernetes, Nomad and Proxmox APIs (OPS-17, OPS-18).
- **Ecosystem**: Terraform provider, Ansible collection, webhooks, and a NetBox-compatible API for Proxmox SDN (API-06, API-07, CONN-17).
- **Remote access gateway**: HTML5 RDP/SSH gateway as an opt-in module with credential injection, session recording and just-in-time access (API-12).
- **Actuators and inventory**: hypervisor actuators (Proxmox `pct set` and cloud-init) that move `static` hosts automatically, more network controllers, and inventory from Docker, Kubernetes and Incus (CONN-14 to CONN-16).
- **Plugin hub**: signed plugin packages, `tenko plugin install`, the WebAssembly component transport beside the process transport, and the public plugin SDK repository (CONN-21).
- **Release and licensing**: DoQ, signed releases, SBOM and the possible publication under the licence decided on 2026-10-22 (the Business Source License 1.1 with AGPL-3.0-or-later as the Change License, ADR 0022; DNS-16, API-19, API-20).

### Done when

Exit criteria for Phase 5 are not yet defined. They are set when Phase 4 completes.

## Verification

Each phase is verified with the methods below. Measurements are reproducible and kept in the repository.

| Area | Method | Phase |
|---|---|---|
| Phase 0 spikes | Spike measurements in `bench/` with reproducible scripts. Gate decision recorded in an ADR. | 0 |
| DNS | dnsperf and flamethrower for throughput and latency. Per-RFC conformance tests tracked in CONFORMANCE.md. Interop with BIND, with XFR in both directions. Fuzzing in CI. | 2 |
| DHCP | kea perfdhcp. Failover chaos test: kill a partner under load and verify that no duplicate leases exist. Relay test with four networks in Docker macvlan or compose. | 3 |
| IPAM and scanner | Compose topology with four segments and one probe per segment; verify that the inventory matches the expected answer key. Spreadsheet import round trip. | 1 |
| IoT move, end to end | Lab with UniFi and five devices: one wireless, one `static`, the rest `reserved`. Drag all to a new network and verify reservation, DNS, VLAN and observed lease within the timeout. The `static` device must stop at its manual step. Block step 5 for one device and verify rollback. Verify that the guardrail refuses to touch the uplink and the management port. | 1 (manual DHCP/DNS steps), 3 (fully automatic) |
| Connectors | Proxmox inventory against the real node with a read-only API token. UniFi read against the reference controller. Dry-run of writes before the first real change. | 1 |
| AD | Windows Server 2016 or later test domain in a VM: domain join, DC locator, GPO retrieval, Netlogon re-registration against Tenko with GSS-TSIG, and migration per the Phase 4 criteria. | 4 |
| Platform | 3-node cluster: kill a controller and verify that DNS and DHCP keep serving. Windows service and systemd start, stop and upgrade. Passkey, TOTP and PIN policy end to end in the UI. | 1 |
| Resources | RSS and CPU of the single-node home-lab profile measured and documented per release. Target: idle below 100 MB RSS with all roles on one node (OPS-15). | 1 onward, every release |

## Open questions

These are non-blocking and are resolved during Phase 0.

| Question | Impact |
|---|---|
| Product name | Resolved: the name Tenko DDI was decided on 2026-10-09. |
| Windows Server version in the reference environment | Query Resolution Policies require 2016 or later. Affects only the test lab. |
| IPv6 in the reference home network today | Affects priority within Phase 3, not the data model. |
| License for a possible publication | Decided on 2026-10-22: the Business Source License 1.1 with an internal-use grant and AGPL-3.0-or-later as the Change License, with a contributor license agreement (`LICENSE.md`, `CLA.md`, ADR 0022); the lawyer's review and the publication itself remain (API-20). |
