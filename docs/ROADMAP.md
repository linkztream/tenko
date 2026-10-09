# DDI Roadmap

DDI is delivered in six phases (Phase 0 to 5), in the order recorded in [ADR 0007](adr/0007-delivery-order.md): platform and IPAM first, then DNS, DHCP, AD integration and migration, and finally enterprise features. The order follows dependencies. IPAM replaces the existing IPAM spreadsheet immediately and builds the intent model that the engines act on later. The DNS and DHCP engines then become the actuators of that model. AD integration and migration need both engines in place.

The reference home-lab environment (three LANs plus a DMZ, Active Directory, a self-hosted UniFi Network Application, Proxmox VE, Home Assistant) is the first acceptance environment. The Phase 1 to 3 criteria below are stated in terms of it. Phase 4 acceptance uses a separate Windows Server test domain.

Per-requirement phase assignments live in [REQUIREMENTS.md](REQUIREMENTS.md). Its Phase column is authoritative. Requirement IDs cited in this document are pointers, not a complete list per phase. Architecture is described in [ARCHITECTURE.md](ARCHITECTURE.md), migration design and runbooks in [MIGRATION.md](MIGRATION.md), and per-RFC targets in [CONFORMANCE.md](CONFORMANCE.md).

## Overview

| Phase | Name | Theme | Exit gate |
|---|---|---|---|
| 0 | Foundation and spikes | Decide with measurements before committing to the architecture | All three spikes have reproducible data in `bench/`; the Raft gate decision is recorded in ADR 0002 |
| 1 | Platform and IPAM | Control plane, IPAM as intent hub, discovery, connectors | The existing IPAM spreadsheet is replaced; all four networks are scanned; UniFi VLANs and a manual-step IoT move work |
| 2 | DNS | Authoritative, forwarder/cache and DNSSEC engines | A home network sends all queries through DDI; BIND interop works in both directions |
| 3 | DHCP | DHCPv4/v6, failover, DDI as IPAM actuator | The failover pair survives the chaos test; the reference environment runs DHCP through DDI |
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

### Spike B: UDP throughput and DNS wire-format crate

- Measure UDP echo-DNS throughput on Windows and Linux with SO_REUSEPORT sharding (one socket per core).
- Compare parsing with `domain` (NLnet Labs) and `hickory-proto`. The result selects the DNS wire-format crate and is recorded in an ADR.
- Windows has no SO_REUSEPORT load distribution. On Windows the spike measures the equivalent RIO/IOCP sharding strategy.
- Measure `recvmmsg` on Linux. io_uring is evaluated as an option, not assumed.

### Spike C: Embedded SPA

Serve the SPA from the binary together with SSE, and measure cold start and bundle size.

**Result (2026-10-09, Windows):** all targets met. Cold start 17 ms (target below 200 ms), idle working set 10.8 MiB (target below 30 MB), about 27,900 SSE clients per GiB (target at least 10,000). The embedding mechanism, caching rules and SSE pattern are decided in ADR 0008; results in `bench/spike-c-embed/results/2026-10-09-windows.md`. Linux and multi-host runs are pending.

### Done when

- All three spikes have measurement data with reproducible scripts in `bench/`.
- The gate decision is documented in ADR 0002, with status Accepted, or in a superseding ADR that records the fallback. (Done: ADR 0002 is Accepted with conditions.)

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
- **Connectors**: Proxmox inventory; UniFi (read topology, write VLANs, port profiles and per-client VLAN with guardrails); Home Assistant inventory (CONN-01 to CONN-09).
- **VLAN objects, topology map and move job** with preview and rollback (IPAM-03, IPAM-19, IPAM-20).

In Phase 1 the move job performs the IPAM intent change, the UniFi L2 move and the observation. The reservation and DNS steps are manual tasks until DDI's own engines exist (Phase 2 to 3), at which point the same job becomes fully automatic.

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
- A home network sends all of its queries through DDI.
- BIND as secondary receives DDI's zones, and the reverse direction works too.
- Fuzz targets for wire format, zone file and TSIG run in CI.

## Phase 3: DHCP

### Deliverables

- **DHCPv4**: scopes, pools, exclusions, reservations, options at all levels, classes and policies, relay and option 82, shared networks, PXE/UEFI, conflict detection, MAC filter, lease WAL and lease history (DHCP-01 to DHCP-08).
- **DHCPv6**: IA_NA, IA_PD, DUID, relay and RFC 6939 correlation (DHCP-09, DHCP-11).
- **Failover**: hash split, MCLT, hot-standby and load-balance modes, partner-down state and lease sync between pairs (DHCP-12).
- **DDNS**: option 81, DHCID and name protection, PTR records, and updates on commit, expire and release (DHCP-13).
- **IPAM reconciliation**: leases, DNS, scans and intent in one view with conflict rules (IPAM-21). Fingerprinting from options 55 and 60 feeds the OS field (DHCP-14).
- **DDI DHCP as actuator**: reservations are created directly from IPAM intent, and leases become observations without polling (DHCP-16).

The move job becomes fully automatic for `reserved` hosts (the DNS step was already automatic in Phase 2). This is where the IoT move becomes one click.

### Done when

- kea perfdhcp numbers are documented.
- The failover pair passes the chaos test: a partner is killed mid-load and no duplicate leases result (DHCP-18).
- The reference home-lab environment runs DHCP through DDI for all four networks via relay.

## Phase 4: AD integration and migration

### Deliverables

- **GSS-TSIG**: TKEY exchange via SSPI on Windows and krb5 on Linux, computer account and SPN setup in a wizard, ownership per RRset, and a "secure only" mode per zone (DNS-28).
- **AD behaviors**: aging and scavenging with Windows semantics (DNS-29), DC locator validation of SRV records in `_msdcs` and `_sites` (DNS-30), and AD Sites and Services sync with IPAM sites (IPAM-22).
- **Migration connectors** as specified in MIGRATION.md: Windows DNS (cmdlets, LDAP and `.dns` files), Windows DHCP (XML and cmdlets), BIND, OPNsense, dnsmasq and Pi-hole, Kea and dhcpd, and NetBox and phpIPAM. Proxmox inventory already exists from Phase 1 (MIG-01, MIG-06 to MIG-13).
- **Migration pipeline**: `ddi migrate plan`, `ddi migrate apply` and `ddi migrate verify`; coexistence modes (secondary, forward, flip); query-replay parity; runbooks in MIGRATION.md (MIG-03 to MIG-05, MIG-17).
- **Inventory sources**: Hyper-V and VMware vSphere (CONN-10, CONN-11).
- **External actuators for coexistence**: DHCP (CONN-12) and DNS (CONN-13).
- **Windows interop lab**: a Windows Server 2016 or later test domain (API-18).

### Coexistence and verification

Migration runs through one pipeline for every source. Each source adapter produces the canonical intermediate representation plus a loss report that lists what could not be mapped (MIG-01). AXFR is the universal baseline for DNS data (MIG-02). The adapters add what AXFR drops: ownership, timestamps, forwarders, views and policies, and DHCP.

Coexistence modes are selected per zone or scope (MIG-04):

1. Secondary: DDI is an AXFR secondary and stays in sync until the flip, with a nightly parity diff.
2. Forward: DDI forwards some zones to the old server while it takes over others.
3. Flip: DDI becomes primary and the old server becomes its secondary, or is switched off after a rollback window.

Verification is by query replay (MIG-05): live queries are sampled from dnstap or the query log, asked of both servers, and the RCODE and answers are diffed with TTL drift ignored. No AD-backed zone storage mode is built (CON-11).

### Done when

- A Windows Server test domain (2016 or later) with Query Resolution Policies, zone scopes, aging and DHCP failover is migrated in the lab without manual intervention (MIG-18).
- Domain join, GPO processing and DC locator work against DDI.
- Windows DNS is switched off and clients notice nothing.

## Phase 5: Enterprise and ecosystem

### Deliverables

- **Recursive resolver**: DDI's own recursive resolver with DNSSEC validation, QNAME minimization, aggressive NSEC and RFC 5011 trust anchor maintenance (DNS-03, DNS-13, DNS-34). Until then, recursion is served by the forwarder, cache and RPZ combination from Phase 2.
- **Identity**: OIDC and SAML, LDAP group mapping, SPNEGO and SCIM; PKCS#11 and KMS support for the KEK (IAM-11 to IAM-14, IAM-17).
- **Scaling hooks**: anycast health hooks (BGP withdrawal) and autoscaling hooks for the Kubernetes, Nomad and Proxmox APIs (OPS-17, OPS-18).
- **Ecosystem**: Terraform provider, Ansible collection, webhooks, and a NetBox-compatible API for Proxmox SDN (API-06, API-07, CONN-17).
- **Remote access gateway**: HTML5 RDP/SSH gateway as an opt-in module with credential injection, session recording and just-in-time access (API-12).
- **Actuators and inventory**: hypervisor actuators (Proxmox `pct set` and cloud-init) that move `static` hosts automatically, more network controllers, and inventory from Docker, Kubernetes and Incus (CONN-14 to CONN-16).
- **Release and licensing**: DoQ, signed releases, SBOM, the license decision and possible publication (DNS-16, API-19, API-20).

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
| AD | Windows Server 2016 or later test domain in a VM: domain join, DC locator, GPO retrieval, Netlogon re-registration against DDI with GSS-TSIG, and migration per the Phase 4 criteria. | 4 |
| Platform | 3-node cluster: kill a controller and verify that DNS and DHCP keep serving. Windows service and systemd start, stop and upgrade. Passkey, TOTP and PIN policy end to end in the UI. | 1 |
| Resources | RSS and CPU of the single-node home-lab profile measured and documented per release. Target: idle below 100 MB RSS with all roles on one node (OPS-15). | 1 onward, every release |

## Open questions

These are non-blocking and are resolved during Phase 0.

| Question | Impact |
|---|---|
| Product name | `ddi` is the working name for the workspace and binary. Rename early if desired. |
| Windows Server version in the reference environment | Query Resolution Policies require 2016 or later. Affects only the test lab. |
| IPv6 in the reference home network today | Affects priority within Phase 3, not the data model. |
| License for a possible publication (Apache-2.0 or AGPL-3.0) | Must be decided before any publication (API-20). |
