# Tenko DDI Requirements

Tenko DDI is a DNS + DHCP + IPAM stack written in Rust with an embedded SolidJS UI. It replaces Active Directory-integrated Windows DNS and DHCP and scales from a home lab (three LANs plus a DMZ) to enterprise. The goals are maximum performance, minimal resource consumption, a fast UI, and security that can be relaxed for lab use. IPAM replaces an existing IPAM spreadsheet and populates itself through network scanning. This is a living specification, maintained under the change rules below.

## How to read this document

Every requirement has a stable ID of the form PREFIX-NN, a phase and a priority.

| Prefix | Area |
|---|---|
| DNS | DNS engines and features |
| DHCP | DHCPv4, DHCPv6, failover, PXE, DDNS |
| IPAM | Address management, reconciler, move jobs |
| SCAN | Scanner and discovery |
| IAM | Identity and access |
| OPS | Operations and high availability |
| API | API and product |
| CONN | Connectors and integrations |
| MIG | Migration |
| CON | Design constraints (corrected premises) |
| PER | Personas |

Security-profile toggles (TGL) and the never-off list (NEVER) are defined in SECURITY-PROFILES.md. RFC-level targets are defined in CONFORMANCE.md.

A requirement's phase is the phase in which it is first delivered. Deliverables and "Done when" criteria per phase are in ROADMAP.md.

| Phase | Name |
|---|---|
| 0 | Foundation and spikes |
| 1 | Platform and IPAM |
| 2 | DNS |
| 3 | DHCP |
| 4 | AD integration and migration |
| 5 | Enterprise and ecosystem |

| Priority | Meaning |
|---|---|
| Must | Required for the product and for the phase's "Done when" |
| Should | Expected; may slip a phase with a recorded reason |
| Could | Desirable; scheduled opportunistically |

Change rules:

- IDs are never reused or renumbered.
- A dropped requirement keeps its row, marked "Withdrawn" with a reason.
- A new requirement takes the next free number in its section.
- A change that alters architecture needs an ADR (see adr/README.md).

## Baseline decisions

| Area | Decision | Recorded in |
|---|---|---|
| Language, data plane | Rust | ADR 0001 |
| Storage and replication | Embedded Raft store over an embedded KV store, conditional on more than 1M records per zone working (go/no-go in Phase 0, Spike A: RSS under 2 GB at 5M records, new node caught up in under 5 minutes on 1 Gbit, p99 query latency unaffected). Fallback: Raft only for configuration, IPAM and policies, with zone data replicated between Tenko nodes by built-in IXFR/NOTIFY (primary/secondary) | ADR 0002 (Proposed, pending Spike A) |
| GUI | SPA (SolidJS + TypeScript) embedded in the binary | ADR 0003 |
| Deployment model | One statically linked binary, `tenko`, running any combination of the roles `controller`, `dns`, `dhcp` and `probe` | ADR 0004 |
| IPAM's role | IPAM is the hub: intent in IPAM propagates to DHCP, DNS and network controllers; observations from DHCP, DNS, scanning, hypervisors and network controllers flow back | ADR 0005 |
| Migration | Connector architecture for mixed sources, built around a canonical intermediate representation | ADR 0006 |
| External systems | Connectors for hypervisors (Proxmox first, Hyper-V and VMware later), Home Assistant and network controllers (UniFi first, self-hosted controller, read and write with guardrails), with VLAN control and a topology map | ADR 0006 |
| External DHCP/DNS actuators | Not in Phase 1. Tenko's own engines in Phases 2 and 3 become the actuators; the Windows connector arrives in Phase 4 as a migration source | ADR 0005 |
| Delivery order | Platform and IPAM first, then DNS, DHCP, AD integration and migration, then enterprise | ADR 0007 |
| RDP/SSH | URI handoff first; HTML5 gateway as an opt-in module in a later phase | ADR 0007 |
| Recursion | Forwarder + cache + RPZ first (Phase 2); Tenko's own recursive resolver with DNSSEC validation in Phase 3, Slice 10 (the owner's decision REC-Q1 of 2026-10-22) | ADR 0007, ADR 0021 |
| Distribution | Private repository now, written as if it will become public | ADR 0007 |

## Personas

| ID | Persona | Needs | Default security profile |
|---|---|---|---|
| PER-01 | Home user (home-lab profile) | One box runs all roles; replaces the existing IPAM spreadsheet; Pi-hole-style blocking; Proxmox and Home Assistant inventory; moving IoT devices with one gesture; minimal friction | Home |
| PER-02 | Business administrator | AD domain with several sites or VLANs; delegation; audit; migration off Windows DNS and DHCP; SSO later | Standard |
| PER-03 | Hardened or regulated environment | Strict authentication (passkeys, MFA per role); audit export; change control through request and approval; external key management | Hardened |
| PER-04 | Lab or pentest | Permissive configuration for testing and training; never attack tooling | Lab |

The reference home-lab environment is three LANs plus a DMZ, Active Directory, a self-hosted UniFi Network Application, Proxmox VE and Home Assistant. It is the first acceptance environment: the "Done when" criteria of Phases 1 to 3 in ROADMAP.md are stated against it, while Phase 4 acceptance uses a Windows Server test domain in the lab (MIG-18). It exercises one probe per segment (SCAN-01), relay-served DHCP (DHCP-04) and a self-hosted UniFi controller (CONN-07).

## Security profiles

Tenko offers four profiles: Home, Standard, Hardened and Lab. The administrator chooses one in the first-run wizard (API-10). A profile is a bundle of toggles (TGL-01 to TGL-22), not a separate code path; the full matrix is in SECURITY-PROFILES.md.

Some behavior can never be switched off: secrets are encrypted at rest (NEVER-01, IAM-15), the audit log is always on (NEVER-02, IAM-18) and every admin action is attributable to an authenticated principal (NEVER-03, IAM-19). The PIN coupling rule (CON-07, IAM-07) applies in every profile. The Lab profile may relax everything else, but it means permissive configuration, never attack tooling (CON-09).

## Design constraints

These are corrected premises: assumptions that were examined and replaced.

### CON-01: Rust, not assembler

**Premise.** Hand-written assembler is needed for maximum performance.

**Constraint.** DNS and DHCP parsers receive unfiltered packets from the network, which is exactly where the BIND, Kea and dnsmasq CVEs live. Rust gives C-class throughput without garbage-collection tails. Performance is I/O bound, not CPU bound: `recvmmsg`, io_uring (a measurable option, not an assumption), RIO, `SO_REUSEPORT` sharding with one socket per core, and a lock-free cache. SIMD is used only where profiling justifies it, and `unsafe` code needs an ADR.

**Affects.** ADR 0001, API-16, DNS-27.

### CON-02: Mail authentication is record content

**Premise.** DKIM, SPF and DMARC are server features.

**Constraint.** They are record content, so the server needs only correct TXT handling, with strings over 255 bytes split into multiple character-strings. The UI provides a record wizard and validator instead. The real server standards are DNSSEC, TSIG, DoT/DoH/DoQ, Response Rate Limiting and DNS Cookies.

**Affects.** DNS-24, DNS-25.

### CON-03: Secure updates mean GSS-TSIG

**Premise.** "Secure updates" in AD can be replaced by TSIG keys or IP ACLs.

**Constraint.** "Secure updates" in AD means GSS-TSIG (RFC 3645) over TKEY with Kerberos. Tenko DNS needs an AD computer account with the SPN `DNS/<host>`, a keytab (Linux) or SSPI under that identity (Windows), and ownership per RRset. Without it, domain controllers fall back to insecure updates and protection is reduced to IP ACLs.

**Affects.** DNS-28, OPS-11.

### CON-04: DNS load balancing is not a client feature

**Premise.** DNS can be load balanced by replicating servers.

**Constraint.** Clients do not balance: they use the first server and fail over slowly. The real options are anycast (routing integration plus health-based withdrawal), an L4 load balancer (a new single point of failure), or two addresses in DHCP option 6. Replication is not load distribution.

**Affects.** OPS-17, DHCP-02 (option 6).

### CON-05: DHCP load balancing is a failover protocol

**Premise.** DHCP load balancing is a simple feature that interoperates across vendors.

**Constraint.** Load balancing in DHCP means a failover protocol. DHCPv4 failover has no RFC; the Windows and ISC variants are proprietary and not interoperable (DHCPv6 has RFC 8156). Coexistence with Windows DHCP therefore uses split scopes, not a shared failover relationship.

**Affects.** DHCP-12, MIG-08.

### CON-06: Autoscaling is hooks, not core

**Premise.** The DNS core needs autoscaling logic.

**Constraint.** One core handles more than 100k QPS, and DNS latency usually sits upstream. What is needed is orchestrator integration (Kubernetes, Nomad, Proxmox API) plus anycast or a load balancer plus warm caches. It is built as hooks and metrics outside the core.

**Affects.** DNS-27, OPS-17, OPS-18.

### CON-07: PIN policy is coupled to the vault

**Premise.** A 4-digit PIN is acceptable for home use.

**Constraint.** A 4-digit PIN protecting a vault that holds domain-admin credentials is not defensible, even at home. The policy is tied to function: a PIN is allowed as the sole factor only while the vault is empty or disabled; otherwise at least a passkey is required, or the PIN serves as a second factor. The rule holds in every security profile.

**Affects.** IAM-03, IAM-07.

### CON-08: Conformance is a matrix, not "all standards"

**Premise.** Tenko should implement all DNS standards.

**Constraint.** DNS alone has roughly 300 RFCs. Tenko publishes a conformance matrix (CONFORMANCE.md) with an explicit target phase per RFC and tests each as its engine lands.

**Affects.** API-17, CONFORMANCE.md.

### CON-09: Lab mode is configuration, not attack tooling

**Premise.** A pentest mode should include offensive capabilities.

**Constraint.** Pentest mode means permissive configuration. Tenko contains no Responder-like functionality (name-resolution poisoning, credential capture). The reason is liability.

**Affects.** SECURITY-PROFILES.md (Lab profile).

### CON-10: Moving a device needs L2 control

**Premise.** Dragging a host to another network in the UI moves the device.

**Constraint.** Drag and drop moves no device physically. Without L2 control a device stays in its old VLAN and gets the old scope's address regardless of what IPAM and DHCP say. Network-controller integration (UniFi first) is therefore a prerequisite for moving devices, not a bonus. A device also picks up its new address only on link flap or lease renewal, because clients do not support DHCP FORCERENEW in practice. A move is a job that waits for observation, not a click that completes immediately.

**Affects.** IPAM-19, CONN-06, CONN-09.

### CON-11: No AD-backed zone storage

**Premise.** Tenko needs a Samba-style mode that keeps zone data in AD.

**Constraint.** The connector model makes this mode unnecessary, so it is not built.

**Affects.** MIG-01, MIG-06.

### CON-12: No WINS lookup

**Premise.** Windows DNS compatibility includes WINS lookup.

**Constraint.** WINS lookup (the WINS and WINS-R records of Windows DNS) is deliberately not supported and is recorded as an explicit non-conformance.

**Affects.** CONFORMANCE.md.

## DNS

Tenko DNS has three engines, not one, because AD clients expect a single server to be authoritative, to forward and cache and, later, to recurse.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| DNS-01 | Authoritative engine serving all common RR types and unknown types (RFC 3597) over UDP and TCP. | 2 | Must |
| DNS-02 | Forwarder/cache engine in the same server as the authoritative engine, with conditional forwarders per zone and stub zones. Recursive service is restricted by an ACL per view (TGL-22). | 2 | Must |
| DNS-03 | Own full recursive resolver. Until it is delivered, recursion is provided by forwarder + cache + RPZ (DNS-02, DNS-21). | 3 (Slice 10) | Should |
| DNS-04 | IPv6 parity: AAAA records, `ip6.arpa` reverse zones and IPv6 transport for every DNS function. | 2 | Must |
| DNS-05 | TCP is mandatory and implemented per RFC 7766. | 2 | Must |
| DNS-06 | EDNS(0) per RFC 6891 with a default UDP buffer size of 1232 bytes. | 2 | Must |
| DNS-07 | DNS Cookies (RFC 7873). | 2 | Must |
| DNS-08 | Outgoing queries use source port randomization and 0x20 case randomization. | 2 | Must |
| DNS-09 | Zone transfer in and out: AXFR, IXFR, NOTIFY, TSIG and XFR-over-TLS (XoT). Interoperates with BIND and Windows as secondary or primary. Required regardless of internal replication, because the same mechanism serves migration (MIG-02). | 2 | Must |
| DNS-10 | Catalog zones (RFC 9432). | 2 | Should |
| DNS-11 | Dynamic updates per RFC 2136, authenticated with TSIG and restricted by ACLs. | 2 | Must |
| DNS-12 | DNSSEC signing: online and offline signing, NSEC and NSEC3, automatic key rollover driven by CDS/CDNSKEY. | 2 | Must |
| DNS-13 | DNSSEC validation in the resolver, with RFC 5011 trust anchor maintenance and negative trust anchors. | 3 (Slice 10) | Must |
| DNS-14 | DoT and DoH served to clients. | 2 | Must |
| DNS-15 | DoT and DoH used toward upstream forwarders. | 2 | Must |
| DNS-16 | DoQ as server and as upstream transport. | 5 | Should |
| DNS-17 | Abuse protection: Response Rate Limiting, per-client limits and minimal-responses. | 2 | Must |
| DNS-18 | ANY queries minimized per RFC 8482. | 2 | Must |
| DNS-19 | ACLs restrict who may request zone transfers, in addition to TSIG (DNS-09). | 2 | Must |
| DNS-20 | Views and policies model for split horizon: a view is a name, match rules (client subnet, transport, interface IP, QType, time of day, FQDN), a zone scope and a weight. One model covers Windows zone scopes + Query Resolution Policies, BIND views and a simple internal/external split, and maps directly during migration. | 2 | Must |
| DNS-21 | RPZ and blocklists: a Pi-hole replacement at home, threat feeds in enterprise. | 2 | Must |
| DNS-22 | Reverse zones are created automatically from IPAM prefixes, including RFC 2317 classless delegation for shared /24s. | 2 | Must |
| DNS-23 | Cache with serve-stale (RFC 8767) and prefetch. | 2 | Must |
| DNS-24 | Correct TXT handling: strings over 255 bytes are split into multiple character-strings (CON-02). | 2 | Must |
| DNS-25 | UI wizard and validator for SPF, DKIM and DMARC records (CON-02). | 2 | Could |
| DNS-26 | dnstap output, also usable as the sampling source for query-replay verification (MIG-05). | 2 | Should |
| DNS-27 | Performance: a single core sustains more than 100k QPS; dnsperf and flamethrower results are documented. | 2 | Should |
| DNS-28 | AD secure dynamic updates: GSS-TSIG (RFC 3645) over TKEY, SSPI on Windows and krb5 on Linux. A wizard sets up the computer account and the SPN `DNS/<host>`. Ownership is tracked per RRset, with a "secure only" mode per zone (CON-03). | 4 | Must |
| DNS-29 | Aging and scavenging with Windows semantics: a per-record timestamp (null means static), NoRefresh and Refresh intervals, and designated scavenging servers. Timestamps survive replication and import (MIG-06, MIG-07). | 4 | Must |
| DNS-30 | AD DC locator: SRV records in `_msdcs` and `_sites` are served and validated. Netlogon re-registers them every 24 h. | 4 | Must |
| DNS-31 | Global Query Block List, with `wpad` and `isatap` as default entries. | 4 | Must |
| DNS-32 | GlobalNames zone. | 4 | Should |
| DNS-33 | Netmask ordering and round robin as toggles. | 4 | Should |
| DNS-34 | Resolver QNAME minimization (RFC 9156) and aggressive use of the DNSSEC-validated cache (RFC 8198). | 3 (Slice 10) | Should |

## DHCP

Tenko DHCP serves from a local lease store with no database round trip in the DORA path (OPS-02) and acts as an IPAM actuator (DHCP-16).

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| DHCP-01 | DHCPv4 core: scopes, pools, exclusions, reservations (keyed by MAC or client-id) and superscopes. | 3 | Must |
| DHCP-02 | Options at every level with inheritance from server to scope to class to reservation, and custom option definitions. DNS redundancy for clients is delivered as two addresses in option 6 (CON-04). | 3 | Must |
| DHCP-03 | Classes and policies: vendor class, user class and MAC wildcard matching. | 3 | Must |
| DHCP-04 | Relay support: option 82 (circuit-id, remote-id), giaddr-based scope selection, link selection (RFC 3527) and shared networks (several subnets on one link). This is how one server serves three LANs plus a DMZ. | 3 | Must |
| DHCP-05 | PXE and UEFI boot: options 43, 60, 66, 67 and 93; ProxyDHCP on port 4011; iPXE; UEFI HTTP boot. | 3 | Must |
| DHCP-06 | Conflict detection (ping before offer) and DECLINE handling. | 3 | Must |
| DHCP-07 | Durable lease store with a local write-ahead log (WAL) per node, and lease history. Leases never pass through the global Raft group, because every DORA exchange is a write. | 3 | Must |
| DHCP-08 | MAC allow and deny filters. | 3 | Must |
| DHCP-09 | DHCPv6 per RFC 8415: IA_NA, IA_PD (prefix delegation), DUID and relay. | 3 | Must |
| DHCP-10 | Router Advertisement interplay: the M and O flags must match the DHCPv6 service, and DHCPv6 cannot set a default route, which stays an RA function. | 3 | Should |
| DHCP-11 | IPv4/IPv6 correlation per host using the client link-layer address option (RFC 6939). | 3 | Should |
| DHCP-12 | Failover between Tenko nodes: hash split (RFC 3074), MCLT, partner-down state, lease sync, and hot-standby and load-balance modes. DHCPv6 failover follows RFC 8156; DHCPv4 failover has no RFC and is Tenko's own protocol, not interoperable with Windows or ISC (CON-05). | 3 | Must |
| DHCP-13 | DDNS from DHCP: option 81 (RFC 4702) and DHCPv6 FQDN (RFC 4704), DHCID and name protection (RFC 4701, RFC 4703), updates on commit, expire and release, PTR records, and "update for legacy clients". | 3 | Must |
| DHCP-14 | Passive OS fingerprinting from options 55 and 60 feeds the IPAM OS field without active scanning. | 3 | Should |
| DHCP-15 | NTP servers via option 42, because Kerberos and DNSSEC depend on time synchronization (OPS-09). | 3 | Must |
| DHCP-16 | Tenko DHCP is an IPAM actuator: reservations are created directly from IPAM intent (MAC or client-id for v4, DUID for v6), and leases become observations without polling. This makes the move job fully automatic for `reserved` hosts (IPAM-19). | 3 | Must |
| DHCP-17 | Performance measured with kea perfdhcp; results documented. | 3 | Should |
| DHCP-18 | Failover chaos test: the partner is killed under load and no duplicate leases result. | 3 | Must |

## IPAM

IPAM is the hub (ADR 0005). Everything it knows is either intent (what the administrator wants) or observation (what is actually seen), and a reconciler drives actuators until the two agree, in both directions.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| IPAM-01 | Tenants and VRFs, so that overlapping RFC 1918 space in separate networks can coexist. | 1 | Must |
| IPAM-02 | Hierarchy: supernet, prefix, range, address. | 1 | Must |
| IPAM-03 | VLAN (and VNI) as first-class objects with id, name and site, linked to prefixes and sites and synchronized with the network controller. Creating a network and VLAN in IPAM can create the UniFi network in the same job (CONN-06). | 1 | Must |
| IPAM-04 | Sites, mappable to AD sites. | 1 | Must |
| IPAM-05 | Status lifecycle for prefixes, ranges and addresses. | 1 | Must |
| IPAM-06 | IPv6 planning on nibble boundaries. | 1 | Must |
| IPAM-07 | "Next free" API for prefixes and addresses. | 1 | Must |
| IPAM-08 | Tags, custom fields, devices and interfaces. | 1 | Must |
| IPAM-09 | Immutable history and soft delete. | 1 | Must |
| IPAM-10 | Utilization alarms when a subnet is nearly full. | 1 | Must |
| IPAM-11 | CSV/Excel import with column mapping in the UI, replacing the existing spreadsheet, and an import/export round trip. | 1 | Must |
| IPAM-12 | Intent and observation are separate layers. Intent: host X has IP Y in network Z, with assignment mode, DNS name and VLAN. Observation: DHCP leases, DNS records, scan results, hypervisor inventory and network-controller client tables. | 1 | Must |
| IPAM-13 | A reconciler continuously compares intent and observation and drives actuators until they match, in both directions: changes in IPAM take effect in DHCP, DNS and network controllers, and changes observed there appear in IPAM. | 1 | Must |
| IPAM-14 | Assignment mode per host: `static`, `reserved`, `dynamic` or `unmanaged`. The mode decides what IPAM may do in DHCP and DNS (table below). | 1 | Must |
| IPAM-15 | Observations without intent create proposals, never intent: an unknown MAC in a lease becomes a "discovered host", a DNS record without a host becomes an "orphaned record". A proposal is approved with one click or by an auto-adopt rule per network. | 1 | Must |
| IPAM-16 | Intent wins for managed hosts. A per-host `lock` flag stops all automation. | 1 | Must |
| IPAM-17 | Every change is a job with steps, status, timeout and rollback, visible in the UI and API. Nothing happens silently. | 1 | Must |
| IPAM-18 | IPAM warns when the MAC (v4) or DUID (v6) is missing before a reservation can be created. | 1 | Must |
| IPAM-19 | Move job: select one or many hosts and drag them to another network. A per-device preview shows old IP to new IP, the DNS change, the L2 action and manual steps. Confirmation runs one job per device (steps below the assignment-mode table) under the guardrails of CONN-09. Phase 1 performs IPAM intent + UniFi L2 move + observation, with DHCP and DNS steps as manual tasks; the DNS step becomes automatic with Tenko DNS (Phase 2) and `reserved` hosts fully automatic with Tenko DHCP (Phase 3). The observation timeout defaults to half the DHCP lease time of the target network (the renewal point), with a floor of 5 minutes, shown in the preview; when it expires the job rolls back automatically. Manual steps are presented as one grouped checklist for the whole job, and a device waits for its ticked tasks before the L2 change. | 1 | Must |
| IPAM-20 | Topology map: a graph of routers, switches, APs, hosts, VMs/containers and hypervisors, with ports, wireless associations, uplinks and VM-to-host links as edges. Sources: UniFi, LLDP/CDP and bridge tables via SNMP, hypervisor connectors, and ARP/ND from probes. The interactive map filters by VLAN and site, opens the host view on click, highlights paths and answers "what is connected to this port". VLAN colors are generated dynamically for the VLANs in view, with hues spread across the spectrum at a fixed lightness and chroma per theme so that every color keeps at least 3:1 contrast against the map background, with labels, a legend and an optional pattern mode as redundancy for colorblind users; with very many VLANs (150 or more) color follows the selection or the site and the rest stay neutral. | 1 | Must |
| IPAM-21 | Unified reconciliation view across the four truths (IPAM intent, DHCP leases, DNS records, scans), with ghost, rogue, orphan and PTR-mismatch views and "who wins" rules. | 3 | Must |
| IPAM-22 | AD Sites and Services: bidirectional sync of site-to-subnet mappings (`CN=Subnets,CN=Sites,CN=Configuration`) with IPAM sites. It is a sync, not a storage model (CON-11). | 4 | Must |
| IPAM-23 | IP conflict detection: the same address observed from two different MACs or DUIDs (ARP/ND, leases, scans), an observed address that collides with the intent of another host, a reservation that overlaps a dynamic pool, and overlapping prefixes inside one VRF are flagged as conflicts with an alert and shown in the host and prefix views. Intentional overlap is only allowed across VRFs (IPAM-01). | 1 | Must |

Assignment modes (IPAM-14). The reconciler design and actuator drivers are described in ARCHITECTURE.md.

| Mode | Behavior |
|---|---|
| `static` | Only DNS is updated. The job adds a manual task: reconfigure the device. |
| `reserved` | An IP change creates or moves the DHCP reservation and updates DNS. |
| `dynamic` | IPAM only observes. |
| `unmanaged` | Nothing touches the host. |

Move job steps (IPAM-19), run per device:

1. Choose the new IP: the same host part (last octet, or interface ID for IPv6) if free in the target network, otherwise the next free address per network policy.
2. Create the reservation in the target scope. The old reservation is kept until the move is observed.
3. Update DNS (A, AAAA, PTR). On a name collision, propose a new name.
4. L2 move via UniFi: change the port profile for wired devices; set a per-client VLAN or move to an SSID that carries the VLAN for wireless devices. Devices that cannot be controlled get a manual step.
5. Wait for observation: a lease in the new scope from the right MAC, or ARP/ping in the new network, within a configurable timeout.
6. Clean up: remove the old reservation, release the old lease, remove the old DNS records.
7. Roll back steps 2 to 4 if steps 4 to 5 do not succeed within the timeout, and mark the device "move failed" with the reason.

## Scanner and discovery

Discovery is passive first and active second. IDS/EDR products will alert on active scanning (Defender for Identity flags port scanning), whereas passive discovery is quiet and cheap.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| SCAN-01 | One probe per network segment, because ARP/ND do not cross routers. The probe is a role of the same agent as the DNS and DHCP nodes (ADR 0004). The DMZ probe is its own trust zone. | 1 | Must |
| SCAN-02 | Passive discovery first: ARP/NDP, mDNS and LLDP. | 1 | Must |
| SCAN-03 | Further passive sources: DHCP snooping and LLMNR. | 1 | Should |
| SCAN-04 | Active scanning: ICMP, TCP SYN port scans and OS fingerprinting. Raw sockets need CAP_NET_RAW on Linux and Npcap on Windows, and do not work in an unprivileged LXC without explicit configuration; the setup is documented. | 1 | Must |
| SCAN-05 | SNMPv3 polling of switches: MAC, ARP, LLDP/CDP and bridge tables give port mapping without scanning. Credentials are held in the vault (IAM-16). | 1 | Must |
| SCAN-06 | Scheduling, rate limits and blackout windows. | 1 | Must |
| SCAN-07 | Documented IDS/EDR allow-listing and slow scan profiles. | 1 | Must |
| SCAN-08 | Host view with open ports and OS. | 1 | Must |
| SCAN-09 | On-demand scans: a network, prefix or single host can be scanned immediately from the UI, API and CLI (passive refresh, port scan, OS fingerprint, SNMP poll), independent of the schedule in SCAN-06. The scan runs as a job with progress and result diff against the previous scan. | 1 | Must |

## Identity and access

Access is object-scoped, and authentication strength follows the security profile (SECURITY-PROFILES.md). The vault and the audit log are never optional (NEVER-01 to NEVER-03).

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| IAM-01 | Object-based RBAC scoped per zone, DHCP scope, prefix and site, with delegation. | 1 | Must |
| IAM-02 | Request and approval workflows for changes (enterprise). | 5 | Should |
| IAM-03 | Local passwords hashed with Argon2id. Policy presets: PIN, Standard, Hardened and Custom (regex + length + HIBP). Semantics follow NIST SP 800-63B. The PIN preset is bound by CON-07. | 1 | Must |
| IAM-04 | Breached-password check against HIBP using k-anonymity, with an offline option. | 1 | Must |
| IAM-05 | Account lockout. | 1 | Must |
| IAM-06 | MFA: TOTP, passkeys (WebAuthn) and recovery codes. The MFA requirement is configurable per role. | 1 | Must |
| IAM-07 | PIN coupling rule (CON-07) enforced in every security profile: a PIN is the sole factor only while the vault holds no secrets; otherwise a passkey is required at minimum, or the PIN serves as a second factor. | 1 | Must |
| IAM-08 | Session management: lifetime and revocation. | 1 | Must |
| IAM-09 | Break-glass local account, usable with a hardware security key only. | 1 | Must |
| IAM-10 | Scoped API tokens with expiry, and service accounts. | 1 | Must |
| IAM-11 | SSO via OIDC and SAML. Reference targets: AD FS, Entra ID and Okta. | 5 | Should |
| IAM-12 | LDAP/AD group mapping. | 5 | Should |
| IAM-13 | Kerberos SPNEGO, which is expected in AD environments. | 5 | Should |
| IAM-14 | SCIM provisioning. | 5 | Could |
| IAM-15 | Vault with envelope encryption: a DEK per secret, with the KEK taken from the OS key store (DPAPI on Windows, TPM or keyring on Linux). | 1 | Must |
| IAM-16 | Vault handling: rotation, zeroization in memory and audit on every reveal. The vault holds TSIG keys, failover secrets, SNMPv3 credentials, DDNS credentials, connector credentials and host credentials. Operator secrets are first-class objects (name, kind, purpose tags, optional user name, notes) bound to hosts by role and referenced by connectors by purpose; a reveal returns the value once to a person with an interactive session of password strength or stronger under the reveal policy (TGL-24), is rate limited, and is audited with the principal, the secret, the host and the reason, never the value. | 1 | Must |
| IAM-17 | External KEK providers: PKCS#11, cloud KMS and an external secrets manager (for example HashiCorp Vault). | 5 | Should |
| IAM-18 | Audit log: immutable and hash-chained, with export to syslog, CEF and JSON. | 1 | Must |
| IAM-19 | Admin action attribution: every change is attributable to an authenticated principal. | 1 | Must |

## Operations and high availability

The data plane survives the control plane. At home, all roles run in one process on one box. In enterprise, three to five controllers run alongside N DNS nodes behind anycast, a DHCP failover pair per site and one probe per segment.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| OPS-01 | One statically linked binary runs any combination of roles: `controller`, `dns`, `dhcp`, `probe` (ADR 0004). | 1 | Must |
| OPS-02 | The data plane never depends on the control plane: each DNS and DHCP node keeps a durable local copy of zones, leases and configuration and keeps answering when the database, UI or controllers are down, with no database round trip in the DHCP DORA path or the DNS query path. | 1 | Must |
| OPS-03 | The controller store runs single-node and as a 3-node cluster, and the cluster survives the loss of a controller. | 1 | Must |
| OPS-04 | Node-to-node communication over gRPC with mTLS, an internal CA and enrollment tokens. The same mechanism serves Docker, LXC and native installs. | 1 | Must |
| OPS-05 | Observability: OpenMetrics (QPS, RCODE mix, latency histograms, cache hit ratio, lease rate, pool utilization), OpenTelemetry traces and health endpoints. The built-in UI dashboard (OPS-20) and the cost budget (OPS-21) build on the same counters. | 1 | Must |
| OPS-06 | Query logs are personal data (GDPR): configurable retention, pseudonymization, and the ability to disable logging. | 2 | Must |
| OPS-07 | Backup and restore are consistent across the database, leases and keys. | 1 | Must |
| OPS-08 | Rolling upgrades with protocol version negotiation between nodes. | 1 | Should |
| OPS-09 | Time synchronization is treated as a dependency: Kerberos tolerates 5 minutes of skew and DNSSEC signatures have validity windows. NTP is distributed via DHCP option 42 (DHCP-15). | 2 | Should |
| OPS-10 | Windows service: Service Control Manager integration and Windows Event Log. | 1 | Must |
| OPS-11 | On Windows, Tenko runs as a gMSA or domain account so that Kerberos works (CON-03). | 4 | Must |
| OPS-12 | MSI and winget packaging. | 4 | Should |
| OPS-13 | Linux: systemd unit, capabilities instead of root, seccomp and a non-root user. | 1 | Must |
| OPS-14 | Containers: Docker bridge NAT breaks DHCP broadcast and DNS source addresses, so macvlan or host networking is required. This is documented with examples (compose with macvlan, LXC notes). | 1 | Must |
| OPS-15 | Resource target: idle below 100 MB RSS with all roles on one node (home-lab profile), measured and published per release. | 1 | Should |
| OPS-16 | Declarative configuration with diff, dry-run and rollback (GitOps). | 5 | Should |
| OPS-17 | Health hooks that drive anycast route withdrawal (BGP via FRR or BIRD). Anycast is the supported way to distribute DNS load across nodes (CON-04). | 5 | Should |
| OPS-18 | Autoscaling hooks for orchestrators (Kubernetes, Nomad, Proxmox API), driven by metrics and kept outside the core (CON-06). | 5 | Could |
| OPS-19 | The replicated store runs on SSD or NVMe storage only. Rotating and SMR disks are unsupported for the data directory; the first-run wizard and the node health check warn when the data directory is on a rotating disk (ADR 0002: 93x slower load and lost leadership on an SMR disk). | 1 | Must |
| OPS-20 | Built-in dashboard in the UI, per node and cluster-wide: queries per second with a 60 s sparkline, p50/p99 latency, cache hit ratio, RCODE mix, DHCP leases per second, pool utilization per scope, store size on disk and in memory, Raft role and replication lag, and logging-ring drop counters. It is fed by the same metrics as OPS-05, pushed once per second over SSE, and never by a separate code path in the data plane. Rates are shown as numbers with a sparkline, never as dial gauges, and large numbers use SI suffixes (1.2K, 48K, 1.3M) so a tile never grows. | 1 | Must |
| OPS-22 | TLS modes for the API and UI: (a) the internal CA with a server certificate for the configured host name; (b) an imported certificate and key with hot reload on change and expiry warnings in the health view; (c) TLS termination in a reverse proxy (HAProxy, nginx, Caddy) in front of Tenko, accepting plain HTTP or the PROXY protocol only from a configured list of trusted proxy addresses and taking client address, scheme and host from the forwarded headers or the PROXY protocol, with the WebAuthn relying-party ID and the Secure cookie flag derived from the public host name; forwarded headers from any other source are refused. Certificate administration is one settings page. Built-in ACME renewal is a later addition. | 1 (ACME: 3) | Must (ACME: Should) |
| OPS-23 | Upgrades: the data directory carries a format version. A newer binary migrates an older format step by step in one transaction after taking a store snapshot; an older binary refuses a newer format with a clear error. `tenko upgrade check` dry-runs the migration against a copy and reports with an exit code. The previous version stays installed for rollback. CI opens a data directory from the previous release in a compatibility test. Every tagged release builds the Linux and Windows binaries with the embedded UI, the container image and checksums (signing arrives with API-19). The procedure (backup, stop, switch, start, verify, roll back) is documented under `deploy/`. | 1 (Slice 2) | Must |
| OPS-24 | In-app updates: the controller checks a configured release source (default: the project's releases) on a schedule, sending nothing but the running version, and shows "update available" with the release notes of every version between the running one and the latest, with required actions and security fixes marked; the notes are shown again at the first sign-in after an upgrade ("what's new"). Native single-node installations can install from the UI: the release is downloaded into the data directory, verified (checksum now, signature with API-19), dry-run checked with `tenko upgrade check`, switched into place through a `current` link and restarted through the supervisor; a version that does not become healthy is switched back. The check can be disabled; air-gapped installations install from an uploaded release file. Installing needs an administrator with step-up authentication and is audited (TGL-23). Containers show the pull command instead. The cluster-wide rolling order comes with OPS-08. | 1 (Slice 2; cluster order in Slice 3) | Should |
| OPS-25 | Modules are independent of roles. The product's IPAM, DNS, DHCP and Discovery modules can each be enabled or disabled per installation (`modules` in `tenko.toml`, all on by default; the first-run wizard asks what the installation is for). A disabled module registers no API routes, no UI area and no background tasks and allocates nothing. Every module works without the others; the integrations between them (reverse zones from IPAM, DDNS from DHCP, reservations from IPAM intent, observations into IPAM) switch on only when both sides are enabled. Roles decide which nodes run which data-plane component, so DHCP can live on its own node apart from DNS and the controller; a node with only `dns` or `dhcp` roles joins a controller for its configuration, and a DNS-only installation is `controller` plus `dns` on one node with the DNS module alone. | 1 (the switch, Slice 2); 2 and 3 (DNS and DHCP modules) | Must |
| OPS-26 | Partition behaviour. A controller that loses quorum enters a visible isolated state: writes are refused with 503 `cluster.no_quorum` and a retry hint, the UI shows the state and offers to queue the change as a proposal, reads continue from the local copy with a staleness indicator. `dns`, `dhcp` and `probe` roles keep serving from their local state and buffer observations locally. On reconnection the node catches up through the log or a snapshot (the control plane never diverges, so there is nothing to merge), queued proposals are re-planned against the current state and either applied or shown with their conflict, observations merge as per-source facts, and lease state merges through the DHCP failover protocol (MCLT). Nothing is merged silently. | 1 (Slice 3) | Must |
| OPS-27 | Multi-site ownership. A site can own objects (its prefixes, scopes and zones) in a site-local Raft group, so that a site keeps changing its own objects while cut off from the rest; global objects stay in the global group and are read-only at an isolated site; ownership moves between sites are explicit jobs. Splitting into more Raft groups was anticipated in ADR 0002. | 5 | Should |
| OPS-28 | Sites over slow or intermittent links. Data-plane roles (`dns`, `dhcp`, `probe`) synchronize from the controllers by resumable deltas: the journal since the node's last revision, a compressed snapshot only when the node is too far behind, with a configurable bandwidth cap; a site never needs Raft membership, and a `dns` node at a branch keeps answering from its local copy across outages. Zone replication without any clustering is also supported: an independent Tenko installation, or a third-party server, receives zones through standard IXFR and NOTIFY with TSIG or XFR over TLS (DNS-09), so two sites can exchange zones over a thin link as primaries and secondaries. | 1 (delta sync, Slice 3); 2 (IXFR between installations) | Must |
| OPS-21 | Observability cost budget: metrics are per-shard counters and fixed-bucket histograms updated with relaxed atomics, with no locks, allocation, formatting or I/O in the query, DORA or renew path; aggregation runs off the hot path once per second or on scrape; expensive gauges (store size, counts, lag) are computed on a timer and cached; per-query logging and dnstap are opt-in, sampled and asynchronous through per-shard ring buffers that drop rather than block. The overhead with metrics enabled is measured in bench/ and must stay below 2 percent throughput at saturation without moving p99 latency; the number is tracked per release. | 1 | Must |

## API and product

The REST API is the only interface the UI uses. This section also holds product-level and engineering-policy requirements.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| API-01 | REST API with an OpenAPI specification derived from the code's types. | 1 | Must |
| API-02 | The UI uses only the public API. | 1 | Must |
| API-03 | A `tenko` CLI that shares the client library. | 1 | Must |
| API-04 | Bulk operations and idempotency keys. | 1 | Must |
| API-05 | Event stream over Server-Sent Events (SSE) for live UI updates. | 1 | Must |
| API-06 | Webhooks. | 5 | Should |
| API-07 | Terraform provider and Ansible collection. | 5 | Should |
| API-08 | UI: keyboard-driven bulk grids, live updates via SSE, dark mode and WCAG accessibility. Localized: Swedish and English are built in; the UI language follows the browser Accept-Language header, falls back to English, can be fixed per user account, and an administrator can set the installation default. Logs, CLI output and API error texts stay in English; API errors carry stable codes that the UI translates. | 1 | Must |
| API-09 | Change UI: multiselect and drag and drop, a preview before every apply, a job panel with per-item status, and undo where possible. | 1 | Must |
| API-10 | First-run wizard with security profile selection (Home, Standard, Hardened, Lab). Insecure settings are loudly visible in the UI. | 1 | Must |
| API-11 | RDP/SSH handoff: the host view produces an `.rdp` file or an `ssh://` URI with host, port and user, and the password is copied to the clipboard from the vault, with audit. Neither the `.rdp` file nor the URI carries a secret; the host view offers both next to each interface address. | 1 | Must |
| API-12 | HTML5 RDP/SSH gateway as an opt-in module: credential injection, session recording and just-in-time access. | 5 | Could |
| API-13 | Code, comments and documentation are in English, and the repository is written as if public: no secrets in the repository (`.env.example` instead), test data from documentation ranges only (RFC 5737, RFC 3849, the RFC 7042 MAC range and RFC 2606 names; see CONFORMANCE.md), license headers empty until the license decision (API-20). | 0 | Must |
| API-14 | CI gates: clippy (pedantic), tests, cargo-deny (licenses, advisories, duplicates), cargo-audit (failing) and fuzz smoke. | 0 | Must |
| API-15 | Every parser of network data has a cargo-fuzz target before it is merged. | 0 | Must |
| API-16 | `#![forbid(unsafe_code)]` in all crates unless an ADR allows `unsafe` (I/O layer). | 0 | Must |
| API-17 | Published conformance matrix (CONFORMANCE.md) with a target phase per RFC, and conformance tests per RFC as engines land (CON-08). | 0 | Must |
| API-18 | Windows interop lab: a test domain on Windows Server 2016 or later (Query Resolution Policies require 2016+) for domain join, DC locator, GPO retrieval and Netlogon re-registration against Tenko with GSS-TSIG. | 4 | Must |
| API-19 | Signed releases (Sigstore, Authenticode) and SBOM. | 5 | Must |
| API-20 | License decision before any publication: decided on 2026-10-22 as the Business Source License 1.1 with an internal-use grant and AGPL-3.0-or-later as the Change License, with a contributor license agreement (ADR 0022); a lawyer's review before publication remains. | 5 | Must |
| API-21 | Language packs: every UI string is externalized under a stable key. Additional languages are XLIFF 2.0 files (XML) named by BCP 47 tag (for example `fr.xlf`, `fr-CA.xlf`) with display name, author, version and source language as metadata inside the file. A pack is uploaded in the UI or dropped in the data directory and activated at runtime without a rebuild. Upload validates the schema, reports missing and extra keys and a completeness percentage, and previews before activation. Missing strings fall back to English; translations are rendered as text (no markup injection) and use ICU MessageFormat for plurals, gender and placeholders; dates, numbers and sort order come from the locale. The built-in Swedish and English ship in the same format and double as templates, and the current key set can be exported with one click. The layout supports right-to-left languages. | 1 | Must |
| API-22 | Ticketing integration: a connector that creates and updates tickets (Jira first, then generic webhooks) for jobs and their manual steps, for example one ticket per device in a move job. | 5 | Could |

## Connectors and integrations

Connectors are pluggable drivers behind common traits (ADR 0006). They bring observations in, push intent out and read legacy systems for migration. Write paths are conservative: previewed, audited and verified before write.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| CONN-01 | One connector framework with common interfaces: InventorySource, Actuator, MigrationSource and NetworkController (ADR 0006), implemented by **plugins** behind a published, versioned protocol rather than compiled-in code (ADR 0012). | 1 | Must |
| CONN-19 | Plugin SDK and host: a plugin is a separate process started and supervised by Tenko (handshake over stdio, gRPC over a local socket or named pipe, health checks, restart with backoff, timeouts), described by a manifest (name, version, protocol versions, capabilities, settings JSON Schema from which the UI builds the form, required secret purposes, network targets, platforms). Plugins never access the vault: the host injects declared secrets per call and audits it. Policy (verify-before-write, guardrails, rate limits, parallelism) stays in the host. The SDK ships a conformance test (`tenko plugin test`) and a Rust helper library; any gRPC-capable language can implement a plugin. | 1 (Slice 2) | Must |
| CONN-20 | Reference plugins (UniFi, Proxmox, Home Assistant, later the migration sources) are built on the SDK and bundled in the `tenko` binary as `tenko plugin run <name>`, launched by the host like third-party plugins. | 1 (Slice 2) | Must |
| CONN-21 | Plugin hub and WebAssembly transport: signed plugin packages, `tenko plugin install <name>`, a sandboxed Wasm component transport beside the process transport, and the protocol, SDK and conformance suite published in a public repository. | 5 | Should |
| CONN-02 | InventorySource contract: observed hosts with name, MACs, IPs, OS, platform, parent host and tags; scheduled polling; webhooks where available. | 1 | Must |
| CONN-03 | Proxmox VE inventory through a read-only API token: `/cluster/resources`, QEMU guest agent `network-get-interfaces`, LXC config and interfaces, and SDN vnets. This captures fixed IPs that never appear in DHCP. | 1 | Must |
| CONN-04 | Home Assistant inventory through the REST/WebSocket API with a long-lived token. The device registry provides MAC, IP, manufacturer and model for IoT devices that nmap cannot fingerprint. | 1 | Must |
| CONN-05 | UniFi read: devices, clients, ports, LLDP, uplinks and client-to-AP/port associations. | 1 | Must |
| CONN-06 | UniFi write: networks and VLANs (UniFi's own DHCP disabled or relaying to Tenko), port profiles (`rest/portconf`) and per-client VLAN override (`rest/user`, where `network_id` is the network's `_id`, not the VLAN number). A Phase 1 spike decides which writes go through which API family. | 1 | Must |
| CONN-07 | UniFi deployment detection and API families. A self-hosted Network Application serves its API on port 8443 without the `/proxy/network/` prefix, with login at `/api/login` using a local account for the classic API; UDM/UCG and Cloud Key deployments use the proxy prefix and are autodetected. The Integration API (`/proxy/network/integration/v1`, `X-API-Key`) is official and versioned and reads sites, devices, clients and networks; network creation is likely supported but only GET is verified in the official documentation. The classic API (`/api/s/{site}/rest/...`) alone offers port profiles and per-client VLAN override, and whether an API key works there varies by controller. Fallback: a local admin account in the vault. | 1 | Must |
| CONN-08 | Verify before write: a network-controller connector never writes anything it has not first read back and diffed. All writes are previewed, audited and available as dry-run. | 1 | Must |
| CONN-09 | Guardrails: never touch the port or VLAN through which Tenko or the controller is reached, and never uplinks. Bulk operations run with configurable parallelism so that dozens of IoT devices cannot overwhelm DHCP or the controller. | 1 | Must |
| CONN-10 | Hyper-V inventory via WinRM/PowerShell: `Get-VM` and `Get-VMNetworkAdapter` (MAC, and IP via integration services). | 4 | Should |
| CONN-11 | VMware vSphere inventory via the vSphere REST API, with the guest IP from VMware Tools. | 4 | Should |
| CONN-12 | External DHCP actuators for coexistence: Windows DHCP via PowerShell and Kea via the Control Agent. Before Phase 4, Tenko's own DHCP is the only DHCP actuator. | 4 | Should |
| CONN-13 | External DNS actuators for coexistence: RFC 2136 and Windows DNS via PowerShell. Before Phase 4, Tenko's own DNS is the only DNS actuator. | 4 | Should |
| CONN-14 | Container and orchestrator inventory (Docker/Podman, Kubernetes, Incus/LXD) through sockets and APIs, for containers and pods that have their own addresses. | 5 | Could |
| CONN-15 | Proxmox hypervisor actuator: sets the guest IP for LXC (`pct set`) and cloud-init VMs, so that `static` hosts can be moved automatically. | 5 | Should |
| CONN-16 | Additional network controllers beyond UniFi. | 5 | Could |
| CONN-17 | NetBox-compatible API, so that Proxmox SDN can use Tenko as its IPAM plugin. | 5 | Could |
| CONN-18 | Wireless networks (SSIDs) are objects in IPAM: read from the network controller with their VLAN mapping and the APs that broadcast them, shown under the VLAN they carry in the prefix tree and on the topology map (AP labels). The move job knows both ways to move a wireless client: the automated path is a per-client VLAN override on the controller while the client stays on its current SSID; "move to SSID" is offered when the target WLAN carries the target VLAN, but joining another SSID is a change on the device itself, so it is a manual task unless the client already knows that network (CON-10). Writing SSID-to-VLAN mappings and creating WLANs through the controller follows the same verify-before-write and guardrail rules (CONN-08, CONN-09). | 1 (write: 2) | Must (write: Should) |

## Migration

Migration from mixed sources (AD-integrated, file-based, BIND, OPNsense, Proxmox-hosted DNS) uses the connector architecture around a canonical intermediate representation (ADR 0006). A DNS server in a Proxmox VM or container is imported through the adapter for its own software; Proxmox itself is an inventory source (CONN-03). Per-source data paths and runbooks are in MIGRATION.md.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| MIG-01 | Every migration source is an adapter that produces the canonical intermediate representation (IR) plus a loss report listing what could not be mapped. | 4 | Must |
| MIG-02 | AXFR is the universal baseline for DNS data from any authoritative server (Windows, BIND, PowerDNS, Knot, NSD, Unbound auth zones). Adapters add what AXFR loses: ownership, timestamps, forwarders, views and policies, and DHCP. | 4 | Must |
| MIG-03 | One pipeline for all sources: `plan` (dry-run diff), `apply`, and `verify` (parity check against the old server), exposed as `tenko migrate plan`, `tenko migrate apply` and `tenko migrate verify`. It runs on the job engine (IPAM-17). | 4 | Must |
| MIG-04 | Coexistence modes, selected per zone or scope in the UI: secondary (Tenko is an AXFR secondary and stays in sync until the flip, with a nightly parity diff), forward (Tenko forwards some zones to the old server while taking over others) and flip (Tenko becomes primary; the old server becomes its secondary or is switched off after a rollback window). | 4 | Must |
| MIG-05 | Verify by query replay: sampled live queries (dnstap or query log) are asked of both servers and the RCODE and answers are diffed, ignoring TTL drift. | 4 | Must |
| MIG-06 | Source: Windows DNS, AD-integrated. AXFR or `Get-DnsServerResourceRecord`, plus an LDAP read of `dnsRecord` in `DomainDnsZones` and `ForestDnsZones` for ownership per RRset, aging timestamps and tombstones, plus PowerShell remoting (DnsServer module) for forwarders, conditional forwarders, root hints, zone scopes, client subnets, recursion scopes, Query Resolution Policies, aging settings, GQBL and RRL. | 4 | Must |
| MIG-07 | Source: Windows DNS, file-backed. The same cmdlets (they do not distinguish storage) or `%SystemRoot%\System32\dns\*.dns` files. The zone file parser understands the Windows `[AGE:n]` comment so that timestamps are kept. | 4 | Must |
| MIG-08 | Source: Windows DHCP. `Export-DhcpServer -Leases` (XML) plus the `Get-DhcpServerv4*` cmdlets for scopes, reservations, options at all levels, policies, filters, superscopes, DNS settings and failover relationships (the shared secret is recreated, not exported). Coexistence uses split scopes (CON-05). | 4 | Must |
| MIG-09 | Source: BIND. AXFR or zone files (RFC 1035) plus a `named.conf` parser: `view` becomes Tenko views, `acl` becomes client subnets, and `forwarders`, `also-notify`, `allow-transfer` and RPZ zones are carried over. | 4 | Must |
| MIG-10 | Source: OPNsense. REST API or `config.xml` backup: Unbound host and domain overrides, Dnsmasq, ISC dhcpd static maps, Kea subnets and reservations, interfaces and VLANs (become IPAM networks) and firewall aliases. | 4 | Must |
| MIG-11 | Source: dnsmasq / Pi-hole. Config files and `/etc/hosts`: `dhcp-host`, `address=`, `host-record`, and blocklists (become RPZ). | 4 | Should |
| MIG-12 | Source: Kea / ISC dhcpd. Kea JSON plus lease file or database; `dhcpd.conf` plus `dhcpd.leases`: subnets, pools, reservations, classes and options. | 4 | Should |
| MIG-13 | Source: generic hosts files, and the NetBox and phpIPAM APIs (CSV/Excel is IPAM-11). | 4 | Should |
| MIG-14 | Exit: export to CSV. | 1 | Must |
| MIG-15 | Exit: export to standard zone files. | 2 | Must |
| MIG-16 | Exit: export to Kea-compatible JSON. Together with MIG-14 and MIG-15 this ensures there is no lock-in. | 3 | Must |
| MIG-17 | Migration runbooks in MIGRATION.md. | 4 | Must |
| MIG-18 | Hands-off acceptance: a Windows Server 2016+ test domain with QRPs, zone scopes, aging and DHCP failover migrates in the lab without manual intervention; domain join, GPO and DC locator work against Tenko; Windows DNS is switched off and clients notice nothing. | 4 | Must |

## Non-goals

- No attack tooling and no Responder-like functionality (CON-09).
- No AD-backed zone storage mode (CON-11).
- No WINS lookup (CON-12).
- No DHCPv4 failover protocol interoperability with Windows or ISC; coexistence uses split scopes (CON-05).
- No autoscaling logic in the core (CON-06).
- No hand-written assembler (CON-01).
