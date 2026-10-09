# ADR 0005: IPAM as the intent hub

- Status: Accepted
- Date: 2026-10-09

## Context

DDI replaces an IPAM spreadsheet that drifts from reality because nothing connects it to DHCP, DNS or the network. There are four sources of truth that disagree: IPAM intent, DHCP leases, DNS records and scan results. Hypervisor inventories and network-controller client tables add more observations.

Typical changes span several systems. Moving a device to another network needs a new address, a DHCP reservation, DNS records and an L2 change on the switch or access point, and it completes only when the device actually renews (CON-10). Doing this by hand is error-prone; doing it with silent automation is dangerous.

## Decision

1. **IPAM holds intent:** host X has IP Y in network Z, with an assignment mode, a DNS name and a VLAN (IPAM-12).
2. **Observations are a separate layer:** DHCP leases, DNS records, scans, hypervisor inventory and network-controller client tables are stored apart from intent and never overwrite it.
3. **A reconciler** continuously compares intent with observation and produces jobs that drive **actuators** until the two match. The same mechanism works in both directions: a change in IPAM lands in DHCP and DNS, and a change seen in DHCP or DNS shows up in IPAM (IPAM-13).
4. **Actuators are pluggable drivers** behind common traits (ADR 0006): DHCP (reservations keyed by MAC or client-id for v4, DUID for v6), DNS (A, AAAA, PTR, CNAME), network controller (VLANs, port profiles, per-client VLAN) and hypervisor (guest IP).
5. **Assignment mode per host** decides what IPAM may do (IPAM-14):

   | Mode | Effect of an IP change in IPAM |
   |---|---|
   | `reserved` | Creates or moves the DHCP reservation and updates DNS |
   | `static` | Updates DNS only, plus a manual task "reconfigure the device" in the job |
   | `dynamic` | IPAM only observes |
   | `unmanaged` | Nothing touches the host |

6. **Observations without intent become proposals, never intent.** An unknown MAC in a lease becomes a "discovered host"; a DNS record without a host becomes an "orphaned record". An administrator approves with one click, or sets an explicit rule such as "auto-adopt in network Z" (IPAM-15).
7. **Intent wins for managed hosts.** A per-host `lock` flag stops all automation for that host (IPAM-16).
8. **Every change is a job** in the job engine (`ddi-jobs`): steps, status, timeout and rollback, visible in the UI and the API, and written to the audit log. Nothing happens silently (IPAM-17). A missing MAC or DUID produces a warning before a reservation can be created (IPAM-18).
9. **Actuator rollout follows the delivery order (ADR 0007).** DDI's own engines are the DHCP and DNS actuators: DNS from Phase 2, DHCP from Phase 3. The network-controller actuator (UniFi) ships in Phase 1. External DHCP and DNS actuators (Windows DHCP and Windows DNS via PowerShell, Kea via its Control Agent, RFC 2136) are deferred to Phase 4, where they serve coexistence during migration (CONN-12, CONN-13). Until the own engines exist, DHCP and DNS steps in jobs are manual tasks.

## Consequences

- The spreadsheet is replaced by a model that drives the network instead of describing it after the fact.
- The device move job (IPAM-19) becomes a composition of actuator steps with a single rollback path; it is semi-manual in Phase 1 and fully automatic for `reserved` hosts in Phase 3.
- Migration reuses the same job engine (ADR 0006), so imports get previews, rollback and audit for free.
- The reconciler must be idempotent and tolerate flapping or delayed observations; jobs that wait for observation need timeouts.
- The UI must present proposals and conflicts clearly; the unified reconciliation view across all four truths ships in Phase 3 (IPAM-21).
- Rogue or unknown devices never become intent without a human decision or an explicit rule.

## Alternatives considered

- **IPAM as a passive inventory.** A better spreadsheet, but nothing propagates to DHCP, DNS or the network, so drift remains.
- **DHCP and DNS as the source of truth, IPAM as a view.** Cannot express intent for static hosts, planned addresses or VLANs, and has no place for assignment modes.
- **Automatically adopting every observation as intent.** Zero friction, but rogue devices would become intended state and the review step disappears.
- **Direct writes to DHCP and DNS without a job engine.** Simpler, but gives no rollback, no waiting for observation and no visible record of what changed.
