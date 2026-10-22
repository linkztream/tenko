# ADR 0007: Delivery order

- Status: Accepted; the "later" part of point 2 (the recursive resolver in Phase 5) is superseded by ADR 0021 (2026-10-22)
- Date: 2026-10-09

## Context

The scope of Tenko DDI is large: IPAM with discovery and connectors, an authoritative and caching DNS server, a DHCPv4/v6 server with failover, AD integration, migration from mixed sources, and enterprise features. The order of delivery decides when the project produces value, which risks are retired early, and which components can be built on top of others.

Dependencies between the parts:

- IPAM intent is what the DNS and DHCP engines act on (ADR 0005).
- DHCP dynamic DNS updates and the DNS step of the device move job need the DNS engine.
- AD integration and Windows migration need both engines, plus GSS-TSIG.
- A full recursive resolver and an HTML5 remote-access gateway are large, security-sensitive components with limited value early on.

## Decision

1. **Phase order:**

   | Phase | Content |
   |---|---|
   | 0 | Foundation and spikes (storage gate, I/O throughput and DNS parser choice, embedded UI) |
   | 1 | Platform and IPAM: replaces the existing IPAM spreadsheet, with discovery, connectors, topology and the move job |
   | 2 | DNS |
   | 3 | DHCP |
   | 4 | AD integration and migration |
   | 5 | Enterprise and ecosystem |

2. **Forwarder and cache before recursion.** Phase 2 delivers forwarding, caching and RPZ; Tenko's own full recursive resolver with DNSSEC validation follows in Phase 5 (DNS-03, DNS-13).
3. **URI handoff before an HTML5 gateway.** Phase 1 delivers RDP and SSH as `.rdp` files and `ssh://` URIs with the password copied from the vault; an HTML5 RDP/SSH gateway with credential injection and session recording is an opt-in module in Phase 5 (API-11, API-12).
4. **External DHCP and DNS actuators wait for Phase 4.** Tenko's own engines are the actuators from Phase 2 and 3; Windows and Kea actuators exist for coexistence during migration (ADR 0005).
5. **Private repository, written as if public.** Code, comments and documentation are in English; license headers stay empty until the license decision (Apache-2.0 or AGPL-3.0); secrets never enter the repository; test data uses documentation address ranges. Signed releases, an SBOM and the license decision precede any publication (API-13, API-19, API-20).

## Consequences

- The IPAM spreadsheet is replaced in Phase 1, before any DNS or DHCP engine exists.
- Until Phase 3, the device move job is semi-manual: IPAM intent, UniFi L2 move and observation are automatic, DHCP and DNS steps are manual tasks (DNS becomes automatic in Phase 2).
- Until Phase 5, DNSSEC validation for recursive traffic is the upstream resolver's job.
- Windows DNS and DHCP remain in production until Phase 4; coexistence modes make the transition gradual.
- Publication is a later decision, but nothing in the repository has to be rewritten to make it public.

## Alternatives considered

- **DNS first.** Replaces the most visible Windows service soonest, but builds the highest-risk engine without the IPAM model it should be driven by; reverse zones from IPAM and the intent hub would be retrofitted.
- **DHCP before DNS.** DHCP dynamic DNS updates and the move job's DNS step would have no Tenko target, forcing interim external integrations.
- **Own recursive resolver early.** Large attack surface (cache poisoning defenses, DNSSEC validation, QNAME minimization) with little benefit over forwarding for the first deployments.
- **HTML5 gateway early.** Credential injection and session recording are security-sensitive and not needed while URI handoff covers remote access.
- **Public repository from the start.** Possible, but the license choice is open; writing as if public keeps the option without forcing the decision.
