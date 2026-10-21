# Phase 3 status

The working state of Phase 3 (DHCP) of Tenko DDI: which work packages of [phase-3-plan.md](phase-3-plan.md) are merged, what each delivered, what is open, and the push state of `main`. Phase 2's state stays in [phase-2-status.md](phase-2-status.md) until its exit document (WP6.5) is merged; this file took over for Phase 3 when WP7.1a merged on 2026-10-21.

## Plan and decisions

The plan was drafted on the night of 2026-10-21 by a local Opus builder and merged as `a2cb543` with ADR 0019 (the DHCP data model and lease path) and ADR 0020 (DDNS from DHCP), both Proposed. The owner decided P3-Q1 to P3-Q11 the same night (leases as rows in the replicated store committed before the ACK, with an asynchronous publication model as the measured fallback; failover pairs and the chaos test to Phase 5; DHCPv6 as the last slice; one model where a scope is an IPAM prefix with a DHCP policy and a reservation is the IPAM reserved host; the reference gateway relays every network to one node; DDNS through the in-process update path with the existing `Origin::Dhcp`; conflict detection through the probe role capped at 300 ms; the observation written in the lease's commit; PXE and classes in Slice 8; the Kea export in Slice 9; the first test drive between the two lab VMs). Open for the owner: P3-Q12 to P3-Q18 (classes as Windows-style conditions, lease history as a bounded table with retention per profile, the behaviour while the store refuses writes, an offline fingerprint table, full PXE with ProxyDHCP last, the Kea export scope, the gateway relay checked by hand) and the threshold of the Q1 fallback (the plan proposes under 1,000 exchanges per second, or p99 above 100 ms at 1,000 per second, on M26 or M28). The plan notes that the Q1 decision contradicts DHCP-07, a line of ARCHITECTURE.md and point 4 of ADR 0002, and lists the text changes in its section 7; how ADR 0002 is marked is the lead's call. Risks run R55 to R71.

## Slice 7 work packages

| Package | State | Commit | Notes |
|---|---|---|---|
| WP7.0 Contracts | Not started | - | The `tenko-core` DHCP types, the `dhcp` store namespace, the routes and DTOs, codes, audit actions, metrics, UI pages and config keys, per plan section 3 |
| WP7.1a The DHCPv4 wire codec | Merged, pushed | `a77fefa` on `origin/main` | Built on the night of 2026-10-21 by a local Opus builder (4 commits on `claude/wp71a-dhcp-codec-7a4ef8`) and squashed after the full Windows gate together with the plan and the install follow-ups: an allocation-free view over a received message (`v4::Message::parse`, the RFC 2131 fields, `chaddr` and `mac`, the option walk over the three areas honouring option 52, `option` and `option_data` with RFC 3396 joining, `validate`), typed reads for options 1, 3, 6, 12, 15, 26, 28, 42, 43, 50 to 55, 57 to 61 (RFC 4361 client identifiers), 66, 67, 77, 81, 82 with sub-options 1, 2, 5, 6, 11 and 12, 93, 94, 97, 116, 118, 119, 121, 124, 125 and 249, typed writes for the options a server sets (119 compressed, 121 per RFC 3442, 82 echoed), `MessageBuilder::reply` and `new` with the size rules, overload and `pad_to`, `DecodeError` and `EncodeError`; fourteen annotated hex fixtures re-encoded byte for byte, 38 tests plus about 30,000 generated cases, zero allocations for parse, read and build; the fuzz target `dhcp_v4` with the fixtures as seeds (300 s on 8 workers in WSL, about 9 M executions, no crash); `docs/dhcp.md` section 1 and the conformance rows (2131, 2132, 3046, 4702 partial as wire format, 3396 implemented). Open: rows for RFC 3004, 3527, 4578, 5107 still say planned and 3397, 3442, 4361, 3925, 3993, 6925, 2563, 3011 have no row though the codec covers their wire formats; `WireName::from_text` reads no escapes |
| WP7.2 Leases in the store | Not started | - | |
| WP7.3 The engine | Not started | - | |
| WP7.4 Scopes, options and the API | Not started | - | |
| WP7.5 The dhcp role | Not started | - | |
| WP7.6 Lab, bench and fuzz | Not started | - | |

Slices 8 and 9 are listed in the plan; their rows are added when they start.

## Push state

`main` carries `a2cb543` (the plan), `807d1b9` (the install follow-ups of Phase 2) and `a77fefa` (WP7.1a), pushed about 23:06 local on 2026-10-21, on top of `48c73d0`.
