# Phase 3 exit

- Status: Draft. WP9.5 fills the parts that need no owner input; the live parts wait for the owner (section 6). The measurements WP9.5 could run on the workstation are in; the cells in angle brackets in section 7 are filled by the lead after the last gate.
- Date: 2026-10-26
- Build: `main` at `116cabc9` (version 0.0.7) plus the WP9.5 branch. Final commit: the squash of the WP9.5 branch on `main` (the commit the WP9.5 row of [phase-3-status.md](phase-3-status.md) names).
- Scope: the exit record of Phase 3 (DHCP). It holds the eleven exit criteria E22 to E32, the measurements M26 to M35, the deviations, the open items carried to Slices 10, 12 and 13, to Phase 4 and to Phase 5, the ROADMAP "Done when" list and the commands the owner runs for the live parts. Every figure is a single-node figure (plan section 2.12). Sources: [ROADMAP.md](../ROADMAP.md) (Phase 3), [phase-3-plan.md](phase-3-plan.md) sections 1.2, 1.6, 2.12, 6 and 9, [phase-3-status.md](phase-3-status.md), [ha-plan.md](ha-plan.md) and [ADR 0025](../adr/0025-dhcp-failover-and-data-plane-ha.md), [phase-2-exit.md](phase-2-exit.md) and the results files under `bench/phase3-dhcp/results/`. The recursion slice (Slice 10, E33 to E42) and the HA slice (Slice 12, E60 to E71) have exit records of their own and are named here only where they take over a Phase 3 line.

Contents:

1. [Exit criteria](#1-exit-criteria)
2. [Measurements](#2-measurements)
3. [Deviations](#3-deviations)
4. [Open items carried to Slices 10, 12 and 13, Phase 4 and Phase 5](#4-open-items-carried-to-slices-10-12-and-13-phase-4-and-phase-5)
5. [ROADMAP "Done when"](#5-roadmap-done-when)
6. [What the owner runs](#6-what-the-owner-runs)
7. [Test totals](#7-test-totals)

## 1. Exit criteria

Status is one of: met, met with deviation, waiting for the owner, documented, not met. The checks are those of [phase-3-plan.md](phase-3-plan.md) section 1.2. The two-host figures of E22 and the lab rows of M32 and M35 come from the two lab VMs on one Proxmox host (2026-10-22); the compose labs ran in WSL (Ubuntu 24.04, Docker 29) and in the weekly `dhcp-lab` CI job; the workstation figures of E32 are from 2026-10-26. The acceptance tests named for WP9.5 (`crates/tenko/tests/acceptance_dhcp_exit.rs`) read the results files and run anywhere.

| # | Check | Requirements | Status | Evidence | Left for the owner |
|---|---|---|---|---|---|
| E22 | kea perfdhcp numbers are documented for one Tenko node: 4-way exchanges and renewals per second and the p99 from DISCOVER to ACK, every lease committed to the store before its ACK, on loopback and from the load VM over a real link, with and without metrics | DHCP-17, DHCP-07, OPS-21 | Met with deviation: documented on loopback and over the link; "with and without metrics" not measured (M33, deviation 176) | `bench/phase3-dhcp/results/2026-10-22-m26-m28-perfdhcp.md` (the static musl binary `tenko serve --roles controller,dhcp`, perfdhcp 2.4.1 from the load VM and on the node VM's loopback, every lease committed to the store before its ACK): about 10,000 4-way exchanges per second within 0.1 percent drops over the link (11,400 with the engine's own client), renewals 4,912 per second beside as many new exchanges, REQUEST to ACK p50 1.1 ms and p99 19 ms at 1,000 per second, p99 about 126 ms at 5,000; the engine alone 20,000 (perfdhcp) and 106,000 (own client). `2026-10-22-m26-m28-loopback.md` (WP7.3, own client, Windows). `crates/tenko/tests/acceptance_dhcp_exit.rs` (`e22_dhcp_17_...` runs; `e22_ops_21_...` is ignored while M33 cannot run). The figures are of 0.0.2 at `a5f9416`; later packages added work to the lease commit (the lease facts of WP8.1, the DDNS and policy fields of WP8.3 and the Slice 8 follow-ups), so the publishable figure is the final build's (section 6.1, deviation 180) | The rerun on the final build over the link and, once a switch exists, the runs with the metrics off (section 6.1) |
| E23 | The reference home-lab environment runs DHCPv4 through Tenko for all four networks: the gateway relays each network to one Tenko node, giaddr and option 82 select the scope, clients keep their addresses across the switch, option 6 and option 42 reach them, and the rollback is one setting on the gateway | DHCP-01, DHCP-02, DHCP-04, DHCP-15 | Waiting for the owner | Automated: `deploy/compose/lab-dhcp` (four /26 client networks behind ISC's `dhcrelay`: a lease on each network from the right scope with options 3, 6 and 42, giaddr and circuit-id on each lease row, link selection with option 82 echoed, renewal at T1 on all four networks, a restart keeps the leases; green in WSL and in the weekly `dhcp-lab` job of 2026-10-25); `crates/tenko/tests/acceptance_dhcp.rs` (the role through the binary, the same leases after a restart); `crates/tenko-dhcp/tests/engine_corpus.rs` (24 modelled clients with byte-exact replies). The runbook is [dhcp.md](../dhcp.md) section 17 (before the day, the switch per network, the check from one client per network, the first hour on the tiles, the rollback, the E23 rows to tick) | The cut-over on a day the owner chooses (section 6.2) |
| E24 | Leases survive the node: the node is killed (SIGKILL, and a power-off of the lab VM) under perfdhcp load and restarted, no lease that was acknowledged is lost, no address is leased to two clients, and the role's lease table equals the store's rows; while the store refuses writes (the test hook of WP6.2) the role behaves as P3-Q14 decides | DHCP-07, OPS-02, OPS-26 | Waiting for the owner: the kills met with deviation, the power-offs open | `bench/phase3-dhcp/results/2026-10-22-m32-crash.md` (20 kills on the workstation, 144,681 ACKs checked: none lost or regressed, every history row present, no address on two clients, the rebuilt table equal to the rows and the index after each kill; the rebuild of 100,000 leases in 170 ms); `crates/tenko-dhcp/tests/lease_crash.rs`; `crates/tenko-dhcp/tests/lease_refusal.rs` (P3-Q14: a renewal answered for its remaining time with nothing written, other requests dropped and counted, the finding raised and cleared); `crates/tenko/tests/acceptance_dhcp.rs` (a restart through the binary keeps every lease); `crates/tenko/tests/acceptance_dhcp_exit.rs` (`e24_dhcp_07_...` runs, `e24_ops_02_...` is ignored until the power-offs). The kills ran on the library entry points of the lease path, not through `tenko serve`, and under the test's own load, not perfdhcp (deviation 168) | The five power-offs of the lab VM (section 6.3) |
| E25 | The five-device move lab of Phase 1 (E8) runs with the DHCP step automatic for the `reserved` devices: the reservation in the target scope from IPAM intent, the observation from the new lease without polling, the old reservation and lease removed in the cleanup, the `static` device stopping at its manual step, the rollback on a blocked step | IPAM-19, DHCP-16, IPAM-18, CON-10 | Met | `crates/tenko/tests/acceptance_move.rs::e25_the_dhcp_step_is_automatic_for_reserved_devices_and_a_lease_confirms_the_move` (the role in relay mode on loopback, five devices: reservations from intent, both scopes offering while the move waits, the new lease confirming the observation, the old lease released, the dynamic device confirmed by its pool lease, the static one stopping at `ipam.move.device`, a cancel restoring both reservations); `crates/tenko-ipam/tests/move_dhcp.rs`; [moves.md](../moves.md) section 4. The 300 s observation timeout is not run (deviation 160) | The five-device lab against the live controller is the Phase 1 step E8 (section 6.4) |
| E26 | A client with option 81 and a legacy client that sends only option 12 get their A and PTR records and a DHCID in Tenko zones on ACK, the records go on release and on expiry, and a second client that claims the first one's name is refused by name protection (RFC 4703); the profile defaults of P3-Q6 hold | DHCP-13 | Met | `crates/tenko/tests/acceptance_dhcp_ddns.rs` (through the binary under the Home profile: A, DHCID and PTR answered by the DNS role on ACK for an option 81 client and an option 12 client, a stolen name refused, the records removed on DHCPRELEASE and on expiry); `crates/tenko-dhcp/tests/ddns.rs` (the profile defaults, Hardened forcing `protect`, the RFC 4701 DHCID examples); [dhcp.md](../dhcp.md) section 13; ADR 0020 Accepted. The rate of M31 fails its latency thresholds (section 2) | None |
| E27 | The relay and options lab: four networks in compose behind a relay; giaddr and link selection (RFC 3527) choose the scope, option 82 is echoed, a shared network with two subnets fills both, options inherit from server to scope to class to reservation, vendor class, user class and MAC wildcard classes select policies, a MAC deny list and an allow list on a restricted scope hold, a squatter is detected before the offer, a DECLINE quarantines the address, and a BIOS, a UEFI and a UEFI HTTP client boot over PXE (iPXE in QEMU) | DHCP-01 to DHCP-06, DHCP-08, TGL-16, TGL-17 | Met with deviation | `deploy/compose/lab-dhcp` rows `link-selection`, `subnet-selection`, `reservation`, `filter.deny`, `class.vendor`, `class.mac-wildcard`, `class.user`, `pxe.bios`, `pxe.uefi` (OVMF), `pxe.http-boot`, `pxe.proxy` (30 of 30 PASS twice on the musl binary, KVM mode); `bench/phase3-dhcp/results/2026-10-22-m35-conflict-probe.md` (a squatter found in 20 of 20 tries by ARP and by ICMP on the lab VMs, the DECLINE held with its audit record); `crates/tenko-dhcp/tests/engine.rs` (`a_restricted_scope_serves_allowed_and_reserved_clients_only`, `a_decline_abandons_the_address_for_the_hold_time_for_every_client`), `contracts.rs` (`selection_takes_the_most_specific_scope_and_siblings_the_shared_network`), `classes.rs`, `conflict.rs`; the options' inheritance in `crates/tenko-dhcp/src/config/tests.rs` and `acceptance_dhcp_config.rs`. The shared network, the inheritance and the restricted scope are crate tests, not compose rows; the PXE rows ran in KVM mode only, not in TCG and not in CI (deviation 166) | None |
| E28 | The reconciliation view shows the four truths (intent, leases, DNS records, scans) for the lab data with the ghost, rogue, orphan and PTR-mismatch lists and the "who wins" rule of each, and a lease's options 55 and 60 set the OS field of an unmanaged host | IPAM-21, DHCP-14, IPAM-23 | Met | `crates/tenko/tests/acceptance_reconcile.rs::e28_the_view_lists_every_seeded_case_and_a_lease_sets_the_os_of_an_unmanaged_host` (exactly the five seeded rows, the unmanaged TV's OS from its lease's options 55 and 60, the conflict in the status and the CLI); Playwright `ipam-reconcile`; [reconciliation.md](../reconciliation.md). The scan truth comes from the bundled sample connector (a probe cannot sight a non-loopback address in the test) | None |
| E29 | DHCPv6 through a relay in the lab: IA_NA from a pool, IA_PD from a delegation pool, a DUID reservation from IPAM intent, RFC 6939 correlation with the DHCPv4 lease of the same MAC, the names of RFC 4704, and the M and O flag check of DHCP-10 in the health view | DHCP-09, DHCP-10, DHCP-11, DHCP-13 | Met | The lab round `dhcp6` of `deploy/compose/lab-dhcp` (`compose.dhcp6.yml`: ISC dhcrelay and dhclient, systemd-networkd, a two-deep relay chain, radvd): rows `v6.lease.dhclient`, `v6.lease.networkd`, `v6.lease.iot`, `v6.rapid-commit`, `v6.renew`, `v6.interface-id`, `v6.reservation`, `v6.correlation.duid`, `v6.correlation.rfc6939`, `v6.fqdn`, `v6.release`, `v6.pd`, `v6.pd.release`, `v6.ra.flags_off`, `v6.ra.managed`, `v6.ra.without_scope` (21 rows twice in WSL at the WP9.2 and WP9.4 gates). Through the binary, new in WP9.5: `crates/tenko/tests/acceptance_dhcp6.rs` (IA_NA from the pool in four messages, a /60 from a delegation pool with Rapid Commit, the DUID reservation of a reserved host, a DUID-UUID client whose relay adds its MAC listed with that MAC and its DHCPv4 lease as the peer, the node's DHCPv6 listener and scope). Crate tests: `engine6.rs`, `engine6_pd.rs`, `role6.rs`, `ddns6.rs` (RFC 4704 names, one DHCID for both families), `ra.rs` | None |
| E30 | The Kea JSON export of the lab configuration and its leases is accepted by `kea-dhcp4 -t` and `kea-dhcp6 -t`, and a Kea server started from it hands the exported reservations to their clients | MIG-16 | Met | Lab rows `export.kea`, `export.kea.report`, `export.kea.reservation`, `export.kea.lease`, `export.kea6`, `export.kea6.golden`, `export.kea6.report`, `export.kea6.reservation`, `export.kea6.lease` (Kea 2.6.3: both `-t` checks accept the export and the golden files, Kea gives a client its reservation through the relay, a client keeps the address the lease file gave it; 50 of 50 rows twice at the WP9.3 gate); `crates/tenko/tests/acceptance_kea_export.rs` (the files through the binary); [MIGRATION.md](../MIGRATION.md) row MIG-16; [dhcp.md](../dhcp.md) sections 18.5 and 18.6. No Kea row for a delegated prefix (deviation 172) | None |
| E31 | Fuzz targets for the DHCPv4 and DHCPv6 wire formats, the option parsers and the relay information run in the weekly fuzz smoke | API-14, API-15 | Met with deviation | `fuzz/fuzz_targets/{dhcp_v4,dhcp4_options,dhcp4_relay_info,dhcp6_wire,dhcp6_relay}.rs` with seeds under `fuzz/seeds/`; the `fuzz-smoke` job of `.github/workflows/ci.yml` runs every target `cargo fuzz list` prints for 60 s; local runs without a crash (`dhcp_v4` about 9 M executions, `dhcp6_wire` 4.3 M with the IA_PD seeds, the two DHCPv4 option and relay targets 61 s each); `crates/tenko/tests/acceptance_dhcp_exit.rs::e31_api_14_...`. The weekly run of 2026-10-25 was cancelled by the job's 60-minute limit before it finished its 41 targets, so no weekly run has yet listed the DHCP targets as passed (deviation 175) | None. The first complete weekly run is the proof |
| E32 | Idle RSS below 100 MB with every role including `dhcp` serving the home scopes, on the musl binary, one node; metrics overhead on the DORA path below 2 percent; the memory of 100,000 leases measured | OPS-15, OPS-21 | Not met: M34 FAIL on Windows (110.41 MiB), M33 not measurable, M30 measured and above its threshold | `bench/phase3-dhcp/results/2026-10-26-e32-rss-leases-metrics.md`: M34 on the Windows release build idles at 110.41 MiB with every role, three scopes and 200 leases (72.90 MiB without `dhcp`; the role's fixed tables cost about 27.5 MiB resident at start, deviation 177); M30 the role's table and index of 100,000 leases 95.35 MiB against 50 MiB, the store's share about 33 MiB (deviation 178); M33 has no switch to turn the metrics off, its isolated stand-in is 0.6 percent (deviation 176). `crates/tenko/tests/acceptance_dhcp_exit.rs` (`e32_ops_15_the_exit_result_file_records_m30_m33_and_m34` runs; the three threshold tests are ignored while the rows do not pass); `crates/tenko-dhcp/tests/lease_rebuild.rs::e32_ops_15_the_memory_of_100000_leases_by_stage`; `crates/tenko-dhcp/tests/metrics_cost.rs` | M34 and M30 on the musl binary in the lab once the tool exists (section 6.5) |

Other acceptance files of this phase, for areas no single E-row names: `acceptance_dhcp.rs` (the `dhcp` role in the process: DORA, the report and lease routes, a restart, a release, a node without a listener), `acceptance_dhcp_config.rs` (the configuration through the CLI), `acceptance_kea_export.rs` (MIG-16) and `acceptance_dhcp_exit.rs` (WP9.5).

## 2. Measurements

Thresholds are those of [phase-3-plan.md](phase-3-plan.md) section 6. Numbers are from the newest results file of each measurement. Linux figures come from the static musl binary (jemalloc); Windows figures from the release build. "Loopback" means client and server on one host: an upper bound.

| # | Measurement | Threshold | Latest number | Verdict | Results file | Still to run |
|---|---|---|---|---|---|---|
| M26 | 4-way exchanges per second, every lease committed before the ACK (DHCP-17) | Documented ceiling; fallback line of P3-Q1: 1,000 per second sustained | The binary over the link: 9,994 / 7,499 / 9,993 per second within 0.1 percent drops at 1 / 2 / 4 workers (perfdhcp), 11,400 closed loop (own client); loopback 7,489 to 7,498 (9,595); the engine alone 19,971 to 19,973 (106,382). Windows, engine alone with its own client: 86,040 to 107,038 | Documented; clear of the fallback line by a factor of ten | `2026-10-22-m26-m28-perfdhcp.md`; `2026-10-22-m26-m28-loopback.md` | The final build over the link (section 6.1) |
| M27 | Renewals per second | Documented | 4,912 per second answered beside as many new exchanges at the 5,000 rung over the link (0.6 percent renewal drops); pure renewals 10,428 per second closed loop (own client); the engine alone 191,580 | Documented | `2026-10-22-m26-m28-perfdhcp.md` | The final build (section 6.1) |
| M28 | p99 from DISCOVER to ACK and the commit's share | At 1,000 per second p99 below 100 ms (fallback line); median documented | REQUEST to ACK at 1,000 per second p50 1.10 ms, p99 19.1 ms over the link (loopback 0.98 / 21.0 ms); at 5,000 per second p99 126 ms; the commit almost all of it (the server's histograms coincide bucket for bucket); DISCOVER to OFFER p99 below 1 ms. Windows commit share at 1,000 per second p99 8.45 ms | PASS (the fallback line holds by a factor of five) | `2026-10-22-m26-m28-perfdhcp.md`; `2026-10-22-m32-crash.md` | The final build (section 6.1) |
| M29 | Store growth under lease churn | Bounded across snapshot and purge during one hour at 500 renewals per second | Not measured | Not run | none | A one-hour run at 500 renewals per second with the store's gauges (deviation 174) |
| M30 | Memory of 100,000 leases (OPS-15) | Below 50 MiB for the role's table and indexes; the store's share documented | Windows release: the table and its client index 95.35 MiB working set (97.04 MiB private; 95.82 and 97.38 MiB in two other runs); the store with the rows after a restart and a scan 33.29 MiB, while writing 39.15 MiB | FAIL (about 1 KiB per lease: the 536-octet `Lease` inline in the table's hash map) | `2026-10-26-e32-rss-leases-metrics.md` | Again after a compact table, and on the musl binary (section 6.5) |
| M31 | DDNS rate end to end | 1,000 lease commits per second with DDNS, p99 from ACK to the answered A record below 250 ms; DORA p99 within 10 percent of M28 | The stand-in (own client, loopback, Windows): 60,000 of 60,000 names answered at 1,000 per second; names p99 699 and 777 ms, DORA p99 403 and 430 ms after the Slice 8 follow-ups on a quiet machine; 1,118 to 4,737 ms under build load on 2026-10-23 | FAIL on the latency thresholds, PASS on the rate (stand-in) | `2026-10-22-m31-ddns.md` | perfdhcp with option 81 on the lab VMs (`run-perfdhcp.sh` sets up no zone and no DDNS) and a quiet-machine repeat (deviation 163) |
| M32 | Crash and restart under load (E24) | 0 acknowledged leases lost, 0 addresses on two clients, over 20 SIGKILLs and 5 power-offs | 20 kills, 144,681 ACKs: none lost, none regressed, none on two clients (Windows, the library entry points) | PASS for the kills; the power-offs not run | `2026-10-22-m32-crash.md` | The five power-offs (section 6.3) |
| M33 | Metrics cost on the DORA path (OPS-21) | Below 2 percent, p99 unchanged | Not measurable by the plan's method (no switch). Stand-in: the metrics work of one exchange 170 ns (27.5 ns without the clock reads) against 27 µs of server CPU per exchange of the engine alone at 5,000 per second, 0.6 percent (0.1 percent) | Not measured (stand-in below the line) | `2026-10-26-e32-rss-leases-metrics.md` | M26 with the metrics on and off once a switch exists (deviation 176) |
| M34 | Idle RSS with every role including `dhcp` (OPS-15) | Below 100 MB (95.37 MiB) on the musl binary | Windows release, roles controller, dns, dhcp and probe, three scopes, 200 leases, 600 s idle: 110.41 MiB at most (112.96 MiB with the M9 data set; 100.37 MiB without leases; 72.90 MiB without `dhcp`; 65.20 MiB the controller alone) | FAIL on Windows; musl not run | `2026-10-26-e32-rss-leases-metrics.md` | The musl run in the lab, after the role's fixed tables are sized from the configuration (section 6.5, deviation 177) |
| M35 | Conflict probe cost | Offer delay at most the 300 ms cap for new addresses, none for renewals; a squatter detected in 20 of 20 tries | Windows: offers 287.9 to 299.0 ms with a probe that never answers, renewals p99 0.17 ms against 0.19 ms; lab VMs, musl `tenko serve`: ARP offers at most 297.0 ms, ICMP 299.1 ms, 20 of 20 squatters found by each, renewals p99 1.93 ms | PASS | `2026-10-22-m35-conflict-probe.md` | None |

Comparison points (plan section 6). ISC's performance reports at reports.kea.isc.org were checked on 2026-10-26: the newest report reachable without a listing is the 1.9.10 development report (2021), whose DORA figures are charts with no figure in its text, so no Kea figure is recorded beside Tenko's (deviation 179). The 2014 figure from the Kea developers' list (Kea 0.9: about 4,100 leases per second with the memfile on a RAM disk, 4,900 without persistence) shows the order of magnitude only; Tenko commits every lease to its Raft store before the ACK, which neither figure does.

## 3. Deviations

Grouped by area. "Row" means a row of [phase-3-status.md](phase-3-status.md). Numbering continues [phase-2-exit.md](phase-2-exit.md), which ended at 152. Items closed by a later package are not listed.

### Scope and the ROADMAP

153. The ROADMAP's "Done when" line for the failover pair ("The failover pair passes the chaos test: a partner is killed mid-load and no duplicate leases result", DHCP-18) is not a Phase 3 criterion. Decision P3-Q2 of 2026-10-21 moved DHCP-12 and DHCP-18 to Phase 5; the owner's decisions HA-Q1 to HA-Q15 of 2026-10-25 brought them back as Slice 12, after WP9.5 and before Phase 4, planned in [ha-plan.md](ha-plan.md) with [ADR 0025](../adr/0025-dhcp-failover-and-data-plane-ha.md) Accepted. The line's checks are E60 to E62, E65 and E68 there; E24 is the single-node stand-in of this phase. Recorded in plan sections 1.2 and 1.6 and the status file. Slice 12.
154. The ROADMAP's "Done when" line for recursion ("resolves through Tenko alone ... with DNSSEC validation on") belongs to Slice 10 ([dns-recursion-plan.md](dns-recursion-plan.md), E33 to E42), which runs beside Phase 3 and has its own status file; it is not closed by WP9.5. Slice 10.
155. A `dhcp` node without a controller, relay between Tenko nodes and the `dhcp` subset of node sync (declared, consumed by no node) are not built (P3-Q5). Recorded in plan section 1.6. Slice 12 (ha-plan WP12.1, WP12.2).

### Engine and role

156. socket2 0.6 has no safe `IP_PKTINFO`, so the receiving interface comes from the binding: every listener binds its own address or interface (WP7.3 and WP7.5 rows). Unscheduled.
157. An offer is not released when the client's REQUEST names another server; it expires after its 10 s hold (WP7.3 row). Unscheduled.
158. WSL's VirtioProxy networking drops the first datagram to a port bound after the socket, so `engine_server` fails in WSL and passes on the VM (WP7.5 row). Accepted (WSL is not a target).
159. The history writes one row per renewal: about 55 rows per second at 100,000 clients on one-hour leases (WP7.2 row); retention per profile bounds it, M29 has not measured it (deviation 174). Unscheduled.
160. E25's 300 s observation timeout is not run in the test; the lease facts use the code default refresh of 15 minutes rather than the stored reconciler setting; the move's cleanup release writes no `dhcp.lease.release` audit row (the job record is its trace); `GET /dhcp/reservations` still answers 501 (WP8.1 row). Unscheduled.
161. A reconciler change set of DHCP names no longer starts a run, so proposals for new DHCP clients wait for the periodic run (five minutes) (Slice 8 follow-ups row). Accepted.

### DDNS

162. The zone audit names the zone, not each lease's address (WP8.3 row). Unscheduled.
163. M31 fails its latency thresholds in the stand-in (names p99 699 and 777 ms, DORA p99 403 and 430 ms against 250 ms and M28 plus 10 percent) while the rate passes; the rest is the store's commit (mean 60 ms with names against 24 ms without). The perfdhcp row with option 81 on the lab VMs and a quiet-machine repeat are not done. Recorded in `2026-10-22-m31-ddns.md`. A store package after the exit.

### Classes, policies and network boot

164. Classes and policies are DHCPv4-only; the MAC filters apply to DHCPv6, and there are no effective options for DHCPv6 clients (WP9.1 and WP9.4 rows). Unscheduled.
165. A scope's DDNS settings cannot be cleared back to the server's (the patch has no `clear_ddns`; the UI copies the server's settings instead) (WP8.6 row). Unscheduled.
166. The PXE rows of E27 ran in KVM mode only; TCG mode and the CI job were not run (`compose.kvm.yml` applies only where `/dev/kvm` exists) (WP8.4 row). Unscheduled.

### DHCPv6

167. RFC 8415 is partial: IA_TA, Reconfigure, Authentication, Server Unicast and Preference are not done, and a unicast request is served rather than answered with `UseMulticast` (CONFORMANCE.md). Unscheduled.
168. The kills of M32 ran on the library entry points of the lease path under the test's own load, not through `tenko serve` under perfdhcp, and on Windows only; no musl kill run (WP7.2 row). The power-offs are the owner's step (section 6.3).
169. No prefix reservations (IPAM has no intent tying a prefix to an interface), RDNSS not judged, no RA check on relayed links, a pool's delegated length changed under live bindings is documented as unsafe (WP9.2 row). Unscheduled.
170. `kind` is not a filter of the history route, and the PD flows ran against the lab's dhclient only (WP9.4 row). Unscheduled.
171. The binary-level DHCPv6 test of WP9.5 (`acceptance_dhcp6.rs`) covers IA_NA, IA_PD, the DUID reservation and the RFC 6939 peer; RFC 4704 names and the RA check stay crate tests and lab rows, since the first needs the DNS role with zones and the second a raw ICMPv6 socket. Accepted.
172. No Kea lab row exports a delegated prefix (WP9.4 row). Unscheduled.

### Deployment and UI

173. `deploy/proxmox/ct/tenko.sh` and its README accept only `controller` and `controller,dns`; the MSI smoke was not run with the `dhcp` role; P3-Q18 (c), the relay check through the probe, is not built (the runbook has a manual offer check); `ui/e2e/README.md` has no row for the reconcile scenario (WP7.5, WP8.2, WP8.6 rows). Unscheduled.

### Measurements

174. M29 (store growth under lease churn for one hour at 500 renewals per second) was not measured by any package. A follow-up with the WP7.6 harness.
175. The weekly fuzz smoke of 2026-10-25 (`ci.yml`, job `fuzz-smoke`, `timeout-minutes: 60`) was cancelled after 60 minutes with 41 targets of 60 s each plus their builds, so it did not finish; the run of 2026-10-18 failed. E31's targets exist and ran locally without a crash; a complete weekly run is the proof. A CI change (a longer limit or the targets split over jobs) is the lead's.
176. M33 cannot run by the plan's method: neither `tenko serve` nor the example server has a switch that turns the `dhcp` role's counters off. The isolated stand-in (`metrics_cost.rs`: 170 ns of metrics work per exchange, 27.5 ns without the clock reads, against 27 µs of server CPU per exchange of the engine alone at 5,000 per second) bounds the cost at 0.6 percent; it says nothing about the p99. E22's "with and without metrics" is the same gap. A switch in the example (or two servers side by side, as M22 did in Phase 2) is the follow-up.
177. Found in WP9.5: the `dhcp` role allocates fixed tables at start whatever the scopes' size: 4,096 pending commits of a 1,472-octet reply and a 1,688-octet `PendingChange` each (about 12.6 MiB, written at start), the committer's queue of 4,096 `PendingChange` (about 6.6 MiB committed), the offer table of 65,536 slots and the probe's pending table. With every role the Windows release build idles at 110.41 MiB with three scopes and 200 leases against 72.90 MiB without the role, and the role costs 27.5 MiB resident and 50 MiB private before any scope exists; one worker instead of eight saves 3.3 MiB. M34 fails on Windows; the musl figure is not measured. The lever is to size the tables from the configuration (or from the pools) and measure again. Recorded in `2026-10-26-e32-rss-leases-metrics.md`. A follow-up package; not fixed here (WP9.5 changes no behaviour).
178. Found in WP9.5: the role's table of 100,000 leases holds 95.35 MiB (about 1 KiB per lease) against M30's 50 MiB: `tenko_core::dhcp::Lease` is 536 octets and sits inline in the table's hash map, which holds 131,072 buckets at 100,000 entries, and the client index allocates per client. The store's share after a restart and a full scan is about 33 MiB. The lever is a compact lease row in the table (or boxed rows with a small key map). Recorded in `2026-10-26-e32-rss-leases-metrics.md`. A follow-up package.
179. No Kea comparison figure is recorded: the newest report reachable at reports.kea.isc.org on 2026-10-26 (1.9.10 development, 2021) gives its DORA figures as charts only. The lead may record a figure from a current Kea release report when one is at hand.
180. The M26 to M28 figures are of 0.0.2 at `a5f9416`; the final build was not measured over the link (no lab VM in WP9.5). Section 6.1.
181. Found in WP9.5 by the conformance check: the rows of RFC 3527 and RFC 5107 still say Planned although `crates/tenko-dhcp/tests/engine.rs::link_selection_option_118_and_the_server_identifier_override_select_and_answer` tests both, and the Notes of RFC 3046 still say that scope selection by sub-option is Planned; the brief of WP9.5 named other rows, so these are left for the lead. CONFORMANCE.md.

Counts per group: scope and the ROADMAP 3, engine and role 6, DDNS 2, classes, policies and network boot 3, DHCPv6 6, deployment and UI 1, measurements 8. Total 29 (items 153 to 181).

## 4. Open items carried to Slices 10, 12 and 13, Phase 4 and Phase 5

| Item | Goes to | Recorded in |
|---|---|---|
| The failover pair (DHCP-12), its chaos test (DHCP-18), DHCPv6 failover, partner-down, split scopes beside Windows DHCP | Slice 12 | ha-plan.md; ADR 0025; deviation 153 |
| `dhcp` and `dns` nodes without a controller, fed by node sync into a node store; leases held by the serving node and published to the controllers | Slice 12 | ha-plan.md; deviation 155 |
| The recursive resolver and the ROADMAP line "resolves through Tenko alone" | Slice 10 | dns-recursion-plan.md; dns-recursion-status.md; deviation 154 |
| GSS-TSIG updates from Windows clients and DHCP-to-AD name ownership | Slice 13 (Phase 4) | identity-plan.md; ADR 0026 |
| DDNS to a DNS server that is not Tenko (RFC 2136, Windows DNS with GSS-TSIG; CONN-13, DNS-28) | Phase 4 | plan 1.6 |
| External DHCP actuators (CONN-12: Windows DHCP, Kea Control Agent) | Phase 4 | plan 1.6 |
| Windows DHCP, Kea and dhcpd as migration sources (MIG-08, MIG-12); the mapping is in `docs/dhcp.md` | Phase 4 | plan 1.6; P3-Q10 |
| DHCPv4 over DHCPv6 (RFC 7341), leasequery (RFC 4388) and bulk leasequery | Phase 5, or never | plan 1.6; CONFORMANCE.md |
| M30 and M34: a compact lease table and the role's fixed tables sized from the configuration, then M30 and M34 again on the musl binary | A follow-up package before 0.1.0 (the lead's call) | deviations 177 and 178 |
| M33: a switch for the DHCP metrics in the example, then M26 with the metrics on and off | A follow-up package | deviation 176 |
| M31 on the lab VMs with perfdhcp and option 81; the store's commit path under DDNS | A store package | deviation 163 |
| M29, store growth under lease churn | A follow-up with the WP7.6 harness | deviation 174 |
| The weekly fuzz smoke within its time limit | The lead (CI) | deviation 175 |
| `m9-idle-rss.sh` with a `[dhcp]` section and a hook for the scopes and the leases (the musl M34) | With the M34 follow-up | section 6.5 |
| DHCPv6 classes and policies, effective options for DHCPv6 clients, prefix reservations, the RA check on relayed links, RFC 8415's remaining parts | Unscheduled | deviations 164, 167, 169 |
| `GET /dhcp/reservations`, the history route's `kind` filter, a scope's `clear_ddns`, the zone audit per lease | Unscheduled | deviations 160, 165, 170, 162 |
| The Proxmox script with the `dhcp` role, the MSI smoke with the role, the relay check through the probe (P3-Q18 c) | Unscheduled | deviation 173 |
| The conformance rows of RFC 3527, 5107 and the note of RFC 3046 | The lead | deviation 181 |
| The home cut-over (E23), the power-offs (M32), the final-build perfdhcp run (E22), the musl E32 runs, the live five-device lab (E8) | Owner | section 6 |

## 5. ROADMAP "Done when"

`- [x]` is met, `- [ ]` is not yet. A line is checked only when its criterion is met or met with deviation. The first four lines are the ROADMAP's; the others are the criteria the plan adds to them (section 1.2).

- [x] kea perfdhcp numbers are documented. E22. Met with deviation: loopback and over the link from the load VM through the musl binary (M26 to M28); the runs with the metrics off are missing (deviation 176).
- [ ] The failover pair passes the chaos test: a partner is killed mid-load and no duplicate leases result (DHCP-18). Not a Phase 3 criterion: moved to Slice 12 by ADR 0025 and ha-plan.md (deviation 153); E24 is the single-node stand-in.
- [ ] The reference home-lab environment runs DHCP through Tenko for all four networks via relay. E23. Waiting for the owner; the role, the relay lab and the runbook are built and tested.
- [ ] The reference home-lab environment resolves through Tenko alone, with no upstream resolver, with DNSSEC validation on. Slice 10 (deviation 154).
- [ ] Leases survive the node (kills and power-offs under load). E24. The twenty kills pass; the five power-offs wait for the owner.
- [x] The five-device move lab runs with the DHCP step automatic. E25. `acceptance_move.rs`; the live lab is the Phase 1 step E8.
- [x] DDNS from DHCP with DHCID and name protection. E26. `acceptance_dhcp_ddns.rs`.
- [x] The relay and options lab, classes, filters, conflicts and PXE. E27. Met with deviation: some rows are crate tests, PXE in KVM mode only (deviation 166).
- [x] The reconciliation view with the four truths and fingerprinting. E28. `acceptance_reconcile.rs`.
- [x] DHCPv6 through a relay: IA_NA, IA_PD, DUID reservations, RFC 6939, RFC 4704, the RA check. E29. The lab round `dhcp6` and `acceptance_dhcp6.rs`.
- [x] The Kea JSON export accepted by Kea. E30. The lab's Kea rows.
- [x] Fuzz targets for DHCPv4 and DHCPv6 in the weekly smoke. E31. Met with deviation: the weekly job has not yet finished a run with them (deviation 175).
- [ ] Idle RSS below 100 MB with every role, metrics cost below 2 percent, the memory of 100,000 leases measured. E32. Not met: M34 110.41 MiB on Windows, M30 95.35 MiB against 50 MiB, M33 not measurable (deviations 176 to 178).

## 6. What the owner runs

Placeholders: `<node-vm>` and `<load-vm>` are the two lab VMs (ssh targets `<user>@<node-vm>`), `<vmid>` the node VM's ID on the Proxmox host, `198.51.100.34` the node's address on the link between the VMs and `198.51.100.35` the load VM's (a bridge or VLAN with no other DHCP server on it), `<version>` the release version, `<checkout>` a copy of the repository on the host that drives the runs (a Linux host or the load VM, with ssh to both VMs without a password). Nothing here needs a secret typed into a chat: the scripts generate their own throwaway administrator passwords. Nothing runs as root except the installer and the hypervisor's own commands.

Where a command does not exist, the row says so. Nothing is invented.

### 6.1 E22 (M26 to M28 on the final build): the real-link runs

Inputs: the two lab VMs as in WP7.6 (Ubuntu 24.04; `kea-admin` with perfdhcp 2.4 installed on the load VM, which WP7.6 did); the final build's static musl binary and the example server, built on a Linux host:

```sh
cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
cargo build -p tenko-dhcp --release --locked --example dhcp_server --target x86_64-unknown-linux-musl
```

The node VM (optional, for the installed service of section 6.5 and the cut-over rehearsal): the installer puts the shipped binary in place as root, the one step that needs it:

```sh
scp target/x86_64-unknown-linux-musl/release/tenko <user>@<node-vm>:tenko-<version>-linux-x86_64
scp deploy/install.sh <user>@<node-vm>:install.sh
ssh <user>@<node-vm>
sudo bash install.sh --yes --profile lab --roles controller,dhcp --binary ./tenko-<version>-linux-x86_64
sudo systemctl stop tenko        # the measurement runs its own instance on other ports
```

The measurement instance is not the service: `run-perfdhcp.sh --kind tenko` copies the binary to `~/dhcp` on the node, starts it as the ssh user with its own data directory under the Lab profile, the API on `127.0.0.1:18443` and a relay listener on the node's address on ports 6767 and 6868, and creates the bench scope `198.18.0.0/15` with one pool of 131,053 addresses and one-hour leases through the API (`scripts/node-setup.sh`). From the driving host:

```sh
cd <checkout>
bench/phase3-dhcp/scripts/run-perfdhcp.sh --kind tenko \
  --binary target/x86_64-unknown-linux-musl/release/tenko \
  --client target/x86_64-unknown-linux-musl/release/examples/dhcp_server \
  --node <user>@<node-vm> --node-addr 198.51.100.34 \
  --load <user>@<load-vm> --load-addr 198.51.100.35 --tune
# loopback on the node VM, for the upper bound:
bench/phase3-dhcp/scripts/run-perfdhcp.sh --kind tenko --binary ... --client ... \
  --node <user>@<node-vm> --load <user>@<node-vm> --node-addr 127.0.0.1
# the tables again from a finished raw directory:
python3 bench/phase3-dhcp/scripts/perfdhcp-report.py <raw-dir>/summary.tsv <raw-dir>
```

The script runs the M26 ladder (workers 1, 2, 4; 1,000 to 40,000 per second, each rung twice, stopping at the first rung that loses more than 1 percent), M27 (renewals beside as many new exchanges, and the own client's pure renewals) and M28 (1,000 and 5,000 per second with packet timestamps and the server's histograms); `--tune` raises the load VM's UDP sysctls with `bench/phase2-dns/scripts/tune-udp.sh` and restores them. Raw output goes to `bench/phase3-dhcp/results/raw/perfdhcp-tenko-<stamp>/` (not committed); `report.md` there holds the tables for a new results file in the shape of `2026-10-22-m26-m28-perfdhcp.md`. The runs with the metrics off do not exist: no switch turns them off (deviation 176).
Pass: M26 above 1,000 per second sustained within 0.1 percent drops, M28's p99 from REQUEST to ACK below 100 ms at 1,000 per second (the fallback line of P3-Q1); the figures documented.

### 6.2 E23: the home cut-over

Inputs: the cut-over day; the lease time on the existing DHCP server shortened a few days before; the gateway able to relay each of the four networks to one address; the reservations of the four networks in IPAM; a node with the roles `controller,dhcp` (and `dns` for option 6) and its `[dhcp] listen` in relay mode on the node's address (`deploy/README.md`, the DHCP section).
Commands: the runbook is [dhcp.md](../dhcp.md) section 17: the before-the-day table, the switch per network (the gateway's relay setting per network, described generically), the manual relay check by DHCP offer, the check from one client per network, the first hour on the dashboard's DHCP tiles, the rollback (the gateway's relay setting back, the old server still running) and the E23 rows to tick.
Pass: the E23 rows of the runbook: every network's clients get their addresses from the right scope through the relay, keep them across the switch, receive options 6 and 42, and the rollback is one setting on the gateway.

### 6.3 E24 (M32): the five power-offs

Inputs: the node VM and a second host for the ACK logs (the load VM); the Proxmox host's shell for `qm`; the node VM's disk honouring flushes (no `cache=unsafe`; with write-back caching the host needs a battery-backed cache, or the run measures the host's cache).
Commands: the procedure of `bench/phase3-dhcp/results/2026-10-22-m32-crash.md`, section "The power-off runs on the lab VM":

1. On the node VM, build the test binary in release (`cargo test --release --locked -p tenko-dhcp --test lease_crash --no-run`, or copy it from a Linux build host) and note its path `target/release/deps/lease_crash-<hash>`.
2. From the load VM, start the node over ssh with its output kept on the load VM:
   `ssh <user>@<node-vm> 'TENKO_LEASE_CRASH_CHILD=/var/tmp/e24/data /path/to/lease_crash-<hash> child_node --exact --ignored --nocapture --test-threads 1' | tee -a acks-<n>.txt`
3. The lead gives the signal after 5 to 60 seconds of load; the owner powers the VM off at the Proxmox host: `qm stop <vmid>` (a hard stop, no shutdown), then `qm start <vmid>`.
4. Copy `acks-<n>.txt` to the VM and check the data directory against every ACK so far:
   `cat acks-*.txt > acks-all.txt`, then `TENKO_LEASE_CRASH_VERIFY=/var/tmp/e24/data TENKO_LEASE_CRASH_ACKS=acks-all.txt /path/to/lease_crash-<hash> verify_after_power_off --exact --ignored --nocapture`, which prints `POWER-OFF OK` with the counts or fails naming the first lost or regressed ACK.
5. Repeat from step 2 on the same data directory until five power-offs are checked.

What the lead checks after: five `POWER-OFF OK` lines whose counts grow from run to run, no failure; the lead adds them to a new M32 results file (the ignored test `e24_ops_02_five_power_offs_of_the_lab_vm_lose_no_acknowledged_lease` of `acceptance_dhcp_exit.rs` reads that file and then runs). The test's node is the lease path's library entry points (deviation 168); the installed service is not used.
Pass: no acknowledged lease lost or regressed, no address on two clients, in five power-offs.

### 6.4 E8 and E25: the five-device lab with the DHCP step automatic

Inputs: the explicit go; the five-device lab of the ROADMAP Verification table (one wireless, one `static`, the rest `reserved`); a target prefix with an enabled Tenko DHCPv4 scope on a VLAN the controller knows; the devices' MACs or client identifiers on their interfaces in IPAM.
Commands: no CLI and no script, as in [phase-2-exit.md](phase-2-exit.md) section 6.4: drag in the IPAM tree or press M; `POST /api/v1/moves?dry_run=true` previews (the DHCP step shows the preview kind `dhcp.reservation`), `POST /api/v1/moves` with `expect_fingerprint` submits ([moves.md](../moves.md) section 4).
Pass: the `static` device stops at its manual step; the reserved devices get their reservations in the target scope, take a lease there and are confirmed by it without polling; the old reservations and leases go in the cleanup; a blocked step rolls back.

### 6.5 E32 (M34 and M30) on the musl binary

Inputs: the node VM and the final build's static musl binary.
Commands: M30 runs as is: `cargo test --release --locked -p tenko-dhcp --test lease_rebuild --no-run --target x86_64-unknown-linux-musl`, then the test binary with `e32_ops_15_the_memory_of_100000_leases_by_stage --exact --ignored --nocapture` and `TENKO_MEMORY_PAUSE_SECS=10`, reading `VmRSS` of `/proc/<pid>/status` at each `MEMORY stage=` line (the Windows script `m30-lease-memory.ps1` shows the reading; there is no Linux script). M34 has no Linux tool yet: `bench/phase1-server/m9-idle-rss.sh` writes no `[dhcp]` section and has no hook for the scopes and the leases (deviation 177 and section 4); the steps it needs are those of `bench/phase3-dhcp/scripts/m34-idle-rss.ps1` (three scopes on the documentation networks through the API, 200 leases with `dhcp_server load --subnet <network>`). The lead writes that hook before the run, and runs it after the follow-up that sizes the role's tables.
Pass: M34 below 95.37 MiB idle; M30 below 50 MiB for the table and its index, the store's share recorded.

### 6.6 Phase 1 and Phase 2 steps that still wait

The owner steps of [phase-2-exit.md](phase-2-exit.md) section 6 are unchanged: E13's bare-metal client, the cut-over of E14, the Windows DNS half of E15, the installer runs on real hosts, `kdig` for E20; and through it those of [phase-1-exit.md](phase-1-exit.md) section 6.

## 7. Test totals

The final-build column is filled by the lead after the last gate on the squashed commit. "Last recorded" is the newest gate with a figure in [phase-3-status.md](phase-3-status.md) and the WP9.5 builder's run on its branch.

| Item | Last recorded | Final build |
|---|---|---|
| Workspace tests (nextest, `--all-features --locked`) | 5,803 (gate of WP9.4's IA_PD half, `55fce518`); the WP9.5 branch: 5,892 passed, 43 skipped (the builder's run on Windows) | <final count> |
| Lab acceptance (`--run-ignored all` of the cluster labs) | 2 passed in each gate | <final> |
| UI tests | 5,183 (WP9.4's IA_PD half); 5,296 on the WP9.5 branch | <final> |
| Playwright scenarios | 251 (WP9.4's IA_PD half) | <final> |
| First-load bundle, gzip | 74.9 KB (the reconciler batches); not recorded since | <final> |
| Fuzz targets (`fuzz/fuzz_targets`) | 41, among them `dhcp_v4`, `dhcp4_options`, `dhcp4_relay_info`, `dhcp6_wire`, `dhcp6_relay` and `scan_ra` | <final> |
| Acceptance files of Phase 3 | `acceptance_dhcp.rs`, `acceptance_dhcp_config.rs`, `acceptance_dhcp_ddns.rs` (E26), `acceptance_move.rs` (E25), `acceptance_reconcile.rs` (E28), `acceptance_kea_export.rs` (MIG-16), and from WP9.5 `acceptance_dhcp6.rs` (E29) and `acceptance_dhcp_exit.rs` (E22, E24, E31, E32; five ignored threshold tests) | <every acceptance file green in the gate of the squash> |
| DHCP lab rounds (`deploy/compose/lab-dhcp`) | default round and `dhcp6` round green twice at the WP9.4 gate; the weekly `dhcp-lab` job green on 2026-10-25 | <final> |
| Requirement trace | `scripts/requirement-trace.mjs` for phases 1, 2 and 3 current on the WP9.5 branch | <current at the squash> |
| Other checks | fmt, workspace clippy with `-D warnings`, `cargo check --locked` of `fuzz/`, the OpenAPI document byte-identical, UI typecheck, lint and build, the changelog check, `cargo deny check` | <all green in the gate of the squash> |
