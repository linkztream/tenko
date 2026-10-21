# Phase 2 exit

- Status: Draft. WP6.5 fills the parts that need no owner input; the live parts wait for the owner (section 6). The measurements of WP6.5 are in; the cells in angle brackets in the header and in section 7 are filled by the lead after the last gate.
- Date: 2026-10-21
- Build: `main` at `48c73d0` (version 0.0.2) plus the WP6.5 branch. Final commit: the squash of the WP6.5 branch on `main` (the commit the WP6.5 row of [phase-2-status.md](phase-2-status.md) names; gated on 2026-10-22 after WP3.14's merge `f20aaf4`).
- Scope: the exit record of Phase 2. It holds the nine exit criteria E13 to E21, the measurements M16 to M25, the deviations, the open items carried to Phase 3 and Phase 5, the ROADMAP "Done when" list and the commands the owner runs for the live parts. Every figure is a single-node figure (plan section 2.10). Sources: [ROADMAP.md](../ROADMAP.md) (Phase 2), [phase-2-plan.md](phase-2-plan.md) sections 1.2, 1.6, 2.10, 6 and 9, [phase-2-status.md](phase-2-status.md), [phase-1-exit.md](phase-1-exit.md) and the results files under `bench/phase2-dns/results/` and `bench/phase1-server/results/`.

Contents:

1. [Exit criteria](#1-exit-criteria)
2. [Measurements](#2-measurements)
3. [Deviations](#3-deviations)
4. [Open items carried to Phase 3 and Phase 5](#4-open-items-carried-to-phase-3-and-phase-5)
5. [ROADMAP "Done when"](#5-roadmap-done-when)
6. [What the owner runs](#6-what-the-owner-runs)
7. [Test totals](#7-test-totals)

## 1. Exit criteria

Status is one of: met, met with deviation, waiting for the owner, documented, not met. The checks are those of [phase-2-plan.md](phase-2-plan.md) section 1.2. E13 and E21 rest on the measurements of WP6.5 (M17, M22, M23), run on two lab VMs on one Proxmox host and from the workstation on 2026-10-21. The acceptance tests named for WP6.5 read the results files and run anywhere.

| # | Check | Requirements | Status | Evidence | Left for the owner |
|---|---|---|---|---|---|
| E13 | dnsperf and flamethrower numbers are documented for one Tenko node: per core on loopback and from a load generator on another host over a real link, UDP and TCP, with and without metrics | DNS-27, OPS-21 | Documented (met) | `crates/tenko/tests/acceptance_dns_exit.rs`; `bench/phase2-dns/results/2026-10-21-m17-real-link.md`; `bench/phase2-dns/results/2026-10-21-m22-metrics-cost.md`; the loopback M16 files `bench/phase2-dns/results/2026-10-17-m16-serve.md` (the `dns` role of `tenko serve`), `2026-10-17-m16-loopback.md` (the engine's example server) and `2026-10-17-baseline-spike-b.md`. Figures: over a virtual link from another VM, dnsperf, UDP 188,000 QPS on one worker (one core busy) and 444,000 on four (135,000 per busy core), p99 1.6 and 5.0 ms at saturation; TCP 1.95 M QPS (491,000 per core); DoT 1.14 M (dnsperf) and DoH 226,000 (h2load); from the workstation over the physical LAN 90,000 QPS, limited by WSL2's path, not by the node; flamethrower over all four transports, its TCP, DoT and DoH figures the tool's, not the server's; with and without metrics in M22 | A bare-metal client on the LAN for a physical-link figure that is the server's (section 6.1) |
| E14 | A home network sends all of its queries through Tenko: clients resolve through a Tenko node that forwards AD zones to the domain controllers and everything else to a DoT upstream, with a blocklist active | DNS-02, DNS-15, DNS-21, DNS-23, TGL-14, TGL-22 | Waiting for the owner | Automated: `crates/tenko/tests/acceptance_dns.rs` (forwarding rules by suffix, the cache, a flush by suffix, the recursion access list refusing a stranger, a fetched block list answering NXDOMAIN with the extended error "Blocked"); `crates/tenko/tests/acceptance_dns_tls.rs` (DoT and DoH served); `deploy/compose/lab-dns` (BIND 9 as plain, DoT and DoH upstream, green twice from the musl image); `crates/tenko-dns/tests/{upstreams,policy,lists}.rs`; M24 and M25 (section 2). The owner's test node has run at home since 2026-10-18 (an Ubuntu LXC, the musl binary, roles `controller` and `dns`); that was a test drive, not the cut-over. The runbook is [dns-resolver.md](../dns-resolver.md) section 9 | The cut-over: choose the day, point DHCP option 6 and RDNSS at the node, run the verification rows of the runbook, keep the rollback (section 6.2). Check the runbook's `rule="..."` label against the live node |
| E15 | BIND as secondary receives Tenko's zones (AXFR, IXFR, NOTIFY, TSIG, XoT) and Tenko as secondary receives a BIND zone; Windows DNS as primary of one zone into Tenko on the owner's go | DNS-09, DNS-19, TGL-10 | Waiting for the owner | BIND halves, met: `crates/tenko/tests/acceptance_dns_xfr.rs` (two real nodes: AXFR with TSIG, NOTIFY then IXFR as one journal step, the read-only secondary, catalog zones both ways, expiry to SERVFAIL); `deploy/compose/lab-dns` (BIND as secondary and as primary: TSIG, NOTIFY, IXFR, XoT and a catalog zone each way, eleven rows PASS twice from the musl image, in the weekly self-hosted lab job); M19 (section 2); `crates/tenko-dns/tests/xfr.rs`. The Windows half is written as a checklist in [dns.md](../dns.md) section 10.13 | The Windows DNS half: allow the transfer of one AD zone to the node's address, create the secondary zone, check the rows (section 6.3) |
| E16 | Fuzz targets for the wire format, the zone file parser and TSIG run in the weekly fuzz smoke | API-14, API-15 | Met | `fuzz/fuzz_targets/{dns_codec,dns_zonefile,dns_tsig}.rs`, and `dns_edns`, `dns_lists`, `dns_tls_wire` beside them (26 targets in all, 20 before Phase 2); the `fuzz-smoke` job of `ci.yml` runs every target `cargo fuzz list` prints for 60 s. `dns_tsig` ran 6.1 M times in 181 s clean on the workstation (WP6.2 row) | None. The first weekly run that lists the six `dns_*` targets is the proof; the status file records no such run yet |
| E17 | Every IPAM address with a DNS name has its A or AAAA and PTR records in Tenko zones, reverse zones exist for the managed prefixes including an RFC 2317 delegation, and the five-device move lab of Phase 1 (E8) runs with the DNS step automatic | DNS-22, IPAM-19, IPAM-13 | Met | `crates/tenko/tests/acceptance_move.rs` (the five-device lab with the DNS step automatic, a name outside Tenko's zones kept manual, a cancelled move puts the records back, a hand-deleted `ipam` record restored and audited, a taken-over one proposed as held); `crates/tenko/tests/acceptance_reverse.rs` (a /26 inside a served /24 gets its RFC 2317 zone with the CNAME glue in the parent, a /25 whose parent is elsewhere gets a proposal with the delegation lines); `crates/tenko-dns/tests/index.rs`; [dns.md](../dns.md) section 7 | The five-device lab against the live controller is the Phase 1 step E8 and waits for the owner's go (section 6.4) |
| E18 | An RFC 2136 update signed with TSIG from `nsupdate` is applied through the store and answered from the index, refused without the key or outside the ACL, and answered SERVFAIL when the store refuses the write | DNS-11, TGL-09 | Met | `crates/tenko/tests/acceptance_dns_update.rs` (add, replace, delete, each prerequisite of RFC 2136 section 2.4, REFUSED without the key and outside the lists, NOTAUTH for an unknown key, `ipam` RRsets protected, SERVFAIL while the store's test hook refuses writes and success when it lets go); `deploy/compose/lab-dns` update round (`nsupdate -y` from the client container, green twice from the musl image); M21 (section 2); `fuzz/fuzz_targets/dns_tsig.rs`. The test uses an RFC 2136 client written in the test; `nsupdate` itself runs in the lab | None |
| E19 | A zone signed by Tenko (NSEC and NSEC3) validates in an external validator, a ZSK rollover completes without a validation failure, and CDS and CDNSKEY are published for the KSK | DNS-12, OPS-09 | Met | `crates/tenko/tests/acceptance_dnssec.rs` (through the binary, `delv` and `dnssec-verify` from the BIND image: a positive answer, NXDOMAIN, NODATA and a wildcard answer "fully validated" with NSEC and with NSEC3, a ZSK rollover validated throughout, CDS listing the KSK); `crates/tenko-dns/tests/{dnssec,dnssec_vectors,dnssec_alloc}.rs`; M20 (section 2); [dnssec.md](../dnssec.md), ADR 0018 | None. The validator steps need the Docker image and are skipped with a message without it (deviation 117) |
| E20 | DoT and DoH are served with the certificate of the configured TLS mode and answer `kdig`; RRL slows a reflection pattern; ANY answers are minimal; a TXT over 255 bytes round-trips split | DNS-14, DNS-17, DNS-18, DNS-24, TGL-11 | Met with deviation | `crates/tenko/tests/acceptance_dns_tls.rs` (DoT and DoH in the three TLS modes of OPS-22 through the binary: the internal CA, imported files with a reload, behind a reverse proxy with PROXY v2; the clients are rustls and hyper in the test); RRL: `crates/tenko-dns/tests/rate.rs` (a reflection flood limited to the rate and slipping every second response); ANY and minimal responses: `crates/tenko-dns/tests/{index,index_corpus,resolver}.rs`; TXT: `crates/tenko-dns/tests/{differential,resolver}.rs` and the model tests of `tenko-core::dns`. No acceptance test is named after the RRL, ANY and TXT parts | `kdig` was not installed in any run: the test asks it too when it is on the `PATH` (deviation 99; section 6.9) |
| E21 | Idle RSS below 100 MB with all Phase 1 roles plus `dns` serving the home zones and a 10,000-entry cache, on the musl binary, one node; metrics overhead on the query path below 2 percent | OPS-15, OPS-21 | Not met: M22 and M23 FAIL on the lab | `crates/tenko/tests/acceptance_dns_exit.rs`; `bench/phase2-dns/results/2026-10-21-m23-idle-rss.md`; `bench/phase2-dns/results/2026-10-21-m22-metrics-cost.md`. Figures: M23 102.46 MiB idle at most against 95.37 MiB by the M9 procedure (200 prefixes, which give 195 reverse zones, plus the ten home zones and 9,984 cache entries), 94.21 MiB with 20 prefixes, 90.25 MiB without the zones and the cache; M22 +4.8 percent CPU per query with the metrics on over 20 simultaneous pairs at two workers (standard error 2.1 points, p99 3.49 against 3.17 ms), +1.9 percent and p99 unchanged at one worker. The two E21 tests of `acceptance_dns_exit.rs` (`e21_ops_21_...` and `e21_ops_15_...`) assert PASS and are marked `#[ignore]` while E21 is not met, so that `main` carries no failing test; they run with `--run-ignored all` once the follow-up package (a metrics shard per worker, the reverse-zone memory of many prefixes) and new M22 and M23 results are in (deviations 145 and 146). The two E13 tests run and pass. An earlier reading with the three roles on the jemalloc musl binary: 85.31 MiB at most, [results](../../bench/phase1-server/results/2026-10-19-m9-idle-rss.md); it is not the M23 procedure (home zones and a full cache) | What the M22 and M23 rows of section 2 list as still to run |

Other acceptance files of this phase, for areas no single E-row names: `acceptance_dns.rs` (the `dns` role in the process, restart, the resolver side, block lists; also E14), `acceptance_dns_views.rs` (views, scopes and weights, DNS-20: client-subnet, transport and interface rules, a 700/300 split within 5 points, recursion per view, no leak through the cache) and `acceptance_dns_exit.rs` (WP6.5, E13 and E21).

## 2. Measurements

Thresholds are those of [phase-2-plan.md](phase-2-plan.md) section 6. Numbers are from the newest results file of each measurement. Linux figures come from the static musl binary, which since 2026-10-19 carries jemalloc as its allocator; Windows figures from the release build. "Loopback" means client and server on one host: an upper bound. "Final build" means the commit named in the header.

| # | Measurement | Threshold | Latest number | Verdict | Results file | Still to run |
|---|---|---|---|---|---|---|
| M16 | QPS per core, loopback, UDP and TCP, 100,000-name zone (DNS-27) | Above 100,000 per core over UDP; TCP documented | `tenko serve --roles controller,dns`, workers 1 / 4 / 8. Windows UDP 132,583 / 112,582 / 87,999 per core, p99 2.7 / 0.8 / 0.5 ms; WSL2 musl UDP 123,188 / 178,847 / 255,783 per core, p99 2.4 / 0.9 / 0.6 ms. TCP documented: Windows 565,520 / 574,649 / 550,094 QPS, musl 945,827 / 1,745,343 / 2,171,837 QPS | PASS (every UDP row but Windows with 8 workers, where the engine's example and the Spike B baseline are also below, because the load generator shares the cores) | `bench/phase2-dns/results/2026-10-17-m16-serve.md`; `2026-10-17-m16-loopback.md`; `2026-10-17-baseline-spike-b.md` | The 8-worker Windows row on another host (M17) |
| M17 | One node over a real link, dnsperf and flamethrower from another host and from the workstation (DNS-27, ADR 0009) | Documented; the number that may be published | The node VM (4 vCPU) and the load VM (8 vCPU) on one Proxmox host, 0.4 ms. dnsperf, 30 s, better of two: UDP 188,105 / 309,572 / 443,753 QPS at 1 / 2 / 4 workers, 187,813 / 159,370 / 134,688 per busy core, p99 1.6 / 3.1 / 5.0 ms (saturated); TCP 1.17 M / 1.25 M / 1.95 M QPS, 491,000 per core at 4; DoT (dnsperf) 1.14 M QPS, p50 0.11 ms and p99 0.5 ms at 10,000 per second; DoH (h2load) 226,000 per second; the harness from the load VM UDP 665,000 and TCP 1.83 M; the workstation over the physical LAN 90,000 QPS (WSL2's path is the limit); flamethrower UDP 154,000 (one thread), its TCP, DoT (40 ms per answer) and DoH (no answer) figures are the tool's | Documented: the UDP figures from dnsperf on the load VM may be published under ADR 0009, with the caveats of a virtual link and a shared host | `bench/phase2-dns/results/2026-10-21-m17-real-link.md` | A bare-metal client on the LAN; two hosts that do not share their cores |
| M18 | Zone load and index memory at 1 M and 6 M RRsets | Load under 60 s at 6 M; index under 1.5 GiB at 6 M | 1.2 M RRsets on the jemalloc musl binary: import to serving 51.5 s, against 176.2 s with musl's malloc back to back (2026-10-19). 7.2 M RRsets (2026-10-17, before jemalloc): import to serving 822 s on musl and 198 s on Windows; the role builds its index from the store in 51 s and 35 s; the index holds 926 MiB (135 octets per RRset); the process peaks 1.7 to 2.3 GiB above an empty node | PASS at 1 M (jemalloc) and for index memory; FAIL at 6 M on the last measurement, not re-measured on jemalloc | `bench/phase2-dns/results/2026-10-19-m18-zone-load.md`; `2026-10-17-m18-zone-load.md` | 6 M on the jemalloc binary: needs a longer request timeout for the upload (deviation 82) |
| M19 | IXFR delta and NOTIFY latency | A 100-record change reaches BIND within 5 s; the delta carries only the change | Five rounds on a 100,000-record zone: 649 to 721 ms from the commit, median 689 ms; BIND had the NOTIFY 233 to 237 ms after the commit; every transfer an IXFR of 204 records and 4,399 octets in one message, against 144 messages and 2.3 MB for the full zone | PASS (Linux musl, one Docker host, loopback) | `bench/phase2-dns/results/2026-10-18-m19-xfr.md` | None for Phase 2; a real link with BIND on another host is optional |
| M20 | Signing time and re-sign rate at 1 M records | 1 M records signed under 5 min; a 100-record change signed again under 1 s | Windows (2026-10-18): NSEC 45.9 s ECDSA and 45.2 s Ed25519, NSEC3 69.6 s and 70.4 s; changes 0.52 to 0.54 s median, 0.61 s at most. Linux musl with jemalloc (2026-10-19), ECDSA with NSEC3: 108.4 s, changes 0.33 to 0.98 s (median 0.59 s). Linux musl with musl's malloc (2026-10-18): NSEC 224.2 s and 213.6 s, NSEC3 316.5 and 294.7 s (321.4 and 319.4 s in first runs) | PASS on Windows; PASS on Linux for the case that failed (ECDSA NSEC3); the other Linux cases were last measured on musl's malloc (Ed25519 NSEC3 295 to 319 s, at the limit) | `bench/phase2-dns/results/2026-10-19-m20-signing.md`; `2026-10-18-m20-signing.md` | ECDSA NSEC, Ed25519 NSEC and NSEC3 on the jemalloc binary (deviation 136) |
| M21 | Dynamic update rate end to end | 1,000 updates/s sustained; p99 under 250 ms from `nsupdate` to the answer | 1,000 TSIG-signed updates per second for 60 s, two runs per platform: 60,000 of 60,000 NOERROR with a valid TSIG each; p99 17.6 and 19.4 ms (Windows release), 14.9 and 15.5 ms (musl). 5,000 per second for 30 s: p99 36.9 and 35.9 ms | PASS (one node, load generator on the same host) | `bench/phase2-dns/results/2026-10-19-m21-update.md` | The same run on a cluster is a Phase 5 comparison |
| M22 | M8 again: metrics cost on the query path (OPS-21) | Below 2 percent, p99 unchanged | The engine's example server (`tenko serve` has no switch), metrics on and off at once on the node, 100,000 QPS each from dnsperf on the load VM: +4.82 percent server CPU per query over 20 pairs at two workers each (mean of the pairs +5.14, standard error 2.12), p99 3.49 against 3.17 ms; +1.89 percent and p99 unchanged over 10 pairs at one worker each; alternating runs at four workers +2.5 to +6.2 percent | FAIL on the lab (above 0 by 2.4 standard errors, above 2 percent by 1.5) | `bench/phase2-dns/results/2026-10-21-m22-metrics-cost.md` | After a fix of the metric shards per worker (deviation 146), again with `run-m17-remote.sh --phases metrics`; hosts that do not share cores |
| M23 | M9 again: idle RSS with every role and the DNS module (OPS-15) | Below 100 MB (95.37 MiB) on the musl binary | The node VM, 0.0.2 musl with jemalloc, roles `controller,probe,dns`, 600 s idle: 102.46 MiB at most by the M9 procedure (200 prefixes and their 195 reverse zones, ten home zones, 9,984 cache entries); 94.21 MiB with 20 prefixes (25 zones); 90.25 MiB without the zones and the cache (85.31 MiB for that procedure in WSL2 on 2026-10-19) | FAIL by the procedure; PASS at home size by 1.2 MiB | `bench/phase2-dns/results/2026-10-21-m23-idle-rss.md` | Again after room is made (deviation 145); on the final build |
| M24 | Cache behaviour | Hit ratio and p99 at a 1 M-name mixed run; serve-stale answers under an upstream cut | Windows, 100,000-entry bound over 25 M queries: 99,968 entries held, hit ratio 0.837 (1.000 once every question fits), p99 3.5 ms closed loop and 1.2 ms paced at 20,000 QPS, about 266,000 QPS, RSS 126 MiB. A 30 s upstream cut: 596,878 stale answers, no error or timeout among 1.2 M queries | PASS (documented) | `bench/phase2-dns/results/2026-10-18-m24-cache.md` | The Linux musl run (WSL2's loopback relay loses packets; needs a Linux host or VM); DoT and DoH upstreams under load |
| M25 | Blocklist compile and match | 1 M names under 2 s; match cost constant per label | 1,000,000 names: compile plus matcher 1.04 s on Windows and 1.56 s on musl; the stored version 10.8 MiB; a lookup 101 / 156 / 251 ns (Windows) and 121 / 160 / 270 ns (musl) at 2 / 4 / 8 labels, about 50 falling to 31 ns per label | PASS | `bench/phase2-dns/results/2026-10-18-m25-lists.md` | None |

### M16, M18 and M20 on one host

All loopback and single-node. The WSL2 rows are a virtual machine on the same workstation as the Windows rows; a WSL2 loopback ran into dropped UDP on some days, which is why M18 asks the last name over TCP and M21 uses the Docker bridge address on Linux (both stated in their files). M18 and M20 on musl were set by the allocator in the store's write path: musl's own malloc made imports and signing four to seven times slower than on Windows. The owner decided on 2026-10-19 to ship jemalloc in the musl binary (M9 on the jemalloc binary: 85.31 MiB at most, 10.1 MiB under the limit, [results](../../bench/phase1-server/results/2026-10-19-m9-idle-rss.md)); mimalloc failed OPS-15 and was dropped. The 6 M row of M18 predates that change and has not been repeated, because the command-line client's 60 s request timeout ends the upload of the 212 MB file.

### M24 and M25

M24 runs the resolver against the engine's example server as upstream, on one Windows host: the resolver, the upstream and the load generator share the cores, so QPS and latency are bounds. M25 is single-thread and does not involve the network.

## 3. Deviations

Grouped by area. "Row" means a row of [phase-2-status.md](phase-2-status.md); "backlog" means the owner backlog of 2026-10-18 in that file. Numbering continues [phase-1-exit.md](phase-1-exit.md), which ended at 74. Items closed by a later package are not listed.

### Engine and role

75. The multi-node data plane is not built. The `dns` role runs inside the controller's process only; the node-file feed, the `dns` subset of node sync (declared in WP4.0 and consumed by no node), `Dns.Update` over the cluster channel, a `dns` node without a controller, per-node zone selection and the per-node status through node commands are Phase 5. Recorded in plan sections 1.6 and 2.10 and the WP4.0 row. Phase 5.
76. Wildcard listen addresses are not expanded (documented and logged), so each address is listed in `listen`; a wildcard bind answers from the address the kernel picks, because there is no `IP_PKTINFO`. Recorded in the WP4.1 and WP4.3 rows. Unscheduled.
77. The role builds its index from one image of all its rows: at 7.2 M RRsets the process peaks 1.7 to 2.3 GiB above an empty node at start. Building the index from the store's pages is a follow-up. Recorded in the WP4.3 row and [dns.md](../dns.md) section 12.11. Unscheduled.
78. An import into a serving node takes 14 to 85 percent longer than into a node without the `dns` role, because each delta copies the zone's overlay and the overlay is folded into a new base often; the cure is an incremental base or a bulk build for imports. Recorded in the WP4.3 row and the M18 results file. Unscheduled.
79. TCP, DoT and DoH run on the controller's core runtime; there is no separate runtime for DNS over TCP, and `[runtime] workers` sets the thread count. Recorded in the M16 results file for `tenko serve`. Unscheduled.
80. The counting-allocator test ran on Windows only, and the systemd smoke with its `systemd-analyze security` threshold was not run with the `dns` role. Recorded in the WP4.3 row. Unscheduled (the weekly systemd smoke now runs the installer, WP6.6).

### Zones and API

81. Key changes need an interactive session (the CLI's tokens get 403); import progress is the job's steps; the staged zone file lives in the memory of the controller that took the request; an import does not check the versions of the RRsets it replaces. Recorded in the WP4.2 row and [dns.md](../dns.md) section 4. Unscheduled.
82. `tenko dns import` gives every request 60 s, and the server reads and checks the whole zone file within the request, so a 212 MB file (6 M records) cannot be imported through the client today. A longer upload timeout, or an upload checked by the job, is a follow-up. Recorded in the M18 results file of 2026-10-19. Unscheduled.
83. Command-line gaps: no `tenko dns` command creates a secondary zone (the API and the UI do) or sets a stub zone's `source`, there is no `tenko dns log`, and the prefix command cannot set `dns_reverse` (it has no update). Recorded in the WP6.1, WP5.1, WP5.4 and WP4.4 rows. Unscheduled.

### IPAM link

84. Every reconciler run reads the `ipam` RRsets of every zone, and the actuator's writes are not fenced with the leader epoch. Recorded in the WP4.4 row and [dns.md](../dns.md) section 7. Unscheduled.
85. The host panel shows no PTR for an address inside an RFC 2317 block. Recorded in the WP4.4 row (UI follow-up). Unscheduled.
86. The reverse zones of imported prefixes: the first forward zone of a tenant switches every prefix without `dns_reverse` to managed and copies its SOA and name servers once into the new reverse zones, so a throw-away test zone became the template of ten reverse zones. Wanted: a chosen default zone for the template, reverse zones that follow it, and a note in the zone form. Recorded in the backlog (2026-10-19) and plan P2-Q11. Backlog.
87. The IPAM import preview refuses each network under an existing prefix of role network with `ipam.prefix.overlap`; it should offer to make that prefix a supernet as one plan step. Recorded in the backlog. Backlog.

### Resolver and cache

88. Tenko has no recursion of its own: names outside the zones and the forwarding rules are refused when no upstream applies. Full recursion (iterative resolution from the root hints with priming, DNSSEC validation, QNAME minimisation, DNS-03, DNS-13, DNS-34) is Phase 5 by ADR 0007 and plan section 1.6. Recorded in the backlog. Phase 5.
89. The upstream pool chooses the fastest healthy upstream per rule, but the round-trip time and health per upstream are not shown in the node status, on the forwarders page or in `tenko dns forwarder list`. Recorded in the backlog. Backlog.
90. The node status does not report the forwarders of the configuration file. Recorded in the WP5.5 row. Unscheduled.
91. The cut-over runbook's `rule="..."` label is the rule's suffix as stored; it is to be checked against a live node at E14. Recorded in the WP5.6 row. With E14.

### Policy and lists

92. The query log's `blocked` flag stays empty, and a forwarded answer is logged before the policy rewrites it (`respond.rs`, `forward.rs`). Recorded in the WP5.2 row. Unscheduled.
93. The last fetch error and time of a list live in the memory of the controller that ran the job: not shared, empty after a restart. Recorded in the WP5.2 row. Unscheduled.
94. The NSDNAME and NSIP triggers of RPZ see only what the upstream's answer carries. Recorded in the WP5.2 row. Unscheduled.
95. A zone switched to RPZ by a delta is compiled without its records until the next full rebuild. Recorded in the WP5.2 row. Unscheduled.
96. A home blocking view in the spirit of Pi-hole: statistics from the query log per list, client and over time, allow-from-the-log, a pause switch, client groups with different lists, ABP and regex rule syntax. Recorded in the backlog. Backlog.

### TLS transports

97. ACME for the DoT, DoH and API certificate is not built (P2-Q8); the three TLS modes of OPS-22 are reused. Recorded in plan P2-Q8 and phase-1-exit section 4. Phase 5.
98. DoQ (DNS-16) is not built. Recorded in plan section 1.6. Phase 5.
99. No `kdig` check ran, because `kdig` is not installed; the tests use their own rustls and hyper clients and ask `kdig` as well when it is on the `PATH`. Recorded in the WP5.3 row. Owner (section 6.9).
100. EDNS padding (RFC 8467) is not done: a passive observer can guess an answer from its length. Recorded in the WP5.3 row and [dns-resolver.md](../dns-resolver.md) section 7.7. Unscheduled.
101. DoH is not served under `/dns-query` on the API's own port, as plan risk R49 proposed; it has an address of its own, or the reverse proxy fronts both. Recorded in the WP5.3 row and [dns-resolver.md](../dns-resolver.md) section 7.7. Unscheduled.
102. The RFC 7858 and 8484 rows of `docs/CONFORMANCE.md` are not moved to Implemented, and the node route shows no open-connection counters for DoT and DoH (`Server::layout` and the metrics have them). Recorded in the WP5.3 row. Unscheduled.
103. A change of the API's TLS mode while the process runs (to the reverse-proxy mode) removes the certificate that DoT and DoH share with the API, and their handshakes fail until the node restarts with a matching `[dns.tls]`; a certificate of their own avoids it. Recorded in [dns-resolver.md](../dns-resolver.md) section 7.7. Unscheduled.

### Query log

104. Daily pseudonymisation keys apply in every profile, a deviation from the Lab row of TGL-15. Recorded in the WP5.4 row. Unscheduled.
105. The dnstap output has no `RESOLVER_*` messages, the log entry holds no copy of the wire message, and no dnstap reader exists on the host (the format is read back in a test with an own reader). Recorded in the WP5.4 row. Unscheduled.
106. The cursor of the log read and of the cache listing carries the queried name in hex into the command row and the audit record. Recorded in the WP5.4 row and the cache browse row. Unscheduled.

### Transfers

107. The transfer state lives in the leader's memory, and no `dns.transfer` events are published. Recorded in the WP6.1 row. Unscheduled.
108. The Windows DNS half of E15 is the owner's step, and that zone transfers without TSIG, because Windows DNS does not sign transfers; the access rests on the address restriction on both sides. Recorded in the WP6.1 row and [dns.md](../dns.md) section 10.13. Owner.
109. RFC 8945 has no test-vector appendix; TSIG is checked with a known-answer test and `dig -y` against BIND. Recorded in the WP6.1 row. Unscheduled.

### Updates

110. An update for a secondary zone is refused, not forwarded to its primary. Recorded in the WP6.2 row. Phase 5, with `Dns.Update`.
111. The number of commits per M21 run was not counted, so how much the per-zone batching folds updates (plan risk R52) is not measured. Recorded in the WP6.2 row and the M21 results file. Unscheduled.
112. DDNS from DHCP (DHCP-13) is not built; the update path of plan section 2.4 is the one it will use. Recorded in plan section 1.6. Phase 3.

### DNSSEC

113. The signing metrics are not wired. Recorded in the WP6.3 row. Unscheduled.
114. There is no algorithm rollover. Recorded in the WP6.3 row. Unscheduled.
115. No RRSIGs are added to the additional section. Recorded in the WP6.3 row. Unscheduled.
116. An NSEC3 owner name is answered as an existing name rather than NXDOMAIN. Recorded in the WP6.3 row. Unscheduled.
117. `acceptance_dnssec.rs` needs the BIND image through Docker (`TENKO_DNSSEC_DOCKER` names the command); without it the validator steps are skipped with a message and the rest of the scenario runs. Recorded in the test's header. Unscheduled.

### Views

118. Zone scopes can be set through the API only: there is no CLI flag and no editor on the zone settings tab. Recorded in the WP6.4 row. Unscheduled.
119. `forwarders.rs` does not check the view row it names, so a rule created as its view is deleted can point at nothing. Recorded in the WP6.4 row. Unscheduled.

### UI

120. The history tab of the zone page does not use `GET /dns/zones/{id}/journal` yet, and the list of simplifications in `wp45-handover.md` (shared notes) is not applied. Recorded in the WP4.5 row. Unscheduled.
121. The end-to-end scenarios fake the DNS routes in the browser, and the e2e server runs the controller role only, so its real-server scenario checks that no DNS tiles appear; the DNS tiles are seen in the mock's sample. Recorded in the WP4.5 and WP5.6 rows. Unscheduled.
122. There is no module switch after setup (the notices link to `/settings`), and the UI has no hosted docs, so the DNS settings page names the `tenko.toml` key and the docs section as text. Recorded in the WP5.5 row. Unscheduled.
123. The server's job titles `dns.job.import`, `dns.job.edit` and `dns.job.list_compile` have no UI units, so the UI shows the key; the cache listing shows the view's id, not its name; the log page has no forwarded flag; `DnsPage.tsx` still says "Coming in a later slice". Recorded in the WP5.2, cache browse, WP5.4 and WP6.4 rows. Unscheduled.
124. The start page's top tile row has the same half-empty last row at wide widths as the tiles had, and `.dash-body`'s maximum width never applies because `.page-body.wide` overrides it. Recorded in the tiles row. Unscheduled.
125. The UI test `App.test.tsx` "shows the DNS page on a deep link into the DNS area" fails under full-suite load at nearly every gate and passes alone; its budget is to be widened or the DNS chunk loaded in the test. Recorded in the backlog. Backlog.

### Deployment

126. The Linux installer and the Proxmox script have run only in WSL distributions, a systemd container and the CI containers. A real unprivileged LXC on a Proxmox host and the sealed key end to end on a VM have not been run, and the release asset `tenko-proxmox.sh` works only once the repository is public. Recorded in the WP6.6 row. Owner (sections 6.5 and 6.6).
127. The MSI has never been installed for real (service, firewall, upgrade, uninstall, purge): the first run is the `msi` job's smoke on the first release, or `msi-smoke.ps1` on a throw-away Windows VM. Recorded in the WP6.7 row. Owner (section 6.7).
128. The MSI and `tenko.exe` ship unsigned (no code-signing certificate, decided 2026-10-19), with the SmartScreen notice documented; the release workflow signs when a signing secret exists. The Linux asset is verified by `SHA256SUMS` only until a detached signature exists. Recorded in the deployment packages notes and [windows/README.md](../../deploy/windows/README.md). Phase 5 (API-19).
129. One command installs one node. A production cluster started from scratch still needs the join step on each further controller ([cluster.md](../cluster.md) section 12.1); an Ansible role over the installer's unattended mode waits for Phase 5. Recorded in the deployment packages notes. Phase 5.
130. The examples in `deploy/README.md`, `deploy/proxmox/README.md` and `deploy/windows/README.md` name versions 0.2.0 and 0.3.0, while the build is 0.0.2 and no release is tagged. Not recorded elsewhere; found while writing this document. Unscheduled.

### Measurements

131. The dnsperf and flamethrower scripts were not run in WP4.6a (the tools are not installed), so the loopback figures of M16 come from the `bench/phase2-dns` load generator, the Spike B tool. Recorded in the WP4.6a row. M17 ran both on 2026-10-21 from the load VM (WP6.5).
132. Every loopback figure is an upper bound with the generator on the same cores, and the WSL2 rows are a virtual machine whose loopback dropped UDP on some days. Recorded in the M16, M18, M21 and M24 results files. Unscheduled.
133. Windows UDP with eight workers is 87,999 per core, below 100,000, as the engine's example (87,906) and the Spike B baseline (88,776) are; the generator shares the cores. Recorded in the M16 results files. Read again at M17.
134. M18 at 6 M failed the load threshold on the last measurement (822 s on musl, 198 s on Windows, before jemalloc) and has not been repeated. Recorded in the WP4.3 row and the M18 results files. Unscheduled.
135. The M18 baseline of 2026-10-19 (176 s at 1 M) is twice that of 2026-10-17 (87 s) on the same machine, and the reason was not looked for; the musl test suite in WSL shows loopback failures that were not compared with the baseline. Recorded in the M18 results file and the allocator row. Unscheduled.
136. After jemalloc only ECDSA with NSEC3 was repeated on the Linux binary; NSEC and Ed25519 were not. Recorded in the M20 results file of 2026-10-19. Unscheduled.
137. M24 is Windows only: the Linux musl run waits for a Linux host or VM, and DoT and DoH upstreams were not measured under load. Recorded in the WP5.1 row. Unscheduled.

### Other

138. The SPF, DKIM and DMARC wizard (DNS-25) is out of Phase 2. Reason: time; the plan made it a Could, only if the UI package of Slice 6 had room. Recorded in plan sections 1.4 and 4 (WP6.5). Unscheduled.
139. GSS-TSIG, aging, the DC locator, GQBL, GlobalNames and netmask ordering (DNS-28 to DNS-33) are Phase 4 with the AD work; the RRset origin field they need exists. Recorded in plan section 1.6. Phase 4.
140. Anycast hooks (OPS-17) are not built; the health endpoint they read exists. Recorded in plan section 1.6. Phase 5.
141. ADR 0017 and ADR 0018 still carry the status Proposed, although the plan was accepted on 2026-10-17 and both are built. Recorded in the WP4.0 and WP6.3 rows. Unscheduled.
142. The data-format fixtures hold 3.42 of the 4 MiB limit; the next format needs a larger limit or compressed fixtures. Recorded in the WP4.0 row. Unscheduled.
143. Documents out of date: `docs/dns-contracts.md` section 7 names the old metric names, `docs/dns.md` section 8 lags on dnstap, the name filter and the kill switch, and `ui/e2e/README.md` has no `dns-log` row. Recorded in the WP5.1 and WP5.4 rows. Unscheduled.
144. The refusal to store the first secret under a PIN-only login (IAM-07, `vault.pin_coupling`) should name the rule and lead to passkey enrolment. Recorded in the backlog. Backlog.

### Found in WP6.5

145. M23 fails by the M9 procedure: 102.46 MiB idle against 95.37 MiB with the M9 data set's 200 prefixes, whose 195 reverse zones the reconciler creates once the first forward zone exists (P2-Q11), plus the ten home zones and a full cache; 94.21 MiB with 20 prefixes and 90.25 MiB without the zones and the cache on the same VM, against 85.31 MiB for the latter in WSL2. Room is to be made before OPS-15 holds with a margin: the start-up peak and the resident code Phase 1 named (its deviation 70 and section 4), and the cost of a reverse zone per managed network. `e21_ops_15_...` in `acceptance_dns_exit.rs` is ignored until then (section 1). Decided on 2026-10-22: the FAIL stands, E21 is not met, and the fix is a follow-up package after the exit closes. Recorded in `bench/phase2-dns/results/2026-10-21-m23-idle-rss.md`. A follow-up package after the exit.
146. M22 fails on the lab: the engine's metrics cost 4.8 percent more server CPU per query over 20 simultaneous pairs at two workers (standard error 2.1 points) and the p99 rose from 3.17 to 3.49 ms in the median, against 1.9 percent and an unchanged p99 at one worker. The candidate cause is two UDP workers on one shard: a family has one shard per CPU and a thread takes its shard round-robin at its first update among every thread of the process (`tenko-core` `metrics::thread_shard`), so workers can share a cache line. A shard per worker taken at the worker's start, then M22 again, is the proposed follow-up; the noise of two VMs on one host is the other half. `e21_ops_21_...` is ignored until then (section 1). Decided on 2026-10-22: the FAIL stands, and the fix is a follow-up package after the exit closes. Recorded in `bench/phase2-dns/results/2026-10-21-m22-metrics-cost.md`. A follow-up package after the exit.
147. `tenko serve` has no switch for the engine's metrics, so M22 measures the engine's example server, which runs the same responder, index and metrics (`docs/dns.md` 12.7; M16 showed the two cost the same per query). Recorded in the M22 results file. Accepted as the method.
148. dnsperf 2.14.0 over DoH stalls with more than two requests in flight on a connection and flamethrower 0.12.0 gets no DoH answer at all, while curl and h2load (100 streams per connection) get every answer from the same listener; which side the two tools disagree with is not known. The DoH figures of M17 come from h2load. Recorded in the M17 results file and `run-flamethrower.sh`. Unscheduled (an HTTP/2 frame trace of one dnsperf connection).
149. flamethrower's TCP and DoT figures are the tool's, not the server's: it opens a connection per burst, and over DoT every answer arrived about 40 ms late (the listener sets `TCP_NODELAY` and writes each answer with its length in one write; dnsperf over DoT answered in 0.11 ms). Its UDP maximum is one thread's. Recorded in the M17 results file. Accepted.
150. The workstation run is limited by WSL2's network path (90,000 QPS with the node under one core busy): WSL2 ran in mirrored mode here, not behind its NAT. A bare-metal client on the LAN is the run that gives a physical-link server figure. Recorded in the M17 results file. Owner (section 6.1).
151. The real link is virtual: both VMs on one Proxmox host and bridge, so they share physical cores, and the CPU model is QEMU's generic virtual CPU; the spread between runs of one configuration (366,000 and 444,000 QPS at four UDP workers) is that sharing. Recorded in the M17 results file. Phase 5 (the cluster labs on separate hosts).
152. For M17 the node's response rate limiting was off (`[dns.limits] rrl = false`) and the per-client TCP and TLS limits raised to 1,000, because one load host would otherwise be limited as one client; M17 measures the engine, not the limiter. Recorded in the M17 results file. Accepted.

Counts per group: engine and role 6, zones and API 3, IPAM link 4, resolver and cache 4, policy and lists 5, TLS transports 7, query log 3, transfers 3, updates 3, DNSSEC 5, views 2, UI 6, deployment 5, measurements 7, other 7, found in WP6.5 8. Total 78 (items 75 to 152).

## 4. Open items carried to Phase 3 and Phase 5

| Item | Goes to | Recorded in |
|---|---|---|
| The node-file feed and the `dns` subset of node sync (declared, consumed by no node) | Phase 5 | plan 1.6 and 2.10; WP4.0 row |
| `Dns.Update` over the cluster channel, with the forwarding of updates for secondary zones to their primary | Phase 5 | plan 2.4 and 2.10; WP6.2 row |
| Per-node zone selection (a `dns` node serving a subset of the zones) | Phase 5, with OPS-27 | plan 1.6 |
| A `dns` node without a controller; the per-node status through node commands | Phase 5 | plan 2.10 |
| The two-host and three-process DNS labs, and every measurement that needs more than one Tenko node (M21 on a cluster as the comparison with the single-node figure) | Phase 5 | plan 2.10; M21 row |
| The Phase 1 VM items: E9 on three VMs, M2 power cut, M4 catch-up (the 6 M RRset data set now exists: `zonegen` of `bench/phase2-dns`, M18), M7, the final M1, M3 and M12 | Phase 5, with the cluster work | phase-1-exit deviation 74; plan P2-Q15 |
| ACME for the API, DoT and DoH certificates (P2-Q8) | Phase 5 | plan P2-Q8; deviation 97 |
| DoQ (DNS-16) | Phase 5 | plan 1.6; deviation 98 |
| Own resolver: iterative resolution, DNSSEC validation, QNAME minimisation and aggressive cache (DNS-03, DNS-13, DNS-34; owner backlog "full recursion") | Phase 5 | ADR 0007; plan 1.6; backlog |
| Anycast hooks (OPS-17) | Phase 5 | plan 1.6 |
| Signed releases and SBOM (API-19), a code-signing certificate, an Ansible role over the installer | Phase 5 | WP6.7 row and deployment notes; phase-1-exit section 4 |
| DDNS from DHCP (DHCP-13), on the update path of plan 2.4 | Phase 3 | plan 1.6; deviation 112 |
| SSID writes (CONN-18) and DHCP relay verification on UniFi | Phase 3, with the DHCP work | plan P2-Q13; phase-1-exit section 4 |
| DHCP on one node first; failover pairs and relay across nodes with the cluster work | Phase 3 (one node), Phase 5 (cluster) | plan 2.10 |
| DHCP tiles on the dashboard and samples from probes | Phase 3 | WP5.6 row; phase-1-exit deviation 29 |
| Raw-socket scanner methods; DHCP snooping with Tenko DHCP | A side package when the quota allows; snooping in Phase 3 | plan P2-Q13; phase-1-exit section 4 |
| Webhook ingress route `POST /connectors/{id}/webhook` | With its first webhook source | plan P2-Q13 |
| GSS-TSIG, aging and the AD DNS features (DNS-28 to DNS-33) | Phase 4 | plan 1.6; deviation 139 |
| Upstream round-trip times and health shown in the status, the forwarders page and the CLI | Backlog | backlog; deviation 89 |
| A home blocking view: statistics per list, client and time, allow-from-the-log, a pause switch, client groups, ABP and regex rules | Backlog | backlog; deviation 96 |
| The reverse-zone template that follows a chosen default zone | Backlog | backlog; deviation 86 |
| The import preview's supernet step for networks under an existing network prefix | Backlog | backlog; deviation 87 |
| The PIN-coupling refusal that names the rule and leads to passkey enrolment | Backlog | backlog; deviation 144 |
| The `App.test.tsx` DNS deep-link test that fails under load | Backlog | backlog; deviation 125 |
| The SPF, DKIM and DMARC wizard (DNS-25) | Unscheduled | plan 1.4; deviation 138 |
| The index built from the store's pages, an incremental base or a bulk build for imports, a longer upload timeout, and M18 at 6 M on the jemalloc binary | Unscheduled | WP4.3 row; deviations 77, 78, 82 and 134 |
| DNSSEC: the signing metrics, an algorithm rollover, RRSIGs in the additional section, NXDOMAIN for an NSEC3 owner name | Unscheduled | WP6.3 row; deviations 113 to 116 |
| Shared transfer state and `dns.transfer` events; a CLI that creates secondary zones; the zone-scope editor and flag | Unscheduled | WP6.1 and WP6.4 rows; deviations 83, 107 and 118 |
| The M24 run on Linux musl and the remaining M20 cases on the jemalloc binary | Unscheduled | deviations 136 and 137 |
| ADR 0017 and 0018 moved from Proposed; the stale documents of deviation 143 | Unscheduled | deviations 141 and 143 |
| E21: room under OPS-15 with the DNS module (M23) and a shard per UDP worker for the metrics (M22), then M22 and M23 again | A follow-up package after the Phase 2 exit closes (decided 2026-10-22) | deviations 145 and 146 |
| A DoH trace of one dnsperf connection (dnsperf and flamethrower against the DoH listener) | Unscheduled | deviation 148 |
| The Windows DNS half of E15, the cut-over of E14, a bare-metal client run for E13 and the installer runs on real hosts | Owner | section 6 |

## 5. ROADMAP "Done when"

`- [x]` is met, `- [ ]` is not yet. A line is checked only when its criterion is met or met with deviation. The first four lines are the ROADMAP's; the others are the criteria the plan adds to them (section 1.2).

- [x] dnsperf numbers are documented. E13. Loopback numbers for the `dns` role (M16) and real-link numbers from another VM and from the workstation over UDP, TCP, DoT and DoH (M17), with and without metrics (M22).
- [ ] A home network sends all of its queries through Tenko. E14. Waiting for the owner; the forwarder, cache, DoT upstream, block lists and the runbook are built and tested.
- [ ] BIND as secondary receives Tenko's zones, and the reverse direction works too. E15. The BIND halves pass in the lab and in `acceptance_dns_xfr.rs`; the criterion also holds the Windows DNS half, which waits for the owner.
- [x] Fuzz targets for wire format, zone file and TSIG run in CI. E16. `dns_codec`, `dns_zonefile` and `dns_tsig` are in the weekly fuzz smoke with three more `dns_*` targets.
- [x] The IPAM addresses with DNS names have their records, reverse zones including RFC 2317 exist, and the move job's DNS step is automatic. E17. `acceptance_move.rs` and `acceptance_reverse.rs`; the live five-device lab is the Phase 1 step E8.
- [x] A TSIG-signed RFC 2136 update is applied through the store, refused outside the policy, and answered SERVFAIL when the store refuses. E18. `acceptance_dns_update.rs`, the lab's `nsupdate` round and M21.
- [x] A zone signed by Tenko validates, a ZSK rollover completes, CDS and CDNSKEY are published. E19. `acceptance_dnssec.rs` with `delv` and `dnssec-verify`; M20.
- [x] DoT and DoH are served with the certificate of the TLS mode; RRL, minimal ANY and split TXT hold. E20. Met with deviation: `kdig` was not installed (deviation 99).
- [ ] Idle RSS below 100 MB with every role and `dns`, and metrics cost below 2 percent. E21. Not met: M23 102.46 MiB by the M9 procedure (94.21 MiB at home size) and M22 +4.8 percent at two workers (deviations 145 and 146).

## 6. What the owner runs

Placeholders: `<host-name>` is the name clients use for the controller, `<admin>` an administrator login, `<ctid>` a Proxmox container ID, `<version>` a release version, `192.0.2.10` the node, `192.0.2.20` the load generator and `192.0.2.30` the workstation in section 6.1, `example.test` a zone. Nothing here needs a secret typed into a chat: passwords and tokens go in at the prompt of the command that asks, or into the owner's `.env`.

Where a command does not exist, the row says so. Nothing is invented. Commands copied from [deploy/README.md](../../deploy/README.md), [deploy/proxmox/README.md](../../deploy/proxmox/README.md) and [deploy/windows/README.md](../../deploy/windows/README.md) keep the version numbers those files use in their examples (0.2.0, 0.3.0); replace them with the version of the build under test (deviation 130).

### 6.1 E13, E21 (M17, M22, M23): the real-link runs

Inputs: three hosts: the node (`192.0.2.10`), the load generator (`192.0.2.20`, dnsperf and flamethrower installed) and the workstation (`192.0.2.30`), reaching each other by ssh without a password; the static musl `tenko` binary (`cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl`), the `phase2-dns` harness and a `phase2-dns zonegen --records 100000` directory.
Commands: `bench/phase2-dns/scripts/run-m17-remote.sh` drives M17, M22 and M23 in phases (`prepare`, `dnsperf`, `tls`, `flame`, `harness`, `workstation`, `metrics`, `m23`, `stop`, `report`); its header lists the options and the usage line (`--node`, `--node-addr`, `--load`, `--load-addr`, `--server-binary`, `--harness`, `--data`). Read that header and the procedure sections of the M17, M22 and M23 results files for the invocations that were used (they ran on 2026-10-21 on two lab VMs; what is left for the owner is a bare-metal client on the LAN and, if wanted, two hosts that do not share cores); the script runs its own instance of Tenko from the ssh user's home directory and never touches an installed service on the node. `bench/phase2-dns/README.md` describes the scripts `run-dnsperf.sh` and `run-flamethrower.sh`; neither tool is installed by the repository.
Pass: M17 documented, M22 below 2 percent with p99 unchanged, M23 below 95.37 MiB.

### 6.2 E14: the home cut-over

Inputs: the cut-over day; permission to change DHCP option 6 and RDNSS on the existing DHCP server (reversible); the upstreams the home uses (P2-Q5); the domain controllers' addresses for the AD zone; a block list URL. A node running the roles `controller,dns` with the home zones.
Commands: the runbook is [dns-resolver.md](../dns-resolver.md) section 9 ("The home cut-over"): before the day, the check from one client, the DHCP change with option 6 and RDNSS and the lease timing, the first hour, the rollback, and verification rows with their commands and expected answers. Placeholders in the runbook are `192.0.2.53` for the node and `192.0.2.1` for today's resolver. Nothing in the network changes until the DHCP server hands out the node's address; the rollback is the same setting set back, with the old resolver still running.
Pass: the verification rows of the runbook; every client resolves through the node; the AD zone is forwarded to the domain controllers; a listed name is blocked.

### 6.3 E15: the Windows DNS half

Inputs: a domain controller that holds one AD-integrated zone (`ad.example.test` in the document), permission to allow the transfer of that one zone to the node's address and to nothing else (read only, revocable), TCP 53 from the node to the controller and UDP 53 from the controller to the node.
Commands: the checklist is [dns.md](../dns.md) section 10.13. On the domain controller, in PowerShell (`<node-address>` is the Tenko node):

```
Set-DnsServerPrimaryZone -Name ad.example.test `
  -SecureSecondaries TransferToSecureServers -SecondaryServers <node-address> `
  -Notify NotifyServers -NotifyServers <node-address>
```

On the node: create the zone as kind "secondary" in the UI (DNS, Zones, new zone) with the controller as primary, or `POST /api/v1/dns/zones` (body in the section). Check with `tenko dns transfer status ad.example.test`, `dig @<node-address> dc1.ad.example.test A`, the two SOA serials, and a test record added on the controller; `tenko dns transfer now ad.example.test` forces the transfer. To revoke, remove the node from the zone's transfer and notify lists on the controller and delete the secondary zone in Tenko.
Pass: a serial and a `last_success` in the transfer status, no `last_error`, equal SOA serials, the test record on the node. Windows DNS transfers without TSIG; the access rests on the address lists.

### 6.4 E8 and E17: the five-device lab with the DNS step automatic

Inputs: the explicit go; the five-device lab of the ROADMAP Verification table (one wireless, one `static`, the rest `reserved`); a target prefix on a VLAN that exists on the controller; the devices' names under zones that Tenko serves (otherwise the DNS step stays manual).
Commands: no CLI and no script, as in [phase-1-exit.md](phase-1-exit.md) section 6.7: drag in the IPAM tree or press M; `POST /api/v1/moves?dry_run=true` previews (the DNS step shows the preview kind `dns.records`), `POST /api/v1/moves` with `expect_fingerprint` submits ([moves.md](../moves.md)).
Pass: the `static` device stops at its manual step; a blocked observation rolls back and puts the records back; the uplink and the management port are refused; the others are seen at their new address, and their A, AAAA and PTR records follow without a manual task.

### 6.5 Install on a Proxmox VE host

Inputs: a Proxmox VE host, a root shell on it, a copy of the repository on the host (or the one-command form with a token), the Tenko binary on the host while the repository is private.
Commands, from [deploy/README.md](../../deploy/README.md), "A Proxmox VE host", and [deploy/proxmox/README.md](../../deploy/proxmox/README.md), "The Tenko container":

```
bash deploy/proxmox/ct/tenko.sh --binary /root/tenko-0.2.0-linux-x86_64
```

The unattended form, with a static address and first-run setup:

```
read -rs TENKO_ADMIN_PASSWORD && export TENKO_ADMIN_PASSWORD     # type the PIN
bash deploy/proxmox/ct/tenko.sh --yes --binary /root/tenko-0.2.0-linux-x86_64 \
  --ip 192.0.2.60/24 --gw 192.0.2.1 --admin admin --storage local-lvm
```

An upgrade is `--update <ctid>`; snapshot the container first with `pct snapshot <ctid> <name>`. The last lines on the host are the container ID, its address, the URL and the setup token.
Pass: the container exists, `tenko health` in it reports ready, the web UI answers on 8443, port 53 answers from the container's address, and the sealed key or the plain key file is what the installer said. Report the first real run of an unprivileged LXC (deviation 126).

### 6.6 Install on a Linux machine or with Docker

Inputs: a VM or server with Debian 12, Ubuntu 24.04 or a RHEL 9 compatible system (x86_64, systemd), a root shell, the binary.
Commands, from [deploy/README.md](../../deploy/README.md), "Install in one command":

```
bash install.sh --binary ./tenko-0.2.0-linux-x86_64
```

Unattended:

```
printf '%s\n' "$ADMIN_PIN" | bash install.sh --yes --binary ./tenko-0.2.0-linux-x86_64 \
  --roles controller,dns --host-name tenko.example.test --forwarders 192.0.2.1,192.0.2.2 \
  --admin admin --password-stdin
```

Docker, in an empty directory, with the published image:

```
echo "$GHCR_TOKEN" | docker login ghcr.io -u <github user> --password-stdin   # while private
cp <checkout>/deploy/compose/quickstart.example.yml compose.yml
echo TENKO_VERSION=0.2.0 > .env
umask 077 && mkdir -p secrets && openssl rand -hex 32 > secrets/tenko_kek
sudo chown 65532:65532 secrets/tenko_kek && chmod 0400 secrets/tenko_kek
docker compose up -d
docker compose exec tenko tenko setup token
```

The same installer command run again with a newer binary is the upgrade; `bash install.sh --uninstall` removes the service and keeps the data, `--uninstall --purge` removes the data too. Keep an offline copy of the key-encryption key.
Pass: the node is ready, the setup works in the browser or with `--admin`, a rerun with the same version changes nothing, a rerun with a newer one upgrades.

### 6.7 Install on Windows with the MSI

Inputs: an elevated prompt on a Windows machine, the MSI `tenko-<version>-windows-x86_64.msi` (unsigned; SmartScreen shows a notice, [windows/README.md](../../deploy/windows/README.md) explains `Unblock-File` and the checksum check).
Commands, from [deploy/windows/README.md](../../deploy/windows/README.md), "MSI installer":

```
msiexec /i tenko-0.2.0-windows-x86_64.msi /qn /l*v tenko-install.log TENKO_ROLES=controller,dns TENKO_PROFILE=home TENKO_HOSTNAME=ddi.example.test TENKO_DNS_ADDRESS=192.0.2.53 TENKO_DNS_PORT=53 TENKO_DATA_DIR=C:\ProgramData\Tenko\data TENKO_START=1 TENKO_FIREWALL=1
```

The wizard is a double-click on the MSI. The upgrade runs the MSI of the new release the same way (`msiexec /i tenko-0.3.0-windows-x86_64.msi /qn /l*v tenko-upgrade.log`). Removal:

```
msiexec /x tenko-0.2.0-windows-x86_64.msi /qn
msiexec /x tenko-0.2.0-windows-x86_64.msi /qn TENKO_PURGE=1
```

The installer for real, on a throw-away VM without Tenko, in an elevated PowerShell 7 (`msi-smoke.ps1` installs, upgrades, uninstalls and purges; it refuses to run where Tenko exists):

```
pwsh -File deploy\windows\build-msi.ps1 -Binary target\release\tenko.exe -Version 0.2.0 -Out dist
pwsh -File deploy\windows\build-msi.ps1 -Binary target\release\tenko.exe -Version 0.2.0 -MsiVersion 0.2.1 -Out upgrade-test
pwsh -File deploy\windows\msi-smoke.ps1 -Msi dist\tenko-0.2.0-windows-x86_64.msi -UpgradeMsi upgrade-test\tenko-0.2.0-windows-x86_64.msi
```

There is no property for an administrator or a password; setup finishes in the browser with the setup token (`setup-token.cmd` in the install folder prints it).
Pass: `msiexec` returns 0; the service `tenko` runs; the setup token works; the upgrade keeps the configuration and the data; every step of `msi-smoke.ps1` prints `==>` and the script ends without a failure. Report the first real install (deviation 127).

### 6.8 The production fresh start

Inputs: clean machines (Linux, Proxmox or Windows), the release assets, the decision that the throw-away labs are not carried over (owner's decision of 2026-10-19).
Commands: there is no separate command or document for a production start. One node is one command of sections 6.5 to 6.7, run on the clean machine. A further controller joins with `tenko cluster join` ([cluster.md](../cluster.md) section 12.1; the command is shown in [phase-1-exit.md](phase-1-exit.md) section 6.8), and an Ansible role over the installer's unattended mode waits for Phase 5 (deviation 129). Carrying data over from a lab is not described; backup and restore ([backup.md](../backup.md), `tenko backup restore`) is the mechanism that exists.
Pass: each machine reports ready after its one command; the setup completes; upgrade by rerunning the same command works.

### 6.9 E20, optional: `kdig` against DoT and DoH

Inputs: `kdig` (from Knot DNS) on the `PATH` of the machine that runs the test.
Commands: no script. `crates/tenko/tests/acceptance_dns_tls.rs` asks `kdig +tls` and `kdig +https` as well when `kdig` is on the `PATH`: `cargo nextest run -p tenko --test acceptance_dns_tls --no-capture`.
Pass: the test passes and prints the `kdig` answers; the status of E20 then loses its deviation.

### 6.10 Phase 1 steps that still wait

The owner steps of [phase-1-exit.md](phase-1-exit.md) section 6 are unchanged: E2 (hardware key, platform authenticator, three TLS modes), E4 (probes in four segments), E5 to E7 (live connectors and the VLAN write), E8 (the lab against the live controller, section 6.4 here), E10 (the smokes on the owner's machines) and M9, M8 on the final build. The VM items of deviation 74 of that document are Phase 5 (section 4).

## 7. Test totals

The final-build column is filled by the lead after the last gate on the squashed commit. "Last recorded" is the newest Windows gate with a figure in [phase-2-status.md](phase-2-status.md); later packages (WP6.3, WP6.2, WP6.7, the tiles fix) passed their gates without a recorded count.

| Item | Last recorded | Final build |
|---|---|---|
| Workspace tests (nextest, `--all-features --locked`) | 4,682 (gate of WP6.1, `159c3f1`) | 4,808 passed, 28 skipped (the gate of `f20aaf4`; the WP6.5 squash adds 4 tests, 2 ignored) |
| Cluster lab acceptance (`--run-ignored all`) | passed in each gate; no count recorded | 2 passed |
| UI tests | 4,042 (WP6.1) | 4,087 |
| Playwright scenarios | 197 (WP6.1) | 203 |
| First-load bundle, gzip | 72.5 KB (WP6.4; unchanged by the tiles fix `8499c75`) | 72.5 KB |
| Fuzz targets (`fuzz/fuzz_targets`) | 26: the 20 of Phase 1 and `dns_codec`, `dns_edns`, `dns_lists`, `dns_tls_wire`, `dns_tsig`, `dns_zonefile`; the weekly smoke runs each for 60 s | 30: the 26 above plus `dhcp_v4` (WP7.1a) and `scan_arp`, `scan_lldp_cdp`, `scan_dhcp_snoop` (WP3.14) |
| Acceptance files of Phase 2 | `acceptance_dns.rs`, `acceptance_dns_tls.rs`, `acceptance_dns_xfr.rs`, `acceptance_dns_update.rs`, `acceptance_dns_views.rs`, `acceptance_dnssec.rs`, `acceptance_reverse.rs`, `acceptance_move.rs` (E17), `acceptance_dns_exit.rs` (WP6.5) | every acceptance file green in the gate of the squash (4,810 workspace tests passed, 30 skipped: the two ignored E21 tests among them; the two cluster lab acceptance tests passed) |
| Requirement trace | `scripts/requirement-trace.mjs` regenerates `phase-1-trace.md` and `phase-2-trace.md`; 160 script tests (WP4.0) | current for phases 1 and 2 at the squash; 165 script tests |
| Other checks | fmt, workspace clippy with `-D warnings`, `cargo check --locked` of `fuzz/`, the OpenAPI document byte-identical, UI typecheck, lint and build, the changelog check, `cargo deny check` (the zip advisories RUSTSEC-2026-0367 to 0369 are ignored in `deny.toml` with the reason) | all green in the gate of the squash on 2026-10-22 (4,087 UI tests, 203 Playwright scenarios, fmt, clippy, deny, the fuzz check, the OpenAPI document identical, the changelog check, the trace check for phases 1 and 2) |
