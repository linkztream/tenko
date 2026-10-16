# Phase 1 exit

- Status: Draft. WP3.8a fills the parts that need no owner input; WP3.8b fills the live parts with the owner.
- Date: 2026-10-16
- Build: `main` at `98e07f1` plus the WP3.8a branch (`wp38a`); the connector, CI and term facts are those of `main` at `9c588c2`. Final commit: the squash of `wp38a` on `main` (`<head>`, filled in at the merge).
- Scope: the exit record of Phase 1. It holds the twelve exit criteria E1 to E12, the measurements M1 to M15, the deviations, the open items carried to Phase 2, the ROADMAP "Done when" list and the commands the owner runs for the live parts. Sources: [ROADMAP.md](../ROADMAP.md) (Phase 1), [phase-1-execution.md](phase-1-execution.md) sections 1.2 and 8, [slice-3-plan.md](slice-3-plan.md) sections 1.1, 3 (WP3.8), 5 and 8, [phase-1-status.md](phase-1-status.md) and the results files under `bench/`.

Contents:

1. [Exit criteria](#1-exit-criteria)
2. [Measurements](#2-measurements)
3. [Deviations](#3-deviations)
4. [Open items carried to Phase 2](#4-open-items-carried-to-phase-2)
5. [ROADMAP "Done when"](#5-roadmap-done-when)
6. [What the owner runs (WP3.8b)](#6-what-the-owner-runs-wp38b)
7. [Test totals](#7-test-totals)

## 1. Exit criteria

Status is one of: met, met with deviation, waiting for the owner, waiting for the VMs. "WP3.8a" marks work done in this package; "WP3.8b" marks what is left for the live run. The tests named for WP3.8a are written in this package; their results are in section 7 once the lead has run them.

| # | Check | Requirements | Status | Evidence | Left for WP3.8b |
|---|---|---|---|---|---|
| E1 | The owner's spreadsheet is imported, loss report empty or acknowledged; its CSV export re-imported into an empty instance previews zero changes | IPAM-11, MIG-14 | Met | `crates/tenko/tests/acceptance_import.rs` (round trip, zero changes); `crates/tenko-ipam/tests/{import_fixture,import_perf}.rs`; `ui/e2e/import.spec.ts`. The real file is never in the repository (API-13); the fixture is its anonymised replica ([import-fixtures.md](import-fixtures.md)) | Optional: import the real file once and acknowledge its loss report (section 6.1) |
| E2 | Passkey login over HTTPS on the configured host name (platform authenticator and hardware key) in each TLS mode of OPS-22; TOTP and PIN preset pass end to end | IAM-03, IAM-06, IAM-09, OPS-22 | Waiting for the owner | Automated: `crates/tenko/tests/acceptance_signin.rs` (PIN, TOTP and a passkey from a software authenticator, in the TLS modes the test can start itself); `ui/e2e/sign-in.spec.ts` (Chromium virtual authenticator); `acceptance_ca_root.rs` (internal CA root and fingerprint) | A hardware key, a platform authenticator, an imported certificate in a browser, and HAProxy in front (section 6.2) |
| E3 | OpenAPI served and committed under `docs/api/`; CI fails on drift | API-01 | Met | `crates/tenko/tests/acceptance_openapi.rs`; `docs/api/openapi.json`; the drift step of the `ui` and embedded-UI CI jobs | Re-run on the final build (section 7) |
| E4 | Three LANs and the DMZ scanned, one probe each; compose lab inventory matches its answer key | SCAN-01 to SCAN-09 | Waiting for the owner | `crates/tenko/tests/{node_scan,node_cluster}.rs`; `crates/tenko-scan` (265 tests at WP2.3); `ui/e2e/{scans,nodes}.spec.ts`; [scanning.md](../scanning.md) | Probes in the four segments (section 6.3). The compose topology with an answer key does not exist in the tree (deviation, scanning) |
| E5 | Proxmox and HASS inventory visible in IPAM | CONN-02 to CONN-04 | Waiting for the owner | `crates/tenko-connect-{proxmox,hass}` (24 and 61 tests, conformance); product run against mocks: 15 host facts, 7 VM-to-host edges, 11 then 21 proposals; `ui/e2e/{connectors,discovery}.spec.ts`. Home Assistant live smoke of 2026-10-16: health Healthy, 106 hosts from 360 devices; its anonymised recording is `crates/tenko-connect-hass/tests/fixtures/recorded.json` (`044cc83`) | The Proxmox ACL, the Proxmox live smoke and recording, both inventories visible in IPAM on the owner's instance (section 6.4) |
| E6 | Topology shows UniFi switches and APs with clients | IPAM-20, CONN-05 | Waiting for the owner | `crates/tenko-connect-unifi/tests/{read,conformance}.rs`; `crates/tenko-ipam/tests/topology.rs`; stand-in controller run: 32 observations, 13 topology nodes, 12 edges. Live reads of 2026-10-16: first with an Integration API key (6 devices, 5 uplinks, 60 clients, reduced topology without ports, networks, port profiles or SSIDs), then with the local view-only account through the classic API (the full read: 122 ports, 9 uplinks, 7 links, 61 clients, 6 networks, 2 port profiles, 1 WLAN); the anonymised recordings are under `crates/tenko-connect-unifi/tests/fixtures/recorded/` with `tests/recorded.rs` (`044cc83`) | The topology map in the UI against the live controller (section 6.5) |
| E7 | A VLAN created in IPAM exists in UniFi after dry run and read-back diff | IPAM-03, CONN-06, CONN-08 | Waiting for the owner | `crates/tenko-connect-unifi/tests/write.rs` (fake controller over pinned TLS); `crates/tenko-ipam/tests/vlan_provision.rs`; [topology.md](../topology.md) section 8 | The live write, only on the owner's explicit go (section 6.6); before it, the two shapes the recordings showed (deviation 44) |
| E8 | IoT device moved by drag and drop with manual DHCP and DNS steps; five-device lab | IPAM-19, CONN-09, CON-10 | Waiting for the owner | `crates/tenko/tests/acceptance_move.rs` (manual steps, cancel and rollback); `crates/tenko-ipam/tests/{moves,move_l2}.rs`; `ui/e2e/move.spec.ts`; [moves.md](../moves.md) | The five-device lab against the live controller, only on the owner's go (section 6.7) |
| E9 | A 3-node cluster loses a controller: writes resume, no committed write lost, SSE clients and probes reconnect | OPS-03, OPS-04 | Waiting for the VMs | `crates/tenko/tests/acceptance_cluster.rs` (E9 on the one-machine lab: three real processes, an SSE client and a probe; no HAProxy); `crates/tenko/tests/cluster_{smoke_grow,failover,partition,membership,observability}.rs`; compose lab `deploy/compose/lab-cluster/smoke.sh` (HAProxy in front, passes in WSL); M3 one host: 20 of 20 runs, writes resumed after 1.59 to 2.00 s ([results](../../bench/phase1-cluster/results/2026-10-15-cluster-lab.md)) | The same on three VMs (section 6.8). `acceptance_partition.rs` covers OPS-26 |
| E10 | Windows service and systemd start, stop, upgrade; Docker with macvlan runs | OPS-10, OPS-13, OPS-14 | Waiting for the owner | `crates/tenko/tests/acceptance_deployment.rs` (the parts that run anywhere); `deploy/windows/smoke.ps1` (owner's run 2026-10-12, all nine steps); `deploy/compose/smoke-macvlan.sh` (second run 2026-10-12 passed, in WSL); `deploy/systemd/smoke.sh` (weekly CI job); `tenko cluster upgrade-check` | Each smoke once on the owner's machines with the final build (section 6.9) |
| E11 | Idle RSS below 100 MB with all Phase 1 roles | OPS-15 | Met with deviation | `crates/tenko/tests/acceptance_observability.rs` (reads M9; its Linux test passes on the 2026-10-16 musl result); M9 Windows 73.70 MiB (2026-10-15); Linux 76.05 MiB on the static musl release binary of the Slice 3 build (2026-10-16, 600 s), the binary that ships for Linux, while the glibc build of the same source, which the M9 procedure builds and the container image ships, fails at 123 to 127 MiB because glibc malloc keeps the start-up peak ([results](../../bench/phase1-server/results/2026-10-16-m9-linux-memory.md)) | M9 on the final build, on the musl binary, on the container image and on a cluster member; the bisect of the rise from about 60 to about 73 MiB; the glibc build under the limit (allocator trim or a smaller start-up peak) |
| E12 | Metrics overhead below 2 percent, p99 unchanged | OPS-21 | Met with deviation | `crates/tenko/tests/acceptance_observability.rs` (reads M8); M8 Windows -0.68 and -0.99 percent, Linux (WSL2) -2.20 and -1.37 percent | M8 on bare-metal Linux once the self-hosted runner can host it |

Other acceptance files of this package, for the Slice 3 areas: `acceptance_access.rs` (scoped views, service account tokens), `acceptance_audit_export.rs`, `acceptance_backup.rs`, `acceptance_languages.rs`. They belong to no single E-row; they close the "acceptance tests for the Slice 3 areas" item of WP3.8.

## 2. Measurements

Thresholds are those of [phase-1-execution.md](phase-1-execution.md) section 8 (M1 to M11) and [slice-3-plan.md](slice-3-plan.md) section 5 (M1 to M15). Numbers are from the newest results file of each measurement. "One host" means the development workstation with all controllers on the loopback and a debug build. "Final build" means the commit named in the header.

| # | Measurement | Threshold | Latest number | Verdict | Results file | Still to run |
|---|---|---|---|---|---|---|
| M1 | Index swap on snapshot install | No empty reads; p99 below 2x baseline | Store bench after WP1.1b: 0 empty reads, p99 1.00x at 1 M and 1.17x at 6 M records. Lab, one host: 0 bad reads, p99 53.0 ms against 42.1 ms (1.26x) | PASS | `bench/phase1-store/results/2026-10-09-windows.md`; `bench/phase1-cluster/results/2026-10-15-cluster-lab.md` | Final run on three VMs; the lab uses IPAM reads, not the 6 M RRset test index |
| M2 | Crash and restart | No lost commit or partial batch; chain verifies | 100 kills (50 bulk, 50 steady) with 0 violations over 34,023 batches; 20 kills with immediate durability and 40 kills during recovery, 0 violations | PASS (kills); power cut not measured | `bench/phase1-store/results/2026-10-09-windows.md` | 10 hard power-offs of the leader VM and 10 of a follower on the VMs; no script exists yet (section 6.10) |
| M3 | Failover | Writes resume within 15 s; no committed write lost | 20 runs at 100 writes/s: resumed after 1.59 / 1.74 / 2.00 s (min / median / max); digests agreed, every committed create present | PASS (one host) | `bench/phase1-cluster/results/2026-10-15-cluster-lab.md` | Final run on three VMs, release build |
| M4 | Network transport | 6 M RRset catch-up below 5 min on 1 Gbit; 1,000 updates/s with p99 below 250 ms | 1,000 writes/s offered: 57 committed per second, p99 7.3 s; 300/s offered: 249 per second, p99 1.9 s. Catch-up of an empty fourth controller: join 17.4 s, no lag 29.3 s after the join began (219.5 MB snapshot) | FAIL on one host (stand-in) | `bench/phase1-cluster/results/2026-10-15-cluster-lab.md` | Three VMs with a release build; the 6 M RRset data set needs the DNS module (section 6.11) |
| M5 | Coalescer ceiling | At least 1,000 updates/s | Deferred durability: 1,000/s achieved, 0 errors, closed loop 6,271/s. Immediate durability: 998/s, closed loop 3,156/s | PASS (store, directly) | `bench/phase1-store/results/2026-10-09-windows.md` | Through a follower; on the musl binary (S3-Q10 falls back to glibc if it drops more than 10 percent); on the final build |
| M6 | Disk growth after re-seed | `sm.redb` below 2x raw | After WP1.1b, at rest: 1.26x (1 M records) and 1.24x (1.5 M). Right after an in-place re-seed the running file measured 2.53x at 1 M. Before WP1.1b: 2.05x and 2.74x. Lab rejoin with an empty data directory: 1.00x | PASS at rest; running figure above 2x (deviation) | `bench/phase1-store/results/2026-10-09-windows.md`; the cluster lab file | Final run on three VMs |
| M7 | UI and SSE on Linux, two hosts, TLS, HTTP/2 | First UI byte within 200 ms after readiness; 10,000 SSE clients per GB of RSS growth (S3-Q12) | Not measured on the full server. Phase 0 baseline: `bench/spike-c-embed/results/2026-10-09-windows.md` | Not measured | none for Phase 1 | The tool of slice-3-plan section 5 is not in `bench/phase1-server` (only the M9 scripts are); build it, then run on two VMs (section 6.12) |
| M8 | Metrics cost | Below 2 percent throughput; p99 unchanged | Windows: -0.68 percent at one worker (5 pairs), -0.99 percent at four (20 pairs), p99 +1.2 and +2.2 percent, about 52 ns per packet. Linux in WSL2: -2.20 percent at one worker (10 pairs), -1.37 percent at four (5 pairs). Zero allocations on update | PASS (Windows); PASS at the limit, accepted by the lead (Linux) | `bench/phase1-metrics/results/2026-10-14-m8.md`; `2026-10-14-m8-linux.md` | Bare-metal Linux; again in Phase 2; final build |
| M9 | Idle RSS | Below 100 MB with all Phase 1 roles | Windows 73.70 MiB (2026-10-15, 200 prefixes, 600 s). Linux 120.89 and 120.73 MiB at most in two runs on `64e337d` (2026-10-16, 200 prefixes, 600 s, WSL2), against 75.09 MiB on 2026-10-09 before Slice 3: +32.3 MiB file-backed (the binary grew from 46.9 to 121.8 MiB), +13.2 MiB anonymous | PASS on Windows, FAIL on Linux | `bench/phase1-server/results/2026-10-15-m9-idle-rss.md`; `2026-10-16-m9-idle-rss.md`; `2026-10-09-m9-idle-rss.md` | Final build on both platforms, the musl binary, a cluster member, the bisect of the rise (section 3, observability) |
| M10 | fsync probe | Warns on SMR, silent on NVMe | NVMe p50 3.7 ms, silent; the SMR drive p50 44.5 ms, warned | PASS | `bench/phase1-store/results/2026-10-09-windows.md` | none |
| M11 | Import speed | 10,000 rows: preview 2 s, apply 5 s | Preview 1.0 to 1.7 s, apply 2.5 to 3.6 s (release, 2026-10-09) | PASS | no results file; `crates/tenko-ipam/tests/import_perf.rs`, WP1.5 row of the status file | Re-run on the final build |
| M12 | Forwarded write latency | Follower p99 at most leader p99 + 20 ms (proposed) | Leader p99 37.1 ms, follower p99 890.7 ms (+853.6 ms) | FAIL (one host) | `bench/phase1-cluster/results/2026-10-15-cluster-lab.md` | Three VMs, release build; the threshold is a proposal and is settled after that run |
| M13 | Scope filtering cost | List of 10,000 hosts within 1.5x unscoped; SSE 100 events/s to 1,000 scoped subscribers below one core | List 1.36x (`MemStore`) and 1.38x (`RaftStore`) at full coverage; SSE end to end 0.88 and 0.95 cores with the anchor cache | PASS (thin margin) | `bench/phase1-rbac/results/2026-10-11-m13-linux.md` | Windows not measured; final build |
| M14 | Backup and restore | 1 M records: create below 2 min; restore and verify below 5 min | Create 9.6 s (live), verify 6.1 s, restore 5.4 s; verify plus restore 11.5 s | PASS | `bench/phase1-backup/results/2026-10-11-m14-linux.md` | Windows not measured; cold cache not measured |
| M15 | Configuration sync | Change reaches a probe within 5 s; bandwidth cap within 10 percent | Median 19.5 ms, max 109.1 ms; cap held at 96.4 to 99.9 percent (burst-corrected) | PASS | `bench/phase1-node-sync/results/2026-10-11-m15-config-sync.md` | Probe on a separate host |

### M12 and M4 on one host

M12: forwarding itself is one call over the cluster port. The follower returns only after it has applied the write (read-your-writes, [cluster.md](../cluster.md) section 12.4), while the leader commits in batches, so the follower's median is three times the leader's and its p99 24 times; the follower also met 87 `ipam.contended` refusals because more writes are in flight at once. M4: the debug build on one machine sustains about 250 API writes per second through one controller, so at 1,000 offered the load met `sys.store.no_quorum` after the store's five seconds and 16,073 writes were not sent. The Spike A figure of 1,000 updates/s is a store-level figure without the API, planner and audit log, and the threshold applies to three hosts with a release build. Neither result is a verdict on the design until that run exists.

### M10 and M11

Both come from Slice 1 and are unchanged. M10 ran on the two disks of the development workstation. M11 is asserted by `import_perf.rs` in release builds.

## 3. Deviations

Grouped by area. "Status" means a row or follow-up paragraph of [phase-1-status.md](phase-1-status.md). Items already closed by a later package are not listed.

### Store and cluster

1. M12 and M4 fail on one host (section 2). Recorded in the cluster lab results file and in the WP3.1c row.
2. M5 through a follower was never measured, and the lab left M5 out. Recorded in the WP3.1a and WP3.1c rows.
3. M1 and M4 in the lab use IPAM data in place of the 6 M RRset test index, and the link is the loopback. Recorded in `bench/phase1-cluster/README.md`.
4. M6 passes at rest and fails on the running figure at 1 M records (2.53x right after an in-place re-seed, because redb doubles a file when it grows). The re-seed rule is stated on the size at start (`state_ratio_at_open`, about 2.0) or on the running figure at about 4.0. Recorded in the store results file and in the conventions of the status file.
5. `max_payload_entries` is 8, not 64: a 64-entry append never completed within openraft's 100 ms heartbeat interval. The lead accepted it as a correctness fix; tuning is a follow-up. Recorded in the WP3.1c row.
6. `ipam.contended` on concurrent creates in one prefix: 57 percent of the lab's writes at 100 per second, which is why the compose load spreads over 20 prefixes. Recorded in the WP3.1c row.
7. `tenko cluster join` against `localhost` spends its 2 s connect budget on `::1` before IPv4. Recorded in the WP3.1c row.
8. The mixed-version rolling upgrade scenario is a skip until `TENKO_OLD_BIN` names an older binary. Recorded in the WP3.1c row.
9. The partition queue holds IPAM changes only: next-free allocations, custom fields, moves, proposals and VLAN provisioning are not queueable. Recorded in the WP3.9 row and [partitions.md](../partitions.md).
10. The browser suite drives the partition banner, the stale item, the queue and the heal against faked cluster routes (`ui/e2e/cluster.spec.ts`, `ui/e2e/support/cluster-mock.ts`), because the browser tests run one controller; the four former `test.fixme` scenarios run that way since WP3.8a. A real three-controller partition is proven at API level only (`cluster_partition.rs`, `acceptance_partition.rs`). Recorded in the WP3.11c and WP3.11d rows and in `ui/e2e/README.md`.
11. The API rate limiter, the login throttle and the reveal rate limit count per controller, not per cluster. Recorded in [cluster.md](../cluster.md) section 12.9 and the WP2.1 follow-up.

### Authorization

12. `password_change_required` is enforced by the UI only; API enforcement was a Slice 2 item and is not recorded as done. Recorded in the Follow-ups list.
13. M13 passes with a thin margin: 1.36x of the 1.5x limit for a list when the grants cover every host, and 0.88 of one core for 1,000 scoped SSE streams. Recorded in the WP3.2 row and the M13 results file.
14. `list_where` checks the cursor after the scope check; moving the cursor first is an optimisation left for the lead. Recorded in the WP3.2 row.
15. The import credential gate checks the importing account, requires `Create` and `Reveal` on secrets, and so only an administrator with a password-or-stronger session imports credentials; a dedicated action is considered when the vault has its own API. Recorded in the Follow-ups list (WP1.5, WP2.1) and the WP3.12b row.
16. Hardened deployments load vendor attestation roots by hand; the FIDO Metadata Service (MDS3) is deferred by S3-Q16. Recorded in the Follow-ups list and slice-3-plan section 7.
17. Viewers keep reading the audit log through the system kind; an installation that wants the trail read by someone who does not see the inventory gives that person the `auditor` role and no other. Recorded in [access.md](../access.md) section 9 and the follow-ups of the wave-2 merges.

### Audit

18. The audit export leaves out client certificates from the internal CA, HTTPS push, and offline verification of RFC 5424 and CEF files (the JSON lines file verifies offline). Recorded in the WP3.3 row.

### Vault and backup

19. Backup: the command is `tenko backup restore` (not `tenko restore`), the schedule is an interval, and parts are uncompressed. Left out: the UI download, old controller records after a re-form, and a self-verify after a write. Recorded in the WP3.4b row.
20. The backup page dropped the manifest preview and the per-backup key choice for want of server data. Recorded in the WP3.11c row.
21. M14 was measured on a Linux virtual machine with a warm cache; Windows and cold caches were not. Recorded in the M14 results file.
22. R15 (KEK directory trust) and R16 (plugin security) are listed as open in the Follow-ups; WP3.4a refuses plain generations once sealed and adds a downgrade alarm, but the list was not updated to say R15 is closed. Recorded in the Follow-ups list and slice-3-plan section 1.2.
23. Zeroization ends at the HTTP response body. Recorded in the WP2.1 follow-up.

### Observability

24. The idle resident set of a fresh single controller rose from about 60 MiB (`e859606`, 60.59 MiB) to about 73 MiB (`a89bafe`, 72.98 MiB) between the WP3.5a squash and the next merge; the WP3.5a squash or the rustls 0.23.46 update is the suspect, and the M9 bisect is pending. It is still 22 MiB under the OPS-15 limit. Recorded in the follow-ups of the WP3.5a merge and the 2026-10-14 and 2026-10-15 M9 files.
25. Linux RSS grows about 14 KiB per prefix (86.4 MiB at 1,000 prefixes), and glibc keeps about 19 MiB of Argon2 buffers after the first login; an allocator trim or a compact index layout is needed before the limit holds at a few thousand prefixes. Recorded in the Follow-ups list and the M9 results file of 2026-10-09.
26. M8 on Linux ran in WSL2, where the one-worker pairs sit at the 2 percent line inside the virtual machine's noise; the lead accepted it. Repeat on bare-metal Linux once the self-hosted runner exists. Recorded in the M8 Linux results file and the WP3.5a row.
27. The trace context is injected into plugin call metadata and exposed by the SDK as a `TraceContext` in the request extensions, but it is not yet passed to the connector trait. Recorded in the WP3.5c row.
28. Traces leave out the Raft service, the node streams and the key-generation exchange; the Linux run of the telemetry tests was not made; an `http://` OTLP endpoint still wants a native certificate store. Recorded in the WP3.5c and WP3.1c rows.
29. The metrics tiles have no DNS or DHCP tiles and no samples from probes themselves; the Linux run of the 100-stream acceptance test is not made. Recorded in the WP3.5b row.

### Deployment

30. M5 and M9 are not measured on the static musl binary; S3-Q10 falls back to glibc if M5 drops more than 10 percent. Recorded in the WP3.6 row.
31. The status file says the systemd-only steps of `smoke.sh` ran nowhere (WP3.6 row), and also that the systemd smoke job was green in CI run 38857682777 on `bc0004a` (2026-10-16). The first end-to-end run of the three smoke scripts in CI is the weekly run. Recorded in the WP3.6 row and the Push state.
32. The UI shows the compatibility cell and the data format panel of the cluster page, and refers to [upgrades.md](../upgrades.md) section 7.7 in plain text for the rolling order; it installs nothing on a cluster (S3-Q14). Recorded in the WP3.6 and WP3.11d rows.
33. A host without .NET's `EventLogMessages.dll` shows Event Log entries without their text (`service install` warns). Recorded in the follow-ups of the WP3.6 merge.
34. The v2 data-directory fixture is 1.4 MB, over the 1 MiB guideline of `docs/upgrades.md` and under the test limit. Recorded in the follow-ups of WP3.0.
35. GitHub-hosted CI minutes ran out on 2026-10-12. The Linux jobs run on the self-hosted runner, the Windows jobs run on the weekly schedule or by hand, and the lead's Windows run in a clean worktree is the merge gate. The first full Linux run on the runner (push run 38859716794) had no result recorded when this was written. Recorded in the Push state.
36. The macvlan smoke ran in a Docker engine inside a WSL distribution, not on a physical segment; a Docker Desktop engine does not see the dummy link. Recorded in the follow-ups of the WP3.6 merge.

### UI

37. Swedish wording of the new placeholders (Granskare, Åtkomst, Granskningsexport, Valv, Säkerhetskopiering, Språk, Kluster, Skanningar, the TGL-21 values) is to be reviewed with the owner. Settled on 2026-10-16: grant, scope and sink stay English words in the Swedish UI (`f786c83`, replacing behörighet, omfång and exportmål). Recorded in the follow-ups of WP3.0, the WP3.11b row and the Push state.
38. Some UI tests assert the Swedish rendering of keys; revisit when language packs are the only source. Recorded in the Follow-ups list.
39. The guardrails page has text fields for device and network identifiers, no picker; a pending data format migration is tested with mocks only. Recorded in the WP3.11d row.
40. The backup stale and failed states have end-to-end cases on faked routes since WP3.8a (`ui/e2e/backup.spec.ts`); the step-up refusal still has component tests only; `DashboardUpdates.test.tsx` is timing-sensitive under load. Recorded in the WP3.11c row.
41. A cancelled move job ends `cancelled`, not `rolled_back`, although its compensation ran; the jobs view should present it as rolled back by cancellation. Recorded in the Follow-ups list.
42. `rawRequest` ignores `ifMatch` on POST (the proposal decisions work around it), `ui/src/api/client.ts` should accept a Blob body, and the `.latest` rethrow pattern of older views should become one guard in `api/live.ts`. Recorded in the Follow-ups list (WP2.9, WP2.10, WP3.0).
43. Several unchanged files under `ui/src/auth/account/` and `ui/src/settings/` are CRLF on disk while the index holds LF; a `.gitattributes` rule for `*.ts` and `*.tsx` would settle it. Recorded in the Follow-ups list (WP2.12).

### Connectors

44. UniFi, live part: the first read of 2026-10-16 used a local Integration API key only and gave a reduced topology (no ports, networks, port profiles or SSIDs; [connectors-unifi.md](../connectors-unifi.md) section 7.2). The same morning the local view-only account existed and the classic API gave the full read; the anonymised recordings exist since `044cc83`. They showed two shapes of Network Application 10.6 the writes must cope with before E7: ports are configured inline without `portconf_id`, and `rest/user` carries no `virtual_network_override_*` members until an override is set; the recorded site also reports every network with DHCP off, because it has no UniFi gateway. E6 in the UI against the live controller is WP3.8b; E7 and E8 wait for the owner's go. Recorded in the UniFi bullet of the Follow-ups list and connectors-unifi.md sections 3 and 13.
45. Proxmox and Home Assistant: the Home Assistant live smoke ran on 2026-10-16 and its anonymised recording exists since `044cc83`; the Proxmox token answers but holds no ACL (needs `PVEAuditor` on `/` for the token and its user), so the Proxmox live smoke, its recording and real proposal counts follow. Recorded in the WP2.5 bullet of the Follow-ups list.
46. No end-to-end host test of the undo refusal (`check_undo` is unit tested); the once-per-interval poll timing is not timed in a test. Recorded in the WP3.12a row.
47. A VLAN provision that asks for DHCP relay stops at the plan on UniFi, because the classic API shows no relay targets to verify. SSID writes (CONN-18) come in Phase 2. Recorded in the Follow-ups list and slice-3-plan section 1.5.
48. The management flag of ports and clients is not shown in the topology port table or the UI. Recorded in the Follow-ups list.
49. No site-to-controller association: a request names the connector, else the only enabled controller. Recorded in the Follow-ups list and slice-3-plan section 1.5 (Phase 5, OPS-27).
50. Move job details: the `move-failed` reason lives in the job error only; the generic `jobs.undo.step` text names the raw step kind; the group checklist does not show the L2 hint; the mock lacks a `controllerFailsWith` option; for a wireless device the preview diff shows the current network while the controller diff shows the previous override. Recorded in the Follow-ups list (WP2.8).
51. Plugin host: no webhook ingress route; network targets are declarations without egress enforcement (R16); one audit record per secret-bearing call; Windows named pipes keep the default DACL. Recorded in the Follow-ups list (WP2.0).
52. Left out of the inventory plugins on purpose: Home Assistant `via_device` parents, IPAM VLAN objects from Proxmox SDN (tags only), firmware and OS facts for Home Assistant devices, an HTTP retry within a call. Recorded in the Follow-ups list (WP2.5).

### Scanning

53. The raw-socket methods (`arp_sweep`, `tcp_syn`, passive `lldp`, `os_fingerprint`) are declared and capability-checked only. S3-Q17 accepted WP3.14 for them; the status file has no WP3.14 row. SCAN-05's CDP and SCAN-03's DHCP snooping do not exist. Recorded in [scanning.md](../scanning.md) section 9 and the Follow-ups list (WP2.3).
54. The TGL-18 text names OS fingerprinting and the full port range, while `os_fingerprint` is declared only and `tcp_connect.ports` takes at most 1,024 ports. Recorded in the Follow-ups list (WP2.3).
55. Scanner quality: mDNS goes out of the default interface only (IPv6 needs an interface index), no ICMP retry for flapping hosts, a batch over 16 MiB fails to queue instead of being split, and an older controller answers `invalid_batch` to methods 9 to 12 of a newer probe. Recorded in the Follow-ups list (WP2.3).
56. The same-process loopback tests of the SNMP fake agent and the TCP and UDP responders cannot run in the WSL instance, so Linux CI is their first Linux run. Recorded in the Follow-ups list (WP2.3).
57. The compose topology with four segments, one probe per segment and an answer key (ROADMAP Verification table, E4) does not exist in the tree; `deploy/compose/lab-cluster/` is the cluster lab. Not recorded elsewhere; found while writing this document.
58. The OUI table holds the full IEEE MA-L registry since 2026-10-10 (the owner approved the download); it is regenerated with `node crates/tenko-scan/data/generate-oui.mjs <oui.csv>` before each release. Recorded in the Follow-ups list (WP2.3).

### Other

59. ACME in Tenko (OPS-22, Should) slips to Phase 2 (S3-Q15). Recorded in slice-3-plan sections 1.2 and 7.
60. `GET /api/v1/openapi.json` serves compact JSON while `docs/api/openapi.json` is pretty-printed; byte equality holds for `tenko openapi` only. Recorded in the Follow-ups list.
61. Uploads to `POST /imports` are sent without `Idempotency-Key`, because the idempotency middleware buffers keyed POSTs under a smaller limit than `max_upload`. Recorded in the Follow-ups list.
62. `JobEngine` staging stays a task-local; the alarm listing endpoint and a `level=` filter on `GET /prefixes` are not built (the UI derives alarms from the tree); `tenko_core::ir` lacks interfaces by name, VRF and tenant names, prefix roles and secret references (Phase 4); the jobs API lacks the current step kind and a job-group filter. Recorded in the Follow-ups list.
63. Reconciler: a per-source VRF and a "learn the MAC" proposal are not built (no overlapping networks in the reference environment); every run reads all intent and facts (fine at home scale); the unused `tenko_core::observe` proposal types can be removed. Recorded in the Follow-ups list (WP2.4) and slice-3-plan section 1.5.
64. Reference-environment housekeeping that blocks builders, not the product: the page file and free space on the build drive, and the size of the WSL disk image (R23). Recorded in the Follow-ups list and slice-3-plan section 8.

### Found in WP3.8a

These came up while the acceptance tests and specs of this package were written. None is fixed here; the lead decides.

65. A session too weak for a role's sign-in requirement gets 403 `auth.step_up_required` on a single read but `200` with no items on a list, and a token with only the `metrics` or `audit:read` scope gets empty lists on `/prefixes` and `/hosts`; [access.md](../access.md) said 403. Settled for the code: a list of a kind the principal reaches nothing of is empty, whatever the reason, which is the convention of every list route of `tenko-api` and of the published OpenAPI descriptions ("empty without permission"), and which section 10 already stated for secrets; single reads, writes and exports carry the refusal. Sections 1, 7, 8 and 10 of access.md now say so, and `acceptance_access.rs` asserts the empty list instead of accepting either.
66. The scoped personal-token dialog on `/account/tokens` was taller than a 720-pixel window and did not scroll (`.dialog.wide` in `ui/src/auth/account/account.css` had no `max-height` or `overflow`), so its Create button was out of reach for the mouse; Enter still submitted. Fixed: the rule now matches the one in `ui/src/settings/settings.css` (`max-height: 84vh; overflow: auto`), and the `test.fixme` in `ui/e2e/tokens.spec.ts` is a running scenario that checks, in a 1280x720 window, that the dialog ends inside the window and that a click on Create creates the token.
67. [audit-export.md](../audit-export.md) section 11 said switching TGL-21 to required without a sink is not refused yet, while `ui/e2e/audit-export.spec.ts` expects 409. The document was stale: the settings service refuses the change with 409 `audit.export.required` (the TGL-21 scenario of `audit-export.spec.ts` proves it). Section 7 of the document now says so and the open item is gone from section 11. `acceptance_audit_export.rs` still adds a sink first.
68. `tenko cluster upgrade-check` on a stand-alone controller showed `-` for the version, majors, Raft wire and formats (only members announce them); [upgrades.md](../upgrades.md) section 5.5 explained `-` only for members joined with an older build. Fixed: the members view of a controller without a member record fills its own row from its binary (`tenko-cluster` `view_local`), so the check shows the real values; the name stays `-` until the first join, which section 5.5 now says. `ops_08_the_cluster_upgrade_check_on_a_single_controller_says_this_binary_fits` in `acceptance_deployment.rs` asserts the row against the line about this binary.
69. [deploy/README.md](../../deploy/README.md) called the systemd smoke the nightly job; `ci.yml` runs it weekly or by hand. Fixed: the README names the job `systemd-smoke` and says it runs on the weekly schedule and by hand; the comments of the cluster lab, Windows service smoke and fuzz smoke jobs in `ci.yml`, which said nightly too, say weekly.
70. The newest Linux M9 result was that of 2026-10-09, before Slice 3; E11 on Linux rested on an older build. Settled by measuring: M9 ran in WSL2 by the documented procedure on `64e337d` (the head of the follow-up branch, which holds all of Slice 3), twice, and fails: idle VmRSS 120.9 and 120.7 MiB at most, 25 MiB over 95.37 MiB ([results](../../bench/phase1-server/results/2026-10-16-m9-idle-rss.md)). 32.3 MiB of the rise since 2026-10-09 are resident pages of the larger binary and 13.2 MiB anonymous memory. E11 is therefore not met on Linux, and `e11_ops_15_the_newest_m9_run_on_linux_passes` in `acceptance_observability.rs` fails on the committed result, as it is meant to. Measured further the same evening ([results](../../bench/phase1-server/results/2026-10-16-m9-linux-memory.md)): the static musl release binary of the same source, the binary that ships for Linux (deviation 30), passes at 76.05 MiB over 600 s, so the newest Linux result is a pass and `e11_ops_15_the_newest_m9_run_on_linux_passes` passes with it; the glibc build, which the M9 procedure builds and the container image ships, fails at 123 to 127 MiB because glibc malloc keeps the 31 MiB start-up peak (parsing the language packs and building the OpenAPI document) and the Argon2 block, and because the binary's resident code grew with `.text` from 28 to 70 MB. No release-profile setting fixes the glibc build (stripping changes nothing, fat LTO saves about 10 MiB); `mallopt` with a 128 KiB mmap threshold plus `malloc_trim` after start-up measured 79.6 MiB. E11 on Linux therefore rests on the musl binary; the glibc container image and the M9 procedure (which should build the musl target) are open items in section 4. M9 on the final build (section 6.13) still applies to both platforms.
71. The acceptance tests on the cluster lab (`acceptance_cluster.rs`, `acceptance_partition.rs`) are ignored as slow and were not in the weekly lab job, which ran `cluster_*.rs` only. Fixed: the `cluster-lab` job of `ci.yml` adds both to its test list and runs them like the `cluster_*.rs` scenarios, ignored tests included; the exit run still runs them with `cargo nextest run -p tenko --test acceptance_cluster --test acceptance_partition --run-ignored all`. The first weekly run after the merge is the proof.
72. Requirements without a test named after them are listed in the generated [phase-1-trace.md](phase-1-trace.md) ("Uncovered"); every one is named by a measurement or a document. No test was invented for them.
73. `tenko-api`'s `one_hundred_streams_get_one_snapshot_per_second_from_one_aggregation` (`crates/tenko-api/tests/metrics_stream.rs`) failed in each of three workspace runs on the workstation with "7 aggregations in 5.0 s" against its limit of 4 to 6, and in a fourth run with the new acceptance binaries left out (the 4,066 tests of `98e07f1`); it passes when run by itself. It is sensitive to load in the full parallel run. Fixed in the test: the counters were read around the CPU readings, and on Windows each CPU reading starts a PowerShell process, which under load can take a second or more, so the counting window was longer than the 5.0 s the test divided by. The counters are now read at the two ends of the measured interval, with the CPU readings outside it, and the aggregations are checked against that interval (one fewer than its whole seconds to one more than its rounded-up seconds, 4 to 6 for 5.0 s as before); every stream must get as many snapshots as there were aggregations, give or take the one in flight. The claim is unchanged: one aggregation per second for 100 streams, not one per stream.

Counts per group: store and cluster 11, authorization 6, audit 1, vault and backup 5, observability 6, deployment 7, UI 7, connectors 9, scanning 6, other 6, found in WP3.8a 9. Total 73.

## 4. Open items carried to Phase 2

| Item | Goes to | Recorded in |
|---|---|---|
| Built-in ACME for the API certificate (OPS-22, Should) | Phase 2 (DNS-01 becomes natural) | slice-3-plan 1.2, S3-Q15 |
| Webhook ingress route `POST /connectors/{id}/webhook` | Phase 2, with the first webhook source | slice-3-plan 1.5 |
| SSID writes (CONN-18 write) and DHCP relay verification on UniFi | Phase 2, and when the vendor API shows relay targets | slice-3-plan 1.5; connectors-unifi.md section 13 |
| M8 again with the DNS engine on the hot path | Phase 2 | phase-1-execution section 8 (M8) |
| The allocator question if M5 drops on musl | Phase 2 | slice-3-plan S3-Q10 |
| DNS and DHCP tiles on the dashboard; samples from probes | Phases 2 and 3 | WP3.5b row |
| UI-orchestrated rolling install on a cluster | Revisit in Phase 2 | slice-3-plan S3-Q14 |
| M2 power cut, M4 at 6 M RRsets, M7 and the final M1, M3, M12 | WP3.8b, and Phase 2 for the 6 M RRset data set (needs the DNS module) | cluster lab results file; cluster.md section 13 |
| Raw-socket scanner methods (SCAN-02 LLDP, SCAN-04 SYN and OS fingerprinting), DHCP snooping, CDP | WP3.14 if scheduled, else Phase 2; snooping with Tenko DHCP in Phase 3 | slice-3-plan S3-Q17 and 1.5; scanning.md section 9 |
| Per-source VRF, "learn the MAC" proposal, Proxmox SDN VLAN objects, Home Assistant `via_device` | Backlog | slice-3-plan 1.5 |
| Alarm listing endpoint and `level=` filter | Backlog | slice-3-plan 1.5 |
| IR extension (interfaces by name, VRF and tenant names, secret references) | Phase 4, with the migration plugins | slice-3-plan 1.5 |
| Plugin egress enforcement and named-pipe DACL (R16, CONN-21) | Phase 5, with the plugin hub | slice-3-plan 1.5 |
| Site-to-controller association | Phase 5, with OPS-27 | slice-3-plan 1.5 |
| Signed releases and SBOM (API-19) | Phase 5 | slice-3-plan 1.5 |
| FIDO Metadata Service (MDS3) for Hardened | Phase 5 (PER-03) | slice-3-plan S3-Q16 |
| Audit export: HTTPS push, client certificates, offline verification of syslog and CEF files | Phase 5 webhooks (API-06) for push; the rest unscheduled | WP3.3 row; slice-3-plan S3-Q6 |
| Backup download from the UI; old controller records after a re-form; self-verify after a write | Unscheduled | WP3.4b row |
| The idle RSS bisect, the allocator trim and the compact index layout | Before the first release | follow-ups of the WP3.5a merge; Follow-ups list (M9 margins) |
| The glibc build under OPS-15 (the container image; allocator trim at start-up, or a smaller start-up peak: the OpenAPI document on request, the language packs parsed on first use) and the M9 procedure building the musl target | Before the first release | deviation 70; 2026-10-16 Linux memory results file |
| Trace context into the connector trait | Unscheduled | WP3.5c row |
| Owner actions that block builders: page file, WSL disk compaction | Owner | slice-3-plan section 8 |

## 5. ROADMAP "Done when"

`- [x]` is met, `- [ ]` is not yet. A line is checked only when its criterion is met or met with deviation.

- [x] The existing IPAM spreadsheet is imported. E1. Proven on the anonymised replica of the file; the real file is imported once in section 6.1 if the owner wants it on record.
- [ ] All four networks (three LANs plus the DMZ) are scanned, with one probe per segment. E4. Waiting for the owner; the scanner, enrolment and on-demand scans are built and tested.
- [ ] Proxmox and Home Assistant inventory is visible in IPAM. E5. Waiting for the owner; proven against mocks.
- [ ] The topology map shows the UniFi switches and APs with connected clients. E6. Waiting for the owner; the full read through the classic API and the anonymised recordings exist; the map in the UI against the live controller is the WP3.8b step.
- [ ] A VLAN created in IPAM exists in UniFi. E7. Waiting for the owner and the explicit go; proven against the fake controller.
- [ ] An IoT device can be moved to a new VLAN by drag and drop, with manual DHCP and DNS steps. E8. Waiting for the owner and the explicit go; the manual flow is proven in `acceptance_move.rs`.
- [ ] A 3-node cluster survives loss of a controller. E9. Met on the lab (20 of 20 kills, no committed write lost); waiting for the VMs.
- [ ] Login with a passkey works. E2. Met with a software authenticator; waiting for the owner for a hardware key, a platform authenticator and the three TLS modes in a real browser.
- [x] The OpenAPI specification is published. E3. `docs/api/openapi.json`, served at `/api/v1/openapi.json`, drift checked in CI.

## 6. What the owner runs (WP3.8b)

Placeholders: `<host-name>` is the name clients use for the controller, `<admin>` an administrator login, `<ca-root.pem>` the CA root file, `<token>` an enrolment token, `<sha256>` a CA fingerprint, `<segment-prefix>` a prefix such as `192.0.2.0/24`, `<unifi-url>`, `<proxmox-url>`, `<hass-url>` the base URLs of those systems. Nothing here needs a secret typed into a chat: credentials go into the vault or the owner's `.env`.

Where a command does not exist yet, the row says so. Nothing is invented.

### 6.1 E1, optional: the real spreadsheet

Inputs: the spreadsheet outside the repository.
Commands: `tenko import <file>` (upload, mapping, preview, apply, wait; `--dry-run` previews only) or the import wizard in the UI; `tenko export prefixes|addresses|hosts` writes the CSV for the round trip. Sources: `crates/tenko/src/client/import.rs` and `export.rs` (no document describes the flags; `tenko import --help` does).
Pass: the loss report is empty or acknowledged; the CSV export imported into an empty instance previews zero changes.

### 6.2 E2: passkey in each TLS mode, hardware key

Inputs: `<host-name>` that resolves for the browser; a hardware security key; a certificate and key in PEM for the imported mode; an HAProxy that ends TLS.
Commands, from [deploy/README.md](../../deploy/README.md) ("TLS", "First-run setup"):

```
tenko setup --url https://<host-name>:8443 --ca-file <ca-root.pem> --admin <admin> --host-name <host-name> --profile standard
tenko ca-root --url https://<host-name>:8443 --fingerprint <sha256> -o <ca-root.pem>
```

The three modes are keys of `tenko.toml` (documented in `deploy/tenko.example.toml`): `[tls] mode = "internal_ca"`; `mode = "imported"` with `cert_path` and `key_path`; `mode = "reverse_proxy"` with `trusted_proxies` and `public_host`. The nearest HAProxy example is `deploy/compose/lab-cluster/haproxy.cfg`; no document gives a single-controller HAProxy recipe.
Then, in each mode, register a passkey with the platform authenticator and with the hardware key and sign in with each. No script exists for these browser steps. Pass: sign-in works over HTTPS on `<host-name>` in all three modes with both authenticators; the relying-party ID is `<host-name>`.

### 6.3 E4: probes in the four segments

Inputs: a host in each of the three LANs and the DMZ, each able to reach the controller on 8443/TCP and 8444/TCP; the prefixes of each segment.
Commands, from [cluster.md](../cluster.md) sections 1.1, 1.2 and 1.5 and [scanning.md](../scanning.md) sections 7 and 12:

```
tenko login --url https://<host-name>:8443 --ca-file <ca-root.pem> --user <admin>
tenko node enrol-token --roles probe --name <probe-name> --expires-in 3600
tenko node enrol --controller https://<host-name>:8443 --token <token> --ca-fingerprint <sha256> --address <probe-address> --data-dir /var/lib/tenko
tenko serve --roles probe --data-dir /var/lib/tenko
tenko node status --check --data-dir /var/lib/tenko
tenko node scan run arp --target <segment-prefix> --dry-run
```

The scope of each probe is `[scan] prefixes` in its `tenko.toml`, or `PUT /api/v1/nodes/{id}/scan-config`; a scan from the controller is `POST /api/v1/scans` or "Scan now" in the UI.
Not available: the compose topology with an answer key for the lab half of E4 does not exist (section 3, scanning). Pass: each segment has a probe that reports; the inventory is checked by hand against the owner's knowledge of the segments.

### 6.4 E5: Proxmox and Home Assistant

Inputs: the Proxmox ACL, a Home Assistant long-lived token, `<proxmox-url>`, `<hass-url>`.
Commands, from [connectors.md](../connectors.md) sections 1.1, 3.2 and 6:

```
pveum user add tenko@pve --comment "Tenko DDI inventory"
pveum user token add tenko@pve inventory --privsep 1
pveum acl modify / --users tenko@pve --roles PVEAuditor
pveum acl modify / --tokens 'tenko@pve!inventory' --roles PVEAuditor
TENKO_LIVE_PROXMOX=1 cargo nextest run -p tenko-connect-proxmox -E 'binary(live)' --no-capture
TENKO_LIVE_HASS=1 cargo nextest run -p tenko-connect-hass -E 'binary(live)' --no-capture
```

The smokes read `PROXMOX_URL`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET`, `HASS_URL`, `HASS_TOKEN` and the optional TLS variables from the environment or the repository's `.env`. The instances are then created with `POST /api/v1/secrets` and `POST /api/v1/connectors` (bodies in connectors.md section 1.1) or on the Connectors page.
Pass: the connectors are healthy; the discovery inbox shows proposals; the hosts of both systems appear in IPAM after approval.

### 6.5 E6: UniFi topology

Inputs: the local view-only account on the controller (it exists since 2026-10-16), `<unifi-url>`, the controller's TLS fingerprint.
Commands, from [connectors-unifi.md](../connectors-unifi.md) sections 7.1, 7.3 and 12:

```
TENKO_LIVE_UNIFI=1 cargo nextest run -p tenko-connect-unifi --run-ignored all live
```

The smoke reads `UNIFI_URL`, `UNIFI_USER` with `UNIFI_PASSWORD` (or `UNIFI_LOCAL_API_KEY`) and optionally `UNIFI_SITE` and `UNIFI_TLS_FINGERPRINT` from `.env`, and writes nothing. Create the instance with `tls = fingerprint`, read the fingerprint from the degraded health detail, compare it with the controller's own display, then set `tls_fingerprint`. The map is `/topology` in the UI and `GET /api/v1/topology`.
Pass: switches and access points with their clients on the map. The read and the anonymised recordings were made on 2026-10-16 (`044cc83`); the recorder in `tests/live.rs` runs again with `TENKO_RECORD=1` ([connectors-unifi.md](../connectors-unifi.md) section 12).

### 6.6 E7: the VLAN write

Inputs: the explicit go; an account with a role that may manage networks; a free VLAN id and name.
Commands: there is no CLI. Use the UI, or `POST /api/v1/vlans/provision?dry_run=true`, read the preview and the read-back diff, then submit the same body without `dry_run` (schemas `VlanProvisionRequest` and `NewVlan` in `docs/api/openapi.json`; behaviour in [topology.md](../topology.md) section 8). The instance needs `writes_enabled` ([connectors-unifi.md](../connectors-unifi.md) section 5.4).
Pass: the network exists on the controller after the job; the verification step shows an empty diff; the job can be rolled back from its receipt.

### 6.7 E8: the IoT move

Inputs: the explicit go; the five-device lab of the ROADMAP Verification table (one wireless, one `static`, the rest `reserved`); a target prefix on a VLAN that exists on the controller.
Commands: no CLI. Drag in the IPAM tree or press M; `POST /api/v1/moves?dry_run=true` previews, `POST /api/v1/moves` with `expect_fingerprint` submits ([moves.md](../moves.md) sections 2 and 4). No script builds the lab or the blocked step 5.
Pass: the `static` device stops at its manual step; a blocked observation rolls back; the uplink and the management port are refused; the others are seen at their new address within the timeout.

### 6.8 E9 on three VMs

Inputs: three Linux VMs (2 vCPU, 4 GB, SSD-backed disks, one network) with the final binary.
Commands, from [cluster.md](../cluster.md) section 12.1. The controller token is created on the Cluster page of the UI or with `POST /api/v1/nodes/enrolments` and `{"roles": ["controller"]}` in a session signed in within the last five minutes; `tenko node enrol-token` cannot do it, because a personal API token is refused with 403 `auth.step_up_required`.

```
# on controllers 2 and 3, with an empty data directory
tenko cluster join --controller https://<host-name>:8443 --token <token> --ca-fingerprint <sha256> --address <controller-address>:8444 --data-dir /var/lib/tenko --config /etc/tenko/tenko.toml
tenko serve --config /etc/tenko/tenko.toml
tenko cluster members
tenko cluster status
tenko cluster verify
```

Kill the leader with `kill -9` while a load runs, then a follower in a separate run. Not available: the 100 writes/s load generator exists only in the Rust harness (`crates/tenko/tests/cluster_support/load.rs`, one machine) and in `deploy/compose/lab-cluster/smoke.sh` (`curl`, one Docker host). A load generator and a driver for three hosts are to be written for this run.
Pass: writes resume within 15 s; `tenko cluster verify` agrees at the load's last revision; SSE clients resume from `Last-Event-ID` or a reset; probes reconnect.

### 6.9 E10: service, systemd, macvlan

Inputs: an elevated PowerShell 7 on the Windows workstation; a systemd test VM; a Docker host with compose and buildx. A debug build of the final commit for the first two.
Commands, from [deploy/README.md](../../deploy/README.md), `deploy/windows/smoke.ps1` and `deploy/compose/smoke-macvlan.sh`:

```
cargo build -p tenko
pwsh -File deploy\windows\smoke.ps1 -Binary .\target\debug\tenko.exe
sudo bash deploy/systemd/smoke.sh target/debug/tenko
bash deploy/compose/smoke-macvlan.sh        # or IMAGE=<tag> to skip the build
```

Never run `smoke.sh` on a production host (it deletes `/var/lib/tenko`). The macvlan script makes a dummy link and removes it.
Pass: every step prints `==>` and the script ends without a failure; the Windows script ends with all nine steps; the systemd score stays below 2.5.

### 6.10 M2: power cut

Inputs: three VMs and access to their power control.
Commands: none exist. The method (slice-3-plan section 5): 10 hard power-offs of the leader VM and 10 of a follower under steady writes; after each restart compare state digests (`tenko cluster verify`) and run `tenko audit verify`. The planned directory `bench/phase1-cluster/power-cut` does not exist. The store-level kill harness (`phase1-store m2` in `bench/phase1-store`) kills a process, not a machine.

### 6.11 M3, M4, M12 and M1 on the VMs

Commands: `bench/phase1-cluster/run.sh` (also `run.ps1`) runs the measurements as `#[ignore]` tests on one machine; its README ([bench/phase1-cluster/README.md](../../bench/phase1-cluster/README.md)) says the final runs belong on three VMs and gives no multi-host mode. Not available: a three-host variant, and the 6 M RRset data set for M4 (needs the DNS module). The Spike A workload (`spike-a-raft load --steady --catch-up`) runs in one process, not over the network.

### 6.12 M7: UI and SSE on two hosts

Commands: none exist. Slice-3-plan section 5 says the Spike C `measure` tool is extended with TLS, HTTP/2, cookie sign-in and `/api/v1/events` in `bench/phase1-server`; that directory holds only the M9 scripts. `bench/spike-c-embed` has the Phase 0 tool without those parts.

### 6.13 M9, M8 and the rest, on the final build

Commands, from [bench/phase1-server/README.md](../../bench/phase1-server/README.md) and the M8 results file:

```
pwsh -NoProfile -File bench\phase1-server\m9-idle-rss.ps1 -Binary <tenko.exe>
bench/phase1-server/m9-idle-rss.sh --binary <tenko>
cargo build --release && target/release/phase1-metrics pairs --listen 127.0.0.2:5399 --workers 1 --out results/raw/m8.jsonl   # in bench/phase1-metrics; 127.0.0.2 is for WSL2, Windows uses 127.0.0.1
```

Bench commands for M13 to M15 are in their results files.

## 7. Test totals

The WP3.8a column holds the runs of 2026-10-16 on the branch `wp38a` (on `98e07f1`), on the Windows workstation. The final-build column is filled by the lead after the last gate on the squashed commit. "Last recorded" is the Windows gate at `615e637`.

| Item | WP3.8a branch | Final build | Last recorded |
|---|---|---|---|
| Workspace tests (nextest, `--all-features --locked`) | 4,107 run: 4,106 passed, 1 failed (deviation 73), 23 skipped | `<workspace tests>` | 4,066 |
| Cluster lab acceptance (`--run-ignored all`) | 2 passed: E9 in 67.2 s, OPS-26 in 37.5 s | `<lab acceptance>` | none |
| UI tests | 3,562 passed in 153 files | `<UI tests>` | 3,562 |
| Playwright scenarios | 160 passed, 1 skipped (deviation 66), three runs in a row without a flake (4.0, 3.9 and 3.7 min) | `<Playwright scenarios>` | 109 |
| First-load bundle, gzip | 71.7 KB | `<first load>` | 71.7 KB |
| Requirement trace | `node scripts/requirement-trace.mjs --check` current; 36 script tests passed | `<trace check>` | none |
| Other checks | fmt, workspace clippy with `-D warnings`, `cargo check` of `fuzz/`, the OpenAPI document byte-identical, UI typecheck, lint and build green; `cargo deny check` fails only on the yanked `zip` 8.x, which `main` handles with `yanked = "warn"` | `<checks>` | none |
