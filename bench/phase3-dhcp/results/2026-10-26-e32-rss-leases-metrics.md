# E32 on the workstation: idle RSS with every role, the memory of 100,000 leases and the metrics cost on the DORA path (Windows release, one node)

Verdict: FAIL (Windows release: M34 idles at 110.41 MiB with every role and the three home scopes with 200 leases against 95.37 MiB, M30 holds 95.35 MiB for the table of 100,000 leases against 50 MiB; M33 cannot run by the plan's method, its isolated stand-in is 0.6 percent; the musl figures are left for the lab)

E32 of `docs/plans/phase-3-plan.md` (section 1.2) asks for the idle RSS below 100 MB with every role including `dhcp` serving the home scopes on the musl binary (M34, OPS-15), the metrics overhead on the DORA path below 2 percent (M33, OPS-21) and the memory of 100,000 leases measured (M30, OPS-15: below 50 MiB for the role's lease table and indexes, the store's share documented). This file holds the parts that need no lab VM: every figure is from the Windows release build on the workstation and is labelled so; the criterion names the static musl binary, whose figures are the lab's (section "Left for the lab"). Every figure is a single-node figure (plan section 2.12).

Machine: Intel Core i9-13900K (24 cores, 32 threads), 63.7 GiB RAM, Windows 11 Enterprise 10.0.26300; rustc 1.99.0. Build: `main` at `116cabc9` (version 0.0.7) with the WP9.5 branch, whose changes to the code are tests and the example's `--subnet` option only; `cargo build -p tenko --release --locked` with the web UI embedded (the release profile with fat LTO, 147.4 MiB), `cargo build -p tenko-dhcp --release --locked --example dhcp_server`, the test binaries with `cargo test --release --locked -p tenko-dhcp --no-run`. The data directories on a local SSD (`F:`).

## Summary

| Measurement | Threshold | Figure | Verdict |
|---|---|---|---|
| M30 memory of 100,000 leases (Windows release) | Below 50 MiB for the role's table and indexes; the store's share documented | The table and its client index: 95.35 MiB working set, 97.04 MiB private; the store with the 100,000 rows after a restart and a full scan: 33.29 MiB working set | FAIL |
| M33 metrics cost on the DORA path (Windows release, stand-in) | Below 2 percent, p99 unchanged, by M26 with the metrics on and off | Not measurable by the plan's method: no switch turns the DHCP metrics off. In isolation the metrics work of one DORA exchange costs 170 ns (27.5 ns without the clock reads) against 27 µs of server CPU per exchange of the engine alone at 5,000 per second: 0.6 percent (0.1 percent) | Not measured (stand-in 0.6 percent) |
| M34 idle RSS with every role, Windows release | Below 100 MB (95.37 MiB) | 110.41 MiB at most over 600 s idle (roles controller, dns, dhcp, probe; three scopes, 200 leases); 112.96 MiB with the M9 data set of 200 prefixes in addition | FAIL |
| M34 idle RSS with every role, musl | Below 100 MB (95.37 MiB) on the static musl binary | Not run here (the lab VM) | Left for the lab |

## M34: idle RSS with every role

### Procedure

`bench/phase3-dhcp/scripts/m34-idle-rss.ps1`, the M9 procedure of `bench/phase1-server/m9-idle-rss.ps1` with the roles `controller,dns,dhcp,probe`:

1. A fresh node: `tenko serve --roles controller,dns,dhcp,probe --config <file> --stop-on-eof`, the API on `127.0.0.1:18443` (internal CA), the DNS role on `127.0.0.1:15353`, a relay-mode DHCP listener on `127.0.0.1:6767` with replies to relays on `6868`, `[dhcp] workers` 0 (one per CPU, at most 8), HIBP offline, the platform key provider (DPAPI).
2. First-run setup through `POST /api/v1/setup` under the Home profile (conflict detection on; the probe role in the process probes with `ping.exe` on Windows).
3. The three home scopes: the IPAM networks `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`, each with a `dhcp_pool` range `.100` to `.199`, a scope with one-hour leases and the options 3 (`.1`), 6 (`.53`) and 42 (`.123`). With `-Prefixes 200` the M9 data set (one /8 and four /16 supernets, the rest /24 networks) first.
4. 200 leases: the example's load client (`dhcp_server load --subnet <network>`, a relay agent at `127.0.0.1` that selects the scope with option 118) runs 67, 67 and 66 DORA exchanges, eight in flight; `GET /dhcp/leases` lists them.
5. 600 s idle, one sample of the server process every 30 s with `Get-Process` (`WorkingSet64`, `PrivateMemorySize64`), then a graceful stop (exit status 0 in every run).

The six variants ran at the same time on other ports (`-Port`, `-DnsPort`, `-DhcpPort`, `-RelayPort`), each with its own data directory; the machine has memory to spare, so no working set was trimmed. Raw output: `results/raw/m34-windows-20261026-08534*` (not committed).

### Results

| Run | Roles | Data | Ready: working set / private (MiB) | Idle working set min / median / max (MiB) | Idle private max (MiB) | Verdict |
|---|---|---|---|---|---|---|
| a | controller, dns, dhcp, probe | three scopes, 200 leases | 91.40 / 98.94 | 103.94 / 107.28 / **110.41** | 108.05 | FAIL |
| d | controller, dns, dhcp, probe | M9 data set (200 prefixes), three scopes, 199 leases | 90.06 / 97.42 | 106.24 / 109.47 / 112.96 | 110.94 | FAIL |
| g | controller, dns, dhcp, probe, `[dhcp] workers = 1` | three scopes, 199 leases | 90.24 / 97.88 | 100.92 / 104.14 / 107.09 | 105.05 | FAIL |
| e | controller, dns, dhcp, probe | three scopes, no leases | 90.45 / 98.25 | 96.23 / 100.32 / 100.37 | 100.15 | FAIL |
| b | controller, dns, probe (baseline) | none | 65.41 / 48.36 | 68.59 / 72.85 / 72.90 | 50.00 | PASS |
| c | controller (baseline) | none | 58.11 / 21.66 | 61.17 / 65.14 / 65.20 | 24.13 | PASS |

In runs d and g one exchange of the first scope's 67 was lost to the load client's two-second limit (the conflict probe holds a new address up to 300 ms, eight in flight); 199 leases were listed.

Where the memory goes, by difference (idle maxima, working set):

- **The `dhcp` role at start: about 27.5 MiB resident and 50 MiB private** (run e against run b), present at the ready line before any scope exists (run e: private 98.25 MiB at ready against 48.36 MiB in run b). The role allocates its fixed tables at start: the worker pool's pending commits (4,096 slots of a 1,472-octet reply and a `PendingChange` of 1,688 octets, about 12.6 MiB, written at start so resident), the committer's queue (`VecDeque::with_capacity(4096)` of `PendingChange`, about 6.6 MiB committed and untouched), the offer table (65,536 slots), the conflict probe's pending table (1,024 parked requests) and the probe cache. Worker count matters little: one worker instead of eight saves 3.3 MiB (run g against run a). The sizes come from `ServerConfig::default()` (`pending: 4_096`, `offers: 65_536`) and `[dhcp.probe] pending`; none depends on the scopes' size.
- **The three scopes and 200 leases: about 10 MiB** (run a against run e), of which a step of 3.1 MiB at about 330 s into the idle phase in every run with leases and in none without (run a: 107.28 MiB at 316 s, 110.41 MiB at 346 s, flat after): the IPAM reconciler's periodic run (every 300 s) opening discovered-host proposals for the 200 new clients. It is a step, not a growth: the samples after it are flat to the end.
- **The M9 data set: 2.6 MiB** (run d against run a).
- The baselines are near the Phase 1 Windows figures (the controller alone idled at about 73 MiB in `bench/phase1-server/results/2026-10-15-m9-idle-rss.md` with the M9 data set; 65.2 MiB here without it).

The Windows figure is not the criterion's: the musl binary's resident set differs by the allocator (jemalloc) and the code pages, and no musl figure with the `dhcp` role exists yet. The `dhcp` role's fixed tables are allocated and written the same way on both platforms, so their 27.5 MiB are not expected to vanish on musl; with the Phase 2 figure of 89.25 MiB for `controller,probe,dns` without zones on the musl binary (`bench/phase2-dns/results/2026-10-22-m23-idle-rss.md`), the lab run is unlikely to pass without a change. Recorded as an open item in `docs/plans/phase-3-exit.md`: size the pending, queue and offer tables from the configuration (or the pools) instead of fixed defaults, and measure again.

## M30: the memory of 100,000 leases

### Procedure

`bench/phase3-dhcp/scripts/m30-lease-memory.ps1` runs the ignored test `e32_ops_15_the_memory_of_100000_leases_by_stage` of `crates/tenko-dhcp/tests/lease_rebuild.rs` from its release test binary. The test does what the rebuild test of WP7.2 does (100,000 lease rows and their client index rows written to a new Raft store in batches of 1,000, the store closed and opened again, the role's table rebuilt with `rebuild_from_view`), stopping 10 s at each stage; the script reads the test process's working set and private bytes three times a second apart from the middle of each pause and keeps the median. The leases are those of the rebuild test: active one-hour bindings with a client identifier, spread over 400 VRFs of 250 rows each, in one scope.

### Results

| Stage | Working set (MiB) | Private (MiB) |
|---|---:|---:|
| start (the runtime only) | 8.21 | 3.05 |
| store-empty (a new Raft store open) | 10.56 | 4.21 |
| store-filled (100,000 rows written, the store open) | 49.71 | 43.40 |
| store-reopened (closed and opened again) | 18.05 | 11.85 |
| table (the table and its client index rebuilt, the view dropped) | 139.20 | 134.64 |
| table-dropped (the table dropped, the store open) | 43.85 | 37.60 |

| Share | Working set (MiB) | Private (MiB) |
|---|---:|---:|
| **The role's table and its client index** (table less table-dropped) | **95.35** | **97.04** |
| The table against the reopened store (table less store-reopened; includes the store's pages the scan read) | 121.15 | 122.79 |
| The store while it writes 100,000 rows (store-filled less store-empty) | 39.15 | 39.19 |
| The store after a restart and a full scan (table-dropped less store-empty) | 33.29 | 33.39 |

The two earlier runs of the same day gave 95.82 and 97.38 MiB for the table: about 1 KiB per lease. `tenko_core::dhcp::Lease` is 536 octets and the table keeps it inline in a hash map keyed by VRF and address (`LeaseIndex.rows`), whose capacity at 100,000 entries is 131,072 buckets; the client index (`HashMap<Vec<u8>, ClientRows>` per scope) adds a heap allocation per client. That is about twice the threshold. The store's share is documented: about 33 MiB resident after a restart and a scan, 39 MiB while writing. Recorded as an open item in `docs/plans/phase-3-exit.md` (a compact lease row in the table, or the rows boxed with a smaller key map); M30 is to be measured again on the musl binary with jemalloc in the lab, which may differ by the allocator's overhead but not by the layout.

## M33: the metrics cost on the DORA path

**Not measurable by the plan's method.** M33 is M26 with the metrics on and off. `tenko serve` has no setting that turns the `dhcp` role's counters off, and the example server (`crates/tenko-dhcp/examples/dhcp_server.rs`) has none either: the per-worker counters (`WorkerMetrics` in `crates/tenko-dhcp/src/v4/engine/metrics.rs`) are always counted, and the example prints them when it stops. What is missing: a switch (a `--no-metrics` option of the example, or a `[metrics]` setting) that skips the counting, so that `run-loopback.sh` and `run-perfdhcp.sh` can run each rung with and without; or, as in Phase 2's M22, two servers side by side with and without. Phase 2 measured the same way for DNS (deviation 147 of `docs/plans/phase-2-exit.md`).

**The stand-in.** The ignored test `e32_ops_21_the_metrics_of_one_dora_exchange_cost_in_isolation` (`crates/tenko-dhcp/tests/metrics_cost.rs`, release) does the metrics work of one DORA exchange on one thread as the worker and the committer do it: the DISCOVER counted and its time read and recorded, the REQUEST counted, the commit's and the REQUEST-to-ACK time read and recorded. Five rounds of 5,000,000 exchanges: 169.5 to 170.6 ns per exchange (median 170.2), and 27.3 to 27.6 ns (median 27.5) for the counters and histograms alone without the seven clock reads; some of those clock reads serve the probe cap, the DECLINE limit and the status's last commit time as well, so the metrics' own share lies between the two figures.

The CPU of an exchange, from the example server (the engine alone, `--store queue`, one worker) under the example's load client at a paced rate, the server process's CPU time over the run less its idle CPU: 27.0 µs per exchange at 5,000 per second (99,999 exchanges, none lost), 55.2 µs at 1,000 per second and 56.8 µs at 2,000 per second (the lower rates pay the wake-ups between packets). Against the smallest of these, the metrics cost 0.63 percent per exchange with the clock reads and 0.10 percent without; the binary, which commits each lease to the store, spends more CPU per exchange, so its share is smaller. This bounds the cost of the counting; it says nothing about the p99, and it is not M33's figure. The script for the CPU per exchange was a one-off on the workstation (Get-Process's `TotalProcessorTime` of the server around a `dhcp_server load --mode dora --rate <r>` run).

## Left for the lab

- **M34 on the musl binary** (the criterion's figure): `bench/phase1-server/m9-idle-rss.sh` knows the roles `controller`, `probe` and `dns` but writes no `[dhcp]` section and has no hook for the scopes and the leases; the lab run needs that option and a `--before-idle` hook that creates the three scopes through the API and runs the load client (the steps of `m34-idle-rss.ps1`, sections 3 and 4).
- **M30 on the musl binary** with jemalloc: `cargo test --release --locked -p tenko-dhcp --test lease_rebuild --no-run --target x86_64-unknown-linux-musl` and the test with `TENKO_MEMORY_PAUSE_SECS`, reading `/proc/<pid>/status` (`VmRSS`) at each stage.
- **M33 by the plan's method**, once a switch exists: M26 on the lab VMs with the metrics on and off, every rung twice, as for M22 in Phase 2.

## Reproduce

```powershell
cargo build -p tenko --release --locked                      # with ui/dist built
cargo build -p tenko-dhcp --release --locked --example dhcp_server
pwsh -File bench\phase3-dhcp\scripts\m34-idle-rss.ps1 -Binary <target>\release\tenko.exe -LoadClient <target>\release\examples\dhcp_server.exe
pwsh -File bench\phase3-dhcp\scripts\m34-idle-rss.ps1 ... -Roles controller,dns,probe -Port 18453 -DnsPort 15363 -DhcpPort 6777 -RelayPort 6878
cargo test --release --locked -p tenko-dhcp --test lease_rebuild --no-run   # prints the test binary
pwsh -File bench\phase3-dhcp\scripts\m30-lease-memory.ps1 -TestBinary <target>\release\deps\lease_rebuild-<hash>.exe
cargo test --release --locked -p tenko-dhcp --test metrics_cost -- --ignored --nocapture
```
