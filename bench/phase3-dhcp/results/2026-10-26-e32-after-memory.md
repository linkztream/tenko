# E32 on the workstation after the memory package: the role's tables sized from the configuration and a compact lease row (Windows release, one node)

Verdict: PASS (Windows release: M34 idles at 87.75 MiB with every role, the three home scopes and 200 leases against 95.37 MiB, M30 holds 20.46 MiB for the table of 100,000 leases against 50 MiB; M33 is unchanged and not measured by its method; the musl figures are left for the lab)

Supersedes: `2026-10-26-e32-rss-leases-metrics.md` (its M30 and M34 rows; its M33 row is carried over unchanged)

E32 of `docs/plans/phase-3-plan.md` (section 1.2) and the open items of deviations 177 and 178 of `docs/plans/phase-3-exit.md`: WP9.5 measured the `dhcp` role at about 27.5 MiB resident before any scope existed (fixed tables of 4,096 pending commits, a committer's queue of 4,096 changes, 65,536 offer slots and the probe's tables) and the role's table of 100,000 leases at about 1 KiB a lease (`2026-10-26-e32-rss-leases-metrics.md`). This package sizes those tables from the configuration image and makes the table's row compact (`docs/dhcp.md` section 10.8); this file holds the same measurements again, by the same scripts, on the same machine and the same day, and the M26 loopback ceiling before and after. Every figure is from the Windows release build and is labelled so; the criterion names the static musl binary, whose figures are the lab's. Every figure is a single-node figure (plan section 2.12).

Machine: Intel Core i9-13900K (24 cores, 32 threads), 63.7 GiB RAM, Windows 11 Enterprise 10.0.26300; rustc 1.99.0. Build: `main` at `116cabc9` (version 0.0.7) with the WP9.5 branch (`c5c6d5ec`) and this package; `cargo build -p tenko --release --locked` with the web UI embedded (147.4 MiB), `cargo build -p tenko-dhcp --release --locked --example dhcp_server`, the test binary with `cargo test --release --locked -p tenko-dhcp --test lease_rebuild --no-run`. "Before" is the WP9.5 build (the M34 figures of `2026-10-26-e32-rss-leases-metrics.md`, and this package's own runs of the example and the test binary built from `c5c6d5ec`). The data directories on a local SSD (`F:`).

## Summary

| Measurement | Threshold | Figure | Verdict |
|---|---|---|---|
| M30 memory of 100,000 leases (Windows release) | Below 50 MiB for the role's table and indexes; the store's share documented | The table and its client index: 20.46 MiB working set, 19.53 MiB private (before: 99.32 MiB in this package's run, 95.35 MiB in WP9.5's); the store with the 100,000 rows after a restart and a full scan: 33.65 MiB working set | PASS |
| M33 metrics cost on the DORA path (Windows release, stand-in) | Below 2 percent, p99 unchanged, by M26 with the metrics on and off | Not measured again: as in `2026-10-26-e32-rss-leases-metrics.md`, no switch turns the DHCP metrics off; the isolated stand-in is 0.6 percent (0.1 percent without the clock reads) | Not measured (stand-in 0.6 percent) |
| M34 idle RSS with every role, Windows release | Below 100 MB (95.37 MiB) | 87.75 MiB at most over 600 s idle (roles controller, dns, dhcp, probe; three scopes, 200 leases); 90.32 MiB with the M9 data set of 200 prefixes in addition (before: 110.41 and 112.96 MiB) | PASS |
| M34 idle RSS with every role, musl | Below 100 MB (95.37 MiB) on the static musl binary | Not run here (the lab VM) | Left for the lab |

## M34: idle RSS with every role

### Procedure

`bench/phase3-dhcp/scripts/m34-idle-rss.ps1` as in `2026-10-26-e32-rss-leases-metrics.md` (section M34): a fresh node with the roles `controller,dns,dhcp,probe`, first-run setup under the Home profile, the three home scopes on the documentation networks (pools `.100` to `.199`, one-hour leases, options 3, 6 and 42), 200 leases from the example's load client, 600 s idle with a sample every 30 s, a graceful stop (exit status 0 in every run). Four variants ran at the same time on other ports, each with its own work directory (`-WorkDir`: two runs started in the same second share the script's default directory, whose name is the start time). Raw output in the run's output directory (not committed).

### Results

| Run | Roles | Data | Ready: working set / private (MiB) | Idle working set min / median / max (MiB) | Idle private max (MiB) | Before: idle max (MiB) | Verdict |
|---|---|---|---|---|---|---|---|
| a | controller, dns, dhcp, probe | three scopes, 200 leases | 68.93 / 52.41 | 81.35 / 84.72 / **87.75** | 61.39 | 110.41 | PASS |
| d | controller, dns, dhcp, probe | M9 data set (200 prefixes), three scopes, 200 leases | 67.45 / 50.66 | 84.02 / 87.28 / 90.32 | 63.95 | 112.96 | PASS |
| e | controller, dns, dhcp, probe | three scopes, no leases | 68.64 / 52.04 | 76.30 / 79.84 / 79.88 | 55.29 | 100.37 | PASS |
| b | controller, dns, probe (baseline) | none | 64.82 / 47.86 | 67.96 / 72.32 / 72.36 | 49.66 | 72.90 | PASS |

Where the memory goes, by difference (idle maxima, working set):

- **The `dhcp` role with the three scopes: 7.52 MiB resident** (run e against run b; before 27.47 MiB), within the 10 MiB this package aimed at. At the ready line, before any scope exists, the role costs 4.1 MiB resident and 4.2 MiB private (run e against run b; before about 26 MiB and 50 MiB). The tables now hold a slot per address the image can lease, 300 for the three scopes, where they held 4,096 pending commits and 65,536 offers: `crates/tenko-dhcp/tests/sizing_alloc.rs` counts 2.84 MiB on the heap for the server's tables with eight workers and the committer's queue on this image (the pending commits about 0.95 MiB, the probe's pending table about 0.9 MiB, the hand-off queue 0.5 MiB, the offer slots 0.2 MiB). The committer's queue of the DHCPv6 store, which has no DHCPv6 scope here, holds the floor of 256 changes, and the DDNS queue starts with room for 1,024 requests instead of 65,536 (both were committed but untouched, so they counted in private bytes, not in the working set).
- **The 200 leases and their traffic: 7.87 MiB** (run a against run e; before 10.04 MiB). It is not the role's table (200 rows of about 200 octets): 3.03 MiB of it is the step at about 330 s into the idle phase that WP9.5 found (the IPAM reconciler's run every 300 s opening discovered-host proposals for the 200 new clients; run a: 84.72 MiB at 300 s, 87.75 MiB at 330 s, flat after), and the rest is what the fill leaves in the process (the store's commits with their observations and history rows, the API's lease listing, the allocator's free memory after the fill's peak of 89.09 MiB).
- **The M9 data set: 2.57 MiB** (run d against run a; before 2.55 MiB).
- The baseline is unchanged within the noise (72.36 against 72.90 MiB).

The Windows figure is not the criterion's: the musl binary's resident set differs by the allocator (jemalloc) and the code pages. With 87.75 MiB on Windows and the Phase 2 figure of 89.25 MiB for `controller,probe,dns` without zones on the musl binary (`bench/phase2-dns/results/2026-10-22-m23-idle-rss.md`), the role's 7.5 MiB and the leases' 7.9 MiB put the musl run near 105 MiB if the two platforms add the same; the lab run decides, and the lab still needs the `[dhcp]` option and the scopes hook of `m9-idle-rss.sh` (section "Left for the lab").

## M30: the memory of 100,000 leases

### Procedure

`bench/phase3-dhcp/scripts/m30-lease-memory.ps1` with the release test binary of `crates/tenko-dhcp/tests/lease_rebuild.rs` (`e32_ops_15_the_memory_of_100000_leases_by_stage`), as in `2026-10-26-e32-rss-leases-metrics.md`: 100,000 active one-hour bindings with a client identifier over 400 VRFs, written to a new Raft store, the store reopened, the role's table rebuilt with `rebuild_from_view`, the working set and private bytes read at each stage. The test binary prints the size of the store's `Lease` (536 octets), which the table no longer keeps.

### Results

| Stage | Working set (MiB) | Private (MiB) | Before: working set (MiB) |
|---|---:|---:|---:|
| start (the runtime only) | 13.76 | 3.11 | 13.75 |
| store-empty | 14.36 | 4.27 | 14.34 |
| store-filled | 61.27 | 52.38 | 59.76 |
| store-reopened | 21.80 | 12.16 | 21.54 |
| table (the table and its client index rebuilt, the view dropped) | 68.47 | 59.11 | 146.92 |
| table-dropped | 48.01 | 39.58 | 47.60 |

| Share | Working set (MiB) | Private (MiB) | Before: working set (MiB) |
|---|---:|---:|---:|
| **The role's table and its client index** (table less table-dropped) | **20.46** | **19.53** | 99.32 |
| The table against the reopened store (includes the store's pages the scan read) | 46.67 | 46.95 | 125.38 |
| The store while it writes 100,000 rows | 46.91 | 48.11 | 45.42 |
| The store after a restart and a full scan | 33.65 | 35.31 | 33.26 |

"Before" is the WP9.5 test binary run by this package an hour earlier (99.32 MiB; WP9.5's own runs gave 95.35, 95.82 and 97.38 MiB). The table now costs about 214 octets a lease all in: the compact row is 88 octets inline in the map by VRF and address (with its key, its control byte and the map's spare buckets, 131,072 at 100,000 rows, about 148 octets a lease), the client index about 43 (a keyed hash of the scope and the identity to the row's key, with its spare buckets), and one boxed byte string per row with the client and the fields the row has (18 octets for these rows, plus the allocator's header). The store's share is unchanged, as it should be: the rows in the store did not change.

### The rows a lease usually gathers

The rows of M30 carry a client and nothing else. `crates/tenko-dhcp/tests/lease_memory.rs` counts the heap the table keeps for 100,000 rows (the bytes asked of the allocator, without its overhead): 20.35 MiB for the rows of M30, the same as the working-set figure above, and 38.81 MiB for rows with what a lease of a relayed client with DDNS gathers (a host name, the forward and reverse names, a 35-octet DHCID and the update time, a fingerprint with 14 parameters and a vendor class, the relay with its option 82, the observation time): about 190 octets more a row in its byte string. Both are below the 50 MiB of M30, and the test fails if either reaches it.

### The rebuild

`a_large_table_rebuilds_from_the_store_in_time` of `lease_rebuild.rs` (release, the same machine, before and after in turns): the rebuild of the table from 100,000 rows took 120 and 120 ms after against 162 and 164 ms before (M32 recorded 170 ms on 2026-10-22); the threshold is 5,000 ms. Encoding the row costs less than the copies of the whole `Lease` it replaced.

## M26 on loopback, before and after

`bench/phase3-dhcp/scripts/run-loopback.sh --workers 4 --stores queue` (the engine's example server over one scope of 198.18.0.0/15 with the example's hash lease table and the queue store; 100,000 clients, window 64), one run of the script before and after, and the M26 line alone three times before and four times after (`dhcp_server serve --workers 4 --store queue` and `dhcp_server load --mode dora --clients 100000 --window 64`). The example's table returns the new `LeaseView` of the trait, and its server's pending commits and offer slots are now sized from its image (131,057 pool addresses: 8,192 pending commits, its configured value, and 131,057 offers instead of 262,144).

| Run | Before | After |
|---|---:|---:|
| M26 4-way closed loop, script | 93,259 /s, p99 0.86 ms | 94,552 /s, p99 0.81 ms |
| M26 alone | 93,193; 93,658; 91,955; 94,295; 93,091 /s | 89,974; 93,659; 94,256; 93,589 /s |
| Median of the M26 runs | 93,259 /s | 93,659 /s |
| M27 renewals, 20 s, script | 97,098 /s, p99 1.28 ms | 103,081 /s, p99 0.79 ms |
| M28 at 1,000/s, script | p99 0.22 ms | p99 0.21 ms |

No exchange was lost and the server dropped nothing in any run. The median moved by +0.4 percent, within the spread of the runs (89,974 to 94,552): the DORA path did not regress. Loopback figures are upper bounds and labelled so.

## Left for the lab

- **M34 on the musl binary** (the criterion's figure): `bench/phase1-server/m9-idle-rss.sh` with a `[dhcp]` section and a hook for the three scopes and the leases, as in `2026-10-26-e32-rss-leases-metrics.md`.
- **M30 on the musl binary** with jemalloc, by the commands of `2026-10-26-e32-rss-leases-metrics.md`.
- **M33 by the plan's method**, once a switch exists.

## Reproduce

```powershell
cargo build -p tenko --release --locked                      # with ui/dist built
cargo build -p tenko-dhcp --release --locked --example dhcp_server
pwsh -File bench\phase3-dhcp\scripts\m34-idle-rss.ps1 -Binary <target>\release\tenko.exe -LoadClient <target>\release\examples\dhcp_server.exe -WorkDir <dir-a>
pwsh -File bench\phase3-dhcp\scripts\m34-idle-rss.ps1 ... -Leases 0 -Port 18463 -DnsPort 15373 -DhcpPort 6787 -RelayPort 6888 -WorkDir <dir-e>
pwsh -File bench\phase3-dhcp\scripts\m34-idle-rss.ps1 ... -Roles controller,dns,probe -Port 18453 -DnsPort 15363 -DhcpPort 6777 -RelayPort 6878 -WorkDir <dir-b>
pwsh -File bench\phase3-dhcp\scripts\m34-idle-rss.ps1 ... -Prefixes 200 -Port 18473 -DnsPort 15383 -DhcpPort 6797 -RelayPort 6898 -WorkDir <dir-d>
cargo test --release --locked -p tenko-dhcp --test lease_rebuild --no-run   # prints the test binary
pwsh -File bench\phase3-dhcp\scripts\m30-lease-memory.ps1 -TestBinary <target>\release\deps\lease_rebuild-<hash>.exe
<target>\release\deps\lease_rebuild-<hash>.exe a_large_table_rebuilds_from_the_store_in_time --exact --nocapture
bash bench/phase3-dhcp/scripts/run-loopback.sh --binary <target>/release/examples/dhcp_server.exe --workers 4 --stores queue
cargo nextest run -p tenko-dhcp --locked --no-capture -E 'binary(lease_memory) | binary(sizing_alloc)'
```
