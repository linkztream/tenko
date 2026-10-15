# Cluster lab measurements on one machine, 2026-10-15 (Windows)

The measurements of WP3.1c on one workstation: three (for M4 and M1 four) `tenko serve`
processes on the loopback, joined with `tenko cluster join`, each link through the lab's TCP
relay (no fault set), the write load through the public API with an `Idempotency-Key` on
every write. They are the one-host runs of the slice 3 plan, section 5; the final runs of
M1, M3, M4 and M12 happen on three VMs in WP3.8. M6 comes from the membership scenario.

## Machine, build and command

- 13th Gen Intel Core i9-13900K, 32 logical CPUs, 63.7 GiB RAM; Windows 11 Enterprise build
  26300; every data directory in `%TEMP%` on the C: SSD.
- Rust 1.99.0, the test profile (debug, `CARGO_PROFILE_DEV_DEBUG=line-tables-only`, no
  release build), `TENKO_UI_STUB=1`; branch `wp31c` at `000c19a` plus the measurement code
  committed in `4d6339c` (the run reported uncommitted changes: those).
- Controllers with four API workers (`[server] workers = 4`), the file KEK, the internal CA,
  `heartbeat_secs = 1`, `isolation_after_ms = 1000`, `catch_up_timeout_secs = 30`, the rate
  limiter off. M4 snapshots by log size (`snapshot_every_entries = 1000`,
  `snapshot_every_log_mib = 2`, `snapshot_keep_entries = 100`), M1 every 500 entries.

```
pwsh -File bench\phase1-cluster\run.ps1 -OutDir bench\phase1-cluster\results\raw\2026-10-15-windows
```

Started 15:51 local time with nothing else running; 34 minutes in all (M3 alone about 20).

## Results

| # | Measurement | Threshold | Result | Verdict |
|---|---|---|---|---|
| M3 | Failover, 20 runs of `kill -9` of the leader at 100 writes/s | Writes resume within 15 s; no committed write lost | Resumed after 1.59 / 1.74 / 2.00 s (min / median / max); digests agreed and every committed create was present after every run | PASS |
| M12 | Forwarded write latency at 100 writes/s, 60 s each | Follower p99 at most leader p99 + 20 ms (proposed) | Leader p99 37.1 ms, follower p99 890.7 ms (+853.6 ms) | FAIL |
| M4 (one host) | 1,000 writes/s for 60 s on the leader | p99 below 250 ms | 57 committed writes/s, p99 7.3 s; 300/s gave 249/s with p99 1.9 s | FAIL (machine and build) |
| M4 (one host) | Catch-up of an empty fourth controller after the load | 6 M RRsets below 5 min on 1 Gbit (WP3.8) | 168.8 MB state, snapshot 216.5 MB: join 17.4 s, no lag 29.3 s after the join began | stand-in only |
| M1 (one host) | Follower reads during a learner's snapshot install | No empty reads; p99 below 2x baseline | 0 bad reads; p99 53.0 ms against 42.1 ms (1.26x) | PASS |
| M6 | State file after a rejoin with an empty data directory | Below 2x raw at rest | 16.8 MB against a raw 16.8 MB (1.00x); the member had 22.0 MB before | PASS |

### M3 failover

| Run | Killed | New leader | Elected (ms) | Writes resumed (ms) | Writes | Refused (503) | Unanswered | p99 (ms) | Digests agree at revision |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1002 | 2024 | 1686 | 703 | 97 | 0 | 2393 | 770 |
| 2 | 1002 | 1 | 2014 | 1664 | 702 | 99 | 0 | 2366 | 1502 |
| 3 | 1 | 1001 | 2014 | 1740 | 702 | 104 | 0 | 2474 | 2228 |
| 4 | 1001 | 1 | 2024 | 1802 | 703 | 111 | 0 | 2390 | 2947 |
| 5 | 1 | 1001 | 2018 | 1842 | 703 | 115 | 0 | 2372 | 3663 |
| 6 | 1001 | 1 | 2018 | 1913 | 703 | 122 | 0 | 2401 | 4369 |
| 7 | 1 | 1001 | 2026 | 1888 | 704 | 119 | 0 | 2389 | 5080 |
| 8 | 1001 | 1 | 2025 | 1801 | 704 | 109 | 0 | 2405 | 5802 |
| 9 | 1 | 1001 | 2021 | 1643 | 703 | 93 | 0 | 2365 | 6544 |
| 10 | 1001 | 1 | 2026 | 1711 | 704 | 99 | 0 | 2374 | 7278 |
| 11 | 1 | 1001 | 2020 | 1938 | 703 | 123 | 0 | 2442 | 7984 |
| 12 | 1001 | 1 | 2023 | 1593 | 703 | 89 | 0 | 2380 | 8731 |
| 13 | 1 | 1001 | 2019 | 1999 | 703 | 129 | 0 | 2384 | 9428 |
| 14 | 1001 | 1 | 2024 | 1986 | 704 | 127 | 0 | 2398 | 10129 |
| 15 | 1 | 1001 | 2023 | 1705 | 703 | 100 | 0 | 2314 | 10860 |
| 16 | 1001 | 1 | 2021 | 1714 | 703 | 102 | 0 | 2377 | 11590 |
| 17 | 1 | 1001 | 2027 | 1864 | 704 | 117 | 0 | 2375 | 12303 |
| 18 | 1001 | 1 | 2021 | 1692 | 702 | 98 | 0 | 2364 | 13038 |
| 19 | 1 | 1001 | 2023 | 1650 | 704 | 96 | 0 | 2372 | 13775 |
| 20 | 1001 | 1002 | 2026 | 1979 | 704 | 130 | 0 | 2398 | 14474 |

Each run: 100 writes/s through a follower, the leader killed after 3 s, the load stopped 2 s
after the first committed write that started after the kill, the digests of the survivors
compared at the load's last committed revision, every committed create read back on every
survivor, the killed controller restarted and the membership complete again before the next
run. "Elected" is when the harness first saw a new leader (it polls every 200 ms); writes
resume before that because the follower that takes the writes forwards them as soon as it
knows the new leader. The refused writes are 503 `sys.store.no_quorum` and
`cluster.no_quorum` in the 2 s without a leader; the write p99 of each run is the failover.

### M12 forwarded write latency

| Load | Writes | Committed | Committed/s | p50 (ms) | p99 (ms) | Max (ms) | Longest stall (ms) | Refused |
|---|---|---|---|---|---|---|---|---|
| leader | 6001 | 6001 | 100.0 | 14.8 | 37.1 | 254.6 | 64 | 0 |
| follower | 6001 | 5914 | 98.6 | 45.2 | 890.7 | 1696.4 | 407 | 87 |

The 87 refusals on the follower are 503 `ipam.contended`: the load changes addresses it
created earlier, and on the follower more writes are in flight at once, so two changes of
one address meet more often. The follower's tail is the finding of this run: its median is
three times the leader's and its p99 is 24 times. Forwarding itself is one call over the
cluster port; the time goes into waiting until the follower has applied the write
(read-your-writes, cluster.md 12.4) while the leader commits in batches. WP3.8 repeats the
run on three hosts with a release build before the threshold, which is a proposal, is
settled.

### M4 on one host

| Load | Writes | Committed | Committed/s | p50 (ms) | p99 (ms) | Max (ms) | Longest stall (ms) | Refused | Not sent |
|---|---|---|---|---|---|---|---|---|---|
| leader, 300/s | 18001 | 14921 | 248.6 | 219.4 | 1919.3 | 6400.5 | 297 | 3080 | 0 |
| leader, 1,000/s | 60001 | 3429 | 57.1 | 1507.4 | 7349.4 | 14038.1 | 2067 | 40490 | 16073 |

At 300 writes/s every refusal is 503 `ipam.contended` (the load's own changes of one
address meeting). At 1,000 writes/s the debug build on one machine is overloaded: 38,935
writes waited longer than the store's five seconds (503 `sys.store.no_quorum`), 1,472 met an
election (`cluster.no_quorum`), and 16,073 were not sent because 2,048 were in flight. The
cluster was whole again 0.6 s after the load stopped. The workstation sustains about 250
API writes per second through one controller in this build. The Spike A figure (1,000
updates/s) is a store-level figure without the API, the planner and the audit log; the
threshold applies to three hosts with a release build (WP3.8).

The empty fourth controller joined after the load (state 168.8 MB, log 520.1 MB, last
snapshot 216.5 MB): `tenko cluster join` copied a snapshot of 219.5 MB in 17.4 s and the
leader saw no lag 29.3 s after the join began. A first attempt with 64 log entries per
append never caught up: openraft 0.9 abandons an append after the heartbeat interval
(100 ms), and 64 large coalesced entries took longer to send and apply; `000c19a` sends at
most eight.

### M1 on one host

| Phase | Reads | Bad or empty | p50 (ms) | p99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| baseline, 20 s | 1000 | 0 | 18.6 | 42.1 | 63.0 |
| during the install, 10 s | 510 | 0 | 20.6 | 53.0 | 60.4 |

50 reads/s of `GET /api/v1/addresses?limit=20` on a follower after 30 s of 200 writes/s,
while a fourth controller joined: its join (the snapshot install) took 5.2 s and it had no
lag 10.2 s after the join began; the "during" window runs from the start of the join until
the new controller was ready. The stand-in is IPAM list reads, not the 6 M RRset test index.

### M6

| File | Bytes |
|---|---|
| raw: the leader's state file after the churn | 16,846,848 |
| the member's state file before it left | 22,024,192 |
| the rejoined member's state file at rest | 16,846,848 |

Churn: 100 writes/s for 20 s (2,001 committed). The member was removed, its data directory
replaced by an empty one, and it joined again with a fresh token (join 3.4 s, membership
complete 16.8 s); its state file, after a graceful stop, has the size of the leader's.

## Linux

Not measured in this run. The scenarios of the lab pass on Linux (WSL Ubuntu 24.04, the
test binaries in an `ubuntu:24.04` container with `--network none`: the WSL networking mode
of the workstation refuses IPv4 loopback connections to ephemeral ports), and the compose
lab's smoke passes there; `run.sh` takes the measurements the same way on a Linux host.

## Conclusion

On one machine the cluster fails over in under two seconds in every one of 20 runs, loses no
committed write, serves follower reads without a dent while a learner installs a snapshot,
and a rejoined member does not grow. The debug build on one host does not reach the write
rate of M4, and forwarded writes have a long tail (M12); both are recorded for WP3.8, which
runs them on three VMs with a release build. The lab found and fixed four defects on the
way: a joining controller with the file KEK could not store the received keys
(`6807f2a`), a replaced dead voter stayed in the membership as a learner (`667bdbf`), a
lagging member could not catch up from large entries (`000c19a`), and the configuration
file a join creates named its role in a form `tenko serve` refuses (`5172cf3`, found by the
compose lab).
