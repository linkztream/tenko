# Phase 1 metrics benchmark (M8)

Measurement M8 of the slice 3 plan (`docs/plans/slice-3-plan.md`, WP3.5 item 7 and section 5):
the cost of the metrics core (`tenko_core::metrics`, OPS-21) on a hot path.

| Threshold | Limit |
|---|---|
| Throughput of the Spike B responder with the counters and a histogram on its hot path | at most 2 percent below the same responder without them |
| p99 latency | unchanged within noise |
| Allocations of a million `inc` and `observe` calls on sealed families | zero |

The package is standalone (its own empty `[workspace]`, its own `target/`, path dependencies on
`crates/tenko-core` and `bench/spike-b-udp`). All traffic is UDP on loopback; the zone is the
spike's `example.test` with documentation addresses.

## What runs

- **The responder** (`src/responder.rs`, `serve`) is the blocking-threads I/O mode of the Spike
  B responder: N OS threads blocking in `recv_from` and `send_to` on one shared socket with
  8 MiB buffers, one receive buffer, response buffer and name key per thread. The worker loop is
  a copy of `blocking_worker` and `run_threads` from `bench/spike-b-udp/src/server.rs`, because
  the spike's library runs its loop to the end and offers no hook; the per-packet work is the
  spike's own `backend::respond` with the `domain` codec (parse, lookup in the 100,000-name
  zone, build). The spike's own per-worker counters are left out, so `--metrics off` has no
  instrumentation at all.
- **With `--metrics on`** every packet adds one to `bench_dns_queries_total{outcome}` (a
  `CounterVec` of four series) and records the time of `respond` in
  `bench_dns_query_duration_seconds` (a `Histogram` with 11 bounds in nanoseconds): two clock
  reads, one counter update and one histogram observation per packet. On and off are separate
  monomorphizations of the worker (`worker::<true>`, `worker::<false>`).
- **The load** is the spike's closed-loop generator (`spike_b_udp::load::run_load`, used as a
  library): 8 client threads with 32 queries in flight each, 5 percent NXDOMAIN, EDNS, 2 s
  warm-up and 20 s measured per run.
- **Pairs** (`pairs`): for each pair a fresh responder with the metrics off and one with them
  on, alternating which goes first, so that drifts in machine load hit both alike; five pairs
  per worker count. Every run appends one JSON line in the spike's record format to
  `results/raw/` (git-ignored) and `pairs` prints the table; `report` prints it again from the
  JSON lines.
- **Zero allocations** (`tests/zero_alloc.rs`): a counting global allocator around a million
  `inc`, `add` and `observe` calls on sealed families (a two-label `CounterVec`, a
  `HistogramVec`, a `Counter`, a `Histogram`) on one thread, then on four threads at once,
  asserts that the updating threads allocated nothing. A global allocator needs
  `unsafe impl GlobalAlloc`, which the workspace forbids; that file is the only one of this
  package that allows `unsafe`.

## Run

From this directory (Git Bash on Windows, bash on Linux):

```
cargo test --release
cargo build --release
target/release/phase1-metrics pairs --listen 127.0.0.1:5399 --workers 1 --out results/raw/m8-windows.jsonl
target/release/phase1-metrics pairs --listen 127.0.0.1:5399 --workers 4 --out results/raw/m8-windows.jsonl
target/release/phase1-metrics report --input results/raw/m8-windows.jsonl
```

On Windows UDP port 5353 is held by the system mDNS responder; use another port, such as 5399.
In the WSL2 distribution of the spike's Linux results, traffic to 127.0.0.1 never reaches local
sockets: use `--listen 127.0.0.2:5399` there (still the `lo` device; see the spike's README), and
a target directory on the Linux file system. Options of `pairs`: `--clients`, `--inflight`,
`--duration`, `--warmup`, `--pairs`, `--label`.

A run by hand: `target/release/phase1-metrics serve --metrics on --workers 4` prints a `ready`
line and serves until its standard input closes; it then prints a `stats` line and, with the
metrics on, the OpenMetrics text of its two families on standard error.

## Results

One Markdown file per run set in `results/`, in the format of `bench/README.md`.
