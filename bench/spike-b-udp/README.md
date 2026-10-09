# Spike B: raw UDP DNS throughput and DNS wire-format crate comparison

## Purpose

Spike B of the Tenko DDI project (DNS + DHCP + IPAM in Rust). It answers two questions:

1. What request/response throughput and latency does raw UDP DNS reach with the chosen I/O
   design, and how does it scale with the number of workers? Measured on Windows and on Linux
   (WSL2).
2. Which DNS wire-format crate should the project build on: `domain` (NLnet Labs) or `hickory-proto`?

Results are written up in `results/`: `results/2026-10-09-windows.md` (Windows numbers, crate
comparison and the recommendation) and `results/2026-10-09-linux-wsl2.md` (Linux under WSL2,
including SO_REUSEPORT). Raw JSONL output goes to `results/raw/` (git-ignored).

## Layout

| File | Content |
| --- | --- |
| `src/main.rs` | CLI: `serve`, `load`, `matrix`, `report` |
| `src/server.rs` | The UDP responder and its I/O modes |
| `src/backend/mod.rs` | The `Codec` trait and the generic hot path `respond` |
| `src/backend/domain_codec.rs` | `Codec` implementation on the `domain` crate |
| `src/backend/hickory_codec.rs` | `Codec` implementation on `hickory-proto` |
| `src/zone.rs` | In-memory zone `example.test`: 100,000 names `host-{n}.example.test` mapping to A records in the RFC 5737 ranges, `HashMap` lookup |
| `src/wire.rs` | Raw wire helpers that do not depend on either crate |
| `src/load.rs` | Closed-loop load generator (QPS, latency percentiles) |
| `src/procstats.rs` | Server CPU time and RSS sampling |
| `src/matrix.rs` | Runs the backend x mode x workers x clients matrix |
| `src/report.rs` | Renders JSONL results as Markdown tables |
| `src/record.rs` | `RunRecord`, the one-JSON-line-per-run result format |
| `benches/codec.rs` | Criterion micro-benchmarks: parse, build and round trip per crate, plus allocations per operation via a counting global allocator from the `stats_alloc` crate |
| `tests/serve_smoke.rs` | End-to-end test: every backend and I/O mode answers real UDP queries; on Linux also with `--reuseport` |
| `scripts/run-matrix.sh` | The throughput matrix used for the results files (workers 1 to 32, three client layouts) |
| `scripts/run-unloaded.sh` | Unloaded latency: one client, one query in flight |
| `scripts/run-ab.sh` | Paired backend comparison: `domain` and `hickory` back to back, five rounds |

## What the server does

Per query it parses the header and the question (plus the EDNS OPT record if present), looks up the
lowercase name and answers:

- A record for a known name: AA=1, RA=0, ID copied from the query.
- NXDOMAIN with the SOA in the authority section for unknown names inside the zone.
- NODATA (NOERROR, no answer) with the SOA for other query types.
- REFUSED for names outside the zone.
- NOTIMP for opcodes other than QUERY.
- BADVERS for an EDNS version greater than 0.
- FORMERR for queries that cannot be parsed.
- Messages with QR=1 (responses) are never answered.

If the query had an OPT record, the response echoes one with UDP size 1232. Responses are capped at
512 bytes without EDNS, or at min(client size, 1232) with EDNS, and are truncated with TC=1 if they
would not fit.

Both crates are compiled behind the cargo features `backend-domain` and `backend-hickory` (both in
the default set) and chosen at runtime with `--backend domain|hickory`. The per-packet code is
shared; only `Codec::parse` and `Codec::build` differ.

## I/O modes

- `--mode tokio`: a multi-threaded tokio runtime with N worker threads and N tasks that share one
  `UdpSocket` (Windows has no SO_REUSEPORT load balancing). On Linux, `--reuseport` binds N sockets
  with SO_REUSEPORT (through `socket2`), one per task.
- `--mode threads`: N OS threads blocking in `recv_from` / `send_to`, on one shared socket. On Linux,
  `--reuseport` gives each thread its own SO_REUSEPORT socket.

Buffers are reused between packets. SO_RCVBUF and SO_SNDBUF default to 8 MiB
(`--rcvbuf` / `--sndbuf`).

## Build and test

Run inside `bench/spike-b-udp`. The crate has its own empty `[workspace]`, so it is not part of the
main workspace.

```
cargo build --release
cargo test --release
```

The tests send real UDP packets on loopback. They use 127.0.0.1 unless `SPIKE_B_LOOPBACK` names
another loopback address (needed on WSL2, see below).

## Running by hand

Start a server:

```
target/release/spike-b-udp serve --backend domain --mode tokio --workers 4 --listen 127.0.0.1:5399
```

It prints `ready pid=... listen=...`. Flags: `--listen` (default `127.0.0.1:5353`), `--backend`,
`--mode tokio|threads`, `--workers N`, `--reuseport` (Linux), `--zone-size 100000`, `--rcvbuf`,
`--sndbuf`. Stop it with Ctrl-C; it prints its packet counters, including the number of packets each
worker received.

On Windows UDP port 5353 is usually held by the system mDNS responder (`serve` then fails with OS
error 10013), so the results were measured on port 5399.

Run the load generator against it:

```
target/release/spike-b-udp load --target 127.0.0.1:5399 --clients 8 --inflight 32 --duration 20s --warmup 2s --server-pid <PID> --json results/raw/manual.jsonl
```

Other flags: `--nx-percent 5`, `--zone-size`, `--timeout 1s`, `--no-edns`, `--label`, `--seed`.
With `--server-pid` the run also records the server's CPU time and RSS.

Quick check with dig, if available:

```
dig @127.0.0.1 -p 5399 host-42.example.test A +norecurse
```

## Benchmark matrix

The scripts used for the results files (Git Bash on Windows, bash on Linux; run from
`bench/spike-b-udp`; `BIN` and `LISTEN` select the binary and the address):

```
LISTEN=127.0.0.1:5399 scripts/run-matrix.sh results/raw/windows.jsonl
LISTEN=127.0.0.1:5399 scripts/run-unloaded.sh results/raw/windows-unloaded.jsonl
LISTEN=127.0.0.1:5399 scripts/run-ab.sh results/raw/windows-ab.jsonl
target/release/spike-b-udp report --input results/raw/windows.jsonl --out results/raw/windows-tables.md
```

- `run-matrix.sh`: workers 1, 2, 4, 8, 16, 32, both backends, both modes, 2 s warm-up and 20 s
  measured, with 256 queries in flight in three client layouts (8 x 32, 32 x 8, 64 x 4). Extra
  arguments go to every `matrix` call, e.g. `--reuseport`.
- `run-unloaded.sh`: one client, one query in flight, one worker.
- `run-ab.sh`: `domain` and `hickory` back to back with identical settings, five rounds,
  alternating which goes first, at 1 and 4 workers in both modes.

For each backend x mode x workers x clients combination `matrix` spawns `serve`, runs the load
generator in-process, records the server's CPU time delta and its sampled peak RSS (through
`sysinfo`), kills the server and appends one JSON line per run to the `--out` file. `--dry-run` lists
the plan without running it.

`report` reads one or more JSONL files and prints Markdown: the best run (highest QPS) per
configuration, one table per mode and socket sharing; a pivot of best QPS by worker count; and the
list of all runs. A configuration is (backend, mode, reuseport, workers).

## Micro-benchmarks

```
cargo bench --bench codec
```

Per crate: `parse` (a captured query), `build_a` and `build_nxdomain` (a response into a reused
buffer), `roundtrip` and `roundtrip_mix` (the server's complete per-packet function `respond`), plus
`hickory_message/*` (the high-level `hickory-proto` `Message` API, for reference). Before criterion
runs, the harness prints allocations and bytes allocated per operation, measured with a counting
global allocator (`stats_alloc`). Afterwards it prints a table of criterion's estimates and writes
both tables to `results/raw/codec-bench.md`. Building with `RUSTFLAGS="--cfg no_alloc_counting"`
leaves the plain system allocator in place (no allocation table).

## Binary size per backend

```
cargo build --release --no-default-features --features backend-domain --target-dir target/size-domain
cargo build --release --no-default-features --features backend-hickory --target-dir target/size-hickory
```

Then compare `target/size-domain/release/spike-b-udp(.exe)` and
`target/size-hickory/release/spike-b-udp(.exe)`. The release profile uses fat LTO, one codegen unit,
`panic = "abort"` and no debug info.

## Linux

### WSL2 (measured)

The Linux results were measured in WSL2 (`Ubuntu-24.04`), building into a target directory on the
Linux file system:

```
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR=/home/plm/target/spike-b-udp
cd /mnt/d/Development/DDI/bench/spike-b-udp
cargo build --release
SPIKE_B_LOOPBACK=127.0.0.2 cargo test --release
export BIN=$CARGO_TARGET_DIR/release/spike-b-udp LISTEN=127.0.0.2:5399
scripts/run-matrix.sh results/raw/linux-wsl2.jsonl
scripts/run-matrix.sh results/raw/linux-wsl2.jsonl --reuseport
scripts/run-unloaded.sh results/raw/linux-wsl2-unloaded.jsonl
scripts/run-ab.sh results/raw/linux-wsl2-ab.jsonl
$BIN report --input results/raw/linux-wsl2.jsonl --out results/raw/linux-wsl2-tables.md
cargo bench --bench codec
```

In that distro traffic to 127.0.0.1 never reaches local sockets, so the runs use 127.0.0.2 (still
the `lo` device) and the tests take it from `SPIKE_B_LOOPBACK`. The default
`net.core.rmem_max`/`wmem_max` of 4 MiB was left unchanged, so the 8 MiB buffer requests are capped
to it. WSL2 numbers are VM numbers and are labelled as such.

### Bare-metal Linux (not measured yet)

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
cd bench/spike-b-udp && cargo build --release && cargo test --release
LISTEN=127.0.0.1:5399 scripts/run-matrix.sh results/raw/linux.jsonl
LISTEN=127.0.0.1:5399 scripts/run-matrix.sh results/raw/linux.jsonl --reuseport
LISTEN=127.0.0.1:5399 scripts/run-unloaded.sh results/raw/linux-unloaded.jsonl
LISTEN=127.0.0.1:5399 scripts/run-ab.sh results/raw/linux-ab.jsonl
target/release/spike-b-udp report --input results/raw/linux.jsonl --out results/raw/linux-tables.md
cargo bench --bench codec
```

Better still, run `serve` and `load` on two machines (`load --target <server-ip>:5399`), so that the
load generator does not compete with the server for CPU.

## Caveats

- Loopback only: client and server share the machine and its network stack, so these numbers say
  nothing about NIC, driver or switch behaviour.
- The load generator runs on the same machine and competes with the server for CPU.
- No CPU pinning; the CPU is a hybrid design (P-cores and E-cores).
- Other jobs were building on the same machine during the measurements; see the results files.
- Windows results are not representative of Linux, and WSL2 results are not bare-metal Linux.
- The zone is synthetic: one A record per name, so responses never need truncation in practice
  (truncation is covered by unit tests).
