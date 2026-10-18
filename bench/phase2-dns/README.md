# Phase 2 DNS bench harness

The measurement harness of Phase 2 (DNS) of the Tenko DDI project: a load generator for any DNS
server, a generator for the zone files and query files of the Phase 2 data sets, a report
renderer, and the procedure scripts of the measurements M16, M17, M18, M22, M24 and M25
(`docs/plans/phase-2-plan.md`, sections 2.10 and 6, work package WP4.6). It contains no server
code: the target is the Tenko engine, the Spike B responder, BIND, NSD or anything else that
answers DNS.

The load generator, the result record, the report renderer and the process sampling are the ones
of Spike B (`bench/spike-b-udp`) carried over by copy, extended for names from a file, TCP and a
fixed query rate. The Spike B numbers (ADR 0009) are therefore comparable with the ones measured
here; `results/2026-10-17-baseline-spike-b.md` is that comparison, the number the first Tenko
engine is measured against.

## Rules

- **Single node first** (plan section 2.10). Every Phase 2 figure is a single-node figure: one
  Tenko process, the load generator on the same host (loopback) or on another host (a real link).
  A cluster figure is a Phase 5 comparison against it, so a slow step shows up as the difference.
  Scripts therefore start one server process and record its pid.
- **Linux runs use the static musl binary**, the one that ships:
  `cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl`, that is
  `target/x86_64-unknown-linux-musl/release/tenko`. Windows runs use the release build. Every
  script says so at its head and refuses a dynamically linked `--server-binary` on Linux with a
  warning (`--allow-dynamic` overrides; the run is then marked not publishable in its meta file).
  The harness itself may be built any way; the Linux runs in this directory build it for musl as
  well, so one binary does everything.
- **Loopback numbers are upper bounds** and are labelled so: client and server share the host
  and its CPUs. The numbers that may be published are the real-link ones (M17).
- Raw output goes to `results/raw/` (git-ignored); results are written up as Markdown in
  `results/` with a `Verdict:` line first, as `bench/README.md` describes. The baseline file is a
  reference and says `Verdict: Reference`; the pass or fail verdicts of M16 and later come with
  the engine.
- Install nothing on a measurement host from these scripts. dnsperf and flamethrower are
  installed by hand on the load host, and the scripts check that they exist.

## Layout

| Path | Content |
| --- | --- |
| `src/main.rs` | CLI: `load`, `report`, `zonegen` |
| `src/load.rs` | The load generator: closed loop or paced, UDP and TCP, latency percentiles, server CPU and RSS by pid |
| `src/names.rs` | The query names file (`name [TYPE]`, the dnsperf input format) |
| `src/wire.rs` | Raw DNS header and query encoding, no DNS crate |
| `src/record.rs` | `RunRecord`, the one-JSON-line-per-run result format |
| `src/report.rs` | JSONL to Markdown tables: best run per configuration, QPS per server core, CPU per query, metrics cost, all runs |
| `src/procstats.rs` | Server CPU time and RSS sampling (`sysinfo`) |
| `src/zonegen.rs` | The zone file and query file generator |
| `tests/cli_smoke.rs` | `zonegen`, then `load` for one second against an in-test UDP responder, then `report` |
| `scripts/run-loopback.sh` | M16 and M22: the load generator against a server on loopback |
| `scripts/run-dnsperf.sh` | M17: dnsperf from another host |
| `scripts/run-flamethrower.sh` | M17: flamethrower from another host (UDP, TCP, DoT, DoH) |
| `scripts/run-m24-cache.sh` | M24: the resolver's cache (`tenko serve` forwarding to the engine's example server) in a 1 M-name mixed run at two cache bounds, and serve-stale under an upstream cut |
| `scripts/run-m25-lists.sh` | M25: the block list compiler and matcher (the engine's example `lists_bench`) on a generated list of 1 M names: compile time, the size of the version, the time per lookup and per label |
| `scripts/server-cpu.sh` | CPU seconds and RSS of a server pid on a Linux host, for the runs where the harness cannot sample the server |
| `scripts/lib.sh` | Shared helpers: machine line, musl linkage check, readiness probe |
| `data/` | Generated zone and query files (git-ignored) |
| `results/` | Write-ups; `results/raw/` is git-ignored |

## Build and test

Inside `bench/phase2-dns` (its own empty `[workspace]`, so it is not part of the main workspace):

```
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

On Linux build the musl binary, so that harness and server are the same kind of binary:
`cargo build --release --target x86_64-unknown-linux-musl`. The tests send real UDP and TCP
packets on loopback; `PHASE2_DNS_LOOPBACK` names another loopback address when 127.0.0.1 does
not reach local sockets (WSL2 with the Windows loopback relay, see below).

## The load generator

```
phase2-dns load --target 127.0.0.1:5399 --names data/100000/queries.txt \
    --transport udp --clients 8 --inflight 32 --duration 30s --warmup 2s \
    --server-pid <PID> --workers 4 --label spike-b-domain --json results/raw/run.jsonl
```

| Flag | Meaning |
| --- | --- |
| `--target` | Address of the server (default `127.0.0.1:5353`) |
| `--names FILE` | Queries, one `name [TYPE]` per line; picked uniformly at random per query. `zonegen` writes it |
| `--transport udp\|tcp` | UDP datagrams, or pipelined queries on persistent TCP connections (RFC 7766) |
| `--clients N`, `--inflight N` | N client threads, each with its own socket or connection and N queries outstanding. The closed loop refills a slot the moment its response arrives |
| `--qps R` | Paced instead: R queries per second in total, at most `--inflight` per client outstanding |
| `--duration`, `--warmup`, `--timeout` | Measured window (default 20 s), uncounted warm-up (2 s), per-query timeout (1 s) |
| `--no-edns` | No OPT record (default: OPT, UDP size 1232) |
| `--rd` | Set recursion desired (default clear, for authoritative servers) |
| `--require-aa` | A response without AA counts as an error (authoritative servers) |
| `--server-pid P` | Sample the server's CPU time and RSS from outside, over the measured window |
| `--label`, `--workers`, `--metrics on\|off` | Copied into the record; the report groups by them |
| `--json FILE` | Append one JSON line per run |

A response is valid if the ID is outstanding, QR is set, TC is clear, the question is echoed, and
the RCODE is NOERROR or NXDOMAIN; it is counted as an answer, NODATA or NXDOMAIN. Anything else is
an error. Queries without a response are timeouts, responses to nothing outstanding are
unexpected. A TCP connection that the server closes is re-opened (counted as a reconnect) and
the outstanding queries count as timeouts.

Latency is measured from the send of a query to the receipt of its response, in an HDR histogram
(three significant digits), and reported as p50, p90, p99, p99.9, max and mean. A paced run is
not corrected for coordinated omission: if the server stalls, the queries that were due are not
sent late and counted at their intended time; the achieved `qps` below the target says that the
run saturated. The server CPU per query is the server's CPU seconds over the window divided by the
responses received; the QPS per server core is its reciprocal (queries per CPU second).

```
phase2-dns report --input results/raw/run.jsonl --out results/raw/run.md
```

renders, per label, transport and EDNS setting, one table with a row per worker count and metrics
setting (the best run of repeated ones), then the metrics cost (M22) where a configuration has a
run with metrics on and one with metrics off, then every run.

## Data sets: `zonegen`

```
phase2-dns zonegen --records 1000000 --out-dir data/1000000
```

writes, deterministically for the same arguments, into the output directory:

| File | Content |
| --- | --- |
| `example.test.zone` | `--records` A records `host-{n}` (RFC 1035 master file, `$ORIGIN example.test.`), an SOA, an NS and the glue `ns1` |
| `2.0.192.in-addr.arpa.zone`, `100.51.198.in-addr.arpa.zone`, `113.0.203.in-addr.arpa.zone` | The reverse zones, with `--ptr-percent` (default 20) PTR records per 100 hosts |
| `queries.txt` | `--queries` (default 1,000,000) lines `name TYPE`, sampled with replacement: A queries for existing hosts, `--nx-percent` (default 5) A queries for `nohost-{n}` (NXDOMAIN) and `--ptr-query-percent` (default 0) PTR queries for existing reverse owners |

**Relation to Spike A.** The generator follows `bench/spike-a-raft/src/gen.rs` record for record,
so the M18 zone import loads the same data set the Raft and store spikes measured:

- owner `host-{n}` for n in `0..N`; host n is in range `n % 3` of the three RFC 5737
  documentation networks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) with last octet
  `1 + (n / 3) % 254`. Spike A used only these networks, not 198.18.0.0/15, so neither does the
  generator; the 768 addresses repeat, which is intended (many owner names, not many addresses);
- PTR number j belongs to host `j * 100 / ptr_percent`; its owner is Spike A's RFC 2317-style
  `{octet}.{block}` with `block = host / 762` in the reverse zone of the host's range, so every
  PTR owner is unique even though there are only 768 real addresses. A real reverse zone would
  use the octet alone, which collides above 768 hosts; the owner names are therefore valid zone
  file names but not real reverse addresses;
- the TTL of a host is one of 300, 600, 900 and 3600 from Spike A's splitmix64 hash of
  `(seed, host)` (default seed 42, Spike A's), shared by the A and the PTR record of a host.
  Spike A's per-record comment fields (site, rack, source) have no place in a zone file and are
  not written.

Sizes and generation times on the baseline machine (see the baseline write-up). The times are for
writing through the OS page cache, so a slow disk adds its own write time when the cache is
flushed. The files are not committed:

| `--records` | A + PTR RRsets | Zone files | `queries.txt` | Time |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 | 100,000 + 20,000 | 3.2 + 3 x 0.3 MiB | 24.8 MiB | 0.04 s |
| 1,000,000 | 1,000,000 + 200,000 | 32.8 + 3 x 2.9 MiB | 25.7 MiB | 0.11 s |
| 6,000,000 | 6,000,000 + 1,200,000 | 202.0 + 3 x 17.7 MiB | 26.6 MiB | 0.53 s |

The query file is a sample of a million lines for all three sizes, so its size barely changes.
The M16 run uses the 100,000-name set (plan section 6), M18 the 1,000,000 and 6,000,000 sets
(`example.test.zone` plus the three reverse zones go through the zone file import, then the
load time and the index memory are read from the engine), the M24 run the 1,000,000 set.

## The measurements

### M16 and M22: QPS per core on loopback (`scripts/run-loopback.sh`)

M16 asks for more than 100,000 QPS per core on UDP with a 100,000-name zone, workers 1 to 16, TCP
documented. M22 repeats it with the metrics off and on (OPS-21; below 2 percent, p99 unchanged).

```
cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl      # in the repository root
cargo build --release --target x86_64-unknown-linux-musl                        # in bench/phase2-dns
phase2-dns zonegen --records 100000 --out-dir data/100000
scripts/run-loopback.sh --harness target/x86_64-unknown-linux-musl/release/phase2-dns \
    --server-binary ../../target/x86_64-unknown-linux-musl/release/tenko \
    --server-cmd "tenko serve --roles dns ... {workers} ... {metrics} ... {listen}" \
    --names data/100000/queries.txt --workers "1 2 4 8 16" --transports "udp tcp" \
    --metrics "off on" --require-aa --duration 30s --runs 3
```

The `--server-cmd` placeholders are replaced per run; the actual `tenko serve` options for the
worker count and the metrics switch are those of the engine (WP4.1, WP4.3) and are written into
the command when they exist. For each configuration the script starts the server, waits until it
answers, runs one measured window with the server sampled by pid, and stops the server. The
`results/raw/loopback-<stamp>.meta.txt` file records the machine, the harness version and the
command line; `phase2-dns report` renders the table. The write-up in `results/` adds the machine
(CPU, cores, RAM, OS, kernel), the toolchain, the binary and the verdict.

For the Spike B responder the same script gives the baseline (`results/2026-10-17-baseline-spike-b.md`).

### M17: one node over a real link (`scripts/run-dnsperf.sh`, `scripts/run-flamethrower.sh`)

dnsperf and flamethrower run from another host (a VM and the workstation) against one Tenko node
on another VM. The scripts take the server address, the `queries.txt` of the zone that node
loads, the transport and a list of rates (0 is the saturation run), keep the raw output of every
step and extract the summary fields. The server's own CPU seconds and RSS come from
`scripts/server-cpu.sh PID` on the server host, read before and after every step. The fields to
record, and the link description (hosts, NICs, path, MTU, RTT), are listed at the head of each
script; the write-up is the number that may be published. Neither tool is installed by this
repository; the scripts check for them and say so.

### M18: zone load and index memory at 1 M and 6 M RRsets

Not a harness run: the zone files of `zonegen --records 1000000` and `--records 6000000` go
through the zone file import and the feed of the engine (WP4.2), and the load time (under 60 s at
6 M) and the index memory (under 1.5 GiB at 6 M) are read from the engine's metrics and from the
process (`--server-pid`-style sampling of the RSS, or `server-cpu.sh` on Linux). The generator
supplies the data and its sizes above.

### M24: cache behaviour (`scripts/run-m24-cache.sh`)

A skeleton until the resolver exists (WP5.1): it prints the plan (warm pass, measured pass over a
1 M-name mixed run, serve-stale under an upstream cut) and the harness gaps to close by then (a
per-second time series, a popularity-skewed query file), and exits with 3.

### M25: block list compile and match (`scripts/run-m25-lists.sh`)

Not a harness run: the example `lists_bench` of `tenko-dns` (built like the shipped binary: the
static musl build on Linux, the release build on Windows) generates 1,000,000 names, compiles them
in hosts and in domain-list form and builds the matcher (threshold: under 2 s together), then
times 100,000 lookups of names with 2, 4 and 8 labels. The script writes the JSON lines to
`results/raw/` and prints the Verdict line. Write-up: `results/2026-10-18-m25-lists.md`.

## Caveats

- Loopback only for `run-loopback.sh`; no NIC, driver or switch behaviour.
- The load generator competes with the server for CPU on the same host; read its CPU in the
  record (`client cpu`). No CPU pinning; the workstation CPU is a hybrid design.
- Other jobs may build on the same machine; the write-ups say what ran.
- Windows results are not representative of Linux, and WSL2 results are VM numbers, not bare
  metal.
- The synthetic zone repeats 768 addresses; a response never needs truncation.
