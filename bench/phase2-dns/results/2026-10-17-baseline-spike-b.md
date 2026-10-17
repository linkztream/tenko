# Phase 2 baseline: the Spike B responder through the Phase 2 harness (Windows and WSL2)

Verdict: Reference (single-node loopback baseline for M16; not a pass or fail)

This is the number the first Tenko engine (WP4.1) is compared against. It measures the Spike B
UDP responder (`bench/spike-b-udp`, backend `domain`, tokio mode, one shared socket) with the
`bench/phase2-dns` load generator on loopback, workers 1, 4 and 8, UDP, EDNS on, a 100,000-name
zone, 30 s per run. Every figure is a single-node figure (plan section 2.10), and a loopback
figure: an upper bound. M16's threshold is above 100,000 QPS per core on UDP; the Spike B
responder reaches 89,000 to 229,000 QPS per server core depending on platform and worker count,
so a Tenko engine that wants to keep the Spike B result needs to land in the same range on the same
machine. The comparison is with the same row of the same platform, never across platforms.

## Summary

| Platform | Workers | QPS | p50 us | p99 us | p99.9 us | Server cores busy | Server CPU us/query | QPS per server core |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows 11 | 1 | 145,062 | 1,733.6 | 2,398.2 | 3,541.0 | 0.98 | 6.78 | 147,441 |
| Windows 11 | 4 | 448,329 | 542.2 | 857.6 | 1,079.3 | 3.95 | 8.80 | 113,606 |
| Windows 11 | 8 | 703,781 | 358.7 | 461.3 | 514.8 | 7.93 | 11.26 | 88,776 |
| WSL2, Linux musl | 1 | 165,188 | 1,552.4 | 2,187.3 | 4,044.8 | 1.00 | 6.05 | 165,299 |
| WSL2, Linux musl | 4 | 913,911 | 269.8 | 463.9 | 758.3 | 4.00 | 4.37 | 228,764 |
| WSL2, Linux musl | 8 | 1,721,045 | 141.8 | 257.0 | 586.8 | 7.91 | 4.60 | 217,578 |

Each row is the better of two runs (QPS), with that run's latencies. Both runs:

| Platform | Workers | QPS run 1 | QPS run 2 |
| --- | ---: | ---: | ---: |
| Windows 11 | 1 | 145,062 | 135,164 |
| Windows 11 | 4 | 440,573 | 448,329 |
| Windows 11 | 8 | 703,781 | 681,521 |
| WSL2, Linux musl | 1 | 158,304 | 165,188 |
| WSL2, Linux musl | 4 | 913,911 | 888,452 |
| WSL2, Linux musl | 8 | 1,721,045 | 1,690,953 |

The two runs differ by up to 7 percent (Windows, 1 worker), so a difference of a few percent
between this baseline and a later run is not a finding. No timeouts, errors, unexpected responses
or send errors in any run. About 5 percent of the responses were NXDOMAIN, as the query file says
(for example 202,845 of 4,054,924 in the Windows 1-worker run of round 2). The server's peak RSS was 16.1 to 16.7 MiB (Windows) and 8.1 to
8.4 MiB (Linux), the 100,000-name zone included.

Latency in a closed loop is queueing delay: with 8 clients x 32 in flight = 256 queries
outstanding, p50 is close to 256 divided by the QPS (Little's law), not the service time of one
query. Compare latencies only between runs with the same load layout; the CPU per query is the
service cost.

## Machine and toolchain

| Item | Value |
| --- | --- |
| CPU | Intel Core i9-13900K (8 P-cores with Hyper-Threading + 16 E-cores = 24 cores, 32 logical processors), hybrid, no CPU pinning |
| RAM | 64 GB |
| Windows | Windows 11 Enterprise 10.0.26300; power plan not recorded (the Spike B runs used Balanced) |
| WSL2 | Ubuntu 24.04.3 LTS, kernel 6.18.33.2-microsoft-standard-WSL2, 32 vCPUs, 51 GB visible; `net.core.rmem_max` 4 MiB (the 8 MiB buffer requests of the responder and 4 MiB of the generator are capped to it) |
| Toolchain | Rust 1.99.0 stable |
| Responder, Windows | `bench/spike-b-udp` at its committed `Cargo.lock`, `cargo build --release --no-default-features --features backend-domain` (`x86_64-pc-windows-msvc`, fat LTO, one codegen unit, `panic = "abort"`) |
| Responder, WSL2 | the same source built static for `x86_64-unknown-linux-musl` (static-pie, `ldd`: statically linked), as the Linux rule asks even for a reference |
| Load generator | `bench/phase2-dns` 0.1.0, release build with the same profile: Windows MSVC, and `x86_64-unknown-linux-musl` in WSL2 |
| Data | `phase2-dns zonegen --records 100000 --out-dir data/100000` (seed 42): `queries.txt`, 1,000,000 lines sampled with replacement, 95 percent `host-{n}.example.test A`, 5 percent `nohost-{n}.example.test A`; the responder's built-in zone holds `host-0` to `host-99999` |
| Address | Windows `127.0.0.1:5399` (UDP 5353 is held by the system mDNS responder); WSL2 `127.0.0.2:5399` (WSL2 does not deliver 127.0.0.1 traffic to local sockets, as in Spike B) |

## Method

`scripts/run-loopback.sh` starts the responder for every worker count, waits until it answers,
runs the load generator for 2 s of warm-up and a 30 s measured window with the responder sampled by
pid (CPU time at both ends of the window, RSS every 100 ms), and stops it. The load layout is
Spike B's 8 clients x 32 in flight (256 outstanding queries), closed loop, EDNS on (OPT, UDP size
1232), `--require-aa`. Round 1 and round 2 are two executions of the same command, one after the
other, Windows first and then WSL2.

Windows (Git Bash, from `bench/phase2-dns`):

```
scripts/run-loopback.sh --harness <phase2-dns.exe> \
    --server-cmd "<spike-b-udp.exe> serve --backend domain --mode tokio --workers {workers} --listen {listen}" \
    --label spike-b-domain-windows --names data/100000/queries.txt --workers "1 4 8" \
    --transports udp --require-aa --duration 30s --out results/raw/baseline-windows.jsonl
```

WSL2 (run from `/mnt/d/...` through `wsl -d Ubuntu-24.04`):

```
scripts/run-loopback.sh --harness <phase2-dns> --server-binary <spike-b-udp> \
    --server-cmd "<spike-b-udp> serve --backend domain --mode tokio --workers {workers} --listen {listen}" \
    --listen 127.0.0.2:5399 --label spike-b-domain-wsl2-musl --names data/100000/queries.txt \
    --workers "1 4 8" --transports udp --require-aa --duration 30s --out results/raw/baseline-wsl2.jsonl
```

`phase2-dns report --input results/raw/baseline-windows.jsonl results/raw/baseline-wsl2.jsonl`
renders the tables above (raw records and logs are in `results/raw/`, git-ignored).

## Consistency with Spike B

The numbers agree with the Spike B results file (`bench/spike-b-udp/results/2026-10-09-windows.md`):
there the Windows responder with one worker reached 146,000 to 162,000 QPS at about 6.2 us of
server CPU per query, and 597,000 to 752,000 QPS with 8 workers; here 135,000 to 145,000 QPS at
6.8 us and 682,000 to 704,000 QPS.

## Server CPU per query

The CPU per query is the responder's user plus kernel time over the window divided by the
responses received. On Windows it grows with the worker count (6.8, 8.8, 11.3 us) because the
workers compete with the load generator for the same cores and for the loopback stack; on WSL2 it
is 6.1 us with one worker and 4.4 to 4.6 us with 4 and 8 (not investigated). The QPS per server core is
the reciprocal. M16's threshold of 100,000 per core is met by the responder in every row except 8 workers on
Windows (88,776).

## Caveats

- **Loopback.** Client and server share one host and one network stack: upper bounds, nothing about
  NIC, driver or switch behaviour. M17 measures the real link.
- **Other load on the machine.** Other sessions were building on the same host. Host CPU
  (Windows `Win32_Processor.LoadPercentage`, the whole machine including the responder and the
  generator, sampled about every 3 s) was, per run, approximately: Windows round 1: 23 percent
  (1 worker), 41 percent (4), 58 percent (8); Windows round 2: 33, 44, 52 percent; WSL2 round 1: 5
  percent (1 worker), 69 percent (4), 79 percent (8); WSL2 round 2: 35, 69, 78 percent. The
  responder and the generator themselves account for at most about 7 percent (1 worker), 27
  percent (Windows, 4 workers), 20 percent (WSL2, 4 workers) and 47 percent (8 workers) of the 32
  logical processors, so part of every run, and most of the WSL2 4- and 8-worker runs, shared the CPU
  with other work whose size cannot be separated from the VM's own overhead. The numbers are if
  anything lower bounds for an idle machine; the spread between rounds (up to 7 percent) is the
  size of the effect seen.
- **WSL2 is a VM**, not bare-metal Linux. Its numbers are labelled so and are compared only with
  later WSL2 numbers (the Tenko musl binary in the same VM), never with Windows ones. The
  Windows host runs 8 workers at 704,000 QPS where WSL2 reaches 1,721,000: that is the loopback
  stack, not the responder.
- **Hybrid CPU, no pinning.** Threads may land on P- or E-cores; one worker's rate varies by
  several percent between rounds.
- **Closed-loop latency** is queueing delay at a fixed 256 outstanding queries (see above). The
  harness's paced mode (`--qps`) is for a latency at a given rate.
- **One zone size, one query mix**: 100,000 names, 95 percent hits and 5 percent NXDOMAIN, no PTR,
  A only, no TCP (the responder has no TCP). The TCP baseline arrives with the first engine.
- **No metrics switch**: the responder has none, so M22's on and off comparison is not part of
  this baseline.
- **Single process, single socket**: with tokio tasks sharing one UDP socket the responder is not
  the best Spike B configuration on Linux (`SO_REUSEPORT` reached more); it is the one with the same
  socket model on both platforms.
