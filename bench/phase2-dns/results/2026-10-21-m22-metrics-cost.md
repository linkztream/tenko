# M22: the metrics cost on the query path over the real link of M17 (Linux)

Verdict: FAIL (metrics on cost 4.8 percent more server CPU per query than metrics off over 20 simultaneous pairs at two workers, standard error 2.1 points, p99 3.49 against 3.17 ms at the median; with one worker 1.9 percent, standard error 1.2, p99 unchanged)

M22 of the Phase 2 plan (section 6, OPS-21, E21 and the "with and without metrics" of E13) is M8 of Phase 1 again with the DNS engine on the query path: the M17 runs with the metrics switched on and off, at the node's full worker count, against the bound "below 2 percent, p99 unchanged". It ran on the hosts of M17 ([2026-10-21-m17-real-link.md](2026-10-21-m17-real-link.md)): the node VM, the load VM, the virtual link between them.

`tenko serve` has no metrics switch: the engine's metrics are always on in a node (`docs/dns.md` section 12.7), so the measurement uses the engine's example server (`crates/tenko-dns/examples/authoritative.rs`, built for musl like the binary), the server M16 measured on loopback, with `--metrics on` and `--metrics off`. It serves the same 100,000-name zone from the production index through the same responder; the switch gates exactly what the role pays per query: one clock read for the latency, one counter increment and one histogram observation on the calling thread's shard (`respond.rs`, `finish`). Its query path with metrics on costs what the role's does (M16: within half a microsecond per query on Windows and 0.2 to 0.4 us in WSL2).

## Summary

The measurement that carries the verdict runs both servers at once: one with the metrics on, one with them off, each with half of the node's four vCPUs as workers (two) and half the rate (100,000 queries per second each), loaded by two dnsperf processes from the load VM in the same 30 s window, their ports swapped from pair to pair. Whatever the hypervisor does to the node in that window, it does to both. The cost of a pair is the server CPU seconds per answered query with the metrics on over those with the metrics off, minus one.

| Design | Pairs | Workers per server | Rate per server | Cost per query, mean of the pairs | Standard error | Over all queries | QPS per server core on / off | p99 median on / off |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| Together (the verdict) | 20 | 2 | 100,000 | +5.14 % | 2.12 | +4.82 % | 95,676 / 100,284 | 3,487 / 3,167 us |
| Together, first series | 6 | 2 | 100,000 | +2.69 % | 2.47 | +2.52 % | 98,681 / 101,170 | 3,263 / 3,231 us |
| Together, one worker each | 10 | 1 | 50,000 | +1.95 % | 1.24 | +1.89 % | 100,575 / 102,473 | 2,943 / 2,943 us |
| Alternating, one server, fixed rate | 6 | 4 | 250,000 offered, 210,000 to 240,000 reached | +6.22 % | 3.09 | +6.01 % | 108,895 / 115,442 | 4,607 / 4,351 us |
| Alternating, one server, saturation | 3 | 4 | as fast as it answers | +3.02 % | 6.61 | +3.78 % | 134,762 / 139,862 | 5,247 / 4,351 us |

The twenty pairs of the verdict, in order (ports swapped every pair): -3.2, +1.9, +0.5, -4.5, -1.5, +7.2, -1.8, +12.7, -10.3, +17.1, +7.1, +14.5, +3.0, -1.4, +15.8, +27.6, -3.1, -0.1, +16.1 and +5.2 percent. Both servers answered their 100,000 queries per second (99,479 and 99,871 on average); the server with the metrics on lost 9,443 queries in all, the one with them off 3,792 (of about 60 M each); the mean latencies at p50, p99 and p99.9 were 159, 3,842 and 5,292 us with the metrics on and 124, 3,391 and 5,023 us with them off.

Reading:

- **Every design puts the cost above zero and four of five above 2 percent.** The pairs scatter by ±10 points, far more than the cost, because the node VM shares the Proxmox host with the load VM, whose eight vCPUs were 7.4 to 7.9 busy driving 200,000 paced queries per second; the noise is the host's, not Tenko's. Twenty simultaneous pairs bring the standard error to 2.1 points, enough to say that the cost is positive (2.4 errors above zero) and not enough to say that it is above 2 percent (1.5 errors above it). Against the bound as written, below 2 percent and p99 unchanged, the measurement does not show a pass: the point estimate is 4.8 percent and the p99 of the server with the metrics on is higher in the median (3.49 against 3.17 ms).
- **One worker per server costs less than two.** With one worker each the cost is 1.9 percent (standard error 1.2) and the p99 is the same to the microsecond; with two workers each it is 4.8 percent. What the metrics do per query is the same in both; what differs is that two worker threads of one process update the same counter and histogram families. A family has one shard per CPU, rounded up to a power of two (four on this node), and a thread gets its shard round-robin at its first update among all the threads of the process that ever update a metric (`tenko-core` `metrics::thread_shard`), so two UDP workers can land on the same shard and share its cache line, which then moves between their cores on every query. On a VM that cost is larger than on the workstation, where M8 measured 0.7 to 2.2 percent for the Spike B responder. This is the candidate cause, not a proven one: the run does not show which shard each worker had.
- **M8 of Phase 1 and this run differ in what they measure**: M8 measured the Spike B responder's counters on the workstation (Windows and WSL2, loopback); M22 measures the engine's full metrics path on a 4-vCPU VM over a link, with the load generator on a VM of the same host.

What would settle it, for the lead: shards per worker thread assigned when a UDP worker starts (so that no two workers share a line) or one stripe per worker, then M22 again with the same script (`--phases metrics`); a run on hosts that do not share their cores would also shrink the noise.

## Method

| Item | Value |
| --- | --- |
| Hosts and link | Those of M17: the node VM (4 vCPU `QEMU Virtual CPU version 2.5+`, 3.8 GiB, Ubuntu 24.04.5, kernel 6.8.0-147, clock source `kvm-clock`), the load VM (8 vCPU, same host and bridge, dnsperf 2.14.0), `ping` 0.4 ms. The load VM's sysctls raised by `tune-udp.sh` for the run and restored after it |
| Server | `authoritative --listen <node>:<port> --workers W --metrics on|off --mode reuseport` (100,000 names, cookies on, TCP on, built with `cargo build -p tenko-dns --example authoritative --release --locked --target x86_64-unknown-linux-musl` from `5bfd7ba`'s tree, static-pie); the node's own Tenko instance of M17 stopped for the runs |
| Load | Together: two `run-dnsperf.sh` at once, UDP, `--rates 100000` (50,000 for one worker each), `-T 4 -c 32 -q 512`, `-e`, `-O latency-histogram`, 30 s, the query file of M17. Alternating: one `run-dnsperf.sh` as in M17 (`-T 8 -c 64 -q 1024`) at `-Q 250000` or without a rate limit |
| CPU | `server-cpu.sh` on the node right before and after each window, for each server pid: utime plus stime from `/proc/<pid>/stat` |
| Cost | Per pair: (CPU seconds over answers) on, over the same off, minus one; the mean of the pairs and its standard error; and over all queries of a series: the sum of CPU seconds over the sum of answers, on against off |

## How to reproduce

```
scripts/run-m17-remote.sh --node user@node --node-addr 192.0.2.10 --load user@load --load-addr 192.0.2.20 \
    --example <authoritative musl> --data data/100000 --phases "metrics stop report" --pairs 20
scripts/run-m17-remote.sh ... --phases "metrics stop report" --pairs 10 --workers 2 --metrics-rate 100000
scripts/run-m17-remote.sh ... --phases "metrics stop report" --metrics-mode alternate --metrics-rate 250000
```

The `report` phase prints the pairs, the mean, the standard error and the p99 medians (`m22-summary.txt` in the output directory).
