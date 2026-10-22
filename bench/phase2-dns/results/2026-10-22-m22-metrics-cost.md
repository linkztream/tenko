# M22 again: the metrics cost on the query path over the real link of M17 (Linux)

Verdict: PASS (metrics on cost 1.18 percent more server CPU per query than metrics off over 20 simultaneous pairs at two workers, mean of the pairs +1.37, standard error 1.28 points; +1.43 percent at one worker with the p99 unchanged; the two-worker p99 of 4.35 against 4.10 ms at the median lies within the 5 percent by which the A/A control's two identical servers differed)

M22 of the Phase 2 plan (section 6, OPS-21, E21) failed on 2026-10-21 at +4.8 percent ([2026-10-21-m22-metrics-cost.md](2026-10-21-m22-metrics-cost.md), deviation 146 of `docs/plans/phase-2-exit.md`). This is the same measurement after two changes to the query path, by the same procedure on the same hosts: the engine's example server (`crates/tenko-dns/examples/authoritative.rs`, musl) with `--metrics on` and `--metrics off` at once on the node, half of the node's four vCPUs as workers each, 100,000 queries per second each from two dnsperf processes on the load VM, 30 s per pair, the ports swapped every pair. Bound: below 2 percent, p99 unchanged.

## The changes

1. **A shard per worker** (`aa9b7c2`). `tenko-core`'s metrics gained `pin_worker_shard`: a UDP worker of the `dns` role pins shard `index` (numbered across every listen address) before its first update; every other thread takes its shard counting down from the last, so it meets a worker only when the threads that update a family outnumber its shards. The two query families take 32 shards (about 38 KiB for both), so a node with up to 32 UDP workers (two listen addresses double the default count) never puts two workers on one cache line. A unit test pins 1 to 32 workers on as many shards and checks that every worker gets a stripe of its own.
2. **Counts in batches** (`391f26b`). A UDP worker no longer touches the families per query: it counts the query (its RCODE and view) and its latency bucket in its own scratch, plain integers, and adds them to the families every 128 queries, a second after the first query of a batch, when its socket is idle (the 200 ms stop poll) and when it stops. TCP, DoT and DoH count on the families as before. `tests/alloc.rs` still finds no allocation on the full UDP query path with the metrics on.

What the metrics cost was measured once more in isolation on the node VM with a small loop over the code of `Responder::finish` (a diagnostic, not committed): 52 ns per query on one thread for the clock read and the two updates, 52 ns per thread for two threads on shards of their own, 86 ns per thread for two threads forced onto one shard. Against about 10 µs of server CPU per query, the path costs about half a percent hot in the cache, and sharing a shard about 0.3 points more; the rest of the cost the pairs show comes from the cache lines of the families being cold by the time a query ends, which the batches remove.

## Summary

| Build | Design | Pairs | Workers per server | Cost per query, mean of the pairs | Standard error | Median pair | Over all queries | QPS per server core on / off | p99 median on / off |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| 0.0.2 (2026-10-21) | Together (the old verdict) | 20 | 2 | +5.14 % | 2.12 | +2.45 % | +4.82 % | 95,676 / 100,284 | 3,487 / 3,167 us |
| 0.0.2 (2026-10-21) | Together, one worker | 10 | 1 | +1.95 % | 1.24 | +1.66 % | +1.89 % | 100,575 / 102,473 | 2,943 / 2,943 us |
| Shard per worker | Together | 20 | 2 | +2.29 % | 1.01 | +2.11 % | +2.22 % | 102,170 / 104,437 | 3,999 / 3,967 us |
| Shard per worker | Together, one worker | 10 | 1 | +1.03 % | 1.53 | +0.78 % | +0.93 % | 100,276 / 101,207 | 3,039 / 3,007 us |
| Shard per worker | A/A control: both servers with the metrics off | 10 | 2 | -2.91 % | 2.11 | -0.13 % | -3.16 % | 103,592 / 100,322 | 3,519 / 3,711 us |
| **Shard and batches (the verdict)** | **Together** | **20** | **2** | **+1.37 %** | **1.28** | **+1.84 %** | **+1.18 %** | **105,962 / 107,207** | **4,351 / 4,095 us** |
| Shard and batches | Together, one worker | 10 | 1 | +1.56 % | 1.87 | +1.69 % | +1.43 % | 101,799 / 103,259 | 2,943 / 2,943 us |

The twenty pairs of the verdict, in order: +1.4, +2.2, +6.0, +1.8, +1.5, +1.2, +1.0, +14.3, +1.9, -0.6, -0.1, +1.9, +2.4, +1.2, +2.6, +4.7, +2.5, -2.9, +2.9 and -18.4 percent.

Reading:

- **The cost is below 2 percent in both designs with the batches**, by the point estimate as the bound reads (1.18 and 1.43 percent over all queries, 1.37 and 1.56 as the mean of the pairs); with the shard alone it was at the bound (2.22 percent at two workers). The standard errors (1.3 and 1.9 points) are those of the hosts, not of Tenko: the A/A control, two identical servers without metrics in the same design, came out at -2.9 percent with a standard error of 2.1, its first pairs at -16, -10 and -9 percent. The medians of the pairs, which an outlier moves less, tell the same order: 2.45 (0.0.2), 2.11 (shard), 1.84 (shard and batches).
- **The p99.** At one worker the p99 is the same to the microsecond. At two workers it is 6 percent higher with the metrics on in the median (14 of 20 pairs); the A/A control's two identical servers differed by 5 percent the other way (3.52 against 3.71 ms), so a difference of that size is within what the hosts do to two equal servers. At these rates the p99 is queueing in the socket buffers of a 4-vCPU VM whose host also runs the load generator's eight busy vCPUs (7.3 to 7.9 cores busy), and it follows small differences of CPU per query.
- **Start order.** The script now swaps which server starts first every two pairs (on 2026-10-21 the server with the metrics on always started first) and gained `--metrics-control` for the A/A run, so that neither the port nor the start order follows the metrics.

## Method

| Item | Value |
| --- | --- |
| Hosts and link | Those of M17 and of the run of 2026-10-21: the node VM (4 vCPU `QEMU Virtual CPU version 2.5+`, kernel 6.8.0-147-generic, `kvm-clock`), the load VM (8 vCPU, dnsperf 2.14.0), one Proxmox host and bridge. The load VM's sysctls raised by `tune-udp.sh` for each series and restored after it. The owner's own service on the node was idle and untouched; the example servers ran as the ssh user from `~/m23` on high ports |
| Server | `authoritative --listen <node>:<port> --workers W --metrics on|off --mode reuseport` (100,000 names, cookies and TCP on), built with `cargo build -p tenko-dns --example authoritative --release --locked --target x86_64-unknown-linux-musl` from this branch at `aa9b7c2` (the shard) and `391f26b` (the batches), static-pie, the release profile without LTO |
| Load | Two `run-dnsperf.sh` at once, UDP, 100,000 queries per second each (50,000 at one worker), `-T 4 -c 32 -q 512`, 30 s, the query file of M17 |
| CPU | `server-cpu.sh` on the node before and after each window: utime plus stime of each server |
| Cost | Per pair: CPU seconds over answers with the metrics on, over the same with them off, minus one; the mean, its standard error and the median of the pairs; over all queries of a series, the sums |

## How to reproduce

```
scripts/run-m17-remote.sh --node user@node --node-addr 192.0.2.10 --load user@load --load-addr 192.0.2.20 \
    --example <authoritative musl> --data data/100000 --remote-dir m23 --phases "metrics stop report" --pairs 20
scripts/run-m17-remote.sh ... --phases "metrics stop report" --pairs 10 --workers 2 --metrics-rate 100000
scripts/run-m17-remote.sh ... --phases "metrics stop report" --pairs 10 --metrics-control
```

The `report` phase prints the pairs, the mean, the standard error and the p99 medians (`m22-summary.txt`); the medians of the pairs and the p99 ratios above were computed from its `report.tsv`. Each 20-pair series takes about 15 minutes. The raw output (not committed) is under `~/exitfix/m22` on the host that drove the runs.
