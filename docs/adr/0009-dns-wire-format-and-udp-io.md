# ADR 0009: DNS wire-format crate and UDP I/O design

- Status: Accepted
- Date: 2026-10-09

## Context

ADR 0001 chose Rust and left two questions to Spike B: which crate parses and builds DNS messages on the hot path, and how UDP sockets and workers are arranged on Windows and Linux. The spike (`bench/spike-b-udp`, results in `results/2026-10-09-windows.md` and `results/2026-10-09-linux-wsl2.md`) built a minimal authoritative responder twice behind one `Codec` trait, once over `domain` 0.12.3 (NLnet Labs) and once over `hickory-proto` 0.26.3, and drove it with a multi-socket load generator at 256 queries in flight. All runs were loopback on one i9-13900K (32 logical CPUs); Linux ran under WSL2, not bare metal; other builds ran concurrently, so each configuration ran with three client layouts and the tables keep the best. The backend comparison was repeated as paired back-to-back runs.

Measured, best run per configuration:

| Platform, mode | 1 worker | 4 workers | 8 workers | Peak |
|---|---|---|---|---|
| Windows, shared socket, threads, `domain` | 148k QPS (159k per core) | 444k | 718k | about 750k at 8 to 16 workers; beyond that the load generator competes for the same cores |
| Linux WSL2, shared socket, threads, `domain` | 195k | 937k | 2.73 M | 3.28 M at 16 workers (207k per core) |
| Linux WSL2, one `SO_REUSEPORT` socket per thread, `domain` | 204k | 1.20 M | 1.91 M | 4.04 M at 32 workers (262k per core) |
| Linux WSL2, shared socket, tokio tasks, `domain` | 192k | 921k | 1.43 M | 1.65 M at 16 workers |

Paired comparison, `hickory-proto` QPS divided by `domain` QPS: 0.90 to 0.94 on Windows, 0.83 to 0.87 on Linux (five rounds each, min to max within 0.02). Server CPU per query was 0.5 to 1.0 us lower with `domain`.

Criterion micro-benchmarks (Windows / Linux, ns per operation): parse 47 / 49 against 82 / 78; build A 77 / 72 against 400 / 278; parse + lookup + build 153 / 145 against 535 / 388. Allocations per operation: `domain` 0 everywhere; `hickory-proto` 6 per A response (217 bytes) and 10 plus one realloc per NXDOMAIN (428 bytes), all from `Name::emit` and the encoder's label-pointer table, even with compression off. Both crates produced byte-identical responses for A, NXDOMAIN and apex SOA with and without EDNS. Release binary with one backend: `domain` 1.68 MB, `hickory-proto` 1.99 MB on Windows. Transitive dependencies: 16 against 50.

`SO_REUSEPORT` balances by flow hash, not load: with 8 client sockets only 7 of 16 workers received traffic; with 64 sockets, 14 to 15 of 16. A shared socket spreads evenly but stops scaling past 16 workers (167k QPS at 32 workers while burning 18.5 cores). A multi-threaded tokio runtime on the UDP path was the slowest arrangement from 8 workers up.

Reference points from published measurements over a real 10 GbE link (Lencse, IEEE Access 2020, RFC 8219 method, 2019 Xeon): NSD 165 to 185k QPS per core, Knot DNS 120 to 190k, BIND 9 20 to 28k. The spike's 150 to 260k per core are loopback figures and not directly comparable, but they put the design in the NSD and Knot class rather than the BIND class, and the per-core target of 100k QPS (DNS-27) is met with margin.

## Decision

1. **`domain` is the DNS wire-format crate** for parsing, building, name handling, zone file parsing, TSIG and DNSSEC record types. It is used behind an internal `Codec` trait in `tenko-dns`, so the crate can be replaced without touching the server, and `hickory-proto` stays available as a second implementation of the trait for differential tests.
2. **The UDP fast path runs on dedicated blocking worker threads, not on a multi-threaded tokio runtime.** tokio remains the runtime for everything else: TCP, DoT, DoH, DoQ, the control plane, connectors and the API.
3. **On Linux, each worker owns its own `SO_REUSEPORT` socket**, pinned one per core by default. Because the kernel spreads by flow hash, the worker count is configurable and a BPF steering program (`SO_ATTACH_REUSEPORT_CBPF`) is a later optimization, as are `recvmmsg` and UDP GSO; none of them is assumed.
4. **On Windows, workers share one socket.** Blocking threads and tokio tasks measured the same; threads are used for symmetry with Linux and lower idle CPU. The worker count defaults to the core count and throughput plateaus around 8 to 16 workers on this hardware.
5. **No allocation per query is a rule, not a result.** The responder reuses receive and send buffers per worker, and the criterion bench with the counting allocator runs in CI so a regression to allocating paths fails the build.
6. **The zone tree, cache and policy engine are Tenko DDI's own** (they live in the replicated store and the in-memory index of ADR 0002); `domain`'s `zonetree`, server transport and resolver modules are not used.

## Consequences

- `domain` is pre-1.0 with an API rework in progress, and signing, validation, XFR and zone-tree helpers sit behind `unstable-*` features. The `Codec` trait, a pinned version in `Cargo.lock`, the differential tests against `hickory-proto` and the fuzz targets (API-15) are the mitigation; DNSSEC signing and XFR message handling are implemented against the stable record types with their own tests rather than against the unstable modules.
- The octets-generic builder API is easy to misuse (rewinding a section silently drops records); the spike caught one such bug in tests, so every builder path keeps a byte-exact test.
- Two threading models exist in `tenko-dns` (blocking UDP workers, async everything else); the boundary is the lock-free in-memory index and the per-worker metrics counters (OPS-21), and it is documented in the crate.
- Worker-to-socket layout differs per platform and is reported in the node's health view so an operator can see uneven `SO_REUSEPORT` distribution.
- The loopback figures are an upper bound. A two-host measurement over a real link is a Phase 2 exit criterion before any absolute number is published (DNS-27).

## Alternatives considered

- **`hickory-proto`.** Larger ecosystem and more downloads, a full server and resolver, but 6 to 10 heap allocations per response in the builder, 2.5 to 3.5 times slower parse-plus-build, 6 to 17 percent lower end-to-end throughput, 34 more transitive dependencies and a 0.3 MB larger binary. It stays as the second `Codec` for differential testing.
- **A hand-written wire-format implementation.** Maximum control and no dependency churn, but it reproduces the part of a DNS server where vulnerabilities historically live, and `domain` already achieves zero allocations and zero-copy parsing. It remains an option behind the same trait if `domain`'s API churn becomes a maintenance problem.
- **A multi-threaded tokio runtime for UDP.** Simplest to write, but measured as the slowest arrangement at scale on both platforms, and idle workers cost CPU.
- **A single shared socket on Linux.** Even load distribution and simpler code, but it stopped scaling at 16 workers while `SO_REUSEPORT` kept scaling to 32.
