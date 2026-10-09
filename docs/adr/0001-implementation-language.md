# ADR 0001: Implementation language

- Status: Accepted
- Date: 2026-10-09

## Context

DDI replaces AD-integrated Windows DNS and DHCP and must scale from a single home-lab box to enterprise deployments. The language choice is driven by four forces:

1. **Attack surface.** The DNS and DHCP engines parse unfiltered packets straight from the network. Parsers of this kind are where the recurring memory-safety CVEs in BIND, Kea and dnsmasq live. Every network parser is reachable by an unauthenticated attacker.
2. **Performance and footprint.** Targets are maximum throughput with minimal resources: more than 100k QPS per core for DNS (DNS-27), idle below 100 MB RSS with all roles on one node (OPS-15), and predictable p99 latency.
3. **Where performance actually comes from.** DNS and DHCP serving is I/O bound, not CPU bound. Throughput comes from batched system calls (`recvmmsg`, io_uring, RIO), SO_REUSEPORT sharding with one socket per core, zero-copy parsing and a lock-free cache (CON-01). An early premise of hand-written assembler hot paths was examined and rejected on this basis.
4. **Deployment.** One statically linked binary (ADR 0004) running as a Windows service and as a Linux daemon, plus containers and LXC.

## Decision

All DDI components (data plane, control plane, CLI) are written in **Rust**.

- `#![forbid(unsafe_code)]` applies to every crate. `unsafe` is allowed only where a dedicated ADR permits it, which is expected only in the I/O layer (API-16).
- Every parser of network data has a `cargo-fuzz` target before it is merged (API-15).
- SIMD and other low-level optimizations are used only where profiling shows a benefit.
- The async runtime is tokio; io_uring (tokio-uring) is a measured option, not an assumption.
- Candidate libraries are listed in ARCHITECTURE.md and confirmed in Phase 0 spikes; final library choices are recorded in their own ADRs.

## Consequences

- Memory safety in the parsers removes the dominant vulnerability class of existing DNS and DHCP servers.
- No garbage collector: no GC pauses in the tail latency, small and predictable RSS.
- C-class throughput is achievable; the remaining performance work is I/O design, measured in Spike B.
- A mature ecosystem exists for the hard parts: DNS wire format (`domain`, `hickory-proto`), DHCP wire format (`dhcproto`), Raft (`openraft`), TLS (`rustls`), HTTP and web (`hyper`, `axum`).
- Static linking and cross-compilation for Windows and Linux are well supported.
- Windows-specific integration (RIO, SSPI for Kerberos, the Service Control Manager) depends on crates that wrap system APIs. Any need for `unsafe` in DDI code there requires an ADR.
- Compile times and the learning curve are higher than for garbage-collected languages.
- Third-party crates are part of the attack surface; `cargo-deny` and `cargo-audit` run in CI and fail the build (API-14).

## Alternatives considered

- **Go.** Productive and with a good network ecosystem, but the garbage collector adds latency tails under load and raises baseline RSS, which works against the p99 and idle-memory targets.
- **C or C++ with assembler hot paths.** Maximum control, but the memory-safety record of C and C++ DNS and DHCP parsers is exactly the risk this project wants to remove. Assembler buys little because the workload is I/O bound, and it multiplies the review and portability burden.
- **Zig.** Attractive control and C interop, but the language is pre-1.0 and lacks mature libraries for DNS, DHCP, Raft, TLS and Kerberos. Ecosystem maturity is insufficient for a security-critical network service today.
