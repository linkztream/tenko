# ADR 0008: UI embedding, static serving and SSE

- Status: Accepted
- Date: 2026-10-09

## Context

ADR 0003 decided that the SPA is embedded in the binary, served by the controller role and kept live with Server-Sent Events, and left the mechanism and its cost to Spike C. The spike (`bench/spike-c-embed`, results in `results/2026-10-09-windows.md`) compared three embedding backends (`include_dir`, `rust-embed`, a `build.rs`-generated `include_bytes!` table), build-time against runtime compression, and two SSE implementations, against the targets cold start below 200 ms, idle RSS below 30 MB and at least 10,000 SSE clients per GB.

Measured on Windows 11, loopback, i9-13900K, Rust 1.99 (other benchmarks ran concurrently):

| Measure | Result |
|---|---|
| Spawn to first `/api/health` 200 | 17.0 ms median |
| Idle working set, 32 workers, no clients | 10.8 MiB (4.9 MiB private) |
| Private memory per idle SSE client | about 37 KiB, flat from 100 to 20,000 clients |
| Fan-out CPU per delivered event, 1,000 clients | 15 to 54 us without coalescing, 2 to 5 us with 50 ms coalescing |
| Static `GET /`, 64 connections | 144k to 161k requests/s, p99 below 0.9 ms |
| Runtime compression of one JS asset | 8 to 10 times the CPU per request, 2 to 3 times lower throughput, larger bodies than build-time brotli |
| Binary size difference between backends | below 9 KB |

## Decision

1. **No embedding crate.** `build.rs` in `tenko-api` copies `ui/dist`, pre-compresses compressible assets and generates an `include_bytes!` table with content type, ETag and the available encodings computed at build time. A `--ui-dir <path>` override serves a directory instead for development; it is disabled or access-controlled in release builds.
2. **Compress at build time.** Brotli (quality 11) and gzip (level 9) variants are generated next to the identity copy for text assets and kept only when at least 5 percent smaller. The server negotiates by `Accept-Encoding` with q-values. No runtime compression layer for static assets; identity and gzip stay available for plain-HTTP lab use and command-line clients.
3. **Caching and routing.** `/assets/*` (hashed file names) get `Cache-Control: public, max-age=31536000, immutable`. `index.html` gets `Cache-Control: no-cache`, an ETag per representation, `Vary: Accept-Encoding` and `304` on `If-None-Match`. Every miss outside `/assets/` and `/api/` falls back to `index.html`; the presence of a dot in the path is not used to tell files from routes, because Tenko DDI routes contain FQDNs and IP addresses. Responses carry `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, and a strict self-only Content Security Policy; HSTS is added when TLS is on.
4. **SSE pattern.** One broadcast hub per controller; each event is encoded once into a shared buffer and written to every stream. A ring of the last 256 events serves `Last-Event-ID` replay; a `reset` event tells a client that lagged or fell outside the ring to reload state. One shared 15 s keep-alive timer, a shutdown broadcast that ends every stream, and optional tick coalescing (a configurable window, off by default below 1,000 clients). The API and UI role runs on its own small runtime of 2 to 4 worker threads. Event ids become cluster-wide (the commit index of the store) once the store exists, so replay works across controllers.
5. **Development mode.** `vite dev` proxies `/api` to the Rust server, including SSE; the server serves a directory through `--ui-dir`.

## Consequences

- `tenko-api` gains a `build.rs`, and the UI build must run before `cargo build`; CI orders the jobs accordingly, and a missing `ui/dist` is a build error, not a silent empty UI.
- The binary grows by the raw and compressed assets (about 1.5 MB for the current skeleton; roughly 2.7 MB more for a 1.8 MB unminified bundle with both variants). Accepted against the operational simplicity of one artifact.
- Fan-out CPU, not memory, limits SSE at scale. Enterprise deployments need per-subscription filtering, coalescing, HTTP/2 over TLS (browsers allow six HTTP/1.1 connections per origin) and reconnect-storm handling with client-side jitter. These are Phase 1 and Phase 5 work items, not open questions.
- `POST /api/events/emit` and `--ui-dir` are development conveniences and must not exist, or must be authenticated, in production builds.
- Linux, TLS, HTTP/2 and client and server on separate hosts were not measured; they are re-measured before the Phase 1 exit.

## Alternatives considered

- **`include_dir`.** Works and starts as fast, but hashes every embedded file at startup, which adds working set for large bundles, and does nothing that the generated table does not.
- **`rust-embed`.** Marginally smaller than `include_dir`; its `compression` feature inflates the UI into the heap at startup (about 7 ms for 1.8 MB) and can only serve identity. Its debug mode is covered by `--ui-dir`.
- **Runtime compression (`tower-http` `CompressionLayer`).** Adds 1.17 MB to the binary, costs 8 to 10 times the CPU per request, cuts throughput by half to two thirds and produces larger bodies than build-time brotli.
- **The axum `Sse` type instead of a raw stream body.** No measurable difference in memory or CPU; the raw body makes a coalesced batch a single write, which is why it was chosen.
