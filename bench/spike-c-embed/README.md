# Spike C: embedded UI and SSE

Spike C of the DDI project (DNS + DHCP + IPAM in Rust) validates
[ADR 0003](../../docs/adr/0003-embedded-spa-ui.md): the SolidJS single-page app is embedded in the
server binary and served by the Rust API process, and live updates reach the browser over
Server-Sent Events (SSE). The spike answers how to embed the UI (which crate, which compression,
which caching headers, how to do the SPA fallback), how to do SSE with axum, and what it costs:
binary size, cold start, idle memory and memory per SSE client. Results and conclusions:
[results/2026-10-09-windows.md](results/2026-10-09-windows.md). This README only describes the code
and how to reproduce the runs.

## Layout

| File | Content |
| --- | --- |
| `Cargo.toml` | Standalone crate (own `[workspace]`), cargo features, release profile (fat LTO, one codegen unit, `panic = "abort"`) |
| `build.rs` | Stages `ui/dist` into `$OUT_DIR/ui`, pre-compresses text files, writes the codegen table |
| `src/main.rs` | CLI, router assembly, listener, graceful shutdown, end-to-end tests |
| `src/assets.rs` | `AssetTable` and the three embedding backends |
| `src/web.rs` | Embedded file handler, content negotiation, ETags, security headers, `--ui-dir` router |
| `src/events.rs` | Broadcast hub with replay ring, the two SSE endpoints, the emit hook |
| `src/mime.rs` | Content type and compressibility by extension; shared with `build.rs` through `#[path]` |
| `src/bin/measure.rs` | Measurement tool (separate binary, not linked into the server) |
| `scripts/build-variants.sh` | Builds every server variant into `results/raw/bin/` |
| `scripts/run-measurements.sh` | Runs the measurements against those variants |
| `scripts/summarize.mjs` | Turns the `RESULT` lines of `results/raw/*.log` into Markdown tables (`node scripts/summarize.mjs`) |
| `scripts/vite-proxy-check.config.mjs` | Standalone Vite config used to check that the dev proxy streams SSE |
| `results/` | Write-up (`2026-10-09-windows.md`); `results/raw/` holds logs and binaries and is git-ignored |

## How embedding works

`build.rs` stages the UI build into `$OUT_DIR/ui/{raw,br,gz}`. The source is `../../ui/dist`, or the
directory in the environment variable `SPIKE_UI_DIST` (a relative path resolves against the package
directory). `raw/` holds every file byte for byte. With the `precompressed` feature, text types
(`html`, `htm`, `js`, `mjs`, `css`, `svg`, `json`, `map`, `webmanifest`, `txt`, `xml`, `wasm`; see
`src/mime.rs`) also get a brotli (quality 11, lgwin 22) variant in `br/` and a gzip (level 9)
variant in `gz/`, each kept only when it is at least 5 % smaller than the original. `build.rs` also
writes `$OUT_DIR/codegen_assets.rs`, a static table of `include_bytes!` entries with build-time
ETags, used by `backend-codegen`.

| Feature | Effect |
| --- | --- |
| `backend-include-dir` (default) | `include_dir!` over `$OUT_DIR/ui` |
| `backend-rust-embed` | `#[derive(RustEmbed)]` over `$OUT_DIR/ui` |
| `rust-embed-compression` | Implies `backend-rust-embed` plus rust-embed's `compression`: files are stored deflated in the binary |
| `backend-codegen` | No embedding crate: the table from `codegen_assets.rs` |
| `precompressed` (default) | Build-time brotli and gzip variants (above) |
| `runtime-compression` | tower-http `CompressionLayer` on the whole app (default predicate: skips `text/event-stream`, images and bodies under 32 bytes) |

If several backends are enabled the priority is codegen > rust-embed > include_dir. With
`--no-default-features` one of the three must be named, otherwise the build fails.

All backends become the same `AssetTable` at startup: a hash map from path to an `Asset` with
precomputed header values (content type, `Cache-Control`, three ETags) and bodies as `Bytes`. For
embedded data the bodies are `Bytes::from_static`, so serving a file is a lookup plus a refcount
increment and no copy. The ETag source differs per backend: xxh3-64 computed at startup for
include_dir, the SHA-256 that rust-embed provides (first 8 bytes) for rust-embed, and xxh3-64
computed at build time for codegen, so the same file has different ETags under different backends.
With rust-embed's `compression` the files are inflated into heap memory once at startup.

rust-embed's `debug-embed` feature is not used. Release builds always embed. Debug builds read the
staged files from disk, which is rust-embed's own form of a disk mode; unlike `--ui-dir` it reads
the staged copy under `$OUT_DIR`, and the table is built once at startup.

## Serving rules

Implemented in `src/web.rs` for the embedded mode:

- Only `GET` and `HEAD`; anything else is `405` with `Allow: GET, HEAD`.
- `/assets/*` (Vite's hashed output) gets `Cache-Control: public, max-age=31536000, immutable`.
  Everything else, in practice `index.html`, gets `no-cache`.
- One ETag per representation: `"<hash>"`, `"<hash>.br"`, `"<hash>.gz"`. `If-None-Match` is compared
  weakly (a `W/` prefix is ignored, `*` and lists are accepted) and ignoring the `.br`/`.gz`
  suffix, so any representation the client holds validates. A match returns `304` with no body.
  `Vary: accept-encoding` is set whenever the file has compressed variants.
- `Accept-Encoding` negotiation with q-values: the highest q wins, ties prefer br, then gzip, then
  identity; `*` covers codings not listed; `q=0` excludes; a missing header means identity. Files
  without variants are always sent as identity.
- `Content-Type` by file extension (`src/mime.rs`); text types carry `charset=utf-8`, unknown
  extensions are `application/octet-stream`.
- SPA fallback: a miss outside `/assets/` returns `index.html` with `200`. DDI routes contain FQDNs
  and IP addresses (`/dns/zones/example.com`, `/ipam/192.0.2.0/24`), so "the path has a dot" cannot
  tell a file from a route. A miss under `/assets/` (including `/assets` and `/assets/`) is `404`,
  so a missing hashed file never turns into HTML. `/api/*` misses are a JSON `404`, never the UI.
  There is no directory listing: directories are not entries of the table.
- Security headers on every response (UI, API, SSE, errors), unless a handler already set one:

  ```text
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
  ```

  HSTS is not set because the spike serves plain HTTP; a TLS deployment adds it.

## API and SSE

| Endpoint | Content |
| --- | --- |
| `GET /api/health` | `{"status":"ok","version":"<crate version>"}`, `Cache-Control: no-store` |
| `GET /api/events` | SSE with frames encoded once at publish time and one shared keep-alive timer |
| `GET /api/events/axum` | Same semantics through axum's `Sse` type, kept for comparison |
| `POST /api/events/emit` | Test hook: publishes an event to every subscriber |

`POST /api/events/emit` takes `Content-Type: application/json` and a body such as
`{"event":"lease.updated","data":{"ip":"192.0.2.10"}}`. The reply is `202` with
`{"id":<event id>,"receivers":<subscribers it was handed to>}`. `event` defaults to `message` and
`data` to `null`. The event name must match `[A-Za-z0-9._:-]{1,64}` (else `422` with a JSON error),
`data` is re-serialized as compact single-line JSON, and the API body limit is 64 KiB. This
endpoint is a test hook; a real product would not expose it unauthenticated.

Wire format of `/api/events`:

- The first bytes are `retry: 3000` and a `: connected` comment, followed by replay or a reset
  when the client sent `Last-Event-ID`.
- Event frames are `id: <n>`, `event: <name>`, `data: <json>` and a blank line.
- A `: keep-alive` comment every 15 s (`--keepalive-secs`) from one shared timer task.
- `event: reset` with `{"reason":"gap"}` when `Last-Event-ID` cannot be replayed (not a number,
  unknown, older than the ring, or from a previous process), or `{"reason":"lagged"}` when the
  client fell more than `--channel-capacity` events behind. The client refetches its state.
- `event: shutdown` with `{}` on graceful shutdown, after which the stream ends.

Design (`src/events.rs`):

- Each event is encoded once at publish into its SSE frame (`Bytes`). Fan-out to N clients is N
  refcount increments plus N socket writes; nothing is formatted per client.
- A `tokio::sync::broadcast` channel carries `Arc<EventRecord>`. A client that lags is sent a
  `reset` instead of being buffered without bound.
- A ring of the last 256 events (`--ring`) serves `Last-Event-ID` replay. Subscribing and taking the
  replay snapshot happen under the same lock that publish holds while it appends and sends, so a
  reconnecting client sees no gap and no duplicate.
- Event ids start at the boot time in microseconds since the Unix epoch, so ids keep increasing
  across restarts and an id from a previous process is detected as a gap.
- Optional coalescing (`--coalesce-ms <N>`, off by default): `publish` only queues the event and
  one flusher task broadcasts everything published within the tick as one `Batch`, so each client
  costs one wake-up and one socket write per tick instead of per event. Replay never goes past the
  last flushed id, so a queued event reaches a new subscriber exactly once, through the flush.
- `TCP_NODELAY` on accepted sockets (small writes would otherwise wait for Nagle and delayed ACK),
  a listen backlog of 4096 for reconnect storms (`SO_REUSEADDR` is not set on Windows), and the
  headers `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`.

`/api/events/axum` differs in that it uses axum's `Sse` with its per-connection `KeepAlive` timer
(fixed at 15 s) and builds an axum `Event` for every event for every client, so the formatting
cost grows with the number of clients. It has the same replay, reset and shutdown behaviour.

Graceful shutdown on ctrl-c: the hub broadcasts `shutdown`, every stream sends it and ends, new SSE
requests get `503`, and the server waits at most `--shutdown-grace-secs` before exiting anyway.

## Build, test, run

`ui/dist` must exist first (`build.rs` fails otherwise): `cd ../../ui && npm ci && npm run build`.
Cargo must be on `PATH`. Commands run from `bench/spike-c-embed/`, Git Bash syntax:

```sh
cargo test --bin spike-c-embed        # unit tests plus end-to-end tests on a real listener
cargo test --bin spike-c-embed --no-default-features --features backend-codegen,precompressed
cargo build --release                  # target/release/spike-c-embed(.exe) and measure(.exe)
target/release/spike-c-embed --listen 127.0.0.1:8080
```

The end-to-end tests cover the static rules (headers, 304, negotiation, HEAD, SPA fallback, 404
under `/assets`, JSON 404 under `/api`, 405), SSE on both endpoints (delivery, `Last-Event-ID`
replay, reset, graceful shutdown, with and without coalescing) and the `--ui-dir` mode. The second
command is the feature-matrix form; swap in `backend-include-dir` or `backend-rust-embed`, with
or without `precompressed`.

Server flags (`--help`): `--listen <ADDR>` (default `127.0.0.1:8080`), `--ui-dir <PATH>`,
`--workers <N>` (tokio worker threads, default logical CPUs), `--keepalive-secs <N>` (15),
`--channel-capacity <N>` (1024), `--ring <N>` (256), `--shutdown-grace-secs <N>` (10),
`--coalesce-ms <N>` (0, off). On start it prints
`listening on <addr> (ui: <backend and file counts>, init: <ms> ms)`.

```sh
curl -sI -H 'Accept-Encoding: br' http://127.0.0.1:8080/    # content-encoding, etag, vary, CSP
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/dns/zones/example.com   # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/assets/missing.js       # 404
curl -N http://127.0.0.1:8080/api/events
curl -N -H 'Last-Event-ID: <id>' http://127.0.0.1:8080/api/events
curl -s -X POST http://127.0.0.1:8080/api/events/emit -H 'Content-Type: application/json' \
  -d '{"event":"lease.updated","data":{"ip":"192.0.2.10"}}'
```

## Measuring

`scripts/build-variants.sh` builds 18 release variants into a separate target dir
(`target/variants`, so concurrent builds do not race with the copies) and copies them to
`results/raw/bin/<variant>.exe`. Names are `<backend>-<payload>[-large]`: backend `incdir`,
`rustembed` or `codegen`; payload `empty` (empty UI), `raw` (no compression), `pre` (build-time
brotli and gzip), `runtime` (include_dir with `runtime-compression`) or `deflate` (rust-embed
compression); `-large` marks the synthetic bundle. The synthetic bundle is a copy of `ui/dist`
plus one JavaScript file concatenated from three of Vite's own unminified Node chunks
(`ui/node_modules/vite/dist/node/chunks/{node,dist,build}.js`), about 1.8 MiB with the Vite
version installed at the time, as a stand-in for a grown app. Its exact size is reported by
`measure bundle`. The script ends by building `measure` and printing each startup line.

`scripts/run-measurements.sh [bundle binsize cold idle sse fanout http]` runs the sections (default
all) against those binaries. Each run writes `results/raw/<name>.log` whose last line is
`RESULT {json}`. The `measure` subcommands, one example each (add `--port` or `--server-arg=...`
as needed; `--help` lists everything):

```sh
measure cold-start --server spike-c-embed.exe --runs 10 --warmup 1
measure idle-rss   --server spike-c-embed.exe --wait-secs 10
measure sse-rss    --server spike-c-embed.exe --clients 100,1000,5000 --path /api/events
measure fanout     --server spike-c-embed.exe --clients 1000 --rate 100 --duration-secs 10
measure http-load  --server spike-c-embed.exe --path / --connections 64 --accept-encoding br
measure bundle     --dir ../../ui/dist
measure binsize    target/release/spike-c-embed.exe
```

`--addr 127.0.0.1:8080 --pid <pid>` replaces `--server` to attach to a running server.

Windows notes:

- Run under Git Bash with `MSYS_NO_PATHCONV=1` (the script sets it), otherwise arguments such as
  `--path /` are rewritten into Windows paths.
- Use `127.0.0.1`, not `localhost`. Client and server share the machine and compete for CPU.
- Process CPU time advances in scheduler ticks of 15.625 ms, so use windows of at least 10 s.
- The ephemeral port range limits how many SSE clients one client machine can hold open to the
  server; check it with `netsh int ipv4 show dynamicport tcp`.

## Development mode

The spike does not change `ui/`; these are the two development setups it would support.
**Frontend work with hot reload:** run the Rust server on `127.0.0.1:8080` and `npm run dev` in
`ui/`, with this addition merged into `ui/vite.config.ts` (which uses `vite-plugin-solid`,
`build.outDir: "dist"` and `target: "es2022"`):

```ts
server: {
  proxy: {
    "/api": { target: "http://127.0.0.1:8080" },
  },
},
```

- The browser talks only to the Vite origin, so the UI code uses relative URLs
  (`fetch("/api/...")`, `new EventSource("/api/events")`) that work unchanged in production.
- Vite's proxy streams `text/event-stream` responses. This was checked with Vite 8.3.4 and the
  standalone config `scripts/vite-proxy-check.config.mjs` (same proxy block, root and cache under
  `results/raw/`, so nothing in `ui/` is touched); see the results file.
- Do not set `changeOrigin` unless the server checks the Host header; the spike does not.
- Write `127.0.0.1` in the target, not `localhost`: on Windows `localhost` can resolve to `::1`,
  where a server bound to `127.0.0.1` does not listen.
- The Vite dev server does not apply the production CSP. Test the CSP against the embedded build
  before release.

**Backend work against a real UI build, without recompiling Rust:** run `npm run build -- --watch`
in `ui/` and `spike-c-embed --ui-dir ../../ui/dist` (relative to where the server is started).
`--ui-dir` serves from disk with tower-http `ServeDir`: `Cache-Control: no-cache` on everything,
`Last-Modified` and `If-Modified-Since`, the same fallback rules as the embedded mode,
precompressed `.br` and `.gz` siblings served when present, `..` in a path rejected (the request
falls back to `index.html`), and no directory listing. The server refuses to start if
`<dir>/index.html` is missing. The product should keep this flag but log loudly when it is used.

## Limitations of the spike

- HTTP/1.1 only (axum is built with `http1`), no TLS, no auth on any endpoint.
- The embedded handler ignores `Range` and `If-Modified-Since`.
- The synthetic bundle is unminified. Measurements come from one Windows machine, with client and
  server on the same host and other builds running concurrently. Linux was not measured.
- The tests and the measurement tool use raw TCP and hyper clients, not a browser `EventSource`.
- Only the proxy part of the Vite setup was checked (with the standalone config), not `vite dev`
  with the real `ui/vite.config.ts` and a browser.
