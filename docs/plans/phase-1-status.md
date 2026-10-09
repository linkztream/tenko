# Phase 1 status

- Date: 2026-10-09 (evening)
- Scope: the execution state of `phase-1-execution.md`. This file is the hand-over point: whoever continues reads it first, then the plan, then the ADRs.

## Slice 1 work packages

| WP | State | Where | Notes |
|---|---|---|---|
| WP1.0 Contracts and skeleton | Merged, pushed, CI green | `02a6d96` on `origin/main` | 245 tests; conformance suite in `tenko_store::testing` |
| Lead additions | Committed locally | `c7b3fe9`, `30df64d`, `0888fa1`, `0aa018d`, `78137df`, `c22c988` | `tenko_core::auth` contract, `AppState` auth/authorizer, `StoreStatus` fsync and re-seed fields, CBOR large-value fix, `AuthStrength::as_str`, `ServerConfig::extensions`, `RunningServer::run_until` |
| WP1.6 Job engine | FINAL, committed locally | `d2a895d`, `7c3703d` | 80 tests in the crate, 37 route tests; model additions applied (client-error variants, manual deadline, `Job.started`) |
| WP1.3 Vault and CA | FINAL, committed locally | `6b7381f` | 195 tests on Windows, 207 in WSL; KEK rotation epoch; DPAPI via a safe wrapper; three TLS modes |
| WP1.7 API platform | FINAL, committed locally | `86cefb9`, `636e97b`, `c22c988` | 328 tests; idempotency never stores secret-bearing responses; `docs/api/openapi.json` generated |
| WP1.2 Authentication | FINAL, committed locally | `0e1e4ad` | 438 tests + 45 route tests; ADR 0010 (in-house WebAuthn on aws-lc-rs); HIBP fixtures keep CRLF (`.gitattributes`) |
| WP1.1 Store | FINAL, committed locally | `5085010` | 102 tests, conformance 26/26 on `RaftStore`, 120 crash kills clean; M1, M2, M5, M10 pass, M6 fails at defaults (2.05x and 2.74x) |
| WP1.1b Store follow-up | FINAL, committed locally | `b38a92e` | 107 tests, conformance 26/26; a snapshot install writes a fresh `sm-<id>.redb` behind the `sm.current` pointer; `RaftStore::reseed_in_place`; journal bounded by bytes (32 MiB default); M6 at rest 1.26x and 1.24x of raw (was 2.05x and 2.74x), M1 pass at 1 M and 6 M records, 120 crash kills clean |
| WP1.4 IPAM domain | FINAL, committed locally | `573dd70` | 107 domain tests, 255 route tests, 83 operations, none at 501; the commit carries `crates/tenko-ipam/Cargo.toml` and `src/lib.rs` without WP1.5's lines, which land with WP1.5. Known limits: lists scan the table and sort in memory; a supernet's address list includes the addresses of its child prefixes |
| WP1.4b Move API | FINAL, committed locally | `b7ad7e2` | `POST /moves` dry run and submit (one operation `create_move`); 8 domain tests, 8 route tests; a host moves every live address outside the target in the same family, one job per address in a group; steps ipam.intent, dhcp.manual (reserved) or device.manual (static), dns.manual, l2.move (manual in Slice 1), observe (timeout from the request, half the longest pool lease, or 3,600 s; `timeout_source` enum), cleanup; rollback tags the object `move-failed`; receipts in `ipam.move_receipts`; `lease_secs` validated on DHCP pools |
| WP1.4c Host expansion | FINAL, committed locally | `b7ad7e2` | `expand=host` on `GET /addresses` and `GET /prefixes/{id}/addresses` adds `interface_detail { id, name, mac?, duid? }` and `host { id, name, mode, lock }` per bound address, resolved once per page; `Page_Address` became `Page_AddressRow`; 5 tests |
| WP1.5 Import and export | FINAL, committed locally | `577a01d` | 137 crate tests, 41 route tests, E1 round trip (export, re-import, zero changes), M11 (10,000 rows: upload and preview 1.0 to 1.7 s, apply 2.5 to 3.6 s in release); fixtures generated from `import-fixtures.md` kept byte-stable by `.gitattributes` |
| WP1.8 Server and CLI | FINAL, committed locally | `7f8a2f1` | 124 tests (125 with import), 36 client tests; `tenko.toml` documented in `deploy/tenko.example.toml`, precedence defaults, file, `TENKO_*`, flags; start order KEK, store, vault, TLS, auth, IPAM, jobs, API in 375 ms cold and 293 ms warm; exit codes in `exit.rs`; M9 pass (Windows 47.6 MiB working set, Linux 75.1 MiB RSS after 10 min idle with 200 prefixes) |
| WP1.8b CA root route | FINAL, committed locally | `69ec08e` | `GET /system/ca-root` (PEM, one hour public cache, 404 `tls.no_internal_ca` outside internal CA mode), fingerprint printed at readiness, `tenko ca-root [--fingerprint]`; 4 route tests, 4 CLI tests |
| WP1.9 UI shell, auth, setup | FINAL, committed locally | `4c3778c`, `0bebd53` | 552 tests in 26 files; first-load bundle 68.9 KB gzip; XLIFF 2.0 en/sv compiled at build; typed client from `docs/api/openapi.json` with drift check; msw mock API; the CI `ui` job now runs lint and test |
| WP1.10 UI IPAM, import, audit | FINAL, committed locally | `fa95cae` | 1,485 tests in 67 files; first load 63.9 KB gzip with message packs per route; grid, IPAM, hosts, move preview, jobs, audit, dashboard, import wizard and export, CA root link, TOTP QR code (`uqr`, MIT); `data-testid` convention and layout in `ui/README.md` |
| WP1.11 Acceptance and E2E | FINAL, committed locally | `b21d9a5` | 137 server tests (8 new acceptance files), 23 Playwright scenarios passing plus 2 `test.fixme` waiting for WP1.4d and WP1.10b, no flakes over three repeats; E1 and E3 verified automatically, E2 for PIN, TOTP and a virtual-authenticator passkey (hardware key, imported certificate and HAProxy stay manual), the manual-step parts of E8; `e2e` CI job added |
| WP1.4d Default tenant and VRF at setup | FINAL, committed locally | `23d6be5` | `IpamService::ensure_defaults` through the planner's first-use path; called by `POST /setup` as the setup principal and by `tenko serve` at start when setup is closed; failures log a warning; 1 route test, 2 domain tests |
| WP1.10b UI fixes from E2E | FINAL, committed locally | `5997eed` | Host form sends only changed custom values (`null` clears); import preview shows the outcome per sheet, pages every listable row in a grid, loads all rows before apply; 1,495 UI tests; first load 64.1 KB gzip |
| WP1.5c Paged preview rows | FINAL, committed locally | `46037b2` | `GET /imports/{id}/rows?limit&cursor` from the stored, encrypted preview; 409 `import.preview.stale` on a mapping change; `CredentialNotice.reason` is a code, text in `detail`; 4 route tests |
| WP1.10c Preview paging in the UI | FINAL, committed locally | see the commit "page the import preview rows through the rows endpoint" | Cursor paging through `GET /imports/{id}/rows`, walk to the end before apply, restart on `import.preview.stale`; 1,502 UI tests; first load 64.1 KB gzip |
| WP1.11b E2E follow-up | FINAL, committed locally | the commit "first prefix on a fresh installation, cleared custom values, per-sheet outcomes and every linked import item" | The two former `test.fixme`s run; per-sheet outcomes and every created link are asserted against `ip-plan.expected.json`; 25 Playwright scenarios, no flakes over three repeats |
| Design spike | Done, committed locally | `4880d8c` | All 16 owner decisions applied; mockups served from `design/` |

## Slice 2 work packages

| WP | State | Where | Notes |
|---|---|---|---|
| WP2.10 Releases, upgrades, modules | In progress | `crates/tenko/src/{upgrade,modules.rs}`, `crates/tenko-store/src/format.rs`, `CHANGELOG.md`, `ui/src/updates` | Started 2026-10-09 night; OPS-23, OPS-24, OPS-25, TGL-23; CI and release workflow steps come as contract requests to the lead |
| WP2.0 Plugin SDK and host | FINAL, committed locally | `e3e0482` | Protocol `tenko.connect.v1` (handshake over stdio, gRPC over a private socket or pipe), manifest with settings schema and secret purposes, host supervisor with backoff and circuit breaker, per-call secret injection with audit, conformance suite, `tenko plugin list|run|test`, sample plugin bundled, connector API with inline edit jobs and run jobs, `connectors` start step and SSE topic; 226 crate tests, 5 route tests, an end-to-end CLI test; `docs/plugins.md` |
| WP2.4 Reconciler | Next | | After WP1.11 reports |
| WP2.6 UniFi, WP2.5 Proxmox and Home Assistant | Waiting for the owner | | Need the UniFi API key or local admin and the Proxmox token |

The committed tree compiles and `Cargo.lock` matches the committed manifests since `7f8a2f1`; every Slice 1 package is committed; each builder keeps its own crate compiling at every save, and the lead verifies the whole workspace at each merge.

## Conventions decided during Slice 1

- Authentication lives in `AppState` (`auth: Option<Arc<dyn Authenticator>>`, `authorizer: Option<Arc<dyn Authorizer>>`); `Ctx` resolves the session cookie or bearer token; public endpoints never take `Ctx`.
- Domain services are injected as `axum::Extension` layers by the server binary (`Arc<AuthService>`, `Arc<IpamService>`, `JobEngine`) through `ServerConfig::extensions`; handlers answer 503 or 501 while absent.
- Shared list helpers: `tenko_api::list::{Filters, PageParams, CursorScope, encode_cursor, …}` and `tenko_api::dto::Page`.
- SSE topics by table namespace: `ipam.*` → `ipam`, `jobs.*` → `jobs`, `import.*` → `import`, `sys.audit` → `audit`, `auth.alarms` and `ipam.alarms` → `system`, `auth.*` and `users.*` → `admin`; events carry references, ids are revisions.
- Every edit is an inline one-step job (`JobEngine::run_inline`), staged through `tenko_jobs::stage` in the handler's own batch.
- Secrets: `Vault::stage_put` in the same batch as the owning row; system keys never count for the PIN rule; the idempotency cache stores only a marker for `no-store` or `Set-Cookie` responses.
- Connectors are plugins (ADR 0012); Slice 2 starts with the SDK and host runner, UniFi first.
- Store data directory: `log.redb`, `sm-<id>.redb` and the pointer file `sm.current`; never copy one without the other, backups go through `current_snapshot()`. Re-seed when `disk_usage().state_ratio_at_open` exceeds about 2.0, or the running `sm_file_ratio` about 4 (redb grows a file by doubling), through `reseed_in_place()` or by rejoining with an empty data directory.
- Binary fixtures are platform-neutral: zip-based files (xlsx, ods) are written with a fixed host byte, times, modes and deflate level, and a test proves byte equality across a pause; the first Linux CI run of Slice 1 failed on the Windows host byte in `ip-plan.xlsx` (fixed in `0429146`).
- Process: one owner per file; contract changes only through the lead; every builder uses its own `CARGO_TARGET_DIR` under `F:\`; a crate must compile at every save (in-progress modules behind a feature or a stub); the lead commits a package only after reading the test summary line, never on the exit status of a pipeline.

## Push state

`main` was pushed to `origin` at `f4eac91` on the night of 2026-10-09 after the full locked verification (check, fmt, clippy, 2,046 Rust tests, deny, audit) and the embedded-UI build with 817 API and server tests in the clean worktree. Later pushes follow the same gate: the clean-worktree verification first, with `docs/api/openapi.json` regenerated (`cargo run -p tenko -- openapi > docs/api/openapi.json`) and `cargo check --workspace --all-targets --all-features`, `cargo nextest run --workspace --all-features`, `cargo deny check`, `cargo audit` and the attribution grep green. A second push at `b5c7953` followed on the night of 2026-10-09 after the gate with the browser suite (23 Playwright scenarios, 826 API and server tests, 1,495 UI tests). Further pushes: `6fb4a9b` and `0cadcab` (CI hardening) and `82c28df` (WP2.0 with its lockfile `8fcb7b7`), each after the clean-worktree gate.

## Follow-ups recorded

- M7 (UI and SSE on Linux, two hosts, TLS, HTTP/2) and the M2 VM power cut belong to the Slice 3 run.
- `JobEngine` staging stays a task-local for Slice 1; an explicit sink on `StepContext` is added when a handler needs to stage from a spawned task.
- `password_change_required` is enforced only by the UI; the API enforcement is a Slice 2 item.
- The embedded UI server should send long-lived cache headers for `/fonts/` (hashed file names) once WP1.8 wires the static routes.
- WebAuthn: the relying-party id is the installation host name; pending ceremonies are in memory, so Slice 3 clustering needs sticky routing or replicated challenges; Hardened deployments should load vendor attestation roots (MDS3 in Slice 3).
- Plugin security (R16) and KEK directory trust (R15) stay open until the hub and the Slice 3 hardening.
- `tenko_core::ir` lacks interfaces by name, VRF and tenant names, prefix roles and secret references; WP1.5 keeps a superset `ImportModel` with `to_ir()`. The IR is extended (IrInterface, interface on IrAddress, vrf on IrNetwork and IrAddress, IrSecretRef) when the Slice 2 migration plugins need it.
- Credential columns of an import create operator secrets; the import requires `Action::Create` and `Action::Reveal` on `ObjectKind::Secret`, so only an administrator with a password-or-stronger session can import credentials. A dedicated action is considered when the vault gets its own API.
- The UI derives active utilization alarms from `GET /prefixes/tree` per VRF and refetches on `system` events; an alarm listing endpoint or a `level=` filter on `GET /prefixes` is a Slice 2 item.
- The hand-written multipart parser of `POST /imports` gets a fuzz target when the fuzz harness arrives with the Phase 2 parsers (CONTRIBUTING rule on parsers of network input); until then its robustness rests on the route tests.
- Uploads to `POST /imports` are sent without `Idempotency-Key`: the idempotency middleware buffers keyed POSTs under a smaller limit than `max_upload`.
- Windows service: install, start and stop under the Service Control Manager were not exercised (needs an elevated shell); the Event Log sink is a Slice 3 item and the service logs to `<data_dir>ogs	enko.log` until then.
- systemd: the unit uses `LoadCredentialEncrypted=` with the `file` KEK provider; a systemd-credential protection kind in tenko-vault (Slice 3 hardening) removes the plain-file warnings. The root `systemd-creds encrypt` path was not run end to end.
- M9 margins: RSS grows about 14 KiB per prefix on Linux (86.4 MiB at 1,000 prefixes) and glibc keeps about 19 MiB of Argon2 buffers after the first login; an allocator trim or a compact index layout is needed before the 100 MB target holds at a few thousand prefixes.
- `reverse_proxy` mode: a client that speaks plain HTTP to the listener needs its origin in `server.allowed_origins` (documented in the example configuration).
- Connectors (WP2.0 open items): no webhook ingress route yet (`POST /connectors/{id}/webhook`); observations are discarded until WP2.4 supplies the `ObservationSink`; in a cluster every controller would run every instance (leader-only or ownership scheduling in Slice 3); network targets are declarations without egress enforcement (R16); rate limiting is 4 concurrent calls, 60 s minimum poll interval and serialized runs; one audit record per secret-bearing call; actuator and migration capabilities are reachable only as typed host calls; Windows named pipes keep the default DACL (no unsafe FFI).
- Jobs API: the kind of the current step in `JobSummary` and a job-group filter on `GET /jobs` would remove two derivations in the UI (Slice 2, with the job engine work).
- Some UI tests assert the Swedish rendering of keys, following the WP1.9 precedent; acceptable while the two languages ship together, revisit when language packs become runtime files (API-21).
- `GET /api/v1/openapi.json` serves compact JSON while `docs/api/openapi.json` is pretty-printed; byte equality holds for the printed form only (`tenko openapi`). Decide whether the route should serve the committed bytes.
- A cancelled move job ends in state `cancelled`, not `rolled_back`, although its compensation ran (new intent removed, old address kept, host tagged `move-failed`); the jobs UI should present it as rolled back by cancellation.
- Disk: on the night of 2026-10-09 `F:` filled up completely (per-builder target directories of tens of GB each) and broke the linker in the verification worktree; the finished builders' directories were removed (139 GB free afterwards). Check `df -h /f` before starting a builder and remove a builder's target directory when its package closes. `C:` has about 19 GB free.
- CI: the Linux runner also ran out of disk during the OpenAPI drift step and the Docker-based cargo-deny action could not pull its image; `0cadcab` frees runner disk, builds debug artifacts with `line-tables-only`, runs the drift check in the embedded-UI job and installs cargo-deny as a binary.
