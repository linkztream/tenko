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
| WP1.4b Move API | In progress | worktree (`crates/tenko-ipam/src/moves.rs`, `routes/moves.rs`) | `POST /moves` dry run and submit: same host part or next free, steps ipam.intent, then the ticked tasks dhcp.manual or device.manual by mode and dns.manual, then l2.move (manual in Slice 1), observe (timeout: half the longest lease of the target's DHCP pools, else 3,600 s, minimum 300 s), cleanup; one job per object in a group with parallelism 2 by default (design decision 8), rollback on timeout; contract additions `Range.lease_secs` and `JobSpec.group_limit` landed in `04b2879` |
| WP1.5 Import and export | FINAL, committed locally | `9ecfe26` | 137 crate tests, 41 route tests, E1 round trip (export, re-import, zero changes), M11 (10,000 rows: upload and preview 1.0 to 1.7 s, apply 2.5 to 3.6 s in release); fixtures generated from `import-fixtures.md` kept byte-stable by `.gitattributes` |
| WP1.8 Server and CLI | FINAL, committed locally | `64c67a8` | 124 tests (125 with import), 36 client tests; `tenko.toml` documented in `deploy/tenko.example.toml`, precedence defaults, file, `TENKO_*`, flags; start order KEK, store, vault, TLS, auth, IPAM, jobs, API in 375 ms cold and 293 ms warm; exit codes in `exit.rs`; M9 pass (Windows 47.6 MiB working set, Linux 75.1 MiB RSS after 10 min idle with 200 prefixes) |
| WP1.8b CA root route | In progress | `routes/system.rs`, `crates/tenko` | `GET /system/ca-root` (PEM, internal CA mode only) and `tenko ca-root` for the setup wizard |
| WP1.9 UI shell, auth, setup | FINAL, committed locally | `4c3778c`, `0bebd53` | 552 tests in 26 files; first-load bundle 68.9 KB gzip; XLIFF 2.0 en/sv compiled at build; typed client from `docs/api/openapi.json` with drift check; msw mock API; the CI `ui` job now runs lint and test |
| WP1.10 UI IPAM, import, audit | In progress | worktree (`ui/`) | Started 2026-10-09 late evening: grid, IPAM, hosts, move preview, jobs, audit, dashboard, then import behind mocks until WP1.5 lands; TOTP QR code included; `ui/README.md` with the `data-testid` convention for WP1.11 |
| WP1.11 Acceptance and E2E | Not started | | After M3 |
| Design spike | Done, committed locally | `4880d8c` | All 16 owner decisions applied; mockups served from `design/` |

The committed tree compiles and `Cargo.lock` matches the committed manifests since `64c67a8`; the working tree carries WP1.4b, WP1.8b and WP1.10 in progress; each builder keeps its own crate compiling at every save, and the lead verifies the whole workspace at each merge.

## Conventions decided during Slice 1

- Authentication lives in `AppState` (`auth: Option<Arc<dyn Authenticator>>`, `authorizer: Option<Arc<dyn Authorizer>>`); `Ctx` resolves the session cookie or bearer token; public endpoints never take `Ctx`.
- Domain services are injected as `axum::Extension` layers by the server binary (`Arc<AuthService>`, `Arc<IpamService>`, `JobEngine`) through `ServerConfig::extensions`; handlers answer 503 or 501 while absent.
- Shared list helpers: `tenko_api::list::{Filters, PageParams, CursorScope, encode_cursor, …}` and `tenko_api::dto::Page`.
- SSE topics by table namespace: `ipam.*` → `ipam`, `jobs.*` → `jobs`, `import.*` → `import`, `sys.audit` → `audit`, `auth.alarms` and `ipam.alarms` → `system`, `auth.*` and `users.*` → `admin`; events carry references, ids are revisions.
- Every edit is an inline one-step job (`JobEngine::run_inline`), staged through `tenko_jobs::stage` in the handler's own batch.
- Secrets: `Vault::stage_put` in the same batch as the owning row; system keys never count for the PIN rule; the idempotency cache stores only a marker for `no-store` or `Set-Cookie` responses.
- Connectors are plugins (ADR 0012); Slice 2 starts with the SDK and host runner, UniFi first.
- Store data directory: `log.redb`, `sm-<id>.redb` and the pointer file `sm.current`; never copy one without the other, backups go through `current_snapshot()`. Re-seed when `disk_usage().state_ratio_at_open` exceeds about 2.0, or the running `sm_file_ratio` about 4 (redb grows a file by doubling), through `reseed_in_place()` or by rejoining with an empty data directory.
- Process: one owner per file; contract changes only through the lead; every builder uses its own `CARGO_TARGET_DIR` under `F:\`; a crate must compile at every save (in-progress modules behind a feature or a stub); the lead commits a package only after reading the test summary line, never on the exit status of a pipeline.

## Push state

Every commit on `main` after `02a6d96` is local. They are not pushed because CI runs `cargo … --locked` and the shared `Cargo.lock` carries the dependencies of the in-progress packages; pushing before their manifests are committed would turn CI red. Push happens after WP1.4b, WP1.4c, WP1.8b and WP1.10 are committed, with `docs/api/openapi.json` regenerated (`cargo run -p tenko -- openapi > docs/api/openapi.json`) and `cargo check --workspace --all-targets --all-features`, `cargo nextest run --workspace --all-features`, `cargo deny check`, `cargo audit` and the attribution grep green.

## Follow-ups recorded

- M7 (UI and SSE on Linux, two hosts, TLS, HTTP/2) and the M2 VM power cut belong to the Slice 3 run.
- `JobEngine` staging stays a task-local for Slice 1; an explicit sink on `StepContext` is added when a handler needs to stage from a spawned task.
- `password_change_required` is enforced only by the UI; the API enforcement is a Slice 2 item.
- The embedded UI server should send long-lived cache headers for `/fonts/` (hashed file names) once WP1.8 wires the static routes.
- TOTP enrolment shows the secret and the otpauth URI as text; a QR code is a WP1.10 item.
- WebAuthn: the relying-party id is the installation host name; pending ceremonies are in memory, so Slice 3 clustering needs sticky routing or replicated challenges; Hardened deployments should load vendor attestation roots (MDS3 in Slice 3).
- Plugin security (R16) and KEK directory trust (R15) stay open until the hub and the Slice 3 hardening.
- `tenko_core::ir` lacks interfaces by name, VRF and tenant names, prefix roles and secret references; WP1.5 keeps a superset `ImportModel` with `to_ir()`. The IR is extended (IrInterface, interface on IrAddress, vrf on IrNetwork and IrAddress, IrSecretRef) when the Slice 2 migration plugins need it.
- Credential columns of an import create operator secrets; the import requires `Action::Create` and `Action::Reveal` on `ObjectKind::Secret`, so only an administrator with a password-or-stronger session can import credentials. A dedicated action is considered when the vault gets its own API.
- The UI derives active utilization alarms from `GET /prefixes/tree` per VRF and refetches on `system` events; an alarm listing endpoint or a `level=` filter on `GET /prefixes` is a Slice 2 item.
- WP1.4c after the move API: `expand=host` on `GET /addresses` and `GET /prefixes/{id}/addresses` adding `interface { id, name, mac, duid }` and `host { id, name, mode, lock }` per row, so the address grids stop resolving rows one by one.
- The hand-written multipart parser of `POST /imports` gets a fuzz target when the fuzz harness arrives with the Phase 2 parsers (CONTRIBUTING rule on parsers of network input); until then its robustness rests on the route tests.
- Uploads to `POST /imports` are sent without `Idempotency-Key`: the idempotency middleware buffers keyed POSTs under a smaller limit than `max_upload`.
- Windows service: install, start and stop under the Service Control Manager were not exercised (needs an elevated shell); the Event Log sink is a Slice 3 item and the service logs to `<data_dir>ogs	enko.log` until then.
- systemd: the unit uses `LoadCredentialEncrypted=` with the `file` KEK provider; a systemd-credential protection kind in tenko-vault (Slice 3 hardening) removes the plain-file warnings. The root `systemd-creds encrypt` path was not run end to end.
- M9 margins: RSS grows about 14 KiB per prefix on Linux (86.4 MiB at 1,000 prefixes) and glibc keeps about 19 MiB of Argon2 buffers after the first login; an allocator trim or a compact index layout is needed before the 100 MB target holds at a few thousand prefixes.
- `reverse_proxy` mode: a client that speaks plain HTTP to the listener needs its origin in `server.allowed_origins` (documented in the example configuration).
