# Contributing to Tenko DDI

Tenko DDI is a DNS + DHCP + IPAM stack written in Rust. One binary runs any combination of
the `controller`, `dns`, `dhcp`, and `probe` roles, with a SolidJS web UI embedded in it.
It replaces Active Directory-integrated Windows DNS and DHCP and scales from a single
home-lab node to a multi-site enterprise deployment.

Read before changing anything substantial:

- `docs/ARCHITECTURE.md`: components, roles, data flow, failure model.
- `docs/REQUIREMENTS.md`: functional and non-functional requirements.
- `docs/adr/`: architecture decision records. An accepted ADR is never edited to change
  its decision; write a new ADR that supersedes it.

## Non-negotiable rules

1. **No tooling banners or attribution trailers.** Commit messages and pull requests carry
   no co-author or generator trailers of any kind; the author recorded by git is the only
   attribution. Code, comments, and docs carry no editor or generator banners. Treat this as
   a security requirement: the toolchain that produced the code is not advertised.
2. **Memory safety.** Every crate is `#![forbid(unsafe_code)]` (enforced through the
   workspace lints) unless an accepted ADR names the crate and the reason. Today no crate
   is exempt.
3. **Fuzz every network parser.** Every parser of network input ships with a fuzz target
   under `fuzz/` before it merges.
4. **Secrets never enter the repository.** Commit a `.env.example` instead of a `.env`.
   Test data uses documentation ranges only: RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), and RFC 7042 example MAC addresses.
5. **The data plane never depends on the control plane.** A `dns` or `dhcp` node keeps
   serving from its local store when every controller is down. Never add a controller
   round-trip to the query path, the DORA exchange, or the renew path.
6. **Security features are toggles, not code paths.** Insecure modes exist for lab use and
   must be loud in the UI and in the logs. Encryption of secrets at rest and audit logging
   are never disabled.

## Conventions

- Rust edition 2024 on the stable toolchain pinned in `rust-toolchain.toml`.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass; `cargo fmt` is
  enforced.
- Code, comments, commit messages, and docs are in English. UI strings are localized
  (`sv`, `en`).
- Conventional Commits, with crate short names as scopes: `feat(dns): …`, `fix(ipam): …`,
  `docs: …`, `chore: …`, `bench: …`.
- Small, focused commits. Never use `--no-verify`. Never amend or force-push a shared
  branch.
- `cargo deny check` and `cargo audit` are CI gates.
- Public API types derive `utoipa::ToSchema`. The OpenAPI document is generated, never
  edited by hand.
- Measure before optimizing. Benchmarks and their results live in `bench/`; a performance
  claim in a pull request links to a result file.
- Every RFC behaviour that is implemented or deliberately skipped is recorded in
  `docs/CONFORMANCE.md`.

## Workspace layout

| Crate                   | Purpose                                                              |
|-------------------------|----------------------------------------------------------------------|
| `tenko-core`            | Shared data model (IPAM tree, zones, leases, policies), migration IR |
| `tenko-store`           | Raft-replicated store, embedded KV, snapshots, local cache           |
| `tenko-cluster`         | Node-to-node gRPC over mTLS, enrolment, internal CA                  |
| `tenko-auth`            | Users, passkeys, TOTP, password policy presets, RBAC, sessions       |
| `tenko-vault`           | Envelope encryption, KEK providers (DPAPI, keyring, PKCS#11)         |
| `tenko-ipam`            | Address tree, intent/observation reconciler, import/export           |
| `tenko-scan`            | Probe role: passive/active discovery, SNMP polling                   |
| `tenko-dns`             | Authoritative, forwarder/cache, RPZ, XFR, views                      |
| `tenko-dhcp`            | DHCPv4/v6, failover, relay handling, DDNS                            |
| `tenko-jobs`            | Job engine: steps, state, timeouts, rollback                         |
| `tenko-connect`         | Connector plugin SDK: protocol, host runner, helper library, manifest, conformance test |
| `tenko-connect-proxmox` | Proxmox VE connector (stub)                                          |
| `tenko-connect-unifi`   | UniFi connector (stub)                                               |
| `tenko-connect-hass`    | Home Assistant connector (stub)                                      |
| `tenko-connect-windows` | Windows DNS/DHCP Server connector (stub)                             |
| `tenko-migrate`         | Plan/apply/verify migration pipeline over connectors                 |
| `tenko-api`             | axum HTTP API, OpenAPI, SSE                                          |
| `tenko`                 | The single binary: `tenko serve --roles …` and the API client commands |

Other top-level directories: `ui/` (SolidJS web UI), `fuzz/` (fuzz targets), `bench/`
(spikes and benchmarks, excluded from the workspace), `deploy/` (container, systemd and
Windows service templates), `docs/` (architecture, requirements, roadmap, ADRs).

## Commands

```sh
cargo build --workspace
cargo nextest run --workspace        # fallback: cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
cargo audit
cargo run -p tenko -- serve --roles controller,dns --data-dir <dir>
cd ui && npm ci && npm run build
```

Rust-only builds use a placeholder UI page: set `TENKO_UI_STUB=1` when `ui/dist` has not been built (CI does this for its Rust jobs). Release builds refuse the placeholder.
