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
- `SECURITY.md`: how to report a vulnerability privately; never in a public issue.
- `CODE_OF_CONDUCT.md`: the Contributor Covenant, which applies in every project space.

## Non-negotiable rules

When two choices stand against each other, this order decides: **security, then
performance, then usability, then features**. A change that improves a later item at the
cost of an earlier one is refused; a review or a design question that weighs options says
where each option stands in this order. The rules below are that order applied.

1. **No tooling banners or attribution trailers.** Commit messages and pull requests carry
   no co-author or generator trailers of any kind. The author recorded by git and the
   `Signed-off-by` trailer required by the Contributor License Agreement (see "Licensing
   and the Contributor License Agreement" below) are the only attribution. Code, comments,
   and docs carry no editor or generator banners. Treat this as a security requirement: the
   toolchain that produced the code is not advertised.
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
- `cargo deny check` and `cargo audit` are CI gates. Every job runs on GitHub-hosted
  runners (`.github/workflows/ci.yml`).
- Public API types derive `utoipa::ToSchema`. The OpenAPI document is generated, never
  edited by hand.
- Measure before optimizing. Benchmarks and their results live in `bench/`; a performance
  claim in a pull request links to a result file.
- Every RFC behaviour that is implemented or deliberately skipped is recorded in
  `docs/CONFORMANCE.md`.
- A change under `crates/` or `ui/src/` comes with an entry under `## [Unreleased]` in
  `CHANGELOG.md` (`node scripts/changelog.mjs check --base origin/main`). A change nothing a
  user can see, such as a test inside a source file, carries the pull request label
  `no-changelog` or, on a push, a line `Changelog: none` in its commit message.

## Licensing and the Contributor License Agreement

Tenko DDI is source-available under the Business Source License 1.1 (`LICENSE.md`): free
to use and modify for your own networks, not to be embedded, packaged, hosted or sold
as part of a commercial product or service without a separate agreement. Every version
becomes available under the Change License named in `LICENSE.md` four years after its
release. The licensor also sells commercial licences; to keep that possible while the
source is open to contributions, every contribution is accepted under the Contributor
License Agreement in `CLA.md`. You keep the copyright in what you write and grant the
licensor the right to distribute it under the project's licences, including commercial
ones.

What this means for a pull request:

- **Accept the CLA once before your first pull request is merged.** Individuals put the
  acceptance sentence from `CLA.md`, Part D.1, in the description of their first pull
  request. Companies and other entities have an authorised representative send the
  completed Schedule 1 from `CLA.md`, Part B, to the contact named there, and each of
  their contributors uses the sentence from Part D.2 instead.
- **Sign off every commit.** Each commit carries a `Signed-off-by: Full Name <email>`
  trailer (`git commit -s`) with your real name and the email of the commit's author
  field. The trailer certifies that the commit is covered by the CLA you accepted.
  Pull requests with unsigned commits are not merged, and maintainers merge in a way that
  keeps the trailers (merge commit or rebase; no squash that drops them).
- **Third-party code is declared, and only permissive.** Name the source and licence of
  anything you did not write yourself in the pull request. Dependencies must carry a
  licence on the allow list in `deny.toml`; `cargo deny check` enforces it. No code or
  snippets copied into the repository under the GPL, AGPL, SSPL or another copyleft
  licence, in any amount. MPL-2.0 is accepted only as an unmodified dependency, and a new
  one is reviewed in its pull request before it is accepted.
- **No per-file licence headers.** `LICENSE.md` governs the whole repository; files carry
  no licence or copyright banner (API-13).
- **Only contribute what you may license.** Code you wrote for an employer or a customer
  needs their permission or their entity CLA; see `CLA.md`, Part A.4.

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
| `tenko-connect-proxmox` | Proxmox VE connector (inventory, bundled plugin)                    |
| `tenko-connect-unifi`   | UniFi connector (network controller and inventory, bundled plugin)  |
| `tenko-connect-hass`    | Home Assistant connector (inventory, bundled plugin)                |
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
cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl   # the Linux release binary (needs musl-tools); a host-target release build is glibc and is neither shipped nor measured
cargo nextest run --workspace        # fallback: cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
cargo audit
cargo run -p tenko -- serve --roles controller,dns --data-dir <dir>
cd ui && npm ci && npm run build
```

Development and test builds carry line tables for the workspace crates and no debug information for dependencies (`[profile.dev]` in `Cargo.toml`), so backtraces name the file and line in Tenko's own code while the build output stays small. For a debugger session with full information build with `--profile dev-full`, for example `cargo test -p tenko-ipam --profile dev-full`; its output lands under `target/dev-full/`.

Rust-only builds use a placeholder UI page: set `TENKO_UI_STUB=1` when `ui/dist` has not been built (CI does this for its Rust jobs). Release builds refuse the placeholder.

## Continuous integration

The workflows live in `.github/workflows/`: `ci.yml` on every push and pull request, `codeql.yml` (code scanning, reporting only) on pull requests and weekly, `release.yml` for a tag. The security checks among them are layer 1 of `docs/plans/security-audit-plan.md`.

- **Actions are pinned to a commit.** Every `uses:` names a full 40-character commit SHA with its tag in a trailing comment: `uses: actions/checkout@<sha> # v5.1.0`. Resolve the SHA from the tag, never from memory: `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, and when that returns an object of type `tag` (an annotated tag), `gh api repos/<owner>/<repo>/git/tags/<sha>` for the commit it points at. The same action is pinned to the same SHA everywhere. An action without release tags (`dtolnay/rust-toolchain`) is pinned to a commit of its default branch, with the branch in the comment and the toolchain as an input. Every `actions/checkout` sets `persist-credentials: false` unless a later step pushes.
- **Pins are updated by Dependabot.** `.github/dependabot.yml` opens one grouped pull request a week for the GitHub Actions, taking a release only when it is a week old; it moves the SHA and the comment together. Review it like any dependency change: read what changed in each action. Cargo and npm get no version pull requests; their advisories are covered by `cargo audit`, `cargo deny`, `npm audit` and Dependabot's security updates.
- **zizmor lints the workflows** (job `workflow-lint`, when a change touches `.github/`). A finding of High severity fails the job; the others are listed in the job summary. Fix a finding where you can. When it is a false positive or an accepted risk, suppress it in `.github/zizmor.yml` under `rules.<audit>.ignore`, as narrowly as possible (`<file>:<line>` rather than a whole file), with a comment that gives the reason and, for a temporary entry, what removes it. Never suppress a finding without a reason.
- **CodeQL ignores test, bench and fuzz paths.** `.github/codeql/config.yml` lists the paths code scanning does not analyse (integration tests, `testing` modules, `bench/`, `fuzz/`, `ui/e2e/`, the UI's dev mock and unit tests, `design/`); add a new class of test or benchmark code there, with a one-line reason. A product alert is answered in the security report (`docs/security/README.md`, one finding per rule and crate) and is never dismissed without a reason.
- **The unit's hardening has gates** (job `unit-check`, when a change touches `deploy/systemd/`, `deploy/install.sh` or `ci.yml`). `deploy/systemd/check-hardening.sh` scores `tenko.service` alone and with each drop-in with `systemd-analyze security --offline=true` and fails when a score reaches its gate: the score measured with systemd 255 plus 0.1 (the unit 1.5, the drop-ins `probe.conf` and `dhcp-direct.conf` 1.7, the installer's data-directory and key-file drop-ins 1.5, all of them at once 1.7). Run it with `bash deploy/systemd/check-hardening.sh` on any Linux host with systemd 250 or later, no root needed. A new drop-in needs its gate in the script, and a deliberate change that moves a score changes the gate in the same commit, with the reason.
- **Dependencies.** `npm audit --omit=dev --audit-level=high` in the UI job fails on a High or Critical advisory against a production dependency of the UI; the full `npm audit` is reported beside it. On a pull request, the dependency review fails on a new dependency with a High or Critical advisory or with a licence outside the allow list of `deny.toml`.
