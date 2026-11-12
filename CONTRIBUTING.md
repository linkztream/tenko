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
- English means American English, with Merriam-Webster's first spelling where it lists two:
  code identifiers, API and CLI names, configuration keys, error codes, UI text, docs,
  comments, commit messages and the changelog (`enroll`, `canceled`, `neighbor`,
  `behavior`, `license`, `normalize`). The standards Tenko implements (RFC 7030, RFC 9156,
  RFC 9432) and the products it sits beside write American English, and a mixed text reads
  as careless. `node scripts/spelling.mjs` checks the tracked files and runs in CI. What
  stays: third-party text and data (`crates/tenko-scan/data/oui.tsv`, dependency licenses,
  quoted standards, proper names, URLs, dependency names); an old spelling kept so that an
  old client, configuration or data file still works, marked `spelling: alias` with the
  version in which it goes away; stored key bytes, marked `spelling: stored key`; git
  history and published release texts.
- Tests follow the standing rules of `docs/testing/rules.md`: no sleep as synchronization, no
  wait limit under 10 s, no assertion on a duration, no wall clock in an expectation, no port
  found by binding and dropping, no retries or `.only`, a runner named for every skipped test
  and early return, a refusal asserted by its code. `node scripts/test-lint.mjs` checks them
  against the baseline `scripts/test-lint.baseline.json` and runs in CI; whoever fixes a test
  removes its baseline entry in the same commit (`--prune`).
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
- Every RFC behavior that is implemented or deliberately skipped is recorded in
  `docs/CONFORMANCE.md`.
- A change under `crates/` or `ui/src/` comes with an entry under `## [Unreleased]` in
  `CHANGELOG.md` (`node scripts/changelog.mjs check --base origin/main`). A change nothing a
  user can see, such as a test inside a source file, carries the pull request label
  `no-changelog` or, on a push, a line `Changelog: none` in its commit message.
  While a version is being released and not yet published, its entries go under its own
  section (the version in `crates/tenko/Cargo.toml`), which the check counts as open until
  the version is bumped.

## Licensing and the Contributor License Agreement

Tenko DDI is source-available under the Business Source License 1.1 (`LICENSE.md`): free
to use and modify for your own networks, not to be embedded, packaged, hosted or sold
as part of a commercial product or service without a separate agreement. Every version
becomes available under the Change License named in `LICENSE.md` four years after its
release. The licensor also sells commercial licenses; to keep that possible while the
source is open to contributions, every contribution is accepted under the Contributor
License Agreement in `CLA.md`. You keep the copyright in what you write and grant the
licensor the right to distribute it under the project's licenses, including commercial
ones.

What this means for a pull request:

- **Accept the CLA once before your first pull request is merged.** Individuals put the
  acceptance sentence from `CLA.md`, Part D.1, in the description of their first pull
  request. Companies and other entities have an authorized representative send the
  completed Schedule 1 from `CLA.md`, Part B, to the contact named there, and each of
  their contributors uses the sentence from Part D.2 instead.
- **Sign off every commit.** Each commit carries a `Signed-off-by: Full Name <email>`
  trailer (`git commit -s`) with your real name and the email of the commit's author
  field. The trailer certifies that the commit is covered by the CLA you accepted.
  Pull requests with unsigned commits are not merged, and maintainers merge in a way that
  keeps the trailers (merge commit or rebase; no squash that drops them).
- **Third-party code is declared, and only permissive.** Name the source and license of
  anything you did not write yourself in the pull request. Dependencies must carry a
  license on the allow list in `deny.toml`; `cargo deny check` enforces it. No code or
  snippets copied into the repository under the GPL, AGPL, SSPL or another copyleft
  license, in any amount. MPL-2.0 is accepted only as an unmodified dependency, and a new
  one is reviewed in its pull request before it is accepted.
- **No per-file license headers.** `LICENSE.md` governs the whole repository; files carry
  no license or copyright banner (API-13).
- **Only contribute what you may license.** Code you wrote for an employer or a customer
  needs their permission or their entity CLA; see `CLA.md`, Part A.4.

## Workspace layout

| Crate                   | Purpose                                                              |
|-------------------------|----------------------------------------------------------------------|
| `tenko-core`            | Shared data model (IPAM tree, zones, leases, policies), migration IR |
| `tenko-store`           | Raft-replicated store, embedded KV, snapshots, local cache           |
| `tenko-cluster`         | Node-to-node gRPC over mTLS, enrollment, internal CA                  |
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
| `tenko-net`             | Network rules a published standard defines (address classes, reverse names) |
| `tenko-api`             | axum HTTP API, OpenAPI, SSE                                          |
| `tenko`                 | The single binary: `tenko serve --roles …` and the API client commands |

Other top-level directories: `ui/` (SolidJS web UI), `fuzz/` (fuzz targets), `bench/`
(spikes and benchmarks, excluded from the workspace), `deploy/` (container, systemd and
Windows service templates), `docs/` (architecture, requirements, roadmap, ADRs).

## Where shared code lives

A fact (a rule, a limit, a name, a helper) is written in one place, and everything else
reads it there. A second copy drifts from the first sooner or later, and then two parts of
the product disagree. The places that hold shared code are called homes; each has a charter
that says what belongs there.

### Before you write a helper

1. **Look first.** Before you write a helper, a constant, a limit, a validation, an error
   code or a metric name, read the index below and search the home it names. If the thing
   exists, use it.
2. **Add it to its home without asking** when it fits the home's charter and only adds: a
   new function, constant, type or module, or a new variant that only your code produces.
   Give it a doc comment that names the rule and its source (an RFC, a requirement in
   `docs/REQUIREMENTS.md`, an ADR), put its unit tests in the home, and in the same pull
   request replace every copy of the same fact in the files your change touches. The
   reviewers of the pull request check the addition against the charter.
3. **Ask the maintainers first** (in an issue, or at the top of your pull request) before
   you change what an existing shared item does or its signature, create a new home, put
   something outside a home's charter, or change a stored format.
4. **`tenko-core` is a home too, with one more step.** Every other crate of the workspace
   is rebuilt when it changes, so the first line of a pull request that changes
   `tenko-core` says so; the maintainers merge it ahead of other open changes. Put a helper
   in `tenko-core` only when a type there needs it; otherwise it goes to the lowest crate
   that every caller already depends on.
5. **A home's module list is append-only.** In the list of modules and re-exports of a home
   (`lib.rs`, `mod.rs`, `index.ts`) and in the target list of `fuzz/Cargo.toml`, add your
   line and never edit or reorder another; parallel changes then merge without a conflict
   that needs a person.

`node scripts/copy-lint.mjs` reports a copy of a fact that a home holds (see "The copy lint"
below).

### The homes

| Home | Charter | Example of what belongs there |
|---|---|---|
| `crates/tenko-net` | Network rules a published standard defines, over `std::net` and `ipnet` types; no workspace crate, no setting, no input or output | Is this address link-local? The reverse name of an address |
| `crates/tenko-core` | Contracts between crates: identifiers, principals, the stored models, the error trait and code lists, the codecs, the metrics registry, test support; never code that only one or two crates use, never a default an operator can set | Hexadecimal and base64 text forms; the `Coded` error trait |
| `crates/tenko-store`: `layout`, `fs`, `follow`, `feed`, `codes` | Everything that puts bytes durably on disk or follows what the store changed; never a domain type or another crate's table | Writing a file only its owner can read; following a table from a revision |
| `crates/tenko-api`: `request` and the answer groups beside `problem` | What a request must look like and what an operation can answer; nothing a crate below the API needs | Parsing `If-Match`; the answers every signed-in route shares |
| `crates/tenko-dns`: `wire` | The DNS wire format: record layout, name compression, RCODE and type numbers, one exchange with a server; never resolution policy, caches or zone data | The number of the SOA record type |
| Each producing crate: `codes`, `metrics::names` | Error codes and metric family names, exported as constants by the crate that produces them; a consumer imports the constant and never writes the string | `tenko_store::codes::PRECONDITION_FAILED` |
| Each setting's owning type | A setting's bounds and default, as constants and `Default` on the type that holds the setting, published through OpenAPI; every other reader reads them there | The minimum PIN length on the password policy type |
| `crates/tenko-jobs`: `read`, `handoff` | How other crates read job tables, and the inline hand-off of work to a job | The jobs of one owner |
| `crates/tenko`: `client::common` | What every client command repeats: paging, usage, printing, idempotency keys, waiting for a job | Paging through a list |
| `scripts/lib/`, `deploy/compose/driver/api.sh`, `bench/lib/node.sh` | Code shared by the repository's Node scripts, by the labs, by the benchmarks; never product logic | The Rust lexer of the lints |
| `ui/src/components/form/` | The form model, one field component per input kind, and the mapping from a field error to its sentence | A text field with its label and error |
| `ui/src/api/` (`cache.ts`, `paginate.ts`, `live.ts`, list item types) | Reading from the server: object cache, paging, live queries, list item types | Every page of a list |
| `ui/src/app/format/`, `ui/src/app/clipboard.ts` | Formatting values for display, and the clipboard | Bytes in KiB, MiB, GiB |

A crate or module that is a home says the same in its header comment: what goes in, what
never goes in, and who may depend on it. Some homes are named before they exist; the change
that creates one copies its charter into the new module's header.

### The index: you need, use

| You need | Use | Home |
|---|---|---|
| Is this address link-local, mapped, special-purpose, a subnet's reserved address? | `tenko_net::addr` | `crates/tenko-net` |
| The reverse name of an address, or the address of a reverse name | `tenko_net::reverse` | `crates/tenko-net` |
| May the server connect to this address on an operator's behalf? | `tenko_core::egress` | `crates/tenko-core` |
| A stored MAC address, DUID, host or domain name, and its parsing | `tenko_core::net` | `crates/tenko-core` |
| The client's address behind a proxy | `tenko_net::proxy` | `crates/tenko-net` |
| Hexadecimal, base64, PEM, DER lengths, civil dates | `tenko_core::codec` | `crates/tenko-core` |
| Declare error codes | `tenko_core::codes!` in your crate's `codes` module | your crate |
| Use another crate's error code | its `codes::*` constant, never the string | the producing crate |
| Use a metric family name | the producer's `metrics::names::*` | the producing crate |
| A setting's bound or default | the constant or `Default` on the setting's type | the owning crate |
| Write a private file, or replace a file atomically | `tenko_store::fs` | `crates/tenko-store` |
| Follow a table's changes | `tenko_store::follow` | `crates/tenko-store` |
| Send tables to a node | `tenko_store::feed` | `crates/tenko-store` |
| Read job tables, or stage inside a job step | `tenko_jobs::read`, `tenko_jobs::stage_or_propose` | `crates/tenko-jobs` |
| Parse `If-Match`, a path id, a JSON body, query parameters, paging | `tenko_api::request` | `crates/tenko-api` |
| Declare what an operation answers | the answer groups beside `tenko_api::problem` | `crates/tenko-api` |
| DNS record layout, name decompression, RCODE and type numbers | `tenko_dns::wire` | `crates/tenko-dns` |
| Paging, usage and printing in a client command | `tenko::client::common` | `crates/tenko` |
| Test support (wait, free port, temporary directory) | `tenko_core::testing`, `ui/src/app/testing`, `ui/e2e/support` | as named |
| A form, a field, a field error's sentence | `ui/src/components/form/` | UI |
| Cache an object, page a list, read a live resource | `ui/src/api/cache.ts`, `paginate.ts`, `live.ts` | UI |
| Format bytes, times, addresses; copy to the clipboard | `ui/src/app/format/`, `ui/src/app/clipboard.ts` | UI |
| Call the API from a lab or a benchmark | `deploy/compose/driver/api.sh`, `bench/lib/node.sh` | scripts |
| Lex Rust or TypeScript source, or keep a lint's baseline, in a script | `scripts/lib/lex.mjs`, `scripts/lib/baseline.mjs` | scripts |

Several rows name a module that a planned change creates (`docs/plans/shared-code-plan.md`,
section 4, says which). Until it exists, the copies it will replace are listed in the copy
lint's baseline; do not add a new one.

### The copy lint

`node scripts/copy-lint.mjs` reports, in product code, a definition or a literal that copies
a fact a home holds: a function that computes a reverse name outside `tenko-net`, another
crate's error code or metric family written as a string, a clipboard write outside the UI's
clipboard module. Each rule, what it matches and what it cannot see are in the header of
`scripts/copy-lint.mjs`. The copies that existed when the lint started are listed in
`scripts/copy-lint.baseline.json`, and that list only shrinks:

- A copy that is not listed fails the check. Use the home instead. When a copy is right on
  purpose, say why in a comment on its line or the line above:
  `// copy-lint: allow <rule> <reason>`. An exception without a reason fails, and so does
  one that suppresses nothing.
- A listed copy that no longer exists fails too: whoever moves a copy to its home removes
  its entry in the same commit with `node scripts/copy-lint.mjs --prune`, which never adds
  one.
- CI fails when a rule has more listed copies than on the base branch
  (`node scripts/copy-lint.mjs --grown-since origin/main`).

## Commands

```sh
cargo build --workspace
cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl   # the Linux release binary (needs musl-tools); a host-target release build is glibc and is neither shipped nor measured
cargo nextest run --workspace        # fallback: cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
cargo audit
node scripts/spelling.mjs
node scripts/test-lint.mjs           # the standing rules for tests (docs/testing/rules.md)
node scripts/copy-lint.mjs           # copies of a fact a home holds ("Where shared code lives")
node --test "scripts/*.test.mjs"
cargo run -p tenko -- serve --roles controller,dns --data-dir <dir>
cd ui && npm ci && npm run build
```

Development and test builds carry line tables for the workspace crates and no debug information for dependencies (`[profile.dev]` in `Cargo.toml`), so backtraces name the file and line in Tenko's own code while the build output stays small. For a debugger session with full information build with `--profile dev-full`, for example `cargo test -p tenko-ipam --profile dev-full`; its output lands under `target/dev-full/`.

Rust-only builds use a placeholder UI page: set `TENKO_UI_STUB=1` when `ui/dist` has not been built (CI does this for its Rust jobs). Release builds refuse the placeholder.

## The gate

Changes reach `main` through the gate: a full local check that applies them onto
`origin/main` as one merge branch, regenerates the generated files and runs every check of
the project on the result: spelling, the test rules and the copy lint, the UI's type check, lint, unit
tests, build and size, formatting, clippy on Windows and on Linux, every Rust test, the traces
and the script tests, the changelog rule, `cargo deny`, the fuzz package, the server build
with the real UI, and the end-to-end suite. The maintainer who merges runs it for each
batch of changes before pushing to `main`; CI then runs again on the push. The scripts, their
configuration and the steps with what each proves are in `scripts/gate/README.md`:

```sh
. ~/tenko-gate.env                        # your configuration, from scripts/gate/gate.env.example
scripts/gate/gate.sh <name> <spec file>   # the spec lists the branches and commits to apply
scripts/gate/gate.sh --list               # the steps
```

The run ends with one line: green, or the step that failed, with the log beside it.

- **A red step** means the merged result fails that check; nothing is merged. The log names
  the check and its output. Fix the change on its branch and run the gate again, or continue
  the merge branch from the failed step with `--from <step>` after a fix made there.
- **A test that fails in the full run is run again alone.** If it passes alone the step is
  green, but the result names the test: a test that passes only alone has a cause, in the
  product or in the test, and is fixed, never retried away.
- **The gate runs alone on its machine.** It uses every core for a long time, and another
  heavy job beside it makes tests fail from load and can stall the machine. While it runs,
  other work on the same machine uses targeted checks only (`cargo clippy -p <crate>`,
  `cargo nextest run -p <crate> --test-threads 4`, `npx vitest run <files>`, one end-to-end
  spec file) and never a whole-workspace command (`--workspace`, `npm run test` without a
  file, `npm run e2e`).

## Continuous integration

The workflows live in `.github/workflows/`: `ci.yml` on every push and pull request, `codeql.yml` (code scanning, reporting only) on pull requests and weekly, `release.yml` for a tag. The security checks among them are layer 1 of `docs/plans/security-audit-plan.md`.

- **Actions are pinned to a commit.** Every `uses:` names a full 40-character commit SHA with its tag in a trailing comment: `uses: actions/checkout@<sha> # v5.1.0`. Resolve the SHA from the tag, never from memory: `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, and when that returns an object of type `tag` (an annotated tag), `gh api repos/<owner>/<repo>/git/tags/<sha>` for the commit it points at. The same action is pinned to the same SHA everywhere. An action without release tags (`dtolnay/rust-toolchain`) is pinned to a commit of its default branch, with the branch in the comment and the toolchain as an input. Every `actions/checkout` sets `persist-credentials: false` unless a later step pushes.
- **Pins are updated by Dependabot.** `.github/dependabot.yml` opens one grouped pull request a week for the GitHub Actions, taking a release only when it is a week old; it moves the SHA and the comment together. Review it like any dependency change: read what changed in each action. Cargo and npm get no version pull requests; their advisories are covered by `cargo audit`, `cargo deny`, `npm audit` and Dependabot's security updates.
- **zizmor lints the workflows** (job `workflow-lint`, when a change touches `.github/`). A finding of High severity fails the job; the others are listed in the job summary. Fix a finding where you can. When it is a false positive or an accepted risk, suppress it in `.github/zizmor.yml` under `rules.<audit>.ignore`, as narrowly as possible (`<file>:<line>` rather than a whole file), with a comment that gives the reason and, for a temporary entry, what removes it. Never suppress a finding without a reason.
- **CodeQL ignores test, bench and fuzz paths.** `.github/codeql/config.yml` lists the paths code scanning does not analyze (integration tests, `testing` modules, `bench/`, `fuzz/`, `ui/e2e/`, the UI's dev mock and unit tests, `design/`); add a new class of test or benchmark code there, with a one-line reason. A product alert is answered in the security report (`docs/security/README.md`, one finding per rule and crate) and is never dismissed without a reason.
- **The unit's hardening has gates** (job `unit-check`, when a change touches `deploy/systemd/`, `deploy/install.sh` or `ci.yml`). `deploy/systemd/check-hardening.sh` scores `tenko.service` alone and with each drop-in with `systemd-analyze security --offline=true` and fails when a score reaches its gate: the score measured with systemd 255 plus 0.1 (the unit 1.5, the drop-ins `probe.conf` and `dhcp-direct.conf` 1.7, the installer's data-directory and key-file drop-ins 1.5, all of them at once 1.7). Run it with `bash deploy/systemd/check-hardening.sh` on any Linux host with systemd 250 or later, no root needed. A new drop-in needs its gate in the script, and a deliberate change that moves a score changes the gate in the same commit, with the reason.
- **Dependencies.** `npm audit --omit=dev --audit-level=high` in the UI job fails on a High or Critical advisory against a production dependency of the UI; the full `npm audit` is reported beside it. On a pull request, the dependency review fails on a new dependency with a High or Critical advisory or with a license outside the allow list of `deny.toml`.
