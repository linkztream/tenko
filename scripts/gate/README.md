# The gate

The gate is the full local check that runs before changes are merged into `main`. It builds
the branch `merge-<name>` from `origin/main` and the changes named in a spec file, regenerates
the generated files, and runs every check of the project in order: the same checks as CI and
more, on the merged result, on one machine. `CONTRIBUTING.md` (section "The gate") says when
it runs and what a red step means.

| File | What it does |
|---|---|
| `gate.sh` | The entry point: applies the spec, runs the steps, writes the log and ends with one result line. |
| `apply.mjs` | The first step: builds `merge-<name>` from the spec file and resolves conflicts by rule. |
| `merge-changelog.mjs` | Merges the conflicts git leaves in `CHANGELOG.md`, both sides kept. |
| `watch-ci.sh` | Waits for the GitHub Actions runs of a commit and prints the jobs that did not succeed. |
| `gate.env.example` | An example of the configuration. |

The tests of the Node parts are `scripts/gate.test.mjs` (`node --test "scripts/*.test.mjs"`).

## Requirements

The gate runs on Windows in Git Bash, with WSL for the Linux clippy:

- `git`, `node` (22), `npm`, `cargo` with `cargo-nextest` and `cargo-deny`, and `wsl` on
  `PATH`;
- a git worktree of your clone used by the gate alone (`git worktree add <dir>`), so that the
  branches a spec names are visible there, with `npm ci` and the Playwright browsers
  installed in its `ui/`;
- a clone of the repository inside the WSL distribution, with Rust installed there;
- `gh`, signed in, for `watch-ci.sh`.

## Configuration

The scripts read environment variables; nothing machine-specific is in the repository. Copy
`gate.env.example` outside the repository, set your values and load it in the shell that runs
the gate. Paths are read by Windows programs, so write them as `F:/dir` (drive letter, forward
slashes, no spaces). A required variable that is missing stops the gate before it starts, with
the names of all missing ones.

| Variable | Required | Meaning |
|---|---|---|
| `TENKO_GATE_WORKTREE` | yes | The gate's worktree. Its first step resets it (`git reset --hard`) to a fresh `merge-<name>`: never a checkout you work in. The gate refuses to run from scripts inside it. |
| `TENKO_GATE_OUT_DIR` | yes | Where the log and the outputs of each run go (see Output). |
| `TENKO_GATE_TARGET_DIR` | yes | Cargo target directory of the OpenAPI generation and the clippy run. |
| `TENKO_GATE_TESTS_TARGET_DIR` | yes | Cargo target directory of nextest and of the server build the end-to-end tests drive. |
| `TENKO_GATE_FUZZ_TARGET_DIR` | yes | Cargo target directory of the fuzz package's check. |
| `TENKO_GATE_WSL_DISTRO` | yes | The WSL distribution of the Linux clippy (`wsl -d <name>`). |
| `TENKO_GATE_WSL_CHECKOUT` | yes | The clone inside that distribution, as its shell writes it (`'~/tenko'`, quoted). |
| `TENKO_GATE_TEST_THREADS` | no, 6 | Test threads of the full nextest run. |
| `TENKO_GATE_BUILD_JOBS` | no, 6 | `CARGO_BUILD_JOBS` of every cargo command. |
| `TENKO_GATE_GITHUB_REPO` | for `watch-ci.sh` | The repository on GitHub, `<owner>/<repository>`. |

Keep the target directories between runs: a run then builds only what changed.

## Running it

```sh
. ~/tenko-gate.env
scripts/gate/gate.sh batch spec-batch.txt              # every step
scripts/gate/gate.sh batch --from nextest              # merge-batch as it stands, from nextest on
scripts/gate/gate.sh batch spec-batch.txt --dry-run    # print what a run would execute
scripts/gate/gate.sh --list                            # the steps
```

`<name>` names the branch `merge-<name>` and the output files (letters, digits, `.`, `-`,
`_`). `--from <step>` continues the branch already checked out in the gate's worktree, for
example after fixing what made a step red there; it needs no spec file. `--dry-run` needs the
configuration but runs nothing: it prints the git commands of the apply step and the commands
of every later step with the configuration filled in.

The terminal shows each step's heading as it starts, the test summaries, the reruns and the
result, and for a red step the last 20 lines of its output; everything goes to the log. The
last line is the result:

```text
gate batch: GREEN; log F:/gate-out/gate-batch.log
gate batch: RED at step apply (conflict in crates/tenko-dns/src/lib.rs (0a1b2c3d)); log F:/gate-out/gate-batch.log
```

Exit codes: 0 green, 1 a step failed, 2 bad usage or configuration. Before the first step the
gate checks the configuration (required variables present, paths absolute) and that `git`,
`node`, `npm`, `npx`, `cargo`, `cargo nextest`, `cargo deny` and `wsl` are there. The commits
on the merge branch carry the git identity configured for the gate's worktree.

### The spec file

One item per line, applied in order onto `origin/main`; blank lines and lines starting with
`#` are ignored.

```text
# squash <branch> <subject>: the branch as one commit
squash topic/dhcp-relay fix(dhcp): a relayed request keeps its gateway address
# pick <commit>: the commit with its own message
pick 0a1b2c3d
```

A squash commit's message is the subject, then the messages of the branch's commits, oldest
first; `Changelog: none` stays only when every commit carries it. `Signed-off-by:` lines are
removed from every message. A conflict is resolved by rule:

- `CHANGELOG.md`: both sides kept (`merge-changelog.mjs`). Lines a side adds under the heading
  above the conflict come first, subsections of the same name are merged, and subsections are
  ordered as the changelog grammar lists them (`scripts/README.md`).
- `docs/api/openapi.json`, `ui/src/api/generated/`, `ui/src/i18n/generated/`,
  `docs/plans/*-trace.md`: the incoming side; the next step regenerates them.
- Anything else stops the gate with the file, the item and the first 80 lines of its diff.

After the last item the apply step fails when `CHANGELOG.md` holds a conflict marker or when
its Unreleased section names a work package (`WP` and a digit).

## The steps

`--list` prints them with their identifiers, which `--from` takes and the result line names.

| Step | Heading | What it runs | What a green step proves |
|---|---|---|---|
| `apply` | apply | `apply.mjs` (above), then `git log --oneline origin/main..HEAD` | The changes apply onto `origin/main` without a conflict that needs a person. |
| `regenerate` | regenerate: openapi, ui types, i18n, traces | `tenko openapi`, `ui/scripts/api-types.mjs`, `ui/scripts/i18n.mjs`, `requirement-trace.mjs` for phases 1 to 4; commits what changed | The generated files match the merged source (a commit "chore: regenerate ..." when they did not). |
| `spelling` | spelling | `scripts/spelling.mjs` | American English in the tracked files. |
| `test-lint` | test lint | `scripts/test-lint.mjs`, then `--grown-since origin/main` | No test breaks the standing rules beyond the baseline, and the baseline did not grow. |
| `ui` | ui typecheck, lint, tests | `npm run typecheck`, `npm run lint`, `npm run test` in `ui/` | The UI type-checks, passes the linters and the message and API type checks, and every unit test passes. |
| `ui-build` | ui build + size | `npm run build`, `npm run size` | The UI builds and stays within its size budget. |
| `fmt` | fmt | `cargo fmt --all -- --check` | The Rust code is formatted. |
| `clippy` | clippy | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | No clippy warning on Windows, all features. |
| `clippy-linux` | clippy (linux, wsl) | the same clippy (without `--all-features`) on the merge commit in the WSL clone | No warning in the Linux-only code. |
| `nextest` | nextest | `cargo nextest run --workspace --all-features --locked --no-fail-fast` | Every Rust test passes (see Reruns). |
| `trace` | trace check, script tests | `requirement-trace.mjs --check` for phases 1 to 4, `node --test "scripts/*.test.mjs"` | The committed traces are current and the scripts' tests pass. |
| `changelog` | changelog | `changelog.mjs validate`, `changelog.mjs check --base origin/main --head HEAD` | The changelog parses, and a product change comes with an entry or `Changelog: none`. |
| `deny` | deny | `cargo deny check` | Advisories, bans, licenses and sources pass `deny.toml`. |
| `fuzz` | fuzz check | `cargo check --locked` in `fuzz/` | The fuzz targets still build against the changed crates. |
| `build` | server build with embedded ui | `cargo build -p tenko --locked` without `TENKO_UI_STUB` | The server builds with the real UI. |
| `e2e` | e2e | `npm run e2e` in `ui/` against that binary | Every end-to-end scenario passes. |

Every cargo command runs with `CARGO_BUILD_JOBS` from the configuration,
`CARGO_PROFILE_DEV_DEBUG=line-tables-only`, `CARGO_INCREMENTAL=0` and
`TENKO_DNSSEC_DOCKER=false`; the steps up to `fuzz` also with `TENKO_UI_STUB=1`.

### Reruns

A test that fails in the full run, on a machine loaded by everything else the gate does, is
run again alone to tell load from a defect:

- `ui`: each failed test file again alone (`npx vitest run <file>`). An error outside the
  tests (an unhandled error or rejection) names no file to rerun and fails the step at once.
- `nextest`: every test that did not pass (failed, timed out, leaked a process or ended on a
  signal) again, together on one thread (`--test-threads 1`, a filter of their names).

When every rerun passes, the step is green, and the result names each test that passed only
alone above the last line. When one fails alone too, the step is red. The names are kept in
`gate-<name>-alone.txt` for every run of that name, so a later `--from` run names them too;
a run from the first step starts the list again. A test that passes only alone still has a
cause, in the product or in the test; the gate never hides it.

## Output

In `TENKO_GATE_OUT_DIR`, for a run named `<name>`; a run with `--from <step>` writes its own
files as `gate-<name>-from-<step>*`, beside those of the full run:

| File | Content |
|---|---|
| `gate-<name>.log` | The whole run. |
| `gate-<name>-ui-tests.txt` | The output of the UI unit tests. |
| `gate-<name>-nextest.txt` | The nextest output without the passing tests. |
| `gate-<name>-nextest-alone.txt` | The rerun of the failed tests, when there was one. |
| `gate-<name>-junit.xml` | nextest's JUnit report of the full run. |
| `gate-<name>-alone.txt` | The tests that failed in a full run, and how they did alone (shared by the runs of one name). |

## `watch-ci.sh`

```sh
scripts/gate/watch-ci.sh <commit>      # every workflow run of that commit
scripts/gate/watch-ci.sh --run <id>    # one run
```

It waits for the runs to start (up to five minutes) and to complete, prints each run's
conclusion and every job that neither succeeded nor was skipped. Exit codes: 0 every run
succeeded or was skipped, 1 a run did not succeed or none started, 2 bad usage or
configuration.
