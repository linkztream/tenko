# Release and changelog scripts

Node scripts (Node 22, standard library only, no `package.json`) for the changelog and the
release manifest. They run in CI and in the release workflow, and by hand from the repository
root.

| File | What it does |
|---|---|
| `changelog.mjs` | Validates `CHANGELOG.md`, prints the notes of one release, and checks that a change to the product comes with an entry. |
| `release-manifest.mjs` | Builds `releases.json` (the manifest running installations read) and `SHA256SUMS` from the changelog and the release binaries. |
| `requirement-trace.mjs` | Generates `docs/plans/phase-1-trace.md`, the table of Phase 1 requirements and exit criteria against the tests, measurements and documents that name them, and checks that the committed file is current. |
| `*.test.mjs` | Tests with `node:test`. |

```sh
node --test "scripts/*.test.mjs"
```

Quote the pattern: Node expands it itself, so the same line works in every shell. A bare
directory (`node --test scripts/`) is not accepted by Node 22.

## `changelog.mjs`

```sh
node scripts/changelog.mjs validate [--file CHANGELOG.md]
node scripts/changelog.mjs notes <version> [--file CHANGELOG.md]
node scripts/changelog.mjs check --base <git-ref> [--head HEAD] [--file CHANGELOG.md]
```

Exit codes: 0 success, 1 the changelog or the rule failed, 2 bad usage or environment.

- `validate` parses the file and prints `CHANGELOG.md: N sections, M entries under Unreleased`.
- `notes` prints the body of the section of a released version, the text of the GitHub
  release. It exits 1 when there is no such section; Unreleased is never served.
- `check` is the CI rule. It lists the paths changed between `<base>` and `<head>`
  (`git diff --name-only <base>...<head>`, or `<base> <head>` when there is no merge base). A
  **product path** is anything under `crates/` or `ui/src/` except files under a `tests/`,
  `benches/` or `fixtures/` directory, `*.test.ts`, `*.test.tsx`, `ui/src/api/generated/`,
  `ui/src/i18n/generated/`, `ui/src/app/testing/` and `ui/src/api/mock/`. When a product
  path changed, the `## [Unreleased]` section of the changelog at `<head>` (the working-tree
  file when `<head>` is `HEAD`) must differ from the one at `<base>` and the file must
  parse; otherwise the check fails and lists the paths. A base that is the all-zero SHA or
  does not exist (a first push) passes with a note. Pull requests that change nothing a user
  can see carry the label `no-changelog`, which skips the CI job; that is the only override.

### Changelog grammar

Keep a Changelog 1.1.0 plus one subsection, `### Action required`. A second parser in Rust
follows the same rules.

- Text before the first `## ` heading is the preamble and ignored. Link reference definitions
  (`[label]: target`) are ignored wherever they are and are never part of a body.
- A leading byte order mark is skipped, and trailing whitespace on a `## ` or `### ` heading
  line is ignored.
- A section heading is exactly `## [Unreleased]` or `## [X.Y.Z] - YYYY-MM-DD`, with a
  SemVer 2.0.0 version (optional `-pre.release` and `+build`, no leading `v`, no leading
  zeros, at most 128 bytes). Any other `## ` line is an error, `## [Unreleased] - <date>` and
  `## [v1.0.0] - <date>` included. The date has a four-digit year, month 1 to 12 and day 1
  to 31; there is no calendar check.
- `## [Unreleased]`, when present, is the first section and appears once. Released versions
  are unique and strictly descending by SemVer precedence in file order.
- A subsection heading is exactly `### Added`, `### Changed`, `### Deprecated`,
  `### Removed`, `### Fixed`, `### Security` or `### Action required`. Any other `### ` line is
  an error. `#### ` and deeper headings are body text.
- The body of a section is its text without the `## ` heading, without leading and trailing
  blank lines, with CRLF turned into LF. `entries` counts the list items (`- ` or `* ` at
  column 0). `security` is true when `### Security` has a non-blank line; `requires_action`
  likewise for `### Action required`, and `action` is that subsection's trimmed text. A
  subsection name may repeat in a section; the texts of repeated `### Action required`
  subsections are joined with one blank line.
- Headings are recognized line by line; a fenced code block does not hide them.

## `release-manifest.mjs`

```sh
node scripts/release-manifest.mjs --version 0.2.0 --assets dist \
  --base-url https://github.com/linkztream/tenko/releases/download/v0.2.0 \
  [--changelog CHANGELOG.md] [--previous prev/releases.json] \
  [--image ghcr.io/linkztream/tenko:0.2.0] [--format 1] [--out releases.json]
```

It takes the section `## [0.2.0] - <date>` of the changelog (an error when it is missing),
hashes every file of `--assets` named `tenko-<version>-<os>-<arch>` or
`tenko-<version>-<os>-<arch>.exe` (other files are ignored with a note), keeps the releases
of `--previous` except an entry for the same version, sorts newest first, and writes
`releases.json` (schema 1, pretty JSON) and `SHA256SUMS` (`sha256sum` format, the assets of
this release) next to it. An asset URL is `<base-url>/<file name>`. A manifest with more than
1,000 releases is refused, and so is a release without any asset.

`action`, `format` and `image` are left out of a release entry when not given; `action`
appears only when the section has an `### Action required` subsection.

## `requirement-trace.mjs`

```sh
node scripts/requirement-trace.mjs            # write docs/plans/phase-1-trace.md
node scripts/requirement-trace.mjs --check    # exit 1 when the committed file is stale
node scripts/requirement-trace.mjs --stdout   # print instead of writing
```

`--root <dir>` runs it against another tree (the tests use it). Exit codes: 0 success, 1 the
committed trace differs from the one that would be written (or does not exist), 2 bad usage
or a missing source document.

Input: the requirement rows of `docs/REQUIREMENTS.md` (`| PREFIX-NN | text | phase | priority |`)
whose phase cell starts with the number 1 (`1`, `1 (Slice 2)`, `1 (ACME: 3)`; not `2`, `10` or
`2 and 3`), and the exit criteria E1 to E12 of the table under "Exit criteria" in
`docs/plans/phase-1-execution.md`. The `CON-NN` design constraints are headings, not rows, and
are not traced.

What counts as a mention of an ID:

- A mention is the whole canonical ID: `OPS-1` never matches `OPS-15`, and `OPS-3` is not
  `OPS-03`. A range (`SCAN-01 to SCAN-09`, `IAM-03 to IAM-09`, `IAM-03 to 05`, with `..`,
  `through` or a dash) names every ID of the set between its ends.
- **Tests**, Rust under `crates/**/tests/**` and `crates/**/src/**`: a function after
  `#[test]` or `#[tokio::test]` whose snake-case name has the lower-case prefix and the
  number as consecutive parts (`fn iam_10_lockout` is IAM-10, `fn phase1_ops_03_x` is
  OPS-03), or whose `///` comment names the ID. It is listed as `file::fn`. A `//!` comment,
  or a `///` comment on anything else, in a file under a `tests` directory names the whole
  file; in `src` it counts as a document.
- **Tests**, TypeScript: `ui/e2e/**/*.spec.ts` and `ui/src/**/*.test.ts(x)`, when a comment or
  the title of `test(`, `it(` or `describe(` names the ID. The file is listed.
- **Measurements**: `bench/**/results/*.md`.
- **Documents**: `docs/**/*.md` except `docs/REQUIREMENTS.md` and the generated trace itself,
  and, as above, code documentation in `crates/**/src`.
- An exit criterion `E9` is named by a test whose Rust name starts with `e9_` or whose
  comment or title has the word `E9`.
- `node_modules`, `target`, `dist`, `.artifacts` and `.git` are never entered.

The output is sorted, has no timestamps and uses `/` in paths. A table cell shows five
entries and then "and N more". The Uncovered section lists the requirements no test names,
and separately those that no test, measurement or document names.

## Where they run

- `.github/workflows/ci.yml`, job `changelog` (pull requests and pushes): `node --test`, then
  `changelog.mjs validate` and `changelog.mjs check --base <base>`.
- `.github/workflows/release.yml` (tags `v*`): `verify` runs `changelog.mjs notes <version>` to
  prove that the section exists; `publish` runs `release-manifest.mjs` over the binaries,
  `changelog.mjs notes <version>` for the release text, and attaches `releases.json` and
  `SHA256SUMS` to the GitHub release.
