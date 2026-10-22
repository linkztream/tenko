# Publication checklist: the day the repository goes public

- Status: Proposed; the owner's steps are in section 3
- Date: 2026-10-22
- Scope: what must be true before the repository's visibility is changed from private to public, and what is done in the first hours after. The licensing model ([ADR 0022](../adr/0022-licensing-model.md), `LICENSE.md`, `CLA.md`) is merged; this list covers the rest.

Making the repository public is one click in the repository settings, and it cannot be
taken back: every commit of the history, every issue and every pull request becomes
readable and gets copied by mirrors within hours. So the order matters. Section 1 is
done in the repository by the publication package; section 2 is what it checked;
section 3 is done by the owner in the repository settings and outside the repository,
in the order given; section 4 is the first days after.

Contents:

1. [Done in the repository](#1-done-in-the-repository)
2. [Checked, with the method](#2-checked-with-the-method)
3. [The owner's steps, in order](#3-the-owners-steps-in-order)
4. [The first days after](#4-the-first-days-after)

## 1. Done in the repository

Merged on `main` before the visibility changes; each item names its file.

| # | Item | Where |
|---|---|---|
| 1 | The licence texts: BSL 1.1 with the internal-use grant, the Change License, the CLA, the licensing section of the contributing guide and the "Commercial Use & Royalties" section of the README | `LICENSE.md`, `CLA.md`, `CONTRIBUTING.md`, `README.md`, ADR 0022 |
| 2 | The security policy: private reporting, what to include, the response commitment, the supported versions, the scope and the hardening pointers; linked from the README and the contributing guide | `SECURITY.md` |
| 3 | The code of conduct (Contributor Covenant 2.1) with the contact of `LICENSE.md` as the enforcement contact; linked from the contributing guide | `CODE_OF_CONDUCT.md` |
| 4 | The pull request template: the CLA sentence for a first contribution, `Signed-off-by`, the checks, English only, no attribution trailers, placeholders in fixtures | `.github/PULL_REQUEST_TEMPLATE.md` |
| 5 | The issue forms (bug report, feature request) and `config.yml`, which disables blank issues and points security reports to the policy | `.github/ISSUE_TEMPLATE/` |
| 6 | The Developer Certificate of Origin check: a CI job on every pull request that fails when a commit lacks a `Signed-off-by` trailer matching its author (a shell step, no third-party action, no secret) | `.github/workflows/ci.yml`, job `dco` |
| 7 | Pull requests never run on a self-hosted runner: the Linux jobs' `runs-on` is `ubuntu-latest` for a `pull_request` event and the repository variable `LINUX_RUNNER` applies only to `push`, `schedule` and `workflow_dispatch` | `.github/workflows/ci.yml`, `.github/workflows/release.yml` |
| 8 | The npm licence check: every production dependency of the web UI carries a licence on the allow list; the copyleft family is refused; development-only packages are listed apart; run in the CI UI job | `ui/scripts/licenses.mjs`, `npm run licenses` |
| 9 | The pre-release notice at the head of the README: no tagged release, unsigned binaries until a certificate exists, production use at the reader's own risk | `README.md` |
| 10 | This checklist | `docs/plans/publication-checklist.md` |

## 2. Checked, with the method

- **The git history, scanned on 2026-10-22** for the patterns that must not be published:
  private address ranges (RFC 1918 and the IPv6 unique local range), internal domain
  suffixes (`.local`, `.lan`, `.home`, `.internal`, `.corp` and the owner's own), private
  keys (`BEGIN ... PRIVATE KEY` blocks) and token patterns (GitHub, cloud provider and
  generic bearer or API-key shapes). The scan covered every commit, not only the tree at
  `main`. It found test fixtures with documentation addresses and the secrets that tests
  and smokes generate for themselves, and nothing else. The scan is repeated on the day
  (section 3, step 2) because commits land between the scan and the publication.
- **The npm licences, on 2026-10-22:** ten production packages, nine under MIT and one
  under BSD-3-Clause; nothing outside the allow list. Of the development-only packages,
  three are MPL-2.0 (a CSS tool and an accessibility test library, used at build and
  test time only), two are MIT-0 and one is CC-BY-4.0 (a browser-support data table);
  none of them ships in the UI bundle.
- **The Rust dependencies** are checked by `cargo deny check` on every push and pull
  request against the allow list in `deny.toml`, which excludes every GPL and AGPL
  licence.

## 3. The owner's steps, in order

Everything below is done by the owner; nothing in the repository can do it. Steps 1 to 4
come before the visibility changes, steps 5 to 13 in the repository settings right
after, and steps 14 to 16 in the days around it.

**Before the visibility changes**

1. **The lawyer's review** of `LICENSE.md`, `CLA.md`, the licensing section of
   `CONTRIBUTING.md` and the "Commercial Use & Royalties" section of `README.md`. ADR 0022
   lists the questions to put to the lawyer, among them whether AGPL-3.0-or-later
   satisfies the compatibility covenant of the BSL. Change the texts on `main` first;
   the licence that a mirror copies on the first day is the one that counts.
2. **Repeat the history scan** on the final `main` with the patterns of section 2, and
   archive the result (the command, the date, the commit and the summary) outside the
   repository, so that a later question "what was checked before publication" has an
   answer. If anything is found, rewriting the history is still possible while the
   repository is private, and impossible afterwards.
3. **The name.** A trademark search for "Tenko" in the classes for software and network
   services, in Sweden, the EU and the US, and a check of the domains the project would
   use. BSL grants no trademark rights, so the word mark is the second lever against a
   rebranded fork. This is a separate report; it does not block publication, but a
   renaming after publication is expensive.
4. **The self-hosted runner.** Remove the label from the repository variable
   `LINUX_RUNNER`, or keep it and accept that `push` to `main` and the weekly schedule
   still run on the owner's machine. With the variable set, a pull request from a fork
   never reaches it (section 1, item 7), but a commit on `main` does, and anyone with
   write access can put one there. The runner's runbook is in `.github/runner/README.md`.

**In the repository settings, right after the visibility changes**

5. **Branch protection on `main`** (Settings, Branches, or a ruleset): require a pull
   request before merging; require the status checks `Rust (Linux)`, `cargo-deny`, `UI`,
   `Rust with the built UI`, `Cluster smoke (Linux)`, `Deploy scripts`, `Changelog` and
   `Signed-off-by on every commit` to pass; require branches to be up to date; no force
   pushes; no deletion; the rules apply to administrators too. The merge method keeps
   `Signed-off-by` trailers: merge commits or rebase, never squash.
6. **Actions: "Require approval for all outside collaborators"** (Settings, Actions,
   General, "Fork pull request workflows from outside collaborators"). Without it, a
   first-time contributor's pull request runs the workflows unattended; with it, a
   maintainer looks at the diff before CI spends minutes on it. Leave the default
   `GITHUB_TOKEN` permissions at read-only; the workflows raise what they need.
7. **Private vulnerability reporting** (Settings, Code security, "Private vulnerability
   reporting"): enable it. `SECURITY.md` and the issue form configuration point to it.
8. **Secret scanning and push protection** (the same page): enable both. Push protection
   blocks a push that carries a known token shape before it lands.
9. **Dependabot** (the same page): enable Dependabot alerts and Dependabot security
   updates for Cargo, npm and GitHub Actions. Version updates are optional; the lock files
   are reviewed by hand today.
10. **Issues and discussions.** Issues are on with the forms of section 1. Decide whether
    to enable Discussions for questions and ideas; if so, add a contact link for them to
    `.github/ISSUE_TEMPLATE/config.yml`.
11. **The repository description and topics**: a one-line description ("DNS, DHCP and
    IPAM in one binary, with a web UI") and topics such as `dns`, `dhcp`, `ipam`, `ddi`,
    `rust`, `solidjs`; the website field once a site exists.
12. **Collaborators and teams.** Review who has write access; with a public repository
    every write-access account is a way onto `main` and, through step 4, onto the runner.
13. **Packages.** The container image on the GitHub container registry is private until
    its visibility is changed too (Packages, the image, Package settings). Change it with
    the first release, not before; there is nothing to pull until then.

**In the days around it**

14. **The first tagged release.** Set the crate version, add the changelog section
    `## [X.Y.Z] - <date>` and push the tag; the release workflow builds the binaries, the
    MSI, the container image, `releases.json` and `SHA256SUMS` and writes the release
    notes from the changelog. Mark it a pre-release (a `-rc.1` or `-alpha.1` tag does so by
    itself) until the data-directory format is frozen. The notes say what the README's
    pre-release notice says: unsigned binaries, no stability promise yet.
15. **Signing.** A code-signing certificate for the Windows binary and the MSI
    (`deploy/windows/README.md`, "Signing"); the workflow signs as soon as the secrets
    exist. Signing of the Linux binary and of `releases.json` is a later requirement with
    its places marked in the release workflow.
16. **The README's status line** (`pre-alpha, Phase 0`) is older than the code; update it
    to the current phase when the first release is tagged.

## 4. The first days after

- Watch the first pull requests from outside: the DCO check and the CLA sentence are new
  to most contributors, and the pull request template explains them, but the first
  responses set the tone.
- Watch the Actions minutes: with the self-hosted runner removed (step 4), every job
  runs on hosted minutes, and a public repository has unlimited minutes for the standard
  runners, so nothing should change; if the variable was kept, check that no pull
  request job ever reports a self-hosted runner.
- Check that the security policy link on the repository's "Security" tab resolves, that
  the issue forms render, and that a test pull request from a fork (a second account)
  runs on `ubuntu-latest` and fails the DCO check without a trailer.
