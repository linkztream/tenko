# Security reports

Every release of Tenko is checked in three layers ([`docs/plans/security-audit-plan.md`](../plans/security-audit-plan.md)):
deterministic checks in CI (layer 1), the lab round `security` on the binary being released
(layer 2, [`deploy/security/`](../../deploy/security/README.md)), and a review of the diff
since the last reviewed release (layer 3). This directory holds, per release, the **public
summary** of what the layers found; the full report and its evidence live in the owner's
private security repository (SA-Q3 (b) of the plan), so that an open weakness of a released
version is not published against the coordinated disclosure that `SECURITY.md` promises.

## The process

1. The round runs at release, before `publish`, and writes one JSON line per row into an
   evidence bundle, which the workflow encrypts with `age` to the owner's key and uploads.
2. The owner (or the lead on the owner's machine) decrypts the bundle.
3. A triage session (the brief of Appendix A of the plan) reads the bundle, the previous
   report and the repository's layer 1 alerts, and writes the full report.
   `scripts/security-report.mjs` does the mechanical part: sections 1 and 2, a finding per
   failed row, the IDs carried over and the next free ID, and the public summary that lands
   here as `release-<version>.md`.

## The report format (section 4.5 of the plan)

```markdown
# Security report: Tenko <version>

- Tag and commit, date, round run URL and bundle hash, the previous report, the reviewed diff

## 1. Layer 1        (L1.1 to L1.11; open alert counts by severity)
## 2. Layer 2 rows   (one line per row; Evidence = path inside the bundle)
## 3. Findings       (ID, Severity, State, Source, Fingerprint, Title, First seen, Evidence)
## 4. Changes since <previous version>
## 5. Notes for the owner
```

The public summary carries the rows with their states, the counts of findings by severity and
state, the fixed findings with their ID and fixing commit, and the open findings by ID and
severity only; the details of an open finding are published when it is fixed or when the
disclosure window of `SECURITY.md` ends.

## Finding IDs and fingerprints

- **ID.** `SF-NNNN`, four digits, sequential across the project, never reused and never
  renumbered.
- **Fingerprint.** `<tool>:<rule>:<location>`, for example `row:net.cluster_port`,
  `nmap:tcp/8444`, `testssl:cipher_negotiated:8443`,
  `zap:10038:/api/v1/dns/zones/{id}`, `codeql:rust/cleartext-logging:crates/tenko-auth/src/session.rs#create`.
  A path with an identifier is normalised to its OpenAPI-style template (a resource id in a
  URL path becomes `{id}`; a port keeps its number), and a line number is never part of a
  fingerprint. The triage matches a new run's findings to the open ones by fingerprint; one
  that matches nothing gets the next ID.

## States

`new` (first seen in this report), `open` (seen again), `fixed` (no longer seen **and** a
named commit since the last report addresses it), `not seen` (gone without a commit that
explains why; it stays on the list and becomes `fixed` only when a later report confirms it),
`accepted` and `not a finding` (the owner's decision, with the reason, quoted), `reopened`
(decided or fixed earlier, seen again). Only the owner moves a finding to `accepted` or `not a
finding`; the triage never does, and never silently closes a finding.

## The rule files

The round turns a tool's raw output into a verdict with the files in
[`deploy/security/rules/`](../../deploy/security/rules/); what they allow is part of what a
report means, so they change only as described below.

**`public-operations.txt`** lists the API operations that answer without a session or a
token, one `METHOD /path` per line as the OpenAPI document writes it, each with its reason in
a comment: liveness and readiness, the setup flow, the sign-in steps, the languages of the
sign-in page, node enrolment, the internal CA's root, the OpenAPI document, and the web
interface's static files. The row `web.unauth` sends every other operation without
credentials and blocks the release on any answer but 401 or 403, and also when the operations
the document declares public are not exactly this list, so a route that loses its
authentication fails the round twice over: by its answer, and by the document's declaration.

**`zap-baseline.tsv`** is ZAP's rule file for `web.ui_baseline` and `web.api_baseline`: per
ZAP rule id, `FAIL` (the alert must never be raised, for example a missing
Content-Security-Policy or a session cookie without `HttpOnly`), `WARN` (the alert is a
finding of the report for the triage) or `IGNORE` (dropped, only with the reason in the
comment above it). A rule that is not listed is `WARN`. The two rows report and do not block
until the file has been through two releases without a new finding of High or above (SA-Q1
(b) of the plan); the commit that makes them blocking says so.

**`testssl-allow.txt`** lists the testssl.sh finding ids that `tls.api` and `tls.dot` pardon
at severity Medium or above, each with its reason.

**How a rule changes.** A change to a rule file is its own commit, or part of the commit that
changes what the rule is about (a route that becomes public adds its entry beside the route),
and carries its reason in the file, as narrowly as the tool allows: one operation, one rule
id, one finding id, never a category or a pattern. A rule is never loosened to make a release
pass: a finding the round raises goes into the report with an ID, and only the owner moves it
to `accepted` or `not a finding`, after which the rule may follow with that decision named in
its comment. Removing an entry whose reason no longer holds needs no decision.

## Severity

Critical, High, Medium, Low, Info. A tool's own severity is the starting point; the triage may
raise it with a reason and lowers it only with the owner's agreement.
