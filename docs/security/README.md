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

## Severity

Critical, High, Medium, Low, Info. A tool's own severity is the starting point; the triage may
raise it with a reason and lowers it only with the owner's agreement.
