# Security summary: Tenko 0.0.10

- Tag and commit: v0.0.10, 5759bce4
- Date: 2026-11-03
- The full report and its evidence are in the owner's private security repository (SA-Q3 (b) of `docs/plans/security-audit-plan.md`); this file is the public summary.

## Rows

| Row | State |
|---|---|
| net.tcp | PASS |
| net.udp | PASS |
| net.listeners | PASS |
| net.cluster_port | PASS |
| net.ipv6 | PASS |
| tls.api | PASS |
| tls.dot | PASS |
| tls.headers | PASS |
| unit.exposure | PASS |
| unit.account | PASS |
| fuzz.targets | FAIL |
| fuzz.dns_wire | PASS |
| web.unauth | FAIL |
| web.ui_baseline | PASS |
| web.api_baseline | PASS |

## Findings

By severity: Critical 0, High 2, Medium 2, Low 5, Info 0.
By state: new 9, open 0, fixed 0, not seen 0, decided 0.
Informational alerts: 24, listed in the full report.

Open findings (details published when fixed or when the disclosure window of `SECURITY.md` ends):

| ID | Severity |
|---|---|
| SF-0001 | Medium |
| SF-0002 | High |
| SF-0003 | Low |
| SF-0004 | Low |
| SF-0005 | High |
| SF-0006 | Medium |
| SF-0007 | Low |
| SF-0008 | Low |
| SF-0009 | Low |

This is the baseline report: it has no earlier report to compare with, so every finding is `new`. SF-0007 to SF-0009 are passive scanner alerts of the web interface and the API.

Fixed on `main` after this release and shipping with 0.0.11 (they stay `new` here and become `fixed` in the report of 0.0.11):

| ID | Title | Fixing commit |
|---|---|---|
| SF-0001 | The on-demand cluster port closes when no token waits and no node is enrolled | `919a0001` |
| SF-0002 | The password check refuses an unauthenticated caller before it reads the body | `927084ff` |
| SF-0003 | A DoH `dns` parameter ending in a multi-byte character no longer panics | `0654ae75` |
| SF-0004 | A zone file with a parenthesis open at its end is refused, not a panic | `0a24d7e8` |
| SF-0005 | `calamine` 0.38 closes RUSTSEC-2026-0436 in the spreadsheet reader | `c136a0e1` |


