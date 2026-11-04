# Security summary: Tenko 0.0.11

- Tag and commit: v0.0.11, 28ea7095
- Date: 2026-11-04
- The round ran on the binary being released, in the release path (run https://github.com/linkztream/tenko/actions/runs/41812375592): 15 rows, all PASS. The round's first run for this release, on `dde29324`, stopped the release on `fuzz.targets` (SF-0010, below); the rows here are those of the final run, on the released commit.
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
| fuzz.targets | PASS |
| fuzz.dns_wire | PASS |
| web.unauth | PASS |
| web.ui_baseline | PASS |
| web.api_baseline | PASS |

## Findings

By severity: Critical 0, High 1, Medium 2, Low 6, Info 1 (after the owner's two severity decisions below; at discovery High 2, Low 6, Info 0).
By state: new 0, open 3, fixed 6, not seen 1, decided 0.
Informational alerts: 25, listed in the full report.

Open findings (details published when fixed or when the disclosure window of `SECURITY.md` ends):

| ID | Severity |
|---|---|
| SF-0006 | Medium |
| SF-0008 | Low |
| SF-0009 | Low |

Not seen in this round (gone without a commit that explains it; they stay on the list until a later report confirms them):

| ID | Severity |
|---|---|
| SF-0007 | Low |

Fixed since the 0.0.10 report, all in 0.0.11 (six findings; SF-0010 was found and fixed within this release):

| ID | Severity | Title | Fixing commit | Release |
|---|---|---|---|---|
| SF-0001 | Medium | The on-demand cluster port closes when no token waits and no node is enrolled | `919a0001` | 0.0.11 |
| SF-0002 | Low | The password check refuses an unauthenticated caller before it reads the body | `927084ff` | 0.0.11 |
| SF-0003 | Low | A DoH `dns` parameter ending in a multi-byte character no longer panics | `0654ae75` | 0.0.11 |
| SF-0004 | Low | A zone file with a parenthesis open at its end is refused, not a panic | `0a24d7e8`, `52b319ad` | 0.0.11 |
| SF-0005 | High | `calamine` 0.38 closes RUSTSEC-2026-0436 in the spreadsheet reader | `c136a0e1` | 0.0.11 |
| SF-0010 | Info | A trust anchor file with an empty identifier is refused | `432ae695` | 0.0.11 |

What each one was:

- **SF-0001.** On a single controller the on-demand cluster port stayed open when the enrolment token was withdrawn and closed only at a restart. The port requires mutual TLS and a valid token, so the exposure was an open listener, not an open door. It now closes when no token waits and no node is enrolled; the row `net.cluster_port` checks the closure.
- **SF-0002.** `POST /api/v1/auth/password/check` answered 400 to a caller without a session or a token because the body extractor ran before the refusal. The answer carried no data; the route parsed input from an unauthenticated caller, but the service refused the caller before it evaluated the password, so only the JSON decoder ran on it. It now refuses first; the row `web.unauth` passes.
- **SF-0003.** The fuzz target `dns_tls_wire` found that a DoH `dns` parameter cut inside a multi-byte character panicked the connection task (the listener kept serving). The input is now a seed of the target.
- **SF-0004.** The fuzz target `dns_zonefile` found that the dependency `domain` 0.12.3 panicked on a zone file with a parenthesis open at its end (authenticated import only; one request task, the node kept running). Tenko refuses the trigger, and since `52b319ad` the import no longer uses the dependency's zone file scanner at all (its `zonefile` feature is a dev-dependency used by a differential test). The upstream issue, NLnetLabs/domain#763, is still open.
- **SF-0005.** RUSTSEC-2026-0436: `calamine` 0.37.0 could panic and allocate without bound in its CFB/OLE2 parser on a malformed `.xls` reaching the spreadsheet reader (CVSS 7.5). 0.0.11 ships `calamine` 0.38.0.
- **SF-0010.** The trust anchor XML parser (RFC 7958) accepted a file whose `TrustAnchor` `id` was empty; the assertion of the fuzz target `dns_trust_anchor_xml` fired (1,099-byte input) and stopped the release round; no product code panicked. The parser has no caller in the product's run path (a running node reads no trust anchor XML; the parser checks the shipped IANA file in a test and feeds the fuzz target), and the identifier steers no validation. The parser now also refuses an empty `KeyDigest` `id`, an empty `validFrom` and an empty `Zone`, and the input is a seed of the target. The fix landed before the tag moved to the released commit.

Severity decisions of the owner, 2026-11-04 (the state of a fixed finding does not change):

- **SF-0002, High to Low.** "After setup the service refused a caller without a session or token before it evaluated anything; only the JSON decoder ran on the caller's input, under the body limit. No data, no oracle, negligible load. The finding is a broken invariant, not an exposure."
- **SF-0010, Low to Info.** "The parser is not in the run path of a node, and the identifier steers no validation; the fuzz target's own assertion failed, not product code. Fixed for the day the parser becomes a trust boundary."

Compared with the 0.0.10 report: 13 PASS and 2 FAIL rows became 15 PASS; code scanning alerts open 523, after the path exclusions of `8eb7f9f9`, 100 now; Dependabot open 1 (unchanged); secret scanning 0.
