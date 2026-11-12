# UI mock plan: what the web UI's unit tests stand on

- Status: Proposed on 2026-11-12. Waits for the owner's answers to MK-Q1 to MK-Q8 (section 8); nothing is built before them.
- Date: 2026-11-12
- Scope: the mock API under `ui/src/api/mock/`, the UI unit tests that run against it, the end-to-end fakes under `ui/e2e/support/` that reuse its code, and `npm run dev:mock`. Written against `main` at `5a2b5a47`. The facts come from reading both sides, a systematic sample of 39 test files, a comparison of 19 behaviors of the mock and the server, and one probe of a server binary; nothing was built and no suite was run for this plan.

Terms used below, explained once. The **mock API** (or **mock**) is TypeScript code that answers the web UI's HTTP requests without a server. **msw** (Mock Service Worker) is the library that catches those requests: in a test it answers them inside the test process, in the browser it answers them from a service worker, a script the browser runs beside the page. **vitest** runs the UI's unit tests; **Playwright** drives a real browser for the **end-to-end tests** (e2e), which run against a real `tenko serve`. **nextest** runs the Rust tests. A **fixture** is data a test starts from. A **recording** is an answer the real server gave to a request, saved to a file; **replay** is answering a test's request from such a file. A **golden file** is a recording that a test compares byte for byte with what the code produces now, so a change of the answer fails the test until the file is written again. **Drift** is the mock and the server answering the same request differently. A **contract** here is anything machine-checked that holds the mock and the server to the same answer. An **in-process harness** runs the server's HTTP routes inside a Rust test, without a process or a network socket. A **ratchet** is a check that lets a number fall but not rise: today's value is kept in a **baseline** file, and the check fails when a change raises it. A **builder-day** is one working day of one builder session; a **work package** (WP, or MK in this plan) is a unit of work one builder takes. **KEK** is the key-encryption key that encrypts the stored secrets; **TSIG** keys sign DNS messages between servers; `$GENERATE` is a zone file directive that writes many records from one pattern. **SHAPE**, **REPLAY** and **LOGIC** are the three classes of test case defined in section 3.2.

## 1. Summary

The mock is 40,090 lines in 109 files, with 17,310 lines of its own tests in 26 more. Three quarters of its lines are in files that re-implement server rules (about 19,900 lines are rules themselves); it grew by 2,043 lines in the last two weeks. All 253 UI test files outside it run with it answering, and 153 import it directly. A sample of 39 of those 153 files (582 test cases) shows that 66 % of the cases need only an answer of the right shape, 13 % need a recorded sequence of answers, and 20 % depend on a result the mock computes with its own copy of a server rule. So four fifths of what the UI tests prove does not need the mock's logic at all, and the fifth that does proves, besides the UI, a copy of a server rule rather than the rule that ships. Of 19 server behaviors compared, most of them changed in the last two weeks, the mock answers 15 differently from the server or lacks the rule (section 4), among them the scope of a limited operator, the demand for a fresh sign-in and the cancel of a running job; three error codes it sends do not exist on the server. In addition, 60 of the 268 end-to-end tests answer part of the API in the browser with the mock's code, 19 of them for DNS routes the real server has served since October.

The recommendation (section 7) is direction D1a: recording scenarios run against a real server process through the end-to-end harness and write its answers into golden files, the UI tests replay them, and the mock's rules are removed area by area. The first package (half a builder-day) stops the mock from growing without a contract; the second (the recorder) starts catching the drift that comes from server changes. The whole is about 34 builder-days, area by area, each step leaving the suites green; the first four packages (9 builder-days) already carry most of the security value. `npm run dev:mock` stays, as a thin store over recorded scenarios (MK-Q2).

## 2. What the mock is

### 2.1 Its parts and their size

`ui/src/api/mock/` holds 109 source files with 40,090 lines and 26 test files with 17,310 lines (measured on `main` at `5a2b5a47`). On 2026-10-29 its 105 source files held 38,047 lines; 17 commits since then added 2,281 source lines and removed 238 (with the test files, 3,627 and 449), and 13 of those commits changed the server in the same commit.

Each source file was classified by reading its header, exports and main functions:

| Class | What it is | Lines | Share |
|---|---|---|---|
| RULES | a store with validation and refusals it decides, derived fields, state transitions, server-side filtering, sorting or paging: a second implementation of server logic | 29,913 | 75 % |
| THIN | canned answers, static fixtures, stores that hold and return what was written | 7,565 | 19 % |
| INFRA | msw wiring, routing helpers, replies, the reset, scenarios, the event stream plumbing | 2,612 | 7 % |

Inside the RULES files, the share of lines that are rules themselves was estimated per file; summed, about 19,900 lines, half the mock, are rules. By area:

| Area | Lines | Area | Lines |
|---|---|---|---|
| IPAM (prefixes, addresses, hosts, planner, reconciliation, moves) | 9,059 | topology and VLANs | 2,530 |
| import (spreadsheet reading, translation, reconciliation) | 5,182 | wiring and helpers | 2,083 |
| DNS | 4,321 | connectors | 1,498 |
| system (updates, backup, KEK, TLS, language packs, audit) | 3,605 | jobs | 1,419 |
| DHCP | 3,375 | cluster | 1,377 |
| sign-in and access | 3,137 | secrets | 1,191 |
| | | scans 964, findings 349 | 1,313 |

The largest second implementations, with the Rust code they copy:

| Mock file | Lines | Rules share | Error codes | Copies |
|---|---|---|---|---|
| `dhcp-model.ts` | 1,853 | 65 % | 31 | scopes, pools, exclusions, shared networks, options, classes, filters (`tenko-dhcp`, `routes/dhcp`) |
| `job-store.ts` | 1,225 | 70 % | 8 | the job state machine and runner (`tenko-jobs/src/{machine,engine,manual}.rs`) |
| `import-translate.ts` | 1,186 | 85 % | via the vocabulary | sheets and mapping into the import model (`tenko-ipam/src/import`) |
| `dns-model.ts` | 1,038 | 65 % | 24 | zones, record sets, batch changes, zone files, access lists, TSIG keys (`tenko-dns`) |
| `ipam/plan-space.ts` | 919 | 85 % | 17 | nesting, overlap, ranges, next free (`tenko-ipam`) |
| `routes-reconcile.ts` | 868 | 65 % | 16 | proposals, observations, the reconciler |
| `routes-secrets.ts` | 773 | 55 % | 16 | secrets and remote secrets |
| `connectors-store.ts` | 764 | 45 % | 14 | plugins, instances, settings schema validation |
| `import-reconcile.ts` | 703 | 85 % | 0 | the import's create and update commands |
| `routes-updates.ts` | 699 | 55 % | 16 | updates and modules |
| `routes-vlans.ts` | 687 | 70 % | 6 | VLAN provisioning (`tenko-ipam/src/vlan/provision.rs`) |
| `access-store.ts` | 667 | 55 % | 8 | grants, delegation, sign-in policy per role, service accounts |
| `routes-auth.ts` | 659 | 60 % | 16 | sign-in, sessions, factors |

The names were mostly copied faithfully: of the 692 code-like names in the mock's sources (error codes, audit actions, job kinds, event topics), 45 do not occur as a literal in the server's sources; most of those the server builds at run time, but three are error codes the server never sends (section 4). So drift is mostly in when a code is sent, not in its spelling.

### 2.2 How it is wired

- **Unit tests.** `ui/src/app/testing/setup.ts` starts the msw server before every test file with `onUnhandledFrame: "error"` and resets the mock's state after every test. So all 253 UI test files outside the mock run with it answering, whether they import it or not. Seven area testkits (`ui/src/{audit,auth/account,dhcp,dns,ipam,settings,updates}/testkit.ts`, 395 lines) seed it for their area. The modules imported most often by tests are `node` (the msw server, 67 files), `ipam/api` (42), `db` (39), `routes-dns` (26), `dhcp-model` (16), `fixtures` (15), `routes-dhcp` (14), `reconcile-store` and `dns-model` (13 each).
- **`npm run dev:mock`.** `vite --mode mock` sets a switch that `ui/src/index.tsx` reads to start the same handlers in a service worker (`ui/src/api/mock/browser.ts`), with an artificial latency and six scenarios (`setup`, `setup-slow-disk`, `signed-out`, `signed-in`, `lab`, `weak`) chosen in the address or at run time through `window.tenkoMock`. The switch is replaced at build time, so no build carries the mock.
- **End-to-end tests.** 15 of the 51 specs (86 of 268 tests) answer part of the API in the browser with `page.route` fakes under `ui/e2e/support/*-mock.ts` (1,467 lines). All but `cluster-mock.ts`, which builds its answers by hand in the mock's shape, call the mock's models:

  | Fake | Specs (tests) | Why, as its header says |
  |---|---|---|
  | `dns-mock.ts` | dns-zones (9), dns-dnssec (3), dns-import (3), dns-keys (4) | "until WP4.2 lands" (the work package of the DNS zone service) the server answered the DNS routes with 501. It landed in October: these 19 tests prove the UI against the mock's DNS model while the real one is in the server, and one of them accepts either answer. |
  | `dns-resolver-mock.ts`, `dns-blocking-mock.ts`, `dns-cache-mock.ts`, `dns-infra-mock.ts` | dns-forwarders (5), dns-lists (4), dns-settings (5), dns-recursion (6), dns-cache (4), dns-blocking (3) | the e2e server runs without the `dns` role |
  | `cluster-mock.ts` | cluster (12), cluster-membership (14) | the e2e server is one controller |
  | `metrics-mock.ts` | metrics (9), metrics-layout (2) | the stream of several controllers |
  | `dhcp6-leases-mock.ts` | dhcp6-leases (3) | no DHCPv6 client behind the e2e server |

  So 60 end-to-end tests run the mock's code for part of the API and 26 more a hand-made copy of the cluster's; "only the end-to-end tests notice drift" holds for the 182 tests that reach the server for everything.
- **Elsewhere.** The mockups under `design/` are static HTML and do not use the mock; no documentation screenshot is made with it. CodeQL skips the directory (`.github/codeql/config.yml`). `docs/ipam.md` states that the mock counts utilization as `tenko_ipam::tree` does; the comparison in section 4 confirms it.

## 3. What depends on it

### 3.1 The 153 test files that import it, by area

| Area | Files | Area | Files | Area | Files |
|---|---|---|---|---|---|
| DNS | 22 | updates | 7 | setup | 3 |
| DHCP | 21 | discovery | 7 | secrets, nodes, jobs, connectors, cluster | 3 each |
| IPAM | 20 | shell | 5 | import, grid, audit | 2 each |
| settings | 15 | topology, scans, dashboard | 4 each | language packs, the app | 1 each |
| hosts | 10 | sign-in and account | 8 | | |

### 3.2 What a sample of them proves

Every fourth file of the 153 (sorted by path, starting with the first) was read with the testkit and mock functions it calls: 39 files, 10,098 lines, 582 test cases. Each test case was put in one class:

- **SHAPE**: every assertion holds for any server answer of the right shape that the test could fix in advance (a seed, a canned answer, an error the test sets itself). The case proves UI behavior: rendering, interaction, what the UI sends, client-side checks, routing, texts.
- **REPLAY**: the case depends on state across requests, but only trivially (write a value, read it back; a list grows by the item posted). A recorded sequence of answers serves it.
- **LOGIC**: at least one assertion depends on a result the mock computes with its own copy of a server rule: a refusal it decides from the request, a derived value (next free address, a job's steps, a list compiled from a fetch), or filtering and paging done by the "server".

| File | Cases | SHAPE | REPLAY | LOGIC | Mock logic it leans on |
|---|---|---|---|---|---|
| `src/App.test.tsx` | 14 | 13 | 1 | 0 | scenario seed |
| `src/auth/account/Account.test.tsx` | 7 | 7 | 0 | 0 | seeded account |
| `src/auth/account/Sessions.test.tsx` | 11 | 7 | 4 | 0 | sessions list, revoke |
| `src/cluster/QueueView.test.tsx` | 23 | 6 | 11 | 6 | queue summary, reapply refusal, heal |
| `src/connectors/ConnectorsView.test.tsx` | 31 | 14 | 5 | 12 | enable, run, check, settings validation |
| `src/dashboard/model.test.ts` | 37 | 37 | 0 | 0 | none |
| `src/dhcp/SharedNetworksPage.test.tsx` | 9 | 5 | 1 | 3 | name check, in-use refusal |
| `src/dhcp/filters/FiltersPage.test.tsx` | 8 | 4 | 1 | 3 | MAC normalization, duplicate |
| `src/dhcp/leases/LeasesPage6.test.tsx` | 40 | 21 | 0 | 19 | server-side lease filters, peer lookup |
| `src/dhcp/reservations/HostReservations.test.tsx` | 32 | 31 | 1 | 0 | seeded leases |
| `src/dhcp/v6/RaPanel.test.tsx` | 19 | 19 | 0 | 0 | none |
| `src/discovery/HostObservations.test.tsx` | 14 | 10 | 2 | 2 | approve, observation order |
| `src/discovery/dormant.test.tsx` | 7 | 7 | 0 | 0 | seed |
| `src/dns/ZonePage.test.tsx` | 17 | 6 | 5 | 6 | record filter, batch diff, origin refusal, serial |
| `src/dns/ZonesPage.test.tsx` | 15 | 11 | 2 | 2 | zone creation |
| `src/dns/forwarders/ForwarderDialog.test.tsx` | 11 | 7 | 4 | 0 | forwarder store |
| `src/dns/lists/ListsPage.test.tsx` | 22 | 10 | 6 | 6 | list compile count, fetch, duplicate name, stale revision |
| `src/dns/recursion/NtaSection.test.tsx` | 19 | 16 | 3 | 0 | anchor store |
| `src/grid/layoutViews.test.tsx` | 5 | 0 | 5 | 0 | preferences store |
| `src/hosts/HostView.lifecycle.test.tsx` | 8 | 4 | 0 | 4 | decommission and reinstate planner |
| `src/hosts/HostsView.test.tsx` | 15 | 8 | 3 | 4 | host filters, dry-run summary |
| `src/import/PreviewRows.test.tsx` | 15 | 9 | 1 | 5 | preview paging, stale 409 |
| `src/ipam/address/AddressForm.test.tsx` | 10 | 5 | 4 | 1 | duplicate refusal |
| `src/ipam/history/HistoryPanel.test.tsx` | 9 | 4 | 3 | 2 | history paging, restore check |
| `src/ipam/prefix/NextFreeDialogs.test.tsx` | 11 | 5 | 0 | 6 | next-free search |
| `src/ipam/reconcile/ReconcileView.test.tsx` | 19 | 15 | 0 | 4 | row filters, finding actions |
| `src/ipam/vlan/PrefixesDialog.test.tsx` | 7 | 3 | 0 | 4 | prefix filter by VLAN |
| `src/jobs/gating.test.tsx` | 9 | 9 | 0 | 0 | seeded jobs |
| `src/scans/ScanNow.test.tsx` | 17 | 8 | 2 | 7 | scan creation: coverage, targets, kill switch |
| `src/secrets/RevealDialog.test.tsx` | 7 | 7 | 0 | 0 | canned answers |
| `src/settings/SettingsPages.test.tsx` | 6 | 6 | 0 | 0 | none |
| `src/settings/audit-export/AuditExportPage.test.tsx` | 14 | 3 | 3 | 8 | export status, policy, test result, validation |
| `src/settings/dns/InfraSection.test.tsx` | 15 | 9 | 1 | 5 | infrastructure cache list, filter, paging, flush |
| `src/settings/reconciler/ReconcilerPage.test.tsx` | 23 | 16 | 6 | 1 | `If-Match` precondition |
| `src/setup/Wizard.test.tsx` | 13 | 8 | 1 | 4 | password check, setup token check |
| `src/shell/areas-wp30.test.tsx` | 9 | 9 | 0 | 0 | module flags |
| `src/topology/SsidView.test.tsx` | 16 | 12 | 1 | 3 | WLAN class finding |
| `src/updates/ModuleGating.test.tsx` | 10 | 9 | 0 | 1 | restart warning |
| `src/updates/WizardModules.test.tsx` | 8 | 5 | 2 | 1 | configured and running modules |
| **Total (39 files)** | **582** | **385 (66 %)** | **78 (13 %)** | **119 (20 %)** | |

What it says:

- 14 of the 39 files (36 %) have no LOGIC case; 3 have a LOGIC majority (`NextFreeDialogs`, `PrefixesDialog`, `AuditExportPage`), the other 22 mix.
- About 31 of the 119 LOGIC cases are weak: the mock computes the value, but from an input the test fixes, so a recorded answer serves them as well. The others split roughly into server-side filtering and paging (about 40 %), refusals the mock decides (about 30 %), and derived values and state transitions (about 30 %).
- A LOGIC case proves two things at once: that the UI handles the answer, and that the mock's rule gives that answer. Only the first is the UI's business; the second proves the copy. Against the real server's answer, the first stays and the second moves to a Rust test of the rule, where it proves the code that ships.
- The borderline calls (a seed made through the mock's planner counted as SHAPE; a narrowing request parameter counted as LOGIC) move about 20 cases either way and do not change the picture.

The mock's own 26 test files (17,310 lines) prove the mock. They are not counted above; they are the best inventory of the behaviors the UI relies on, which a migration uses as its checklist (section 7).

## 4. How far the mock and the server have drifted

19 behaviors of four areas were read on both sides: 16 from server commits of the last two weeks, and three long-standing rules that every page meets (I5 to I7) (`git log` of `crates/tenko-api/src/routes/` since 2026-10-29 has 26 commits; 13 of them changed no mock file). "Differs" means a UI test against the mock sees another status, error code, field or acceptance than against the server. The descriptions name what is accepted and refused, nothing more.

| # | Behavior (server commit) | Verdict | The difference |
|---|---|---|---|
| A1 | PINs of six digits (`fa399894`) | differs | the server holds any digits-only secret to six digits; the mock lets a custom policy with a lower minimum accept four or five. The policy error's field is `password` on the server, `new_password` or `admin.password` in the mock |
| A2 | a password for every administrator (`fa399894`) | differs | granting the administrator role: the server also refuses a password not known to meet the administrator rule (400 `auth.invalid_request`, field `roles`); the mock refuses only PIN-like secrets |
| A3 | a fresh sign-in for sensitive changes (`e9a7aac4`) | rule missing | the server answers 403 `auth.step_up_required` with `required: fresh` on settings, role policies, adding or removing factors, recovery codes, token creation and the first password; the mock asks for a recent sign-in only on backup and KEK, a password on secret reveal, and a stronger sign-in on updates, delegation and scoped tokens, but not on the routes listed |
| A4 | a known device passes the account-wide sign-in delay (`5e93f4d1`) | rule missing | the mock counts failures per user name only; no account-wide delay, no cap of ten known devices, no expiry after 30 days; a malformed device id is 404 in the mock, 400 `sys.invalid_value` on the server. The list's fields and order are the same |
| A5 | tokens held to their strength (`e9a7aac4`) | differs | creating a personal token from a weak session: 403 `auth.step_up_required` on the server, 201 in the mock; a service account's token takes the stricter of creator and owner on the server, the creator's only in the mock; the mock never authenticates a bearer token at all |
| A6 | the password check refuses an anonymous caller before it reads the body (`927084ff`) | differs | after setup, an anonymous call with an empty or malformed body: 401 `auth.unauthenticated` on the server, 400 `sys.invalid_request` in the mock |
| D1 | deny wins in DNS access lists (`8ab632e2`) | same | both store any mix; evaluation happens per query and is out of the mock's reach. Beside it: a duplicate list name is 409 `dns.acl.in_use` in the mock, 400 `sys.invalid_value` on the server, and the mock refuses an entry of kind `kerberos` |
| D2 | the profile's floor on zone transfers (`8ab632e2`) | same | neither refuses a setting; the findings the server raises for a transfer weaker than the profile are missing in the mock |
| D3 | limits on zone file imports (`8ab632e2`) | rule missing | the record, `$GENERATE` and record set limits (422 `dns.zonefile.invalid`), 413, 408 and 429 `dns.import.busy` are not in the mock, which also skips `$GENERATE` as a loss instead of expanding it |
| D4 | owners of names in secure zones (`b3eee8b3`, `4ab64680`) | differs | the server refuses an owner for a name that holds a manual, IPAM or DHCP record (409 `dns.owner.protected`); the mock refuses only locator and wildcard names, and treats `*` in any label as a wildcard where the server looks at the first. The mock ignores `scope`, lacks the refusals and the `If-Match` check on release, filters owners by substring where the server matches exactly, and omits `hold_until` |
| D5 | DHCP settings, relays, bounds (`f8786c56`) | differs | the bounds, codes and relay rules agree; but a settings `PUT` without `lease`, `authoritative` or `ddns` resets them in the mock and keeps them on the server, the mock raises the revision on a change that changes nothing, and a type error is `dhcp.settings.invalid` in the mock and a request parse error on the server |
| D6 | lease rows, lease history, lease paging (`72a20803`, `c121826d`) | differs | the lease row agrees; a DHCPv4 history row carries `names` on the server, never in the mock; paging differs as in I6 |
| I1 | a new or resized prefix and the prefixes it would hold (`d760a656`) | rule missing | the server answers 403 `auth.out_of_scope` before planning when the new network would hold a prefix outside the caller's grants; `auth.out_of_scope` appears nowhere in the mock |
| I2 | a limited operator sees and changes nothing outside its scope (`788290be`) | rule missing | the server filters lists before paging and refuses reads and writes outside the scope; the mock answers everything to any signed-in user (its own comment in `routes-access.ts` says it enforces no scopes) |
| I3 | bounded IPAM imports (`e9a7aac4`) | differs | the server limits sheets, rows, columns, cells, text and uncompressed size besides the 20 MiB upload (413 `import.upload.too_large`); the mock checks only the upload and adds a parameter the server does not send |
| I4 | batch and sink lists grow as they fill (`e6e3a457`) | same | no change visible in the API |
| I5 | utilization counting (`docs/ipam.md`) | same | used, reserved, capacity, the edges of IPv4 /30 and IPv6 /126, supernet sums agree; percentages may differ in the last digit (floating point on the server, rounded integers in the mock) |
| I6 | list paging (the prefix and address lists) | differs | default 100 and maximum 1,000 agree, but a `limit` over 1,000 is 400 `sys.invalid_query` on the server and silently clamped by the mock; the server's cursor is bound to its endpoint and filters, so a foreign cursor is 400 `sys.invalid_cursor`, where the mock's offset cursor is accepted anywhere |
| I7 | job states, cancel, import steps | differs | the states and the transition table agree, but canceling a running job answers 202 on the server with the job still running and `cancel_requested` set (the runner rolls it back later, and a second cancel is 202 again); the mock rolls back inside the call, answers with the job `canceled`, and a second cancel is 409. An import job's steps are `import.chunk` repeated and `import.finish` on the server, a fixed `import.parse`, `import.plan`, `import.apply_chunk` in the mock |

Beyond the 19, three error codes the mock sends do not exist on the server: a move into a supernet is 422 `ipam.move.target_not_network` on the server and 422 `ipam.move.target_supernet` in the mock (both appeared on 2026-10-09 and never matched); `ipam.prefix.dns_reverse_role` (`ui/src/api/mock/ipam/plan-space.ts:349`) and `cluster.member.not_learner` (`ui/src/api/mock/routes-cluster.ts:57`) occur nowhere in the server's sources. And the stale DNS fakes of the end-to-end suite (section 2.2).

In sum: 4 the same, 10 different, 5 rules the mock lacks. Three of the five missing rules guard access (scope, fresh sign-in, token strength), so in the unit tests the UI's handling of those refusals is proved only where a test sets the refusal by hand; the end-to-end suite has one spec for a scoped operator (`scoped-operator.spec.ts`, 6 tests, against the real server) and none for the fresh sign-in or token strength. Two differences change what a page shows in normal use: the cancel of a running job (the UI tests a sequence the server never produces) and the settings `PUT` of DHCP.

## 5. What could carry a contract today

- **The generated types** (`ui/src/api/generated/schema.d.ts`, 56,379 lines, and `operations.ts`, 467 lines, from `docs/api/openapi.json`; `npm run lint` checks they are current). They hold the mock to the server's shapes, which is why the drift above is in values and conditions, never in field types. They carry no values and no behavior.
- **`docs/api/openapi.json`**: 320 paths, 450 operations, 1,096 schemas. Error codes are listed in the prose of each response's description, not as data; 4 operations carry an example of any kind and no response carries an example answer. Its schemas name the format of every field (`uuid`, `date-time`, the `SecretString` type of secrets), which is what a recorder needs to make answers repeatable (section 7).
- **Golden files.** `docs/api/examples/` does not exist on `main` at `5a2b5a47`. The contracts of the dashboard history (WP18.0, a work package not yet merged there) bring the first golden file, `docs/api/examples/metrics-stream.jsonl`, written byte for byte by a Rust test from hand-built values of the stream's data types and read by the UI test `ui/src/api/metrics-history.contract.test.ts`. It is the same idea for one data type, not a recording of routes; it shows that a golden file shared by a Rust test and a UI test fits the project's checks.
- **The scope table** (`crates/tenko-api/src/routes/scope_table.rs`, 2,016 lines): an in-process installation of the IPAM side (the authorizer with real accounts and grants, the IPAM service, the job engine, the import service, the reconciler, the findings) that calls every IPAM operation of the OpenAPI document for a scoped operator and fails on an operation it does not know. The other areas (access, audit, backup, cluster, connectors, DNS, the key-encryption key, scans, secrets, settings, setup, system, users and more) are listed there as areas it does not drive. Beside it, `crates/tenko-api/src/routes/tests.rs` calls every operation anonymously and with a token, and the test kit of `routes::auth` (a `Harness` that sends a request to the router and returns status and body, used by about 43 files) covers sign-in. So the server can produce answers in process for IPAM and sign-in today; for the other areas an installation would have to be built first.
- **The end-to-end support** (`ui/e2e/support/`): `server.ts` starts a real `tenko serve` per test in a directory of its own (the **Lab profile**, the security profile meant for test installations, which allows plain HTTP), with the `dhcp` role when a test asks, plus helpers for accounts, sign-in, IPAM and imports. A probe on 2026-11-12 with a copy of a debug binary of `main` (`tenko 0.0.11`, Lab profile, plain HTTP on loopback, a fresh data directory, before setup) measured 1,888, 1,830 and 1,902 ms from start to the readiness probe answering 200. This harness reaches every route the shipped server serves, through the same middleware, configuration and roles.
- **The server's tests**: `crates/tenko-api` alone has 1,395 test functions. Several behaviors of section 4 are proved there or beside it (the scope table proves I1 and I2; `crates/tenko-jobs/tests/transitions.rs` has `running_cancel` and `queued_cancel` for I7); which rule halves of the UI's LOGIC cases have no Rust test yet is part of each area package (section 7).
- **Time.** Only `tenko-auth` and `tenko-jobs` take their time from a clock a test can set; `Timestamp::now()` appears in 239 files of the server's crates. Recorded answers therefore carry real times, and a recorder must replace them, whichever direction records.
- **Suite times today**, from the logs of the **gate** (the full check the project lead runs on the development workstation before every merge): the full vitest run took 87 s and 127 s for 5,864 tests, of which 44 % to 50 % is setting up the test environment; the end-to-end suite, at 264 tests then, took 6.9 to 8.0 minutes with 4 workers.

## 6. The directions

The brief's three directions are D1 to D3; D1 comes in two variants, and D4 is added because the facts suggest it.

### D0. Leave the mock as it is

Removes nothing, costs nothing now. Keeps: every server change of behavior made twice (17 mock commits in two weeks), and every server change that skips the mock drifting silently (13 of the 26 route commits since 2026-10-29; section 4 shows the result); 15 known differences, three access rules the UI tests never meet, and 60 end-to-end tests partly on the mock's code. Drift is caught by the end-to-end tests that reach the server, for the flows they walk. `dev:mock` unchanged. The facts do not support this: drift is the norm for behavior changed in the last two weeks, and it hides most where security is concerned.

### D1a. Recorded answers from a server process (recommended)

Recording scenarios, written in TypeScript beside the end-to-end tests and run by the same runner without a browser, start `tenko serve` through `ui/e2e/support/server.ts`, drive requests over HTTP, and write the answers to golden files; a check mode compares a new recording with the files and fails when one is stale. The UI tests replay the files through one msw handler. The mock's rules are removed area by area; a LOGIC case keeps its UI half on the recorded answer, and its rule half is proved by a Rust test of the rule in the crate that owns it (many exist; each area package adds the missing ones).

- Removes: the RULES code and the mock's own tests, area by area; the end-to-end fakes that call the mock's models.
- Keeps: the THIN stores and the INFRA (for `dev:mock`, MK-Q2); the SHAPE and REPLAY cases unchanged in meaning; hand-written canned answers, without rules, for the states one server cannot reach (a cluster of several controllers, connector processes, network scans, an update installed from a release source, DHCPv6 clients; MK-Q7), about 5,000 of today's lines, which shrink to fixtures.
- Cost: about 34 builder-days (section 7).
- Suites afterwards: vitest as today or slightly faster (26 mock test files fewer; replay answers from a table instead of running rules); the recording check needs the debug binary the gate already builds for the end-to-end suite, and adds an estimated 1 to 3 minutes to the gate (one server start of about 2 s plus setup per scenario file, 4 in parallel; MK1 measures it). A server builder who changes behavior runs the check for the area after building the binary, as for an end-to-end spec today.
- Drift caught by: the recording check, at the gate or in the server builder's own run; and the replay itself, which fails a UI test on a request no recording holds and names it, so a UI test cannot silently depend on behavior nobody recorded. What no scenario records is not caught, nor are the hand-written answers of MK-Q7, which only the generated types and the end-to-end suite hold.
- `dev:mock`: stays, thinner (MK-Q2).
- Why a process and not D1b: it reaches every area the shipped server serves, through the binary as it ships, with no installation to build per area.

### D1b. Recorded answers from in-process server tests

As D1a, but the recording scenarios are Rust tests in `tenko-api` that build the installation in process, as the scope table does, and nextest compares the files.

- Removes and keeps: as D1a.
- Cost: about 40 builder-days: D1a's packages, plus an installation per area beyond IPAM and sign-in (about 0.5 to 1 builder-day each for DNS, DHCP, system, secrets, topology, scans).
- Suites afterwards: seconds in nextest instead of minutes in the gate; no binary needed to record.
- Drift caught by: nextest. Earlier than D1a only for a change inside `tenko-api`: a builder of `tenko-ipam` or `tenko-dns` runs only that crate's tests, so the recordings fail at the gate there as in D1a.
- Worth adding later for IPAM, where the installation exists (MK-Q1, option b).

### D2. Keep the mock and prove it

The same scenarios run against the mock and against a real server process, and a difference fails a test.

- Removes: nothing. Adds the parity runner and the scenarios, and to pass, the rules the mock lacks today must be written into it: the scope rules, the fresh sign-in, token strength, the asynchronous cancel, the stricter paging, the import limits. The mock grows by an estimated 2,000 to 4,000 lines.
- Cost: about 22 builder-days (runner 3, scenarios about 1.5 per area for 9 areas, the known differences about 6), then for good: every server change of behavior is written twice, plus a parity scenario.
- Suites afterwards: vitest as today; the parity run needs the binary, a few minutes in the gate.
- Drift caught by: parity scenarios, where one exists.
- `dev:mock`: unchanged and more faithful.
- Weighs badly on the first priority: the access rules would gain a second, TypeScript implementation that can itself be wrong, and the UI tests would still prove the UI against the copy.

### D3. The UI's behavior tests against a real server

vitest starts a `tenko serve` per worker, resets it between files (a fresh data directory and a restart, about 2 s, plus setup and sign-in), and the tests seed it through the API.

- Removes: the RULES code where a test can build its state through the API.
- Keeps: the same hand-written answers as D1a for the states one server cannot reach.
- Cost: about 45 builder-days (infrastructure 3; 153 files at about a quarter of a day each, since every seed becomes API calls; the canned answers as in D1a).
- Suites afterwards: the UI unit run grows from about 2 minutes to an estimated 5 to 8 (253 files over 4 workers at 3 s or more of restart and setup each, plus real request time). A UI change can reuse a built binary, but a branch that changes the server needs a fresh debug build before its UI tests mean anything, which puts a cargo build of the whole server into UI work on a shared build machine.
- Drift caught by: everything the tests touch, at the price of turning unit tests into integration tests.
- `dev:mock`: kept frozen (no longer test truth, it rots) or replaced by `npm run dev` against a local server.

### D4. Fix the known differences in place

Write the five missing rules and the ten differences of section 4 into the mock, correct the three codes the server never sends, and drop the stale DNS fakes of the end-to-end suite.

- Removes: nothing; adds about 1,500 lines (the scope rules are the largest part).
- Cost: about 6 builder-days.
- Drift caught by: nothing new. At the measured rate (15 of 19 recent behaviors), new differences appear within weeks.
- `dev:mock`: unchanged and, for a while, more faithful.
- Worth it only as a stopgap if the owner wants none of D1 to D3 now.

### Comparison

| | D0 leave | D1a process recordings | D1b in-process recordings | D2 parity | D3 real server | D4 fix in place |
|---|---|---|---|---|---|---|
| Security: UI tests see the server's real refusals | no | yes, for recorded scenarios | yes, for recorded scenarios | only via a TypeScript copy | yes | via a copy fixed once |
| Performance: added suite time | none | 1 to 3 min in the gate | seconds in nextest | minutes in the gate | 3 to 6 min per UI run, a server build for server branches | none |
| Usability: double work afterwards | stays | ends | ends | stays and grows | ends | stays |
| `dev:mock` | kept | thinner | thinner | kept | frozen or gone | kept |
| Drift caught | by e2e tests that reach the server | gate, or the server builder's check | nextest; gate for crates other than `tenko-api` | where a parity scenario exists | everywhere touched | not |
| Builder-days | 0 | about 34 | about 40 | about 22, then ongoing | about 45 | about 6, then ongoing |

## 7. Recommendation and packages

**Recommended: D1a.** By the owner's order. On security, it puts the server's real refusals (scope, fresh sign-in, token strength) into the UI's tests, recorded from the binary as it ships, and removes a second implementation of access rules instead of adding one (D2, D4); D3 and D1b are as faithful on this point but not more. On performance, it adds an estimated 1 to 3 minutes to the gate and nothing to the UI loop, where D3 adds minutes to every UI run; D1b is cheaper in suite time, but needs an installation built per area and catches drift earlier only for changes inside one crate. On usability, it ends the double work, covers every area with one recorder written in the same language as the UI tests, and keeps `dev:mock`. It fits the rule that correct and reliable tests come before features: a UI test then proves the UI against the code that ships. Its cost ends, unlike D2 and D4.

**How the recorder and the replay work** (MK1 builds them; the pilot proves them):

- A **scenario** is an ordered list of steps on one fresh server. A step is a write (any request but `GET`) with its answer, or a wait for a named condition (a job finished, a lease granted), as the end-to-end tests wait today. After setup and after every write, the scenario records the answers to the reads (`GET`) it lists; those reads make a **state**. The event stream is recorded too: the events that arrive during a step belong to it.
- **Replay**: a UI test names a scenario and optionally a state to start in. A `GET` is answered from the current state, as often and in any order (polling works); a `GET` the state lacks fails the test and names the request. A write must equal the scenario's next write (method, path and query, and the JSON body after normalization) or the test fails and names it; it gets the recorded answer, the state advances, and the step's events are emitted on the mock's event stream. That is how the REPLAY cases (write, then read back) are served.
- **Normalization**: every answer is walked with its operation's schema from `docs/api/openapi.json`. Identifiers (`format: uuid`) become fixed values in order of first appearance; times (`format: date-time`) become fixed times in the same order (`2026-01-01T00:00:00Z` plus one second per new value); secrets (`SecretString`) become placeholders. Revisions and counts come out the same on a fresh server when the steps are the same. The check fails on a scenario whose two runs differ, so a source of difference is found when the scenario is written, not later.

The packages, in order. MK0 stops the mock from growing on its own, but not the other half of drift: a server change that leaves the mock alone. That half is caught from MK1 on, for every behavior a recording holds, which is why MK1 follows at once. From MK1 on, a server change of behavior in an area not yet migrated records its changed answer and converts the UI tests that touch it, instead of editing the mock; that costs the change about what editing the mock costs today. After MK1 the area packages are independent of each other: each owns its area's mock files, tests, testkit and scenarios, and switches its area's `dev:mock` handlers to its recordings in the same package, so `dev:mock` never loses an area. `db.ts` and `handlers.ts` are touched by each (one line per area; the lead merges them).

| Package | What | Files owned | Done when | Builder-days |
|---|---|---|---|---|
| MK0 | **The ratchet.** A script with a baseline of every mock source file's line count and error-code literals, and of the e2e fakes: a new file, a file over its count or a new code fails, unless the change cites a server test that proves the same answer (`mock-contract: <file>::<test>`, checked to exist; the citation is a promise a reviewer reads, not a proof). After MK1 the citation is a recording instead. A second check: every error code the mock sends must occur in the server's sources (it would have caught the three codes of section 4). `--prune` lowers the baseline when files shrink. Runs beside `test-lint` | `scripts/mock-ratchet.mjs`, its baseline and test, a section in `docs/testing/rules.md`, one step in the CI job that runs `test-lint` | CI fails on a commit that adds a line to `dhcp-model.ts` without a citation; the three codes are corrected; the baseline is committed | 0.5 |
| MK1 | **Recorder and replay.** The recording runner on the end-to-end harness (a runner project without a browser), the normalizer, the check mode, the file format under `docs/api/examples/recorded/<area>/<scenario>.json` (MK-Q6); the msw replay handler and a testkit call `useRecording(name, state?)`, typed against `operations.ts`; a request log (`TENKO_REPLAY_LOG`) that names which test files request which routes. Pilot: an IPAM list with paging, a scoped operator's refusal, and a job canceled while it runs (I7, a sequence with events), each replayed by one converted test file. Measures the check's time in the gate and the files' size | `ui/e2e/record/`, `ui/src/api/recorded/`, the pilot test files, the gate step | the pilot passes in the gate; a changed server answer fails the check; two runs of every pilot scenario are identical; the measured time and size are in the package's report | 3.5 |
| MK2 | **Honest end-to-end tests.** The four DNS zone specs (19 tests) run against the real server without `dns-mock.ts`. The e2e server gets the `dns` role on loopback ports, as it already gets the `dhcp` role, where that works, and the DNS node fakes go; the states one server cannot reach (several controllers, DHCPv6 clients) use hand-written answers without the mock's models | `ui/e2e/support/*-mock.ts`, the 15 specs, `server.ts` | no file under `ui/e2e/` imports `src/api/mock`; the specs pass | 2 |
| MK3 | **Sign-in and access** (security first): `auth.ts`, `routes-auth.ts`, `access-store.ts`, `routes-access.ts`, `routes-admin.ts`, `policy.ts`, `profiles.ts`; scenarios for A1 to A6 and the scope refusals | those files, `ui/src/auth/**` and the setup tests | the area's RULES lines removed; each removed mock test's behavior named against a Rust test (added where missing); the area's `dev:mock` pages on recordings | 3 |
| MK4 | **IPAM** (`ipam/*`, `routes-move.ts`, `routes-reserve.ts`, `name-authority.ts`); scenarios for I1, I2, I5, I6 and the move refusals | those files, `ui/src/ipam/**`, `ui/src/hosts/**` tests | as MK3 | 4.5 |
| MK5 | **Jobs and import** (`job-store.ts`, `routes-jobs.ts`, `import-*.ts`, `routes-import.ts`): the asynchronous cancel and the import's real steps | those files, `ui/src/jobs/**`, `ui/src/import/**` tests | as MK3 | 4.5 |
| MK6 | **DNS** (`dns-*.ts`, `routes-dns*.ts`) | those files, `ui/src/dns/**`, `ui/src/settings/dns/**` tests | as MK3 | 3.5 |
| MK7 | **DHCP** (`dhcp-model.ts`, `dhcp-leases-model.ts`, `routes-dhcp*.ts`) | those files, `ui/src/dhcp/**` tests | as MK3 | 3.5 |
| MK8 | **Topology, reconciliation, scans, findings, discovery** | `topology-*.ts`, `routes-vlans.ts`, `reconcile-*.ts`, `routes-reconcile*.ts`, `ipam-reconcile-model.ts`, `scans-store.ts`, `routes-scans.ts`, `findings-store.ts`, and their tests | as MK3; scans on hand-written answers (MK-Q7) | 3.5 |
| MK9 | **System and the rest**: updates, backup, the key-encryption key (KEK, the key that encrypts the stored secrets), TLS, language packs, audit and its export, secrets, connectors, cluster, nodes, metrics | the remaining RULES files and their tests | as MK3; the RULES class is empty; cluster, connectors and update installs on hand-written answers (MK-Q7) | 4.5 |
| MK10 | **Closing**: the ratchet's baseline at its floor, `docs/ipam.md`, `ui/README.md` and `docs/testing/rules.md` updated | docs, the baseline | the mock holds THIN and INFRA and the hand-written answers only | 1 |
| | | | **Total** | **34** |

The area estimates include the Rust tests for the rule halves that have none yet (about half a builder-day an area) and the switch of the area's `dev:mock` pages. The range is 30 to 40 builder-days; MK1's pilot narrows it.

**How each step stays green.** An area package converts its tests file by file (a test that passes on the recording replaces the one on the mock's rule in the same commit), removes a rule only after no test imports it, and deletes a mock test only after naming the Rust test that proves its behavior. About 100 test files outside the areas (the app, the shell, the dashboard) request routes of many areas without importing the mock; MK1's request log names which of them request the area's routes, the package runs those files in batches (`--maxWorkers=4`), and the gate's full run is the final check. The ratchet's baseline only falls.

**What the suites look like afterwards**: the vitest run stays at about its present 1.5 to 2 minutes (fewer files, answers from a table, the environment setup unchanged); the gate gains the recording check, estimated at 1 to 3 minutes and measured in MK1; the end-to-end suite keeps its 268 tests, of which the 19 DNS zone tests and, if the `dns` role works in the harness, the 27 DNS node tests then reach the real server.

**A cheaper first stop.** MK0 to MK3 (9 builder-days) already give most of the security value: the growth stops, the recorder exists for every area, the end-to-end tests are honest, and sign-in and access are proved against the real server. MK-Q5 asks whether to stop there for now.

## 8. Questions for the owner

**MK-Q1. Which direction?**
- (a) D1a, recordings from a server process; about 34 builder-days, area by area. *Recommended* (section 7).
- (b) D1a now, with D1b's in-process recordings added later for IPAM, where the installation exists, so that IPAM changes fail in nextest already.
- (c) D2, keep the mock and prove it with parity scenarios; about 22 builder-days and the double work stays.
- (d) D3, the UI's behavior tests against a real server; about 45 builder-days and slower UI runs.
- (e) D4, fix the known differences in place; about 6 builder-days, drift resumes.
- (f) D0, leave it.

**MK-Q2. What becomes of `npm run dev:mock`?**
- (a) It stays, as the THIN stores over recorded scenarios: every page shows real answers, writes are kept and shown, refusals appear where a scenario recorded them, no rules. Each area package switches its pages. *Recommended*: pages can still be designed without a server, and it costs nothing in the tests.
- (b) It goes; a `npm run dev:lab` starts a local copy of a server binary with a seeded data directory. Exact, but needs a binary.
- (c) It keeps today's code, outside the tests. It would rot unseen.

**MK-Q3. How strict is the ratchet before recordings exist (MK0 to MK1)?**
- (a) Growth only with a cited server test that proves the same answer. *Recommended*: stops silent growth at once without blocking a server change.
- (b) No growth at all. A server change that must change the mock waits for MK1.
- (c) A warning only.

**MK-Q4. The end-to-end fakes (MK2): now, or at the end?**
- (a) Now, right after MK1: the DNS zone fakes go, the e2e server gets the `dns` role where it can. *Recommended*: 60 tests that count as reaching the server partly run the mock's code, 19 of them for routes the server serves.
- (b) At the end, after MK9.

**MK-Q5. At what pace?**
- (a) MK0 to MK3 now (9 builder-days); then the other areas as builder slots are free, an area early when a server change touches it. *Recommended*.
- (b) All of it as one slice of about 34 builder-days.
- (c) MK0 only, the rest later.

**MK-Q6. Where do the recordings live?**
- (a) `docs/api/examples/recorded/`, beside the first golden file: public documentation of real answers, and later a source of response examples for the OpenAPI document, which has none. *Recommended*.
- (b) `ui/src/api/recorded/`, as test data only.

**MK-Q7. What answers the states one server cannot reach** (a cluster of several controllers, connector processes, network scans, an update installed from a release source, DHCPv6 clients)?
- (a) Hand-written canned answers typed by the generated types, with no rules; the rules are proved in the crates that own them. *Recommended*: about 5,000 of today's lines shrink to fixtures; drift there is held only by the types and the end-to-end suite, which the plan states.
- (b) Their mock rules stay as they are, listed as exceptions in the ratchet.
- (c) Record them from a lab of several processes (the cluster lab). Faithful, but slow and a package of its own.

**MK-Q8. The missing Rust tests for the rule halves of LOGIC cases: in each area package, or apart?**
- (a) In each area package, so that no rule loses its test when the UI case moves to a recording. *Recommended*; included in the estimates.
- (b) Apart, as a test-health package after the migration.

## 9. Risks

- **MK-R1. Answers are not repeatable.** Most crates read the wall clock directly, identifiers are random, background services run on their own time. The normalizer replaces times, identifiers and secrets through the OpenAPI schemas; scenarios wait for named conditions; the check runs every new scenario twice and refuses one whose runs differ. MK1's pilot includes a job with events to prove it.
- **MK-R2. States one server cannot reach** (MK-Q7): their UI tests keep a hand-made view of the server.
- **MK-R3. The recordings grow large.** Scenarios stay small (the reads a page makes, per state); MK1 measures the size per scenario, and a size budget goes into the ratchet if needed.
- **MK-R4. A LOGIC case's rule half is lost** when its UI half moves to a recording. Each area package names, for every removed mock test and every converted LOGIC case, the Rust test that proves the rule, and adds the missing ones (MK-Q8).
- **MK-R5. Shared files and tests outside the areas** (`db.ts`, `handlers.ts`, the app and shell tests) while areas move in parallel: each package touches only its own lines, runs the files the request log names, and the gate's full run is the final check.
- **MK-R6. The gate grows.** The recording check adds an estimated 1 to 3 minutes; MK1 measures it, and if it exceeds 3 minutes the check runs only the scenarios of the areas a change touches, with the full check nightly.
- **MK-R7. Recordings are public.** They hold only test values (`example.test`, RFC 5737 and RFC 3849 addresses, generated test accounts); secrets in answers (tokens, recovery codes) are replaced by placeholders through the `SecretString` type of the OpenAPI document.
