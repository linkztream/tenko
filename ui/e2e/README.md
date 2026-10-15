# End-to-end tests

Browser tests of the embedded UI against the real `tenko` binary. How to build and run them,
and the `data-testid` convention they rely on, are in the section "End-to-end tests" of
`ui/README.md`. This page lists what the support modules offer.

## Specs

| Spec | Covers |
|---|---|
| `setup-wizard`, `sign-in`, `language` | First-run setup, TOTP and passkeys, the UI language |
| `ipam`, `move`, `import`, `audit` | IPAM writes through the plan dialog, moves, the spreadsheet import, the audit log |
| `discovery` | Proposal inbox, approve and reject, rejection memory, observations and subject pages, adoption policies, the dashboard tile, the status bar item with the number of open proposals |
| `connectors` | Plugins and the CLI list, the schema-generated form, runs and their jobs, observations, lifecycle, secret injection, the dashboard tile; the instance page, the list and the tile follow the plugin process without a reload |
| `nodes` | Enrolment tokens shown once, a second `tenko` process enrolled as a probe, the registry and panel, revocation, the dashboard tile and the cluster summary following enrolment, connection and revocation while open |
| `cluster` | The cluster page of a single controller (one member, leader and voter, quorum single, no promote or step-down, a removal refused with the reasons of a single member, the digest check, the compatibility cell and the data format panel), "Add a controller" (a controller token shown once, pending in the token list), a viewer, Swedish; the queue and partition scenarios are `test.fixme` until a lab can isolate a controller |
| `scans` | The scans page and its probes section with an enrolled probe, "Stop all scans" with a reason and "Resume all", "Scan now" refused with `scan.job.no_probe`, the probe's scan configuration (the node panel link, the offered configuration, a save with the scanner off and no prefixes, the revision), the per-probe stop and resume, a viewer, Swedish; nothing is ever scanned |
| `secrets` | The secrets page under Settings (/settings/secrets) and the redirect from the old /secrets address, the PIN coupling, create and reveal with the clipboard, the TGL-24 step-up with a passkey, TGL-24 and MFA changed on /settings/security while the vault holds a secret, host credentials, the RDP and SSH hand-off with a typed user name and ports |
| `updates` | Air-gapped default, the check against a local release source, notes and marks, the install with its dry run and restart (the health probe names the new version), what is new, a refused dry run |
| `access` | The access page: a scoped grant through the scope picker and its revocation, the sign-in requirement of a role, a service account with a scoped token shown once that reads only its prefix as a bearer, and display gating: a scoped operator sees the write actions on the prefix of its grant and none on a prefix it may only read |
| `vault` | The vault page: the key of the controller with its file provider marked weak, the generations, and the online rotation followed to a new generation and epoch |
| `audit-export` | The audit export page against the real sinks: a file sink whose records land in the export directory, syslog over UDP to a loopback listener, a TCP sink to a closed port and a TLS sink to a plain listener failing with their codes, the server's field errors in the dialog, TGL-21 (no required export without a sink, the last sink not removable), a stale revision, the alarm delay, keyboard and axe, Swedish |
| `backup` | The backup page: back up now with a passphrase (a weak or mistyped one refused first) and the run in the list with its restore command, an interval schedule with a recipient kept across a reload, enabling without a recipient hinted and refused (`backup.key.missing`), keyboard and axe, Swedish |
| `reconciler` | The reconciler settings page: the server's defaults in human units, a changed interval and orphan age kept across a reload, an interval of 10 s refused inline with nothing sent, the keyboard order of the fields, axe, Swedish |
| `guardrails` | The guardrails page: the default of ten parallel writes, a VLAN path and a client path saved and shown after a reload, removing one path saves the other alone, `max_parallel` 0 refused inline, the add dialog with the keyboard, axe, Swedish |
| `metrics` | The live metrics of the start page: an administrator gets a sample within three seconds with a number on every tile and the controller as leader, and the next samples follow; a viewer sees no tiles; nothing in them takes the focus, axe, Swedish |

Each area spec also renders at least one page in Swedish (`support/i18n.ts`). A `test.fixme`
marks a scenario that waits for a recorded defect.

## Support modules

| Module | What it offers |
|---|---|
| `support/fixtures.ts` | `server`, `api`, `signedIn`; the options `transport` (`plain` or `internal_ca`) and `serverOptions` (below) |
| `support/server.ts` | `TenkoServer`: one `tenko serve` per test with its own directory and free port |
| `support/process.ts` | `Proc` (a child process with its output collected line by line) and `runTenko` (one CLI command to its end) |
| `support/api.ts` | The public API over the browser's cookies; `ADMIN`; `waitForJob` |
| `support/ui.ts` | Locators by `data-testid`, `data-key`, `data-id`, `data-col`; the account menu |
| `support/i18n.ts` | `expectRendered`: the document language, and no message key shown instead of its text |
| `support/discovery.ts` | The bundled sample connector plugin as a source of observations; proposals and facts |
| `support/accounts.ts` | Other accounts than the administrator: `signInAsViewer`, a viewer signed in through the API |
| `support/probe.ts` | `ProbeNode`: a second `tenko` process enrolled as a probe node |
| `support/release.ts` | `ReleaseSource`: a release source on the loopback with a manifest and release files |
| `support/totp.ts`, `support/webauthn.ts` | TOTP codes (RFC 6238) and Chromium's virtual platform authenticator |
| `support/ipam.ts`, `support/import.ts`, `support/move.ts` | Helpers of the IPAM, import and move scenarios |

## Server options

Every test server stays on the machine. Two defaults of `support/server.ts` see to it, unless
a test asks otherwise with `test.use({ serverOptions: { ... } })`:

- `updates.air_gapped = true`: the server never asks the release source. Without it, every
  server would fetch the project's `releases.json` a minute after it starts.
- `[cluster] listen = []`: the cluster port stays closed. Without it, a server opens the default
  `0.0.0.0:8444` as soon as an enrolment token exists, a fixed port on every interface that
  parallel tests would fight over.

The options:

| Option | Effect |
|---|---|
| `cluster: true` | A cluster port of its own on the loopback with one-second heartbeats (`server.clusterPort`), for `ProbeNode`; use it with `transport: "internal_ca"`, since enrolment pins the internal CA |
| `updates: { sourceUrl, readyTimeoutSecs }` | The release source of the test (`ReleaseSource.manifestUrl`) instead of air-gapped |
| `layout: true` | Runs from `<data_dir>/updates/current` after `tenko upgrade layout`, supervised, so an install from the UI is possible; the test restarts the server (`server.restart()`) when it exits with status 12 |
| `versionFromLayout: false` | With `layout`: the version comes from the build, not from the layout directory, so an installed copy of the same build reports the old version |
| `profile` | The bootstrap profile; Lab for `plain`, Home for `internal_ca` by default |

The sample plugin, the probe node and the release source are real flows of the product: no
test-only route of the server is used. `TENKO_TEST_VERSION_FROM_LAYOUT=1` (debug builds only)
lets the same build install as the next version.
