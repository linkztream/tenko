# End-to-end tests

Browser tests of the embedded UI against the real `tenko` binary. How to build and run them,
and the `data-testid` convention they rely on, are in the section "End-to-end tests" of
`ui/README.md`. This page lists what the support modules offer.

## Specs

| Spec | Covers |
|---|---|
| `setup-wizard`, `sign-in`, `language` | First-run setup, TOTP and passkeys, the UI language |
| `ipam`, `move`, `import`, `audit` | IPAM writes through the plan dialog, moves, the spreadsheet import, the audit log |
| `discovery` | Proposal inbox, approve and reject, rejection memory, observations and subject pages, adoption policies, the dashboard tile |
| `connectors` | Plugins and the CLI list, the schema-generated form, runs and their jobs, observations, lifecycle, secret injection, the dashboard tile |
| `nodes` | Enrolment tokens shown once, a second `tenko` process enrolled as a probe, the registry and panel, revocation, the dashboard tile |
| `secrets` | The PIN coupling, create and reveal with the clipboard, the TGL-24 step-up with a passkey, host credentials, the RDP and SSH hand-off |
| `updates` | Air-gapped default, the check against a local release source, notes and marks, the install with its dry run and restart, what is new, a refused dry run |

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
