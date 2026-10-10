# Tenko DDI web UI

The web UI of Tenko DDI: a SolidJS single-page application, built into `ui/dist` and embedded
in the server binary (ADR 0003, ADR 0008). It talks only to the public API under `/api/v1`
and follows its live changes over Server-Sent Events.

## Commands

Run everything from `ui/` (Node 22 or later).

| Command | What it does |
|---|---|
| `npm run dev` | Development server; proxies `/api` (and the SSE stream) to the Rust server at `TENKO_API_URL`, default `http://127.0.0.1:8080`. |
| `npm run dev:mock` | Development server that answers `/api` in the browser with the msw handlers of `src/api/mock`; nothing is proxied. |
| `npm run typecheck` | Type checks the application and the Node scripts. Run it after every change set. |
| `npm run lint` | ESLint with the project rules, the i18n check (`scripts/i18n.mjs --check`) and the drift check of the generated API types. |
| `npm run test` | The vitest suite (jsdom, msw in Node). |
| `npm run build` | Production build into `dist/`. |
| `npm run size` | Bundle report of `dist/` after a build: raw, gzip and brotli per file and the first-load total. |
| `npm run i18n` | Compiles the XLIFF files into `src/i18n/generated/keys.ts`. |
| `npm run api:types` | Regenerates `src/api/generated/schema.d.ts` from `docs/api/openapi.json`. Never edit the generated file by hand. |
| `npm run e2e` | End-to-end tests (Playwright, Chromium) against the real `tenko serve`; see "End-to-end tests". `npm run e2e:report` opens the last HTML report. |

Before a change is handed over: `npm run typecheck`, `npm run lint`, `npm run test` and
`npm run build` all pass, and the first page load stays under 75 KB gzip (`npm run size`).

## Layout

```
ui/
  i18n/                 en.xlf (English source) and sv.xlf (Swedish targets), XLIFF 2.0
  public/               favicon, theme-init.js, fonts/ (JetBrains Mono + OFL.txt), licenses/
  scripts/              i18n compiler, Vite i18n plugin, API type generator, size report,
                        the ESLint plugin with the project rules
  src/
    index.tsx, App.tsx  entry, providers, the router root
    app/                router registration, deep links (paths.ts), preferences, formats,
                        colors, styles (tokens.css, design.css, app.css), testing helpers
    api/                typed client, problem details, SSE stream, live queries, pagination,
                        type aliases (types.ts), the move API (moves.ts), mock/ (msw handlers)
    i18n/               t(), tx(), formats, locale choice, message packs
    components/         small shared pieces: Dialog, Icon, Addr, Si, toast, QrCode, ...
    grid/               the data grid and its parts: filter bar, column chooser, action bar,
                        cells, selection, keyboard focus, sources, drag and drop
    shell/              rail, top bar, status bar, command palette, keyboard chords, search
    auth/, setup/, settings/   sign-in, account, first-run wizard, settings (WP1.9); SettingsNav.tsx
                        is the settings navigation (security, users, updates, secrets)
    dashboard/          the start page (decision 13)
    ipam/               networks (tree and prefix pane), addresses, tenancy collections,
                        forms, plan dialogs, history, move preview, utilization alarms
    hosts/              host list and detail, interfaces, connection hand-off
    jobs/               job list and job detail with manual steps
    audit/              audit log, record detail, chain verification
    import/             import wizard and export panel; api.ts is its only API module
    updates/            update notice, release notes, what is new, install from the UI
                        (OPS-24, TGL-23), and the module switch of OPS-25 (modules.ts,
                        ModuleGate); api.ts is its only API module
    secrets/            operator secrets (WP2.1): the secrets page, a sub-page of Settings at
                        /settings/secrets (the old /secrets address redirects, see
                        SecretsRedirect.tsx), the reveal dialog with the step-up in place and
                        the clipboard path (clipboard.ts); api.ts is its only API module, also
                        used by the credentials and the remote hand-off of the host page
                        (hosts/credentials.tsx, hosts/Connect.tsx)
    discovery/          the proposal inbox with the docked proposal panel, the observations
                        and the picture of one subject (WP2.9); HostObservations.tsx is the
                        observation section of the host page; api.ts is its only API module,
                        also used by the adoption tab of the prefix pane
                        (ipam/prefix/AdoptionPanel.tsx) and the dashboard
    connectors/         connector plugins and instances (WP2.9): the list, one instance, the
                        instance form with the settings form built from the plugin's settings
                        schema (schema.ts, SchemaForm.tsx); api.ts is its only API module
    nodes/              cluster nodes and enrolment tokens (WP2.9): the node list with the docked
                        node panel, revocation, the token dialog; the requests are api/nodes.ts
```

Every area folder owns a `routes.ts` that exports `routes: AppRoute[]`; `src/app/router.ts`
finds them with `import.meta.glob`, so adding an area never edits a shared file. Every route
component is loaded with `lazy()`, so every area is its own chunk. Build every link with
`src/app/paths.ts`; never write a path by hand.

## Conventions

### API

- `api.get/post/put/patch/delete` in `src/api/client.ts` are typed by the OpenAPI paths: a
  path that is not in the document does not compile. Only `src/api/**` may call `fetch`
  (an ESLint rule enforces it). Area-specific request modules (`src/api/moves.ts`,
  `src/import/api.ts`) wrap the client and keep the rest of an area free of wire details.
- POST sends an `Idempotency-Key`; pass the same key when retrying one logical operation,
  `idempotencyKey: null` to send none (uploads). PATCH and DELETE send `If-Match` with the
  revision of the object being edited, or `ANY_REVISION` where none applies.
- Errors arrive as `ApiError` with the stable problem code; show them with the translated
  `errors.<code>` message, never with the server's English `detail`.
- Lists are cursor paginated: `fetchPage`, `fetchAll` in `src/api/paginate.ts`.
- Live data: `createLiveQuery({ topics, relevant, fetch })` refetches when an event of its
  topics arrives (debounced) and after a stream reset. Grids use `createListSource` in
  `src/grid/source.ts`, which adds paging, sorting and the brief highlight of changed rows.
- Address lists are read with `expand=host`, so host, mode and MAC arrive with each row;
  do not fetch per row.

### Writes: preview, acknowledge, apply

Every IPAM write is previewed first: the view sends the request with `dry_run=true`, shows
the plan (`src/ipam/plan/PlanDialog.tsx`: changes, warnings, the warnings that need an
acknowledgement), then sends it again with the acknowledged codes. Forms follow the same
path through `FormDialog` (`src/ipam/tenancy/FormDialog.tsx`) or `WriteForm`
(`src/ipam/formKit.tsx`): the form validates locally, then the plan dialog takes over;
Cancel in the plan returns to the form with its values. After a write, `useWriteToast`
shows the result with a link to the job when the write started one. Deletes offer Undo
(restore) in the toast.

### Text and i18n

- No literal UI string in code: every visible text, including `title`, `aria-label` and
  `placeholder`, goes through `t("area.key", args)` or `tx()` for rich text. The ESLint
  rule `tenko/no-literal-ui-string` refuses literals; `npm run lint` refuses a key without
  an English source or a Swedish target.
- Keys are stable, lower case, dotted by area (`ipam.col.vid`, `jobs.state.waiting`).
  Messages are ICU MessageFormat. English source texts use no contractions and no
  apostrophes.
- Numbers use `si()` or `<Si>`, `<Count>` for exact counts, `formatDuration`,
  `formatRelative` and the other formatters of `src/i18n`.

### Message packs

The English table of the whole UI would make the first page load too large, so the keys of
the lazily loaded areas live in message packs. A pack is a list of key prefixes in
`vite.config.ts`; a key belongs to the first pack whose prefix it starts with, and every
other key stays in the core table that the first load carries.

| Pack | Prefixes |
|---|---|
| `grid` | `grid.` |
| `jobs` | `jobs.`, `ipam.move.task.`, `ipam.move.step.`, `ipam.move.title` |
| `ipam` | `ipam.`, `hosts.`, `move.` |
| `audit` | `audit.` |
| `dashboard` | `dashboard.` |
| `import` | `import.` |
| `setup` | `setup.` |
| `settings` | `settings.` |
| `account` | `account.` |
| `updates` | `updates.`, `errors.update.`, `errors.upgrade.` |
| `secrets` | `secrets.`, `errors.vault.`, `errors.remote.` (also loaded by the host views; the secrets route loads `settings` too, for the settings navigation) |
| `discovery` | `discovery.`, `errors.ipam.proposal.`, `errors.ipam.reconciler.` (also loaded by the host views) |
| `connectors` | `connectors.`, `errors.connect.` |
| `nodes` | `nodes.`, `errors.cluster.` |

The `jobs` pack also holds `connect.job.` and `cluster.job.`, the job titles the server sends
for connector and node edits, and the `ipam` pack `errors.ipam.adoption.` for the adoption tab.

The Vite plugin (`scripts/vite-plugin-i18n.mjs`) builds one module per pack and language
(`virtual:tenko-i18n/<language>/<pack>`). A route loads its packs together with its chunk:

```ts
const PACKS = ["grid", "ipam"];
{ path: "/ipam/vlans", component: lazy(withPacks(PACKS, () => import("./tenancy/VlansView"))) }
```

`withPacks` waits for the packs of the current language before the component renders;
changing the language loads the same packs in the new one. A text read before its pack
arrived (a route title) is read again when the pack arrives. A component that shows keys of
another area lists that pack too (the move preview loads `jobs` for the job texts). Tests
run without packs: all keys are in the core table. A new area with many keys adds a pack
with its prefix here and in its `routes.ts`.

### Styling, accessibility and security

- Colors, spacing and type come from the tokens in `src/app/styles/tokens.css`; components
  use classes and token variables, never fixed colors.
- No static `style` attribute (`tenko/no-static-style`): the Content Security Policy has no
  `'unsafe-inline'`. Use a class, or set a dynamic value through the CSSOM.
- Every control works from the keyboard with a visible focus ring, every input has a
  label, and no state is shown by color alone (VLAN chips carry the id, alarm levels carry
  a word and an icon). View tests run axe (`src/app/testing/axe.ts`) on each page.
- The grid is a WAI-ARIA grid with `aria-activedescendant`: arrow keys, Home/End,
  PageUp/PageDown, Space and Shift selection, Enter opens, the context menu key opens the
  row actions, `/` focuses the filter.

### Mock API and tests

- `src/api/mock` holds msw handlers for every endpoint the UI uses, with seeded data in the
  documentation ranges (RFC 5737, RFC 3849, RFC 7042 MACs, `example.test` names). The IPAM
  mock (`mock/ipam`) plans and applies writes like the server: dry runs, warnings that need
  an acknowledgement, revisions, history, restore and live events.
- `src/app/testing/setup.ts` starts msw in Node, refuses any request no handler answers,
  and resets the mock state and the host cache between tests. `renderRoute(view, { url, path, routes })` renders a view under
  a memory router; `signInAlex()` signs in the seeded administrator; `bridgeMockEvents()`
  (`src/audit/testkit.ts`) delivers the mock's live events to the views.

## data-testid convention

End-to-end tests (WP1.11) find elements by `data-testid`, never by text or CSS class. The
names are kebab case and stable; text and layout may change without breaking them.

| What | Test id | Extra attributes |
|---|---|---|
| Page root | `page-<area>[-<view>]` | |
| Data grid | `grid-<grid id>` | |
| Grid row | `row` | `data-id` (object id), `data-key` (readable key: IP, CIDR, name) |
| Grid cell | | `data-col` (column id) |
| Grid footer, empty state | `grid-foot`, `grid-empty` | |
| Filter bar, its input | `filterbar` (the only one on a page) or `filterbar-<grid id>`, `filter-input` | |
| Action (button, link) | `<area>-<action>`, e.g. `vlan-create`, `dashboard-claim` | |
| Dialog body or form | `dialog-<name>`, e.g. `dialog-vlan-form`, `dialog-delete` | |
| Form field | `field-<name>` | |
| Error line under a form field | `field-error` | `data-field` (the request field, e.g. `name`; in the settings form of a connector its path, e.g. `settings.url` or `settings.ssids[1]`). The help line has no test id |
| Error of a request or a page (`ErrorNotice`) | `error-notice` | `data-code` (the problem code of an `ApiError`, e.g. `auth.invalid_credentials`; absent for any other error) |
| Form submit | `form-submit` | |
| Plan dialog | `plan-summary`, `plan-blocking`, `plan-ack`, `plan-confirm` | |
| Repeated item | one generic id, e.g. `move-item`, `tree-node` | `data-id`, `data-key` or `data-index` |
| Status bar items | `status-<name>`, e.g. `status-alarms` | |
| Docked panel | `<object>-panel`, e.g. `proposal-panel`, `node-panel` | `data-id` |
| Filter of a view | `filter-<name>`, e.g. `filter-state`, `filter-kind-<kind>`, `filter-prefix` | |
| Repeated item by position | the generic id, e.g. `toast-action` | `data-index` |
| Confirmation dialog | `dialog-confirm`, `confirm-ok`, `confirm-cancel` | |
| State and kind of an item | | `data-state` (job, step and chain chips), `data-status` (`status-badge`), `data-kind` and `data-action` (`plan-change`, `history-entry`), `data-code` (`plan-ack`), `data-job` (`job-group-task`) |

Page roots in this version:

| Route | Test id |
|---|---|
| `/` | `page-dashboard` |
| `/setup`, `/signin`, `/account/:section?` | `page-setup`, `page-signin`, `page-account` |
| `/ipam`, `/ipam/prefixes/:network/:length` | `page-ipam` |
| `/ipam/addresses`, `/ipam/addresses/:ip` | `page-ipam-addresses`, `page-ipam-address` |
| `/ipam/hosts`, `/ipam/hosts/:fqdn`, `/ipam/macs/:mac` | `page-hosts`, `page-host`, `page-mac` |
| `/ipam/vlans`, `/ipam/sites`, `/ipam/tenants` | `page-ipam-vlans`, `page-ipam-sites`, `page-ipam-tenancy` |
| `/ipam/tags`, `/ipam/custom-fields` | `page-ipam-tags`, `page-ipam-custom-fields` |
| `/ipam/move` | `page-move-preview` |
| `/ipam/import` | `page-import` |
| `/jobs`, `/jobs/:id` | `page-jobs`, `page-job` |
| `/audit`, `/audit/:seq` | `page-audit`, `page-audit-record` |
| `/settings/secrets`, `/settings/secrets/:id` (`/secrets` and everything under it redirect here) | `page-secrets` |
| `/discovery`, `/discovery/:id` | `page-discovery` (with `proposal-panel`) |
| `/discovery/observations`, `/discovery/observations/:subject` | `page-discovery-observations`, `page-discovery-subject` |
| `/connectors`, `/connectors/:id` | `page-connectors`, `page-connector` |
| `/nodes`, `/nodes/:id` | `page-nodes` (with `node-panel`) |

The hooks of the WP2.9 views beyond the generic ones:

| View | Test ids |
|---|---|
| Proposal inbox | `grid-proposals`, `discovery-reconcile`, `filter-state` (a select), `filter-severity-<severity>`, `filter-kind-<kind>`, `filter-prefix`, `discovery-empty`; dialogs `dialog-approve` (the plan dialog), `dialog-reject` with `field-reason`, `dialog-reconcile-report` with `report-count` (`data-key` the member) |
| Proposal panel | `proposal-panel` (`data-id`), `proposal-summary`, `discovery-approve`, `discovery-reject`, `evidence` (`data-index`, `data-key` the source key), `proposal-change`, `proposal-decision`, `proposal-adoption-error`, `proposal-subject-link`, `proposal-superseded-by`; the kind, severity and state badges carry `data-kind`, `data-severity` and `data-state` |
| Observations | `grid-observations`, `discovery-lookup` with `field-subject` and `form-submit`, `filter-current-<current, expired or all>`, `filter-type-<type>`, `filter-<source, mac, ip or within>`, `observations-empty` |
| Subject | `subject-summary`, `subject-sources`, `subject-macs`, `subject-ips`, `subject-names`, `subject-os`, `subject-ports`, `subject-tls`, `subject-vendors`, `subject-attachments`, `subject-intent`, `subject-sightings`, `subject-proposals`, `subject-proposal` (`data-id`), `subject-facts`, `subject-unknown`; facts are `fact` (`data-key` the source key and the subject key, `data-state` current or expired) |
| Host page | `host-observations` with `host-observations-body`, `host-observations-summary`, `host-open-ports`, `host-os`, `host-proposal` (`data-id`), `host-observation-link` (`data-key` the subject) |
| Prefix pane | `prefix-tab-adoption`, `prefix-adoption`, `adoption-effective` (`data-mode`), `adoption-source` (`data-source` own, inherited or default), `adoption-edit`, `adoption-clear`, `adoption-proposals`, `dialog-adoption-form` with `field-mode-<mode>`, `field-only_dhcp_pools`, `field-min_sightings`, `field-host_mode`, `field-vendors` |
| Connectors | `grid-connectors`, `connectors-create`, `connectors-empty`, `connectors-plugins`, `plugin` (`data-key` the name, `data-usable`), `plugin-unusable`, `connector-health` (`data-health`) |
| Connector | `connector-run`, `connector-check`, `connector-toggle`, `connector-edit`, `connector-delete`, `connector-disabled`, `connector-process`, `connector-restarts`, `connector-failures`, `connector-last-error` (`data-code`), `connector-remote`, `connector-remote-error`, `connector-last-run`, `connector-observations`, `connector-runs`, `connector-run-job` (`data-id`), `connector-settings-view`, `connector-config`, `connector-secret` (`data-key` the purpose), `connector-writes` |
| Connector form | `dialog-connector-form`, `field-plugin`, `field-name`, `connector-settings` with the settings form (`settings-form`, `settings-empty`, `field-settings-<name>`, `settings-item` and `settings-item-remove` with `data-field` and `data-index`, `settings-item-add`), `connector-secrets` with `field-secret-<purpose>`, `field-poll_interval`, `field-call_timeout`, `connector-guardrails` with `field-writes_enabled` and `field-enabled`, `connector-writes-warning`; error lines are `field-error` with `data-field` the path of the setting (`settings.url`, `settings.auth.user`, for an item `settings.ssids[1]`) |
| Nodes | `grid-nodes`, `nodes-enrol`, `nodes-version-mismatch`, `nodes-cluster`, `nodes-empty`, `node-link` (`data-state`), `nodes-tokens`, `enrolment` (`data-id`, `data-state`), `enrolment-node` (the link to the node a used token enrolled; `data-id` the node id), `enrolment-delete` |
| Node panel | `node-panel` (`data-id`), `node-mismatch`, `node-connection`, `node-buffer`, `node-certificate`, `node-revoke` |
| Enrolment | `dialog-enrol` with `field-role-<role>`, `field-name`, `field-lifetime` and `field-vrf`; then `dialog-enrol-token` with `enrol-once`, `enrol-command`, `enrol-token`, `enrol-fingerprint`, `nodes-copy-command`, `nodes-copy-token` and `enrol-done` |
| Dashboard | `dashboard-proposals`, `dashboard-proposals-link`, `dashboard-proposals-hint` (`data-conflicts`), `dashboard-connectors`, `dashboard-connectors-link`, `dashboard-connectors-hint` (`data-total`, `data-failing`), `dashboard-nodes`, `dashboard-nodes-link`, `dashboard-nodes-hint` (`data-total`, `data-mismatched`). The hints are translated plural messages, so their numbers are data attributes; a tile that has not read its data (or the nodes tile without a cluster summary) leaves them off |
| Host connect panel | `host-connect` with `remote-target` (`data-key` the address, or the host name), `host-rdp` and `host-ssh` (`data-key`), `field-user`, `field-rdp_port` and `field-ssh_port` |
| Release notes (`Markdown` of `updates/markdown.tsx`, in `update-release`, `update-action` and the install confirmation) | `md-heading` (`data-level` the level of the element, 1 to 6), `md-paragraph`, `md-list` (`data-ordered` `true` or `false`), `md-item`, `md-strong`, `md-em`, `md-code` (inline code), `md-pre` (fenced code), `md-link`; text that stays text has none |
| Settings navigation (the tabs of the settings pages and of the secrets page, which administrators see) | `settings-nav` with `settings-nav-link` (`data-key` `security`, `users`, `updates` or `secrets`) |
| Security settings | `toggle` (`data-key` the toggle id, e.g. `TGL-24`) with `toggle-edit` and `toggle-reset` (only while the value deviates from the profile); `dialog-toggle` with `form-submit`, `form-cancel`, `toggle-pin-coupling` (the PIN coupling rule refuses the draft) and the editor's fields: `field-password_policy`, `field-mfa`, `field-breach_check`, `field-lockout`, `field-step_up-<session, fresh or passkey>`, `field-bound_host_only`; the profile dialog shows `profile-pin-coupling` |

A new view follows the same pattern: a page root id, `grid-<id>` for each grid, the generic
row and cell hooks from `DataGrid`, and `<area>-<action>` for its actions.

## End-to-end tests

`ui/e2e/` holds the browser tests of the embedded UI against the real server: first-run wizard,
sign-in with TOTP and passkeys, IPAM, import, move, audit and language (WP1.11), and discovery,
connectors, nodes, secrets and updates (WP2.11). Every test starts its own `tenko serve` with a
temporary data directory and a free port (`e2e/support/server.ts`), so tests are independent and
run in parallel; the Slice 2 specs also start a second `tenko` process as a probe node, a local
release source and the bundled sample connector. `e2e/README.md` describes the specs, the
support modules and the server options.

- Build first: `npm run build`, then `cargo build -p tenko` without `TENKO_UI_STUB`. The binary
  is found through `TENKO_BIN`, `CARGO_TARGET_DIR/debug/tenko` or `../target/debug/tenko`; the
  global setup copies it to `e2e/.artifacts/bin/` and refuses a placeholder-UI build.
- The default instance is the Lab profile with plain HTTP on `http://localhost` (a secure
  context, so passkeys work with the relying party `localhost`); `test.use({ transport:
  "internal_ca" })` runs a test over HTTPS with the internal CA.
- Fixtures (`e2e/support/fixtures.ts`): `server`, `api` (the API over the page's cookies),
  `signedIn` (setup through the API, the browser signed in). TOTP codes come from
  `e2e/support/totp.ts` (RFC 6238), passkeys from Chromium's virtual authenticator
  (`e2e/support/webauthn.ts`).
- Locate elements by `data-testid` and the `data-key`, `data-id` and `data-col` attributes of this
  convention only (helpers in `e2e/support/ui.ts`), never by text, role name or CSS class.
- `TENKO_E2E_UI_DIR=<dir>` serves the UI from a directory (`vite build --outDir <dir>`) instead
  of the embedded one, which saves the Rust build while writing tests.
- Output (report, traces, screenshots) goes to `e2e/.artifacts/`, which git ignores.

## Third-party code

| Package or asset | Licence | Use |
|---|---|---|
| solid-js, @solidjs/router | MIT | UI framework and router |
| intl-messageformat | BSD-3-Clause | ICU messages |
| uqr | MIT | QR code of the TOTP enrolment, encoded in the browser (`public/licenses/uqr.txt`) |
| JetBrains Mono | SIL Open Font License 1.1 | Monospace font (`public/fonts/OFL.txt`) |

Development dependencies (Vite, vitest, msw, ESLint, axe-core and others) are listed in
`package.json` and are not part of the build.
