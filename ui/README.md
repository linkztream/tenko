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
    auth/, setup/, settings/   sign-in, account, first-run wizard, settings (WP1.9)
    dashboard/          the start page (decision 13)
    ipam/               networks (tree and prefix pane), addresses, tenancy collections,
                        forms, plan dialogs, history, move preview, utilization alarms
    hosts/              host list and detail, interfaces, connection hand-off
    jobs/               job list and job detail with manual steps
    audit/              audit log, record detail, chain verification
    import/             import wizard and export panel; api.ts is its only API module
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
| Form submit | `form-submit` | |
| Plan dialog | `plan-summary`, `plan-blocking`, `plan-ack`, `plan-confirm` | |
| Repeated item | one generic id, e.g. `move-item`, `tree-node` | `data-id`, `data-key` or `data-index` |
| Status bar items | `status-<name>`, e.g. `status-alarms` | |
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

A new view follows the same pattern: a page root id, `grid-<id>` for each grid, the generic
row and cell hooks from `DataGrid`, and `<area>-<action>` for its actions.

## End-to-end tests

`ui/e2e/` holds the browser tests of the embedded UI against the real server (WP1.11): first-run
wizard, sign-in with TOTP and passkeys, IPAM, import, move, audit and language. Every test
starts its own `tenko serve` with a temporary data directory and a free port
(`e2e/support/server.ts`), so tests are independent and run in parallel.

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
