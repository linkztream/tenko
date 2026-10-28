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
  i18n/                 en.xlf (English source) and sv.xlf (Swedish targets), XLIFF 2.0; fragments
                        <lang>.d/<area>.xlf beside them: each package adds its keys only in its own
                        fragment, and the lead folds the fragments into the main files at the end
                        of the slice
  public/               favicon, theme-init.js, licenses/ (including the font's OFL.txt)
  scripts/              i18n compiler, Vite i18n plugin, API type generator, size report,
                        the ESLint plugin with the project rules
  src/
    index.tsx, App.tsx  entry, providers, the router root
    app/                router registration, deep links (paths.ts), preferences, formats,
                        colors, styles (tokens.css, design.css, app.css), testing helpers
    api/                typed client, problem details, SSE stream, live queries, pagination,
                        type aliases (types.ts), the move API (moves.ts), mock/ (msw handlers)
    i18n/               t(), tx(), formats, locale choice, message packs
    components/         small shared pieces: Dialog, Icon, Addr, Si, Sparkline, toast, QrCode, ...
    grid/               the data grid and its parts: filter bar, column chooser, action bar,
                        cells, selection, keyboard focus, sources, drag and drop
    shell/              rail, top bar, status bar, command palette, keyboard chords, search
    auth/, setup/, settings/   sign-in, account, first-run wizard, settings (WP1.9); SettingsNav.tsx
                        is the settings navigation (security, users, updates, secrets, access, audit
                        export, vault, certificates, backup, reconciler, guardrails, DNS, languages); the later ones
                        are sub-pages in folders of their own (settings/access/, audit-export/, vault/,
                        certificates/, backup/, reconciler/, guardrails/, dns/, languages/) with a route each in
                        settings/routes.ts. The first-run wizard's steps are setup/steps/; the DNS
                        upstreams step (Dns.tsx, P2-Q5) writes the root forwarding rule after setup
                        and the [dns] section of tenko.toml (generateDnsConfig in setup/generate.ts)
    dashboard/          the start page (decision 13); MetricsTiles.tsx and metrics.ts are its live
                        metrics for administrators (WP3.5b), on a stream of their own, with the
                        DNS tiles while a controller runs the dns role (WP5.6)
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
    cluster/, scans/    the cluster area on the rail and the scans of the discovery module, which has
                        no rail entry (WP3.0 placeholders; WP3.11a builds them)
    dhcp/               the DHCP area (Phase 3): the scopes with pools, exclusions and options, shared
                        networks, options, classes, policies, filters and the DHCP settings (WP7.4);
                        leases and history still say they come with a later package
    dns/                the DNS area (Phase 2, WP4.5): the zone list, a zone with its record grid,
                        settings and history tabs, the zone file import and export, access lists
                        and TSIG keys; api.ts is its only API module (types.ts holds the types
                        without the client, shared with the mock service), model.ts the pure name,
                        record and access list helpers, paths.ts its links. log/ is the query log
                        page of a node (WP5.4) with its own api.ts and model.ts; forwarders/ the
                        forwarding rules and lists/ the block lists (WP5.5), each with its api.ts,
                        model.ts (forwarders/model.ts also serves the wizard's DNS step) and
                        dialogs. The upload of a block list file goes through uploadBlockList in
                        api.ts, a raw request until WP5.2 puts PUT /dns/lists/{id}/file in the
                        document. views/ is the views page (WP6.4) with its api.ts, model.ts (the rule drafts,
                        the scope map and its shares, the positions of a move) and dialogs. The DNS
                        records block of the host and address pages is hosts/DnsRecords.tsx;
                        the DNS settings of the node are settings/dns/
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
  `idempotencyKey: null` to send none (uploads). Every write sends `If-Match` when `ifMatch` is
  given (POST too, for an action on an existing object): the revision of the object being
  edited, or `ANY_REVISION` where none applies.
- A body is JSON, except a `FormData` (multipart) and a `Blob` or `File`, which are sent as they
  are; a Blob travels with its own type as `Content-Type` (`application/octet-stream` when it
  has none).
- Errors arrive as `ApiError` with the stable problem code; show them with the translated
  `errors.<code>` message, never with the server's English `detail`.
- Lists are cursor paginated: `fetchPage`, `fetchAll` in `src/api/paginate.ts`.
- Live data: `createLiveQuery({ topics, relevant, fetch })` refetches when an event of its
  topics arrives (debounced) and after a stream reset. Grids use `createListSource` in
  `src/grid/source.ts`, which adds paging, sorting and the brief highlight of changed rows.
  Read the value of a query with `query.latest()` (or `latest(resource)`), not with
  `query.value.latest`: that getter throws the error of a failed read, the guard answers
  `undefined` and leaves the error on `query.value.error`.
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

### Writing direction (right to left)

The document's `lang` and `dir` follow the UI language: `setLocale` sets `dir="rtl"` for a
language written right to left (Arabic, Hebrew, Persian, Urdu and the like, see
`src/i18n/direction.ts`), and `direction()` tells a component the current direction. The layout
mirrors through the style sheets alone:

- Write every side of the inline axis in its logical form: `margin-inline-start`,
  `padding-inline-end`, `border-inline-start`, `inset-inline-end`, `border-start-end-radius`,
  `text-align: start` or `end`, and `margin-block`/`margin-inline` for a shorthand whose left
  and right values differ. The block axis (`margin-top`, `top`) and `width` and `height` stay as
  they are.
- A horizontal distance in an inset shadow or a translation is multiplied by
  `var(--inline-sign, 1)`, which is -1 right to left (`src/i18n/bidi.css`):
  `box-shadow: inset calc(3px * var(--inline-sign, 1)) 0 0 var(--accent)`. A box centred with
  `left: 50%` and `translateX(-50%)` is direction-neutral.
- A declaration that must stay physical (a check mark drawn by two borders) carries the comment
  `/* physical: <reason> */` on its line.
- `node scripts/css-logical.mjs` refuses physical declarations in `src/**/*.css` and
  `--fix` rewrites those with an exact logical form; a test in `scripts/css-logical.test.mjs` runs
  the same check over the style sheets in `npm run test`.
- Identifiers (`.mono`, `.addr`, `.mac`, `code`, `kbd`, `pre`) are isolated left-to-right runs in
  a right-to-left document, so `2001:db8::/32` keeps its order; mark an identifier with `.mono`.
- Tests switch to a pseudo-locale with `usePseudoLocale("ar-XB")` (right to left, every text
  wrapped in a right-to-left override) or `usePseudoLocale("en-XA")` (accented letters in
  brackets) from `src/i18n/pseudo.ts`; tests that assert Swedish texts keep doing so.

### Uploaded language packs

Languages beyond English and Swedish, and overrides of those two, come from the server as
XLIFF 2.0 language packs (`docs/languages.md`). `src/i18n/remote.ts` reads
`GET /api/v1/i18n/languages` before the first render (`loadLanguages()` in `src/index.tsx`) and
again when an `i18n.*` table changes, registers each active pack with the runtime and fetches
its messages only when the UI switches to it. Pack messages are ICU text read by the full
message parser, a lazy chunk loaded with the first pack; a key a pack lacks falls back to
English. The preview of an uploaded candidate is per browser tab (`startPreview`,
`endPreview`) and shows the preview bar (`src/i18n/PreviewBar.tsx`). The build writes the
merged documents of the built-in languages to `dist/i18n/<language>.xlf`; the server reads them
as its templates and key set.

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
| `cluster` | `cluster.` (`cluster.job.` stays in `jobs`, which is listed first) |
| `scans` | `scans.` |
| `access` | `access.` (the settings sub-pages of Slice 3 load `settings` too, for the settings navigation) |
| `audit_export` | `audit_export.` |
| `vault` | `vault.` |
| `backup` | `backup.` |
| `certificates` | `certificates.` (the certificates settings page, `/settings/certificates`) |
| `reconciler` | `reconciler.` (the text of `ipam.reconciler.settings.invalid` is `reconciler.error.invalid`, mapped in the page, because `errors.ipam.reconciler.` belongs to `discovery`) |
| `guardrails` | `guardrails.` (likewise `connect.guardrails.invalid` is `guardrails.error.invalid`, because `errors.connect.` belongs to `connectors`) |
| `languages` | `languages.` |
| `metrics` | `metrics.` (the live metrics of the start page, loaded with their lazy part for administrators) |
| `dhcp` | `dhcp.`, `errors.dhcp.` (the DHCP area, Phase 3; WP7.4: the error texts of the DHCP codes) |
| `findings` | `shell.nav.badge.`, `shell.status.findings.` (U2: the words of the rail badges and of the findings in the status bar, loaded with `src/shell/findingsShell.ts` after the first page) |
| `dns` | `dns.`, `errors.dns.` (the DNS area, Phase 2; the DNS block of the host and address pages uses `hosts.dns.` in `ipam`, the import job `jobs.title.dns_import` and `jobs.step.dns_import_*` in `jobs`) |

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
- Every list's columns can be resized on the handle at the trailing edge of the header
  (`src/grid/ColumnResize.tsx`): drag it, double-click or double-tap it to fit the content,
  or Tab from the grid to the handle of the focused column and use the arrow keys (Shift for
  larger steps, Enter or Escape to go back); the widths are kept per list and per user in
  `localStorage` (`src/grid/widths.ts`), "Reset column widths" in the column menu (or under a
  list without one) drops them, and the phone layout (560 px and narrower) ignores them.

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
| Column resize handle, width reset | `col-resize` (in each header cell), `grid-reset-widths` (grid footer, a list without a column menu), `reset-column-widths` (column menu) | `data-resize` (column id) |
| Filter bar, its input | `filterbar` (the only one on a page) or `filterbar-<grid id>`, `filter-input` | |
| Action (button, link) | `<area>-<action>`, e.g. `vlan-create`, `dashboard-claim` | |
| Dialog body or form | `dialog-<name>`, e.g. `dialog-vlan-form`, `dialog-delete` | |
| Form field | `field-<name>` | |
| Error line under a form field | `field-error` | `data-field` (the request field, e.g. `name`; in the settings form of a connector its path, e.g. `settings.url` or `settings.ssids[1]`). The help line has no test id |
| Error of a request or a page (`ErrorNotice`) | `error-notice` | `data-code` (the problem code of an `ApiError`, e.g. `auth.invalid_credentials`; absent for any other error) |
| Form submit | `form-submit` | |
| Plan dialog | `plan-summary`, `plan-blocking`, `plan-ack`, `plan-confirm` | |
| Repeated item | one generic id, e.g. `move-item`, `tree-node` | `data-id`, `data-key` or `data-index` |
| Status bar items | `status-<name>`, e.g. `status-findings-act`, `status-findings-review`, `status-findings-info` | |
| Shell (U2) | `rail` with `rail-sep`, `rail-badge` (`data-level` `act` or `review`) and `rail-dot` inside the links (`data-area`, `data-group`); `node-chip` and `cluster-card` (`cluster-card-member` with `data-state`, `cluster-card-open`); `profile-chip` and `profile-card` (`profile-card-toggle` with `data-toggle` and `data-changed`, `profile-card-open`); the page header `page-header` with `page-info`, `page-info-popover` and `page-sub`; a filter chip's count `chip-count`; an applied severity of the inbox `filter-level` (`data-level`) | |
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
| `/settings/access`, `/settings/audit-export`, `/settings/vault`, `/settings/backup` | `page-access`, `page-audit-export`, `page-vault`, `page-backup` (placeholders with `<name>-placeholder`) |
| `/settings/languages` | `page-languages` |
| `/settings/certificates` | `page-certificates` |
| `/settings/reconciler`, `/settings/guardrails` | `page-reconciler`, `page-guardrails` |
| `/settings/dns` | `page-dns-settings` |
| `/cluster`, `/cluster/queue` | `page-cluster`, `page-cluster-queue` |
| `/scans`, `/scans/:id` | `page-scans`, `page-scan` |
| `/dns`, `/dns/zones/:id/:tab?`, `/dns/import/:id` | `page-dns`, `page-dns-zone` (`data-id`), `page-dns-import` (`data-id`) |
| `/dns/acls`, `/dns/keys` (administrators, scope `dns.keys`) | `page-dns-acls`, `page-dns-keys` |
| `/dns/log` | `page-dns-log` |
| `/dns/forwarders`, `/dns/lists` | `page-dns-forwarders`, `page-dns-lists` |
| `/dns/views` | `page-dns-views` |
| Every other path under `/dns` | `page-dns-later` with `dns-coming` |
| `/dhcp` the scopes, `/dhcp/scopes/{prefix}/{tab}`, `/dhcp/shared-networks`, `/dhcp/options`, `/dhcp/classes`, `/dhcp/policies`, `/dhcp/filters`, `/settings/dhcp` (WP7.4); `/dhcp/leases`, `/dhcp/history` and every other DHCP path still say the part comes with a later package (`dhcp-coming`) | `page-dhcp-scopes`, `page-dhcp-scope`, `page-dhcp-networks`, `page-dhcp-options`, `page-dhcp-classes`, `page-dhcp-policies`, `page-dhcp-filters`, `page-dhcp-settings`; `page-dhcp` |
| `/discovery`, `/discovery/:id` | `page-discovery` (with `proposal-panel`) |
| `/discovery/observations`, `/discovery/observations/:subject` | `page-discovery-observations`, `page-discovery-subject` |
| `/connectors`, `/connectors/:id` | `page-connectors`, `page-connector` |
| `/nodes`, `/nodes/:id` | `page-nodes` (with `node-panel`) |
| `/nodes/:id/scan` | `page-scan-config` (`data-node`) |
| Any route the person may not open | `page-forbidden` |

The hooks of the WP2.9 views beyond the generic ones:

| View | Test ids |
|---|---|
| Proposal inbox | `grid-proposals`, `discovery-reconcile`, `filter-state` (a select), `filter-severity-<severity>`, `filter-kind-<kind>`, `filter-prefix`, `discovery-empty`; dialogs `dialog-approve` (the plan dialog), `dialog-reject` with `field-reason`, `dialog-reconcile-report` with `report-count` (`data-key` the member); for a selection `actionbar` with `action-approve` and `action-reject`, `dialog-approve-many` with `approve-kinds`, `reject-kinds` in `dialog-reject`, and `dialog-skipped` with `skipped-item` (`data-id`, `data-code`), `skipped-keep` and `skipped-close` |
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
| Partition (every page; WP3.11a) | `cluster-banner` (`data-state` `isolated`, `electing` or `conflicts`), `status-stale`; `dialog-no-quorum` with `no-quorum-hint`, `no-quorum-queue`, `no-quorum-queued` and `no-quorum-close` |
| Cluster | `cluster-summary` with `cluster-quorum` (`data-state`), `cluster-term`, `cluster-leader` (`data-node`), `cluster-voters` (`data-count`), `cluster-node` (`data-node`), `cluster-changing`; `cluster-step-down`, `cluster-add-controller` (opens `dialog-enrol` with the role fixed), `cluster-queue-link`; `cluster-members` with `member-row-<node>` (`data-id`, `data-state` the health, `data-role`), `member-health` (`data-state`), `member-leader`, `member-lag`, `member-contact`, `member-promote-<node>`, `member-remove-<node>` |
| Membership dialogs | `dialog-promote`, `dialog-remove`, `dialog-step-down` with `preview`, `preview-voters` and `preview-tolerated` (`data-before`, `data-after`), `preview-blockers` and `preview-forceable` (items with `data-blocker`), `preview-caveats` (items with `data-caveat`), `field-force`, `field-replace`, `step-down-successor` (`data-node`), `promote-confirm`, `remove-confirm`, `step-down-confirm` |
| Digest check | `cluster-digests`, `cluster-check-digests`, `digests-result`, `digests-overall` (`data-state` `agree` or `differ`), `digest-row-<node>` (`data-state` `agrees`, `differs` or `missing`), `digest-state`, `digest-value` |
| Queue | `queue-unavailable`; `queue-local`, `queue-local-empty`, `queue-item-<id>` (`data-state`), `queue-item-summary`, `queue-item-state`, `queue-cancel-<id>`, `dialog-cancel-queued`; `queue-changes`, `queue-changes-empty`, `queued-change-<id>` (`data-state`), `queued-change-summary`, `queued-change-state`, `queued-change-conflict` (`data-code`), `queued-reapply-<id>`, `queued-discard-<id>`, `queued-dismiss-<id>` (an applied change), `dialog-reapply` (the plan dialog), `dialog-discard-queued` |
| Scans | `scans-list`, `scan-row-<id>` (`data-state`), `scan-changes`, `scans-empty`; `scans-probes`, `probe-row-<node>` (`data-state` `stopped` or `active`), `probe-in-process`, `probe-sync`, `probe-scope`, `probe-switch`; `scans-stop-all`, `scans-resume-all`, `dialog-stop-scans` with `field-reason`, `confirm-ok`, `confirm-cancel` |
| Scan | `scan-state` (`data-state`), `scan-facts`, `scan-progress`, `scan-error`, `scan-probe-<node>`, `scan-diff`, `scan-diff-totals`, `diff-total-<type>`, `diff-total-all`, `scan-diff-items`, `diff-row-<n>` (`data-state` the change), `scan-diff-empty`, `scan-diff-waiting`, `scan-diff-truncated`, `scan-not-found` |
| Scan now (prefix pane, host page) | `scan-now`, `dialog-scan-now` with `scan-now-kind-<kind>`, `scan-now-deadline`, `scan-now-start`, `scan-now-cancel`, then `scan-now-started` (an `error-notice` for a refusal), `scan-now-follow`, `scan-now-close` |
| Probe scan configuration | `scan-config-form` (`data-dirty`), `scan-config-save`, `scan-config-revert`, `scan-config-readonly`, `scan-config-stale`, `scan-config-remote`, `scan-config-reload`, `scan-config-lacking`, `scan-config-errors`, `scan-config-not-probe`, `scan-config-back`; `scan-group-general`, `scan-group-scope`, `scan-group-methods`, `method-<key>` (`data-raw`) with `method-<key>-raw`, `field-<path>` (e.g. `field-concurrency`, `field-icmp.interval_secs`); `scan-devices`, `scan-devices-empty`, `scan-device`, `device-add`, `device-remove-<i>`, `device-lacking`, `device-<column>-<i>`; `scan-config-sync` (`data-sync`, `data-stored`) with `scan-sync-state`, `scan-sync-origin`, `scan-sync-revision`; `scan-config-applied` with `scan-applied-*`; `scan-kill-switch` (`data-state` `running` or `stopped`) with `scan-ks-state`, `scan-ks-reason`, `scan-ks-confirmed`; `scan-stop`, `scan-resume`, `dialog-stop-probe` with `field-reason`, `form-submit`, `form-cancel`; `node-scan-config` (the link in the node panel) |
| Dashboard | `dashboard-proposals`, `dashboard-proposals-link`, `dashboard-proposals-hint` (`data-conflicts`), `dashboard-connectors`, `dashboard-connectors-link`, `dashboard-connectors-hint` (`data-total`, `data-failing`), `dashboard-nodes`, `dashboard-nodes-link`, `dashboard-nodes-hint` (`data-total`, `data-mismatched`). The hints are translated plural messages, so their numbers are data attributes; a tile that has not read its data (or the nodes tile without a cluster summary) leaves them off |
| Live metrics (start page, administrators) | `metrics-tiles` (`data-state` the connection state of its stream, `data-controllers` the controllers of the last sample, absent before the first), `metrics-waiting` (before the first sample), `metrics-group-controller` and `metrics-group-dns` (the headings of the two groups of tiles), `metrics-tile-<name>` for `requests`, `commit`, `store`, `raft`, `jobs`, `ingest`, `sse` and `nodes` (`data-value` the raw number, absent while unknown), `metrics-sparkline-<name>` (`data-points` the samples drawn, at most 60), `metrics-raft-node` per controller on the Raft tile (`data-node`, `data-role`, `data-lag`, `data-state` `current`, `stale` or `unsupported`) |
| Host connect panel | `host-connect` with `remote-target` (`data-key` the address, or the host name), `host-rdp` and `host-ssh` (`data-key`; disabled when the port was not seen open), `connect-ports` (the open ports of an address), `connect-unscanned`, `connect-no-scan` with `connect-scan-link`, `connect-loading`, `connect-web` with `web-primary`, `web-http` and `web-address`, `connect-web-more` with `web-more`, `field-user`, `field-rdp_port` and `field-ssh_port` |
| Release notes (`Markdown` of `updates/markdown.tsx`, in `update-release`, `update-action` and the install confirmation) | `md-heading` (`data-level` the level of the element, 1 to 6), `md-paragraph`, `md-list` (`data-ordered` `true` or `false`), `md-item`, `md-strong`, `md-em`, `md-code` (inline code), `md-pre` (fenced code), `md-link`; text that stays text has none |
| Settings navigation (the tabs of the settings pages and of the secrets page, which administrators see) | `settings-nav` with `settings-nav-link` (`data-key` `security`, `users`, `updates`, `secrets`, `access`, `audit-export`, `vault`, `certificates`, `backup`, `reconciler`, `guardrails`, `dns` or `languages`) |
| Security settings | `toggle` (`data-key` the toggle id, e.g. `TGL-24`) with `toggle-edit` and `toggle-reset` (only while the value deviates from the profile); `dialog-toggle` with `form-submit`, `form-cancel`, `toggle-pin-coupling` (the PIN coupling rule refuses the draft) and the editor's fields: `field-password_policy`, `field-mfa`, `field-breach_check`, `field-lockout`, `field-audit_export-<local, optional or required>`, `field-step_up-<session, fresh or passkey>`, `field-bound_host_only`; the profile dialog is `dialog-profile` (opened by `security-change-profile`) with `field-profile` (the radio group; `field-profile-<profile>` each choice), `form-submit`, `form-cancel` and `profile-pin-coupling` |
| Languages | `languages-template` (the English template), `languages-upload-form` with `field-file` and `languages-upload`, `languages-refusal` with `languages-refusal-problem` (`data-index`, `data-code`, `data-key` the field), `grid-languages` with `row` (`data-key` the tag, `data-status`), `status-badge` (`data-status`), `languages-previewed` (`data-state` `previewed` or `waiting`), `languages-preview`, `languages-activate`, `languages-discard`, `languages-report-open`, `languages-remove` or `languages-revert` (a built-in language), `languages-template-language`; `languages-report` (`data-key` the tag) with `languages-report-complete` (`data-percent`, `data-translated`, `data-total`), `languages-report-missing`, `languages-report-extra` and `languages-report-stale` (each with `data-count` and a `-keys` list), `languages-report-clean`, `languages-problem` (`data-index`, `data-code`, `data-key`) and `languages-report-close`; dialogs `dialog-activate`, `dialog-discard` and `dialog-remove` with `confirm-ok` and `confirm-cancel` |
| Preview bar (every page while this tab previews a pack) | `languages-preview-bar` (`data-key` the tag) with `languages-preview-open` and `languages-preview-end` |
| Access (`/settings/access`, `page-access`) | `access-roles` with `access-role` (`data-key` the role) holding `access-role-mfa` (`data-mfa`) and `access-role-policy-edit`; `dialog-role-policy` with `field-mfa-<profile, optional, totp_or_stronger or passkey>`, `role-policy-weaker`, `form-submit`, `form-cancel`; `access-grants` with `access-grant` (`data-key` the grant id, `data-role`), `access-grant-scope`, `access-grant-revoke`, `access-grant-add`, `access-grants-empty`; `access-service-accounts` with `access-service-account` (`data-key` the name), `access-service-account-tokens`, `access-service-account-add`, `access-sa-tokens` with `access-sa-token` (`data-key` the name), `access-sa-token-create`, `access-sa-token-revoke` |
| Grant dialog | `dialog-grant` with `field-subject`, `field-role-<operator or viewer>`, the scope picker `scope-picker` (`field-scope-kind-<everything, vrf, site or prefix>`, `field-scope-object`, `field-scope-subtree`), `field-delegable`, `form-submit`, `form-cancel` |
| Service account dialog | `dialog-service-account` with `field-name`, `field-display_name`, `field-role-<role>`, `form-submit`, `form-cancel` |
| Token dialogs (account tokens and service account tokens) | `dialog-token` with `field-name`, `field-lifetime` (service accounts), `field-kind-<personal or scoped>` (own tokens), `token-grants` with `token-grant` (`data-index`, holding `field-token-role` and a scope picker), `token-grant-add`, `token-grant-remove`, `field-token-scope-<metrics or audit_read>`, `token-grants-error`; `dialog-token-created` with `token-secret`, `token-stored`, `token-done` (service accounts); the own token list shows `token-reach` (`data-scoped`) |
| User page (access parts) | `user-kind` (a service account), `access-grants` of the account, `access-sa-tokens` of a service account |
| Vault (`/settings/vault`, `page-vault`) | `vault-key` with `vault-provider`, `vault-protection` (`data-code`), `vault-active`, `vault-epoch`; `vault-warnings` with `vault-warning` (`data-code`); `vault-rotation` with `vault-rotate`, `vault-rotation-none`, `vault-rotation-state` (`data-phase`), `vault-step-up` with `vault-sign-in-again`; `vault-controllers` with `vault-controller` (`data-key` the node) and `vault-downgrade`; `vault-generations` with `vault-generation` (`data-key`, `data-active`); `vault-refused` |
| Audit export (`/settings/audit-export`, `page-audit-export`) | `audit-export-warning` (`data-code`; `audit-export-required` for `audit.export.required`), `audit-export-policy` (`data-required`, `data-satisfied`), `field-alert_after_secs` with `audit-export-alert-save`, `audit-export-sinks` with `audit-export-add`, `audit-export-empty`, `audit-export-sink` (`data-key` the name, `data-state` disabled, pending, ok, behind, failing or alarm) holding `audit-export-state`, `audit-export-delivered`, `audit-export-lag`, `audit-export-last-success`, `audit-export-checkpoint`, `audit-export-error`, `audit-export-edit`, `audit-export-toggle`, `audit-export-remove`; `dialog-audit-sink` with `field-name`, `field-transport-<tls, tcp, udp or file>`, `field-format`, `field-host`, `field-port`, `field-facility`, `field-server_name`, `field-ca_pem`, `field-client_cert_pem`, `field-client_key`, `field-file`, `field-max_mib`, `field-keep`, `audit-export-test`, `audit-export-test-result` (`data-delivered`), `form-submit`, `form-cancel` |
| Backup (`/settings/backup`, `page-backup`) | `backup-warnings` with `backup-warning` (`data-code`), `backup-restored`, `backup-step-up` with `backup-sign-in-again`, `backup-status` with `backup-now`, `backup-target`, `backup-last-good`, `backup-last-failed`, `backup-age`, `backup-next`, `backup-running`, `backup-job`; `backup-schedule` with `field-enabled`, `field-interval`, `field-keep`, `field-recipient`, `field-target-dir`, `field-include-config`, `backup-needs-recipient`, `form-submit`; `backup-runs` with `backup-run` (`data-key`, `data-outcome`, `data-reason`) holding `backup-run-file`, `backup-run-outcome`, `backup-run-error` (`data-code`), `backup-restore-open`, and `backup-runs-empty`; `dialog-backup` with `backup-create-key`, `field-passphrase`, `field-passphrase-again`, `form-submit`, `form-cancel`; `dialog-backup-restore` with `backup-restore-command` |
| Reconciler (`/settings/reconciler`, `page-reconciler`) | `reconciler-form` with `field-adopt`, `field-interval`, `field-debounce`, `field-refresh`, `field-purge`, `field-orphan`, `field-retention` (in seconds, seconds, minutes, hours, days, days), `field-error` (`data-field` the field id), `form-submit`, `reconciler-reloaded` (after a 409), `error-notice` (`data-code`) |
| Certificates (`/settings/certificates`, `page-certificates`) | `certificates-refresh`, `certificates-read-at`, notices `certificates-expiring` (`data-code` `sys.tls.certificate_expiry`), `certificates-pending-notice` (`sys.tls.certificate_pending`), `certificates-error`, `certificates-none`, `certificates-plain`; `certificates-mode` (`data-mode`) with `certificates-mode-name`, `certificates-min-version`, `certificates-hsts`; the certificate in use `certificates-served` and a newer one on disk `certificates-pending`, each with facts `cert-` or `pending-` plus `subject`, `names`, `issuer`, `not-before`, `not-after`, `days` (`data-state`), `chain`, `fingerprint`, `loaded`; `certificates-imported` with `imported-cert-path`, `imported-key-path`, `imported-interval`, `imported-accept` (`data-accepted`), `imported-rule`; `certificates-ca` with `ca-subject`, `ca-not-after`, `ca-fingerprint`, `ca-root-download`; `certificates-proxy` with `proxy-host`, `proxy-trusted`, `proxy-protocol` |
| Guardrails (`/settings/guardrails`, `page-guardrails`) | `guardrails-form` with `field-max_parallel`, `field-error` (`data-field`), `guardrails-paths` with `guardrails-add`, `guardrails-empty`, `guardrails-note`, `guardrail-path` (`data-kind`, `data-key` such as `vlan:30`) holding `guardrail-remove`, `form-submit`, `guardrails-reloaded`; `dialog-guardrail-path` with `field-kind`, `field-device`, `field-port`, `field-network`, `field-vid`, `field-mac`, `guardrails-duplicate`, `form-submit`, `form-cancel` |
| Cluster compatibility and data format (WP3.11d) | `member-compat-<node>` with `compat-majors`, `compat-wire`, `compat-formats`; `cluster-format` (`data-state` `current` or `pending`) with `format-stored`, `format-binary`, `format-target`, `format-current`, `format-blockers` with `format-blocker` (`data-node`), `format-advice`, and `cluster-warning` (`data-code` `upgrade.migration_blocked`) |
| Job state and job group | `job-state` (`data-state`; `data-rollback="cancel"` on a cancelled job that its cancellation rolled back); in `job-group`: `job-group-l2-hint` on a layer 2 undo task, `job-group-not-moved` with `job-group-not-moved-item` (`data-job`, `data-state`), `job-group-move-failed`, `job-group-not-moved-reason`, `job-group-not-moved-link` |
| Personal tokens (`/account/tokens`) | `account-token-create`, `account-token` (`data-key` the name), `account-token-revoke`; the form with `field-name`, `field-lifetime`, `form-submit`; `dialog-token-created` with `token-secret`, `token-stored`, `token-done` |
| Partition links | `cluster-banner-link` (the banner's link to the queue), `no-quorum-show-queue` (the same in `dialog-no-quorum`) |
| Command palette | `dialog-palette`, `palette-item` (`data-key` the command id) |
| Cancel of a form or plan dialog | `form-cancel`, `plan-cancel` |
| DNS area (every page) | `dns-nav` with `dns-nav-link` (`data-key` `zones`, `views`, `forwarders`, `lists`, `acls`, `keys`, `log`); `dns-not-built` (the API answers 501), `dns-off` with `dns-modules-link` (the module is switched off) |
| Zone list | `grid-dns-zones` (rows keyed by the zone name), `filter-input`, `dns-zone-create`, `dns-zones-empty`; per row `zone-kind` (`data-kind`), `zone-reverse`, `zone-stub` (a stub zone, served through the forwarder), `zone-not-served` (a secondary zone), `zone-origins` (`data-key` the origins present, comma-separated); `dialog-zone-form` with `field-name`, `field-kind`, `field-serial`, `field-source`, `field-soa.mname`, `field-soa.rname`, `field-name_servers`, `field-soa.ttl`, `field-description`, `form-submit`, `form-cancel`; `dialog-zone-delete` with `confirm-ok` |
| Zone page | `zone-name`, `zone-header-serial` (`data-key` the serial), `dns-zone-import`, `dns-zone-export`, `dns-zone-delete`, `zone-tab-records`, `zone-tab-settings`, `zone-tab-history`; `zone-records` with `grid-dns-records` (one row per record, `data-key` `<relative name>/<type>/<index>`), `filter-input`, `filter-type`, `filter-origin`, `dns-rrset-add`, `dns-batch-toggle`, `rrset-origin` (`data-kind`), `rrset-taken-over`, `rrset-pending`, `dns-records-empty`; row actions `add`, `remove`, `delete`, `takeover`; the batch bar `dns-batch` (`data-count`) with `batch-item` (`data-index`, `data-key` `<name>/<type>`), `batch-item-drop`, `dns-batch-discard`, `dns-batch-review`; `dialog-rrset-form` with `field-name`, `field-type`, `field-ttl`, `field-data`; `dialog-rrset-delete`, `dialog-take-over`; `dialog-batch-diff` with `plan-summary` (`data-count`), `plan-change` (`data-kind` `add`, `change` or `delete`, `data-key` `<name>/<type>`), `plan-confirm`, `plan-cancel` |
| Zone settings and history | `zone-settings` with `zone-source` holding `field-source` (stub, secondary and forward zones), `field-soa.mname`, `field-soa.rname`, `field-soa.refresh`, `field-soa.retry`, `field-soa.expire`, `field-soa.minimum`, `field-soa.ttl`, `field-name_servers`, `field-serial`, `field-description`, `form-submit`; `zone-history` with `zone-serial`, `history-entry` (`data-kind` the audit action, `data-key` the sequence number), `zone-history-refused` |
| Zone transfers (WP6.1) | `zone-transfer` with `transfer-allow` (`data-key` the access list id) and its `transfer-allow-remove`, `field-allow-add`, `transfer-notify` (`data-index`) with `field-notify.<i>.address`, `field-notify.<i>.port`, `field-notify.<i>.key`, `transfer-notify-add`, `transfer-notify-remove`, `field-require_tsig`, `field-xot`, `field-catalog`; for a secondary zone `zone-primaries` with `transfer-primary-row` and `field-primaries.<i>.address`, `.port`, `.key`, `.tls_name`, `.xot`, `zone-transfer-status` with `transfer-serial`, `transfer-next-refresh`, `transfer-expires`, `transfer-running` (`data-state`), `transfer-primary` (`data-key`) with `transfer-last-error` (`data-code`), `transfer-now`; `zone-transfer-unavailable`, `zone-from-primary`; on the records tab `zone-records-readonly` |
| Zone file import | `import-steps` with `import-step` (`data-key` `upload`, `preview`, `apply` or `done`), `import-upload`, `import-dropzone`, `import-choose`, `import-file-input`, `import-file` (`data-key` the file name), `field-zone_file`, `field-replace`, `import-preview`; `import-preview-report` with `import-fact` (`data-key` `added`, `replaced` or `removed`, `data-count`), `import-types` with `import-type` (`data-key` the type, `data-count`), `import-losses` with `import-loss` (`data-index`, `data-code`) or `import-no-losses`, `import-back`, `import-apply`; `import-result` (`data-state` `done` or `failed` once finished) with `import-serial` (`data-key`), `import-open-job`, `import-again`, `import-open-zone` |
| Access lists and TSIG keys | `grid-dns-acls` (rows keyed by the list name) with `acl-entry`, `dns-acl-create`, `dns-acls-empty`, `dialog-acl-form` with `field-name`, `field-entries`, `field-description`, `dialog-acl-delete`; `grid-dns-keys` (rows keyed by the key name), `dns-key-create`, `dns-keys-empty`, `dialog-key-form` with `field-mode-generate`, `field-mode-import`, `field-name`, `field-algorithm`, `field-secret`, `field-description`; `dialog-key-created` with `key-secret`, `key-copy`, `key-stored`, `key-done`; `dialog-key-delete` |
| Query log (`/dns/log`) | `field-node`; `dns-log-figures` (`data-state` `on` or `stopped`, `data-client` `pseudonym`, `address` or `hidden`, `data-written`, `data-dropped`); `dns-log-filters` with `field-qname`, `field-client`, `field-rcode`, `field-from`, `field-until`, `field-error` (`data-field`), `form-submit`, `dns-log-reset`; `dns-log-table` with `dns-log-row` (`data-index`, `data-key` the query name, `data-rcode`; cells by `data-col` `time`, `client`, `transport`, `name`, `type`, `rcode`, `latency`, `flags`), `dns-log-client` (`data-kind` `pseudonym` or `address`), `dns-log-cached`, `dns-log-blocked`; `dns-log-empty` (`data-filtered`), `dns-log-partial`, `dns-log-paging` (`data-page`) with `dns-log-newer` and `dns-log-older`; `dns-log-refresh`, `dns-log-stop`, `dns-log-start` (administrators), `dns-log-stopped`; `dns-log-off` with `dns-log-settings-link`, `dns-log-not-dns`, `dns-log-no-node` |
| Cache (`/dns/cache`) | `field-node` (shared with the query log); `dns-cache` with `dns-cache-audit-note`, `dns-cache-form` with `field-cache-suffix`, `dns-cache-show`, `dns-cache-flush` and `dns-cache-flush-dialog`; `dns-cache-browser` with `dns-cache-tree` and `dns-cache-node` (`data-key` the folder name), `dns-cache-tree-more`; `dns-cache-folder`, `dns-cache-table` with `dns-cache-row` (`data-key`, `data-type`, `data-stale`, `data-own`), `dns-cache-folder-row`, `dns-cache-data`, `dns-cache-state`, `dns-cache-stale`, `dns-cache-ede`; `dns-cache-pane-more`, `dns-cache-capped`, `dns-cache-empty`; `dns-cache-no-node`, `dns-cache-not-dns` |
| Forwarders (`/dns/forwarders`) | `grid-dns-forwarders` (rows keyed by the suffix, `<suffix>@<view>` for a rule of one view), `dns-forwarder-create`, `dns-forwarders-empty`; per row `fwd-default` (the root rule), `fwd-transport` (`data-kind` `plain`, `dot` or `doh`), `fwd-upstream` (`data-key` the address and port asked); row actions `edit`, `delete`; `fwd-no-default` with `fwd-settings-link` (no root rule), `fwd-problems` with `fwd-problem` (the node's problems), `dns-recursion` (`data-state` `default`, `data-key` the profile); `dialog-forwarder-form` with `field-suffix`, `field-transport-<plain, dot or doh>`, `field-upstreams`, `fwd-known` (`data-key` the TLS name of the well-known resolver) with `fwd-use-dot`, `field-tls_name`, `field-all_views`, `field-description`, `field-error` (`data-field`), `form-submit`, `form-cancel`; `dialog-forwarder-delete` with `confirm-ok` |
| Views (`/dns/views`) | `grid-dns-views` (rows keyed by the view name), `dns-view-create`, `dns-views-empty`, `view-default` (`data-key` the profile); per row `view-order` (`data-key` the position; the drop target of a drag) with `view-drag`, `view-move-up`, `view-move-down`, `view-rule` (`data-kind` the test), `view-every` (no rules), `view-scope` (`data-key` `<zone>:<scope>`, `data-weight`), `view-recursion` (`data-state` `default`, `list` or `missing`, `data-key` the list name); row actions `edit`, `up`, `down`, `delete`; `dialog-view-form` with `field-name`, `field-order` (create), `view-rules` with `view-rule-editor` (`data-index`, `data-kind`) holding `field-rule-values`, `field-rule-transport-<udp, tcp, dot or doh>`, `field-rule-from`, `field-rule-to` and `view-rule-remove`, `field-rule-kind`, `view-rule-add`; `view-scopes` with `view-scope-editor` (`data-index`) holding `field-scope-zone`, `field-scope-scope`, `field-scope-weight`, `view-share` (`data-key` the per cent) and `view-scope-remove`, `view-scope-add`; `field-recursion`, `field-description`, `field-error` (`data-field` `name`, `rules`, `scope_map`, `recursion` or `description`), `form-submit`, `form-cancel`; `dialog-view-delete` with `confirm-ok` and, when refused, `view-in-use` (`data-code`) with `view-in-use-by` (`data-key` `forwarder:<suffix>`); on the forwarders page `fwd-views-link` |
| Block lists (`/dns/lists`) | `grid-dns-lists` (rows keyed by the name), `dns-list-create`, `dns-lists-empty`; per row `list-disabled`, `list-source` (`data-kind` `url` or `upload`), `list-action` (`data-kind`), `list-version` (`data-key` the version, `data-count` the names), `list-last-error` (`data-code`); row actions `fetch` (URL lists), `upload` (uploaded lists), `edit`, `delete`; `list-job` (`data-id` the job, `data-state` its state) with `list-job-open`; `dialog-list-form` with `field-name`, `field-source-<url or upload>`, `field-url`, `field-interval`, `field-file` (a new uploaded list), `field-format`, `field-action`, `field-redirect`, `field-enabled`, `field-description`, `field-error` (`data-field`), `form-submit`; `dialog-list-upload` with `field-file`, `form-submit`; `dialog-list-delete` |
| DNS settings (`/settings/dns`, read-only) | `dns-settings-refresh`, `dns-settings-forwarders`, `dns-settings-listeners` with `dns-settings-listener` (`data-index`, `data-key` the address, `data-kind` the transport), `dns-settings-tls` (`data-dot`, `data-doh`), the groups `dns-settings-role`, `dns-settings-cache`, `dns-settings-tcp`, `dns-settings-log` with `dns-setting` (`data-key` the figure, `data-value` the raw value), `dns-setting-key` (the `tenko.toml` key) and `dns-setting-doc`; `dns-settings-problems` with `dns-settings-problem`, `dns-settings-log-off`, `dns-settings-no-role`, `dns-settings-off` with `dns-modules-link`, `dns-settings-no-node`, `dns-not-built` |
| First-run wizard, DNS step | `setup-step` and `setup-card` with `data-key` `dns`; `setup-dns` (`data-state` `wanted` or `skipped`) with `field-dns-upstreams`, `setup-dns-transport` (`data-key` the transport), `setup-dns-known` (`data-key` the TLS name) with `setup-dns-use-dot`, `field-dns-tls-name`, `setup-dns-preset`, `setup-dns-switch` (`data-key` `cache`, `dot`, `doh` or `log`), `field-dns-entries`, `setup-dns-checklist` with `setup-dns-check` (`data-key`); on the review `setup-review-dns` (`data-count` the upstreams); on the result `setup-result-dns` (`data-state` `saved`, `failed` or `none`) with `setup-dns-saved`, `setup-dns-failed`, `setup-dns-config` (the `[dns]` section), `setup-dns-copy` |
| DNS records of a host or an address | `host-dns` with `host-dns-row` (`data-key` the address), `host-dns-record` (`data-kind` `forward` or `reverse`, `data-key` `<type> <data>`), `host-dns-zone`, `host-dns-empty`, `host-dns-none` (`data-kind`) |

A new view follows the same pattern: a page root id, `grid-<id>` for each grid, the generic
row and cell hooks from `DataGrid`, and `<area>-<action>` for its actions.

## End-to-end tests

`ui/e2e/` holds the browser tests of the embedded UI against the real server: first-run wizard,
sign-in with TOTP and passkeys, IPAM, import, move, audit and language (WP1.11), discovery,
connectors, nodes, secrets and updates (WP2.11), language packs (WP3.7), the DNS zones, zone files and keys (WP4.5), the query log (WP5.4), the forwarders, block lists, DNS settings and the wizard's DNS step (WP5.5), and the views (WP6.4). Every test starts its own `tenko serve` with a
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
| JetBrains Mono | SIL Open Font License 1.1 | Monospace font (`public/licenses/OFL.txt`; the font is `src/app/fonts/`) |

Development dependencies (Vite, vitest, msw, ESLint, axe-core and others) are listed in
`package.json` and are not part of the build.
