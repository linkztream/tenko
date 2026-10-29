# Tenko DDI design language

This folder is the Phase 1 design spike for the Tenko DDI user interface: a design language, a token file, a logo, and clickable HTML mockups of the core views. It exists so the owner can review the look and the interaction model before any SolidJS component is written. Nothing here is product code. The SolidJS UI will take over the tokens and the component inventory, not the markup.

Start with [`mockups/index.html`](mockups/index.html). The owner has reviewed the mockups: the answers are in [`REVIEW.md`](REVIEW.md) and summarized under [Decisions](#decisions) below; the rest of this document already reflects them.

## How to open

Double-click `mockups/index.html`. Every page is static HTML, CSS and a little plain JavaScript, with no build step and no framework. Each page loads three local files (`../tokens.css`, `shell.css`, `shell.js`) and one stylesheet from Google Fonts for the identifier face (JetBrains Mono). Offline, the pages fall back to the platform monospace face and still work. The product will not call Google: it embeds the font file (SIL Open Font License) in the binary next to the UI bundle, served from `/assets/` like every other asset (ADR 0008).

Theme, density and the "Emphasize host part" preference are remembered per browser in `localStorage` (`tenko-theme`, `tenko-density`, `tenko-emphasize`) and can all be changed in the account menu (the AK avatar, top right); the theme button in the top bar also cycles system, light, dark. Every mockup has a collapsed "Mockup notes" drawer, opened from the right end of the status bar (from the header in the wizard and on the sign-in page), with the decisions and open questions for that view, and an "All mockups" link back to the index. Some have a "Mockup scene" switcher to show states that would otherwise need live data; mockup-only chrome carries the word "Mockup" and is never drawn with a dashed border. A dashed border means a proposal (not yet intent), in the mockups and in the product alike.

## Principles

The ten principles come from the design proposal of 2026-10-26, carried out in [`docs/plans/ui-plan.md`](../docs/plans/ui-plan.md). Five of the earlier six stay (one is sharpened) and five are added.

1. **Exceptions first, everything reachable.** The umbrella. Every view has three layers in this order: what needs a person, a summary in counts, the full detail. Healthy state is never hidden, only collapsed.
2. **Speed and density first.** Compact 28 px rows by default, 13 px text, no hero banners, and the same 28 px in every list, reconciliation included. A cell that needs more lines expands on demand in the side panel instead of making every row tall. Every view must render its first useful rows before anything else is fetched.
3. **Anything in three clicks or one keystroke.** Ctrl+K finds any address, host, MAC, prefix, record or command. `g` chords jump between areas. The palette shows each command's shortcut, so it is also where shortcuts are learned. A convenience, not a goal in itself.
4. **Keyboard first, mouse equal.** Grids have a cell focus ring, Space selects, Enter edits, Esc backs out. Every drag gesture has a keyboard twin (`M` for move to network).
5. **Nothing happens silently.** Every change is a job with a preview, visible steps, a state and a way back. Background work never takes over the screen. Live changes arrive as a short flash on the cell that changed.
6. **Color is for exceptions.** A healthy grid is calm and almost monochrome. Agreeing, managed and done states never get a colored fill or wash; green appears only as a small glyph next to a word. A colored fill means a person should look. Color appears where a person must act (conflict, proposal, intent and observation disagree, failed job) and for the accent (selection, focus, primary action). State never relies on color alone: it always has a glyph and a word.
7. **Aggregate before you repeat.** When most rows share a value, say it once: in a group row, a column header or a count chip. Only the rows that differ carry a badge.
8. **Words before codes.** Every job kind, event and record type has a sentence-case label. The code stays available, in the data font and secondary (see [Label catalog](#label-catalog)).
9. **Explain once, on demand.** A view's explanation lives behind an info button next to its title, not in a paragraph above the data. An explanation repeated per row moves to the group header.
10. **Empty is a state, not a card.** A metric with no source is not drawn; it is listed in one "Hidden" line. A feature that is not set up shows one sentence and one action.

Dark and light are both designed with equal care, not inverted: each theme has its own validated steps for state and chart colors (see [Tokens](#tokens)).

## Decisions

The owner reviewed all mockups on 2026-10-09 and answered the review guide. These decisions are applied everywhere in this folder. Decisions 17 to 20 come from the design proposal of 2026-10-26 ([ui-plan.md](../docs/plans/ui-plan.md)).

| # | Topic | Decision | Where it shows |
|---|---|---|---|
| 1 | Density | Compact (28 px rows) stays the default; dense and comfortable are one click away. | Filter bar, account menu |
| 2 | Address treatment | Addresses and MACs render plain in the data font. Graying the network part and bolding the host part (and graying a MAC's vendor part) is a per-user preference, "Emphasize host part", off by default. | Account menu; all grids |
| 3 | Color only for exceptions | Stays as shown (red conflict, magenta discovered, amber differs). "Adopt" stays. | IPAM grid |
| 4 | Identifier font | JetBrains Mono, embedded in the product; the accent stays. | `tokens.css` |
| 5 | Move gesture | Dragging onto the prefix tree is primary; `M` and the action bar remain. No drop target on the topology map. | IPAM, topology |
| 6 | Move preview | Stays its own page. | Move job |
| 7 | Manual steps | One grouped checklist for the whole job; a device waits for its ticked tasks before its L2 change. A disabled "Create tickets" button hints at a ticketing connector (later). | Move job |
| 8 | Move defaults | Automatic rollback on timeout. The default observation timeout is half the DHCP lease of the target network (the renewal point, T1), never below 5 minutes, explained in the preview ("lease 24 h → timeout 12 h"). Parallelism 2. | Move job |
| 9 | Side panel versus page | As mocked. | Host |
| 10 | Copying a password | As mocked. Single sign-on (SAML and OIDC: ADFS, Entra ID, Okta) comes later and is noted on the sign-in mockup. | Host, sign-in |
| 11 | VLAN colors | No cap of three: the palette is generated for the VLANs in view, hues spread evenly in OKLCH at a fixed lightness and chroma per theme, every color at least 3:1 against the map; labels on edge groups, a legend and a patterns mode as redundancy. See [Charts and VLANs](#charts-and-vlans). | Topology, `tokens.css`, `shell.js` |
| 12 | Numbers | Queries per second is a number, never a dial. Every number that can grow uses SI suffixes (1.2K, 48K, 1.3M) so a tile never grows; the exact value is in the tooltip. | Dashboard, `tenko.si()` |
| 13 | Start page and navigation | The dashboard is the start page (the brand links to it, sign-in and the wizard lead to it). The rail keeps icons with labels (72 px). | All pages |
| 14 | Status bar | Stays. | All pages |
| 15 | Logo | The fox is approved. The lockup keeps exactly the letterforms of the 16 px header wordmark. The two-tone fox (tails in the accent) is used on the sign-in page and in the wizard, one color everywhere else. | Logo, sign-in, wizard |
| 16 | SSIDs (owner's request) | Wireless networks are IPAM objects, read from UniFi with their VLAN mapping and shown under the network that carries their VLAN. A wireless client moves to the SSID that carries the target VLAN instead of getting a per-client VLAN override. Access points are labeled with their SSIDs on the map. | IPAM tree, move job, topology |
| 17 | Rail in three groups (proposal of 2026-10-26) | The rail keeps its 12 items in their order; a hairline separates three groups (Operate, Work, System) and Settings sits at the bottom. A badge per group shows the findings of that area, colored by the worst severity. | Rail, status bar |
| 18 | Findings model with three severities | Conflicts, proposals, ghost addresses, disagreements, alarms and jobs that wait for a person are one object, a finding, with a severity: Act now, Review or Info. Only Act now colors the dashboard, the rail and the status bar; Info is listed where it lives and never counted as a problem. Components ask for a severity (`--severity-act`, `--severity-review`, `--severity-info`), not for a domain color. | Dashboard, rail, status bar, Discovery, Reconcile |
| 19 | Label catalog for codes | Job kinds and audit events read as sentence-case labels from the language files; the code stays one line below, in the data font. | Jobs, Audit, dashboard |
| 20 | Empty states and the Hidden line | A metric without a source is not drawn; one "Hidden" line names it with the reason. A feature that is not set up shows one sentence and one action, on a quiet fill and never dashed. | Dashboard, every panel |

## Visual direction

**Type.** The interface text uses the platform face (Segoe UI Variable on Windows 11, SF on macOS, the system sans elsewhere): zero bytes, native rendering, instant first paint. Identifiers (addresses, MACs, prefixes, DUIDs, ports) use one embedded monospace face, **JetBrains Mono**: wide, open shapes with clear 0 and O, 1, l and I, which matters in a product where a misread MAC or address is a real outage. Its code ligatures are switched off everywhere (`font-variant-ligatures: no-contextual` on the root, `none` on identifiers), so the `::` of an IPv6 address always shows as two colons.

**The address treatment.** Addresses and MACs render plain in the data font by default, one color and one weight. The markup always carries the split (network part and host part of an address, vendor part of a MAC), so the per-user preference "Emphasize host part" in the account menu can gray the network part and set the host part in bold (`192.0.2.`**`41`**), and gray a MAC's vendor part. The same applies to IPv6 (prefix and interface identifier).

**Color.** Cool, slightly ink-blue neutrals in both themes, and one accent: *kikyo*, a bellflower blue-violet (`#4B44CF` light, `#9C97FF` dark). The accent marks only selection, focus, the primary action, running work and link hover; identifiers in grids (prefixes, addresses, MACs) render in `--ink`, not in the accent. Domain states have their own reserved hues (below). Charts use a validated categorical palette that never borrows the accent or a state color.

**Shape.** Hierarchy comes from hairlines and spacing, not from shadows or cards. Radius grows with the size of the thing: 3 px for badges, 5 px for buttons and inputs, 8 px for panels and popovers, 12 px for dialogs. Shadows exist only on floating layers: menus, palette, toasts, drag ghosts.

## Tokens

All tokens are CSS custom properties in [`tokens.css`](tokens.css). Components use roles, never raw hex. Light is the default; dark applies when the OS prefers dark, unless the user picked light, and always when the user picked dark. The choice is stored as `tenko-theme` and written to `<html data-theme>`. A two-line inline script in each page's `<head>` applies it before first paint, so there is no flash.

### Type scale

| Token | Size | Use |
|---|---|---|
| `--fs-11` | 11 px | kbd hints, badge text, axis ticks |
| `--fs-12` | 12 px | secondary text, column headers, status bar |
| `--fs-13` | 13 px | body, grid cells, controls (default) |
| `--fs-14` | 14 px | panel titles, dialog body |
| `--fs-16` | 16 px | section headings |
| `--fs-18` | 18 px | page titles |
| `--fs-24` | 24 px | stat tile values |
| `--fs-36` / `--fs-48` | 36 / 48 px | wizard heading, the single hero figure on a dashboard |

Weights: 400, 500 (labels), 600 (headings, emphasis), 700 (host part of an address). Sentence case everywhere: no all-caps labels, no letter-spaced eyebrow labels. Numbers in columns use tabular figures (`.num`); large standalone figures keep proportional figures.

### Spacing and density

A 4 px base with a 2 px half-step: `--sp-1` 2, `--sp-2` 4, `--sp-3` 6, `--sp-4` 8, `--sp-5` 12, `--sp-6` 16, `--sp-7` 20, `--sp-8` 24, `--sp-9` 32, `--sp-10` 48.

| Density | Row height | Cell padding | Control height |
|---|---|---|---|
| Dense | 24 px | 6 px | 24 px |
| Compact (default) | 28 px | 8 px | 28 px |
| Comfortable | 34 px | 10 px | 32 px |

Density is a user setting on `<html data-density>`, switchable from every grid's filter bar.

### Surfaces and ink

| Role | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#F3F4F7` | `#111318` | app canvas |
| `--surface` | `#FFFFFF` | `#171A21` | content, grids, panels |
| `--surface-2` | `#F7F8FA` | `#1C2028` | grid header, rail, quiet fills |
| `--surface-3` | `#EEF0F4` | `#252A34` | hover, pressed |
| `--line` / `--line-strong` | `#E2E5EB` / `#CBD0D9` | `#2A303B` / `#3A414F` | hairlines |
| `--control-line` | `#8E96A5` | `#687184` | input borders (3:1) |
| `--ink` | `#161921` | `#E6E9EF` | primary text |
| `--ink-2` | `#464D5C` | `#B0B7C4` | secondary text |
| `--ink-3` | `#626A7C` | `#8C95A6` | muted text; lowest step for text that must be read (at least 4.5:1, also on the selection wash) |
| `--ink-4` | `#9CA3B0` | `#5B6372` | placeholders and disabled only |
| `--accent` | `#4B44CF` | `#9C97FF` | selection, focus, primary action, running work |
| `--accent-wash` | `#EDECFC` | `#25234A` | selected rows |

### Domain state colors

Assignment modes (IPAM-14). Saturation follows how much Tenko controls the host: the two managed modes are colored, the two observe-only modes are gray. Each mode has a glyph, so the color is never needed to tell them apart.

| Mode | Glyph | Light | Dark | Meaning |
|---|---|---|---|---|
| `reserved` | filled diamond | `#0B7F75` | `#3CC2B2` | DHCP reservation and DNS follow intent |
| `static` | filled square | `#3D64A8` | `#84A8E6` | only DNS follows; the device is set by hand |
| `dynamic` | half-filled circle | `#6B7486` | `#9AA3B3` | observe only |
| `unmanaged` | dashed ring | `#8D94A1` | `#6E7686` | Tenko never touches it |

Exceptions: the only loud colors in a healthy grid.

| State | Light | Dark | Treatment |
|---|---|---|---|
| Discovered host or orphaned record (proposal) | `#B03A86` | `#E883C5` | dashed row edge and dashed badges: not yet intent |
| Conflict (IPAM-23) | `#C8322F` | `#FF7A72` | red row edge, conflict octagon, the word "Conflict" |
| Intent and observation differ | `#9A5A00` text, `#F0A31A` marker | `#F2B544` | amber badge with "!" on the source that disagrees |
| Locked | ink-2 | ink-2 | lock glyph; a shield glyph when a guardrail locks it |

Job states (IPAM-17). Running and waiting share the accent: running is a filled progress pie, waiting is a dashed ring with a countdown.

| State | Glyph | Light | Dark |
|---|---|---|---|
| Queued | hollow ring | `#7C8496` | `#8D96A6` |
| Running | filling pie | accent | accent |
| Waiting for observation | dashed ring + countdown | accent | accent |
| Done | filled dot in a ring | `#1E7F3A` | `#4CC27A` |
| Failed | diamond | `#C8322F` | `#FF7A72` |
| Rolled back | open ring | `#B0521A` | `#F0965A` |

### Severity

Components ask for a severity, not for a domain color. The three roles point at the existing colors and follow them in both themes:

| Role | Points at | Used for |
|---|---|---|
| `--severity-act` | `--conflict` | Act now: a person must decide now (conflict, waiting job, over the alarm) |
| `--severity-review` | `--proposal` | Review: a person should look (unknown device, orphaned record, PTR mismatch, intent and observation differ) |
| `--severity-info` | `--ink-3` | Info: listed where it lives, never counted as a problem |

`--ok-wash` and `--job-done-wash` are for chips only; no row or column is filled with them.

### Text on a colored fill

Text on a colored fill (map cells, badges, counters) is a dark shade of the fill's own hue on light fills and a light shade on dark fills, never plain white or black by default. It must reach 4.5:1 against the fill; 3:1 is allowed only at 24 px and up. Each fill token that can carry text has a paired `-on` token (`--mode-static-on`, `--conflict-on`, `--proposal-on`, `--severity-act-on` and so on in `tokens.css`) that is checked once, so no component picks a text color by eye. The accent's pair is `--accent-ink`. Washes carry ordinary ink and need no pair. The address map's 11 px octets follow this rule, with `--ink-3` on free cells.

### Charts and VLANs

Chart colors follow the data-visualization method used for the dashboard: eight categorical hues in a fixed order (`--series-1` to `--series-8`), a single-hue sequential ramp (`--seq-*`) and a fixed status scale (`--status-good`, `-warning`, `-serious`, `-critical`), each validated for color-vision deficiency and contrast against Tenko's own surfaces (`#FFFFFF` and `#171A21`). Status colors always come with an icon and a label.

VLAN identity is generated, not fixed. The VLANs visible in a view get hues spread evenly around the OKLCH circle, starting at `--vlan-h0` (255), at one lightness and chroma per theme (`--vlan-l` and `--vlan-c`: 0.58 and 0.14 in light, 0.70 and 0.13 in dark). Chroma is reduced only where a hue would leave sRGB, and lightness is nudged until each color has at least 3:1 against the map background; with these values every color measures at least 4:1 on the light map and 6:1 on the dark one, for any number of VLANs from 1 to 24. `tenko.vlanPalette(n)` in `mockups/shell.js` implements the rule, and `--vlan-lan`, `--vlan-lab`, `--vlan-iot` and `--vlan-dmz` in `tokens.css` are its four-VLAN instance. Hue alone cannot separate many VLANs for every reader, so color is never alone: every edge group carries a VLAN label, the legend lists the VLANs in view with their swatches, and a "Patterns" mode adds a dash style per VLAN.

With 150 or more VLANs no palette stays readable, so color follows attention: color by selection (the VLANs you pick in the filter are colored, all others neutral gray) or color by site (sites get the hues, VLANs stay neutral), with search and focus mode to reduce the view first. Labels and patterns work at any count.

### Motion

`--dur-1` 80 ms, `--dur-2` 160 ms, `--dur-3` 240 ms, and `--dur-flash` 1400 ms for the live-update flash. Motion only answers an action (opening, expanding, confirming), except the flash, which is the one deliberate exception because a remote change needs to be noticed. With reduced motion, the flash becomes a static underline and nothing animates.

## Navigation shell

The shell keeps its parts and tells you where the findings are, from any page.

| Group | Items | Badge |
|---|---|---|
| Operate | Dashboard, IPAM, DNS, DHCP, Discovery, Topology | The count of findings for that area, colored by the worst severity |
| Work | Jobs, Audit | Jobs: the count of jobs waiting for you |
| System | Connectors, Nodes, Cluster | A dot when a connector or node is unhealthy |
| Bottom | Settings | A dot when a setting is weaker than the profile allows |

- **Rail.** Twelve items in the order of decision 13, separated into the three groups by a hairline. Info findings never raise a badge.
- **Top bar.** Mark, command field, node status, profile, theme, help and account. The node chip is cluster-aware ("Leader · 1 node", "Follower · 3 nodes, 1 behind") and opens a short cluster card; the profile chip opens what the profile changes.
- **Page header.** One pattern for every view: title (18 px) with an info button, one subtitle line of facts (counts, scope, freshness), primary actions on the right, sub-navigation tabs under it.
- **Filter bar.** One pattern for every list: query field, exception chips with counts, density, columns. Each list shows the chips its findings need.
- **Status bar.** Live, last event, running and waiting jobs and the version, then open findings as one count per severity; each count links to the filtered findings list. Info is a plain count outside the totals.

## Component inventory

All of these exist in [`mockups/shell.css`](mockups/shell.css) and are used across the mockups.

| Component | Class | Notes |
|---|---|---|
| Navigation shell | `.app`, `.topbar`, `.rail`, `.main`, `.statusbar` | Top bar: mark, command field (Ctrl+K), the cluster-aware node chip ("Leader · 1 node", "Follower · 3 nodes, 1 behind") with its cluster card, the profile chip with what the profile sets, theme, keyboard sheet, account. Rail: the 12 items in three groups with badges, and Settings, with labels under icons (see [Navigation shell](#navigation-shell)). Status bar: live connection, last event, running and waiting jobs, open findings per severity, selection count. Built in the product (U2): `ui/src/shell/` (`Rail.tsx`, `railBadge.tsx`, `StatusBar.tsx`, `FindingsStatus.tsx`, `TopBar.tsx`, `TopCards.tsx`), the counts from one store (`findings.ts`). |
| Security banner | `.banner.danger` | Persistent while the Lab profile or any weakened setting is active. Hatched edge, cannot be dismissed. |
| Grid | `table.grid` | Sticky header, cell-level focus ring (`td.focus`), selected rows with an accent edge, proposal rows dashed, conflict rows with a red edge, free runs collapsed into one striped row, ranges as collapsible group rows. |
| Inline editor | `.cell-input`, `.cell-hint` | Enter or double-click edits a hostname in place; a one-line hint states the consequence ("updates A and PTR as a job"). Mode opens a small list with each mode's consequence. |
| Filter bar | `.filterbar`, `.query`, `.chip` | A query field that accepts `field:value` terms (or applies on Enter for a list read on request), dimension chips, exception toggles with counts (conflicts, proposals, differs), density switch, column chooser. Built in the product (U2) as one component, `ui/src/grid/FilterBar.tsx`, used by Jobs, Reconciliation, the DNS cache, IPAM addresses, Audit and Discovery. |
| Prefix tree | `.tree`, `.tnode` | Tenant and VRF, supernet, prefix, range; wireless networks (SSIDs, `.tnode.ssid` with a wifi glyph) under the network that carries their VLAN; utilization meter per prefix; drop target state while dragging (a prefix or an SSID). |
| Selection action bar | `.actionbar` | Appears with a selection: Move to network, Set mode, Lock, Export CSV, each with its key. |
| Side panel | `.panel` | Docked over the grid on the right; the full-page view of the same object uses the same sections. |
| Job panel | `.jstate` plus the move-job mockup | Per-item state with glyph and word, step list, countdown while waiting for observation, failure reason and Roll back. |
| Toast | `.toasts`, `.toast` | Result of an action with Undo or Open job. Auto-dismisses unless it reports a failure. |
| Command palette | `#palette` (shell.js) | One field for addresses, hosts, MACs, prefixes and commands; `>` limits to commands. |
| Account menu | `.acct` (shell.js) | Opens from the avatar: theme, row density, "Emphasize host part", keyboard shortcuts, sign out. |
| Number formatter | `tenko.si()`, `data-si` (shell.js) | 982, 1.2K, 48K, 1.3M: at most three significant digits so tiles and cells never grow; the exact value goes into the title. |
| Wizard and sign-in | wizard and sign-in mockups | Focused pages without the rail; the two-tone mark. The wizard has numbered steps on the left and one card on the right; sign-in is passkey first. |
| Badges | `.mode`, `.src`, `.flag`, `.tag`, `.vlan`, `.meter` | Mode glyph and word; source badges (agrees, differs, only observed, stale); flags; VLAN swatch and number; utilization meter neutral until it crosses the alarm. A badge appears only where a row differs from its column's majority. The majority in the header is built (U4, `ui/src/grid/majority.ts`, `Column.majority`): when every loaded row of a column shares one value, the header reads "State · all insecure" and the cells stay empty; one row that differs brings the cells back. |
| Finding (row, chip, strip) | `.finding`, `.finding-chip`, `.attention` | The glyph of the kind, one word, one default action. The chip carries a count; the strip is the dashboard's needs-attention strip, or one "All clear" line. The chip is built (U2, `ui/src/components/Finding.tsx`): the status bar's counts per severity. The strip is built (U3, `ui/src/dashboard/Attention.tsx`): a row per finding to act on with the glyph, the kind, the subject, one line of evidence, since when and the default action, one line for the findings to review per area, or one "All clear" line. The row is built (U4, `ui/src/discovery/findingColumns.tsx` with `FindingAction.tsx`): the glyph of the kind in its domain color and its word, the subject as a link, one line of evidence, since when and the default action as a button, in the Discovery list and, per network, in the reconciliation view; the side panel of both is `FindingPanel.tsx`, which leads a conflict with both MAC addresses (`ConflictLead.tsx`). Mockup: [`mockups/reconciliation.html`](mockups/reconciliation.html). |
| Metric block | `.metric`, `.metric-row` | Label (12 px, `--ink-3`), value (24 px, SI), unit, one line of context. A sparkline only with a window and its scale. A metric without a source is not drawn; it joins the Hidden line. Built (U3, `ui/src/components/Metric.tsx`): a real link when it has a destination, the context in the act color only for a finding to act on, an unknown value as a dash; `.metric-row` lays blocks out in one row with shared hairlines (the dashboard's health row and system panel). |
| Empty state | `.empty-state` | One sentence of what is missing and one action, on a `--surface-2` fill. Never dashed. Built (U3, `ui/src/components/EmptyState.tsx`): the dashboard's DHCP panel while no scope has a pool ("Create a scope"). |
| Group row | `tr.group-row` | Collapses a run of similar rows with a count ("Intent wins · 23", "Today · 4 jobs"); the sentence that would repeat per row is said once here. Built (U4, `ui/src/grid/GroupedGrid.tsx` and `groups.ts`): a 28 px row with the chevron, the label (a severity word colored only for Act now and Review), the count, an optional short note and the shared sentence; the open or closed state per grid and group key for the session; Enter, Space and a click toggle it, its button carries `aria-expanded`; virtualization and the grid's keys stay; a group can end with a tail row such as "Show more". Discovery and the reconciliation view use it; Jobs by day (U5) and the IPAM networks (U6) are next. |
| Info button | `.info-btn` | Beside a view's title; opens its explanation in a popover. Built (U2) in the page header, `ui/src/components/PageHeader.tsx` with `Popover.tsx`: title, info button, one subtitle line of facts, actions, tabs; used by Jobs, Audit, Discovery, Reconciliation and the DNS cache. |
| Hidden line | `.hidden-line` | One line at the foot of a view naming the metrics that are not drawn and why. Built (U3, `ui/src/components/HiddenLine.tsx`): each item says what and why, and a real toggle button ("Show all metrics", "Show fewer metrics", with its pressed state) draws them for the session; not drawn when nothing is hidden. |
| Address map | `.amap` (planned) | One CSS grid cell per address, colored only where a finding sits, last octet in the cell's `-on` token; up to 1,024 cells (a /22), one cell per /24 above that. No chart library. |

## Keyboard map

| Where | Keys | Action |
|---|---|---|
| Anywhere | Ctrl+K | Command palette and search |
| | ? | Keyboard shortcuts |
| | G then B / I / D / H / T / J / S | Go to Dashboard, IPAM, DNS, DHCP, Topology, Jobs, Settings |
| | Shift+T | Cycle theme |
| Grids | Arrow keys, J / K | Move the cell focus |
| | Space | Select or deselect the focused row |
| | Shift+Up / Down | Extend the selection |
| | Ctrl+A | Select all rows in view |
| | Enter | Edit the focused cell |
| | Esc | Cancel the edit, close the menu, then clear the selection |
| | / | Filter this view |
| | . | Open the details panel |
| | Shift+Enter | Open as a full page |
| Changes | M | Move the selection to a network (opens the preview) |
| | Shift+M | Set assignment mode |
| | L | Lock or unlock |
| | N | Claim the next free address |
| | Ctrl+Z | Undo the last change |
| | Shift+J | Open the job panel |
| | Ctrl+Shift+E | Export CSV |
| Tree | [ and ] | Focus the tree, focus the grid |

Single-key shortcuts never fire while focus is in a text field.

## Interaction rules

- **Preview before apply.** Anything that changes more than the row you are typing in shows its consequences first: old and new value, which systems are touched (DHCP, DNS, UniFi), what stays manual. The confirm button names the action and the count ("Start 5 moves"). The result toast uses the same verb.
- **Small edits preview inline.** Renaming a host or changing its mode shows the consequence in a one-line hint or menu, commits on Enter, and offers Undo in the toast.
- **Undo where possible.** Every committed change is a job, so undo is a compensating job, offered in the toast and in the job panel. Where undo is impossible (a device already moved and seen), the UI says so and offers Roll back instead.
- **Optimistic updates with reconciliation.** Edits show immediately with a pending marker. The job and the SSE stream confirm them; if the server disagrees, the cell returns to the server's value with a flash and a toast that explains why. The UI never shows a value that the server has refused.
- **Live updates via SSE.** Changed cells flash once in a pale accent and settle. Rows never jump under the cursor: new rows are announced with a count ("3 new, show") while you are scrolled or have a selection.
- **No modal spinners for background work.** Scans, moves and imports run as jobs. The status bar and the Jobs badge show them; the rest of the UI stays usable. A spinner is allowed only inside the control that is waiting, for less than a second.
- **Drag and drop has a keyboard twin.** Dragging a selection lifts it as a stacked ghost with a count. Valid targets highlight with a dashed accent outline, invalid ones dim and say why on hover. Dropping opens the preview; it never changes anything by itself.
- **Errors say what happened and what to do.** "No ARP or lease from 00-00-5E-00-53-2C within 5:00. The client did not reconnect." followed by Retry and Roll back. No apologies, no codes without words.
- **Durations read as people say them.** 17 h 17 min, not 1,037 min. A number nobody can judge is noise: a ratio says what it is a ratio of, and a value that cannot be a real count (1.8e19 addresses) is shown as what it means.
- **Every chart names its window and its scale.** A sparkline without a window ("last 60 s") and a scale (the axis maximum) is not drawn.
- **Numbers never resize their container.** Counts that can grow use SI suffixes with at most three significant digits (1.2K, 48K, 1.3M), with the exact value on hover. Queries per second is a number, never a dial.
- **Moves wait for the network, then clean up after themselves.** A move waits for each device up to half the target network's DHCP lease (never less than 5 minutes) and rolls back automatically on timeout. Other failures wait for a decision (Retry or Roll back).
- **Insecure state is loud.** The Lab profile and any setting weaker than the Home profile show a persistent banner.

## Label catalog

Codes are for the author; labels are for the person. Every job kind and audit event has a sentence-case label that names its object, and the code stays one line below it in the data font and secondary ink. The catalog lives in the language files (`ui/i18n/en.d` and `sv.d`), one XLIFF unit per code, and the hook is `tDynamic(key) ?? code`: a code without a label shows the code and nothing breaks. There is no separate catalog format.

Template rules:

- A label is a verb phrase in sentence case with no trailing period: "Edit host controller-1 (3 objects)".
- The object (name, address, count) fills a placeholder from the job's or event's parameters; code never builds a label by joining strings.
- A count reads through a plural unit ("1 object", "3 objects").
- A label never contains a secret, a token or a credential value, and never contains the code.
- A name that can be long is truncated by the cell, not by the template.
- Record data gets the same treatment: an HTTPS or SVCB record reads `alpn=h2,h3 ipv4hint=192.0.2.10`, not JSON keys.

The first codes:

| Code | Label |
|---|---|
| `ipam.job.edit` | Edit host controller-1 (3 objects) |
| `dhcp.job.edit` | Edit DHCP scope 192.0.2.0/24 |
| `scan.job.run` | Scan host-192-0-2-11 |
| `ipam.reconcile.run` | Reconcile IPAM |
| `ipam.observation.ingest` | Ingest observations (UniFi) |
| `connect.secret.inject` | Pass credentials to a connector |

## The mark

The Tenko mark is a nine-tailed fox, the form a tenko takes. A geometric fox head, seven points with two ears and a pointed chin, sits in front of nine tails that fan out behind it. The tails rise from a point just behind the chin, at 25-degree steps from -100 to +100 degrees, and each one flicks its tip outward, so the silhouette reads as a fox spreading its tails, not as a flower or a sun. It is built on a 48-unit grid: the fan center is at (24, 33), the tails end on circles of radius 22 at the sides and 24 at the top, and a 1.5-unit knockout separates the head from the tails so the mark works in a single color. It is drawn in `currentColor` and follows the theme. The two-tone variant colors only the tails with the accent and is used on the sign-in page and in the first-run wizard; everywhere else the mark is one color. Below 24 px the small cut drops the eyes and widens the knockout to 1.9 units; the favicon uses that cut and switches between ink and light ink with the system theme. Clear space: keep x on every side, where x is half the width of the head (9 units, about a fifth of the mark's height). Minimum sizes are 16 px for the mark and 88 px wide for the lockup. The wordmark "Tenko" is drawn as monoline strokes on the same grid, with "DDI" set in the x-height in a lighter stroke, so the lockup needs no font file; its letterforms are fixed as the ones in the 16 px header wordmark of every page. See [`logo/preview.html`](logo/preview.html) for every variant at 16, 32 and 128 px on light and dark, the construction grid and the rules for use.

## Files

| Path | What |
|---|---|
| `README.md` | This document |
| `REVIEW.md` | Questions for the owner while clicking through, and what was left out on purpose |
| `tokens.css` | Design tokens for light and dark, with the severity roles and the paired `-on` text tokens |
| `../docs/plans/ui-plan.md` | The plan that turns the 2026-10-26 proposal into work packages U1 to U8 |
| `logo/tenko-mark.svg` | The mark, one color (`currentColor`) |
| `logo/tenko-mark-duo.svg` | The mark, two-tone (tails in the accent) |
| `logo/tenko-favicon.svg` | The small cut for 16 to 24 px, adapts to the system theme |
| `logo/tenko-lockup.svg` | Mark plus wordmark "Tenko" and "DDI" |
| `logo/preview.html` | All variants on light and dark, pixel tests, construction, clear space |
| `mockups/index.html` | Entry page linking every mockup |
| `mockups/shell.css`, `mockups/shell.js` | Shared components and behavior for the mockups (icons, theme, palette, keyboard sheet, toasts) |
| `mockups/shell-and-ipam.html` | Application shell and the IPAM view (reference implementation) |
| `mockups/host.html` | Host detail as a side panel and as a full page |
| `mockups/move-job.html` | Move job: preview, running job panel, jobs list |
| `mockups/topology.html` | Topology map with hover card, port panel, filters and legend |
| `mockups/dashboard.html` | Dashboard per node and for the cluster |
| `mockups/reconciliation.html` | Discovery's findings list grouped by severity with the side panel of a conflict, and the per-network reconciliation view (U4) |
| `mockups/wizard.html` | First-run wizard |
| `mockups/signin.html` | Sign-in (passkey first), with the two-tone mark |

## Notes for the SolidJS implementation

- `tokens.css` can be imported as is. Components should reference roles (`var(--surface)`, `var(--mode-reserved)`), never hex values.
- The grid needs virtualized rows. The cell focus model (row index, column index) and the selection model (set of ids plus an anchor) are separate state, as in the mockup script.
- The icon sprite in `shell.js` is a 16-unit stroke set; it becomes one inline sprite in the bundle.
- The font is the only binary asset besides the mark: JetBrains Mono as one variable WOFF2 under `/assets/`, measured at 31 KB for the Latin subset (which covers Swedish) and 43 KB with Latin Extended. Regular and bold come from the same file.
- Every UI string in the mockups is plain English in sentence case and is meant to become a key in the English language pack (API-21).
