# Tenko DDI design language

This folder is the Phase 1 design spike for the Tenko DDI user interface: a design language, a token file, a logo, and clickable HTML mockups of the core views. It exists so the owner can review the look and the interaction model before any SolidJS component is written. Nothing here is product code. The SolidJS UI will take over the tokens and the component inventory, not the markup.

Start with [`mockups/index.html`](mockups/index.html), and use [`REVIEW.md`](REVIEW.md) as the question list while you click through.

## How to open

Double-click `mockups/index.html`. Every page is static HTML, CSS and a little plain JavaScript, with no build step and no framework. Each page loads three local files (`../tokens.css`, `shell.css`, `shell.js`) and one stylesheet from Google Fonts for the identifier face (Atkinson Hyperlegible Mono). Offline, the pages fall back to the platform monospace face and still work. The product will not call Google: it embeds the font files (SIL Open Font License) in the binary next to the UI bundle, served from `/assets/` like every other asset (ADR 0008).

Theme and density are remembered per browser in `localStorage` (`tenko-theme`, `tenko-density`). The theme button in the top bar cycles system, light, dark. Every mockup has a collapsed "Mockup notes" drawer, opened from the right end of the status bar (from the header in the wizard), with the open questions for that view. Some have a dashed "Mockup scene" switcher to show states that would otherwise need live data. Dashed borders always mean mockup-only, never product UI.

## Principles

1. **Speed and density first.** Compact 28 px rows by default, 13 px text, no hero banners. The screen is for data, not chrome. Every view must render its first useful rows before anything else is fetched.
2. **Anything in three clicks or one keystroke.** Ctrl+K finds any address, host, MAC, prefix, record or command. `g` chords jump between areas. The palette shows each command's shortcut, so it is also where shortcuts are learned.
3. **Keyboard first, mouse equal.** Grids have a cell focus ring, Space selects, Enter edits, Esc backs out. Every drag gesture has a keyboard twin (`M` for move to network).
4. **Nothing happens silently.** Every change is a job with a preview, visible steps, a state and a way back. Background work never takes over the screen. Live changes arrive as a short flash on the cell that changed.
5. **Dark and light with equal care.** Both themes are designed, not inverted. Each has its own validated steps for state and chart colors.
6. **Color is for exceptions.** A healthy grid is calm and almost monochrome. Color appears where a person must act (conflict, proposal, intent and observation disagree, failed job) and for the accent (selection, focus, primary action). State never relies on color alone: it always has a glyph and a word.

## Visual direction

**Type.** The interface text uses the platform face (Segoe UI Variable on Windows 11, SF on macOS, the system sans elsewhere): zero bytes, native rendering, instant first paint. Identifiers use one embedded face, **Atkinson Hyperlegible Mono**, drawn for low-vision legibility: 0 and O, 1, l and I, 5 and S, 8 and B are unmistakable. That is the hardest legibility problem in this product, where a misread MAC or address is a real outage. The identifier face is where the typography spends its boldness.

**The address treatment.** In a grid, the network part of every address is set in muted ink and the host part in bold ink: `192.0.2.`**`41`**. Within a prefix the network part is identical on every row, so the eye goes straight to what differs. MACs follow the same rule: the vendor part (OUI) is muted. The same treatment applies to IPv6 (prefix muted, interface identifier strong).

**Color.** Cool, slightly ink-blue neutrals in both themes, and one accent: *kikyo*, a bellflower blue-violet (`#4B44CF` light, `#9C97FF` dark). The accent marks only selection, focus, the primary action and running work. Domain states have their own reserved hues (below). Charts use a validated categorical palette that never borrows the accent or a state color.

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

### Charts and VLANs

Chart colors follow the data-visualization method used for the dashboard: eight categorical hues in a fixed order (`--series-1` to `--series-8`), a single-hue sequential ramp (`--seq-*`) and a fixed status scale (`--status-good`, `-warning`, `-serious`, `-critical`), each validated for color-vision deficiency and contrast against Tenko's own surfaces (`#FFFFFF` and `#171A21`). Status colors always come with an icon and a label.

VLAN identity uses the categorical order: LAN, Lab and IoT take slots 1 to 3. Views where any two VLANs can sit side by side (the topology map) can color at most three VLANs and stay distinguishable for every reader, so a fourth VLAN in view is drawn neutral with a dashed outline and keeps its VLAN tag. With many VLANs the rule becomes: color the three you are focusing on, gray the rest.

### Motion

`--dur-1` 80 ms, `--dur-2` 160 ms, `--dur-3` 240 ms, and `--dur-flash` 1400 ms for the live-update flash. Motion only answers an action (opening, expanding, confirming), except the flash, which is the one deliberate exception because a remote change needs to be noticed. With reduced motion, the flash becomes a static underline and nothing animates.

## Component inventory

All of these exist in [`mockups/shell.css`](mockups/shell.css) and are used across the mockups.

| Component | Class | Notes |
|---|---|---|
| Navigation shell | `.app`, `.topbar`, `.rail`, `.main`, `.statusbar` | Top bar: mark, command field (Ctrl+K), cluster and node status, security profile, theme, keyboard sheet, account. Rail: Dashboard, IPAM, DNS, DHCP, Topology, Jobs, Settings, with labels under icons. Status bar: live connection, last event, running and waiting jobs, selection count. |
| Security banner | `.banner.danger` | Persistent while the Lab profile or any weakened setting is active. Hatched edge, cannot be dismissed. |
| Grid | `table.grid` | Sticky header, cell-level focus ring (`td.focus`), selected rows with an accent edge, proposal rows dashed, conflict rows with a red edge, free runs collapsed into one striped row, ranges as collapsible group rows. |
| Inline editor | `.cell-input`, `.cell-hint` | Enter or double-click edits a hostname in place; a one-line hint states the consequence ("updates A and PTR as a job"). Mode opens a small list with each mode's consequence. |
| Filter bar | `.filterbar`, `.query`, `.chip` | A query field that accepts `field:value` terms, dimension chips, exception toggles with counts (conflicts, proposals, differs), density switch, column chooser. |
| Prefix tree | `.tree`, `.tnode` | Tenant and VRF, supernet, prefix, range; utilization meter per prefix; drop target state while dragging. |
| Selection action bar | `.actionbar` | Appears with a selection: Move to network, Set mode, Lock, Export CSV, each with its key. |
| Side panel | `.panel` | Docked over the grid on the right; the full-page view of the same object uses the same sections. |
| Job panel | `.jstate` plus the move-job mockup | Per-item state with glyph and word, step list, countdown while waiting for observation, failure reason and Roll back. |
| Toast | `.toasts`, `.toast` | Result of an action with Undo or Open job. Auto-dismisses unless it reports a failure. |
| Command palette | `#palette` (shell.js) | One field for addresses, hosts, MACs, prefixes and commands; `>` limits to commands. |
| Wizard | wizard mockup | Numbered steps on the left, one card on the right, Back and Continue. |
| Badges | `.mode`, `.src`, `.flag`, `.tag`, `.vlan`, `.meter` | Mode glyph and word; source badges (agrees, differs, only observed, stale); flags; VLAN swatch and number; utilization meter neutral until it crosses the alarm. |

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
- **Insecure state is loud.** The Lab profile and any setting weaker than the Home profile show a persistent banner.

## The mark

The Tenko mark is a nine-tailed fox, the form a tenko takes. A geometric fox head, seven points with two ears and a pointed chin, sits in front of nine tails that fan out behind it. The tails rise from a point just behind the chin, at 25-degree steps from -100 to +100 degrees, and each one flicks its tip outward, so the silhouette reads as a fox spreading its tails, not as a flower or a sun. It is built on a 48-unit grid: the fan center is at (24, 33), the tails end on circles of radius 22 at the sides and 24 at the top, and a 1.5-unit knockout separates the head from the tails so the mark works in a single color. It is drawn in `currentColor` and follows the theme. The two-tone variant colors only the tails with the accent. Below 24 px the small cut drops the eyes and widens the knockout to 1.9 units; the favicon uses that cut and switches between ink and light ink with the system theme. Clear space: keep x on every side, where x is half the width of the head (9 units, about a fifth of the mark's height). Minimum sizes are 16 px for the mark and 88 px wide for the lockup. The wordmark "Tenko" is drawn as monoline strokes on the same grid, with "DDI" set in the x-height in a lighter stroke, so the lockup needs no font file. See [`logo/preview.html`](logo/preview.html) for every variant at 16, 32 and 128 px on light and dark, the construction grid and the rules for use.

## Files

| Path | What |
|---|---|
| `README.md` | This document |
| `REVIEW.md` | Questions for the owner while clicking through, and what was left out on purpose |
| `tokens.css` | Design tokens for light and dark |
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
| `mockups/wizard.html` | First-run wizard |

## Notes for the SolidJS implementation

- `tokens.css` can be imported as is. Components should reference roles (`var(--surface)`, `var(--mode-reserved)`), never hex values.
- The grid needs virtualized rows. The cell focus model (row index, column index) and the selection model (set of ids plus an anchor) are separate state, as in the mockup script.
- The icon sprite in `shell.js` is a 16-unit stroke set; it becomes one inline sprite in the bundle.
- The font is the only binary asset besides the mark: Atkinson Hyperlegible Mono as one variable WOFF2 under `/assets/`, measured at 18 KB for the Latin subset (which covers Swedish) and 28 KB with Latin Extended. Regular and bold come from the same file.
- Every UI string in the mockups is plain English in sentence case and is meant to become a key in the English language pack (API-21).
