# Tenko DDI design language

This folder is the Phase 1 design spike for the Tenko DDI user interface: a design language, a token file, a logo, and clickable HTML mockups of the core views. It exists so the owner can review the look and the interaction model before any SolidJS component is written. Nothing here is product code. The SolidJS UI will take over the tokens and the component inventory, not the markup.

Start with [`mockups/index.html`](mockups/index.html). The owner has reviewed the mockups: the answers are in [`REVIEW.md`](REVIEW.md) and summarized under [Decisions](#decisions) below; the rest of this document already reflects them.

## How to open

Double-click `mockups/index.html`. Every page is static HTML, CSS and a little plain JavaScript, with no build step and no framework. Each page loads three local files (`../tokens.css`, `shell.css`, `shell.js`) and one stylesheet from Google Fonts for the identifier face (JetBrains Mono). Offline, the pages fall back to the platform monospace face and still work. The product will not call Google: it embeds the font file (SIL Open Font License) in the binary next to the UI bundle, served from `/assets/` like every other asset (ADR 0008).

Theme, density and the "Emphasize host part" preference are remembered per browser in `localStorage` (`tenko-theme`, `tenko-density`, `tenko-emphasize`) and can all be changed in the account menu (the AK avatar, top right); the theme button in the top bar also cycles system, light, dark. Every mockup has a collapsed "Mockup notes" drawer, opened from the right end of the status bar (from the header in the wizard and on the sign-in page), with the decisions and open questions for that view, and an "All mockups" link back to the index. Some have a dashed "Mockup scene" switcher to show states that would otherwise need live data. Dashed borders always mean mockup-only, never product UI.

## Principles

1. **Speed and density first.** Compact 28 px rows by default, 13 px text, no hero banners. The screen is for data, not chrome. Every view must render its first useful rows before anything else is fetched.
2. **Anything in three clicks or one keystroke.** Ctrl+K finds any address, host, MAC, prefix, record or command. `g` chords jump between areas. The palette shows each command's shortcut, so it is also where shortcuts are learned.
3. **Keyboard first, mouse equal.** Grids have a cell focus ring, Space selects, Enter edits, Esc backs out. Every drag gesture has a keyboard twin (`M` for move to network).
4. **Nothing happens silently.** Every change is a job with a preview, visible steps, a state and a way back. Background work never takes over the screen. Live changes arrive as a short flash on the cell that changed.
5. **Dark and light with equal care.** Both themes are designed, not inverted. Each has its own validated steps for state and chart colors.
6. **Color is for exceptions.** A healthy grid is calm and almost monochrome. Color appears where a person must act (conflict, proposal, intent and observation disagree, failed job) and for the accent (selection, focus, primary action). State never relies on color alone: it always has a glyph and a word.

## Decisions

The owner reviewed all mockups on 2026-10-09 and answered the review guide. These decisions are applied everywhere in this folder.

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

## Visual direction

**Type.** The interface text uses the platform face (Segoe UI Variable on Windows 11, SF on macOS, the system sans elsewhere): zero bytes, native rendering, instant first paint. Identifiers (addresses, MACs, prefixes, DUIDs, ports) use one embedded monospace face, **JetBrains Mono**: wide, open shapes with clear 0 and O, 1, l and I, which matters in a product where a misread MAC or address is a real outage. Its code ligatures are switched off everywhere (`font-variant-ligatures: no-contextual` on the root, `none` on identifiers), so the `::` of an IPv6 address always shows as two colons.

**The address treatment.** Addresses and MACs render plain in the data font by default, one color and one weight. The markup always carries the split (network part and host part of an address, vendor part of a MAC), so the per-user preference "Emphasize host part" in the account menu can gray the network part and set the host part in bold (`192.0.2.`**`41`**), and gray a MAC's vendor part. The same applies to IPv6 (prefix and interface identifier).

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

VLAN identity is generated, not fixed. The VLANs visible in a view get hues spread evenly around the OKLCH circle, starting at `--vlan-h0` (255), at one lightness and chroma per theme (`--vlan-l` and `--vlan-c`: 0.58 and 0.14 in light, 0.70 and 0.13 in dark). Chroma is reduced only where a hue would leave sRGB, and lightness is nudged until each color has at least 3:1 against the map background; with these values every color measures at least 4:1 on the light map and 6:1 on the dark one, for any number of VLANs from 1 to 24. `tenko.vlanPalette(n)` in `mockups/shell.js` implements the rule, and `--vlan-lan`, `--vlan-lab`, `--vlan-iot` and `--vlan-dmz` in `tokens.css` are its four-VLAN instance. Hue alone cannot separate many VLANs for every reader, so color is never alone: every edge group carries a VLAN label, the legend lists the VLANs in view with their swatches, and a "Patterns" mode adds a dash style per VLAN.

With 150 or more VLANs no palette stays readable, so color follows attention: color by selection (the VLANs you pick in the filter are colored, all others neutral gray) or color by site (sites get the hues, VLANs stay neutral), with search and focus mode to reduce the view first. Labels and patterns work at any count.

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
| Prefix tree | `.tree`, `.tnode` | Tenant and VRF, supernet, prefix, range; wireless networks (SSIDs, `.tnode.ssid` with a wifi glyph) under the network that carries their VLAN; utilization meter per prefix; drop target state while dragging (a prefix or an SSID). |
| Selection action bar | `.actionbar` | Appears with a selection: Move to network, Set mode, Lock, Export CSV, each with its key. |
| Side panel | `.panel` | Docked over the grid on the right; the full-page view of the same object uses the same sections. |
| Job panel | `.jstate` plus the move-job mockup | Per-item state with glyph and word, step list, countdown while waiting for observation, failure reason and Roll back. |
| Toast | `.toasts`, `.toast` | Result of an action with Undo or Open job. Auto-dismisses unless it reports a failure. |
| Command palette | `#palette` (shell.js) | One field for addresses, hosts, MACs, prefixes and commands; `>` limits to commands. |
| Account menu | `.acct` (shell.js) | Opens from the avatar: theme, row density, "Emphasize host part", keyboard shortcuts, sign out. |
| Number formatter | `tenko.si()`, `data-si` (shell.js) | 982, 1.2K, 48K, 1.3M: at most three significant digits so tiles and cells never grow; the exact value goes into the title. |
| Wizard and sign-in | wizard and sign-in mockups | Focused pages without the rail; the two-tone mark. The wizard has numbered steps on the left and one card on the right; sign-in is passkey first. |
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
- **Numbers never resize their container.** Counts that can grow use SI suffixes with at most three significant digits (1.2K, 48K, 1.3M), with the exact value on hover. Queries per second is a number, never a dial.
- **Moves wait for the network, then clean up after themselves.** A move waits for each device up to half the target network's DHCP lease (never less than 5 minutes) and rolls back automatically on timeout. Other failures wait for a decision (Retry or Roll back).
- **Insecure state is loud.** The Lab profile and any setting weaker than the Home profile show a persistent banner.

## The mark

The Tenko mark is a nine-tailed fox, the form a tenko takes. A geometric fox head, seven points with two ears and a pointed chin, sits in front of nine tails that fan out behind it. The tails rise from a point just behind the chin, at 25-degree steps from -100 to +100 degrees, and each one flicks its tip outward, so the silhouette reads as a fox spreading its tails, not as a flower or a sun. It is built on a 48-unit grid: the fan center is at (24, 33), the tails end on circles of radius 22 at the sides and 24 at the top, and a 1.5-unit knockout separates the head from the tails so the mark works in a single color. It is drawn in `currentColor` and follows the theme. The two-tone variant colors only the tails with the accent and is used on the sign-in page and in the first-run wizard; everywhere else the mark is one color. Below 24 px the small cut drops the eyes and widens the knockout to 1.9 units; the favicon uses that cut and switches between ink and light ink with the system theme. Clear space: keep x on every side, where x is half the width of the head (9 units, about a fifth of the mark's height). Minimum sizes are 16 px for the mark and 88 px wide for the lockup. The wordmark "Tenko" is drawn as monoline strokes on the same grid, with "DDI" set in the x-height in a lighter stroke, so the lockup needs no font file; its letterforms are fixed as the ones in the 16 px header wordmark of every page. See [`logo/preview.html`](logo/preview.html) for every variant at 16, 32 and 128 px on light and dark, the construction grid and the rules for use.

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
| `mockups/signin.html` | Sign-in (passkey first), with the two-tone mark |

## Notes for the SolidJS implementation

- `tokens.css` can be imported as is. Components should reference roles (`var(--surface)`, `var(--mode-reserved)`), never hex values.
- The grid needs virtualized rows. The cell focus model (row index, column index) and the selection model (set of ids plus an anchor) are separate state, as in the mockup script.
- The icon sprite in `shell.js` is a 16-unit stroke set; it becomes one inline sprite in the bundle.
- The font is the only binary asset besides the mark: JetBrains Mono as one variable WOFF2 under `/assets/`, measured at 31 KB for the Latin subset (which covers Swedish) and 43 KB with Latin Extended. Regular and bold come from the same file.
- Every UI string in the mockups is plain English in sentence case and is meant to become a key in the English language pack (API-21).
