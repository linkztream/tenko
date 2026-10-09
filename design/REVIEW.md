# Review guide

Open `mockups/index.html` and work through the six views in order. Each page has a "Mockup notes" button at the right end of the status bar with the questions for that view; the list below is the short version, the decisions that shape the SolidJS work. A one-word answer is fine for most of them.

## Questions for the owner

1. **Density.** Rows are 28 px with 13 px text by default, with Dense (24 px) and Comfortable (34 px) one click away. Is compact the right default for daily use, or should dense be the default and compact the option?
2. **The address treatment.** In the grid, the network part of each address is gray and the host part bold (`192.0.2.`**`41`**), and MACs gray their vendor part. Does it make scanning faster for you, or does it distract? Should IPv6 get the same treatment (prefix gray, interface identifier bold)?
3. **Color only for exceptions.** A healthy grid is almost monochrome; color appears for conflicts, proposals, disagreements and failures. Is that calm enough to work in all day, or do you want the assignment modes to tint whole rows?
4. **Accent and identifier font.** The accent is a bellflower blue-violet, and addresses use Atkinson Hyperlegible Mono, one embedded variable font of 18 KB, chosen because 0/O and 1/l/I cannot be confused. Keep both, or prefer the system monospace face and no font download at all?
5. **Where the move gesture lives.** Today: select rows, then drag them onto a network in the prefix tree, or press `M` (or "Move to network" in the action bar) and pick the network. Should drag stay the primary gesture, or should the action bar lead and drag be the power-user shortcut? Should dropping also work onto a network in the topology map?
6. **Preview: page or panel.** Dropping hosts opens the move preview as its own page (`move-job.html`). Would you rather have the preview as a wide panel over the grid, so the grid stays in view while you confirm?
7. **Manual steps in phase 1.** Until Tenko runs DNS and DHCP itself, the reservation and DNS steps of a move are manual tasks. Show them per device in the preview, or as one grouped checklist for the whole job (as the mockup does)? And should a device wait until you have ticked its reservation and DNS tasks before Tenko changes its port or VLAN (the mockup assumes yes), or only warn?
8. **Move defaults.** Parallelism 2 and an observation timeout of 5 minutes. Right for a home network with dozens of IoT devices, or should the timeout be longer by default (some devices reconnect only every 10 to 15 minutes)? When it expires, should Tenko roll back by itself (as job #218 did) or always ask?
9. **Side panel versus full page.** The host side panel shows identity, mode, lock, disagreements, remote access and the latest history; the full page adds the complete history, ports and DNS records. Is that the right split? Is 460 px a good panel width on your screen?
10. **Copying a password.** "Copy password" copies from the vault, clears the clipboard after 30 s and writes an audit entry, shown inline. Is that enough, or should a reveal require a fresh passkey check in Standard and Hardened?
11. **VLAN colors on the map.** For color-blind safety only three VLANs are colored at once; a fourth (DMZ in the sample) is gray with a dashed outline and a tag. Acceptable, or would you rather pick which three VLANs get color?
12. **Dashboard form.** Queries per second is a large number with a 60-second sparkline instead of a dial gauge, because a dial takes more room and is harder to read precisely. Agree?
13. **Home page and navigation.** The rail shows labels under the icons (72 px wide) and starts with Dashboard, which was not in the original list. Should the app open on the dashboard or on IPAM, and do you prefer labels or icons only (48 px)?
14. **Status bar.** The bottom bar shows the live connection, the last event, running and waiting jobs and the selection count. Useful at a glance, or noise you would hide?
15. **The mark.** Does the nine-tailed fox read as a fox at 16 px in the browser tab (see `logo/preview.html`)? One color everywhere, or the two-tone version (tails in the accent) on the sign-in screen and in the wizard?

## Deliberately left out

- **DNS and DHCP views** (zones, records, scopes, leases). They reuse the grid, filter bar, side panel and job panel shown in IPAM; DNS arrives in phase 2 and DHCP in phase 3.
- **Settings**: security toggles with deviation markers, connector setup (UniFi, Proxmox, Home Assistant), users, roles and API tokens, the audit log viewer, language packs.
- **CSV and Excel import** with column mapping (IPAM-11), and the spreadsheet round trip.
- **The reconciliation view** across the four sources of truth (IPAM-21, phase 3).
- **Sign-in, MFA prompts and the account menu.**
- **Request and approval workflows** (IAM-02, phase 5) and the HTML5 RDP/SSH gateway (API-12).
- **Swedish text, right-to-left layout and language-pack upload.** All strings are English and written to become keys.
- **Narrow screens.** The mockups target desktop widths from 1280 px; narrower windows degrade, but no phone or tablet layout was designed.
- **Real behavior.** No virtualized grid, no real SSE, no API; the live flashes and countdowns are simulated, and nothing here is a performance measurement.
- **Exhaustive empty, loading and error states.** A few examples are shown where they matter (no lease, failed move, rotating disk); the rest follow the rules in `README.md`.
- **Accessibility testing.** The pages use semantic roles, visible focus and contrast-checked colors, but they have not been tested with a screen reader.
