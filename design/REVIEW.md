# Review guide (answered)

Status: **answered by the owner on 2026-10-09.** Every question below keeps its original wording, followed by the owner's answer and what changed. The same decisions are summarized in the Decisions section of `README.md`, and the mockups already reflect them. Open the views from `mockups/index.html`; each page's "Mockup notes" drawer marks what was decided for that view and lists the questions that are still open.

## Questions and answers

1. **Density.** Rows are 28 px with 13 px text by default, with Dense (24 px) and Comfortable (34 px) one click away. Is compact the right default for daily use, or should dense be the default and compact the option?
   **Answered:** keep compact (28 px) as the default; dense and comfortable stay one click away (filter bar and account menu).

2. **The address treatment.** In the grid, the network part of each address is gray and the host part bold (`192.0.2.`**`41`**), and MACs gray their vendor part. Does it make scanning faster for you, or does it distract? Should IPv6 get the same treatment (prefix gray, interface identifier bold)?
   **Answered:** addresses and MACs render plain in the monospace font by default. The split becomes a per-user preference, "Emphasize host part", off by default (account menu, avatar top right). Applied to IPv4, IPv6 and MACs alike.

3. **Color only for exceptions.** A healthy grid is almost monochrome; color appears for conflicts, proposals, disagreements and failures. Is that calm enough to work in all day, or do you want the assignment modes to tint whole rows?
   **Answered:** stays as is (red conflict, magenta discovered, amber differs). "Adopt" stays.

4. **Accent and identifier font.** The accent is a bellflower blue-violet, and addresses use Atkinson Hyperlegible Mono, one embedded variable font of 18 KB, chosen because 0/O and 1/l/I cannot be confused. Keep both, or prefer the system monospace face and no font download at all?
   **Answered:** switch the identifier font to JetBrains Mono (embedded in the product, 31 KB for Latin; Google Fonts link in the mockups with the same offline fallback). Keep the accent.

5. **Where the move gesture lives.** Today: select rows, then drag them onto a network in the prefix tree, or press `M` (or "Move to network" in the action bar) and pick the network. Should drag stay the primary gesture, or should the action bar lead and drag be the power-user shortcut? Should dropping also work onto a network in the topology map?
   **Answered:** dragging onto the prefix tree is primary; `M` and the action bar remain. No drop target on the topology map.

6. **Preview: page or panel.** Dropping hosts opens the move preview as its own page (`move-job.html`). Would you rather have the preview as a wide panel over the grid, so the grid stays in view while you confirm?
   **Answered:** the preview stays its own page.

7. **Manual steps in phase 1.** Until Tenko runs DNS and DHCP itself, the reservation and DNS steps of a move are manual tasks. Show them per device in the preview, or as one grouped checklist for the whole job (as the mockup does)? And should a device wait until you have ticked its reservation and DNS tasks before Tenko changes its port or VLAN (the mockup assumes yes), or only warn?
   **Answered:** one grouped checklist for the whole job, as mocked, and a device waits for its ticked tasks before the L2 change. Added: a disabled "Create tickets" button (ticketing integration, later) that hints at a Jira-style connector.

8. **Move defaults.** Parallelism 2 and an observation timeout of 5 minutes. Right for a home network with dozens of IoT devices, or should the timeout be longer by default (some devices reconnect only every 10 to 15 minutes)? When it expires, should Tenko roll back by itself (as job #218 did) or always ask?
   **Answered:** roll back automatically on timeout. The default timeout is half the DHCP lease time of the target network (the renewal point, T1), never below 5 minutes, explained in the preview ("lease 24 h → timeout 12 h"). Parallelism 2 stays.

9. **Side panel versus full page.** The host side panel shows identity, mode, lock, disagreements, remote access and the latest history; the full page adds the complete history, ports and DNS records. Is that the right split? Is 460 px a good panel width on your screen?
   **Answered:** as mocked.

10. **Copying a password.** "Copy password" copies from the vault, clears the clipboard after 30 s and writes an audit entry, shown inline. Is that enough, or should a reveal require a fresh passkey check in Standard and Hardened?
    **Answered:** as mocked. Added a sign-in mockup (`mockups/signin.html`) whose notes record that single sign-on (SAML and OIDC: ADFS, Entra ID, Okta) comes later.

11. **VLAN colors on the map.** For color-blind safety only three VLANs are colored at once; a fourth (DMZ in the sample) is gray with a dashed outline and a tag. Acceptable, or would you rather pick which three VLANs get color?
    **Answered:** no fixed cap. The palette is generated for the VLANs in the current view: hues spread evenly across the OKLCH circle at a fixed lightness and chroma per theme, every color at least 3:1 against the map background, with labels on every edge group, a legend and a "Patterns" mode (dash styles) as redundancy. With 150 or more VLANs, color by selection or by site and keep the rest neutral (`README.md`, Charts and VLANs).

12. **Dashboard form.** Queries per second is a large number with a 60-second sparkline instead of a dial gauge, because a dial takes more room and is harder to read precisely. Agree?
    **Answered:** a number, never a dial. Large numbers use SI suffixes (1.2K, 48K, 1.3M) so a tile never grows, and the same formatter applies wherever numbers can grow (`tenko.si()` in `shell.js`).

13. **Home page and navigation.** The rail shows labels under the icons (72 px wide) and starts with Dashboard, which was not in the original list. Should the app open on the dashboard or on IPAM, and do you prefer labels or icons only (48 px)?
    **Answered:** the start page is the dashboard (the brand, the sign-in page and the wizard lead there). The rail keeps icons with labels (72 px).

14. **Status bar.** The bottom bar shows the live connection, the last event, running and waiting jobs and the selection count. Useful at a glance, or noise you would hide?
    **Answered:** the status bar stays.

15. **The mark.** Does the nine-tailed fox read as a fox at 16 px in the browser tab (see `logo/preview.html`)? One color everywhere, or the two-tone version (tails in the accent) on the sign-in screen and in the wizard?
    **Answered:** the fox is approved. The lockup keeps exactly the letterforms of the small 16 px header wordmark. The two-tone fox goes on the sign-in page and the wizard; one color everywhere else.

## Added by the owner during the review

16. **Wireless networks (SSIDs) are objects in IPAM**, read from UniFi with their VLAN mapping and shown under the network that carries their VLAN in the prefix tree (a row with a wifi glyph). A move of a wireless client offers "Move to SSID" (the SSID that carries the target VLAN) instead of a per-client VLAN override, and the topology map labels access points with their SSIDs. Applied to the IPAM tree, the move job and the topology map, and marked as the owner's request in their mockup notes.

## Deliberately left out

- **DNS and DHCP views** (zones, records, scopes, leases). They reuse the grid, filter bar, side panel and job panel shown in IPAM; DNS arrives in phase 2 and DHCP in phase 3.
- **Settings**: security toggles with deviation markers, connector setup (UniFi, Proxmox, Home Assistant), users, roles and API tokens, the audit log viewer, language packs.
- **CSV and Excel import** with column mapping (IPAM-11), and the spreadsheet round trip.
- **The reconciliation view** across the four sources of truth (IPAM-21, phase 3).
- **MFA prompts and single sign-on.** A sign-in page and an account menu now exist; MFA step-up and SSO (IAM-11) come later.
- **Ticketing.** The "Create tickets" button in the move job is a placeholder for a later connector.
- **Request and approval workflows** (IAM-02, phase 5) and the HTML5 RDP/SSH gateway (API-12).
- **Swedish text, right-to-left layout and language-pack upload.** All strings are English and written to become keys.
- **Narrow screens.** The mockups target desktop widths from 1280 px; narrower windows degrade, but no phone or tablet layout was designed.
- **Real behavior.** No virtualized grid, no real SSE, no API; the live flashes and countdowns are simulated, and nothing here is a performance measurement.
- **Exhaustive empty, loading and error states.** A few examples are shown where they matter (no lease, failed move, rotating disk); the rest follow the rules in `README.md`.
- **Accessibility testing.** The pages use semantic roles, visible focus and contrast-checked colors, but they have not been tested with a screen reader.
