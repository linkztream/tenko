# Windows takeover plan: DNS zones and DHCP off the domain controllers, step by step and reversible

- Status: Accepted on 2026-11-01 for the decisions of section 6 that the owner took that day (WT-Q1 to WT-Q7); WT-Q8 to WT-Q12 decided by the owner on 2026-11-05 as recommended. On 2026-11-05 the owner also reordered what follows the slice: the Kerberos line of Slice 13 (WP13.0 to WP13.4 of [identity-plan.md](identity-plan.md)) runs before the real cutover, which then happens under Hardened from its first day (WT-Q5 and WT-Q7, amended). Amended on 2026-11-20: the reference domain runs DNS and DHCP on both controllers with a DHCP failover relationship in load balance, confirmed by the owner (section 2.15); the DHCP servers' DNS credential is one dedicated unprivileged user (WT-Q13, decided 2026-11-20); and the rehearsal moves from the owner's afternoon to a second line of the Windows lab run by an operator, an inside observer and the lead, reading only the lab domain (section 2.13, WT-Q6 amended, WT-Q14, decided 2026-11-20). Amended again on 2026-11-20 by the owner's decision that one script, run by the administrator on a domain-joined Windows machine and approved by a signed-in person in Tenko's UI, drives the takeover (section 2.16, ADR 0038 proposed, WT-Q15 to WT-Q17 open). The plan binds and changes only through rule 2.8 of the execution plan. The owner's standing direction, single node first and cluster-aware (section 2.10 of [phase-2-plan.md](phase-2-plan.md)), binds this work; section 2.14 says how
- Date: 2026-11-01
- Scope: Slice 14, Phase 4's first slice. An operator moves the DNS zones and the DHCP service of a small Active Directory domain from the domain controllers to Tenko with no client noticing, each step reversible, rehearsed first in the Windows lab. DNS data arrives by zone transfer; DHCP data arrives by a mirror that a scheduled script on each DHCP server pushes to Tenko's API; a takeover action per scope turns the mirror into Tenko's own leases and records. Written against `main` at `8e4f4112`. Requirement IDs refer to [REQUIREMENTS.md](../REQUIREMENTS.md), toggles (TGL) to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md). Exit criteria, measurements and risks continue the project's series: E72 onward, M69 onward and R137 onward (the high-availability plan ends at E71 and M68, the identity plan at R136; the amendment of 2026-11-20 takes R217 to R219, the next free numbers; the script's amendment takes E144 to E146, M93 and R220 to R224)

This plan follows the shape of [identity-plan.md](identity-plan.md): the goal and the exit criteria as checks, one slice, the design decisions the packages share, the contracts, the work packages with owners and acceptance, the order, the measurements, the owner's decisions, the risks and the owner's actions. "(proposed)" marks a choice the documents leave open. Sizes are in builder-days. Two records need an ADR (the lead numbers them; 0032 and 0033 are the next free numbers): the mirrored source kind with its push, its token scope and its trust rules (sections 2.1 to 2.4), and the flip of a zone with the takeover's adoption rule (sections 2.6 to 2.8). WP14.0 writes both as Proposed.

Contents:

1. [Scope and exit](#1-scope-and-exit)
2. [Design decisions the packages share](#2-design-decisions-the-packages-share)
3. [Contracts and shared files (WP14.0)](#3-contracts-and-shared-files-wp140)
4. [Work packages](#4-work-packages)
5. [Order, measurements and exit checks](#5-order-measurements-and-exit-checks)
6. [Owner decisions](#6-owner-decisions)
7. [Requirement rows touched](#7-requirement-rows-touched)
8. [Risks](#8-risks)
9. [Owner actions](#9-owner-actions)
10. [Documents this slice writes](#10-documents-this-slice-writes)
11. [Sources](#11-sources)

## 1. Scope and exit

### 1.1 Goal

**The domain this is for.** The reference domain is small and common: one zone for everything (the AD domain zone is also the zone of the clients, with about sixty names registered by Windows DHCP, each with a DHCID record because name protection and aging are on), `_msdcs` as a zone of its own, AD-integrated storage, two controllers that both run the DNS Server and the DHCP Server role, reverse zones, conditional forwarders, one scope over the whole client network served by both DHCP servers through one failover relationship (load balance assumed; section 2.15 says what differs for hot standby and for split scopes), about thirty reservations with mixed naming, no DHCP policies, no IPv6, and fewer than five domain-joined Windows machines whose own DNS registration is switched off per machine by a registry value. Every name and address in this plan is a placeholder as in [active-directory.md](../active-directory.md): `corp.example.test`, `_msdcs.corp.example.test`, `dc1` and `dc2` at `192.0.2.5` and `192.0.2.6`, `tenko1` at `192.0.2.53`, the client network `192.0.2.0/24` with its reverse zone `2.0.192.in-addr.arpa`.

**What changes.** Today's runbook ([active-directory.md](../active-directory.md), steps 1 to 11) copies the zones once by transfer, exports and re-imports them as `manual` records, builds the DHCP scope by hand from `Export-DhcpServer`, and before the DHCP switch deletes every record Windows DHCP wrote (step 10), so that each client is without a name until it renews. This slice replaces the copies by live feeds and the deletion by an adoption:

1. **DNS by transfer, kept live.** Tenko is a secondary of every AD zone (AXFR and IXFR with NOTIFY from the controllers) until the operator flips a zone. The flip turns the secondary into a primary in place and keeps every record with its provenance (section 2.6); the controllers then hold their copies as secondaries of Tenko.
2. **DHCP by a mirror.** A static PowerShell script, scheduled every 60 s on each controller that runs DHCP (one mirror per server, section 2.15) under an account that can only read DHCP, reads the scopes, the options at every level, the reservations and the active leases, turns them into the source-neutral intermediate representation (IR) of [MIGRATION.md](../MIGRATION.md) and pushes it to Tenko's API over HTTPS with a token that can do nothing but write that one mirror. Tenko never holds a Windows credential and never connects to Windows.
3. **A takeover per scope.** In the UI and the CLI, one action converts the mirrored leases to Tenko leases with their remaining time, adopts the A, DHCID and PTR records of the mirrored leases and reservations as Tenko DHCP's own (with Tenko's DHCID; the proof is the mirrored lease or reservation, not a renewal), activates the Tenko scope and records what it did. The reverse action deactivates the Tenko scope and leaves the records; the operator activates the Windows scope again.
4. **One script drives it** (amended 2026-11-20, section 2.16). The administrator runs `Tenko-Takeover.ps1` from the release on a domain-joined machine; it discovers the domain, shows what it will change, does the Windows side with the credential it asks for and the Tenko side through a session a signed-in person approves in the UI with a code. The person starts the window in the UI after reviewing what was found.
5. **A rehearsal first.** Step 0 of the runbook is a second line of the Windows lab ([`deploy/compose/lab-ad/windows/takeover/`](../../deploy/compose/lab-ad/windows/takeover/README.md)): both lab controllers with Windows DNS and Windows DHCP in a failover relationship, a Windows client on a DHCP reservation, and the lab's Tenko node serving nothing until the takeover, run by the lab's operator, an inside observer on the admin workstation and the lead (section 2.13).

**What stays.** The controllers stay controllers, Tenko joins nothing and holds no directory data (CON-11). Under the Home profile the controllers register their locator records by unsigned RFC 2136 updates accepted by address (today's footing, section 4 of the runbook); the Hardened profile becomes possible with GSS-TSIG in Slice 13 ([identity-plan.md](identity-plan.md) WP13.0 to WP13.4), which stays as planned and follows this slice. Nothing in the core assumes Windows: the mirror is a source kind that any adapter can feed with the same IR (Kea, BIND, dnsmasq and OPNsense adapters are its siblings), and the takeover acts on the IR and on records, never on Windows. Active Directory integration is always an option, never a requirement.

### 1.2 Exit criteria

| # | Check | Requirements | Package |
|---|---|---|---|
| E72 | The exporter: on PowerShell 5.1 (a hosted Windows runner) and 7 (Linux and Windows runners), the Pester suite over recorded cmdlet output with documentation addresses produces the fixture IR byte for byte, puts every policy, filter, superscope, failover relationship and scope delay in the loss report with its source location, refuses to start as a member of a privileged group, and `-Once` prints the IR and the loss report without pushing; PSScriptAnalyzer reports nothing above its rule file; the install script registers the task under the given account and stores the token with DPAPI for that account only | MIG-01, MIG-08 | WP14.1 |
| E73 | The push: a push with the mirror's token is accepted, an unchanged push writes nothing to the store and no audit record, a changed one writes one snapshot row and one `migrate.mirror.push`; the token is refused on every other operation of the OpenAPI document (403) and on another mirror's push; an older sequence (409), a body above the bound (413), an IR that does not validate (422 with the path of the first error) and a push faster than the floor (429) are refused and audited at most once a minute; the mirror card shows its freshness and turns stale after three missed intervals with the finding `migrate.mirror.stale` | MIG-01, IAM-10 | WP14.1 |
| E74 | The diff and the prepare: from the fixture snapshot, the diff lists every difference against Tenko's scopes by kind, and for a paired mirror every difference between the two partners' configurations (section 2.15) as a row the operator decides; the prepare job creates a disabled scope whose pool, exclusions, options at server, scope and reservation level, reservations (with the name rule of section 2.9) and DDNS settings equal the mirror's, attaches to IPAM hosts that already hold a reservation's MAC or address instead of duplicating them, and a second prepare changes nothing; every loss entry must be acknowledged before the prepare runs | MIG-08, MIG-03 (partly) | WP14.1, WP14.2 |
| E75 | The flip: a secondary holding the fixture AD zones (the domain zone with sixty DHCP names, `_msdcs`, the reverse zone) flips to primary in place with the origins of section 2.6; an unsigned update from the controllers' access list changes a locator record; an update of a frozen DHCP name is refused and audited; the reverse flip makes it a secondary again and the next transfer replaces its records; `release` turns the remaining frozen names into `manual` records | MIG-04 | WP14.2 |
| E76 | The takeover in the DHCP lab: with the fixture mirrors of both partners and the flipped zones, the job refuses while either mirror is stale or shows the scope active, waits for a push of each that shows the source's scope inactive, adopts the union of their leases by the rule of section 2.15 (a lease conflict between the two is skipped and reported) and every mirrored lease with its remaining time and every name of section 2.8 as `dhcp` records with Tenko's DHCID, enables the scope and writes `dhcp.scope.takeover` with its counts; a client of each identity kind (option 61 of type 1, no option 61, an RFC 4361 DUID) renews and rebinds and keeps its address and its name, also when the identity guessed at adoption was wrong; a client with another MAC that claims an adopted name or address is refused; INIT-REBOOT of an adopted client is answered; the reverse action disables the scope and leaves leases and records; a failed job rolls back to the state before it | MIG-04, MIG-08, DHCP-13 | WP14.2 |
| E77 | The rehearsal in the Windows lab's takeover line (run by the operator, the inside observer and the lead; [the line's manifest](../../deploy/compose/lab-ad/windows/takeover/README.md)): from the Windows-first start state with DNS and DHCP on both controllers in a failover relationship, the full runbook from step 1 to the end of the parallel period, then the reverse of each phase and the way forward again; the Windows client keeps its address, its name and its domain logon through every step (`ipconfig /all`, `nltest /dsgetdc:corp.example.test /force`, `Resolve-DnsName`), with no NAK in Tenko's counters; the DHCID identifier type Windows DHCP uses is recorded from the lab's records; every entry of the manifest has its evidence filed | MIG-17, API-18 (partly) | WP14.4 (lab) |
| E78 | The security rows `ad.*` of the round `security` ([security-audit-plan.md](security-audit-plan.md) section 4.2) pass on the release binary: spoofed and unlisted updates, a transfer from a disallowed address, a DHCID takeover from the wrong client, the mirror token's scope | TGL-09, IAM-10 | WP14.4 |
| E79 | The runbook: [active-directory.md](../active-directory.md) rewritten around the mirror and followed end to end in the rehearsal; [dns.md](../dns.md) section 13.9 states the profiles correctly; [MIGRATION.md](../MIGRATION.md) says that the Windows DHCP source is the pushed mirror | MIG-17 | WP14.3 |
| E80 | M69 and M70 measured on the musl binary and recorded in `bench/phase4-takeover/results/` | API-17 | WP14.2 |
| E80a | The cut-over of all four networks of the reference home-lab environment (owner-run, the real cutover of section 1.3, on the first 0.1 release that carries Slice 14 complete): the gateway relays each network to one Tenko node, giaddr and option 82 select the scope, clients keep their addresses across the switch, option 6 and option 42 reach them, and the rollback is one setting on the gateway; the runbook is [dhcp.md](../dhcp.md) section 17, whose rows are ticked for each network. Moved here from the Phase 3 exit (E23 of [phase-3-exit.md](phase-3-exit.md)) by the owner's decision of 2026-11-20: the networks' DHCP and DNS are integrated with Active Directory, so the cut-over needs this slice | DHCP-01, DHCP-02, DHCP-04, DHCP-15 | Owner-run |
| E144 | The script: on Windows PowerShell 5.1, the Pester suites over recorded cmdlet output and a mocked API run every phase forward, again (nothing changes), and back with `-Reverse`; a failure injected at each step stops with exit 2 and resumes; for each value of section 2.16.3, an answer that Windows contradicts stops with exit 4 and changes nothing further; an answer holding control characters prints none; the code test finds no `Invoke-Expression`, no script block made from text and no command line built from a value; the state file of every phase holds no secret; `-DryRun` changes nothing and contacts no Tenko; the release ships the three scripts signed (WT-Q15), in `SHA256SUMS` and attested, and the script refuses an exporter whose digest differs | MIG-17, MIG-08 | WP14.5 |
| E145 | The approval: a script's code matches only over the root the node serves (a test with a second root computes another code); collecting needs the key's signature and works once; the delegated session reaches every operation of section 2.16.2's set for the plan's objects and 403 `auth.delegation.refused` on every other operation of the OpenAPI document and on every object outside the plan; it reaches the flip and the takeover only after the window started; it can never start the window, approve, or reach the token API; a personal token is still refused by the flip, the takeover and the window; the session ends at revocation, abort, the run's end and its lifetime; every action is audited with the run; under Hardened the approval and the window need a passkey sign-in within five minutes | IAM-10, TGL-03, TGL-04 | WP14.6 |
| E146 | Usability: in the rehearsal (the takeover line's phase 6), with the script's README and the UI only, the takeover of the lab domain, the finish included, takes at most 10 Windows actions, 5 Tenko actions and 3 typed values, and the full reverse at most 5 and 2; the observer records actions, values, pages and wrong turns per phase, and every wrong turn is a finding for WP14.5 or WP14.6 | MIG-17 | WP14.4 |

### 1.3 The slice

| Slice | Content | Closes |
|---|---|---|
| 14. The Windows takeover | The contracts and two ADRs; the exporter script and its scheduled task; the mirrored source with its push, freshness, diff and loss report; the flip of a zone and its reverse; the prepare, the takeover and the reverse of a scope; the runbook around the mirror; the takeover script with its approval and its run page (section 2.16); the security rows; the rehearsal | E72 to E80, E144 to E146 |

After this slice, in the owner's order (WT-Q7 as amended on 2026-11-05): the Kerberos line of Slice 13 (WP13.0 to WP13.4), with the Windows lab as its interop lab; then the real cutover at home with the runbook, under Hardened from the first day; then the rest of Slice 13.

### 1.4 Requirements

| Requirement | What this slice delivers | Phase today |
|---|---|---|
| MIG-08 Windows DHCP source | Partly: scopes, pools, exclusions, options at every level, reservations, DNS settings and active leases by the pushed mirror; policies, filters, superscopes and failover relationships to the loss report (WT-Q2) | 4, Must |
| MIG-04 Coexistence modes | Partly: secondary (exists) and flip, in place and reversible, for DNS; the per-scope takeover as the flip of DHCP. Forward mode exists as forwarding rules and is not touched; the nightly parity diff is left out (section 1.6) | 4, Must |
| MIG-17 Runbooks | The Windows DNS and DHCP runbook, validated in the rehearsal | 4, Must |
| MIG-01 IR and loss report | The exporter is an adapter that produces `DhcpIr` and a `LossReport`; the core consumes nothing else | 4, Must |
| MIG-02 AXFR as the baseline | Used as is for every AD zone | 4, Must |
| MIG-03 The pipeline | Partly: the prepare and the takeover run as jobs with steps and rollback (IPAM-17); `tenko migrate plan`, `apply` and `verify` as commands are not built here | 4, Must |
| API-18 Windows interop lab | Partly: the Windows lab's takeover line; GSS-TSIG and the full MIG-18 domain stay with Slice 13 and later | 4, Must |
| CONN-12 External DHCP actuator | Explicitly not: Tenko writes nothing to Windows; the takeover script deactivates and activates the Windows scope with the administrator's credential (section 2.16) | 4, Should |
| CONN-13, DNS-28, DNS-29, DNS-30, MIG-06, MIG-18 | Not here: CONN-13 and DNS-28 with Slice 13 and the actuator package; DNS-29 (aging) is why frozen names are released by hand (section 2.6); MIG-06's LDAP read and MIG-18's domain are later | 4 |
| DHCP-13 DDNS, TGL-09, TGL-29 | Used: adopted records are DDNS records from then on; the profile rules of [dhcp.md](../dhcp.md) section 13.1 and [dns.md](../dns.md) section 13.2 apply unchanged | 3, delivered |
| IAM-10 Scoped tokens | A new special scope `mirror:<id>` (section 2.1) | 1, delivered |

### 1.5 Carried items

| Item | Where |
|---|---|
| Phase 2 exit deviation 108 and E15: the Windows half of the transfer check was never run by the owner | E77, the rehearsal |
| [active-directory.md](../active-directory.md) step 10: delete the records Windows DHCP wrote before the switch | Replaced by the takeover (section 2.8, WT-Q3) |
| [dns.md](../dns.md) section 13.9 says unsigned updates work only in Lab, while section 13.2, the code (`update/policy.rs`, `require_tsig()`) and the runbook say Home and Standard too | WP14.3 |
| [dns.md](../dns.md) section 1: "the name and the kind do not change"; a secondary cannot become a primary | WP14.2: the flip |
| [MIGRATION.md](../MIGRATION.md) names PowerShell remoting for `tenko-connect-windows`; WT-Q1 rules it out for this source | WP14.3 |
| [MIGRATION.md](../MIGRATION.md) and [dhcp-contracts.md](../dhcp-contracts.md) line 250: the "offer delay on the Tenko scope" does not exist | The loss report keeps `Delay`; the runbook does not use split scopes (section 2.7) |
| [identity-plan.md](identity-plan.md) section 3.9: WP13.4 rewrites sections 4 to 6 of the runbook for GSS-TSIG | WP13.4 wrote the GSS-TSIG runbook first (on 2026-11-10, with the zones imported from the Windows export); WP14.3 adds the mirror and the flip on top of it |
| The `Ad` variant of `Origin`, set by nothing (identity plan section 1.5) | The flip sets it (section 2.6), in the meaning identity plan section 3.6 gives it |

### 1.6 Left out, with reasons

| Item | Reason | Goes to |
|---|---|---|
| WinRM, PowerShell remoting or any Tenko connection to Windows | WT-Q1: it needs Kerberos or NTLM credentials in Tenko and a channel through which Tenko's wishes run on a controller. The takeover script uses WinRM from the administrator's machine with the administrator's credential, never from Tenko (section 2.16) | Not built for this source |
| The Windows credential entered into Tenko, the server managing Windows remotely | Set aside by the owner on 2026-11-20: a compromised node would hold a domain administrator's credential | Not built |
| Writing to Windows DHCP or Windows DNS from Tenko (CONN-12, CONN-13) | WT-Q1 and ADR 0023's boundary; the takeover script writes to Windows with the administrator's credential, and Tenko writes nothing there | The actuator package, if ever |
| A proof of the script's key on every request (RFC 9449) | The delegated session's secret lives only in the memory of the process that holds the key and the domain credential; whoever reads that memory has the credential too | Later, if the session is ever used elsewhere |
| A KDS root key created by the script | A forest-wide change that needs Enterprise Admins and ten hours before first use; the script takes a user account where none exists | Not needed |
| The gateway's relay changed by the script | The script reaches Windows and Tenko only; it names the change and waits for the person | The gateway's own connector, if ever |
| A Windows DNS adapter (MIG-06, MIG-07): owner SIDs, aging timestamps, server settings | The transfer carries the records; ownership waits for GSS-TSIG, aging for DNS-29; the forwarders are entered by hand (a handful) | Phase 4, later packages |
| Policies, filters, superscopes | WT-Q2: to the loss report; the reference domain has none | MIG-08's remainder |
| A Windows failover relationship as a Tenko pair (ADR 0025 decision 13) | The relationship goes to the loss report, and the takeover reads both partners' mirrors (section 2.15); a Tenko DHCP pair is Phase 5 | Slice 12, Phase 5 |
| Split scopes during coexistence | The takeover is a clean switch per scope; Tenko has no offer delay; Tenko beside Windows on one network is what the runbook avoids (a Windows split-scope pair as the source is section 2.15) | Not needed |
| The nightly parity diff of MIG-04 and query replay (MIG-05) | In secondary mode Tenko's copy is the transfer itself; the serials and the diff view are the check | MIG-05's package |
| A reconciler view of the mirrored leases | ADR 0031: no fact rows per lease; a view like `LeaseFacts` over the snapshot is a small follow-up once the slice stands | Later |
| A Tenko DHCP pair, a second DNS node | Single node first; the controllers' secondary copies stand in for a second primary (R143) | Slice 12, Phase 5 |
| DHCPv6 in the mirror | The reference domain has no IPv6; `Get-DhcpServerv6*` maps onto the same IR later | MIG-08's remainder |

### 1.7 Starting point in the code

Facts the packages build on, read on `8e4f4112` (the two research notes of 2026-11-01 checked them in code; nothing was run):

- **The IR** (`crates/tenko-core/src/ir.rs`, `ir/dhcp.rs`). `DhcpIr { server_options, option_defs, classes, scopes, superscopes, policies, filters, failover, leases }`; `IrScope { cidr, name, description, active, lease_secs, ranges, exclusions, reservations, options, ddns: Option<DdnsPolicy>, superscope, restricted, delay_ms, origin }`; `IrReservation { ip, client: IrClientId { mac, client_id }, name: Option<HostName>, bootp, options, .. }`; `IrLease { ip, scope, client, hostname, expires, state: IrLeaseState { Active, ActiveReservation, Declined, Expired, Other }, origin }`; `SourceLocation { sheet, row, column }`. `HostName` takes one or more labels, so a fully qualified name fits. No consumer of `DhcpIr` exists; the Windows XML mapping is a written specification ([dhcp-contracts.md](../dhcp-contracts.md) section 11).
- **Connectors** (`crates/tenko-connect`). `MigrationSource` (`migration.rs`) and the plugin host (`host/`, ADR 0012) are pull-based: `ConnectorInstance { plugin, settings, secrets, poll_interval_secs (60 to 86,400), writes_enabled, .. }`. `tenko-connect-windows` and `tenko-migrate` are placeholders of about 25 lines.
- **Tokens** (`crates/tenko-auth/src/model.rs`). `ScopedTokenRecord { owner, grants: Vec<TokenGrant>, scopes: Vec<TokenScope>, expires_at, .. }`; `TokenScope` is a `Copy` enum with `metrics` and `audit:read`; the right of a request is the intersection of the token's grants and its owner's; TGL-05 caps the lifetime (Home 365 days).
- **Secondary zones** (`crates/tenko-dns/src/xfr/in.rs`, `zone/secondary.rs`). AXFR and IXFR in, NOTIFY accepted only from the configured primary's address; the copy is written with the origin `transfer`; a secondary is read only (409 `dns.zone.secondary`), and the same code refuses a write to a `transfer` RRset in a primary zone ([dns.md](../dns.md) section 10.7). Transfers out need `transfer.allow` and, for Windows, `transfer.require_tsig = false`, per zone with no profile override (`xfr/out.rs`, `refusal()`).
- **Updates** (`crates/tenko-dns/src/update/`). `manual`, `dynamic`, `dhcp` and `ad` RRsets may be changed by an update, `ipam` only with `may_replace_ipam`, `transfer` and `dnssec` never; every changed RRset becomes `dynamic`. Home and Standard follow the zone's `require_tsig`, Hardened always requires a signature, Lab never (`policy.rs`).
- **DHCP engine** (`crates/tenko-dhcp/src/v4/engine/mod.rs` `request`, `allocator.rs`). RENEWING or REBINDING for a free pool address with no record is ACKed and creates the lease with the scope's lease time, not the old remaining time; INIT-REBOOT with no reservation and no lease row of the client is silent (RFC 2131); an address held by another client's row is NAKed on an authoritative scope. The client is option 61 when sent, else `htype` and `chaddr` (`tests/engine.rs` lines 225 to 305).
- **DDNS** (`crates/tenko-dhcp/src/ddns/`). DHCID per RFC 4701 types 0, 1 and 2 with SHA-256 over the identifier and the canonical name (`dhcid.rs`); the planner treats a name as the lease's own only when the DHCID RRset has the origin `dhcp` and the computed bytes (`plan.rs` `dhcid_is`); `manual`, `dynamic`, `transfer`, `dnssec` and `ad` names are refused whatever `conflict` says; there is no adoption mode (`take_over` exists only for `ipam`). The worker follows `dhcp.leases`, takes the name from option 81 or, with `legacy_clients`, option 12 on the row, and removes a lease's names when its name or client changes.
- **Building a scope by API.** `POST /dhcp/scopes`; pools are IPAM ranges of role `dhcp_pool` (`POST /prefixes/{id}/ranges`); `POST /dhcp/scopes/{prefix}/exclusions`; `PUT /dhcp/option-sets/{owner}`; reservations through `POST /addresses/reserve` (an IPAM host of mode `reserved`, keyed by client identifier, else MAC); the spreadsheet import covers hosts, not scopes. An address with a `dns_name` in IPAM gets no DDNS: the IPAM actuator writes its records with the origin `ipam`.
- **Lease rows** (ADR 0031). The lease table is the observation source; a new cold field is added with a serde default and a presence bit without a data format change (`granted` did so); the store's format is 5.
- **Jobs** (`tenko-jobs`, [jobs.md](../jobs.md)). Steps, rollback, audit, and a task that waits for a person (`POST /jobs/{id}/steps/{index}/complete`).

## 2. Design decisions the packages share

### 2.1 The mirror's transport and trust

A **mirrored source** is a new kind of source beside the plugin instances: Tenko does not poll it, it is pushed to. Its row holds a name, a `kind` label (`windows-dhcp` for this exporter; a label of `[a-z0-9-]{1,32}`, never an enumeration of products, so that a Kea or dnsmasq script can push the same IR under its own label), the expected interval (60 s), the token's id, the last accepted sequence, the hash of the last snapshot and the times of the last push and the last change.

The trust rules (ADR 0033, proposed):

1. **Push only.** The exporter calls `PUT /api/v1/migrate/mirrors/{id}/snapshot` over HTTPS on the API port. Tenko opens no connection to the controller, holds no Windows credential and has no way to make the script do anything: the answer carries the accepted sequence and whether the snapshot changed, and the script logs it and acts on nothing else (WT-Q1).
2. **A token that can write one mirror and nothing else.** Creating the mirror creates a service account `mirror-<id>` (named by the mirror's id, so that the mirror's name is a display name that may hold spaces and be renamed without a side effect) with no grants and one scoped token whose only special scope is `mirror:<id>`. The token may be bound to the source prefixes the exporter pushes from, by the source binding of scoped tokens (IAM-21, [access.md](../access.md) section 7.2): a push from elsewhere is refused like an unknown token and audited as `auth.token.source_refused`. Under Hardened a mirror is created, enabled or given a new token only with at least one prefix, and a mirror whose token has none stops pushing when the profile is switched, with the finding `migrate.mirror.unbound` (section 2.11). A prefix is at least a /16 or a /48. An installation holds at most 32 mirrors. The push route accepts exactly that scope for exactly that id; every other operation answers 403 to that token, including reads of its own mirror, so a stolen token gives neither data nor reach. The token is shown once, expires within TGL-05 (WT-Q11), and is replaced from the mirror card; the old one stops at once.
3. **The script is static and comes with the release.** It is in the release assets and in the repository, versioned with Tenko and listed in `SHA256SUMS`; the documentation says to compare the digest before copying it to the controller. Tenko never serves it, never generates it and never updates it: a compromised Tenko node cannot change what runs on a controller (the privilege boundary of ADR 0023: a more privileged account never runs what a less privileged one wrote).
4. **The script runs with DHCP read rights only.** A domain account (a group managed service account where the domain has a KDS root key, else a user account with a long random password) that is a member of `DHCP Users` and of no privileged group, with the right to log on as a batch job on the controllers that run DHCP. The script refuses to start when its account is a member of `Domain Admins`, `Enterprise Admins`, `Administrators`, `DHCP Administrators` or `DnsAdmins` (a check of its own token's groups), so a convenient misconfiguration fails loudly.
5. **The script verifies Tenko.** The install script takes the SHA-256 fingerprint of Tenko's certificate authority (shown on the mirror card) and the script accepts only a chain ending in it; nothing is added to the controller's trust store. The token is stored with DPAPI for the task's account (`ConvertFrom-SecureString` without a key), readable by nothing else on the controller.
6. **Bounds and replays.** A body of at most 8 MiB (gzip allowed, 32 MiB inflated), at most 1,000 scopes, 10,000 reservations and 20,000 leases, so that a snapshot at every bound is written in one store batch with room to spare (the owner's decision of 2026-11-20: what one store batch holds with room to spare. With the exporter's item sizes the snapshot row at every bound is about 11.8 MB of the 16 MiB batch; 50,000 leases alone take 10.4 MB, so neither 100,000 nor 50,000 fit); a strictly increasing `sequence` per mirror (an older or equal one is refused as a replay, 409 `migrate.mirror.sequence`); at most one push per 10 s per mirror (429); the body is read whole first, within the server's deadline for request bodies (408 `sys.body_timeout`), and only then does the push take the node's one decode, so that a slow body holds no other mirror; one push of a mirror is in flight on a controller at a time (429 for the next), so the bodies arriving hold at most 8 MiB per mirror. The IR is parsed with the strict serde types of `tenko-core` (`deny_unknown_fields` on the envelope), so a value that does not validate is refused whole with the path of the first error (422 `migrate.mirror.invalid`); nothing of a refused push is stored.

DNS data does not use the mirror: it comes by the existing zone transfer, AXFR and IXFR with NOTIFY, address-restricted on both sides because Windows DNS does not sign transfers ([dns.md](../dns.md) section 10.13).

### 2.2 The exporter

`deploy/windows/mirror/` holds three files and their tests:

- `Tenko-DhcpMirror.ps1`, the exporter: PowerShell 5.1 and 7, the `DhcpServer` module only, no other module and nothing downloaded. One run reads `Get-DhcpServerv4Scope`, `Get-DhcpServerv4ExclusionRange`, `Get-DhcpServerv4Reservation`, `Get-DhcpServerv4OptionValue -All` at server, scope and reservation level, `Get-DhcpServerv4OptionDefinition`, `Get-DhcpServerv4DnsSetting` per scope and at server level, `Get-DhcpServerv4Lease` per scope, and, only to report them, `Get-DhcpServerv4Policy`, `Get-DhcpServerv4Filter`, `Get-DhcpServerv4Superscope` and `Get-DhcpServerv4Failover`. It maps them onto `DhcpIr` with the mapping of [dhcp-contracts.md](../dhcp-contracts.md) section 11 (the XML element names there are the cmdlets' property names), writes a loss entry for every policy, filter, superscope, failover relationship, scope `Delay`, BOOTP-only scope and lease state other than active, active reservation, declined and expired, and pushes the envelope of section 3.1. Lease expiry times are converted to UTC; the envelope carries `taken_at` from the controller's clock, and Tenko computes each lease's remaining time against `taken_at`, so clock skew between the controller and the node does not shorten or lengthen a lease.
- `Install-TenkoDhcpMirror.ps1`: registers the scheduled task (every minute, under the given account, "run whether the user is logged on or not", no highest privileges, a new instance is not started while one runs), stores the token with DPAPI under that account and the fingerprint beside it, and runs one `-Once` to show the result. `-Remove` unregisters the task and deletes the stored token.
- `README.md`: the account, the rights, the digest check, the two commands, what the log says.

`-Once` is the dry run: it reads, maps and prints the IR and the loss report as JSON on standard output and pushes nothing, so an operator can read exactly what would leave the controller. A normal run writes one line per run to a log file under the task account's profile (sequence, counts, answer, duration) and keeps the last seven days.

The mapping lives in the script because the exporter is the adapter (WT-Q2): the core receives only the IR and the loss report, as it would from any other source, and validates them. The cost is a mapping in PowerShell besides the Rust side of the other adapters; the Pester tests with recorded cmdlet output (section 3.4) hold it to the fixture IR.

### 2.3 What the mirror carries, and the loss report

Every 60 s (WT-Q2): the scopes with their pools, exclusions, lease time, state (active or inactive) and DNS settings; the options at server, scope and reservation level with the custom definitions; the reservations; the leases in the states active, active reservation and declined. Expired leases are left out. Policies, filters and superscopes go to the loss report, as do failover relationships; the server's DNS credential is never read (`Get-DhcpServerDnsCredential` is not called).

The loss report of the latest snapshot is shown on the mirror card. An entry is acknowledged per scope (`POST /migrate/mirrors/{id}/losses/ack` with the entries' keys, by an administrator's interactive session); an acknowledgment holds while the entry recurs unchanged and lapses when it changes. The prepare and the takeover refuse a scope with an unacknowledged entry (MIGRATION.md: nothing is dropped silently).

### 2.4 Storage and freshness

- `migrate.mirrors`: one row per source (section 2.1).
- `migrate.snapshots`: one row per mirror, an accepted envelope as CBOR with the hash of its configuration. What a push writes (the owner's decision of 2026-11-20; the earlier "one small write every ten minutes" did not hold, since leases change between most pushes):
  - The **configuration** (the scopes with their state, pools, exclusions and DDNS settings, the options at every level, the definitions, classes, policies, filters, superscopes, failover relationships, reservations, the source and every loss entry but those of leases) has its own hash. A push whose configuration changed is written at once: the snapshot, the mirror row and the audit record `migrate.mirror.push`. A scope that turned inactive is a changed configuration, so the push the takeover waits for (section 2.7, step 2) is always written.
  - The **leases** and their loss entries have a hash of their own. Changed leases alone (a new lease, a lease gone, a state or an expiry moved) write the snapshot and the row at most every ten minutes per mirror (`LEASES_WRITE_SECS`), with no audit record. The mirror says which push the stored leases are from (`stored_sequence`, `stored_at`), so nobody takes a stored expiry time for a current one.
  - The controller that received a push holds its envelope in memory as the newest, stored or not.
  - Otherwise the push moves the freshness in memory, and the mirror row is written at most every half of the stale threshold (section 2.14).
  
  The lease path is never touched (ADR 0030 and 0031: no fact rows, nothing on the commit path).
- **For WP14.2:** the prepare and the takeover need the newest leases and take them from a push made for that moment (the newest envelope on the controller that received it, or the push the takeover waits for), never from the stored copy, whose leases may be ten minutes old.
- Freshness on the mirror card (on the connectors page, beside the plugin instances): the time since the last push, the time since the last change, the sequence, the counts of scopes, reservations and leases, the script's version and the server name it reports, and the losses. The mirror is **stale** after three missed intervals (180 s): the card says so and the system status carries the finding `migrate.mirror.stale` (a warning; an error once the mirror's scope was taken over and the Windows side is expected to be quiet, section 2.10).

### 2.5 The diff and the prepare

The **diff** compares a mirrored scope with Tenko's scope of the same network: the pool ranges, the exclusions, the lease time, the options at each level, the reservations (added, changed, removed, by MAC or client identifier and address), the DDNS settings mapped by the table of [active-directory.md](../active-directory.md) step 10, and whether the network is an IPAM prefix. Each row says what the prepare would do.

The **prepare** is a job (one per scope) that makes Tenko's scope equal to the mirror's while it serves nothing: it creates the IPAM prefix when missing, the scope with `enabled = false`, the pool as a range of role `dhcp_pool`, the exclusions, the option sets of the scope and of each reservation (server-level options become the server's set only where the server set has none of that code, otherwise a diff row the operator decides), the DDNS settings, and each reservation as an IPAM host of mode `reserved` named by section 2.9. A host that IPAM already holds with the reservation's MAC or client identifier, or with the reservation's address, is attached rather than duplicated; a disagreement between the two (the MAC on one host, the address on another) is a diff row that blocks the prepare until the operator resolves it. Reservations get no `dns_name` in IPAM, so their records stay DDNS records, as Windows DHCP writes them (section 2.9). The prepare runs again whenever the operator wants, and a run against an unchanged mirror changes nothing. Its reverse is the job's rollback or the ordinary deletion of the scope.

### 2.6 The flip of a zone, and the origins it keeps

`POST /dns/zones/{id}/flip` with `{"to": "primary", "soa": {...}, "ns": [...]}` turns a secondary zone into a primary zone in place (ADR 0034, proposed): the kind changes, the transfer service stops refreshing it, the SOA `mname` and `rname` and the apex NS set become the operator's values (step 3 of today's runbook, done in the same commit), the serial continues from the copy's, and the records stay. The origins after the flip:

| The copy's RRset | Origin after the flip | Why |
|---|---|---|
| A, AAAA and DHCID at a name that holds a DHCID RRset, and a PTR whose target is such a name | `transfer` (frozen) | A name a DHCP server wrote; it waits for the takeover, and no writer touches it until then ([dns.md](../dns.md) section 10.7) |
| The apex SOA and NS | Replaced | The operator's values |
| Every other RRset (the controllers' SRV, CNAME and A records, static hosts, the `_msdcs` zone entire) | `ad` | Records of an AD zone without a known owner (identity plan section 3.6): an update from the access list may change them, as before; Slice 13's claim rule applies to them later (WT-Q9) |

The reverse zones are flipped after the forward zones are on Tenko, so that the PTR rule reads the forward names; a PTR whose target is in a zone Tenko does not hold becomes `ad`. The flip writes one change set per zone and the audit record `dns.zone.flip` with the counts by origin.

The reverse flip, `{"to": "secondary", "primaries": [...]}`, turns the primary back into a secondary of the named primaries; the next transfer replaces every record with the copy's, `transfer` again. It is step 2 of the DNS rollback (section 2.10); step 1 is on Windows.

`POST /dns/zones/{id}/release` turns every remaining `transfer` RRset of a primary zone into `manual`, or deletes them with `{"delete": true}`, and lists them first in a dry run. It is for the names that a takeover did not adopt because no mirrored lease or reservation stands behind them (stale names; Windows would have scavenged them, Tenko cannot until DNS-29). Catalog zones keep their own rule: `release` refuses a catalog zone.

Frozen names between the flip and the takeover: Windows DHCP's update of a frozen name is refused (audited as `dns.update.refuse`); a client renewing at Windows keeps its address and its frozen name, which is still right. A client new to Windows DHCP in that gap gets a `dynamic` name with Windows' DHCID, which the takeover adopts under WT-Q8. The runbook therefore does the flip and the takeover in one window (section 2.13).

### 2.7 The takeover of a scope

The takeover is a job per scope (`POST /migrate/mirrors/{id}/scopes/{cidr}/takeover`, the UI button on the mirror's scope row, `tenko migrate takeover <mirror> <cidr>`), with these steps:

1. **Check.** The mirror is fresh (a push younger than 120 s), and so is its partner when it has one (section 2.15); the loss entries of the scope are acknowledged on each; the prepare's diff is empty for pools, exclusions and reservations; Tenko's scope is disabled; the forward zone and the reverse zones are primary zones on Tenko that take DHCP updates under the profile (`update.dhcp`, [dhcp.md](../dhcp.md) section 13.1) and the scope's DDNS is enabled when the mirror's was. A failure ends the job with its code and changes nothing.
2. **The Windows scope off (a task for the person).** The job shows the line to run on each DHCP server (`Set-DhcpServerv4Scope -ComputerName dc1.corp.example.test -ScopeId 192.0.2.0 -State InActive`, and the same for `dc2`) and waits, for at most ten minutes, for a push of each mirror that shows the scope inactive. Those pushes are the snapshot the takeover uses: together they hold every lease Windows granted until it stopped answering. Nothing writes to Windows (CONN-12 explicitly not); the job proves the state from the mirror instead.
3. **The records** (section 2.8), one change set per zone.
4. **The leases** (section 2.8), in batches of 1,000 rows.
5. **The scope on.** `enabled = true`; from this commit the role answers for the network once the relay or the listener reaches it.
6. **The record.** A row in `migrate.takeovers` (the scope, the snapshot's sequence, the counts, the adopted addresses and names, the names left frozen, the skipped items with their reasons, the before-images of every RRset it changed) and the audit record `dhcp.scope.takeover` with the counts.

A failure in steps 3 to 5 rolls the job back from the before-images: the RRsets as they were, the adopted lease rows removed, the scope disabled. The rollback is the job engine's, so it is visible and audited like every other.

Between step 2 and the moment clients reach Tenko, nobody answers the network. With the lease time lowered the day before (section 2.13), a client's renewal goes unanswered (it is unicast to the controller) and its rebinding broadcast reaches Tenko at T2, within minutes; a client that boots meanwhile sends INIT-REBOOT and is answered from its adopted row.

### 2.8 The adoption rule

**Leases.** Each mirrored lease of the scope (of both partners, merged by the rule of section 2.15) in the state active or active reservation becomes a `dhcp.leases` row: state `active`, the address, `ends` = `taken_at` plus the remaining time of the Windows lease (at most the Tenko scope's maximum lease time), `granted` = the adoption time (ADR 0031 point 3), the host name, and the cold field `adopted { mirror, sequence, guessed }`. A declined lease becomes an `abandoned` row with the hold of `[dhcp.decline]`. A lease is skipped and reported when its address is outside the Tenko pool and not a reservation, when it conflicts with a Tenko reservation of another client, or when Tenko holds an active row of another client at the address.

**The client's identity.** Tenko keys a lease by option 61 when the client sends one, else by `htype` and `chaddr`. Windows shows a client's identifier as six octets for both a client that sends option 61 of type 1 with its MAC and a client that sends none, so the mirror cannot always tell which key the client will present. The adoption decides it in this order: an identifier longer than six octets is the client's option 61 as it is; else, where a DHCID stands at the lease's name, Tenko computes the DHCID of both candidates (type 1 over `01` and the MAC, type 0 over `htype` 1 and the MAC) and takes the one that equals the record Windows wrote; else option 61 of type 1 with the MAC (proposed; most clients of a Windows network send it), and the row is marked `guessed`. Whether a candidate ever matches Windows' DHCID is what the rehearsal records (R137).

**The engine's rule for an adopted row.** When a REQUEST in RENEWING, REBINDING or INIT-REBOOT names an address whose active row is `adopted` and keyed by another identity, and the row's MAC equals the request's `chaddr` with `htype` 1, the row is the client's: the change rewrites it under the identity the client presented (a renewal, `granted` kept, `adopted` cleared) instead of refusing the address as another client's, and INIT-REBOOT counts the row as the client's record. A request from another MAC gets what it gets today: NAK on an authoritative scope, silence otherwise. The check reads fields the row already holds, so the path stays free of allocations (`tests/alloc.rs`). The first REQUEST of every adopted client clears `adopted`, whatever its key.

**Records.** For each adopted lease and each mirrored reservation with a lease, the name is the lease's host name under the name rule (section 2.9) and the zone is the scope's forward zone. At that name the takeover adopts:

| At the name | Condition | Written |
|---|---|---|
| A (or AAAA) and DHCID, origin `transfer` | The A RRset holds the lease's address and no other; a DHCID RRset stands beside it | A with the lease's address and DHCID computed by Tenko for the row's identity, origin `dhcp`, TTL by the scope's DDNS settings (a third of the lease time by default) |
| A and DHCID, origin `dynamic` | As above (WT-Q8, proposed: Windows DHCP rewrote the name after the flip or during a reverted takeover) | The same |
| PTR at the address's reverse name, origin `transfer` or `dynamic` | Its target is the name | PTR, origin `dhcp` |
| `manual`, `ipam`, `ad`, `dnssec`, a CNAME, an A RRset with other addresses, a name without a DHCID | Never adopted | Skipped and reported; Tenko's DDNS treats the name by its usual rules at the next renewal |

A name the takeover adopts loses its Kerberos owner (identity plan section 3.6; the zone's **Owners** tab) in the same change set: a `dynamic` name a Windows DHCP server created after the flip is owned by the principal that signed its update, and an adopted name belongs to the lease from then on (section 2.15).

The adopted lease row carries what a DDNS write would have left on it: the name as its option 81 name with the S flag (the server writes the A record), and the `ddns` block (`forward`, `reverse`, `dhcid`, `updated`). So the DDNS worker, which follows every committed row, finds the names to be the lease's own and writes nothing; at the client's first renewal the planner sees a `dhcp` name with the lease's DHCID and replaces it with what the client asks for. Where the engine rewrote a `guessed` row under another identity, the DHCID at the name is no longer the lease's: the worker replaces the A and DHCID of an adopted row's own name in one change set (the row's `ddns.dhcid` equals the record), and only then forgets the old identity. Names with a DHCID that no mirrored lease or reservation explains stay frozen and are listed in the takeover's record with the `release` action.

### 2.9 Names

The rule for every name the slice derives (WT-Q4), for a reservation's IPAM host and for the name at which records are adopted:

- A fully qualified name is kept (lowercased). When it is under a zone Tenko serves it is the record name; when it is not, it becomes the host's name and the reservation gets no adopted record, with a loss entry.
- A bare host name gets the zone: `nas01` becomes `nas01.corp.example.test` (the scope's forward zone, from its DDNS settings or option 15).
- A factory name is kept as it is (WT-Q10): the device's own default (`ESP_3A1F2B`, `android-5f2c9e01d4a6b7c8`) is not tidied into a name Tenko would have chosen. When it is a valid host-name label it gets the zone like any bare name; when it is not (an underscore, a space), it is kept as the host's name in IPAM, no record is derived from it, and a loss entry says so.

A reservation's IPAM address gets no `dns_name`, so the reservation's records stay DDNS records with the origin `dhcp`, written from the client's name as Windows DHCP wrote them (Windows registers reserved clients the same way as others). An operator who gives a reservation a `dns_name` later moves its records to IPAM by IPAM's existing take-over of `dhcp` records.

### 2.10 The reverse, per phase in two steps

| Phase | Step 1 | Step 2 |
|---|---|---|
| Mirror and secondaries (nothing served) | Remove the task on each DHCP server (`Install-TenkoDhcpMirror.ps1 -Remove`) and the transfer permission on the controllers | Delete the mirror (its service account and token go with it) and the secondary zones in Tenko |
| DNS flipped | On Windows, the controllers' secondaries become AD-integrated primaries again, with Tenko's latest data (`ConvertTo-DnsServerPrimaryZone -ReplicationScope Domain`, `Forest` for `_msdcs`) | In Tenko, the reverse flip to secondary of the controllers; the next transfer brings the records back as `transfer` |
| DHCP taken over | In Tenko, the reverse action: the scope disabled, its leases and records kept, `dhcp.scope.revert` audited | On each DHCP server, conflict detection on (`Set-DhcpServerSetting -ConflictDetectionAttempts 1`: neither knows the leases Tenko granted) and the scope active again (`Set-DhcpServerv4Scope -State Active`), and the relay or the listener back; the names Tenko wrote stay with the origin `dhcp`, and Windows' updates may change them ([dns.md](../dns.md) section 13.4) |

The takeover script's `-Reverse` performs both steps of a phase, Windows' first, and the Windows step alone when the node cannot be reached (section 2.16.1). After a reverse action, the mirrors are expected to show the Windows scope active again; after a takeover, a mirrored scope that turns active again on either partner while Tenko's scope serves is an error finding (`migrate.mirror.scope_active`): two servers would answer one network.

### 2.11 Profiles

Home now (WT-Q5): the AD zones take unsigned updates from an access list of the controllers' addresses (`require_tsig = false`), Tenko DHCP writes into them by its internal path (`update.dhcp` unset follows the profile, Home allows it), name protection is `protect`, transfers out to the controllers' secondaries are unsigned and address-restricted. Standard works the same with `update.dhcp = true` on the zones. Hardened refuses unsigned updates and stays out of reach for an AD zone that takes updates until Slice 13; the runbook says so, and the mirror, the flip and the takeover work under every profile. Under Hardened a mirror's token must be bound to source prefixes: creating a mirror, enabling one and replacing its token need at least one prefix (section 2.1, rule 2). The certificate binding of TGL-47 does not apply to a mirror token (ADR 0033); the prefixes take its place.

### 2.12 Audit, metrics and findings

| Kind | Name | When |
|---|---|---|
| Audit | `migrate.mirror.create`, `.update`, `.delete`, `.token` | Management of a mirror (administrator, interactive session) |
| Audit | `migrate.mirror.push` | A push that changed the snapshot: sequence, counts, hash, losses |
| Audit | `migrate.mirror.refuse` | A refused push: the code, the client address; at most once a minute per mirror |
| Audit | `migrate.mirror.losses_ack` | Loss entries acknowledged |
| Audit | `dhcp.scope.prepare`, `dhcp.scope.takeover`, `dhcp.scope.revert` | The three scope actions with their counts |
| Audit | `dns.zone.flip`, `dns.zone.release` | The zone actions with the counts by origin |
| Metric | `tenko_migrate_mirror_pushes_total{mirror, outcome}` | `changed`, `unchanged`, `refused` |
| Metric | `tenko_migrate_mirror_age_seconds{mirror}` | Seconds since the last accepted push |
| Finding | `migrate.mirror.stale`, `migrate.mirror.scope_active`, `migrate.mirror.token_expiring` (14 days ahead) | System status and the mirror card |

### 2.13 The runbook's shape, and the rehearsal

The rewritten runbook (WP14.3) is ordered so that every step before the window changes nothing a client uses. Since the amendment of section 2.16 the takeover script performs these steps in its phases (steps 1 to 5 in phase 2, step 6 in phases 4 and 5 after the person starts the window, step 8 in phase 6), and the runbook describes them for reading before a run and for the manual path:

0. **The rehearsal** (WT-Q6 as amended): the runbook from step 1 in the Windows lab's takeover line, below.
1. The starting state and the backups (today's step 1, with `Export-DhcpServer -Leases` on each DHCP server).
2. Tenko as secondary of every AD zone from one controller (section 2.15), the controllers allowing the transfer and notifying the node; one mirror per DHCP server, paired; the scope prepared from the mirrors; the losses acknowledged on both; the diff empty, the partner rows included. Coexistence mode secondary: no client points at Tenko.
3. The access list of the controllers and the zones' update policy (it applies from the flip); the profile confirmed (Home).
4. Optional (amended 2026-11-20): a lease time ahead, the Windows scope's lease time lowered to an hour; the day before the window, to 10 minutes (T2 then falls under nine minutes, so every client rebinds to Tenko within minutes of the switch; the rehearsal confirms the figure). No client loses its address or its name without it: a client whose renewal goes unanswered keeps its lease and rebinds to Tenko at T2, within seven eighths of the lease time. The script offers it and states both times.
5. The registry value on each domain-joined Windows machine that is not a controller: `DisableDynamicUpdate` = 1 (`REG_DWORD`) under `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, so that the member does not try to register its own name and the DHCP server writes it; checked with `reg query`. The controllers keep their registration.
6. **The window.** Directory replication forced (`repadmin /syncall /AdeP`) and a transfer from the controller Tenko copies from, so that the copy holds both controllers' latest registrations; the flip of each zone, forward zones first (section 2.6); the controllers' copies converted to secondaries of Tenko in the order of R142, with Tenko's `transfer.allow` and `notify` naming them; the controllers pointed at Tenko and registering (today's step 5); then per scope the takeover (section 2.7) and the relay or the listener; the check from a client.
7. **The parallel period**, a week: the mirror keeps running and must show the Windows scope inactive; the controllers serve their secondary copies as the second DNS server of the clients' option 6 list, behind Tenko.
8. After the parallel period, in this order: the failover relationship removed (`Remove-DhcpServerv4Failover`, which deletes the scope on the partner), each server's authorization removed (`Remove-DhcpServerInDC`), the DHCP Server role removed from both, each exporter's task and mirror removed, and the zones' objects in the directory partitions deleted (a DNS Server role installed later on a controller serves objects left there at once, as authoritative primaries with their old data, measured on 2026-11-20); the way back is the role (about a minute per server, no restart, measured), its security groups (`Add-DhcpServerSecurityGroup`) and the authorization on one server, then, after directory replication, on the other (run on both at once it creates conflicting duplicate groups, measured), `Import-DhcpServer` of step 1's export on one server and `Add-DhcpServerv4Failover`, which creates the scope on the partner. The DNS Server role stays on the controllers as Tenko's secondaries until a second Tenko node exists (Phase 5, WT-Q12, R143).

Each phase keeps its two-step rollback (section 2.10). The INIT-REBOOT note: a client that boots with a lease Tenko holds no row for (one the mirror missed) gets silence, as RFC 2131 says, and falls back to DISCOVER after its timeout; it is offered its old address when the address is free, and the conflict probe ([dhcp.md](../dhcp.md) section 14) stands between it and a second client.

**The rehearsal** (WT-Q6 as amended on 2026-11-20): a second line of the Windows lab, the takeover line, beside the counted line of E44 (identity plan), whose entries it leaves untouched; the two lines never run at the same time. Its start state is Windows-first: both lab controllers with Windows DNS and Windows DHCP in a failover relationship in load balance, one scope over `192.0.2.0/24` with exclusions, reservations and options 3, 6 and 15, the lab's Windows client on a DHCP reservation, and the lab's Tenko node installed and serving nothing. Three actors run it: the **operator** builds the machines, takes and restores snapshots, and runs commands on the Tenko node and step scripts on the lab machines; the **inside observer**, a session on the admin workstation `adm1` (joined, with the Remote Server Administration Tools for Active Directory, DHCP, DNS and group policy), reads at once and changes something only after its own user approves that change, and never signs in to the Tenko node's API; the **lead** decides and reads the evidence. No secret travels on the channels between them: credentials live in files on the hosts that only root or SYSTEM reads. The line runs under Standard until its Hardened entry and under Hardened from the flip on, as the owner's cutover will (WT-Q5 as amended); the interactive actions under Hardened need an administrator's passkey session on the node. Nothing from the owner's own domain enters the lab (WT-Q14). The manifest, with the start state, every entry with its actor, action, check and evidence, what runs with the first package alone and what waits for which package, and the first basic set, is [`deploy/compose/lab-ad/windows/takeover/README.md`](../../deploy/compose/lab-ad/windows/takeover/README.md).

### 2.14 Single node first, cluster-aware

One node with the `controller`, `dns` and `dhcp` roles. Cluster-aware now: the mirror rows, the snapshots and the takeover records are in the replicated store; the push is accepted by any controller and written through the store; the freshness lives in the memory of the controller that took the push and is written to the mirror row at most every half of the stale threshold while pushes arrive (90 s at the default interval, `Mirror::freshness_write_secs`), so another controller or a restarted one reads a mirror that pushes as fresh, never falsely stale, with a sequence at most that far behind; the takeover's lease rows carry the node as every lease row does. A second DNS primary and a DHCP pair are Phase 5 and Slice 12; until then the controllers' secondary copies are the DNS fallback (R143).

### 2.15 Two controllers with DNS and DHCP (amended 2026-11-20)

The owner's domain runs DNS and DHCP on both controllers with replication between the DHCP servers. The owner confirmed on 2026-11-20 that it is a failover relationship in load balance (50 percent each, a maximum client lead time, the MCLT, of one hour, no shared secret read), and the table at the end says what would differ for hot standby and split scopes. Read against the first package as built (`8ea12bc2`), each decision of this plan holds or changes as follows.

| Decision | Holds | Changes |
|---|---|---|
| The transport and the trust (2.1, WT-Q1, ADR 0033) | Push only, one token per mirror, the static script, the read-only account, the pinned root, the bounds | **One exporter per DHCP server, each with a mirror of its own** (its own account `mirror-<id>`, token, sequence series and state directory); under Hardened each token is bound to its server's own address as a /32. The exporter reads only its local server (it calls the cmdlets without `-ComputerName`), so each mirror is what that partner holds; WT-Q17 proposes one task per server on a member server instead, reading its server with `-ComputerName` (section 2.16.4). Two exporters pushing to one mirror are a misconfiguration the built code does not see: their sequences are both the Unix time, the stored snapshot alternates between the two servers, and every push is written and audited as a changed configuration (R219). The follow-up of WP14.1 (section 4) binds a mirror to the `source.server` of its first accepted push and refuses a push naming another (409 `migrate.mirror.source`, audited) until its token is replaced |
| The pair (new, proposed) | | The mirror row gains `partner: Option<MirrorId>`, set on both rows at once by an administrator's interactive session (`PATCH /migrate/mirrors/{id}` with `partner`, audited as `migrate.mirror.update`); the takeover, the findings and the diff read the pair. A third mirror cannot join a pair; 32 mirrors are 16 pairs |
| The exporter (2.2) | The reads, the mapping, `-Once`, the log | Microsoft's cmdlet page says `Get-DhcpServerv4Lease` returns only active leases unless called with `-AllLeases`; on Windows Server 2025 it was measured (2026-11-20) to return active and declined leases and the reservations without it, `-AllLeases` adding the expired ones, and an inactive scope to return its leases unchanged. Since the documented and the measured behavior differ, the follow-up of WP14.1 passes `-AllLeases` and leaves the expired leases out, which gives the same snapshot under either behavior |
| The loss report (2.3) | Each mirror reports the relationship as one entry (`mirror.failover`: its name, the partner, the mode, the scopes; never the secret), which names no address and so belongs to every scope of that mirror; acknowledged on each mirror | The relationship's MCLT, share and state are not carried (the exporter leaves the IR's `failover` list empty although `IrFailover` has the fields); nothing in the takeover needs them, since the union of both mirrors is complete in every relationship state |
| Freshness (2.4) | Per mirror | The pair is fresh when both are; after a takeover `migrate.mirror.stale` is an error for either. Two mirrors pushing in the same second share the node's one decode: the second waits up to 2 s and is otherwise answered 429 and retried at its next minute (M69 measures it) |
| The diff and the prepare (2.5) | The rows against Tenko's scope | For a paired mirror the diff adds rows of kind `partner` for every configuration difference between the two mirrors' latest snapshots (pools, exclusions, lease time, options at every level, reservations, DDNS), with the action `decide`. Windows copies scope settings to the partner only when someone runs `Invoke-DhcpServerv4FailoverReplication` or the console's replication, so a reservation made on one partner only is the common case. The prepare runs when the partners agree, so it is made from either |
| The takeover (2.7) | The job, its steps, its rollback | Step 1 checks both mirrors; step 2 deactivates the scope on each server with its own line, because a scope's state is a scope setting that Windows does not copy to the partner by itself (measured on 2026-11-20: creating the relationship copies the scope, its options and reservations at once, and afterwards neither a state nor a new reservation reached the partner within five minutes, while `Invoke-DhcpServerv4FailoverReplication -Force` carried both within about five seconds), and `Invoke-DhcpServerv4FailoverReplication` is not used for it since it overwrites the partner's whole configuration; since section 2.16 the takeover script runs both lines; the relationship and both authorizations stay in place. The job waits for a push of each mirror that shows the scope inactive. The record names both mirrors with the sequence and the lease hash of each push it used |
| The lease state between the partners (2.8) | The adoption of a lease | Binding updates between Windows partners are lazy: a lease granted shortly before the deactivation may be known only to the partner that granted it, and the other partner may hold a shorter end for a lease it did not grant (bounded by the MCLT). The union of the two pushes: an address in one mirror only is taken from it; the same address with the same client in both takes the later end; the same address with two clients is adopted for neither and reported (`migrate.takeover.lease_conflict`), and the conflict probe guards it |
| The exporting partner down | | Its mirror goes stale and the takeover refuses (`migrate.takeover.not_fresh` naming it): a partner that comes back with its scope active answers the network beside Tenko. A partner lost for good is first taken out on Windows (on the survivor `Remove-DhcpServerv4Failover`, which keeps the scope there; the lost server's authorization removed with `Remove-DhcpServerInDC`, so that a restored copy of it does not answer), then its mirror is deleted, and the takeover runs from one mirror |
| The reverse (2.10) | Two steps per phase | On Windows both servers: conflict detection on and the scope active again on each. The end of the parallel period removes the relationship before the role (2.13, step 8) |
| The DHCP servers' DNS identity (WT-Q13) | | Both partners must register with the same credential, else the partner's update of a name the other wrote fails (Microsoft's failover guidance). Between the flip and the takeover they write into Tenko's zones; under Hardened with GSS-TSIG a frozen name is refused as designed, and a new name is owned by the signing principal until the takeover adopts it and clears the owner (2.8). Without a credential they sign as the controllers' computer accounts, which are privileged in Tenko's ownership rules ([active-directory.md](../active-directory.md) section 4) and may change any name. The owner's domain already works this way (WT-Q13, decided 2026-11-20): one dedicated unprivileged user as the DNS credential on both servers, and its scope uses DHCP name protection |
| DNS: the copy (2.1, 2.6) | Transfer and NOTIFY, address-restricted | Tenko's secondaries name one primary, the controller holding the PDC emulator role (`dc1`): each Windows server keeps its own SOA serial for an AD-integrated zone, so a second entry in `source.primaries`, which are tried in order, can hold newer data under a lower serial or older data under a higher one (R217). Both controllers allow the transfer and notify the node; under Hardened Tenko refuses their unsigned NOTIFY and refreshes on the SOA timers, so the window forces replication and a transfer first (2.13, step 6) |
| DNS: the flip, the reverse, the registrations (2.6, 2.10) | The origins, `ad` for the controllers' records, the reverse zones after the forward zones, `_msdcs` flipped like the others | The conversion on Windows is per zone across both controllers (R142 as amended); both controllers then register with Tenko as privileged principals. The DNS reverse on Windows makes the zone AD-integrated on `dc1` and removes `dc2`'s file-backed secondary so that `dc2` loads the directory copy |
| The loss report at the takeover | | The relationship's entry on each mirror; for split scopes also the secondary server's `Delay` |

What would differ for the other two kinds of replication:

| Kind | What differs |
|---|---|
| Failover in hot standby | The standby answers only when it has lost its partner; its mirror shows the active server's leases as replicated, with the same lag. The union rule and everything above hold; the loss entry names the mode |
| Two servers with split ranges (no relationship) | Each mirror holds the same scope with the other server's share excluded and only its own leases, so the union is the whole lease set and conflicts do not arise. The partner rows of the diff show each server's exclusion of the other's share; the prepare's rule for a pair without a relationship is the union of the pools and the exclusions both servers have in common, decided once by the operator as a `decide` row. The secondary's `Delay` is a loss entry |

### 2.16 One script drives the takeover (amended 2026-11-20)

The owner graded the takeover of sections 2.1 to 2.15 by what the operator must do: a runbook open all the way, commands on two systems, values carried by hand. He decided on 2026-11-20 that **one script, run by the administrator on a domain-joined Windows machine, drives the takeover**: it asks for the domain's name, warns that it will act with administrator rights and lists exactly what it will change, asks for an account with enough rights through `Get-Credential`, and then does the Windows side with that account and the Tenko side through Tenko's API. Three conditions are fixed: (1) the script comes from the signed release, never from the node; (2) it never executes text that Tenko sends: it takes values, checks them against what Windows itself reports and uses them in fixed commands; (3) it signs in to Tenko through an approval a signed-in person gives in Tenko's UI, so the takeover stays the decision of an interactive session and is audited as such; the Windows credential lives only in that PowerShell session's memory, is never written and never sent to Tenko, and the Tenko server never holds a Windows right. The alternative set aside: the Windows credential entered into Tenko, with the server managing Windows remotely.

Everything the service does stays as sections 2.1 to 2.15 design it: the mirror and its push, the flip and its origins, the prepare, the adoption rule, the takeover job and its rollback, the reverse per phase. What changes is who performs the Windows half and the calls to Tenko, and how a script reaches operations that need an interactive session. [ADR 0038](../adr/0038-takeover-script-and-delegated-session.md) (Proposed) records the approval and the delegated session.

#### 2.16.1 The script

**Name and place.** `deploy/windows/takeover/Tenko-Takeover.ps1`, with its `README.md` and Pester suites. The release ships it beside the exporter and its installer as three assets, `Tenko-Takeover.ps1`, `Tenko-DhcpMirror.ps1` and `Install-TenkoDhcpMirror.ps1`, each signed with the release's Authenticode certificate (WT-Q15), listed in `SHA256SUMS` and covered by the release's provenance attestation like every release file. The script carries the SHA-256 of the exporter and the installer at its commit (the text before an Authenticode signature block; a Pester test keeps the values current) and installs neither when its digest differs. It refuses a node whose version is not its own (the version `GET /health` names; a gate, nothing more): the administrator takes the script of the release the node runs.

**What it needs.** Windows PowerShell 5.1 with .NET Framework 4.7.2 or later (the exporter's minimum), a domain-joined machine, WinRM over Kerberos (TCP 5985, on by default on Windows Server) to every controller and to the mirror host, and HTTPS to the node. It needs no module of its own: every Windows cmdlet runs in a CIM or remoting session opened with the credential on a server that holds the module with its role (the controllers hold `ActiveDirectory`, `GroupPolicy`, `DnsServer` and `DhcpServer`), so the script works the same whether its own process runs as the administrator or as an ordinary user. It may run on:

| Host | What differs |
|---|---|
| An admin workstation (recommended, as section 4.1 of [active-directory.md](../active-directory.md) advises a management host) | Needs no Remote Server Administration Tools; it must stay on only while the script runs, since the exporter runs on the mirror host |
| A member server | The same; it is the mirror host itself when the person picks it |
| A controller | The sessions to itself are loopback; it is never the mirror host (WT-Q17) |

**The credential.** `Get-Credential` once per sitting. The reference domain needs a member of Domain Admins (accounts and a group policy object in the directory, the DNS and DHCP servers, remoting on the controllers); the script reads the account's groups before any change and lists what is missing. The credential opens the sessions and nothing else: it is never written, never put into a command line or an argument list, never sent to Tenko, and is dropped when the script ends.

**Parameters.** None is required. Three forms: `.\Tenko-Takeover.ps1` runs or resumes the next phase; `-DryRun` discovers and prints the change list, changes nothing on Windows and contacts no Tenko; `-Reverse` undoes the latest phase done, both halves, and run again walks one more phase back. The script asks for the domain (the domain the machine is joined to is offered), for Tenko's address (a host name or an address, port 8443 unless written `host:port`) and, when it runs on no member server, for the mirror host, chosen from the list of the domain's reachable member servers. A resumed run reads the domain and the address from the state file and shows them.

**What it discovers by itself** (read only, before anything is shown):

| Object | From Windows | Used for |
|---|---|---|
| The domain and the forest root, the controllers, the PDC emulator, the global catalogs | `Get-ADDomain`, `Get-ADDomainController -Filter *` | The plan; the PDC emulator as the one primary of Tenko's secondaries (R217) |
| The DNS servers and their zones | `Get-DnsServerZone` on every controller, each read on its own: a controller with the role may hold no zone (measured: a controller never enlisted in the DNS application partitions serves none) | The AD-integrated forward zone, `_msdcs`, the reverse zones and their replication scope; conditional forwarders and server forwarders |
| Zone objects in the directory partitions that no server loads | The `dnsZone` objects under `DomainDnsZones` and `ForestDnsZones` | A warning: a later DNS role install serves them as authoritative primaries with their old data at once (measured); the finish deletes the plan's zones' objects (phase 6) |
| The transfer and notify lists, the dynamic update mode per zone | `Get-DnsServerZone` | Tenko added, the old lists kept for the reverse |
| The DHCP servers and their scopes | `Get-DhcpServerInDC`, `Get-DhcpServerv4Scope`, `Get-DhcpServerv4Binding` | The plan; a scope whose network none of its servers is bound to is relayed, and the gateway's relay is named as a manual action |
| The failover relationship | `Get-DhcpServerv4Failover` | The pair of mirrors; the servers named by their FQDN from `Get-DhcpServerInDC`, since the two partners name each other differently (measured) |
| The servers' DNS credential and DNS settings | `Get-DhcpServerDnsCredential` (the user name only), `Get-DhcpServerv4DnsSetting` (never option 81, whose bits outlive a setting, measured) | WT-Q13: the same unprivileged user on both servers, else the script creates one and sets it on both (a listed change) |
| Filter lists, policies, superscopes | `Get-DhcpServerv4FilterList` (its Allow and Deny state), `Get-DhcpServerv4Filter`, `Get-DhcpServerv4Policy`, `Get-DhcpServerv4Superscope` | Shown as what Tenko will not take over (the loss report the mirror then carries) |
| Domain members that are DHCP clients | The scopes' leases matched with `Get-ADComputer` | The group policy object of phase 2 |
| A KDS root key, the mirror host's DHCP management tools | `Get-KdsRootKey`, the host's features | A group managed service account for the exporter where a key exists, else a user with a random password; the tools added when missing |

Every read selects properties by name and treats an absent result and a single object as lists (measured: `Get-DhcpServerv4Filter` returns nothing when no entry exists, `Get-DhcpServerv4Superscope` one object; a whole CIM object serializes to about 69 KB).

**What it shows before it changes anything.** The warning that it will act as the named account with administrator rights; then the change list, per system and machine, each line with its reverse (the reference domain's list is the content of the phases below: about 25 lines); what Tenko will not take over; the time clients need to move to Tenko (seven eighths of the lease time, since continuity does not depend on lowering it, section 2.13 step 4); and, once Tenko is reached, the approval code. The person types the domain's name to confirm the first change of each sitting.

**The phases.** Each step checks the actual state first and acts only when it differs, so every phase can be run again; each phase's reverse is `-Reverse`.

| Phase | Windows (with the credential) | Tenko (through the approval) | Reverse |
|---|---|---|---|
| 0. Discover | Reads only | None | None |
| 1. Approval | None | The approval of section 2.16.2 | The run aborted, its session revoked |
| 2. Prepare, nothing served | The backups (`Export-DhcpServer -Leases` per server, `Export-DnsServerZone` per zone, copied to the state directory); the exporter's account in `DHCP Users`; the exporter installed on the mirror host with one task per DHCP server (section 2.16.4); Tenko's address added to each zone's transfer and notify lists on the PDC emulator, read back on every controller after `repadmin /syncall /AdeP`, and set where it did not arrive (either answer of the pending measurement works); the DHCP DNS credential where WT-Q13 needs it; under WT-Q16 the computer account of [active-directory.md](../active-directory.md) section 4.1 with a one-time password generated in memory; the group policy object `Tenko takeover: DNS client registration off`, filtered to the members found, which sets section 2.13 step 5's effect as the DNS client's dynamic update policy (`RegistrationEnabled` = 0 under `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, a policy value that leaves with the object; the rehearsal confirms the effect); optionally the lease time lowered | The secondary zones from the PDC emulator and a transfer; the forwarding rules from Windows' forwarders; the zones' update policy (it applies from the flip); `POST /dns/kerberos/adopt` with the one-time password, which Tenko replaces at once; two mirrors bound to the mirror host's address as a /32, paired; the first pushes awaited; the prepare of each scope | Everything of the phase removed, the lists and settings restored from the state file |
| 3. Review | None | The person reviews the run page and starts the window (section 2.16.5); the script waits, or ends with exit 3 and resumes later | None |
| 4. DNS window | `repadmin /syncall /AdeP`; after the flip, per zone with `_msdcs` last, each controller made a file-backed secondary of Tenko by its own state (an AD-integrated primary converted, an absent zone added, R142); the controllers' DNS clients Tenko first, `nltest /dsregdns` and `ipconfig /registerdns` on each | A transfer; the copy compared with every controller's records, type by type, which holds whether or not the controllers' serials differ (R217); the flip of each zone, forward zones first; `transfer.allow` and `notify` naming the controllers; checks: the locator records answered by Tenko | The controllers back to AD-integrated primaries (section 2.10), the DNS clients restored; the reverse flip |
| 5. DHCP window | Per scope: `Set-DhcpServerv4Scope -State InActive` on each server, with the scope id Windows reported, when the job's task opens; checks from the script's host: adopted names and the locator records through Tenko | The takeover job (section 2.7); its task completed by the script; the record read | Tenko's revert; conflict detection on and the scope active on each server |
| 6. Finish, after the parallel period (a second sitting) | The relationship removed, both authorizations removed, the DHCP role removed from both servers, the exporter, its tasks and account removed, the plan's zone objects deleted from the directory partitions (a DNS role install would otherwise serve them stale) | The frozen names released to `manual` after their dry run; the mirrors deleted; the run closed | The way back of section 2.13 step 8, from phase 2's backup |

The DNS Server role stays on the controllers as Tenko's secondaries (WT-Q12); the group policy object stays as part of the end state.

**When a step fails halfway.** The script stops at the step, records it as failed with its error, and prints two choices: run again, which resumes at the step after reading the actual state, or `-Reverse`, which undoes the phase's done steps in reverse order. A failed takeover job rolls itself back (section 2.7); the script then makes the Windows scope active again. When Tenko cannot be reached, `-Reverse` does the Windows half alone and records Tenko's half as pending, so that Windows can serve again without the node.

**The state file.** `%ProgramData%\Tenko\takeover\<domain>\state.json` on the machine that ran the script, with an access list of SYSTEM and Administrators, beside the backups of phase 2. It holds the run's id, the script's version, Tenko's address and the pinned fingerprint, the plan, each step with its state and time, and the values the reverse restores (the transfer and notify lists, the replication scopes, the DNS client addresses, the lease times, the created objects' names and SIDs, the task names, the mirror ids, the group policy object's id). It holds no password, token, session or code. A run resumed on another machine reads the plan from the run on Tenko as values and checks each against Windows, as for any value from Tenko.

**Exit states.** 0 the phase is done; 1 refused before any change (a precondition, a right missing, the person declined); 2 stopped at a failed step (named in the state file); 3 waiting for the person's review or for the parallel period; 4 a value from Tenko disagreed with Windows, and nothing further was changed; 5 reversed.

**Rules for its code.** No `Invoke-Expression`, no script block made from text, no command line built from a value: every value is bound to a typed parameter (`[ipaddress]`, `[int]`, a string checked against its pattern). A remoting session runs script blocks written in the script, with values as arguments. Text from Tenko (an error's detail, a name) is printed only after control characters are removed and its length bounded, so that an answer cannot write escape sequences into the console. A Pester test fails on any of these constructs, beside PSScriptAnalyzer's rule file of the exporter.

#### 2.16.2 The approval

The flow is the device-authorization pattern of RFC 8628 with the code computed on both sides instead of sent:

1. The script makes a P-256 key pair in memory (`ECDsaCng`, .NET Framework 4.7.2), connects to the address without trusting the chain, and reads the root of the presented chain. It sends `POST /api/v1/auth/approvals` (no credential) with the purpose `windows-takeover`, the domain, the public key as its uncompressed point, the script's version, the machine's name and the Windows user's name. Tenko answers with an approval id and a nonce; nothing else.
2. Both sides compute the **code**: the first 60 bits of SHA-256 over a fixed context string, the domain, the SHA-256 of the root, the public key and the approval id, written as twelve characters of Crockford's base32 in three groups (`K7QD-M2XR-9FHA`). The script shows it with the address to open, `https://<address>/approve`.
3. The person signs in to the UI (under Hardened with a passkey) and types the code. Tenko compares it with the code it computes over its own root for each pending approval, in constant time. A match shows the request: the domain, the machine, the Windows user, the source address, the script's version, and what the approval allows. A code that matches nothing is refused; a script that reached Tenko through an interceptor computed its code over another root and cannot match, so the person's comparison of identities is the typing of the code itself. Approving needs a sign-in within the last five minutes (`require_fresh_person`).
4. The script collects with `POST /auth/approvals/{id}/collect`, signing the nonce with its private key (a 64-octet ECDSA signature); Tenko answers once, with the delegated session's secret. The approval is consumed. The script pins the root for the rest of the run and later hands the same fingerprint to the exporter's install, so no fingerprint is copied by hand.
5. The script sends its plan once (`PUT /migrate/runs/{id}/plan`): the zones, controllers, DHCP servers, scopes, the mirror host and the node name it will use. The plan is fixed for the run and narrows the session to its objects.

Bounds: at most eight pending approvals per installation, ten minutes each, one open run per domain, one request per source address every 10 s, a body of at most 16 KiB parsed with strict types; five wrong codes from one session within ten minutes lock that session's lookups for ten minutes.

**The delegated session.** A session of the approving administrator (`Principal::User`, so that every rule that asks for an interactive session reads it as one), with one new field, `delegation: Option<DelegationId>`, on the session record and on the principal, so that every audit record names the run. It is presented as `Authorization: Bearer tnka_…`, never as a cookie, so no browser carries it and no cross-site rule applies. It is not a token: the token API neither creates, lists nor renews it, and a personal token never becomes one. It counts as signed in at the moment of the approval, so the operations that need a sign-in within five minutes (creating a mirror, which mints a token) run in phase 2's first minutes; a later sitting needs a new approval.

What it may call is a fixed operation set in `tenko-auth` (`delegation::TAKEOVER`), checked in `authorize` beside the role check, narrowed to the plan's objects and to the stage of the run:

| Stage | Operations |
|---|---|
| Always | The reads of the run, its zones, mirrors (snapshot, losses, diff), jobs and takeovers; `GET /system/ca-root`; the run's phase reports |
| Before the window | Create the plan's secondary zones and transfer them; the forwarding rules of the plan's forwarders; the plan's zones' update policy and Kerberos settings; `POST /dns/kerberos/adopt` for the plan's account; create the mirrors of the plan's DHCP servers bound to the mirror host's /32, pair them; the prepare of the plan's scopes |
| After the window started | The flip to primary of the plan's zones with the plan's SOA and NS; `transfer.allow` and `notify` naming the plan's controllers; the takeover of the plan's scopes from snapshots the window bound (section 2.16.5); the task of the run's takeover jobs |
| Reverses, at any stage | The revert of the run's takeovers; the reverse flip of the run's zones to the plan's PDC emulator; deleting the run's mirrors and, before a flip, its secondary zones; `release` of the run's zones to `manual` after its dry run (never `delete`) |
| Never | Users, tokens, sessions other than its own end, settings, the profile, backups, secrets, approvals, starting the window, any object outside the plan (403 `auth.delegation.refused`) |

**Lifetime and revocation.** The shorter of eight hours and the profile's absolute session lifetime, with the profile's idle limit (TGL-04; the script's requests keep it active while it runs). It ends when the run is waiting for the parallel period, done, aborted or reversed; when the script ends (it revokes its own session); when the person presses **Revoke** on the run page or revokes it in the session list; and, as every session, when the approver is disabled or loses the administrator role.

**Audit.** `auth.approval.request` (at most once a minute per source), `.approve`, `.deny`, `.collect`, `.refuse` (a code matching nothing, once a minute); `migrate.run.create`, `.plan`, `.phase`, `.window`, `.abort`; and every operation the script calls, with the approver as principal and the run in `delegation`. The run page lists them.

**The flip's interactive rule.** The flip refuses everything but `Principal::User` (`needs_a_session` on `feat/zone-flip`), and `interactive_only` refuses every token on the kinds `mirror` and `takeover`. A delegated session is a `Principal::User` created by a person's fresh interactive approval of one run; it reaches the flip and the takeover only for the plan's objects and only after the person started the window with a second fresh interactive action that a delegated session can never take. A token gains nothing: it stays `Principal::Token`, the rules refuse it as today, and nothing converts one into the other. The check is in `authorize`, which every route calls before its own rule, so the flip's route needs no change.

**Under each profile.**

| Profile | The approver | The session | The mirrors' tokens |
|---|---|---|---|
| Home, Lab | A sign-in within five minutes, at the strength the account has | 8 hours at most, 7 days idle | Bound to the mirror host's /32 by the script, though the profile does not require it |
| Standard | The same; administrators sign in with a second factor (TGL-02) | 8 hours, idle 1 hour | The same |
| Hardened | A passkey (TGL-03) within five minutes, for the approval and again for the window | 8 hours, idle 15 minutes: a script waiting for the review keeps it active; one that ended needs a new approval | Bound, as Hardened requires (section 2.1); certificate binding does not apply to them (ADR 0033) |

**Reused and added.** Reused: the session record, the principal, `authorize` and `interactive_only`, `require_fresh_person`, the session list and its revocation, the token grants inside the creator's roles, the mirror's creation with its source prefixes, the single-use code table and its constant-time comparison of the integration enrollment (ADR 0035), `GET /system/ca-root`, the exporter's certificate check (the same C# class, held equal by a test). Added: the approval table and its five routes, the delegation field and the operation set, the run table and its routes, the run page.

#### 2.16.3 Trust

**The script is the released one.** The administrator downloads the three assets from the release page and runs `powershell.exe -NoProfile -ExecutionPolicy AllSigned -File .\Tenko-Takeover.ps1`. Under `AllSigned` Windows refuses an unsigned or altered script whatever the machine's own policy is, and asks once whether to trust the publisher, showing the signer's name, which the README names. `Get-AuthenticodeSignature` shows the same; `Get-FileHash` against `SHA256SUMS` and `gh attestation verify` prove the file came from the tagged commit's release run. Tenko never serves, generates or links a script, and the UI shows no command to copy: values only, as text (section 4.1 of [active-directory.md](../active-directory.md) already says so for its block).

**Tenko is the right Tenko.** The code binds the root the script saw to the root the person's browser session reached (section 2.16.2, step 3); the script pins it for the run, compares `GET /system/ca-root` with it, and refuses a resumed run whose new approval binds another root. The exporter receives the same fingerprint. The anchor is the person's signed-in browser session on the node, as for every administrative action.

**Each value from Tenko, and its check before use:**

| Value | Used for | Check |
|---|---|---|
| The node's address | Transfer and notify lists, the controllers' primaries, their DNS clients | Equal to the address the pinned connection reached; the node answers each plan zone's SOA over DNS with the serial the API reports |
| The node's name | The SOA `mname`, the NS set, the SPN `DNS/<name>` | One host label under the domain; no computer object and no SPN of that name exists in the directory; shown in the change list |
| Zone names, scope networks, server names | Gates and reports | Members of the script's own discovered plan; anything else is ignored and logged |
| Serials, counts, states, the pushes seen inactive, the window started | Gates only | The scope's state read again on each server with `Get-DhcpServerv4Scope` before and after the step |
| A job's task | When to deactivate | Its text is never run: the script runs its fixed cmdlet with the scope id Windows reported, for a scope of its plan |
| Mirror ids and tokens | The exporter's install | An id of the run's own creations, by pattern; a token by its pattern, held as a `SecureString` and passed only to the installer |
| The root's fingerprint | The pin | Equal to the pinned one |
| Adopted names | The checks after the takeover | Names in a zone the script read from Windows |
| Errors and details | The console | Control characters removed, length bounded |

**The trust boundaries:**

| What | Written by | Executed or used by | With which rights |
|---|---|---|---|
| `Tenko-Takeover.ps1`, the exporter, its installer | The release run, signed | The administrator; the exporter's account on the mirror host | Domain Admins; `DHCP Users` only |
| Answers of the API | The node, as the account `tenko` | The script, as data after the checks above | None of Windows |
| The Windows credential | The administrator, at the prompt | The script's CIM and remoting sessions | Its own; it never leaves the process |
| The delegated session's secret | The node | The script, against the node only | The approver's, narrowed to the plan |
| The mirrors' tokens | The node | The exporter, stored with DPAPI for its account | Writing one mirror each |
| The one-time password of Tenko's computer account | The script, in memory | The node, which replaces it at once | Tenko's own account in the domain (ADR 0026: a member of Domain Computers with its SPN), never the operator's |
| The group policy object | The script, with fixed content | The members, as SYSTEM | One policy value, fixed in the script |
| The state file and the backups | The script | The script | Readable by SYSTEM and Administrators; nothing secret |

**What a compromised Tenko node can still do to a takeover in progress:** lie about its own state (the script stops at the first check Windows or the node's DNS answers contradict, exit 4); refuse or stall (the script stops; `-Reverse` brings Windows back without the node); after the flip and the takeover, serve wrong records in its zones and wrong leases, and feed the controllers' secondary copies, which is what any DNS and DHCP authority can do; read the plan, which the transfer gives it anyway; use its own computer account to read the directory as any domain computer can (WT-Q16). **What it cannot:** obtain the Windows credential; make the script run code; make it act on an object Windows did not report; point a controller at an address other than the one the pinned connection reached; change the exporter or the group policy object; obtain a delegated session without a person typing the code of a script on that person's screen. The delegation guards against a stolen session, not against a compromised node, which enforces its own rules; the Windows side is guarded by the script's checks.

#### 2.16.4 The mirror

The scheduled exporter stays, and the script installs it in phase 2, one task per DHCP server, and removes it in phase 6. The parallel period needs fresh data (the error finding `migrate.mirror.scope_active` when a Windows scope turns active again, section 2.10), and the review needs a diff over pushes the person can read before the window. A script that pushed snapshots itself during its run would leave no token at rest but nobody watching during the week of the parallel period: two servers could answer one network unnoticed. By the priority order the installed exporter wins on security (the bounds ADR 0033 measured, and the watch) at equal performance, and with the install automatic, at equal usability.

Where it runs changes (WT-Q17): by default on a member server that reads each DHCP server over RPC (`-ComputerName`, a new parameter of the exporter, reporting the server's FQDN as `source.server`), which a member of `DHCP Users` can do for all fourteen read cmdlets (measured). Nothing of Tenko then lands on a controller, and the controllers' Default Domain Controllers Policy needs no batch logon right for the task's account. The script installs with the built installer through a remoting session: the two files copied with `Copy-Item -ToSession` and checked by digest there, the token passed as a `SecureString` to `-Token` (encrypted in the Kerberos session), the account a group managed service account where the domain has a KDS root key (the script never creates one), else a user with a random password that exists only in memory and in the task's own store.

#### 2.16.5 Tenko's side

**The UI.** One page, **Windows takeover** (`ui/src/migrate/takeover/`): before a run, the node's address and its root's fingerprint as text and the field for the script's code; during a run, the request it approved (machine, Windows user, version), the phases with the script's reports beside what Tenko observes itself (zones and their serials, the mirrors' freshness, the jobs), what the script found (the plan), the diff and the loss report of each scope, and **Start the window**: one action that acknowledges the loss entries shown, decides the `decide` rows shown (among them option 6 of Tenko's scope with Tenko first, so that Windows' option 6 is not changed), and binds the takeover of each scope to the configuration hash of the push it showed, after a sign-in within five minutes (a passkey under Hardened). A newer configuration refreshes the page and asks again. **Revoke** ends the session; **Abort** ends the run. The mirror page, the zone page and the Scopes tab stay as the manual path; the mirror's Settings tab shows the install's values as text and no longer a command to copy.

**The API beyond what exists:** `POST /auth/approvals` (none), `POST /auth/approvals/lookup` and `POST /auth/approvals/{id}/approve` (an administrator's session, fresh), `POST /auth/approvals/{id}/deny` (session), `POST /auth/approvals/{id}/collect` (the key's signature); `GET /migrate/runs`, `GET /migrate/runs/{id}` (`migrate.read`), `PUT /migrate/runs/{id}/plan` and `PUT /migrate/runs/{id}/phases/{phase}` (the run's session), `POST /migrate/runs/{id}/window` and `DELETE /migrate/runs/{id}` (an administrator's session, never a delegated one; the window fresh). Codes `auth.approval.*` (`not_found`, `expired`, `code`, `limit`, `signature`, `consumed`), `auth.delegation.refused`, `migrate.run.*` (`not_found`, `plan_fixed`, `no_window`, `state`, `binding`). Tables `auth.approvals`, `migrate.runs`.

**The CLI** keeps every command of section 3.2 for the manual path and the labs, and adds `tenko migrate run list|show`. An approval is never given from the CLI: the CLI signs in with tokens, which are not interactive.

#### 2.16.6 Usability, as a requirement with a number

Counted for the reference domain under Hardened, the parallel period's end included. An action is one command run or one submit in the UI; a value is one thing the operator must know or look up and type; pages are the documentation open while working, at 50 lines a page. The plan as it stood counts the commands of sections 2.13 and 2.15 (the owner's "about twenty steps" counts their groups).

| | Windows actions | Tenko actions | Values | Pages |
|---|---|---|---|---|
| Takeover, the plan as it stood | about 54 | about 31 | about 30 (names and addresses of both controllers and the node, the URL, the fingerprint, two mirror ids and tokens, the read account and its password, the scope, three zones, SOA and NS values, the Kerberos account, its unit, SPN and password, the lease times, the member machines, the relationship) | about 20 (the runbook, the exporter's README, this plan's section 2.15) |
| Takeover, this design | 9 (download and run, the publisher prompt, the domain, the address, the credential, the confirmation; the second sitting: run, credential, confirmation), 10 on a workstation, where the mirror host is picked from a list | 5 (sign in and type the code, twice; start the window) | 3 (the domain, offered; the node's address; one's own account), and the code carried from the console to the browser | 1 (the script's README); the run page explains itself |
| Full reverse, the plan as it stood | about 21 | about 10 | about 15 | about 10 |
| Full reverse, this design | 5 (`-Reverse`, the credential, a confirmation for each of the three phases walked back) | 2 (sign in and type the code); none when Tenko is down | 1 and the code | 1 |

Expected grade on the owner's scale: A+. What stands between it and A++ ("a button followed by the zone name"): the node's address typed into the script, the code carried to the browser, the credential prompt and the publisher prompt the conditions require, the second sitting after the parallel period, and, where a network is relayed, the change on the gateway, which the script names but cannot make. E146 holds the design to these numbers in the rehearsal.

#### 2.16.7 What stays, changes and goes

| Piece | Built or planned | Verdict | Why |
|---|---|---|---|
| The push, the mirror service, freshness, losses, diff (WP14.1) | Built | Stays | The script reads them through the API |
| `Tenko-DhcpMirror.ps1` | Built | Changes: `-ComputerName` (WT-Q17), the follow-up's fixes | Runs on the mirror host |
| `Install-TenkoDhcpMirror.ps1` | Built | Stays; called through a session with its existing `-Token` and `-Account` | Its manual use stays documented |
| The mirror's Settings tab with the commands to copy | Built | Changes: values as text | Condition 2: no text from Tenko is run |
| The flip, its reverse and `release` (`feat/zone-flip`) | Built, in review | Stays | The delegated session passes `needs_a_session` only through the delegation check in `authorize` |
| The prepare, the adoption, the takeover job (WP14.2) | Planned | Stays; content 5 changes (section 4) | The service is the same; the script completes the job's task |
| The runbook (WP14.3) | Planned | Changes | It describes what the script does, phase by phase, for reading before a run and for the manual path |
| Section 4.1's static block of the runbook | Built | Stays for the manual path | The script does the same with a generated password |
| Lowering the lease time (section 2.13 step 4, proposed) | Planned | Optional, offered by the script | Continuity does not depend on it; it only shortens the time clients need to reach Tenko |
| Option 6 changed on Windows before the takeover (the takeover line's T34) | Lab entry | Goes from the script path | Tenko's scope gets it by the window's decision; Windows' reverse then restores nothing |

**Where the design waits for the measurements still running.** The SOA serials of the two controllers: the copy is compared record by record with both, so either answer works. Whether the transfer permission follows to the other controller: it is read back on each and set where it did not arrive. What the conversion to a secondary does to the directory copy and to the other controller, and the way back: each controller is brought to the target state by what it holds after replication; the one open point is whether a directory object left behind blocks `ConvertTo-DnsServerPrimaryZone` in the reverse (R223), which the rehearsal answers before WP14.5's reverse of phase 4 is final.

## 3. Contracts and shared files (WP14.0)

### 3.1 Types (`tenko-core`, `tenko-auth`, `tenko-dhcp`)

- `ir`: `MirrorSnapshot { format: u16 (1), sequence: u64, taken_at: Timestamp, source: MirrorOrigin { kind: SourceKindLabel, server: String, adapter: String, adapter_version: String }, dhcp: DhcpIr, losses: LossReport }` with `deny_unknown_fields` on the envelope and the bounds of section 2.1; `SourceLocation` used as `{sheet: <cmdlet>, column: <object key>}` by the exporter. `IrLease`, `IrScope` and `IrReservation` stay as they are; WP14.0 checks that every field the exporter fills validates (a Windows host name with uppercase letters, an option value's text form) and adds a field only by the rule of additive serde defaults.
- `migrate` (new module): `Mirror { id, name, kind, enabled, token: ApiTokenId, account: UserId, interval_secs, last_sequence, last_hash, last_push, last_change, created, updated }`, amended for section 2.15 by `partner: Option<MirrorId>` and the bound server name, both with serde defaults; `Takeover { id, mirror, scope, sequence, state { Done, RolledBack, Reverted }, counts, adopted_leases, adopted_names, frozen_names, skipped: Vec<(Item, Code)>, before: Vec<RrSetImage>, job, at, by }`, amended by the partner's mirror, sequence and lease hash as an optional field with a serde default; `LossAck { mirror, key, entry_hash, by, at }`.
- `auth`: `TokenScope::Mirror(MirrorId)`, serialized `mirror:<id>`; `TokenScope` loses `Copy` or the mirror id moves to a field of its own (WP14.0 chooses; the wire form `mirror:<id>` is the contract).
- `dhcp`: `Lease.adopted: Option<Adopted { mirror: MirrorId, sequence: u64, guessed: bool }>`, a cold field with a serde default and a presence bit (no data format change, as `granted` in ADR 0031); `PendingChange` gains the rekey kind of section 2.8.
- `dns`: the flip and release request types; no new `Origin` value (`Transfer` and `Ad` exist).
- For section 2.16 (WP14.6): `auth::Approval { id, purpose, domain, key (the uncompressed P-256 point), nonce, client { machine, user, version, source }, state { Pending, Approved, Denied, Consumed, Expired }, approver, run, created, expires }`; `SessionRecord.delegation` and `Principal::User.delegation`, both `Option<DelegationId>` with a serde default; `migrate::TakeoverRun { id, domain, approval, approver, session, plan: TakeoverPlan, phases, window: Option<Window { by, at, bindings: [(MirrorId, sequence, configuration hash)], decided }>, mirrors, takeovers, state }` with `TakeoverPlan` bounded (64 zones, 16 controllers, 32 DHCP servers, 256 scopes).
- Tables: `migrate.mirrors`, `migrate.snapshots`, `migrate.takeovers`, `migrate.loss_acks`; for section 2.16 `auth.approvals` and `migrate.runs`. WP14.0 decides whether the namespace, the object kinds and the audit actions are values an older binary cannot decode and therefore need data format 6, as Phase 3's namespace needed 4 ([dhcp-contracts.md](../dhcp-contracts.md) section 13); the upgrade path is then an empty migration with its fixture.

### 3.2 API and CLI

- Push (token only): `PUT /migrate/mirrors/{id}/snapshot` → `200 {"sequence", "changed"}`; 401, 403, 409 `migrate.mirror.sequence`, 413 `migrate.mirror.too_large`, 422 `migrate.mirror.invalid`, 429.
- Management (session, administrator; reads also `migrate.read` for operators): `GET, POST /migrate/mirrors`; `GET, PATCH, DELETE /migrate/mirrors/{id}`; `POST /migrate/mirrors/{id}/token` (interactive only; shows the token once); `GET /migrate/mirrors/{id}/snapshot` (the IR as stored), `GET /migrate/mirrors/{id}/losses`, `POST /migrate/mirrors/{id}/losses/ack`; `GET /migrate/mirrors/{id}/scopes/{cidr}/diff`; `POST /migrate/mirrors/{id}/scopes/{cidr}/prepare`, `.../takeover`, `.../revert` (each answers a job); `GET /migrate/takeovers`, `GET /migrate/takeovers/{id}`.
- DNS: `POST /dns/zones/{id}/flip`, `POST /dns/zones/{id}/release` (with `dry_run`).
- CLI: `tenko migrate mirror list|create|show|token|delete|losses|ack`, `tenko migrate diff <mirror> <cidr>`, `tenko migrate prepare|takeover|revert <mirror> <cidr>`, `tenko dns zone flip <zone> --to primary|secondary ...`, `tenko dns zone release <zone> [--delete] [--dry-run]`.
- Codes: `migrate.mirror.*` (`not_found`, `sequence`, `too_large`, `invalid`, `rate`, `stale`, `scope_active`, `token_expiring`, and for section 2.15 `source` and `partner`), `migrate.takeover.*` (`not_fresh`, `source_active`, `diff`, `zone`, `losses`, `wait_timeout`, and the skip reason `lease_conflict`), `dns.zone.flip.*` (`not_secondary`, `not_primary`, `catalog`); i18n units in `sv` and `en`.
- The approval and the run (section 2.16.5): the routes, codes and audit actions listed there; `tenko migrate run list|show`.
- Annotations per [api/README.md](../api/README.md): the push is the only operation a `mirror:` token reaches; the takeover and the flip are interactive-only; each operation names whether the takeover's delegated session reaches it and at which stage (section 2.16.2).

### 3.3 The UI (the routes stubbed by WP14.0)

The connectors page lists mirrors beside the plugin instances, each with the card of section 2.4. A mirror's page has three tabs: **Scopes** (each mirrored scope with its Tenko counterpart, the diff, and the Prepare, Take over and Revert actions with their states), **Losses** (the entries with their acknowledgment) and **Settings** (name, token, the fingerprint and the install's values as text, deletion; the commands to copy go, section 2.16.3). A zone's page gets **Flip** (for a secondary, with the SOA and NS form) and **Release frozen names** (for a primary that has some). The takeover's job page shows the task of step 2 with the scope and the servers as text, never a command to copy (section 2.16.3), and the wait for the mirror. The **Windows takeover** page of section 2.16.5 is the operator's place for a scripted takeover.

### 3.4 Shared fixtures

- `crates/tenko-core/tests/fixtures/mirror/`: `snapshot.json`, the envelope of a fictitious domain `corp.example.test` (one scope `192.0.2.0/24`, thirty reservations named in every way of section 2.9, sixty leases of each identity kind, options at the three levels, one policy, one filter and one superscope for the loss report), and `snapshot-inactive.json` (the same with the scope inactive); for section 2.15 the partner's view of the same domain (`snapshot-partner.json` and its inactive form, with one lease known to one partner only, one shorter end and one lease conflict).
- `crates/tenko-dns/tests/fixtures/ad-zones/`: the three zones as a transfer would bring them (sixty DHCP names with DHCID, two of them stale, the locator records, `_msdcs`, the reverse zone), with DHCID values computed for type 0 and type 1 so that the identity choice of section 2.8 can be tested both ways.
- `deploy/windows/mirror/tests/fixtures/`: the recorded output of each cmdlet (as `ConvertTo-Json -Depth 6` writes it) that produces `snapshot.json`.

Nothing from a real export enters the repository; the rehearsal's real data stays on the lab node and is deleted at the end.

### 3.5 Shared files the lead owns

REQUIREMENTS.md, SECURITY-PROFILES.md, ROADMAP.md, CONFORMANCE.md, the workspace `Cargo.toml` and `deny.toml` (no new crate is expected: the push is an `axum` route, the IR is `serde`, the exporter is PowerShell), `scripts/requirement-trace.mjs`, the CI workflow files (WP14.1 asks for the Pester and PSScriptAnalyzer jobs; Pester 5 and PSScriptAnalyzer are CI tools under Apache-2.0 and MIT, never shipped).

## 4. Work packages

Every package below touches `crates/tenko-core/src/{ir,migrate}*`, `crates/tenko-migrate/**`, `crates/tenko-api/src/routes/migrate*`, `crates/tenko-dns/src/zone/{flip,secondary}*`, `crates/tenko-dhcp/src/{v4/engine,ddns,takeover}/**`, `deploy/windows/mirror/**`, `ui/src/migrate/**`, `ui/src/dns/**` (the zone actions), and the documents of section 10; within the slice one package owns each file, as listed.

### Slice 14: The Windows takeover

#### WP14.0 The contracts and the two ADRs (4 builder-days)

- **Requirements:** MIG-01, MIG-04, MIG-08 (the shared types).
- **Owns:** section 3 in code: the types and their validation with property tests, the tables, the token scope, the lease field, the route stubs answering 501, codes, audit actions, metric families, the UI route stubs; the fixtures of section 3.4 (the PowerShell fixtures with WP14.1's builder); the data format decision; the two ADRs as Proposed (the mirrored source; the flip and the adoption rule).
- **Depends on:** the owner's decisions (taken for WT-Q1 to WT-Q7; WT-Q8 to WT-Q12 before WP14.2 starts).
- **Acceptance:** the workspace builds; the fixture `snapshot.json` deserializes into `MirrorSnapshot` and round-trips; a lease row with and without `adopted` decodes in both directions; the trace regenerated.
- **Risk:** R144, R148.

#### WP14.1 The exporter, the mirror API and the UI (13 builder-days, two builders in parallel)

- **Requirements:** MIG-01, MIG-08, IAM-10.
- **Owns, the script line (5 days):** `deploy/windows/mirror/**` (the exporter, the install script, the README, the Pester suites and fixtures, the PSScriptAnalyzer rule file), the release workflow's lines that ship the two scripts with their digests (with the lead).
- **Owns, the server line (8 days):** `crates/tenko-migrate/src/mirror/**` (the push, its validation, bounds, sequence and hash, freshness, losses and acknowledgments, the diff), `crates/tenko-api/src/routes/migrate.rs` (the mirror routes), the token scope's check in `tenko-auth`, the CLI's `migrate mirror` and `migrate diff`, `ui/src/migrate/**` (the cards, the mirror page's Losses and Settings tabs and the diff of the Scopes tab), [MIGRATION.md](../MIGRATION.md) section "Windows DHCP" with the WP14.3 builder.
- **Depends on:** WP14.0.
- **Content:** 1. the cmdlet reads and the mapping onto the IR; 2. the loss entries; 3. the account check, DPAPI, the fingerprint pin on both editions; 4. `-Once` and the log; 5. the install and remove script; 6. the push route and its refusals; 7. the snapshot row, the freshness and the findings; 8. the losses and their acknowledgment; 9. the diff; 10. the UI and the CLI.
- **Acceptance:** E72; E73; the diff half of E74; the route tests of [api/README.md](../api/README.md) for the new operations; a Playwright test of the mirror card going stale and fresh again.
- **Risk:** R139, R140, R141, R145, R146.

#### WP14.1a The follow-up for two DHCP servers (3 builder-days)

- **Requirements:** MIG-08, MIG-01.
- **Owns:** the files of WP14.1 that section 2.15 changes, and the `Mirror` and `Takeover` amendments of section 3.1 in `tenko-core`.
- **Depends on:** WP14.1 merged; before WP14.2's takeover step (content 5).
- **Content:** 1. the mirror bound to the server of its first push, the refusal `migrate.mirror.source` and its audit; 2. the `partner` field, its interactive PATCH with both rows in one batch, and `migrate.mirror.partner` for a pairing that is refused (a mirror already paired, itself, a deleted mirror); 3. the diff's `partner` rows; 4. `migrate.mirror.scope_active` and the stale error read for either mirror of a pair; 5. `-AllLeases` in the exporter with the expired leases left out, so that the snapshot is the same under the documented and the measured behavior (section 2.15), with its Pester fixture; 6. the partner fixtures of section 3.4.
- **Acceptance:** route and service tests for each refusal; the diff of the fixture pair shows exactly the fixture's differences; E72 still passes with the expired leases left silent.
- **Risk:** R219.

#### WP14.2 The flip, the prepare, the takeover and their reverses (17 builder-days)

- **Requirements:** MIG-04, MIG-08, DHCP-13, IPAM-17.
- **Owns:** `crates/tenko-dns/src/zone/flip.rs` and the flip's hand-off in `zone/secondary.rs`, the `flip` and `release` routes and commands, the zone page actions; `crates/tenko-dhcp/src/takeover/**` (the prepare, the takeover and the revert jobs, the record adoption, the identity choice), the rekey rule in `v4/engine/mod.rs` with its allocation test rows, the adopted-name rule in `ddns/plan.rs` and `ddns/worker.rs`, the takeover routes and `tenko migrate prepare|takeover|revert`, the Scopes tab's actions and the job page's task; `bench/phase4-takeover/` (M69, M70); [dns.md](../dns.md) sections 1 and 10.6 to 10.7 (the flip, the frozen names, the release) and [dhcp.md](../dhcp.md) sections 9.2 and 13.4 and a new section on the takeover.
- **Depends on:** WP14.0. It reads snapshots from the store and needs nothing of WP14.1's routes, so the two run in parallel; the UI actions follow WP14.1's page.
- **Content:** 1. the flip with the origin table of section 2.6, its reverse and `release` (4 days); 2. the prepare (3 days); 3. the lease adoption with the identity choice, the union of a pair's two pushes (section 2.15) and the engine's rekey rule (4 days); 4. the record adoption and the DDNS rule for adopted rows (3 days); 5. the job, its task and rollback, the record, the audit, the routes, the CLI and the UI actions (3 days). Amended for section 2.16: the task of step 2 shows the scope and the servers as text and no command; the run's delegated session may complete it; a takeover started under a run is bound to the window's bindings (the mirror, the sequence and the configuration hash the person started the window on), refuses a newer configuration with 409 `migrate.run.binding`, and keeps the `decide` rows the window decided (option 6 among them) when the prepare runs again.
- **Left by WP14.1 for this package:** the finding `migrate.mirror.stale` is a warning; that it becomes an error once a scope of the mirror was taken over (section 2.4) is built here, with the takeover record it reads. The stored snapshot keeps the `taken_at` of its last write, because an unchanged push writes nothing and changed leases are written at most every ten minutes: a lease's remaining time is computed from its absolute `expires` or from the `taken_at` of the push the job waits for (section 2.7, step 2), never from the stored `taken_at`, and the leases the job adopts come from that push (`MirrorService::newest` on the controller that received it), never from the stored copy (section 2.4). Whether a loss entry is on the lease side depends on its pushed code (`migrate.loss.lease_state`), so a hostile controller can file any loss there, and a change of it is then written up to ten minutes late and without an audit record: the takeover checks the acknowledgments against the losses of the newest leases it acts on, not against the stored snapshot, and its own audit record names the sequence and the lease hash of the push it adopted, since a change of leases is audited nowhere else. The newest leases are held for three intervals after their push on the controller that took it: the takeover runs where its push arrived, or waits for the next one. The prepare and the takeover bind to the sequence the operator reviewed in the diff, as the acknowledgment of a loss entry binds to the sequence of the report that was read, and refuse with 409 when a newer snapshot came in.
- **Acceptance:** E74 (the prepare half), E75, E76 in the DHCP lab ([`deploy/compose/lab-dhcp`](../../deploy/compose/lab-dhcp)) with `dhclient` clients of each identity kind and the fixture zones; the counting-allocator test still binds the DHCPv4 path; the E22 figure within its tolerance; E80.
- **Risk:** R137, R138, R142, R147, R149.

#### WP14.3 The runbook around the mirror, and the documentation fixes (4 builder-days)

- **Requirements:** MIG-17.
- **Owns:** the rewrite of [active-directory.md](../active-directory.md) (sections 1, 5 to 8 and the DHCP part: the order of section 2.13 with step 0, the lease-time lowering, the registry value, the INIT-REBOOT note, the rollback per phase in two steps, the Windows side of each step as copyable PowerShell); [dns.md](../dns.md) section 13.9 (unsigned updates from an address the zone's lists allow are possible in Home and Standard when the zone switches `require_tsig` off, and in Lab; Hardened refuses them; a Windows host cannot sign with a static TSIG key, which the bullet wrongly implies); [MIGRATION.md](../MIGRATION.md): the connector architecture sentence and Appendix A's transport line for Windows DHCP (the pushed mirror, no remoting), the Windows DHCP row of the sources table, the runbook table's status.
- **Depends on:** WP14.0 for the names of the routes and commands; finished after WP14.2 and before WP14.4's rehearsal.
- **Amended for section 2.16 (3 builder-days instead of 4):** the runbook leads with the scripted path (download, verify, run, approve, start the window, finish) on one page, and describes each of the script's phases with its Windows and Tenko actions and its reverse, for reading before a run and as the manual path; the copyable PowerShell stays only for the manual path and is printed by the documentation, never by Tenko.
- **Acceptance:** E79 apart from the rehearsal row; every command in the runbook exists in the build (a script greps the runbook's `tenko` commands against `tenko --help` output); the placeholders of the runbook only.
- **Risk:** R141, R150.

#### WP14.4 The security rows and the rehearsal (5 builder-days, plus the lab's takeover line)

- **Requirements:** TGL-09, IAM-10, MIG-17, API-18 (partly).
- **Owns:** the rows `ad.*` in `deploy/security/` (with SA3's skeleton of [security-audit-plan.md](security-audit-plan.md); until it lands, a round `takeover` in the DHCP lab carries them), the rehearsal's checklist and result file `bench/phase4-takeover/results/<date>-rehearsal.md` (no real names or addresses), `docs/plans/windows-takeover-exit.md`.
- **Depends on:** WP14.1, WP14.2, WP14.3; for content 4 WP14.5 and WP14.6.
- **The rows:**

  | Row | What is checked | How |
  |---|---|---|
  | `ad.update_unlisted` | An unsigned update from an address not on the controllers' list is refused | `nsupdate` from the scanner container: REFUSED, `dns.update.refuse` audited |
  | `ad.update_spoof` | What the address footing does not protect, kept visible | An update over UDP with a controller's source address (a raw socket in the scanner container) is accepted: `WARN`, with the limit of [active-directory.md](../active-directory.md) section 4 in the report; the same over TCP does not complete its handshake: `PASS` |
  | `ad.xfr_disallowed` | A transfer of an AD zone from an address not on `transfer.allow` is refused | AXFR and IXFR from the scanner container: REFUSED; AXFR over UDP: refused |
  | `ad.dhcid_takeover` | An adopted name and address stay with their client | A client with another MAC asks for an adopted lease's address (NAK) and sends option 81 with an adopted name (refused by name protection, the lease row says so); the rekey rule does not fire for another MAC |
  | `ad.mirror_token` | The mirror token reaches its push and nothing else | Every operation of the served OpenAPI document with the token: 403 except the push; another mirror's push: 403; a replayed sequence 409, an oversized body 413, an invalid IR 422; plain HTTP refused |

- **Content:** 1. the rows; 2. the rest of the takeover line's manifest (section 2.13; its entries marked "now" run as soon as their actors are ready, before this package): the result file with the DHCID identifier type, the times between deactivation and the client's rebinding, and the cmdlet behaviors of R139, R140, R142, R217 and R218; 3. the exit document; 4. (section 2.16) the line's phase 6, the scripted takeover with the usability record of E146, and the rows `ad.delegation` (the delegated session walked through the served OpenAPI document: 403 outside its set and its plan; the flip and the takeover before the window; the window itself) and `ad.approval_code` (a script behind an interceptor with its own root: the code does not match).
- **Acceptance:** E77, E78, E146, the rehearsal row of E79.
- **Risk:** R137, R138, R139, R140, R142, R217, R218.

#### WP14.5 The takeover script (9 builder-days, the script line)

- **Requirements:** MIG-17, MIG-08.
- **Owns:** `deploy/windows/takeover/**` (the script, its README, the Pester suites with recorded cmdlet output and a mocked API, the code test of section 2.16.1); after WP14.1a, the exporter's `-ComputerName` (WT-Q17) and the installer's use through a remoting session in `deploy/windows/mirror/**`, with the mirror README's scripted path; the release workflow's lines that ship, sign and list the three scripts (with the lead, WT-Q15).
- **Depends on:** WP14.1a merged; WP14.6's routes and the code's test vector; WP14.2 for phases 4 and 5 against a node; WT-Q15 to WT-Q17 decided.
- **Content:** 1. discovery, the change list and `-DryRun` (2 days); 2. the state file, resume, `-Reverse` and the exit states (2); 3. the approval client: the key, the code, the pin, the collection (1); 4. phases 2 and 6 on Windows: the accounts, the group policy object, the exporter's install, the backups, the finish (2); 5. phases 4 and 5: replication, the conversions by state, the DNS clients, the scope state (1.5); 6. the checks of section 2.16.3 and the code rules (0.5).
- **Acceptance:** E144; the takeover line's phase 6 runs to its end with this package's script (WP14.4).
- **Risk:** R220, R222, R223, R224.

#### WP14.6 The approval, the delegated session and the run page (9 builder-days)

- **Requirements:** IAM-10, TGL-03, TGL-04, MIG-17.
- **Owns:** `crates/tenko-auth/src/approval/**`, `crates/tenko-auth/src/delegation.rs` and the delegation check in `authz.rs`, the session record's field; in `tenko-core` the principal's field and the run types (the pull request's first line says so); `crates/tenko-migrate/src/run/**`; the routes of section 2.16.5 in `crates/tenko-api/src/routes/`; `ui/src/migrate/takeover/**`, the approval page, the mirror Settings tab's values as text; `tenko migrate run`; the code's test vector `crates/tenko-auth/tests/fixtures/approval-code.json`, which WP14.5's Pester suite reads.
- **Depends on:** WP14.0; WP14.2's takeover job for the window's bindings (content 3).
- **Content:** 1. the approvals: table, routes, the code and its vector, the signature check, the bounds (3 days); 2. the delegated session: the operation set by stage and plan, the check in `authorize`, its end, the audit (3); 3. the run: its plan, its phases, the window with its bindings, acknowledgments and decisions (1.5); 4. the run page and the approval page (1.5).
- **Acceptance:** E145; route tests for every new operation per [api/README.md](../api/README.md); a Playwright test of approval, window and revocation; the new tables additive under data format 6 (ADR 0033, choice b).
- **Risk:** R220, R221.

Total: 63 builder-days (46 before section 2.16; WP14.5 and WP14.6 add 18, WP14.3 gives back one), of which WP14.2 is the critical path (17 days after the contracts); WP14.5 and WP14.6 run beside it.

## 5. Order, measurements and exit checks

### 5.1 Order

WP14.0 first. Then three lines in parallel: the script line of WP14.1, the server line of WP14.1, and WP14.2 (the flip first, so that the record adoption has zones to work on). WP14.3 drafts from WP14.0's names and is finished once WP14.2's behavior is merged. WP14.1a follows WP14.1 and comes before WP14.2's takeover job. WP14.4's rows follow WP14.1 and WP14.2; the takeover line's "now" entries run as soon as the lab is ready, the rest last, with the runbook as written. WP14.6 starts after WP14.0 and finishes its window part after WP14.2's job; WP14.5 starts after WP14.1a and runs against WP14.6's routes; the takeover line's phase 6 comes last. At most two Rust builders at a time beside the other open work; the script lines need no Rust. After the exit: the owner's real cutover, then Slice 13 (WT-Q7).

### 5.2 Measurements

| # | Measurement | Threshold | Package |
|---|---|---|---|
| M69 | The push of an unchanged snapshot of 1,000 reservations and 10,000 leases, 60 s apart and once a second for a minute, on the node of M21; and two mirrors of a pair pushing in the same second (the second is answered within the decode's wait) | p99 of the route under 200 ms; no store write and no audit record for the unchanged ones; the DHCPv4 REQUEST-to-ACK p99 of the lab load unchanged within 5 percent while it runs | WP14.2 |
| M70 | The takeover of a scope with 10,000 leases and 10,000 adopted names, from the push that shows the source inactive to the scope enabled | Under 30 s; the DNS answer for an adopted name never NXDOMAIN during the takeover (a probe once every 100 ms) | WP14.2 |
| M93 | The scripted window in the takeover line (phases 4 and 5 of section 2.16.1), from the person starting the window to the scope enabled, and each controller's time without a zone during the conversions | Under 10 minutes for the lab domain; the gap per zone recorded (R142) | WP14.4 |

## 6. Owner decisions

Each question lists its options, the trade-offs and the recommendation. The owner decided WT-Q1 to WT-Q7 on 2026-11-01 and WT-Q8 to WT-Q12 on 2026-11-05; each ends with the decision. WT-Q13 and WT-Q14 were decided on 2026-11-20. WT-Q15 to WT-Q17 come with section 2.16 and are open.

**WT-Q1. How does the Windows DHCP data reach Tenko?**
- Options: (a) a scheduled PowerShell script on a controller pushes to Tenko's API over HTTPS with a token scoped to write one mirror; (b) Tenko pulls over WinRM with PowerShell remoting, as MIGRATION.md's design said; (c) a Tenko component installed on the controller that Tenko instructs; (d) a periodic `Export-DhcpServer` file copied to Tenko by hand.
- Trade-offs: (b) needs Kerberos or NTLM credentials with DHCP rights stored in Tenko, and a channel through which a compromised Tenko runs commands on a controller; (c) is the same channel with an installed foothold, which the privilege boundary of ADR 0023 forbids; (d) has no credentials but is not live and turns the cutover into a race with the copy; (a) holds no Windows credential in Tenko, keeps the controller's side static and read only, and is live within a minute. DNS needs none of these: the zone transfer with NOTIFY is live already.
- **Recommendation: (a); DNS by the existing transfer.**
- **Decided (2026-11-01): (a), the scheduled script pushes with a token scoped to one source; Tenko never holds a Windows credential and never connects to Windows; DNS data comes by AXFR and IXFR with NOTIFY.**

**WT-Q2. What does the mirror carry, how often, and where does the mapping live?**
- Options: (a) every 60 s: scopes, options at every level, reservations and active leases, with policies, filters and superscopes in the loss report, mapped by the script onto the IR; (b) the full `Export-DhcpServer -Leases` XML pushed raw, mapped by a Windows adapter inside Tenko; (c) configuration only, leases left to the renewals.
- Trade-offs: (b) puts a Windows-specific parser in the core and a large document on the wire every minute; (c) gives up the takeover's continuity (the address protection between the switch and each client's rebinding, the INIT-REBOOT answer, the record adoption); (a) keeps the core source-neutral, with the cost of a mapping written in PowerShell and held to the fixture by tests.
- **Recommendation: (a); the exporter is one adapter, Kea, BIND, dnsmasq and OPNsense adapters are its siblings, and nothing in the core assumes Windows.**
- **Decided (2026-11-01): (a).**

**WT-Q3. What does the takeover do?**
- Options: (a) per scope, in the UI and the CLI: convert the mirrored leases to Tenko leases with their remaining time, adopt the transferred A, DHCID and PTR records of mirrored leases and reservations as `dhcp` records with Tenko's DHCID (the proof is the mirrored lease or reservation), activate the scope, record it; the reverse deactivates the scope and leaves the records; (b) today's step 10: delete the Windows-written records and let the renewals write them anew; (c) adopt at the first renewal, when the client proves its identity.
- Trade-offs: (b) leaves every client without a name until it renews; (c) needs no mirror for the records but trusts a renewal from whoever asks first, and a client that never renews keeps a frozen name; (a) keeps every name served throughout, with the mirror as the proof and the engine's rule for the identity a client presents (section 2.8).
- **Recommendation: (a).**
- **Decided (2026-11-01): (a); it replaces step 10's deletion. Today `conflict = protect` refuses any `transfer` record, which is why the adoption is an explicit action.**

**WT-Q4. How are the reservations' names made?**
- Options: (a) a fully qualified name is kept, a bare host name gets the zone, a factory name is kept as it is; (b) every name made a bare label under the zone; (c) names left out, the operator names hosts later.
- Trade-offs: (b) rewrites names the operator chose; (c) loses thirty names the operator typed once; (a) keeps what is there and adds only the zone.
- **Recommendation: (a), with the reading of WT-Q10.**
- **Decided (2026-11-01): (a).**

**WT-Q5. Which profile?**
- Options: (a) Home now, with unsigned RFC 2136 updates from the controllers' addresses by access list, and Hardened after GSS-TSIG; (b) wait for Slice 13 and take over under Hardened at once; (c) Standard now.
- Trade-offs: (b) delays the takeover by Slice 13's 82 builder-days; (c) adds nothing the reference domain needs over Home except stricter defaults the runbook sets per zone anyway; (a) is the runbook's assumption and the footing whose limits section 4 of the runbook documents.
- **Recommendation: (a).**
- **Decided (2026-11-01): (a), Home now; Hardened after GSS-TSIG (Slice 13, WP13.0 to WP13.4 of identity-plan.md, which stays as planned and follows this slice).**
- **Amended (2026-11-05): the Home profile with the access list stays the path of the rehearsal and of a home user without a domain; the owner's own cutover waits for Slice 13's GSS-TSIG and runs under Hardened from the first day, so that secure updates are the integration test and no interim period takes unsigned updates.**

**WT-Q6. How is the takeover rehearsed?**
- Options: (a) a throwaway domain controller and one Windows client on the owner's hypervisor, the lab node fed by a zone transfer from the real domain and by a read-only mirror of the real DHCP server, in one afternoon, as step 0 of the runbook; (b) the container lab only (Samba AD, `dhclient`); (c) straight to the real domain with the rollbacks ready.
- Trade-offs: (b) cannot show Windows DHCP's DHCID records, the cmdlets' behavior or a Windows client's DHCP sequence; (c) learns those on the real network; (a) learns them on real data without serving it, at the cost of one afternoon and the care of section 2.13.
- **Recommendation: (a).**
- **Decided (2026-11-01): (a), one afternoon, step 0 of the runbook.**
- **Amended (2026-11-20): the rehearsal runs in the existing Windows lab as a second line beside the counted line, with Windows DNS and Windows DHCP on both controllers, run by the lab's operator, an inside observer and the lead (section 2.13); a set of basic tests runs there first.**

**WT-Q7. What comes after this slice?**
- Options: (a) the real cutover, then Slice 13 while the lab controller still stands; (b) Slice 13 first, then the cutover under Hardened; (c) the cutover and Slice 13 in parallel.
- Trade-offs: (b) is WT-Q5 (b); (c) competes for the owner's lab time; (a) uses the rehearsal's lab for E44 of the identity plan.
- **Recommendation: (a).**
- **Decided (2026-11-01): (a).**
- **Amended (2026-11-05): Slice 14 is built and rehearsed first; then WP13.0 to WP13.4 of identity-plan.md on the rehearsal's throwaway domain; then the real cutover under Hardened; then WP13.5 to WP13.8.**

**WT-Q8. Does the takeover adopt `dynamic` names besides `transfer` ones?**
- Options: (a) `transfer` only, as WT-Q3's text says; (b) `transfer`, and `dynamic` names that carry a DHCID and the mirrored lease's address; (c) also `manual` names with a DHCID.
- Trade-offs: under (a), a name Windows DHCP wrote after the flip (a client new to Windows in the window) or during a reverted takeover is `dynamic` and is refused at the first renewal, which brings step 10's gap back for those names; (b) closes that with the same proof as WT-Q3 (a DHCID at the name means a DHCP server wrote it, and the controllers' access list means only the controllers' services write `dynamic` records); (c) would let a takeover change records an operator made.
- **Recommendation: (b).**
- **Decided (2026-11-05): (b), `transfer` names and `dynamic` names that carry a DHCID and the mirrored lease's address.**

**WT-Q9. What origin do the other transferred records get at the flip?**
- Options: (a) `ad`; (b) `manual`; (c) `transfer` kept on every RRset.
- Trade-offs: (c) refuses Netlogon's hourly registration of every locator record (event 5774 every hour, a changed controller address never registered); (b) is updatable but loses the mark that the record came from AD, which Slice 13's claim rule needs (identity plan section 3.6); (a) is updatable from the access list today and governed by the claim rule later.
- **Recommendation: (a).**
- **Decided (2026-11-05): (a), origin `ad`, updatable from the access list and governed by the claim rule later.**

**WT-Q10. What does "a factory name is kept as it is" mean for a name that is not a valid host name?**
- Options: (a) a valid label gets the zone like any bare name; an invalid one is kept as the IPAM host's name, with no record derived and a loss entry; (b) an invalid one is tidied (`ESP_3A1F2B` to `esp-3a1f2b`) and gets the zone; (c) a factory name is recognized by its pattern and never gets the zone.
- Trade-offs: (b) invents a name nobody chose, and the client keeps registering its own under DDNS anyway; (c) guesses at patterns that change by vendor; (a) is decidable by syntax alone and changes nothing the owner typed.
- **Recommendation: (a), the reading section 2.9 writes.**
- **Decided (2026-11-05): (a).**

**WT-Q11. How long does the mirror token live?**
- Options: (a) within TGL-05 (365 days under Home), with the finding `migrate.mirror.token_expiring` 14 days ahead and a replacement from the mirror card; (b) non-expiring for mirror tokens as an exception to TGL-05.
- Trade-offs: (b) avoids a yearly chore but makes one token class an exception to a never-relaxed rule; (a) keeps the rule and makes the chore visible in time.
- **Recommendation: (a).**
- **Decided (2026-11-05): (a), within TGL-05, with `migrate.mirror.token_expiring` 14 days ahead.**

**WT-Q12. What happens to the DNS Server role on the controllers after the flip?**
- Options: (a) it stays, the controllers holding secondary copies of Tenko's zones (the clients' second DNS server) until a second Tenko node exists; (b) it is removed after the parallel period, as today's runbook does; (c) the AD-integrated zones stay frozen as today's runbook does, without becoming secondaries.
- Trade-offs: (b) leaves one Tenko node as the only server of the AD zones until Phase 5; (c) keeps a stale copy that grows staler; (a) keeps a current copy that answers when the node is down and makes the DNS rollback a conversion with current data (section 2.10), at the cost of keeping the role and converting AD-integrated zones to secondaries (R142).
- **Recommendation: (a).**
- **Decided (2026-11-05): (a), the controllers keep the DNS Server role as secondaries of Tenko's zones until a second Tenko node exists.**

**WT-Q13. Under which identity do the two Windows DHCP servers register their clients' names, before and during the parallel period?**
- Options: (a) one dedicated user account, a member of no privileged group and not of DnsUpdateProxy, set as the DNS credential on both servers (`Set-DhcpServerDnsCredential`); (b) the same account, also a member of DnsUpdateProxy; (c) no credential: each server signs as its controller's computer account.
- Trade-offs: (c) is the default and breaks failover's updates (the partner cannot change a name the other owns on Windows) and, in Tenko's zones, signs as a privileged principal that may change any name, the controllers' locator records included: security last. (b) leaves every name it writes without an owner, so any computer of the realm can take one until the takeover adopts it. (a) gives each name one unprivileged owner that both servers share, and the takeover clears it (section 2.8); its cost is one account whose password lives in both servers, changed by hand. The rehearsal sets up whatever the owner's domain has, so that it rehearses the real state; the recommendation is what the cutover should start from.
- **Recommendation: (a), set on the owner's servers before the mirror is installed; security first, at no cost in performance or features.**
- **Decided (2026-11-20): (a), one dedicated unprivileged user account as the DNS credential on both DHCP servers, not a member of DnsUpdateProxy. The owner's domain already works this way and its scope uses DHCP name protection.**

**WT-Q14. Does the rehearsal still read the owner's own domain?**
- Options: (a) no: the takeover line uses only the lab domain, and the owner's real data is first read by the runbook's step 2 on his own node (secondaries and mirrors that serve nothing, the diff and the prepare), with the DHCID identifier type recorded there before the window; (b) yes: as E77 first had it, a read-only transfer and mirror of the real domain into the lab node for an afternoon.
- Trade-offs: (b) shows the real names and the real DHCID type earlier, at the price of a transfer permission and an exporter task on the real controllers pointed at a lab node, and of real names on a machine whose results are filed in a public repository; (a) touches nothing real until the owner's own node, which reads the same data under the same restrictions, and learns the real DHCID type one step later, still before any client is affected.
- **Recommendation: (a); security first, and step 2 of the runbook gives the same reading without a second copy.**
- **Decided (2026-11-20): (a), the rehearsal reads only the lab domain.**

**WT-Q15. How is the takeover script signed?**
- Options: (a) an Authenticode code-signing certificate whose key lives in a cloud signing service or on a hardware token, used by the release's existing signing step for the three scripts, and the release fails rather than ship them unsigned; (b) no Authenticode: the digest in `SHA256SUMS` and the release's provenance attestation, checked by hand, the script run with `-ExecutionPolicy Bypass`; (c) a certificate of the project's own that each administrator imports once as a trusted publisher.
- Trade-offs: (b) meets condition 1 through the attested release, but rests on a check the person may skip, and a run with `Bypass` checks nothing; today's release signs Windows files only when its signing secrets exist and ships them unsigned otherwise. (c) asks every administrator to trust a root the project made, on every machine. (a) lets Windows check the signature at every run under `AllSigned` and shows the publisher; its cost is the certificate's yearly fee and the signing secrets in the release run.
- **Recommendation: (a), security first at no cost in performance or usability; until it is in place the scripts ship with (b)'s checks, and the owner's cutover waits for (a).**

**WT-Q16. How do the zones take updates after a scripted flip?**
- Options: (a) secure updates with GSS-TSIG under every profile, the script creating Tenko's computer account of [active-directory.md](../active-directory.md) section 4.1 with a one-time password it generates; (b) by the profile: GSS-TSIG under Hardened, unsigned updates from the controllers' addresses (WT-Q5's footing) under the others; (c) the zone's own mode on Windows carried over: secure only becomes (a), nonsecure and secure becomes the access list.
- Trade-offs: (b) keeps Tenko out of the directory under Home and Standard, but takes updates whose source address can be forged over UDP (`ad.update_spoof`). (a) signs every update and gives each name an owner, at the price that Tenko holds a computer account of the domain, which reads the directory as any domain computer can (ADR 0026, accepted; WT-Q5 as amended already takes it for the owner's cutover); that account is Tenko's own identity, not a right of the operator's, which is how this plan reads condition 3. (c) asks the operator nothing and, for the reference domain and every domain left on Windows' default, is (a).
- **Recommendation: (c), which is (a) for the reference domain; security first, no new question for the operator.**

**WT-Q17. Where does the exporter run during a scripted takeover?**
- Options: (a) one task per DHCP server on a member server, reading its server over RPC with `-ComputerName`, the tokens bound to that host; (b) on each DHCP server as built, with the batch logon right granted to the task's account in the Default Domain Controllers Policy by the script; (c) on the machine that runs the script, a workstation included.
- Trade-offs: (b) puts a task, an account with batch logon and a token on each controller and changes the controllers' policy. (c) stops pushing when the workstation sleeps, so the mirror turns stale in the parallel period, an error finding. (a) keeps the controllers free of anything of Tenko (a member of `DHCP Users` reads all fourteen cmdlets over RPC, measured), at the cost of a parameter in the exporter, a member server that stays on and the DHCP management tools on it.
- **Recommendation: (a), security first; (b) where the domain has no member server.**

## 7. Requirement rows touched

No new requirement IDs. Proposed edits to the lead's files, to be applied with the decisions:

| Row | Today | Proposed |
|---|---|---|
| MIG-08 | "Source: Windows DHCP. `Export-DhcpServer -Leases` (XML) plus the `Get-DhcpServerv4*` cmdlets for scopes, reservations, ..." | Adds: "The source is a scheduled exporter on the DHCP server that pushes the IR every minute to Tenko's API with a token that can write only that source (the mirror); Tenko holds no Windows credential and does not connect to Windows." |
| MIG-04 | "... flip (Tenko becomes primary; the old server becomes its secondary or is switched off after a rollback window)." | Adds: "A flip keeps every record with its provenance and is reversible; for DHCP the flip is the per-scope takeover of the mirrored leases and records." |
| MIG-17 | "Migration runbooks in MIGRATION.md." | "Migration runbooks, listed in MIGRATION.md; the Windows DNS and DHCP runbook is [active-directory.md](../active-directory.md), validated by a rehearsal in the Windows lab." |
| CONN-12 | "External DHCP actuators for coexistence: Windows DHCP via PowerShell and Kea ..." | Unchanged; the Windows takeover does not use it (section 1.4) |

ROADMAP: the Phase 4 deliverables gain the line for this slice (written with this plan). MIGRATION.md (WP14.3): the Windows DHCP row and the transport sentence. CONFORMANCE.md: no RFC row changes; RFC 4701 and 4703 gain the note that adopted DHCID records are rewritten under Tenko's computation.

## 8. Risks

| # | Risk | Proposed resolution |
|---|---|---|
| R137 | The DHCID identifier type Windows uses is unknown until the rehearsal, so the adoption may guess a client's identity wrongly | The identity choice of section 2.8 compares both candidates against Windows' record; the engine's rekey rule and the DDNS rule for adopted rows make a wrong guess harmless for the same MAC; E76 tests both guesses; E77 records the real answer |
| R138 | The mirror lags at the moment of takeover: a lease Windows granted after the last push is missing | The takeover waits for a push that shows the scope inactive, which follows the last grant; a missing lease is taken back at its rebinding as today (a free pool address with no record is ACKed); the conflict probe guards an INIT-REBOOT client's old address |
| R139 | `Get-DhcpServerv4Lease` behaves otherwise than assumed. Measured on Windows Server 2025 on 2026-11-20: an inactive scope returns its leases unchanged; a member of `DHCP Users` reads every cmdlet over RPC; without `-AllLeases` the cmdlet returns active and declined leases and the reservations, unlike Microsoft's page, and `-AllLeases` adds the expired ones | WP14.1a passes `-AllLeases` and leaves the expired leases out, which is the same snapshot under both behaviors; an older Windows Server is read in the rehearsal's cmdlet notes when one is available |
| R140 | PowerShell 5.1 on an older controller (.NET Framework before 4.7.1) lacks the certificate callback the pin needs | The script uses `ServicePointManager`'s callback on 5.1 and `HttpClientHandler`'s on 7; the Pester suite runs on both; the README names the minimum (Windows Server 2016 with its current .NET) |
| R141 | A controller is multi-homed: NOTIFY and updates come from an address not on the lists | The runbook lists every controller address in the access list and the transfer source; NOTIFY from another address falls back to the SOA refresh; the rehearsal shows which address each controller uses |
| R142 | Converting an AD-integrated zone to a secondary removes it from the directory partition on every controller at once, `_msdcs` from the forest partition | The runbook converts one zone at a time, `_msdcs` last: on `dc1` with `ConvertTo-DnsServerSecondaryZone`, then replication, then on `dc2` `Add-DnsServerSecondaryZone` (between the two, `dc2` answers nothing for the zone; the clients ask Tenko first); the way back converts on `dc1` with `ConvertTo-DnsServerPrimaryZone` and removes `dc2`'s file-backed copy so that it loads the directory's; the rehearsal runs both and measures `dc2`'s gap; the exports of step 1 stay the backup |
| R143 | The single Tenko node is the AD zones' only primary until Phase 5 | The controllers' secondary copies keep answering (WT-Q12) and are the clients' second server; Tenko's SOA `expire` for the AD zones at 14 days so the copies outlive an outage; updates wait for the node (Netlogon retries hourly) |
| R144 | A new namespace or object kinds force data format 6 | WP14.0 decides it first; an empty migration with its fixture, as Phase 3 did |
| R145 | The mirror token leaks from the controller | It writes one mirror and reads nothing; DPAPI for the task account; replacement from the card; a forged snapshot can change only what a person later prepares or takes over, behind the diff and the loss acknowledgment |
| R146 | The exporter's PowerShell mapping drifts from the IR | The fixture IR is shared with the Rust tests; the push validates strictly; a refused push is a finding within three minutes |
| R147 | The rekey rule lets a client claim an adopted lease with a forged MAC | Only a REQUEST with the row's MAC on the same network, the same exposure as any DHCP client today; `ad.dhcid_takeover` tests another MAC; the rule ends at the first REQUEST |
| R148 | Parallel work: this slice beside Slice 12, the UI plan and Phase 3's remainder | At most two Rust packages at once; the script line needs none; the lab and the rehearsal while no package is running |
| R149 | The frozen names between the flip and the takeover go stale if the window is split | The runbook does both in one window; WT-Q8 (b) adopts what Windows wrote meanwhile; `release` handles the rest |
| R150 | The runbook's PowerShell drifts from the cmdlets of newer Windows Server versions | Every cmdlet named with its Microsoft page in the Sources; the rehearsal runs them; `Get-Help` checks noted where a page was not found |
| R217 | Each Windows DNS server keeps its own SOA serial for an AD-integrated zone, so a copy taken from one controller can lag the other's registrations, and a second primary in the secondary zone's list can mislead the serial check | One primary per secondary zone (section 2.15); replication forced and a transfer taken before the flip; the rehearsal reads both serials |
| R218 | A scope deactivated on one partner only: the other keeps answering its share, or in a partner state all clients, beside Tenko | The takeover waits for both mirrors to show the scope inactive; `migrate.mirror.scope_active` for either afterwards; Microsoft documents no automatic copy of the state, and none happened within five minutes (measured on 2026-11-20) |
| R219 | Two exporters installed with one mirror: alternating snapshots, a write and an audit record every push | WP14.1a binds a mirror to its server; until then the install script's mirror id is checked by hand on each server |
| R220 | A person types the code of a script someone else runs, after being talked into it | The approval page shows the machine, the Windows user, the source address and the version; the session reaches nothing that serves before the person starts the window, a second decision on a page that shows the plan; one run per domain at a time; **Revoke** on the run page |
| R221 | The delegated session is a new reach into interactive-only operations | The operation set is fixed in code, checked in `authorize` for every route, narrowed to the plan and the stage; a route added later is outside it until listed; `ad.delegation` walks the served OpenAPI document |
| R222 | WinRM does not reach a controller or the mirror host from the administrator's machine | Phase 0 opens every session before the change list is shown and stops with exit 1, naming the host and the port |
| R223 | The conversion of an AD-integrated zone and its reverse differ from R142's assumption (a directory object left behind that blocks the reverse conversion, a second controller still loading it); being measured | Each controller is brought to the target state by what it holds; the reverse of phase 4 is finished after the measurement; the finish deletes the plan's zone objects |
| R224 | The release ships the scripts unsigned (WT-Q15 open) | WT-Q15 (a) makes the release fail instead; until then the digest and the attestation, checked by hand |

## 9. Owner actions

| When | Action |
|---|---|
| Before WP14.0 | Read the plan (WT-Q1 to WT-Q7 decided on 2026-11-01, WT-Q8 to WT-Q12 on 2026-11-05) |
| Before the rehearsal | Nothing to answer: WT-Q13, WT-Q14 and the kind of replication (failover in load balance) are decided; the takeover line itself is run by the lab's operator, the inside observer and the lead |
| Before WP14.5 starts | WT-Q15 to WT-Q17 (section 2.16) |
| The takeover | The script from the release, verified; its first sitting (discovery, approval, phase 2), the review and **Start the window** on the run page; the relay on the gateway where a network is relayed |
| After the parallel period | The script's second sitting (phase 6): the DHCP Server role removed; the DNS Server role kept as Tenko's secondary (WT-Q12) |

## 10. Documents this slice writes

| Document | Package |
|---|---|
| ADR for the mirrored source (proposed 0033) and ADR for the flip and the adoption rule (proposed 0034; ADR 0032 is the plugin model), the lead numbering them | WP14.0 |
| [active-directory.md](../active-directory.md), rewritten around the mirror | WP14.3 |
| [dns.md](../dns.md) sections 1, 10.6, 10.7 (the flip, frozen names, release) and 13.9 (the profiles) | WP14.2, WP14.3 |
| [dhcp.md](../dhcp.md) sections 9.2, 13.4 and a new section "The takeover of a scope" | WP14.2 |
| [MIGRATION.md](../MIGRATION.md): the Windows DHCP source, the transport, the runbook table | WP14.3 |
| `docs/dhcp-contracts.md` section 11: the cmdlet names beside the XML elements | WP14.1 |
| `deploy/windows/mirror/README.md` | WP14.1 |
| [connectors.md](../connectors.md): a section on mirrored sources | WP14.1 |
| `bench/phase4-takeover/` with the M69, M70 and rehearsal results | WP14.2, WP14.4 |
| [`deploy/compose/lab-ad/windows/takeover/README.md`](../../deploy/compose/lab-ad/windows/takeover/README.md), the takeover line's start state and manifest (written with the amendment of 2026-11-20); its evidence in `results/` beside it | WP14.4 |
| `docs/plans/windows-takeover-status.md`, `docs/plans/windows-takeover-exit.md` | the lead; WP14.4 |
| [ADR 0038](../adr/0038-takeover-script-and-delegated-session.md), the takeover script and its delegated session (Proposed, written with section 2.16) | Accepted when E144 and E145 pass |
| `deploy/windows/takeover/README.md` | WP14.5 |

**The trace.** `scripts/requirement-trace.mjs` traces Phases 1 to 3 only; E72 to E80 belong to Phase 4. This plan names requirements of Phases 1 to 3 (DHCP-13, IAM-10, IPAM-17, API-17, TGL-09, TGL-29), so the Phase 1 and Phase 3 trace files count it among the documents that name them; the lead regenerates them with this plan (`node scripts/requirement-trace.mjs` and `--phase 3`). When Phase 4 gets its trace, the lead adds this plan to its entry in `PHASES`.

## 11. Sources

The facts about Tenko come from the code and the documents read on `8e4f4112` (section 1.7 and the two research notes of 2026-11-01, which name their files and lines). The Windows behavior this plan relies on is marked as a risk where it was not verified (R137, R139, R140, R142); WP14.1 and WP14.3 read the pages below before their text relies on them, and the rehearsal checks them on Windows.

Specifications:

- RFC 2131, DHCP (the client states, INIT-REBOOT silence, T1 and T2): https://www.rfc-editor.org/rfc/rfc2131.html
- RFC 4361, node-specific client identifiers: https://www.rfc-editor.org/rfc/rfc4361.html
- RFC 4701, the DHCID record: https://www.rfc-editor.org/rfc/rfc4701.html
- RFC 4702, the client FQDN option: https://www.rfc-editor.org/rfc/rfc4702.html
- RFC 4703, resolution of FQDN conflicts among DHCP clients: https://www.rfc-editor.org/rfc/rfc4703.html
- RFC 2136, dynamic update: https://www.rfc-editor.org/rfc/rfc2136.html
- RFC 1995, RFC 1996 and RFC 5936, IXFR, NOTIFY and AXFR: https://www.rfc-editor.org/rfc/rfc1995.html, https://www.rfc-editor.org/rfc/rfc1996.html, https://www.rfc-editor.org/rfc/rfc5936.html

Microsoft, to be read by WP14.1 and WP14.3:

- The DhcpServer module (`Get-DhcpServerv4Scope`, `Get-DhcpServerv4Lease`, `Get-DhcpServerv4Reservation`, `Get-DhcpServerv4OptionValue`, `Get-DhcpServerv4DnsSetting`, `Set-DhcpServerv4Scope`, `Export-DhcpServer`): https://learn.microsoft.com/en-us/powershell/module/dhcpserver/
- The DnsServer module (`ConvertTo-DnsServerSecondaryZone`, `ConvertTo-DnsServerPrimaryZone`, `Set-DnsServerPrimaryZone`): https://learn.microsoft.com/en-us/powershell/module/dnsserver/
- Scheduled tasks (`Register-ScheduledTask`, `New-ScheduledTaskPrincipal`): https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/
- `ConvertFrom-SecureString` and DPAPI: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring
- Enable or disable DNS dynamic registration (`DisableDynamicUpdate`): https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/enable-disable-dns-dynamic-registration
- Configuring Name Protection (archived): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd759188(v=ws.11)

Tools for CI only: Pester (https://pester.dev), PSScriptAnalyzer (https://github.com/PowerShell/PSScriptAnalyzer).

Project documents: [MIGRATION.md](../MIGRATION.md), [active-directory.md](../active-directory.md), [dns.md](../dns.md) sections 6, 10 and 13, [dhcp.md](../dhcp.md) sections 9, 13 and 17, [dhcp-contracts.md](../dhcp-contracts.md) section 11, [identity-plan.md](identity-plan.md), [security-audit-plan.md](security-audit-plan.md), [jobs.md](../jobs.md), ADR 0006, ADR 0012, ADR 0020, ADR 0023, ADR 0026, ADR 0030, ADR 0031.
