# Windows takeover plan: DNS zones and DHCP off the domain controllers, step by step and reversible

- Status: Accepted on 2026-11-01 for the decisions of section 6 that the owner took that day (WT-Q1 to WT-Q7); WT-Q8 to WT-Q12 are open and carry a recommendation. The plan binds and changes only through rule 2.8 of the execution plan. The owner's standing direction, single node first and cluster-aware (section 2.10 of [phase-2-plan.md](phase-2-plan.md)), binds this work; section 2.14 says how
- Date: 2026-11-01
- Scope: Slice 14, Phase 4's first slice. An operator moves the DNS zones and the DHCP service of a small Active Directory domain from the domain controllers to Tenko with no client noticing, each step reversible, rehearsed first on a throwaway domain. DNS data arrives by zone transfer; DHCP data arrives by a mirror that a scheduled script on a controller pushes to Tenko's API; a takeover action per scope turns the mirror into Tenko's own leases and records. Written against `main` at `8e4f4112`. Requirement IDs refer to [REQUIREMENTS.md](../REQUIREMENTS.md), toggles (TGL) to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md). Exit criteria, measurements and risks continue the project's series: E72 onward, M69 onward and R137 onward (the high-availability plan ends at E71 and M68, the identity plan at R136)

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

**The domain this is for.** The reference domain is small and common: one zone for everything (the AD domain zone is also the zone of the clients, with about sixty names registered by Windows DHCP, each with a DHCID record because name protection and aging are on), `_msdcs` as a zone of its own, AD-integrated storage, two controllers, reverse zones, conditional forwarders, one Windows DHCP server with one scope over the whole client network and about thirty reservations with mixed naming, no DHCP policies, no IPv6, no DHCP failover, and fewer than five domain-joined Windows machines whose own DNS registration is switched off per machine by a registry value. Every name and address in this plan is a placeholder as in [active-directory.md](../active-directory.md): `corp.example.test`, `_msdcs.corp.example.test`, `dc1` and `dc2` at `192.0.2.5` and `192.0.2.6`, `tenko1` at `192.0.2.53`, the client network `192.0.2.0/24` with its reverse zone `2.0.192.in-addr.arpa`.

**What changes.** Today's runbook ([active-directory.md](../active-directory.md), steps 1 to 11) copies the zones once by transfer, exports and re-imports them as `manual` records, builds the DHCP scope by hand from `Export-DhcpServer`, and before the DHCP switch deletes every record Windows DHCP wrote (step 10), so that each client is without a name until it renews. This slice replaces the copies by live feeds and the deletion by an adoption:

1. **DNS by transfer, kept live.** Tenko is a secondary of every AD zone (AXFR and IXFR with NOTIFY from the controllers) until the operator flips a zone. The flip turns the secondary into a primary in place and keeps every record with its provenance (section 2.6); the controllers then hold their copies as secondaries of Tenko.
2. **DHCP by a mirror.** A static PowerShell script, scheduled every 60 s on a controller under an account that can only read DHCP, reads the scopes, the options at every level, the reservations and the active leases, turns them into the source-neutral intermediate representation (IR) of [MIGRATION.md](../MIGRATION.md) and pushes it to Tenko's API over HTTPS with a token that can do nothing but write that one mirror. Tenko never holds a Windows credential and never connects to Windows.
3. **A takeover per scope.** In the UI and the CLI, one action converts the mirrored leases to Tenko leases with their remaining time, adopts the A, DHCID and PTR records of the mirrored leases and reservations as Tenko DHCP's own (with Tenko's DHCID; the proof is the mirrored lease or reservation, not a renewal), activates the Tenko scope and records what it did. The reverse action deactivates the Tenko scope and leaves the records; the operator activates the Windows scope again.
4. **A rehearsal first.** Step 0 of the runbook is one afternoon on a throwaway domain controller and one Windows client on the owner's hypervisor, with the lab node fed by a zone transfer from the real domain and by a read-only mirror of the real DHCP server.

**What stays.** The controllers stay controllers, Tenko joins nothing and holds no directory data (CON-11). Under the Home profile the controllers register their locator records by unsigned RFC 2136 updates accepted by address (today's footing, section 4 of the runbook); the Hardened profile becomes possible with GSS-TSIG in Slice 13 ([identity-plan.md](identity-plan.md) WP13.0 to WP13.4), which stays as planned and follows this slice. Nothing in the core assumes Windows: the mirror is a source kind that any adapter can feed with the same IR (Kea, BIND, dnsmasq and OPNsense adapters are its siblings), and the takeover acts on the IR and on records, never on Windows. Active Directory integration is always an option, never a requirement.

### 1.2 Exit criteria

| # | Check | Requirements | Package |
|---|---|---|---|
| E72 | The exporter: on PowerShell 5.1 (a hosted Windows runner) and 7 (Linux and Windows runners), the Pester suite over recorded cmdlet output with documentation addresses produces the fixture IR byte for byte, puts every policy, filter, superscope, failover relationship and scope delay in the loss report with its source location, refuses to start as a member of a privileged group, and `-Once` prints the IR and the loss report without pushing; PSScriptAnalyzer reports nothing above its rule file; the install script registers the task under the given account and stores the token with DPAPI for that account only | MIG-01, MIG-08 | WP14.1 |
| E73 | The push: a push with the mirror's token is accepted, an unchanged push writes nothing to the store and no audit record, a changed one writes one snapshot row and one `migrate.mirror.push`; the token is refused on every other operation of the OpenAPI document (403) and on another mirror's push; an older sequence (409), a body above the bound (413), an IR that does not validate (422 with the path of the first error) and a push faster than the floor (429) are refused and audited at most once a minute; the mirror card shows its freshness and turns stale after three missed intervals with the finding `migrate.mirror.stale` | MIG-01, IAM-10 | WP14.1 |
| E74 | The diff and the prepare: from the fixture snapshot, the diff lists every difference against Tenko's scopes by kind; the prepare job creates a disabled scope whose pool, exclusions, options at server, scope and reservation level, reservations (with the name rule of section 2.9) and DDNS settings equal the mirror's, attaches to IPAM hosts that already hold a reservation's MAC or address instead of duplicating them, and a second prepare changes nothing; every loss entry must be acknowledged before the prepare runs | MIG-08, MIG-03 (partly) | WP14.1, WP14.2 |
| E75 | The flip: a secondary holding the fixture AD zones (the domain zone with sixty DHCP names, `_msdcs`, the reverse zone) flips to primary in place with the origins of section 2.6; an unsigned update from the controllers' access list changes a locator record; an update of a frozen DHCP name is refused and audited; the reverse flip makes it a secondary again and the next transfer replaces its records; `release` turns the remaining frozen names into `manual` records | MIG-04 | WP14.2 |
| E76 | The takeover in the DHCP lab: with the fixture mirror and the flipped zones, the job waits for a push that shows the source's scope inactive, adopts every mirrored lease with its remaining time and every name of section 2.8 as `dhcp` records with Tenko's DHCID, enables the scope and writes `dhcp.scope.takeover` with its counts; a client of each identity kind (option 61 of type 1, no option 61, an RFC 4361 DUID) renews and rebinds and keeps its address and its name, also when the identity guessed at adoption was wrong; a client with another MAC that claims an adopted name or address is refused; INIT-REBOOT of an adopted client is answered; the reverse action disables the scope and leaves leases and records; a failed job rolls back to the state before it | MIG-04, MIG-08, DHCP-13 | WP14.2 |
| E77 | The rehearsal (owner-run, one afternoon): on the throwaway domain the full runbook from step 0 to the parallel period, then the rollback of each phase and the way forward again; the Windows client keeps its address, its name and its domain logon through every step (`ipconfig /all`, `nltest /dsgetdc:corp.example.test /force`, `Resolve-DnsName`), with no NAK in Tenko's counters; on the real data (transfer and read-only mirror into the lab node, never served), the prepare and a dry takeover of the real scope run, and the DHCID identifier type Windows uses is recorded from the real records | MIG-17, API-18 (partly) | WP14.4 (owner-run) |
| E78 | The security rows `ad.*` of the round `security` ([security-audit-plan.md](security-audit-plan.md) section 4.2) pass on the release binary: spoofed and unlisted updates, a transfer from a disallowed address, a DHCID takeover from the wrong client, the mirror token's scope | TGL-09, IAM-10 | WP14.4 |
| E79 | The runbook: [active-directory.md](../active-directory.md) rewritten around the mirror and followed end to end in the rehearsal; [dns.md](../dns.md) section 13.9 states the profiles correctly; [MIGRATION.md](../MIGRATION.md) says that the Windows DHCP source is the pushed mirror | MIG-17 | WP14.3 |
| E80 | M69 and M70 measured on the musl binary and recorded in `bench/phase4-takeover/results/` | API-17 | WP14.2 |

### 1.3 The slice

| Slice | Content | Closes |
|---|---|---|
| 14. The Windows takeover | The contracts and two ADRs; the exporter script and its scheduled task; the mirrored source with its push, freshness, diff and loss report; the flip of a zone and its reverse; the prepare, the takeover and the reverse of a scope; the runbook around the mirror; the security rows; the rehearsal | E72 to E80 |

After this slice, in the owner's order (WT-Q7): the real cutover at home with the runbook, then Slice 13 while the lab controller still stands.

### 1.4 Requirements

| Requirement | What this slice delivers | Phase today |
|---|---|---|
| MIG-08 Windows DHCP source | Partly: scopes, pools, exclusions, options at every level, reservations, DNS settings and active leases by the pushed mirror; policies, filters, superscopes and failover relationships to the loss report (WT-Q2) | 4, Must |
| MIG-04 Coexistence modes | Partly: secondary (exists) and flip, in place and reversible, for DNS; the per-scope takeover as the flip of DHCP. Forward mode exists as forwarding rules and is not touched; the nightly parity diff is left out (section 1.6) | 4, Must |
| MIG-17 Runbooks | The Windows DNS and DHCP runbook, validated in the rehearsal | 4, Must |
| MIG-01 IR and loss report | The exporter is an adapter that produces `DhcpIr` and a `LossReport`; the core consumes nothing else | 4, Must |
| MIG-02 AXFR as the baseline | Used as is for every AD zone | 4, Must |
| MIG-03 The pipeline | Partly: the prepare and the takeover run as jobs with steps and rollback (IPAM-17); `tenko migrate plan`, `apply` and `verify` as commands are not built here | 4, Must |
| API-18 Windows interop lab | Partly: the throwaway domain of the rehearsal; GSS-TSIG and the full MIG-18 domain stay with Slice 13 and later | 4, Must |
| CONN-12 External DHCP actuator | Explicitly not: nothing in this slice writes to Windows; the operator deactivates and activates the Windows scope | 4, Should |
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
| [identity-plan.md](identity-plan.md) section 3.9: WP13.4 rewrites sections 4 to 6 of the runbook for GSS-TSIG | WP14.3 writes the mirror version first; WP13.4 revises it on top |
| The `Ad` variant of `Origin`, set by nothing (identity plan section 1.5) | The flip sets it (section 2.6), in the meaning identity plan section 3.6 gives it |

### 1.6 Left out, with reasons

| Item | Reason | Goes to |
|---|---|---|
| WinRM, PowerShell remoting or any Tenko connection to Windows | WT-Q1: it needs Kerberos or NTLM credentials in Tenko and a channel through which Tenko's wishes run on a controller | Not built for this source |
| Writing to Windows DHCP or Windows DNS (CONN-12, CONN-13) | WT-Q1 and ADR 0023's boundary; the operator's two PowerShell lines per scope are the whole Windows side | The actuator package, if ever |
| A Windows DNS adapter (MIG-06, MIG-07): owner SIDs, aging timestamps, server settings | The transfer carries the records; ownership waits for GSS-TSIG, aging for DNS-29; the forwarders are entered by hand (a handful) | Phase 4, later packages |
| Policies, filters, superscopes, failover relationships | WT-Q2: to the loss report; the reference domain has none | MIG-08's remainder |
| Split scopes during coexistence | The takeover is a clean switch per scope; Tenko has no offer delay; two servers on one network are what the runbook avoids | Not needed |
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
2. **A token that can write one mirror and nothing else.** Creating the mirror creates a service account `mirror-<name>` with no grants and one scoped token whose only special scope is `mirror:<id>`. The push route accepts exactly that scope for exactly that id; every other operation answers 403 to that token, including reads of its own mirror, so a stolen token gives neither data nor reach. The token is shown once, expires within TGL-05 (WT-Q11), and is replaced from the mirror card; the old one stops at once.
3. **The script is static and comes with the release.** It is in the release assets and in the repository, versioned with Tenko and listed in `SHA256SUMS`; the documentation says to compare the digest before copying it to the controller. Tenko never serves it, never generates it and never updates it: a compromised Tenko node cannot change what runs on a controller (the privilege boundary of ADR 0023: a more privileged account never runs what a less privileged one wrote).
4. **The script runs with DHCP read rights only.** A domain account (a group managed service account where the domain has a KDS root key, else a user account with a long random password) that is a member of `DHCP Users` and of no privileged group, with the right to log on as a batch job on the controllers that run DHCP. The script refuses to start when its account is a member of `Domain Admins`, `Enterprise Admins`, `Administrators`, `DHCP Administrators` or `DnsAdmins` (a check of its own token's groups), so a convenient misconfiguration fails loudly.
5. **The script verifies Tenko.** The install script takes the SHA-256 fingerprint of Tenko's certificate authority (shown on the mirror card) and the script accepts only a chain ending in it; nothing is added to the controller's trust store. The token is stored with DPAPI for the task's account (`ConvertFrom-SecureString` without a key), readable by nothing else on the controller.
6. **Bounds and replays.** A body of at most 8 MiB (gzip allowed, 32 MiB inflated), at most 1,000 scopes, 10,000 reservations and 100,000 leases; a strictly increasing `sequence` per mirror (an older or equal one is refused as a replay, 409 `migrate.mirror.sequence`); at most one push per 10 s per mirror (429). The IR is parsed with the strict serde types of `tenko-core` (`deny_unknown_fields` on the envelope), so a value that does not validate is refused whole with the path of the first error (422 `migrate.mirror.invalid`); nothing of a refused push is stored.

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
- `migrate.snapshots`: one row per mirror, the latest accepted envelope as CBOR with its hash. A push whose hash equals the stored one writes no row and no audit record; it moves the freshness in the controller's memory only, which is written to the mirror row at most every ten minutes. So a steady mirror costs the store one small write every ten minutes, not one a minute, and the lease path is never touched (ADR 0030 and 0031: no fact rows, nothing on the commit path).
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

1. **Check.** The mirror is fresh (a push younger than 120 s); the loss entries of the scope are acknowledged; the prepare's diff is empty for pools, exclusions and reservations; Tenko's scope is disabled; the forward zone and the reverse zones are primary zones on Tenko that take DHCP updates under the profile (`update.dhcp`, [dhcp.md](../dhcp.md) section 13.1) and the scope's DDNS is enabled when the mirror's was. A failure ends the job with its code and changes nothing.
2. **The Windows scope off (a task for the person).** The job shows the line to run on the controller (`Set-DhcpServerv4Scope -ScopeId 192.0.2.0 -State InActive`) and waits, for at most ten minutes, for a push that shows the scope inactive. That push is the snapshot the takeover uses: it holds every lease Windows granted until it stopped answering. Nothing writes to Windows (CONN-12 explicitly not); the job proves the state from the mirror instead.
3. **The records** (section 2.8), one change set per zone.
4. **The leases** (section 2.8), in batches of 1,000 rows.
5. **The scope on.** `enabled = true`; from this commit the role answers for the network once the relay or the listener reaches it.
6. **The record.** A row in `migrate.takeovers` (the scope, the snapshot's sequence, the counts, the adopted addresses and names, the names left frozen, the skipped items with their reasons, the before-images of every RRset it changed) and the audit record `dhcp.scope.takeover` with the counts.

A failure in steps 3 to 5 rolls the job back from the before-images: the RRsets as they were, the adopted lease rows removed, the scope disabled. The rollback is the job engine's, so it is visible and audited like every other.

Between step 2 and the moment clients reach Tenko, nobody answers the network. With the lease time lowered the day before (section 2.13), a client's renewal goes unanswered (it is unicast to the controller) and its rebinding broadcast reaches Tenko at T2, within minutes; a client that boots meanwhile sends INIT-REBOOT and is answered from its adopted row.

### 2.8 The adoption rule

**Leases.** Each mirrored lease of the scope in the state active or active reservation becomes a `dhcp.leases` row: state `active`, the address, `ends` = `taken_at` plus the remaining time of the Windows lease (at most the Tenko scope's maximum lease time), `granted` = the adoption time (ADR 0031 point 3), the host name, and the cold field `adopted { mirror, sequence, guessed }`. A declined lease becomes an `abandoned` row with the hold of `[dhcp.decline]`. A lease is skipped and reported when its address is outside the Tenko pool and not a reservation, when it conflicts with a Tenko reservation of another client, or when Tenko holds an active row of another client at the address.

**The client's identity.** Tenko keys a lease by option 61 when the client sends one, else by `htype` and `chaddr`. Windows shows a client's identifier as six octets for both a client that sends option 61 of type 1 with its MAC and a client that sends none, so the mirror cannot always tell which key the client will present. The adoption decides it in this order: an identifier longer than six octets is the client's option 61 as it is; else, where a DHCID stands at the lease's name, Tenko computes the DHCID of both candidates (type 1 over `01` and the MAC, type 0 over `htype` 1 and the MAC) and takes the one that equals the record Windows wrote; else option 61 of type 1 with the MAC (proposed; most clients of a Windows network send it), and the row is marked `guessed`. Whether a candidate ever matches Windows' DHCID is what the rehearsal records (R137).

**The engine's rule for an adopted row.** When a REQUEST in RENEWING, REBINDING or INIT-REBOOT names an address whose active row is `adopted` and keyed by another identity, and the row's MAC equals the request's `chaddr` with `htype` 1, the row is the client's: the change rewrites it under the identity the client presented (a renewal, `granted` kept, `adopted` cleared) instead of refusing the address as another client's, and INIT-REBOOT counts the row as the client's record. A request from another MAC gets what it gets today: NAK on an authoritative scope, silence otherwise. The check reads fields the row already holds, so the path stays free of allocations (`tests/alloc.rs`). The first REQUEST of every adopted client clears `adopted`, whatever its key.

**Records.** For each adopted lease and each mirrored reservation with a lease, the name is the lease's host name under the name rule (section 2.9) and the zone is the scope's forward zone. At that name the takeover adopts:

| At the name | Condition | Written |
|---|---|---|
| A (or AAAA) and DHCID, origin `transfer` | The A RRset holds the lease's address and no other; a DHCID RRset stands beside it | A with the lease's address and DHCID computed by Tenko for the row's identity, origin `dhcp`, TTL by the scope's DDNS settings (a third of the lease time by default) |
| A and DHCID, origin `dynamic` | As above (WT-Q8, proposed: Windows DHCP rewrote the name after the flip or during a reverted takeover) | The same |
| PTR at the address's reverse name, origin `transfer` or `dynamic` | Its target is the name | PTR, origin `dhcp` |
| `manual`, `ipam`, `ad`, `dnssec`, a CNAME, an A RRset with other addresses, a name without a DHCID | Never adopted | Skipped and reported; Tenko's DDNS treats the name by its usual rules at the next renewal |

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
| Mirror and secondaries (nothing served) | Remove the task (`Install-TenkoDhcpMirror.ps1 -Remove`) and the transfer permission on the controllers | Delete the mirror (its service account and token go with it) and the secondary zones in Tenko |
| DNS flipped | On Windows, the controllers' secondaries become AD-integrated primaries again, with Tenko's latest data (`ConvertTo-DnsServerPrimaryZone -ReplicationScope Domain`, `Forest` for `_msdcs`) | In Tenko, the reverse flip to secondary of the controllers; the next transfer brings the records back as `transfer` |
| DHCP taken over | In Tenko, the reverse action: the scope disabled, its leases and records kept, `dhcp.scope.revert` audited | On Windows, the scope active again (`Set-DhcpServerv4Scope -State Active`) and the relay or the listener back; the names Tenko wrote stay with the origin `dhcp`, and Windows' updates may change them ([dns.md](../dns.md) section 13.4) |

After a reverse action, the mirror is expected to show the Windows scope active again; after a takeover, a mirrored scope that turns active again while Tenko's scope serves is an error finding (`migrate.mirror.scope_active`): two servers would answer one network.

### 2.11 Profiles

Home now (WT-Q5): the AD zones take unsigned updates from an access list of the controllers' addresses (`require_tsig = false`), Tenko DHCP writes into them by its internal path (`update.dhcp` unset follows the profile, Home allows it), name protection is `protect`, transfers out to the controllers' secondaries are unsigned and address-restricted. Standard works the same with `update.dhcp = true` on the zones. Hardened refuses unsigned updates and stays out of reach for an AD zone that takes updates until Slice 13; the runbook says so, and the mirror, the flip and the takeover work under every profile.

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

The rewritten runbook (WP14.3) is ordered so that every step before the window changes nothing a client uses:

0. **The rehearsal** (WT-Q6): the runbook from step 1 on a throwaway domain, below.
1. The starting state and the backups (today's step 1).
2. Tenko as secondary of every AD zone, the controllers allowing the transfer and notifying the node; the mirror installed; the scope prepared from the mirror; the losses acknowledged; the diff empty. Coexistence mode secondary: no client points at Tenko.
3. The access list of the controllers and the zones' update policy (it applies from the flip); the profile confirmed (Home).
4. A lease time ahead, the Windows scope's lease time lowered to an hour; the day before the window, to 10 minutes (proposed; T2 then falls under nine minutes, so every client rebinds to Tenko within minutes of the switch; the rehearsal confirms the figure).
5. The registry value on each domain-joined Windows machine that is not a controller: `DisableDynamicUpdate` = 1 (`REG_DWORD`) under `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, so that the member does not try to register its own name and the DHCP server writes it; checked with `reg query`. The controllers keep their registration.
6. **The window.** The flip of each zone, forward zones first (section 2.6); the controllers' copies converted to secondaries of Tenko, with Tenko's `transfer.allow` and `notify` naming them; the controllers pointed at Tenko and registering (today's step 5); then per scope the takeover (section 2.7) and the relay or the listener; the check from a client.
7. **The parallel period**, a week: the mirror keeps running and must show the Windows scope inactive; the controllers serve their secondary copies as the second DNS server of the clients' option 6 list, behind Tenko.
8. The DHCP Server role removed after the parallel period; the DNS Server role stays on the controllers as Tenko's secondaries until a second Tenko node exists (Phase 5, WT-Q12, R143).

Each phase keeps its two-step rollback (section 2.10). The INIT-REBOOT note: a client that boots with a lease Tenko holds no row for (one the mirror missed) gets silence, as RFC 2131 says, and falls back to DISCOVER after its timeout; it is offered its old address when the address is free, and the conflict probe ([dhcp.md](../dhcp.md) section 14) stands between it and a second client.

**The rehearsal** (one afternoon of the owner's): a throwaway domain controller with the DNS and DHCP roles and one Windows client on the owner's hypervisor, on an isolated network, plus a lab Tenko node. Two feeds from the real domain into the lab node, both read-only: a zone transfer of the real AD zones (the real controllers allow the transfer to the lab node's address for the afternoon) and the exporter on the real DHCP server pushing to a second mirror on the lab node. The lab node's `dhcp` role has no listener on the real network, so a scope prepared from the real mirror can never answer there. The afternoon runs the whole runbook on the throwaway domain with its client (the flip, the takeover, each rollback and the way forward again) and, on the real data, the flip of the real zones' copies, the prepare and a dry takeover of the real scope (no listener), which shows the real names adopted and the DHCID identifier type Windows uses. At the end: the transfer permission and the exporter's task on the real server are removed, the lab node's mirrors deleted.

### 2.14 Single node first, cluster-aware

One node with the `controller`, `dns` and `dhcp` roles. Cluster-aware now: the mirror rows, the snapshots and the takeover records are in the replicated store; the push is accepted by any controller and written through the store; the freshness lives in the leader's memory and is rebuilt from the row on a leader change (a mirror reads as stale until its next push, at most a minute); the takeover's lease rows carry the node as every lease row does. A second DNS primary and a DHCP pair are Phase 5 and Slice 12; until then the controllers' secondary copies are the DNS fallback (R143).

## 3. Contracts and shared files (WP14.0)

### 3.1 Types (`tenko-core`, `tenko-auth`, `tenko-dhcp`)

- `ir`: `MirrorSnapshot { format: u16 (1), sequence: u64, taken_at: Timestamp, source: MirrorOrigin { kind: SourceKindLabel, server: String, adapter: String, adapter_version: String }, dhcp: DhcpIr, losses: LossReport }` with `deny_unknown_fields` on the envelope and the bounds of section 2.1; `SourceLocation` used as `{sheet: <cmdlet>, column: <object key>}` by the exporter. `IrLease`, `IrScope` and `IrReservation` stay as they are; WP14.0 checks that every field the exporter fills validates (a Windows host name with uppercase letters, an option value's text form) and adds a field only by the rule of additive serde defaults.
- `migrate` (new module): `Mirror { id, name, kind, enabled, token: ApiTokenId, account: UserId, interval_secs, last_sequence, last_hash, last_push, last_change, created, updated }`; `Takeover { id, mirror, scope, sequence, state { Done, RolledBack, Reverted }, counts, adopted_leases, adopted_names, frozen_names, skipped: Vec<(Item, Code)>, before: Vec<RrSetImage>, job, at, by }`; `LossAck { mirror, key, entry_hash, by, at }`.
- `auth`: `TokenScope::Mirror(MirrorId)`, serialized `mirror:<id>`; `TokenScope` loses `Copy` or the mirror id moves to a field of its own (WP14.0 chooses; the wire form `mirror:<id>` is the contract).
- `dhcp`: `Lease.adopted: Option<Adopted { mirror: MirrorId, sequence: u64, guessed: bool }>`, a cold field with a serde default and a presence bit (no data format change, as `granted` in ADR 0031); `PendingChange` gains the rekey kind of section 2.8.
- `dns`: the flip and release request types; no new `Origin` value (`Transfer` and `Ad` exist).
- Tables: `migrate.mirrors`, `migrate.snapshots`, `migrate.takeovers`, `migrate.loss_acks`. WP14.0 decides whether the namespace, the object kinds and the audit actions are values an older binary cannot decode and therefore need data format 6, as Phase 3's namespace needed 4 ([dhcp-contracts.md](../dhcp-contracts.md) section 13); the upgrade path is then an empty migration with its fixture.

### 3.2 API and CLI

- Push (token only): `PUT /migrate/mirrors/{id}/snapshot` → `200 {"sequence", "changed"}`; 401, 403, 409 `migrate.mirror.sequence`, 413 `migrate.mirror.too_large`, 422 `migrate.mirror.invalid`, 429.
- Management (session, administrator; reads also `migrate.read` for operators): `GET, POST /migrate/mirrors`; `GET, PATCH, DELETE /migrate/mirrors/{id}`; `POST /migrate/mirrors/{id}/token` (interactive only; shows the token once); `GET /migrate/mirrors/{id}/snapshot` (the IR as stored), `GET /migrate/mirrors/{id}/losses`, `POST /migrate/mirrors/{id}/losses/ack`; `GET /migrate/mirrors/{id}/scopes/{cidr}/diff`; `POST /migrate/mirrors/{id}/scopes/{cidr}/prepare`, `.../takeover`, `.../revert` (each answers a job); `GET /migrate/takeovers`, `GET /migrate/takeovers/{id}`.
- DNS: `POST /dns/zones/{id}/flip`, `POST /dns/zones/{id}/release` (with `dry_run`).
- CLI: `tenko migrate mirror list|create|show|token|delete|losses|ack`, `tenko migrate diff <mirror> <cidr>`, `tenko migrate prepare|takeover|revert <mirror> <cidr>`, `tenko dns zone flip <zone> --to primary|secondary ...`, `tenko dns zone release <zone> [--delete] [--dry-run]`.
- Codes: `migrate.mirror.*` (`not_found`, `sequence`, `too_large`, `invalid`, `rate`, `stale`, `scope_active`, `token_expiring`), `migrate.takeover.*` (`not_fresh`, `source_active`, `diff`, `zone`, `losses`, `wait_timeout`), `dns.zone.flip.*` (`not_secondary`, `not_primary`, `catalog`); i18n units in `sv` and `en`.
- Annotations per [api/README.md](../api/README.md): the push is the only operation a `mirror:` token reaches; the takeover and the flip are interactive-only.

### 3.3 The UI (the routes stubbed by WP14.0)

The connectors page lists mirrors beside the plugin instances, each with the card of section 2.4. A mirror's page has three tabs: **Scopes** (each mirrored scope with its Tenko counterpart, the diff, and the Prepare, Take over and Revert actions with their states), **Losses** (the entries with their acknowledgment) and **Settings** (name, token, the fingerprint and the two PowerShell commands to copy, deletion). A zone's page gets **Flip** (for a secondary, with the SOA and NS form) and **Release frozen names** (for a primary that has some). The takeover's job page shows the task of step 2 with the command to copy and the wait for the mirror.

### 3.4 Shared fixtures

- `crates/tenko-core/tests/fixtures/mirror/`: `snapshot.json`, the envelope of a fictitious domain `corp.example.test` (one scope `192.0.2.0/24`, thirty reservations named in every way of section 2.9, sixty leases of each identity kind, options at the three levels, one policy, one filter and one superscope for the loss report), and `snapshot-inactive.json` (the same with the scope inactive).
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

#### WP14.2 The flip, the prepare, the takeover and their reverses (16 builder-days)

- **Requirements:** MIG-04, MIG-08, DHCP-13, IPAM-17.
- **Owns:** `crates/tenko-dns/src/zone/flip.rs` and the flip's hand-off in `zone/secondary.rs`, the `flip` and `release` routes and commands, the zone page actions; `crates/tenko-dhcp/src/takeover/**` (the prepare, the takeover and the revert jobs, the record adoption, the identity choice), the rekey rule in `v4/engine/mod.rs` with its allocation test rows, the adopted-name rule in `ddns/plan.rs` and `ddns/worker.rs`, the takeover routes and `tenko migrate prepare|takeover|revert`, the Scopes tab's actions and the job page's task; `bench/phase4-takeover/` (M69, M70); [dns.md](../dns.md) sections 1 and 10.6 to 10.7 (the flip, the frozen names, the release) and [dhcp.md](../dhcp.md) sections 9.2 and 13.4 and a new section on the takeover.
- **Depends on:** WP14.0. It reads snapshots from the store and needs nothing of WP14.1's routes, so the two run in parallel; the UI actions follow WP14.1's page.
- **Content:** 1. the flip with the origin table of section 2.6, its reverse and `release` (4 days); 2. the prepare (3 days); 3. the lease adoption with the identity choice and the engine's rekey rule (3 days); 4. the record adoption and the DDNS rule for adopted rows (3 days); 5. the job, its task and rollback, the record, the audit, the routes, the CLI and the UI actions (3 days).
- **Acceptance:** E74 (the prepare half), E75, E76 in the DHCP lab ([`deploy/compose/lab-dhcp`](../../deploy/compose/lab-dhcp)) with `dhclient` clients of each identity kind and the fixture zones; the counting-allocator test still binds the DHCPv4 path; the E22 figure within its tolerance; E80.
- **Risk:** R137, R138, R142, R147, R149.

#### WP14.3 The runbook around the mirror, and the documentation fixes (4 builder-days)

- **Requirements:** MIG-17.
- **Owns:** the rewrite of [active-directory.md](../active-directory.md) (sections 1, 5 to 8 and the DHCP part: the order of section 2.13 with step 0, the lease-time lowering, the registry value, the INIT-REBOOT note, the rollback per phase in two steps, the Windows side of each step as copyable PowerShell); [dns.md](../dns.md) section 13.9 (unsigned updates from an address the zone's lists allow are possible in Home and Standard when the zone switches `require_tsig` off, and in Lab; Hardened refuses them; a Windows host cannot sign with a static TSIG key, which the bullet wrongly implies); [MIGRATION.md](../MIGRATION.md): the connector architecture sentence and Appendix A's transport line for Windows DHCP (the pushed mirror, no remoting), the Windows DHCP row of the sources table, the runbook table's status.
- **Depends on:** WP14.0 for the names of the routes and commands; finished after WP14.2 and before WP14.4's rehearsal.
- **Acceptance:** E79 apart from the rehearsal row; every command in the runbook exists in the build (a script greps the runbook's `tenko` commands against `tenko --help` output); the placeholders of the runbook only.
- **Risk:** R141, R150.

#### WP14.4 The security rows and the rehearsal (5 builder-days, plus the owner's afternoon)

- **Requirements:** TGL-09, IAM-10, MIG-17, API-18 (partly).
- **Owns:** the rows `ad.*` in `deploy/security/` (with SA3's skeleton of [security-audit-plan.md](security-audit-plan.md); until it lands, a round `takeover` in the DHCP lab carries them), the rehearsal's checklist and result file `bench/phase4-takeover/results/<date>-rehearsal.md` (no real names or addresses), `docs/plans/windows-takeover-exit.md`.
- **Depends on:** WP14.1, WP14.2, WP14.3.
- **The rows:**

  | Row | What is checked | How |
  |---|---|---|
  | `ad.update_unlisted` | An unsigned update from an address not on the controllers' list is refused | `nsupdate` from the scanner container: REFUSED, `dns.update.refuse` audited |
  | `ad.update_spoof` | What the address footing does not protect, kept visible | An update over UDP with a controller's source address (a raw socket in the scanner container) is accepted: `WARN`, with the limit of [active-directory.md](../active-directory.md) section 4 in the report; the same over TCP does not complete its handshake: `PASS` |
  | `ad.xfr_disallowed` | A transfer of an AD zone from an address not on `transfer.allow` is refused | AXFR and IXFR from the scanner container: REFUSED; AXFR over UDP: refused |
  | `ad.dhcid_takeover` | An adopted name and address stay with their client | A client with another MAC asks for an adopted lease's address (NAK) and sends option 81 with an adopted name (refused by name protection, the lease row says so); the rekey rule does not fire for another MAC |
  | `ad.mirror_token` | The mirror token reaches its push and nothing else | Every operation of the served OpenAPI document with the token: 403 except the push; another mirror's push: 403; a replayed sequence 409, an oversized body 413, an invalid IR 422; plain HTTP refused |

- **Content:** 1. the rows; 2. with the owner, the rehearsal of section 2.13 (the lead gives the commands; the builder records the result, the DHCID identifier type, the times between deactivation and the clients' rebinding, the cmdlet behaviors of R139 and R140); 3. the exit document.
- **Acceptance:** E77 (owner-run), E78, the rehearsal row of E79.
- **Risk:** R137, R138, R139, R140, R142.

Total: 42 builder-days, of which WP14.2 is the critical path (16 days after the contracts).

## 5. Order, measurements and exit checks

### 5.1 Order

WP14.0 first. Then three lines in parallel: the script line of WP14.1, the server line of WP14.1, and WP14.2 (the flip first, so that the record adoption has zones to work on). WP14.3 drafts from WP14.0's names and is finished once WP14.2's behavior is merged. WP14.4's rows follow WP14.1 and WP14.2; the rehearsal comes last, with the runbook as written. At most two Rust builders at a time beside the other open work; the script line needs no Rust. After the exit: the owner's real cutover, then Slice 13 (WT-Q7).

### 5.2 Measurements

| # | Measurement | Threshold | Package |
|---|---|---|---|
| M69 | The push of an unchanged snapshot of 1,000 reservations and 10,000 leases, 60 s apart and once a second for a minute, on the node of M21 | p99 of the route under 200 ms; no store write and no audit record for the unchanged ones; the DHCPv4 REQUEST-to-ACK p99 of the lab load unchanged within 5 percent while it runs | WP14.2 |
| M70 | The takeover of a scope with 10,000 leases and 10,000 adopted names, from the push that shows the source inactive to the scope enabled | Under 30 s; the DNS answer for an adopted name never NXDOMAIN during the takeover (a probe once every 100 ms) | WP14.2 |

## 6. Owner decisions

Each question lists its options, the trade-offs and the recommendation. The owner decided WT-Q1 to WT-Q7 on 2026-11-01; each ends with the decision. WT-Q8 to WT-Q12 came up while writing the plan and are open.

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

**WT-Q6. How is the takeover rehearsed?**
- Options: (a) a throwaway domain controller and one Windows client on the owner's hypervisor, the lab node fed by a zone transfer from the real domain and by a read-only mirror of the real DHCP server, in one afternoon, as step 0 of the runbook; (b) the container lab only (Samba AD, `dhclient`); (c) straight to the real domain with the rollbacks ready.
- Trade-offs: (b) cannot show Windows DHCP's DHCID records, the cmdlets' behavior or a Windows client's DHCP sequence; (c) learns those on the real network; (a) learns them on real data without serving it, at the cost of one afternoon and the care of section 2.13.
- **Recommendation: (a).**
- **Decided (2026-11-01): (a), one afternoon, step 0 of the runbook.**

**WT-Q7. What comes after this slice?**
- Options: (a) the real cutover, then Slice 13 while the lab controller still stands; (b) Slice 13 first, then the cutover under Hardened; (c) the cutover and Slice 13 in parallel.
- Trade-offs: (b) is WT-Q5 (b); (c) competes for the owner's lab time; (a) uses the rehearsal's lab for E44 of the identity plan.
- **Recommendation: (a).**
- **Decided (2026-11-01): (a).**

**WT-Q8. Does the takeover adopt `dynamic` names besides `transfer` ones? (open)**
- Options: (a) `transfer` only, as WT-Q3's text says; (b) `transfer`, and `dynamic` names that carry a DHCID and the mirrored lease's address; (c) also `manual` names with a DHCID.
- Trade-offs: under (a), a name Windows DHCP wrote after the flip (a client new to Windows in the window) or during a reverted takeover is `dynamic` and is refused at the first renewal, which brings step 10's gap back for those names; (b) closes that with the same proof as WT-Q3 (a DHCID at the name means a DHCP server wrote it, and the controllers' access list means only the controllers' services write `dynamic` records); (c) would let a takeover change records an operator made.
- **Recommendation: (b).**

**WT-Q9. What origin do the other transferred records get at the flip? (open)**
- Options: (a) `ad`; (b) `manual`; (c) `transfer` kept on every RRset.
- Trade-offs: (c) refuses Netlogon's hourly registration of every locator record (event 5774 every hour, a changed controller address never registered); (b) is updatable but loses the mark that the record came from AD, which Slice 13's claim rule needs (identity plan section 3.6); (a) is updatable from the access list today and governed by the claim rule later.
- **Recommendation: (a).**

**WT-Q10. What does "a factory name is kept as it is" mean for a name that is not a valid host name? (open)**
- Options: (a) a valid label gets the zone like any bare name; an invalid one is kept as the IPAM host's name, with no record derived and a loss entry; (b) an invalid one is tidied (`ESP_3A1F2B` to `esp-3a1f2b`) and gets the zone; (c) a factory name is recognized by its pattern and never gets the zone.
- Trade-offs: (b) invents a name nobody chose, and the client keeps registering its own under DDNS anyway; (c) guesses at patterns that change by vendor; (a) is decidable by syntax alone and changes nothing the owner typed.
- **Recommendation: (a), the reading section 2.9 writes.**

**WT-Q11. How long does the mirror token live? (open)**
- Options: (a) within TGL-05 (365 days under Home), with the finding `migrate.mirror.token_expiring` 14 days ahead and a replacement from the mirror card; (b) non-expiring for mirror tokens as an exception to TGL-05.
- Trade-offs: (b) avoids a yearly chore but makes one token class an exception to a never-relaxed rule; (a) keeps the rule and makes the chore visible in time.
- **Recommendation: (a).**

**WT-Q12. What happens to the DNS Server role on the controllers after the flip? (open)**
- Options: (a) it stays, the controllers holding secondary copies of Tenko's zones (the clients' second DNS server) until a second Tenko node exists; (b) it is removed after the parallel period, as today's runbook does; (c) the AD-integrated zones stay frozen as today's runbook does, without becoming secondaries.
- Trade-offs: (b) leaves one Tenko node as the only server of the AD zones until Phase 5; (c) keeps a stale copy that grows staler; (a) keeps a current copy that answers when the node is down and makes the DNS rollback a conversion with current data (section 2.10), at the cost of keeping the role and converting AD-integrated zones to secondaries (R142).
- **Recommendation: (a).**

## 7. Requirement rows touched

No new requirement IDs. Proposed edits to the lead's files, to be applied with the decisions:

| Row | Today | Proposed |
|---|---|---|
| MIG-08 | "Source: Windows DHCP. `Export-DhcpServer -Leases` (XML) plus the `Get-DhcpServerv4*` cmdlets for scopes, reservations, ..." | Adds: "The source is a scheduled exporter on the DHCP server that pushes the IR every minute to Tenko's API with a token that can write only that source (the mirror); Tenko holds no Windows credential and does not connect to Windows." |
| MIG-04 | "... flip (Tenko becomes primary; the old server becomes its secondary or is switched off after a rollback window)." | Adds: "A flip keeps every record with its provenance and is reversible; for DHCP the flip is the per-scope takeover of the mirrored leases and records." |
| MIG-17 | "Migration runbooks in MIGRATION.md." | "Migration runbooks, listed in MIGRATION.md; the Windows DNS and DHCP runbook is [active-directory.md](../active-directory.md), validated by a rehearsal on a throwaway domain." |
| CONN-12 | "External DHCP actuators for coexistence: Windows DHCP via PowerShell and Kea ..." | Unchanged; the Windows takeover does not use it (section 1.4) |

ROADMAP: the Phase 4 deliverables gain the line for this slice (written with this plan). MIGRATION.md (WP14.3): the Windows DHCP row and the transport sentence. CONFORMANCE.md: no RFC row changes; RFC 4701 and 4703 gain the note that adopted DHCID records are rewritten under Tenko's computation.

## 8. Risks

| # | Risk | Proposed resolution |
|---|---|---|
| R137 | The DHCID identifier type Windows uses is unknown until the rehearsal, so the adoption may guess a client's identity wrongly | The identity choice of section 2.8 compares both candidates against Windows' record; the engine's rekey rule and the DDNS rule for adopted rows make a wrong guess harmless for the same MAC; E76 tests both guesses; E77 records the real answer |
| R138 | The mirror lags at the moment of takeover: a lease Windows granted after the last push is missing | The takeover waits for a push that shows the scope inactive, which follows the last grant; a missing lease is taken back at its rebinding as today (a free pool address with no record is ACKed); the conflict probe guards an INIT-REBOOT client's old address |
| R139 | `Get-DhcpServerv4Lease` behaves otherwise than assumed for an inactive scope (no leases returned), or `DHCP Users` cannot read every cmdlet's data | The rehearsal checks both; fallback: the takeover uses the last push before the deactivation, with the R138 path for the gap |
| R140 | PowerShell 5.1 on an older controller (.NET Framework before 4.7.1) lacks the certificate callback the pin needs | The script uses `ServicePointManager`'s callback on 5.1 and `HttpClientHandler`'s on 7; the Pester suite runs on both; the README names the minimum (Windows Server 2016 with its current .NET) |
| R141 | A controller is multi-homed: NOTIFY and updates come from an address not on the lists | The runbook lists every controller address in the access list and the transfer source; NOTIFY from another address falls back to the SOA refresh; the rehearsal shows which address each controller uses |
| R142 | Converting an AD-integrated zone to a secondary removes it from the directory partition on every controller at once, `_msdcs` from the forest partition | The runbook converts one zone at a time, `_msdcs` last, each controller's secondary added before the next; the rehearsal runs the conversion and its rollback (`ConvertTo-DnsServerPrimaryZone`); the exports of step 1 stay the backup |
| R143 | The single Tenko node is the AD zones' only primary until Phase 5 | The controllers' secondary copies keep answering (WT-Q12) and are the clients' second server; Tenko's SOA `expire` for the AD zones at 14 days so the copies outlive an outage; updates wait for the node (Netlogon retries hourly) |
| R144 | A new namespace or object kinds force data format 6 | WP14.0 decides it first; an empty migration with its fixture, as Phase 3 did |
| R145 | The mirror token leaks from the controller | It writes one mirror and reads nothing; DPAPI for the task account; replacement from the card; a forged snapshot can change only what a person later prepares or takes over, behind the diff and the loss acknowledgment |
| R146 | The exporter's PowerShell mapping drifts from the IR | The fixture IR is shared with the Rust tests; the push validates strictly; a refused push is a finding within three minutes |
| R147 | The rekey rule lets a client claim an adopted lease with a forged MAC | Only a REQUEST with the row's MAC on the same network, the same exposure as any DHCP client today; `ad.dhcid_takeover` tests another MAC; the rule ends at the first REQUEST |
| R148 | Quota: this slice beside Slice 12, the UI plan and Phase 3's remainder | At most two Rust builders; the script line needs none; the lab and the rehearsal while builders are idle |
| R149 | The frozen names between the flip and the takeover go stale if the window is split | The runbook does both in one window; WT-Q8 (b) adopts what Windows wrote meanwhile; `release` handles the rest |
| R150 | The runbook's PowerShell drifts from the cmdlets of newer Windows Server versions | Every cmdlet named with its Microsoft page in the Sources; the rehearsal runs them; `Get-Help` checks noted where a page was not found |

## 9. Owner actions

| When | Action |
|---|---|
| Before WP14.0 | Read the plan; answer WT-Q8 to WT-Q12 (WT-Q1 to WT-Q7 decided on 2026-11-01) |
| Before the rehearsal | The throwaway domain: one controller with the DNS and DHCP roles and one Windows client on an isolated network of the hypervisor, and a lab Tenko node; the lead gives the steps |
| Before the rehearsal | The DHCP read account in the real domain: a member of `DHCP Users` and of no privileged group, with the right to log on as a batch job on the DHCP server; the exporter's task on the real server for the afternoon |
| Before the rehearsal | The transfer permission of the real AD zones to the lab node's address for the afternoon, removed at its end |
| Before the window | The registry value `DisableDynamicUpdate` = 1 confirmed on each domain-joined Windows machine that is not a controller |
| Before the window | The profile confirmed as Home on the node; the Windows lease time lowered a lease time ahead and again the day before |
| The window | The runbook from step 6: the flip, the conversions on the controllers, the deactivation of the Windows scope, the takeover, the relay |
| After the parallel period | The DHCP Server role removed; the DNS Server role kept as Tenko's secondary (WT-Q12) |

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
| `docs/plans/windows-takeover-status.md`, `docs/plans/windows-takeover-exit.md` | the lead; WP14.4 |

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
