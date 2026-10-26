# Tenko DDI Security Profiles

Tenko DDI ships four security profiles: Home, Standard, Hardened and Lab. The operator selects one in the first-run wizard (API-10). Each profile maps to a persona defined in [REQUIREMENTS.md](REQUIREMENTS.md): PER-01 (home user), PER-02 (business administrator), PER-03 (hardened or regulated environment) and PER-04 (lab or pentest).

This document owns the toggle IDs TGL-01 to TGL-38 and the never-off IDs NEVER-01 to NEVER-03. Requirement IDs (IAM-, DNS-, DHCP-, SCAN-, CONN-, OPS-, API-) and design constraints (CON-) are defined in REQUIREMENTS.md. Role and node structure is described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Principles

- **Bundles of toggles, not code paths.** Every profile runs the same code. A profile only sets toggle values; no engine contains a profile-specific branch.
- **Proposed defaults.** The matrix values are proposed defaults, to be validated during Phase 1. After first run, any toggle can be changed individually except the never-off items. The UI shows every deviation from the selected profile.
- **Insecure state is loud.** While the Lab profile is active, or while any toggle is set weaker than the Home value, the UI shows a persistent warning banner. Every toggle change is written to the audit log.
- **Lab may switch off everything except the never-off items.** The never-off list (NEVER-01 to NEVER-03) holds in every profile.
- **Toggles follow features.** A toggle appears when its feature ships. The Phase column of the matrix lists that phase.

## Profiles

| Profile | Persona | Intent |
|---|---|---|
| Home | PER-01 | One box runs all roles. Minimal friction, sane defaults. |
| Standard | PER-02 | Business AD environment. The default for organizations. |
| Hardened | PER-03 | Regulated environments: strict authentication, audit export, least privilege. |
| Lab | PER-04 | Permissive configuration for testing and training. Never attack tooling (CON-09). |

## Toggle matrix

Values are proposed defaults (see Principles). The Phase column is the phase in which the toggle first appears. The Home value is the baseline against which the UI judges a toggle as weaker.

Reading the matrix:

- "Optional" and "Off allowed" mean the control is not enforced; the operator may still enable it.
- The Related column lists the requirements that define the underlying feature; the toggle only selects how strictly that feature is applied.
- Each audit entry for a toggle change records the acting principal (NEVER-03) together with the old and new value.

| ID | Toggle | Home | Standard | Hardened | Lab | Phase | Related |
|---|---|---|---|---|---|---|---|
| TGL-01 | Password policy preset | PIN preset (subject to IAM-07) | Standard preset: at least 12 characters; a random password is offered | Hardened preset: passphrase of at least 16 characters | PIN preset (subject to IAM-07) | 1 | IAM-03 |
| TGL-02 | MFA requirement | Optional (IAM-07 can force it) | Required for administrator roles | Required for all accounts | Optional (IAM-07 can force it) | 1 | IAM-06 |
| TGL-03 | Passkey required for administrators | No | No (recommended) | Yes | No | 1 | IAM-06 |
| TGL-04 | Session lifetime (absolute / idle) | 30 days / 7 days | 12 hours / 1 hour | 8 hours / 15 minutes | 30 days / 7 days | 1 | IAM-08 |
| TGL-05 | API token maximum lifetime | 365 days | 90 days | 30 days | No maximum (non-expiring tokens allowed) | 1 | IAM-10 |
| TGL-06 | Breached-password check (HIBP) | On, online k-anonymity | On, online k-anonymity | On, offline corpus preferred | Off | 1 | IAM-04 |
| TGL-07 | Lockout | On, progressive delay | On, progressive delay then temporary lock | On, lock until timeout or administrator unlock, with alert | Off | 1 | IAM-05 |
| TGL-08 | TLS on API and UI | On, certificate from the internal CA | On, internal CA or imported certificate | On, TLS 1.3 only, HSTS | Optional, plain HTTP allowed | 1 | API-01, OPS-04 (internal CA) |
| TGL-09 | DNS dynamic updates from external clients | None by default; any mode per zone | TSIG; secure only for the zones the Kerberos wizard enables, nonsecure and secure allowed per zone as a deviation | TSIG or GSS-TSIG only, secure only with ownership on every zone with Kerberos, unsigned rejected | Unsigned allowed | 2 (GSS-TSIG in 4) | DNS-11, DNS-28 |
| TGL-10 | Zone transfer ACL | Deny all | Listed secondaries with TSIG | Listed secondaries, TSIG required, XoT for transfers that leave the site | Allow any | 2 | DNS-09, DNS-19 |
| TGL-11 | Response Rate Limiting | On | On | On, stricter limits | Off | 2 | DNS-17 |
| TGL-12 | DNSSEC validation | On | On | On, negative trust anchors must have an expiry | Off allowed | 3 (Slice 10) | DNS-13 |
| TGL-13 | DNSSEC signing | Off | Opt-in per zone | On for zones served externally | Off | 2 | DNS-12 |
| TGL-14 | DoT/DoH to upstreams | Preferred, plaintext fallback | Preferred, plaintext fallback logged | Required, no plaintext fallback | Off | 2 | DNS-15 |
| TGL-15 | Query logging and retention | Off (opt-in, 7 days) | On, pseudonymized, 30 days | On, pseudonymized, retention per policy (default 30 days), exported with the audit stream | On, not pseudonymized, 7 days | 2 | OPS-06 |
| TGL-16 | DHCP conflict detection | On | On | On | Off | 3 | DHCP-06 |
| TGL-17 | DHCP MAC filtering | Off | Off | Allow-list on scopes marked restricted | Off | 3 | DHCP-08 |
| TGL-18 | Scanner active probing | On: ICMP, common TCP ports, OS fingerprinting | On, scheduled, outside blackout windows | Off (passive only) unless enabled per segment | On: all techniques, full port range | 1 | SCAN-04, SCAN-06 |
| TGL-19 | Scanner rate limit per probe | Normal (100 packets/s) | Slow (50 packets/s) | Slowest (10 packets/s) | Unlimited | 1 | SCAN-06, SCAN-07 |
| TGL-20 | UniFi write access | On | On | Off (read-only) until explicitly enabled; writes need approval once IAM-02 exists | On | 1 | CONN-06, CONN-08, CONN-09 |
| TGL-21 | Audit export | Local only | Local, syslog optional | Export required (syslog, CEF or JSON), alert on export failure | Local only | 1 | IAM-18 |
| TGL-22 | Recursion and forwarding ACL | Prefixes known to IPAM | Prefixes known to IPAM | Explicit allow-list per view | Any (open resolver allowed) | 2 | DNS-02, DNS-20 |
| TGL-23 | In-app update check and install (OPS-24) | Check daily, install from the UI | Check daily, install from the UI with step-up authentication | Check daily (version string only), install only from an uploaded and verified release file | Check daily, install from the UI | 1 (Slice 2) | OPS-24, API-19 |
| TGL-24 | Secret reveal (IAM-16, API-11) | A signed-in session of password strength or stronger | Step-up: a sign-in within the last five minutes | Step-up with a passkey or hardware security key within the last five minutes; reveal only secrets bound to the host in view | A signed-in session of password strength or stronger | 1 (Slice 2) | IAM-07, IAM-16, API-11 |
| TGL-25 | Default resolution outside the zones and rules | Recurse | Recurse | Recurse | Recurse | 3 (Slice 10) | DNS-03 |
| TGL-26 | QNAME minimisation | Relaxed | Relaxed | Relaxed (strict allowed) | Relaxed | 3 (Slice 10) | DNS-34 |
| TGL-27 | Trust anchor signalling (RFC 8145) | On | On | Off | On | 3 (Slice 10) | DNS-13 |
| TGL-28 | Negative trust anchor lifetime | At most 7 days | At most 7 days | Expiry required, at most 7 days | At most 7 days | 3 (Slice 10) | DNS-13 |
| TGL-29 | DDNS from DHCP (`UpdatePolicy.dhcp` unset; the internal path, not TGL-09) | Writes into the scope's zones | Only zones with `dhcp: true` | Only zones with `dhcp: true`; name protection forced | Writes | 3 | DHCP-13 |
| TGL-30 | Bug report link from the web UI to GitHub ("Report a bug": the new-issue page prefilled with the redacted diagnostics, filed under the person's own account) | On | On | Off: the dialog copies the diagnostics to the clipboard only, no outbound link from the interface | On | 3 | OPS-05 |
| TGL-31 | Automatic partner-down in a DHCP failover pair | Automatic with evidence after 600 s | Automatic with evidence after 600 s | Automatic on the controllers' witness only, else by hand | Automatic with evidence after 60 s | 3 (Slice 12) | DHCP-12 |
| TGL-32 | Kerberos account password rotation | 30 days | 30 days | 30 days, a failed rotation alarms | Off allowed (30 days by default) | 4 (Slice 13) | DNS-28 |
| TGL-33 | Local person accounts beside a verified directory provider | Allowed | Allowed | Break-glass only | Allowed | 4 (Slice 13) | IAM-09, IAM-12 |
| TGL-34 | Directory transport for LDAP | LDAPS or StartTLS, verified | LDAPS or StartTLS, verified | LDAPS only, verified | Plain allowed, with the clear-text warning | 4 (Slice 13) | IAM-12 |
| TGL-35 | Directory check interval and grace | 15 minutes, 15 minutes grace | 15 minutes, 15 minutes grace | 5 minutes, no grace | 15 minutes, 15 minutes grace | 4 (Slice 13) | IAM-12 |
| TGL-36 | Personal tokens of directory users | Allowed within TGL-05 | Allowed within TGL-05 | Not allowed (service accounts only) | Allowed | 4 (Slice 13) | IAM-10 |
| TGL-37 | Backup before an update (ADR 0023) | Asked, default yes; "no backup" allowed and audited | Asked, default yes; "no backup" allowed and audited | Required: `backup: "skip"` is refused | Asked, default yes; "no backup" allowed and audited | 2 | OPS-07, OPS-24 |
| TGL-38 | A second person's approval of a change (the UI plan, UI-Q9) | Off | Off | On: a change job waits for approval by a second person before it runs; the approver is recorded in the audit entry and in the recent changes | Off | Planned, 4 (Slice 13) | IAM-02, API-09 |

Notes:

- **TGL-06 and a PIN.** A PIN-like secret (digits only, under 12 characters) under a preset that admits a PIN is not checked against the corpus, because every short numeric code is in it. The PIN preset relies on the coupling rule (IAM-07) instead.
- **TGL-12 before Slice 10.** Until the own resolver ships (Phase 3, Slice 10, [dns-recursion-plan.md](plans/dns-recursion-plan.md)), Tenko forwards and caches, so DNSSEC validation is the upstream resolver's job (DNS-03, DNS-13). From Slice 10 the toggle applies to recursed and to forwarded answers alike (REC-Q3); a forwarding rule may set `validate = false`.
- **TGL-09 scope.** The toggle concerns dynamic updates from external clients. The DDNS path from Tenko DHCP to Tenko DNS is internal and is not governed by it (DHCP-13).
- **TGL-24 and the PIN rule.** The PIN coupling rule applies on top of every value: a PIN-strength session never reveals, and personal API tokens never reveal. No value is weaker than Home, so the toggle never raises the banner. Operators may reveal (administrators create, change, bind and delete), so they count as accounts that can reach the vault.
- **TGL-08 and a replaced certificate.** With an imported certificate, whether the node loads a certificate that is replaced in its files while it runs is a decision of the profile: on under Lab and Home, off under Standard unless `tls.accept_external_replacement = true`, never under Hardened (the key is refused there). Where it is off, the new certificate is reported as pending (`sys.tls.certificate_pending`) and the next restart loads it. See [certificates.md](certificates.md) section 4.
- **TGL-37 follows the profile.** Like TGL-30 it is decided by the selected profile and has no stored value of its own yet; an install that does not answer still needs a good backup younger than one hour in every profile, so no profile installs without a restore point by accident ([upgrades.md](upgrades.md) section 8.12).
- **TGL-38 and Slice 13.** A second person needs a second identity, so the toggle ships with the directory identity of Slice 13 ([identity-plan.md](plans/identity-plan.md)); until then a Hardened change is a job with a preview and no approval step. It is a guard rail of the Hardened profile: only an administrator can lift it, and the lifted state is a weakened setting (next note). The approval workflow beyond one approver (IAM-02) stays in Phase 5.
- **A setting weaker than the profile is a finding.** Besides the banner, a toggle set weaker than the selected profile's value raises the finding "A setting is weaker than the profile allows" of the findings model ([ui-plan.md](plans/ui-plan.md) section 2.2). Its subject is the toggle, its evidence the profile's value and the current one, and its action opens the setting. The severity is Review under Home and Standard and Act now under Hardened; under Lab the banner already says so and no finding is raised. The Settings entry of the navigation rail shows a dot while any such finding is open. Every change of a toggle stays in the audit log as before (NEVER-03).
- **TGL-19 values.** The packet rates are starting points. The slower profiles exist because IDS/EDR products (for example Defender for Identity) flag port scans (SCAN-07).

## Never-off list

These controls cannot be switched off in any profile, including Lab.

| ID | Control | Why |
|---|---|---|
| NEVER-01 | Secrets encrypted at rest (envelope encryption, IAM-15) | The vault holds TSIG keys, SNMPv3 and DDNS credentials and connector credentials (IAM-16). A plaintext copy in the store, a backup or a snapshot would turn any read access into a compromise of AD, hypervisors and network controllers. |
| NEVER-02 | Audit log (immutable, hash-chained, IAM-18) | Insecure configuration needs a trail more than a secure one. Toggle changes, secret reveals and every other change must stay reconstructable and tamper-evident. |
| NEVER-03 | Admin action attribution (IAM-19) | Every change must be attributable to an authenticated principal. An audit entry without an identity has no forensic value, so anonymous administrative changes are not possible, even in Lab. |

Audit export (TGL-21) is a toggle; the audit log itself is not.

## PIN coupling rule

CON-07 and IAM-07 define the rule precisely:

- A PIN may be the sole authentication factor only while the vault holds no secrets (empty or disabled).
- As soon as the vault holds a secret, every account that can reach it needs at least a passkey, or the PIN as a second factor alongside another factor.

Rationale: a 4-digit PIN protecting a vault with domain-admin credentials is not defensible, even at home.

The rule applies in every profile, including Lab. It is a function of vault state, not a toggle, so it does not appear in the matrix and no profile can relax it. TGL-01 and TGL-02 are both subject to it, which is why their PIN-friendly values read "subject to IAM-07" and "IAM-07 can force it".

Enforcement: Tenko refuses to store the first secret until the accounts that can reveal secrets satisfy the rule. The first-run wizard explains this before the operator connects anything.

Example: a home user who connects Proxmox or UniFi stores credentials in the vault, so PIN-only login ends at that point.

## Lab profile: permissive, never offensive

Lab means permissive configuration for testing and training: open recursion, unsigned dynamic updates, no rate limits, plain HTTP, no lockout. It never adds attack tooling (CON-09): no Responder-like name-resolution poisoning, no credential capture, no exploit modules. The reason is liability.

Lab is loud in the UI. The persistent warning banner described under Principles is shown for as long as the profile is active, and the never-off list still applies.

## Installation: what the machine is prepared for

The profile chosen at installation also decides what the installer prepares on the host,
the root-only part of the roles: the systemd drop-ins that grant `CAP_NET_RAW` (the probe
role's raw methods, the dhcp role's direct mode), the roles' ports on the host firewall, and
systemd-resolved's stub listener off for the dns role on every address. This is an
installer decision, not a toggle: the service never gains privileges at runtime (ADR 0023),
so switching a role on later cannot grant them.

| Profile | Prepared for | Roles question |
|---|---|---|
| Home, Standard, Lab | Every role, so that a role switched on from the Nodes page finds its privileges and ports | Not asked; the node starts with every role and the operator trims the set |
| Hardened | The roles chosen at installation only (least privilege) | Asked; another role is prepared by an explicit rerun as root (`install.sh --prepare --roles ...`) |

The node reports per role whether the machine is prepared for it, and the Nodes page names
what is missing and the installer command ([cluster.md](cluster.md), section 13.4). The
installer remembers the profile it prepared for (`/etc/tenko/prepared-roles`); a profile
changed later in the web UI changes nothing on the host until the operator runs
`install.sh --prepare --profile <name>`.

## Structural controls outside the profile system

These controls are always on because they are architecture, not toggles. No profile, including Lab, has a setting for them.

| Control | Reference |
|---|---|
| Node-to-node gRPC with mTLS and enrollment | OPS-04 |
| Break-glass account with hardware key only | IAM-09 |
| Verify-before-write and guardrails for network-controller writes | CONN-08, CONN-09 |
| Preview before every apply | API-09 |
| Audit on every secret reveal | IAM-16 |
