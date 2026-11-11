# Tenko DDI Security Profiles

Tenko DDI ships four security profiles: Home, Standard, Hardened and Lab. The operator selects one in the first-run wizard (API-10). Each profile maps to a persona defined in [REQUIREMENTS.md](REQUIREMENTS.md): PER-01 (home user), PER-02 (business administrator), PER-03 (hardened or regulated environment) and PER-04 (lab or pentest).

This document owns the toggle IDs TGL-01 to TGL-41 and the never-off IDs NEVER-01 to NEVER-03. Requirement IDs (IAM-, DNS-, DHCP-, SCAN-, CONN-, OPS-, API-) and design constraints (CON-) are defined in REQUIREMENTS.md. Role and node structure is described in [ARCHITECTURE.md](ARCHITECTURE.md).

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
| TGL-01 | Password policy preset | PIN preset: at least 6 digits (subject to IAM-07); an administrator always has a password | Standard preset: at least 12 characters; a random password is offered | Hardened preset: passphrase of at least 16 characters | PIN preset: at least 6 digits (subject to IAM-07); an administrator always has a password | 1 | IAM-03 |
| TGL-02 | MFA requirement | Optional (IAM-07 can force it) | Required for administrator roles | Required for all accounts | Optional (IAM-07 can force it) | 1 | IAM-06 |
| TGL-03 | Passkey required for administrators | No | No (recommended) | Yes | No | 1 | IAM-06 |
| TGL-04 | Session lifetime (absolute / idle) | 30 days / 7 days | 12 hours / 1 hour | 8 hours / 15 minutes | 30 days / 7 days | 1 | IAM-08 |
| TGL-05 | API token maximum lifetime (mirror tokens included; the finding `migrate.mirror.token_expiring` is raised 14 days ahead) | 365 days | 90 days | 30 days | No maximum (non-expiring tokens allowed) | 1 | IAM-10 |
| TGL-06 | Breached-password check (HIBP) | On, online k-anonymity | On, online k-anonymity | On, offline corpus preferred | Off | 1 | IAM-04 |
| TGL-07 | Lockout | On: 3 attempts per account and network, then waits of 10 s, 30 s, 3 min, 5 min and 10 min (the last repeats) | On: as Home, then a lock of 30 minutes that ends by itself | On: as Standard, with an alarm per lock, an earlier unlock by an administrator, and the lock holds for a passkey too | Off | 1 | IAM-05 |
| TGL-08 | TLS on API and UI | On, certificate from the internal CA | On, internal CA or imported certificate | On, TLS 1.3 only, HSTS | Optional, plain HTTP allowed; a node enrolls over plain HTTP, or through a reverse proxy that does not state the scheme, only here | 1 | API-01, OPS-04 (internal CA) |
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
| TGL-21 | Audit export | Local only | Local, syslog optional | Export required (a TCP, TLS or file sink that confirms delivery; UDP does not count), alert on export failure | Local only | 1 | IAM-18 |
| TGL-22 | Recursion and forwarding ACL | Prefixes known to IPAM | Prefixes known to IPAM | Explicit allow-list per view | Any (open resolver allowed) | 2 | DNS-02, DNS-20 |
| TGL-23 | In-app update check and install (OPS-24) | Check daily, install from the UI | Check daily, install from the UI with step-up authentication | Check daily (version string only), install only from an uploaded and verified release file | Check daily, install from the UI | 1 (Slice 2) | OPS-24, API-19 |
| TGL-24 | Secret reveal (IAM-16, API-11) | A signed-in session of password strength or stronger | Step-up: a sign-in within the last five minutes | Step-up with a passkey or hardware security key within the last five minutes; reveal only secrets bound to the host in view | A signed-in session of password strength or stronger | 1 (Slice 2) | IAM-07, IAM-16, API-11 |
| TGL-25 | Default resolution outside the zones and rules | Recurse | Recurse | Recurse | Recurse | 3 (Slice 10) | DNS-03 |
| TGL-26 | QNAME minimization | Relaxed | Relaxed | Relaxed (strict allowed) | Relaxed | 3 (Slice 10) | DNS-34 |
| TGL-27 | Trust anchor signaling (RFC 8145) | On | On | Off | On | 3 (Slice 10) | DNS-13 |
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
| TGL-39 | Agent writes through jobs (`tenko mcp`, [ADR 0029](adr/0029-an-agent-tool-with-guard-rails.md)) | On: an agent may create a job with a preview and a manual step that a person approves in the interface | On | Off: agent tokens are read only | On | Planned, after U6 of the UI plan | IAM-10, IAM-19, API-09, IPAM-17 |
| TGL-40 | DHCP trusted relay agents (`dhcp.settings.trusted_relays` unset; `docs/dhcp.md` section 9.8) | None: only clients on the node's own links until relay agents are listed | None, as Home | None, as Home | Every sender is trusted, with the health row `dhcp.relay.trust_any` | 3 | DHCP-04, DHCP-09 |
| TGL-41 | DHCP limits per client and per scope (`dhcp.settings.limits` unset; `docs/dhcp.md` section 14.9) | 16 DHCPv4 bindings per MAC address, 16 DHCPv6 addresses and 8 prefixes per DUID, 100 new clients a second per scope | As Home, 200 new clients a second | 8 bindings per MAC address, 8 addresses and 4 prefixes per DUID, 100 new clients a second | Off, for the load tools of the benches | 3 | DHCP-01, DHCP-09 |

Notes:

- **TGL-06 and a PIN.** A PIN-like secret (digits only, under 12 characters) under a preset that admits a PIN is not checked against the corpus, because every short numeric code is in it. The PIN preset relies on the coupling rule (IAM-07) instead.
- **TGL-12 before Slice 10.** Until the own resolver ships (Phase 3, Slice 10, [dns-recursion-plan.md](plans/dns-recursion-plan.md)), Tenko forwards and caches, so DNSSEC validation is the upstream resolver's job (DNS-03, DNS-13). From Slice 10 the toggle applies to recursed and to forwarded answers alike (REC-Q3); a forwarding rule may set `validate = false` under Home and Standard, gated as a negative trust anchor is (`dns.keys` in an interactive session, never on the root rule, audited), and never under Hardened, where the toggle is on ([dns-resolver.md](dns-resolver.md) section 2.1).
- **TGL-09 scope.** The toggle concerns dynamic updates from external clients. The DDNS path from Tenko DHCP to Tenko DNS is internal and is not governed by it (DHCP-13).
- **TGL-09 and ownership.** Under Hardened every zone with Kerberos settings has the ownership rules of the identity plan (section 3.6) on, whatever its `ownership` setting says (`policy::ownership_on` in `crates/tenko-dns/src/update/policy.rs`); under the other profiles a zone has them on when its Kerberos settings say `ownership = windows`.
- **TGL-10 is a floor under Hardened.** Under Hardened every zone transfer out, and the signed SOA query of a secondary, must be signed with a TSIG key that an access list of the zone names, and a transfer to an address outside the site must come over TLS (XoT), whatever the zone's `require_tsig` and `xot` say; a NOTIFY for a secondary zone must be signed with its primary's key (`tenko_dns::xfr::access`). The site is the security setting `transfer_site`: a list of networks in CIDR notation, at most 256, whose default is the private (RFC 1918), shared (RFC 6598), unique-local (RFC 4193), loopback and link-local ranges. An administrator changes it in the security settings (`PATCH /api/v1/settings/security`, with the fresh sign-in the other security settings take, or the web UI's security settings; `tenko dns transfer site` shows the list); every change is audited with the list before and after, and a change of profile returns it to the default. An empty list is allowed and means that under Hardened every transfer needs XoT. Under the other profiles the list has no effect. Under Home, Standard and Lab the zone's settings apply as stored, as for TGL-09; a zone that transfers without TSIG there is an informational finding (`dns.transfer.weaker_than_profile`), and under Hardened a zone whose settings the profile overrides is a warning (`dns.transfer.profile_refuses`), so the change is visible before a secondary is refused ([dns.md](dns.md) sections 10.1 and 10.14). Standard does not force TSIG because Windows DNS secondaries cannot sign transfers.
- **TGL-24 and the PIN rule.** The PIN coupling rule applies on top of every value: a PIN-strength session never reveals, and personal API tokens never reveal. No value is weaker than Home, so the toggle never raises the banner. Operators may reveal (administrators create, change, bind and delete), so they count as accounts that can reach the vault.
- **TGL-08 and a replaced certificate.** With an imported certificate, whether the node loads a certificate that is replaced in its files while it runs is a decision of the profile: on under Lab and Home, off under Standard unless `tls.accept_external_replacement = true`, never under Hardened (the key is refused there). Where it is off, the new certificate is reported as pending (`sys.tls.certificate_pending`) and the next restart loads it. See [certificates.md](certificates.md) section 4.
- **TGL-37 follows the profile.** Like TGL-30 it is decided by the selected profile and has no stored value of its own yet; an install that does not answer still needs a good backup younger than one hour in every profile, so no profile installs without a restore point by accident ([upgrades.md](upgrades.md) section 8.12).
- **TGL-38 and Slice 13.** A second person needs a second identity, so the toggle ships with the directory identity of Slice 13 ([identity-plan.md](plans/identity-plan.md)); until then a Hardened change is a job with a preview and no approval step. It is a guard rail of the Hardened profile: only an administrator can lift it, and the lifted state is a weakened setting (next note). The approval workflow beyond one approver (IAM-02) stays in Phase 5.
- **TGL-39 and the read tools.** The toggle governs only the writes of the agent tool: whether the service mints an agent token that may propose and accepts job creation by an agent principal. The read tools follow the signed-in person's own permissions and have no toggle. A tool never executes a change under any value: a proposal is a job with a preview that waits for a person to approve it in the interface, and the agent token cannot confirm a manual step. Like TGL-38 it is a guard rail, not a weakening: no value is weaker than Home.
- **A setting weaker than the profile is a finding.** Besides the banner, a toggle set weaker than the selected profile's value raises the finding "A setting is weaker than the profile allows" of the findings model ([ui-plan.md](plans/ui-plan.md) section 2.2). Its subject is the toggle, its evidence the profile's value and the current one, and its action opens the setting. The severity is Review under Home and Standard and Act now under Hardened; under Lab the banner already says so and no finding is raised. The Settings entry of the navigation rail shows a dot while any such finding is open. Every change of a toggle stays in the audit log as before (NEVER-03).
- **TGL-19 values.** The packet rates are starting points. The slower profiles exist because IDS/EDR products (for example Defender for Identity) flag port scans (SCAN-07).
- **TGL-07 counts a login as a whole (IAM-05, IAM-06).** A wrong second-factor code (TOTP or recovery code) counts toward the account's lock exactly like a wrong password. A correct password alone clears nothing; the account's failures from a network are forgotten only when the login completes with its last factor. The lock is therefore reached after the configured number of wrong passwords and codes together from one network, however many challenges they are spread over (8 with the default policy: 3 attempts and 5 waits), and it is audited as `auth.user.lock` with the alarm of Hardened as for passwords. The lock and the waits are checked at every step: the password, the TOTP code, the recovery code and the password change. The numbers of TGL-07 and how they apply are in [Sign-in lock](#sign-in-lock-tgl-07).

## Sign-in lock (TGL-07)

TGL-07 is a mode and a policy. The mode decides whether the lock applies (Home waits but never locks, Standard and Hardened lock, Lab does nothing); the policy holds the numbers, and an administrator changes both in the security settings, which need a sign-in within the last five minutes. The defaults are the same in Home, Standard and Hardened; only Hardened makes the lock hold for a passkey.

| Setting | Default | Range | Meaning |
|---|---|---|---|
| `attempts` | 3 | 1 to 20 | Attempts an account has from one network before the first wait. |
| `waits_secs` | 10, 30, 180, 300, 600 | 1 to 10 waits, each 1 s to one day | The waits between the next attempts, in order. In a mode that locks, the failure after the last wait locks; otherwise the last wait repeats. |
| `lock_secs` | 1,800 (30 minutes) | one minute to one day | How long the lock holds. It always ends by itself. |
| `account_max_delay_secs` | 60 | 0 to 600 (0: off) | The ceiling of the account-wide delay. |
| `passkey_holds_lock` | Hardened only | yes or no | Whether the lock also holds for a passkey sign-in. |
| `alarm_after_failures` | 5 | 1 to 100 | Failed sign-ins of one account, counted across every network, that raise the alarm `auth.alarm.sign_in_failures`; it is raised again each time the count doubles (10, 20, 40 and so on). A policy stored before this setting gets 5. |

A measure across every network of an account only delays; it never locks, for any account. A lock belongs to the account and one network (the owner's decision of 2026-11-11). The policy has no setting that turns the account-wide delay into a lock.

**What is counted where.** A failure counts three ways:

- *The account from one network* (an IPv4 address, or the /64 of an IPv6 address): the attempts, the waits and the lock. One network cannot lock the account for another, so nobody can keep a named administrator out by failing from elsewhere.
- *The account across every network*: once it has failed as often as one network may before its lock (8 with the defaults), each further failure waits 1 s, then 2 s, doubling up to `account_max_delay_secs`, and each delay admits one attempt, also when many arrive together. This keeps a guess spread over many networks slow without locking anyone out; the count is forgotten after the lock's duration, at least an hour, without a failure. A correct password that opens a second factor gives its turn back, so every code of the challenge takes a turn of its own; a code held back by the delay keeps its challenge until the challenge's own end. Once the account has failed `alarm_after_failures` times across networks (5 with the defaults), and again each time the count doubles, administrators get the alarm `auth.alarm.sign_in_failures`, once however many networks the failures came from (counted in each controller's memory, so each controller of a cluster counts and alarms on its own, and the count is forgotten an hour after the last failure); a name that is no account is counted and delayed alike but raises no alarm, since an alarm names an account. A network from which the account completed a sign-in in the last 30 days (a *known network*, kept in each controller's memory and forgotten at a restart) is not held back by this delay; an administrator's password reset forgets the account's known networks. Someone who fails at the moment each delay ends takes every turn, so a person signing in from a network that is not known can be held back for as long as the guessing goes on: sign in with a passkey, from a known network, or block the guessing networks at the firewall.
- *The network across every account*: 20 attempts, then 1 s doubling up to 30 s, against one network trying many accounts.

Failures are kept in each controller's memory and forgotten after the lock's duration (or twice the longest wait, if longer) without a failure; a completed sign-in from a network forgets that network's count, not the account-wide one. A lock is also stored (`auth.locks`, by the name and the network) in the same write as the audit record of the failure, so it holds on every controller and after a restart. Names that do not exist are counted, delayed and locked exactly like accounts, and their locks are stored as well: the answer (`auth.throttled` with the seconds to wait) does not tell whether an account exists, the last administrator excepted (below). A name holds at most 256 stored locks; ended locks are removed every hour. The sign-in page shows the wait without naming the account.

**The last administrator.** The network never locks out the last administrator, the one person left with the admin role who is enabled. That account still meets the waits from each network, but the last wait repeats instead of a lock. No lock is stored or enforced for it. Like every account it meets the account-wide delay, at the password and at the second factor: limits per network do not stop guesses from endlessly many networks. The account-wide delay never locks; from a known network, or with a passkey, the administrator is not held back by it. The alarm is raised for every account, the last administrator included. Because its waits repeat where another name would be locked, the answers to many failures from one network show which name is the last administrator.

**Passkeys.** A passkey cannot be guessed, so under Home and Standard a passkey sign-in passes the lock of its network: an administrator whose password is being attacked still gets in. Under Hardened the lock holds for a passkey as well (`passkey_holds_lock`). The account-wide delay never applies to a passkey. The break-glass account keeps its own limit (IAM-09).

**Shared addresses.** Clients behind one address share its waits and locks: the hosts of one IPv6 /64, the users behind one NAT address, and every client behind a reverse proxy that is not listed as trusted (`[tls] trusted_proxies`), which then all appear with the proxy's address. List the proxy, or a failing client behind it locks the others out.

**Unlocking.** An administrator lifts the locks of an account in the web UI (`POST /users/{id}/unlock`), on any controller. When no other administrator can sign in, stop the server and run `tenko user unlock <name>` on the host as the service account (for example `runuser -u tenko -- tenko user unlock admin`). It removes every stored lock of the account, records the unlock in the audit log (`auth.user.unlock`, `via: offline`), and gives a PIN whose period has ended a new period ([PINs](#pins)). It runs only as the account that owns the data directory (`exec.unsafe_owner` refuses root, ADR 0023), works on a single controller only (a member of a cluster unlocks from the web UI of another controller), and grants nothing that this account does not already have. The waits a running server kept in memory end when that server stops.

**The bound on password hashing.** Every sign-in attempt costs one Argon2id computation (19 MiB under the baseline parameters, 64 MiB under Hardened), and names that do not exist cost the same. The computations in flight share a memory budget, `[auth] password_hash_memory_mib`. An attempt that finds the budget spent gets `auth.throttled` with a wait of one second at once, before any memory is taken, so a flood of sign-ins cannot take memory from DNS and DHCP. One network has at most two sign-in computations in flight, and a quarter of the budget (at most one computation at the Hardened parameters) is kept for attempts from a known network of the account, so a flood from many networks slows the others without taking every computation. Every sign-in is charged the cost of the dummy verification, whatever its stored hash costs. The default is 64 MiB for each processor the host reports, at least 2 and at most 8 processors (128 to 512 MiB). One computation runs on one processor, so more computations at once would only wait for a processor while they hold their memory. A computation larger than the budget runs alone. An unknown name is verified at the strongest parameters among the stored passwords, and a stored password weaker than that waits as long, so the time of an answer does not tell whether an account exists after a profile change.

## PINs

The PIN preset of Home and Lab takes digits only, at least six of them (IAM-03). A PIN is a choice for accounts without the admin role.

**An administrator never signs in with a PIN.** An account with the admin role has a password of at least 12 characters that is not digits only, in every profile; where the profile asks for more (Hardened: 16), the stricter rule holds. This applies to the first administrator at first-run setup, to an administrator an administrator creates, to an administrator's own change and to a reset. An account that signs in with a PIN cannot be given the admin role until it has such a password. The installer (`deploy/install.sh`), the Proxmox container script, the setup wizard and `tenko setup` say the rule where they ask for the first administrator's password; the installer and the Proxmox script refuse a shorter or numeric one before they install anything, and the server stays the authority for the rest (a breached password, a simple pattern).

**How long a PIN holds.** A six-digit PIN has one million values; a guess needs half of them on average, 500,000. With the default policy:

| Who guesses | Attempts per day | Expected time for a six-digit PIN |
|---|---|---|
| One network, Home (no lock: 10 minutes between attempts once the waits have run) | about 144 | about 9.5 years |
| One network, Standard (8 attempts, then a lock of 30 minutes) | about 237 | about 5.8 years |
| Any number of networks against any account, the last administrator included (the account-wide delay: one attempt per minute, also when attempts arrive together) | about 1,440 | about 350 days |

The figures are per controller: each controller counts in its own memory, so a cluster of three controllers gives an attacker up to three times as many attempts until a lock is stored. A network the account completed a sign-in from lately is held only by the waits of that network, so a guesser who shares it (the same IPv4 address behind a NAT, the same IPv6 /64) gets the per-network figures above. For comparison, a four-digit PIN fell in about 3.5 days per controller under the old progressive delay. Administrators get the alarm `auth.alarm.sign_in_failures` once an account has failed 5 times across networks (`alarm_after_failures`). Lab does not count at all.

**PINs from before the six-digit minimum.** The stored hash does not tell how long a PIN is. A PIN stored before the minimum rose to six digits is therefore marked as one to change until a sign-in shows that it meets the policy. A sign-in with a PIN of six digits or more clears the mark. A sign-in with a shorter PIN succeeds, but the session can do nothing except set a new PIN, and for an administrator the new secret must be a password. A marked PIN works for `unconfirmed_pin_days` (a security setting, 30 by default, 1 to 365) from the first start of the version that introduced the minimum; that date is written once for the installation through the store. After that the PIN is refused like a wrong one: it is hashed, counted and audited. Administrators get one alarm per account (`auth.alarm.pin_expired`), and an administrator resets the PIN. This includes the last administrator, whose way back is `tenko user unlock` on the host: it starts a new period, after which the PIN must be changed at the next sign-in. The users page shows the date a marked PIN stops working. The expiry is decided at each sign-in from the stored dates; the hourly check only raises the alarm, so a check that does not run never keeps an expired PIN working.

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

### Security keys, the session cookie and passkey origins

- **Which security key counts as one (IAM-09, ADR 0010).** Without `[auth] attestation_roots` a security key counts as a hardware key on its `packed` attestation alone, which no maker's root confirms. Its registration is then recorded with `attestation_anchored: false` in the audit record `auth.webauthn.register`, and the server logs a warning. Under Hardened the break-glass account's key must chain to a configured root: without roots, or with roots that do not confirm the key, the registration is refused (403 `auth.webauthn.attestation_untrusted`), and an account becomes the break-glass account only with such a key (400 `auth.invalid_request`). A break-glass key registered earlier, or under another profile before a switch to Hardened, stays.
- **The session cookie.** Over HTTPS the cookie is `__Host-tenko_session` (`Secure`, `Path=/`, no `Domain`, `HttpOnly`, `SameSite=Strict`), which no other host, a sibling subdomain included, can set or replace. Over plain HTTP (the Lab profile, TGL-08) a browser refuses such a cookie, so it is `tenko_session` there. A request is read with the name of its own scheme only, as the server sees the scheme (behind a trusted proxy, the scheme the proxy states).
- **Passkey origins.** A passkey ceremony is accepted from `https://<rp id>` and from `https://<rp id>:<port>` for each port the server listens on, and from no other port. A UI reached through a reverse proxy or a port forward on another port needs that origin in `[auth] origins`; until it is listed, a passkey sign-in there is refused with `auth.webauthn.origin_mismatch`, which names the origin it saw. Password sign-in is not affected.
