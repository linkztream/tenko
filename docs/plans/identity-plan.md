# Identity plan: GSS-TSIG from Windows and directory sign-in for administrators

- Status: Accepted on 2026-10-25: the owner decided every question of section 7 (ID-Q1 to ID-Q18) as recommended, ID-Q13 with one addition (LDAPS must be easy to set up, by importing the certificate chain of the domain controllers in the UI; section 3.13). The plan binds and changes only through rule 2.8 of the execution plan. The owner's standing direction, single node first and cluster-aware (section 2.10 of [phase-2-plan.md](phase-2-plan.md)), binds this work; section 3.20 says how
- Date: 2026-10-25
- Scope: the two identity gaps the owner decided on 2026-10-25 to do "right and well from the start" after the comparison with Infoblox, BlueCat and EfficientIP: (1) secure dynamic updates from Windows clients and domain controllers with GSS-TSIG (DNS-28, CON-03, OPS-11, with what DNS-29, DNS-30 and API-18 need of it), and (2) directory-based sign-in for administrators (IAM-11, IAM-12, IAM-13). Data-plane high availability, the other gap, is planned separately. Written against `main` at `3bee0354`. Requirement IDs refer to [REQUIREMENTS.md](../REQUIREMENTS.md), toggles (TGL) and never-off items (NEVER) to [SECURITY-PROFILES.md](../SECURITY-PROFILES.md), RFC targets to [CONFORMANCE.md](../CONFORMANCE.md). Exit criteria, measurements and risks continue the project's series (E43 onward, M45 onward, and R117 onward after R100 to R116 of the high-availability plan); that plan ([ha-plan.md](ha-plan.md), Slice 12, ADR 0025) uses E60 to E71 and M60 to M68.

This plan does for identity what [dns-recursion-plan.md](dns-recursion-plan.md) did for the recursive resolver: the goal, the exit criteria as checks, one slice, the designs compared for the hard choice (the Kerberos implementation), the contracts the packages share, the work packages with owners and acceptance, the order, the measurements, the risks and the decisions only the owner can take. "(proposed)" marks a choice the documents leave open. Sizes are in builder-days. [ADR 0026](../adr/0026-kerberos-and-directory-identity.md) (Accepted on 2026-10-25) records the decision this plan recommends.

Contents:

1. [Scope and exit](#1-scope-and-exit)
2. [Kerberos for GSS-TSIG: the designs compared](#2-kerberos-for-gss-tsig-the-designs-compared)
3. [Design decisions the packages share](#3-design-decisions-the-packages-share)
4. [Contracts and shared files (WP13.0)](#4-contracts-and-shared-files-wp130)
5. [Work packages](#5-work-packages)
6. [Order, measurements and exit checks](#6-order-measurements-and-exit-checks)
7. [Owner decisions](#7-owner-decisions)
8. [Requirement rows touched](#8-requirement-rows-touched)
9. [Risks](#9-risks)
10. [Owner actions](#10-owner-actions)
11. [Documents this slice writes](#11-documents-this-slice-writes)
12. [Sources](#12-sources)

## 1. Scope and exit

### 1.1 Goal

**Secure updates.** A Windows computer, a domain controller and a Linux host with `nsupdate -g` register their names in an AD zone that Tenko serves as primary, with the zone set to "secure only": each update is signed with GSS-TSIG (RFC 3645) on a security context negotiated by TKEY (RFC 2930) with Kerberos (RFC 4120) inside SPNEGO (RFC 4178), and is accepted only for names the signing principal may change under the ownership rules Windows applies (section 3.6). An unsigned update is refused, which is what makes a Windows client try the secure one. Tenko accepts the Kerberos tickets with the keys of an AD computer account it holds in the vault, as the unprivileged service account on Linux (ADR 0023) and as its virtual service account on Windows, in the static musl binary and in the Windows binary alike, with no system Kerberos library and no keytab file on disk. With that, the take-over runbook ([active-directory.md](../active-directory.md)) stops depending on address lists, the Hardened profile can host an AD zone that takes updates, and member servers with static addresses register themselves again.

**Directory sign-in.** An administrator signs in to the web UI and the API with the organisation's identity: through an OpenID Connect provider (Entra ID, AD FS, Keycloak, Okta), through an LDAP bind against Active Directory or another directory, or, inside an AD domain, with Kerberos through the browser (SPNEGO, reusing the acceptor of the first half). Directory groups map onto Tenko's roles and scopes (IAM-01, ADR 0015); local accounts remain for break-glass (IAM-09) and for service accounts with scoped tokens (IAM-10); the security profile decides how far local person accounts remain beside a directory (section 3.17).

The ROADMAP puts GSS-TSIG in Phase 4 and directory sign-in in Phase 5. ID-Q10 recommends one slice for both in Phase 4: they share the Kerberos acceptor, the directory model and the lab, and the take-over of AD DNS needs both, the first for the records and the second so that the administrators of an AD site sign in as themselves.

### 1.2 Exit criteria

| # | Check | Requirements | Package |
|---|---|---|---|
| E43 | In the lab (section 3.19): a Samba AD domain controller provisioned without its own DNS registers its locator records in a Tenko zone set to secure only through `samba_dnsupdate` (`nsupdate -g`), and a Linux client with `kinit` and `nsupdate -g` adds, replaces and deletes its records over UDP and TCP; the TKEY exchange completes with mutual authentication and every answer is signed and verifies at the client; an unsigned update is REFUSED, an update on an unknown or expired context is answered NOTAUTH with BADKEY, a skewed client gets BADTIME, a replayed signed update is refused, a second principal is refused on a name the first owns, and an offer of NTLM alone is refused | DNS-28, CON-03, TGL-09 | WP13.2 |
| E44 | Owner-run Windows interop (API-18): on a Windows Server test domain (2022 or 2025, controllers without the DNS Server role, Tenko the primary of the domain zone and `_msdcs`, both secure only) every record of each controller's `Netlogon.dns` is registered by Netlogon with GSS-TSIG and refreshed at the hourly registration, also with `UpdateSecurityLevel` set to 256 by group policy; `dcdiag /test:dns` passes; a new Windows 11 client joins the domain through Tenko; a member server with a static address registers its A and PTR records with a secure update and refreshes them; another computer account cannot overwrite them; after a restart of the Tenko node mid-day, which drops its contexts, every client's next update succeeds after a new negotiation; packet captures of a client's and a controller's exchanges are committed to the lab directory | DNS-28, DNS-30, API-18, MIG-18 | WP13.4 (owner-run) |
| E45 | The service account: a pre-staged computer account with a one-time password is taken over by Tenko (the password changed by Tenko, the AES keys derived and stored as a system secret, no administrator credential entered into Tenko); a keytab made with `ktpass` imports and works; a rotation (forced in the lab, every 30 days by default) moves the key version, and tickets issued before it are still accepted until they expire; the self-test reports a missing SPN, a duplicate SPN, a key version Tenko does not hold, an RC4-only account and clock skew above 60 s, each as a health finding with its fix | DNS-28, OPS-09, OPS-11, IAM-16 | WP13.3 |
| E46 | Ownership: the table-driven tests of section 3.6 pass (a new name, an owned name, the owner, a privileged group, a DnsUpdateProxy member, a claimable imported name, the locator names, a record of IPAM, a manual record, a scavenged name within and after its hold); imported records are governed by the owner SIDs of the Windows adapter (MIG-06) or by the claim rule; a secure update refreshes the aging timestamp (DNS-29) without changing the owner | DNS-28, DNS-29, MIG-06 | WP13.2, WP13.4 |
| E47 | OIDC sign-in against Keycloak in the lab and, owner-run, against Entra ID: groups or app roles map to roles and scopes, a user without a mapping is refused, removal from the group takes effect at the next sign-in; a wrong issuer, audience, nonce or state, an expired or unsigned ID token, a token signed with an algorithm off the allow-list and a replayed callback are refused; the profile's MFA rule holds through the provider's `amr` claim or through a Tenko factor | IAM-11, IAM-06, TGL-02 | WP13.5 |
| E48 | LDAP sign-in against the Samba AD controller over LDAPS and StartTLS: a nested group maps through `tokenGroups`, a disabled account and a removed group end the session at the next directory check, an empty password is refused without a bind, a filter value with special characters is escaped, plain LDAP is refused outside Lab and shows the clear-text warning in Lab, a certificate that does not verify is refused; the certificate setup (ID-Q13): the provider setup fetches the chain from the configured server, shows it with its fingerprints and pins it only after confirmation, a chain that changes later is refused and shown rather than pinned again, a pasted or uploaded PEM file and the system trust store work as the other two sources, and, as the acceptance test, LDAPS is configured against the lab's Samba AD controller with a private CA in under five minutes using only the UI | IAM-12, IAM-05 | WP13.6 |
| E49 | Kerberos sign-in to the web UI: `curl --negotiate` from a Linux client with a ticket in the lab and, owner-run, a domain-joined Edge with the site in its allow-list obtain a session whose roles come from the PAC's groups through the mappings | IAM-13 | WP13.7 |
| E50 | Profiles: under Hardened an AD zone takes signed updates only with ownership on, local person accounts cannot sign in once a directory provider is verified (break-glass and service accounts can), and every new action is in the audit log with its principal (NEVER-02, NEVER-03); the toggle rows of section 7 show their values and the banner rules hold | TGL-09, IAM-09, IAM-19 | WP13.8 |
| E51 | Fuzz targets for every new parser (TKEY records, SPNEGO tokens, AP-REQ, the authenticator checksum, the PAC, the keytab file, MIC tokens) run in the weekly fuzz smoke; the counting-allocator test still binds the query path and the TSIG path, now with a GSS-TSIG verification on an established context | API-14, API-15 | WP13.1, WP13.2 |
| E52 | M45 to M49 measured on the musl binary and documented; the conformance rows of section 11 are Implemented, Partial or Deliberately skipped with test references; the exit document records every criterion's state | API-17, OPS-15 | WP13.8 |

### 1.3 The slice

One slice: **Slice 13, Kerberos and directory identity**. Slice 12 is the high-availability plan's ([ha-plan.md](ha-plan.md)).

| Slice | Content | Closes |
|---|---|---|
| 13. Kerberos and directory identity | The spike and the contracts; the Kerberos acceptor and client in pure Rust; TKEY and GSS-TSIG in the update path with ownership per name; the service account's lifecycle and its wizard; the Windows interop lab and the runbook; OIDC; LDAP; Kerberos for the web UI; the measurements and the exit document | E43 to E52 |

### 1.4 Requirements

| Requirement | What this slice delivers | Phase today |
|---|---|---|
| DNS-28 GSS-TSIG | TKEY, GSS-TSIG, the account, ownership, the zone modes (WP13.1 to WP13.4) | 4, Must |
| CON-03 Secure updates mean GSS-TSIG | Met; the constraint's text changes (section 8) | 4 |
| OPS-11 Windows identity for Kerberos | Met differently: neither a gMSA nor a domain account is needed (ID-Q2, section 8) | 4, Must |
| DNS-29 Aging and scavenging | Not built here; the interplay (section 3.8) is a contract its package keeps | 4, Must |
| DNS-30 DC locator | The secure registration of the locator records (E44); the validation of the SRV records stays with its own package | 4, Must |
| API-18 Windows interop lab | The GSS-TSIG and sign-in rows of the lab (E44, E47, E49) | 4, Must |
| MIG-06 Windows DNS source | Uses the owner SIDs it reads (section 3.6); the adapter is not built here | 4, Must |
| IAM-11 SSO | OIDC (WP13.5); SAML not built (ID-Q11) | 4, Must (ID-Q10, decided 2026-10-25; was 5, Should) |
| IAM-12 LDAP/AD group mapping | LDAP sign-in and the group mapping for every provider, with LDAPS set up from the UI by importing the controllers' certificate chain (WP13.5, WP13.6) | 4, Must (ID-Q10, decided 2026-10-25; was 5, Should) |
| IAM-13 Kerberos SPNEGO | Kerberos sign-in to the web UI (WP13.7) | 4, Should (ID-Q10, decided 2026-10-25; was 5, Should) |
| IAM-06, IAM-08, IAM-09, IAM-10, IAM-19 | Applied to directory users: MFA, sessions, break-glass, tokens, attribution (section 3.17) | 1, delivered |
| IAM-16 Vault | New system secret purposes for the Kerberos keys and the providers' secrets | 1, delivered |
| TGL-09 | Its Phase 4 values become real (section 3.7) | 2 (GSS-TSIG in 4) |

### 1.5 Carried items

| Item | Where |
|---|---|
| Phase 2 exit deviation 139 (GSS-TSIG, aging and the AD DNS features are Phase 4; the RRset origin field exists) | GSS-TSIG closed by E43 to E46; aging, GQBL, GlobalNames and netmask ordering stay with their own packages |
| The `Ad` variant of `Origin`, present since Phase 2 and set by nothing | Section 3.6: records imported from an AD zone without a known owner |
| The comment "GSS-TSIG is Phase 4" in `update/policy.rs`; [dns.md](../dns.md) section 13.9 and [active-directory.md](../active-directory.md) section 4, the address-list footing | WP13.2, WP13.4 |
| The comparison of 2026-10-25 (`docs/comparison.md`, untracked): directory sign-in, SSO and GSS-TSIG are gaps against the enterprise three | This plan |
| The ROADMAP's help-wanted line "Sign-in with OIDC (a design note as an ADR first)" | ADR 0026 and WP13.5 |

### 1.6 Left out, with reasons

| Item | Reason | Goes to |
|---|---|---|
| SAML 2.0 | ID-Q11: no maintained pure-Rust service provider without libxml2 and OpenSSL (the `openssl` crates are banned in `deny.toml`), a long record of XML signature wrapping flaws in SAML implementations, and every reference identity provider speaks OIDC; Keycloak bridges a provider that speaks only SAML | Not built unless the owner decides otherwise |
| RADIUS and TACACS+ | ID-Q12: device-administration protocols; RADIUS authenticates with MD5 constructions (CVE-2024-3596), the TACACS+ client crate is MPL-2.0 and stale; nothing in the personas needs them | Not built |
| NTLM in SPNEGO | Windows uses Kerberos for secure updates; NTLM gives no mutual authentication and no PAC Tenko can verify; the Kerberos-only rule is structural, not a toggle | Never |
| RC4-HMAC (RFC 4757), DES and 3DES | The account is AES only (ID-Q3); Microsoft moved the KDC default to AES in April 2026; the crates evaluated carry no RC4 | Deliberately skipped |
| Kerberos FAST, constrained delegation, S4U, PKINIT, user-to-user | An acceptor of updates and sign-ins needs none of them | Not built |
| Tenko as the client of secure updates towards Windows DNS (CONN-13 with GSS-TSIG) | The coexistence actuator is its own Phase 4 package; it reuses the client half of `tenko-krb` (section 3.1) | The CONN-13 package |
| SCIM provisioning (IAM-14) | Accounts appear at first sign-in; deprovisioning is the directory check (section 3.16) | Phase 5 |
| OIDC back-channel and front-channel logout | The `openidconnect` crate does not implement them; Tenko's sessions are short under Standard and Hardened | Later, if a provider needs it |
| A `dns` node without a controller accepting secure updates | Single node first; the keys reach a remote node through node sync's purposes (section 3.20) | Phase 5 |
| A KEK held outside the host (IAM-17) for the Kerberos keys | Same vault, same KEK as every system secret | Phase 5 |

### 1.7 Starting point in the code

Facts the packages build on, read on `3bee0354`:

- **TSIG** (`crates/tenko-dns/src/tsig.rs`). `Keyring` holds `Arc<TsigKey>` in an `ArcSwap` map keyed by the lowercase wire name; `TsigKey` wraps an `aws_lc_rs::hmac::Key`; `verify_request`, `Signer` and `Verifier` hash through `aws_lc_rs::hmac::Context` with the shared helpers `feed_message`, `feed_variables` and `feed_timers`; `Mac` is a fixed 64-octet buffer; `Verified { key, mac, time_signed }` goes to the update path; `FUDGE` is 300 s; answers are always signed; signing and verifying allocate nothing once the key is found (`tests/alloc.rs`). There is no trait for the MAC: HMAC is hard-wired in four places (`verify_request`, `Signer`, `Verifier`, `refusal_tsig`).
- **The update path** (`crates/tenko-dns/src/update/`). `Inner::answer` verifies TSIG first, parses, finds the zone, runs `policy::check(zone, acls, profile, client, key: Option<&KeyName>)`, tests prerequisites against the index and queues per zone; `apply::Planner` checks the policy again per item, applies the origin rules in `may_change`, writes `RrSet { origin: Origin::Dynamic, key, updated }` in `fresh` and commits one batch; the audit actions are `dns.update.apply` and `dns.update.refuse` (rate-limited per client). The identity of an update is a TSIG key name and nothing else.
- **TKEY**. `Rtype::TKEY` (249) exists in `tenko-core`; the query path answers a TKEY question FORMERR in `authoritative.rs` (`early`) and a query that carries TSIG NOTAUTH; the update parser ignores additional records other than OPT and TSIG.
- **The model** (`crates/tenko-core/src/dns.rs`, `dns/rrset.rs`). `RrSet { zone, scope, name, rtype, ttl, rdata, origin, key, updated }`; `Origin::{Manual, Ipam, Dynamic, Dhcp, Ad, Transfer, Dnssec}` with `may_replace`; `UpdatePolicy { allowed, require_tsig, may_replace_ipam, dhcp }`; `AclEntry::{Prefix, Key, Any}`. No owner, no aging timestamp.
- **Authentication** (`crates/tenko-auth`). Local accounts only: `UserRecord` with password, TOTP, recovery codes, passkeys, `break_glass` and `kind` (person or service account); roles `Admin`, `Operator`, `Viewer`, `Auditor`; `GrantRecord { subject, role, scope: ScopeRule, delegable, .. }`; sessions in `auth.sessions` under the hash of a 256-bit secret, cookie `tenko_session` (`HttpOnly; SameSite=Strict`, `Secure` over HTTPS), lifetimes from TGL-04, no refresh token; `AuthStrength` from `Pin` to `HardwareKey`; personal and scoped tokens capped by TGL-05; step-up for reveals (TGL-24); CSRF by an Origin check (`middleware/csrf.rs`). No external identity of any kind, in code or as a stub.
- **The vault** (`crates/tenko-vault`). System secrets (never revealed) and operator secrets; TSIG secrets are system secrets with purpose `dns.tsig`, read by the `dns` role through `ZoneService::tsig_key` and reloaded by `Directory::follow` on a store watch; node sync declares purposes per role for Phase 5 (`crates/tenko-cluster/src/node_sync/secrets.rs`).
- **Platform**. The Linux release is a static-pie musl binary (about 124 MB unstripped, `bench/phase1-server/results/2026-10-16-m9-linux-memory.md`) running in `gcr.io/distroless/static-debian12:nonroot` or under systemd as `tenko`; the Windows service (`crates/tenko/src/platform/windows.rs`) uses `windows-service` and runs as `NT SERVICE\<name>` by default; `unsafe_code = "forbid"` for the workspace; `deny.toml` allows MIT, Apache-2.0 (also with the LLVM exception), BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, MPL-2.0, CC0-1.0 and OpenSSL and bans the `openssl` crates; `aws-lc-rs` 1.18, `rustls` 0.23, `reqwest` 0.12 and `windows` 0.61 are already in the graph; `rsa` is not.
- **Elsewhere**. No LDAP and no Kerberos code anywhere; `tenko-connect-windows` is a placeholder; the Windows adapter of MIG-06 will read `dnsNode` objects over LDAP, and [MIGRATION.md](../MIGRATION.md) already says that ownership comes from their security descriptors.

## 2. Kerberos for GSS-TSIG: the designs compared

### 2.1 What the server side must do

The work of a GSS-TSIG server is smaller than "Kerberos" suggests, and the comparison turns on that. An acceptor never talks to a KDC: the client brings a service ticket encrypted in the service's long-term key, and the server needs that key, a clock and a replay cache. Per exchange:

1. **TKEY in** (RFC 2930, RFC 3645 section 3.1): a QUERY with the question `<key name> TKEY` and a TKEY record in the additional section, algorithm `gss-tsig`, mode 3 (GSS-API negotiation), the client's token in the key data. The key name is the client's choice (Windows uses a generated unique name). Windows sends it over TCP, since the token exceeds 512 octets (observed by third parties; no specification says so).
2. **SPNEGO** (RFC 4178): the token is a `negTokenInit` with a list of mechanisms and, in practice, an optimistic first token. Windows lists the Microsoft Kerberos OID (1.2.840.48018.1.2.2) before the standard one (1.2.840.113554.1.2.2) and may list NegoEx and NTLM; MIT clients may send a raw Kerberos token without SPNEGO. Tenko picks Kerberos, answers with `negTokenResp` (`accept-completed`, `supportedMech` echoing the OID chosen, the AP-REP as response token, a `mechListMIC` when RFC 4178 asks for one), and refuses a list without Kerberos.
3. **AP-REQ** (RFC 4120 section 3.2, RFC 4121 section 4.1): decrypt the ticket with the key of its encryption type and key version, check its times and flags, decrypt the authenticator with the ticket's session key, check the client name against the ticket, the time against the skew (300 s) and the replay cache, read the GSS checksum (type 0x8003: the channel bindings, which DNS leaves empty, and the flags, with mutual authentication and integrity asked by Windows), take the client's subkey and sequence number.
4. **AP-REP**: Windows requires mutual authentication, so the response token carries an AP-REP encrypted in the session key, with an acceptor subkey or not, and the acceptor's sequence number.
5. **The PAC** ([MS-PAC]): an AD ticket carries the client's SIDs (user, primary group, groups, extra SIDs). The server signature is checked with the service key; the KDC signature cannot be checked without the KDC's key, and does not need to be, since only the KDC and a holder of the service key can make a ticket the server accepts.
6. **TKEY out**: NOERROR with the TKEY in the answer section and the output token, signed with TSIG under the new context; [MS-GSSA] section 3.1.5.1 says the request MAC is left out of the digest of this first signed message entirely, not as a zero length.
7. **Every later message** carries TSIG with the algorithm `gss-tsig` and the key name; its MAC is a GSS MIC token (RFC 4121 section 4.2.6.1): a 16-octet header (`04 04`, flags, filler, the sender's sequence number) and HMAC-SHA1-96 over the TSIG digest data followed by that header, under a key derived from the context key with usage 25 (initiator) or 23 (acceptor). The server verifies with the initiator's key and signs its answers with the acceptor's.

Steps 1, 6 and 7 are DNS and belong in `tenko-dns` whatever the choice; steps 2 to 5 are the Kerberos part. Once the context exists, step 7 is one HMAC per message under a key derived once, which `aws-lc-rs` computes without allocating, exactly as TSIG does today. The Kerberos library is therefore needed only to establish a context, off the query path; the per-message MIC is Tenko's own small code over the session key the library hands over.

Two client-side operations are needed by the controller, never by the data plane: an AS exchange and a TGS exchange to test the account (the self-test of section 3.1), and the Kerberos change-password protocol (RFC 3244) to take over and rotate the account's password.

### 2.2 The options

**(a) GSSAPI through the system library.** `libgssapi` (MIT licence) and `cross-krb5` bind `libgssapi_krb5` (MIT Kerberos) or Heimdal through `bindgen` and dynamic linking. That is how BIND does it (`tkey-gssapi-keytab`). It contradicts the release: the static musl binary cannot load a shared library without a dynamic loader, so it would need a glibc build (which the project neither ships nor measures, CONTRIBUTING and the memory notes), or `dlopen` (`unsafe`, an ADR under CON-01, and a host that installs MIT Kerberos). The distroless image has no Kerberos library. The keytab would be a file in the data directory for the library to read (`KRB5_KTNAME`), the replay cache another, and MIT's own configuration (`krb5.conf`) a third input to the process. Mature, and the reference for interop; the wrong shape for this product.

**(b) A pure-Rust Kerberos stack: Devolutions `sspi` and `picky-krb`.** `sspi` 0.23.0 (2026-10-01, MIT OR Apache-2.0, very active: about eight committers in the last two months, latest commit 2026-10-23) implements Kerberos, NTLM and Negotiate as SSPI-shaped packages in Rust. Its Kerberos server side is real (`src/kerberos/server/mod.rs`): `ServerProperties` takes the ticket decryption key as raw bytes (`ticket_decryption_key`, `additional_service_keys` per SPN), the service name, `max_time_skew` and an authenticator cache; the acceptor decrypts the ticket, checks the authenticator, the skew and the replay cache, and builds the AP-REP. The Negotiate rewrite merged on 2026-02-10 (PR 595) added a SPNEGO acceptor for Kerberos and NTLM with `mechListMIC`. `query_context_session_key` returns the session keys, and `change_password` exists for the client side. Gaps: `make_signature` and `verify_signature` answer `UnsupportedFunction` for Kerberos (the MIC of GSS-TSIG; Tenko computes it itself, section 2.1), no keytab parsing (Tenko keeps keys in the vault, not keytabs; an import parser is small), no RC4 (not wanted), integrity-only wrap tokens for AES only (not needed). Its dependencies include `picky` 7.0.0-rc.27 and `rsa` 0.10.0-rc.18 as exact pre-release pins, `picky-krb`, RustCrypto hashes and ciphers, `crypto-bigint`, `rand` 0.10 and `tracing`; `reqwest`, `rustls`, `tokio` and `hickory-resolver` are optional behind `network_client` and `dns_resolver`; no OpenSSL. On Windows it also pulls the `windows` crate. Whether its Linux code contains `unsafe` blocks and whether it builds on musl was not verified (issue 82 asks for musl support; the 2026-09-28 release added musl assets to its NuGet package). `picky-krb` 0.13.0 (2026-10-07, MIT OR Apache-2.0) is the ASN.1 types of RFC 4120, the GSS-API token framing, the PAC, and the AES and DES3 encryption with n-fold and key derivation, over RustCrypto.

**(b') Tenko's own acceptor over `picky-krb`.** The same stack one level lower: Tenko writes steps 2 to 5 (a few hundred lines of SPNEGO and AP-REQ/AP-REP logic) over `picky-krb`'s types and crypto, and the AS, TGS and change-password exchanges of the controller over the same types. Smaller dependency graph (no `picky` with X.509 and RSA, no NTLM, no CredSSP), every decision in Tenko's code and fuzzed by Tenko; but the Windows quirks that `sspi` has already met (the Microsoft OID, `mechListMIC`, DCE-style flags, acceptor subkeys) must be found again, in the lab. A third pure-Rust candidate exists: `krb5` 1.0.0 (MIT OR Apache-2.0), created 2026-10-13 by a single author, claiming a GSS-API acceptor with keytabs, MIC tokens and PAC parsing, AES only, tested against MIT and not against AD: too young to depend on today, worth reading as a reference.

**(c) SSPI on Windows, (b) on Linux.** On Windows the operating system's own SSPI accepts the context under the identity of the service, which is what OPS-11 assumed (a gMSA or a domain account). It needs the `windows` crate's `AcceptSecurityContext`, `MakeSignature` and `VerifySignature`, which are `unsafe extern "system"` functions: Tenko's code would need an `unsafe` exemption (CON-01, an ADR) or a crate that wraps them (`cross-krb5` wraps them on Windows, and binds the system GSSAPI on Unix, so it brings back (a) on Linux). It also needs a Windows host joined to the domain and a service identity with the SPN, which the default virtual account `NT SERVICE\tenko` is not, so the MSI and ADR 0023's Windows terms change. Two code paths for one protocol, each with its own failures, and the Linux path is still (b).

**(d) A helper process.** The Kerberos part runs in a separate executable (a sidecar linked against MIT Kerberos, or `gssproxy` on the host) and Tenko talks to it over a local socket. It keeps the static binary static, but makes the release two artifacts, needs a host package on Linux (against the distroless image and the single binary of ADR 0004), and adds a socket protocol to secure. The argument for it is privilege separation: the helper could hold the service key where the `tenko` account cannot read it. Under the threat model of ADR 0023 that buys little: an attacker who controls the service account can already sign any update through the helper by asking it, and the service key's worth to an attacker (forging tickets to the DNS service, a silver ticket) is a power over Tenko itself, which that attacker already has; the helper does not stop the attacker reaching the vault's other secrets either. The connector plugins of ADR 0012 are the precedent for helper processes, and they are justified by third-party code, not by this.

### 2.3 Comparison

| Criterion | (a) System GSSAPI | (b) `sspi` + `picky-krb` | (b') Own acceptor on `picky-krb` | (c) SSPI + (b) | (d) Helper |
|---|---|---|---|---|---|
| Static musl binary | No (dynamic link or `dlopen`) | Yes (musl build to be proven in the spike) | Yes | Linux part as (b) | Yes, plus a second artifact |
| Windows service | MIT Kerberos for Windows, not done in practice | Same code as Linux | Same code as Linux | Native, needs a domain identity | Second artifact |
| `unsafe` in Tenko | Yes with `dlopen` | None | None | Yes, or `cross-krb5` | None in Tenko, the helper is C |
| Host dependencies | MIT or Heimdal, `krb5.conf` | None | None | Domain-joined host, gMSA | Package on the host |
| Keys | Keytab file on disk | Vault, raw keys | Vault, raw keys | LSA (Windows), vault (Linux) | Helper's keytab |
| Windows interop record | Decades (BIND, Samba) | Devolutions' products against Windows; acceptor side newer (2026) | None until the lab | Native (Windows) | As (a) |
| What Tenko writes | TKEY and MIC glue | TKEY, MIC, keytab import, glue | TKEY, MIC, SPNEGO, AP-REQ/AP-REP, PAC checks, client exchanges | Both | Protocol to the helper |
| Dependency weight | Small Rust, large C | `sspi` with `picky`, pre-release pins, NTLM and CredSSP compiled in | `picky-krb` and RustCrypto | Both | Small Rust |
| Licences | MIT (bindings); MIT Kerberos is BSD-style | MIT OR Apache-2.0 | MIT OR Apache-2.0 | Both | Helper's |
| Fit with ADR 0023 | Keytab file is a new on-disk secret | Good | Good | Windows terms change | A second process with its own account |

### 2.4 Recommendation

(b), decided by a spike before any other package (WP13.0): one pure-Rust Kerberos acceptor on Linux and Windows, in a new crate `tenko-krb` that wraps it behind Tenko's own interface (`Acceptor::step(token) -> Step { Continue(token) | Established(Context, token) }`, `Context { client, realm, sids, session keys, expiry, flags }`, plus the client half), with the keys of the account held in the vault and the MIC tokens computed by Tenko over `aws-lc-rs`. The spike accepts a Samba-issued and a Windows-issued SPNEGO token with a raw AES key through `sspi`'s acceptor, returns the AP-REP the client accepts, exchanges MICs both ways, and measures the musl and Windows builds, `cargo deny`, the `unsafe` count of the graph, the binary size and the compile time. It also builds the same acceptance over `picky-krb` alone, as far as the AP-REQ and AP-REP, to price (b'). If `sspi` fails any of: it builds on musl and on the Windows target, `cargo deny` passes without an exception Tenko cannot justify, its acceptor completes the Windows exchange, or it adds more than 3 MiB to the stripped musl binary, then (b') becomes the choice and `sspi` is kept as a reference. Either way `tenko-krb` is the only crate that names the Kerberos dependency, so changing it later touches one crate. (a), (c) and (d) are rejected for the reasons in 2.2; (c) is the one a later ADR could revisit if a Windows-only customer needs the LSA to hold the key, and nothing in this design prevents adding it behind the same interface.

## 3. Design decisions the packages share

### 3.1 The service account

- **Kind.** An AD **computer account** (ID-Q3), for example `TENKO-DNS$`, in an organisational unit the operator chooses. A computer account has the salt rule of [MS-KILE] that Tenko can compute (the realm in upper case, `host`, the account name in lower case without the `$`, a dot, the realm in lower case), can change its own password with the change-password protocol, and is what CON-03 already names. A user account works too (its salt is the realm and the account name; the keytab import path accepts it), but is not what the wizard creates. A gMSA is not used: its password is a constructed attribute that the members of a group read over LDAP, so Tenko would need an LDAP bind as a principal allowed to read it, and its key version behaviour was not verified.
- **Encryption types.** `msDS-SupportedEncryptionTypes` = 24 (0x18, AES128 and AES256 with SHA-1). The KDC then issues tickets and session keys in AES only, which is also Microsoft's default for accounts without the attribute since April 2026. An account that still carries RC4 is a health finding (E45).
- **SPNs.** `DNS/<fqdn>` for every name under which a Tenko node is the primary of an AD zone (the SOA `mname`; a Windows client asks for a ticket to the server the SOA names). One account per installation holds the SPN of every node (ID-Q6): the SPNs of one account share its keys, so every node accepts with the same key, and a second node needs one more SPN, not another account. `HTTP/<fqdn>` for Kerberos sign-in to the web UI (WP13.7) goes on the same account. An SPN must be unique in the forest; the self-test checks it.
- **Who creates it, and who owns its password** (ID-Q4). The recommended path keeps every administrator credential out of Tenko and every script out of Tenko's hands:
  1. **Pre-staged account with a one-time password (default).** The domain administrator runs a short PowerShell block that is printed in [active-directory.md](../active-directory.md) and versioned with the release, not generated by the node: `New-ADComputer` with the name, the OU, `-ServicePrincipalNames`, `-KerberosEncryptionType AES128,AES256`, and `-AccountPassword` read interactively as a one-time password. In the wizard the operator gives Tenko the account name, the realm and that one-time password; Tenko obtains a ticket for `kadmin/changepw` with it, changes the password to a random one of 120 printable characters (RFC 3244), derives the AES keys itself (PBKDF2 with 4,096 iterations, RFC 3962), learns the key version from a service ticket it requests for its own SPN, stores the keys and forgets both passwords. From then on the password is Tenko's and nobody else knows it. This is the `adcli join --one-time-password` pattern.
  2. **Keytab import.** The administrator creates the account and a keytab on a DC with `ktpass /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /mapuser ...` (or `msktutil` from Linux) and uploads the keytab once; Tenko parses it (MIT keytab format version 2, own parser with a fuzz target), keeps the AES entries for the principal, refuses RC4 and DES entries, and does not keep the file. The password is the administrator's; Tenko does not rotate it, and a password reset in AD needs a new keytab (the self-test says so).
  3. **Not built: a wizard that binds to LDAP with an administrator credential and creates the account itself.** Least friction, but it hands a credential that can create objects in the directory to a system whose own service account the threat model of ADR 0023 assumes may be compromised, and the brief of the owner's privilege boundary (a more privileged account never runs what a less privileged one wrote, and never hands it its credentials) says no. The static PowerShell block is the same amount of work for the administrator, and it is reviewed with the release.
- **Rotation** (ID-Q5). For an account Tenko owns, Tenko changes the password every 30 days by default (a job of `tenko-jobs`): new password and keys are written to the vault as `pending` first, the change-password request is sent, the new key version is read back from a fresh service ticket, the keys move from `pending` to `current` and the old ones to `previous`. A restart in the middle finds `pending` and tests which version the KDC now issues. The previous version is kept until the next rotation, so a ticket issued before the change (ten hours at most by AD's default service ticket lifetime) is still accepted. Rotation also keeps `lastLogonTimestamp` moving, so a script that disables computer accounts that never log on does not disable this one. A domain member's 30-day machine password change ("Domain member: maximum machine account password age") is done by the member's Netlogon for its own account; Tenko's account is not a domain member, so nothing in AD rotates it, and the controllers' own password changes do not touch it.
- **The self-test** runs after setup, after every rotation, daily, and on demand: an AS exchange as the account (the key is right), a TGS exchange for each of its SPNs and an acceptance of that ticket by the node's own acceptor (the SPN maps to this account and the key version is held), the KDC's time from the exchange against the node's (skew), the account's encryption types (from the ticket's encryption type), and a duplicate-SPN check when an LDAP provider of the realm is configured. Each failure is a health finding with its fix (section 3.10). The KDCs are found through `_kerberos._tcp.<realm>` SRV records, which on a take-over Tenko serves itself, or are listed by the operator.

### 3.2 The keys in the vault, and the no-root model

The keys are a system secret with the new purpose `dns.krb` (never revealed, NEVER-01): per key version, the principal, the realm, the key version number, the encryption type and the key bytes, `current`, `previous` and `pending`, as one secret per account. The `dns` role reads them through the same watcher that loads TSIG keys today (`Directory::follow`), so a rotation reaches the acceptor without a restart; the controller writes them. No keytab file exists on disk on either platform, so nothing new appears under the data directory, nothing needs root to install or to read it (ADR 0023 invariants I1 to I4 hold unchanged), and backups carry the keys encrypted like every other system secret. On Windows the KEK is protected by DPAPI as today, and the service keeps running as `NT SERVICE\tenko`: it needs no domain identity, because it never asks the operating system to accept a ticket. A Phase 5 `dns` node receives the keys through node sync's purposes (`("krb", Role::Dns)` beside `("tsig", Role::Dns)`), per request over mTLS and audited, like TSIG keys.

### 3.3 The TKEY lifecycle

- **Where.** A TKEY query is recognised by the query path with one comparison of the question type (as an UPDATE is recognised by its opcode) and handed to a TKEY task on the runtime, off the worker; the worker allocates nothing more for ordinary queries. TKEY is accepted over UDP and TCP, for mode 3 (negotiation) and mode 5 (deletion, which must be signed by the context it deletes); every other mode is answered with BADMODE, an algorithm other than `gss-tsig` with BADALG (the Windows 2000 name `gss.microsoft.com` is refused: that system is long out of support), a key name already in use with BADNAME.
- **The context table.** Per node, in memory, keyed by the key name (lowercase wire form): the state (negotiating or established), the principal, its realm and SIDs, the derived MIC keys for both directions, the sequence window, the client address, the creation time and the expiry. The expiry is the earliest of the ticket's end time and `[dns.gss] context_max_secs` after establishment (3,600 by default, BIND's fallback figure); the client renegotiates after it. A negotiation not completed within 30 s is dropped. Bounds (proposed): 10,000 established and 1,000 negotiating contexts per node (2,000 and 200 under Home), at most 32 negotiating per client address; the oldest idle context leaves first when the table is full, and a refused negotiation is counted. Contexts are not stored or replicated: a restart drops them and clients negotiate again, which is what BIND does and what E44 checks with Windows.
- **Replay.** The acceptor's replay cache keeps the authenticators seen within the skew window (RFC 4120 section 3.2.3); after a start the node accepts only authenticators whose time is later than its start, which refuses a replay of anything sent before a restart without the five minutes of refusals the RFC otherwise asks for. On an established context the sequence numbers of the MIC tokens are checked in a window of 64 (a duplicate is refused, reordering within the window is allowed), so a captured signed update cannot be replayed within the TSIG fudge either.

### 3.4 GSS-TSIG in the TSIG module

`tsig.rs` gains a key abstraction: the keyring holds `MacKey::Hmac(TsigKey)` as today or `MacKey::Gss(Arc<GssContext>)`, and the feed helpers write into a `MacSink` that is either an HMAC context or the MIC computation (HMAC-SHA1 under the derived key, with the token header fed last). The digest data is the same as for TSIG (RFC 3645 section 5.1 refers to RFC 2845), the MAC field holds the 28-octet MIC token (it fits `Mac`), the time check and BADTIME are the same, and the answer is signed with the acceptor's key and the `SentByAcceptor` flag. The first signed message of a context, the TKEY response, omits the request MAC from its digest ([MS-GSSA] 3.1.5.1). The counting-allocator test gains a GSS-TSIG verification on an established context (E51).

### 3.5 The identity of an update, and the policy

`Verified` carries a `Signer`: none, `Tsig(KeyName)` or `Gss(GssIdentity { principal, realm, sid, groups })`. `policy::check` takes the signer instead of the key name. `AclEntry` gains `Kerberos { realm, principal: Option<pattern>, from: Option<prefix>, deny }`: a list entry that allows principals of a realm (optionally matching a name pattern such as `*$` for computers only, optionally from a prefix). The update policy gains `kerberos: Option<KerberosUpdate { realms, ownership, owner_hold_days }>`; `require_tsig` keeps its field name in the API and means "a signature is required, TSIG or GSS-TSIG" (the UI says so). The Windows zone settings map:

| Windows (MS-DNSP `fAllowUpdate`) | Tenko zone `update` |
|---|---|
| None (`ZONE_UPDATE_OFF`, 0) | `allowed` empty |
| Nonsecure and secure (`ZONE_UPDATE_UNSECURE`, 1) | `allowed` with a Kerberos entry and an address entry, `require_tsig = false`, `kerberos` set |
| Secure only (`ZONE_UPDATE_SECURE`, 2) | `allowed` with a Kerberos entry, `require_tsig = true`, `kerberos` set |

The wizard sets "secure only" on the zones the operator names, with one list `ad-<realm>` holding the realm's Kerberos entry. The RRsets an update changes record the signer: `key` as today for TSIG, and a new `principal` (the principal's name, for display and audit) for GSS-TSIG.

### 3.6 Ownership

Windows secures a **name**, not an RRset: the records of a name live in one `dnsNode` object, and its security descriptor says who may change it. Tenko follows that (ID-Q7) and changes the wording of DNS-28 and MIG-06 accordingly (section 8). A new table `dns.name_owners` keyed by zone, scope and name holds `NameOwner { sid: Option<Sid>, principal, since, hold_until: Option<time> }`, written in the same batch as the change. The SID is the key of the match when both sides have one (it survives a rename), the principal name otherwise (an MIT realm has no PAC).

The rules, applied in a zone whose `kerberos.ownership` is `windows` (the default for AD zones; ID-Q8), to an update signed with GSS-TSIG, after the origin rules of [dns.md](../dns.md) section 13.4, which stay as they are (IPAM records only with `may_replace_ipam`, transfer and signer records never):

| The name | Who may change it |
|---|---|
| No owner, no records (a new name) | Any principal the zone's lists allow. The principal becomes the owner, unless it is a member of DnsUpdateProxy: then the name stays without an owner and the next principal that changes it becomes the owner (Microsoft's documented behaviour for that group) |
| Owned | The owner, or a privileged principal |
| A locator name (`_msdcs` zone, `_ldap`, `_kerberos`, `_kpasswd`, `_gc` SRV names, the domain apex A and AAAA, `gc._msdcs`, `DomainDnsZones`, `ForestDnsZones`) | Privileged principals only, whoever registered it first; the controllers count as privileged |
| Imported from an AD zone without a known owner (origin `ad`, owner unset) | A privileged principal, or the principal whose own host name the record carries: `HOST$@REALM` may claim `host.<zone>` (BIND's `ms-self` rule) and a PTR record whose data is `host.<zone>`; the claimant becomes the owner |
| Manual records (origin `manual`) | Privileged principals only, in a zone with ownership on; a Windows administrator's static record is owned by that administrator, never by an authenticated client |
| A name whose last record was removed (scavenged or deleted) | The old owner and privileged principals until `hold_until` (the removal plus `owner_hold_days`, proposed 14; how long Windows keeps a tombstoned node's descriptor is checked in the lab); then a new name |

**Privileged principals** are the members of groups named by SID in the zone's realm settings: Domain Admins (RID 512), Enterprise Admins (519), Domain Controllers (516), and DnsAdmins (no fixed RID; the wizard reads it with an LDAP provider or takes it from `Get-ADGroup DnsAdmins`), plus any group the operator adds. Membership comes from the PAC, so no directory lookup is made on the update path. DnsUpdateProxy is named by SID the same way. A Kerberos principal of a realm without a PAC (MIT) has no group membership and is privileged only when named explicitly. Updates signed with TSIG or unsigned (in a zone that allows them) do not take ownership and may not change an owned name; with `ownership = none` a zone behaves as today.

The Windows adapter (MIG-06) reads the owner SID of each `dnsNode`'s security descriptor into `dns.name_owners`, so a migrated zone keeps its ownership; the zone file and AXFR import mark the records Windows would call dynamic (those with an aging timestamp) as origin `ad` without owner, so they become claimable under the rule above, and keep the static ones as `manual`. That is what keeps the take-over safe: no authenticated client can claim a controller's record or a server's static record, and every client can refresh its own.

### 3.7 Zone modes and the security profiles

TGL-09 gains its Phase 4 values (the row exists; section 8 has the text): Home keeps "None" by default and allows any mode per zone; Standard defaults the zones the wizard enables to secure only and allows "nonsecure and secure" per zone, shown as a deviation; Hardened enforces secure only on every zone with `kerberos` set, with ownership `windows`, and refuses unsigned updates as today; Lab allows everything, loudly. The Kerberos-only rule (no NTLM), AES only and the replay checks are structural and hold in every profile. Two proposed new toggle rows are in section 7: the account's rotation interval, and the local person accounts beside a directory.

### 3.8 Aging and scavenging

DNS-29 is its own Phase 4 package; this plan fixes the contract it keeps. The aging timestamp is a field of the RRset; an update that adds or changes records sets it to now; an update that only re-sends the same data (a refresh, as the Windows DNS client sends every 24 hours and Netlogon every hour) sets it only when the no-refresh interval (7 days by default) has passed, and writes nothing otherwise, so that hourly locator refreshes do not become hourly writes. A refresh is an update like another: it is verified, checked for ownership and audited at the rate limit of a refusal when it writes nothing. Scavenging deletes the records, not the owner, which is held as in section 3.6. Static records (timestamp unset) are never scavenged.

### 3.9 The controllers' registrations and the take-over runbook

Netlogon registers the records listed in `Netlogon.dns` when the controller starts, when the service starts and every hour (MS-ADTS: `DnsRefreshInterval`, 60 minutes by default, TTL 600 s), with the controller's machine account as the principal. With GSS-TSIG shipped, [active-directory.md](../active-directory.md) changes as follows (WP13.4 writes it):

- Section 4 becomes the description of secure updates in Tenko: what the account is, what ownership means, what the profiles require; the address-list footing becomes the variant for a site that does not want a Tenko account in its directory, and the Hardened profile can host an AD zone that takes updates.
- A new step between steps 3 and 4: the Kerberos account (the PowerShell block, the one-time password in the wizard, the self-test), with its check (`tenko dns kerberos status` shows the key versions and the SPNs) and its way back (delete the account; the zones fall back to the address list).
- Step 4: the zones' update policy becomes secure only with the realm's list; the controllers' address list is no longer needed (it may be kept as an extra condition with `from`).
- Step 5: the controllers register with secure updates; `UpdateSecurityLevel` may now be set to 256 by group policy; the check is `nltest /dsquerydns` and the audit records with the controllers' principals.
- The static-address members register themselves; the paragraph that tells the operator to add their records by hand goes.
- The DHCP part: Tenko DHCP keeps its internal path (TGL-29). During a coexistence period a Windows DHCP server that registers for its clients should use a dedicated user account for its DNS credentials (Microsoft's guidance for DHCP on a controller with secure-only zones), not the controller's machine account, which is privileged.

### 3.10 Failure modes

| Failure | What the client sees | What Tenko shows | Fix |
|---|---|---|---|
| Clock skew above 300 s | TKEY refused (BADKEY with the Kerberos error in the output token), or BADTIME on a signed update | `dns.gss.clock_skew` finding with the measured skew (self-test against the KDC), counter `skew` | OPS-09: time synchronisation on the node |
| A ticket for a key version Tenko does not hold | TKEY refused | `dns.gss.kvno_unknown` naming the version seen | Someone reset the password in AD: run the takeover again or import a new keytab |
| Rotation failed | Nothing (the old key stays current) | `dns.gss.rotation_failed` with the KDC's error, alarm after two failures | Usually the account is disabled or its password policy refuses; the self-test names it |
| Account disabled or deleted | The client's KDC request fails; no TKEY reaches Tenko | `dns.gss.self_test_failed` (the AS exchange fails) | Re-enable or re-create |
| SPN missing or duplicate | The client gets no ticket or the wrong one | `dns.gss.spn_missing`, `dns.gss.spn_duplicate` | `setspn -S`, `setspn -Q` |
| RC4 ticket (the account lost its encryption types) | TKEY refused | `dns.gss.weak_etype` | `msDS-SupportedEncryptionTypes` = 24 |
| Node restarted | BADKEY on the old context | Contexts at zero, counter `unknown_context` | None: the client negotiates again (E44) |
| Context table full | TKEY refused | Counter `limit`, finding when it persists | Raise the bound, find the client |
| Only NTLM offered | TKEY refused | Counter `mechanism` | The client cannot get a Kerberos ticket: DNS name, SPN, time |

### 3.11 Audit and metrics

Audit actions (new): `dns.krb.account.adopt`, `dns.krb.account.import`, `dns.krb.account.rotate`, `dns.krb.account.check` (only on failure or change), `dns.krb.account.delete`, `dns.gss.refuse` (a refused negotiation: the client, the reason, the principal when known; at most once a minute per client, like `dns.update.refuse`). `dns.update.apply` and `dns.update.refuse` gain the principal and its SID when signed with GSS-TSIG and the ownership decision (`owner`, `privileged`, `claimed`, `proxy`). Sign-in: `auth.login` gains the method (`password`, `oidc`, `ldap`, `negotiate`, `passkey`, ...) and the provider; new `auth.provider.create`, `.update`, `.delete`, `.verify`, `auth.mapping.create`, `.delete`, `auth.directory.revoke` (a directory check ended or narrowed a session). Never a token, a password, a key or a ticket in a record.

Metrics: `tenko_dns_tkey_total{outcome}` (`established`, `continue`, `deleted`, `mechanism`, `token`, `skew`, `kvno`, `limit`, `unknown_context`), `tenko_dns_gss_contexts{state}`, `tenko_dns_gss_establish_seconds`, and a new label `auth` (`none`, `tsig`, `gss`) on `tenko_dns_updates_total`; `tenko_auth_logins_total{method,outcome}`, `tenko_auth_directory_request_seconds{provider,kind}`.

### 3.12 OpenID Connect

- **Library.** `openidconnect` 4.0.1 (MIT): authorization code flow, discovery, ID token verification (RSA, ECDSA P-256 and P-384, EdDSA), UserInfo, RP-initiated logout, over `reqwest` with `rustls`. It does not verify `azp` (Tenko does) and does not do back-channel logout. It depends on `rsa` 0.9, which carries RUSTSEC-2023-0071 (the Marvin timing attack on private-key operations; ID token verification uses only public-key operations): `cargo deny` needs a justified ignore, or WP13.5 verifies the ID token itself with `aws-lc-rs` over the crate's types (R119).
- **Provider settings.** `OidcProvider { id, name, issuer, client_id, client_secret (a system secret, purpose auth.oidc), scopes, username_claim, groups_claim, mfa: { trust_amr: [values] } | none, ca: optional PEM, button_label, enabled }`. Entra ID: app roles in the `roles` claim are recommended over groups, since a user in more than 200 groups gets an overage marker instead of the `groups` claim; Tenko refuses a sign-in that carries the overage marker with a message that says so, rather than calling Microsoft Graph. AD FS (2016 or later): an application group with a groups issuance rule. Keycloak and Okta: a `groups` claim.
- **Flow.** `GET /auth/oidc/{provider}/start` creates a flow record (`auth.oidc_flows`, state, nonce, PKCE verifier S256, the return path, 10 minutes, single use) and a flow cookie (`tenko_oidc`, `HttpOnly; Secure; SameSite=Lax`, since the callback is a cross-site top-level navigation that a `Strict` cookie would not survive), then redirects to the provider. `GET /auth/oidc/{provider}/callback` matches state and cookie, exchanges the code with the client secret, verifies the ID token (issuer exactly the provider's, audience and `azp`, `exp`, `iat` within the skew, the nonce, the algorithm from an allow-list of RS256, PS256, ES256 and EdDSA, the key from the provider's JWKS, fetched again on an unknown key ID at most once a minute), maps the claims, creates the session with the usual `tenko_session` cookie and answers a small page that moves the browser to the UI. No access or refresh token is kept. Step-up (TGL-24 `fresh`) sends the user through the provider again with `max_age=0`; the session's `authenticated_at` is the ID token's `auth_time`.
- **Discovery.** The provider's metadata is fetched at configuration, verified by a test sign-in (the provider becomes `verified` only after an administrator completed one), and refreshed daily.

### 3.13 LDAP and Active Directory

- **Library.** `ldap3` 0.12.1 (MIT OR Apache-2.0) with the `tls-rustls-aws-lc-rs` feature (`aws-lc-rs` is already in the graph; the default `tls-native` would need OpenSSL). Paged results and the extensible-match filters it parses cover the AD searches. Its SASL GSSAPI feature binds the system GSSAPI and is not used; Kerberos sign-in goes through section 3.14 instead.
- **Transport** (ID-Q13). LDAPS on 636 by default; StartTLS on 389 allowed; plain LDAP only under Lab, with the banner and, on the provider's own setup page, a warning in words that the credentials cross the network in clear text. The certificate is always verified, against one of three sources the setup offers side by side: the chain imported from the server (below), a PEM file that is pasted or uploaded, or the system trust store. Several URLs or `_ldap._tcp.<domain>` SRV discovery for failover.
- **Importing the certificate chain** (the owner's addition to ID-Q13, 2026-10-25: configuring LDAPS must be easy enough that nobody drops to the Lab profile to run plain LDAP with cleartext credentials). The setup page has a button "Fetch the certificate chain" beside the server URL: the controller opens a TLS connection to the configured server (LDAPS, or StartTLS after the LDAP extended request), reads the chain the server presents, sends no credential and no LDAP request beyond StartTLS, and shows each certificate (subject, issuer, validity, key type, subject alternative names, SHA-256 fingerprint) with a plain statement of whether the chain already verifies against the system trust store, so that an administrator sees at once whether a private CA is involved. The administrator confirms by comparing the fingerprints with the ones the domain controller shows (the page gives the `certutil` and `openssl` commands that print them) and ticks which certificates to trust; the default is every certificate above the server's own, else the server's certificate itself with a note that a pin of the server certificate must be redone when it is renewed. Only then is the pin stored with the provider, as trust anchors for this provider alone (never added to the system store or to another provider). Verification at every connection is ordinary path validation against the pinned set, with the server name check and the validity dates; "accept whatever is presented" does not exist as a setting. A chain that changes later (a new CA) is refused with a finding that shows the difference, and is never pinned again without the same confirmation. The fetch is an interactive-session action of an administrator with the right to change providers, connects only to the URL being configured, and keeps nothing before the confirmation. The same screen takes a PEM file by paste or by upload (a bundle of one or more certificates, shown for confirmation in the same way, private keys refused), and offers the system trust store as the third source. In the Samba lab the controller's LDAPS certificate comes from a private CA that is generated per run and trusted by nothing, so that the import is what makes LDAPS work (section 3.19).
- **Binds.** A read-only service account (a system secret, purpose `auth.ldap`) finds the user (by `sAMAccountName` or `userPrincipalName`, with RFC 4515 escaping), reads `objectGUID`, `objectSid`, `userAccountControl` and `accountExpires`, refuses a disabled or expired account, and then Tenko binds as the user's DN with the user's password over the TLS session to check it. An empty password is refused before any bind (an empty simple bind is an unauthenticated bind that succeeds). The groups come from `tokenGroups` (a base-scope read of the user's entry, AD only), which lists every group SID the user holds transitively, the primary group included; for other directories `memberOf`, or a group search, with nesting only where the server resolves it.
- **The directory check.** For the lifetime of a session, at most every `recheck_minutes` (proposed 15 under Home and Standard, 5 under Hardened), the session's next request looks the user up again by `objectGUID` with the service account: disabled, deleted or with changed groups, the session's grants are recomputed or the session ends (`auth.directory.revoke`). A directory that cannot be reached keeps the session for a grace period (proposed 15 minutes, 0 under Hardened) and refuses new LDAP sign-ins; break-glass works throughout.
- **Lockout.** Tenko's own lockout (TGL-07) runs per user name before the directory is asked, so a guessing attack against Tenko does not lock the AD account through AD's own threshold.
- **Strength.** A password bind is `AuthStrength::Password`; where the profile requires a second factor (TGL-02), the LDAP user enrols TOTP or a passkey in Tenko, stored on the user's Tenko record.

### 3.14 Kerberos sign-in to the web UI

`GET /auth/negotiate` answers 401 with `WWW-Authenticate: Negotiate`; the browser (Edge or Chrome with the site in `AuthServerAllowlist`, Firefox with `network.negotiate-auth.trusted-uris`) answers with a SPNEGO token for `HTTP/<fqdn>`, which the same acceptor accepts with the same account's keys (RFC 4559); the AP-REP goes back in the response header, and the PAC's SIDs feed the mappings of the realm's provider (an LDAP provider of that realm, or a `negotiate` provider that holds only SID mappings). The sign-in page offers "Sign in with Windows" only when a negotiate provider is enabled, and navigates the whole window to the route, so the browser's own Negotiate handling applies. Strength: `Password` (Tenko cannot see how the user signed in to Windows). Opt-in per installation (IAM-13 stays Should).

### 3.15 What is not built

SAML (ID-Q11), RADIUS and TACACS+ (ID-Q12), NTLM, and SCIM: section 1.6 gives the reasons.

### 3.16 Mapping groups to roles and scopes

- **The mapping.** `DirectoryMapping { id, provider, group: Sid | Dn | Claim(value), role, scope: Option<ScopeRule> }`. The roles and scope rules are those of [access.md](../access.md): `Admin` and `Auditor` are global and take no scope; `Operator` and `Viewer` take a scope or none. A user's effective rights are the union of the mappings their groups match, plus any local grant an administrator gave the user's Tenko record.
- **Derived, not stored.** Mapped grants are computed at sign-in and at each directory check and held on the session, not written as `GrantRecord` rows, so removing a user from a group takes effect at the next sign-in or check without anyone editing Tenko. A user whom no mapping matches is refused and no record is created.
- **The Tenko record.** At first sign-in a person record is created with `source: External { provider, subject }`, where the subject is immutable (the OIDC `iss` and `sub`, the AD `objectGUID`, the Kerberos SID), never the display name. The record holds what Tenko needs of its own (language, Tenko MFA factors, personal tokens, the last mapped roles for display); it has no password. A rename in the directory renames the display name only.
- **Scopes from the directory.** Site and prefix scopes are named by Tenko ID in the mapping; a later package may map AD sites to IPAM sites (IPAM-22) and so offer "the site's administrators" as a mapping.

### 3.17 Local accounts, break-glass, sessions and tokens

- **Break-glass** (IAM-09) stays a local account with a hardware key only, works whatever the directory does, and raises its alarm as today. Activating a directory provider under Hardened requires a break-glass account to exist.
- **Local person accounts beside a directory** (ID-Q15): allowed under Home, Standard and Lab; under Hardened, once a provider is verified, local person accounts other than break-glass cannot sign in (the accounts are kept, disabled for sign-in, so that switching the provider off restores them). Service accounts are local in every profile (IAM-10).
- **Sessions** (IAM-08): the same table, cookie and lifetimes (TGL-04); the record gains `source` (local, OIDC, LDAP, negotiate with the provider) and `directory_checked_at`. No session is longer than the profile allows, whatever the provider says.
- **MFA and step-up** (ID-Q16): an OIDC provider whose `amr` claim carries one of the values the provider lists as multi-factor (`mfa`, `hwk`, `otp`, ...) yields `PasswordTotp` strength (`HardwareKey` for `hwk` when the provider is marked as attesting it); otherwise the profile's MFA rule asks for a Tenko factor after the provider's sign-in. TGL-24's `passkey` step-up under Hardened is met by a Tenko passkey on the external user's record.
- **Personal tokens of directory users** (ID-Q17): allowed under Home, Standard and Lab within TGL-05, suspended when a directory check ends the user's access and when the user has not signed in for 30 days (OIDC has no check without a sign-in); under Hardened only service accounts hold tokens.

### 3.18 The UI flows

- **Sign-in page:** the local form (user name and password, passkey) and one button per enabled OIDC provider and for Windows sign-in; a user name with an `@suffix` or `DOMAIN\` prefix that names an LDAP provider goes to that provider; a bare name is local, or goes to the default LDAP provider when one is set and no local account has that name.
- **Settings, Sign-in providers:** create an OIDC provider (issuer, client, secret, claims; the redirect URI shown to copy into the provider; "Test sign-in" in a new window, which verifies it), an LDAP provider (URLs, TLS mode, the certificate source with the chain import, the PEM paste or upload and the system trust store, service account, base DN, filters, group mode; the plain-LDAP option, offered under Lab only, carries the clear-text warning; "Test" with a user name and password, which shows the groups found and the roles they would map to), a negotiate provider (realm, SID mappings); each shows its state, last success and last error.
- **Access, Directory mappings:** a table of group to role and scope per provider, with the users currently mapped (from the last sign-ins) and a dry run for a user name.
- **DNS, Active Directory, Kerberos:** a wizard with the realm (and its KDCs, found by SRV or listed), the account name and OU shown together with the PowerShell block filled with those values for the administrator to type on a DC, then the one-time password, then the self-test with its findings; or the keytab upload. Then the zones: a list of the zones of the realm with their current mode and the change to secure only, previewed (API-09) with what changes for the controllers. A status page shows the key versions, the SPNs, the last rotation and self-test, the contexts and the refusals of the last hour.
- **Zone settings, Dynamic updates:** the mode in Windows terms beside the lists, the ownership switch, the privileged groups, and per record the owner and the principal of the last change.

### 3.19 The labs and the acceptance tests

- **`deploy/compose/lab-ad`** (new, weekly on hosted runners, never a pull request gate): a Samba AD domain controller container (`samba-tool domain provision --dns-backend=NONE`, realm `LAB.EXAMPLE.TEST`) whose DNS is the Tenko node, so that its own `samba_dnsupdate` registers the DC records through `nsupdate -g` (E43, a controller-shaped client); a Linux client container with MIT `kinit` and `nsupdate -g` running the rows of E43; LDAPS and StartTLS against the same controller, whose certificate is issued by a private CA generated per run, and the UI end-to-end test of the five-minute LDAPS setup (E48); `curl --negotiate` against the UI (E49); a Keycloak container with a realm export for OIDC (E47). The images are pinned by digest. Samba is GPL-licensed and Keycloak Apache-2.0; both are only run as containers in the lab, nothing of them is copied into the repository or linked. Every secret of the lab is generated per run; the repository is public and so are the runners' logs.
- **The Windows interop lab** (API-18, owner-run, E44 and the Entra ID row of E47): two Windows Server 2022 or 2025 controllers without the DNS Server role and a Windows 11 client, the steps of the rewritten runbook, captures with `pktmon` or Wireshark committed under `deploy/compose/lab-ad/windows/`. A first probe of it runs early, inside WP13.2 (R120): one controller registering through the TKEY code before the rest of the slice is built.
- **Unit and table tests:** the acceptor against recorded tokens (Samba, MIT and Windows captures); MIC vectors; the RFC 3962 key derivation test vectors; the ownership table; the OIDC verifier against crafted tokens; the LDAP filter escaping; fuzz targets `krb_spnego`, `krb_ap_req`, `krb_pac`, `krb_keytab`, `dns_tkey`, `gss_mic` (E51).

### 3.20 Single node first, cluster-aware

The slice builds and measures one node with the `controller` and `dns` roles. What is cluster-aware now: one account per installation with one SPN per node name; the keys a system secret with a node-sync purpose; contexts per node (a client negotiates with the server it updates, so nothing about a context is shared); `dns.name_owners` in the replicated store beside the RRsets it governs; directory sessions in the replicated session table like local ones. A `dns` node without a controller accepting secure updates (it must reach the store with `Dns.Update` anyway) is Phase 5.

## 4. Contracts and shared files (WP13.0)

### 4.1 Model (`tenko-core`)

- `dns`: `UpdatePolicy.kerberos: Option<KerberosUpdate { realms: Vec<Realm>, ownership: Ownership { Windows, None }, owner_hold_days: u16, privileged: Vec<Sid>, update_proxy: Option<Sid> }>`; `AclEntry::Kerberos { realm, principal: Option<String>, from: Option<IpNet>, deny }`; `RrSet.principal: Option<PrincipalName>`; `NameOwner { sid: Option<Sid>, principal: PrincipalName, since, hold_until }`; `Realm`, `PrincipalName`, `Sid` with parsing and validation; `KrbAccount { realm, name, spns, kdcs, owned: bool, rotation_days, versions: [KeyVersionMeta], last_rotation, last_check }` (metadata only; the keys are the secret); the aging timestamp is not added here (DNS-29's package).
- `auth` (in `tenko-auth`): `UserSource { Local, External { provider, subject } }` on `UserRecord`; `DirectoryProvider { Oidc(..), Ldap(..), Negotiate(..) }` with a state (`draft`, `verified`, `disabled`), the LDAP variant holding its `LdapTrust { System, Pem { certs }, Imported { certs, fingerprints, confirmed_by, confirmed_at } }` (certificates only, never a key); `DirectoryMapping`; `SessionRecord.source` and `directory_checked_at`; `OidcFlow`.
- Tables: `dns.name_owners`, `dns.krb_accounts`, `auth.providers`, `auth.mappings`, `auth.oidc_flows`, `auth.external_ids` (provider and subject to user ID, unique).

### 4.2 Crates

- **`tenko-krb`** (new): `keys` (RFC 3962 string-to-key with the AD salt rules, key derivation, n-fold), `keytab` (import parser), `acceptor` (SPNEGO and the Kerberos mechanism, replay cache, the PAC), `mic` (RFC 4121 MIC tokens over `aws-lc-rs`), `client` (AS, TGS, change password over UDP and TCP to port 88 and 464, used by the controller only). The only crate that names `sspi` or `picky-krb`. `#![forbid(unsafe_code)]` like every crate.
- **`tenko-directory`** (new): the LDAP client over `ldap3` (find, bind, `tokenGroups`, the check) and the OIDC client over `openidconnect`, so that `tenko-auth` stays free of network clients and the Windows adapter of MIG-06 can reuse the LDAP part.
- `tenko-dns`: `tkey` (the handler and the context table), the `MacKey` and `MacSink` change in `tsig`, the `Signer` in `update`, the ownership rules in `update::apply`.

### 4.3 API, CLI and UI

- Routes (session only where `interactive_only` says, annotated per [api/README.md](../api/README.md)): `GET /dns/kerberos`, `POST /dns/kerberos/adopt`, `POST /dns/kerberos/import`, `POST /dns/kerberos/check`, `POST /dns/kerberos/rotate`, `DELETE /dns/kerberos`; `GET /dns/zones/{id}/owners` (paged); `GET, POST /auth/providers`, `GET, PATCH, DELETE /auth/providers/{id}`, `POST /auth/providers/{id}/test`, `POST /auth/providers/ldap/chain` (fetches the chain from the URL in the body and returns it with its fingerprints and whether it verifies against the system store; session only; it stores nothing, the pin is made by the provider's create or update call that carries the confirmed certificates); `GET, POST /access/directory-mappings`, `DELETE /access/directory-mappings/{id}`; public: `GET /auth/oidc/{id}/start`, `GET /auth/oidc/{id}/callback`, `GET /auth/negotiate`, `GET /auth/providers/public` (the buttons); `POST /auth/login/password` gains an optional `provider`.
- CLI: `tenko dns kerberos status|adopt|import|check|rotate|delete`, `tenko auth provider ...` (including `tenko auth provider ldap-chain <url>`, which prints the chain and fingerprints), `tenko access mapping ...`.
- Codes: `dns.gss.*` and `dns.krb.*` (the findings of 3.10 and the refusals), `auth.provider.*`, `auth.directory.*`, `auth.oidc.*`; i18n units in `sv` and `en`.
- Configuration: `[dns.gss] context_max_secs, contexts_max, negotiating_max, per_client_max, skew_secs`.

### 4.4 Shared files the lead owns

REQUIREMENTS.md, SECURITY-PROFILES.md, ROADMAP.md, CONFORMANCE.md, `deny.toml` (the new crates' licences are on the list; an advisory ignore needs the lead), the workspace `Cargo.toml` dependencies, `scripts/requirement-trace.mjs` (section 11).

## 5. Work packages

Every package below touches `crates/tenko-krb/**`, `crates/tenko-directory/**`, `crates/tenko-auth/**`, `crates/tenko-api/src/routes/auth*`, `crates/tenko-api/src/routes/access*`, `crates/tenko-dns/src/{tsig,tkey,update}/**`, `crates/tenko-core/src/dns.rs` (the fields of 4.1), `ui/src/auth/**`, `ui/src/settings/**`, `ui/src/dns/**` (the Kerberos and zone settings pages), `deploy/compose/lab-ad` and the documents of section 11; within the slice one package owns each file, as listed.

### Slice 13: Kerberos and directory identity

#### WP13.0 The spike and the contracts (6 builder-days)

- **Requirements:** DNS-28, IAM-11, IAM-12 (the shared model).
- **Owns:** `bench/spike-krb/` (a standalone package, excluded from the workspace) with its result file; section 4 in code: the model, the tables, the route stubs answering 501, codes, audit actions, metric families, configuration keys, the UI route stubs, the empty `lab-ad` compose services; ADR 0026 refined with the spike's figures.
- **Depends on:** the owner's answers to section 7.
- **Content:** 1. the spike of section 2.4 (`sspi` acceptor against a Samba token and a recorded Windows token with a raw AES key, the AP-REP accepted by MIT's `gss_init_sec_context` in the client container, MICs both ways; the same over `picky-krb` alone up to AP-REP; musl and Windows builds; `cargo deny`; the `unsafe` count of the graph; the stripped size difference; compile time); 2. the model with validation and property tests; 3. the tables; 4. the stubs; 5. the choice between (b) and (b') written into ADR 0026.
- **Acceptance:** the result file answers each criterion of section 2.4 with a figure; workspace builds; model tests pass; `cargo deny` passes; the trace (section 11) regenerated.
- **Risk:** R117, R118, R119, R133.

#### WP13.1 `tenko-krb`: the acceptor, the keys and the client (14 builder-days)

- **Requirements:** DNS-28, CON-03, IAM-13 (the same acceptor).
- **Owns:** `crates/tenko-krb/**`, its fuzz targets.
- **Depends on:** WP13.0.
- **Content:** 1. keys and salts with the RFC 3962 vectors and the MS-KILE salt examples; 2. the keytab import parser; 3. the acceptor over the spike's choice: SPNEGO (both Kerberos OIDs, raw Kerberos tokens, `mechListMIC`), AP-REQ checks, replay cache, AP-REP, PAC with the server signature; 4. MIC tokens over `aws-lc-rs` with the derived keys held per context; 5. the client: AS exchange with pre-authentication, TGS exchange, change password, over UDP with the TCP fallback; 6. fuzz targets `krb_spnego`, `krb_ap_req`, `krb_pac`, `krb_keytab`, `gss_mic`.
- **Acceptance:** recorded Samba, MIT and Windows tokens accepted and wrong ones refused for each check; the MIC accepted by MIT's `gss_verify_mic` in the client container and MIT's accepted by Tenko; the client changes a password on the Samba controller and obtains a ticket with the new key; fuzz targets in the weekly smoke; no `unsafe`.
- **Risk:** R117, R126.

#### WP13.2 TKEY and GSS-TSIG in the update path, with ownership (14 builder-days)

- **Requirements:** DNS-28, TGL-09, DNS-11 (the update path it extends).
- **Owns:** `crates/tenko-dns/src/tkey/**`, the `MacKey` change in `tsig.rs`, `Signer` and the ownership rules in `update/**`, the query path's hand-off of TKEY in `authoritative.rs`, the `dns_tkey` fuzz target, the `gss` round of `lab-ad` (E43), [dns.md](../dns.md) section 13 (the GSS-TSIG part).
- **Depends on:** WP13.1 (the acceptor's interface can be stubbed from WP13.0 for the first days).
- **Content:** 1. TKEY modes 3 and 5 with the context table and its bounds; 2. GSS-TSIG verify and sign with the MS-GSSA rule; 3. `Signer` through policy, planner, RRset `principal` and audit; 4. `AclEntry::Kerberos`; 5. `dns.name_owners` and the table of section 3.6; 6. metrics; 7. the counting-allocator rows; 8. the early Windows probe of R120 with the owner.
- **Acceptance:** E43 in the lab; the ownership table tests (E46 rows that do not need MIG-06); the alloc test; no change to the TSIG tests beyond the new key type; M21 unchanged (within 5 percent).
- **Risk:** R120, R121, R122, R125.

#### WP13.3 The account's lifecycle and the wizard (9 builder-days)

- **Requirements:** DNS-28, OPS-09, OPS-11, IAM-16.
- **Owns:** `crates/tenko-dns/src/zone/kerberos.rs` (the controller side: adopt, import, rotation job, self-test, findings), the `dns/kerberos` routes and CLI, the UI wizard and status page, the vault purpose `dns.krb` and its node-sync declaration, the static PowerShell block in [active-directory.md](../active-directory.md).
- **Depends on:** WP13.1.
- **Content:** 1. adopt with a one-time password; 2. keytab import; 3. rotation with the pending state and recovery; 4. the self-test and the findings of 3.10; 5. the watcher that hands the keys to the acceptor; 6. the routes, CLI and UI.
- **Acceptance:** E45 against the Samba controller (the adopt, the rotation, the restart between the change and the commit, the findings); the PowerShell block run once in the owner's Windows lab (with WP13.4).
- **Risk:** R123, R124, R130.

#### WP13.4 The AD semantics, the Windows interop lab and the runbook (7 builder-days, plus the owner's lab time)

- **Requirements:** DNS-28, DNS-30, API-18, MIG-06 (the owner field it fills).
- **Owns:** the locator-name list and the import marking of section 3.6 in `crates/tenko-dns/src/zone/import*`, the zone settings UI for ownership and owners, `deploy/compose/lab-ad/windows/` (the steps and the captures), the rewrite of [active-directory.md](../active-directory.md) sections 4 to 6.
- **Depends on:** WP13.2, WP13.3.
- **Content:** 1. the import marking (origin `ad` without owner for dynamic records); 2. the owner view per zone; 3. the owner-run lab of E44 with the lead; 4. the runbook.
- **Acceptance:** E44 (owner-run) and the remaining rows of E46; the runbook followed once end to end in the Windows lab.
- **Risk:** R120, R121, R134.

#### WP13.5 Directory sign-in: the model, the mappings and OIDC (12 builder-days)

- **Requirements:** IAM-11, IAM-12 (the mapping), IAM-06, IAM-08, IAM-10.
- **Owns:** `crates/tenko-auth/src/{directory,external}/**` (sources, mappings, derived grants, the profile rules of 3.17), the OIDC half of `crates/tenko-directory`, the provider and mapping routes, the OIDC routes, the sign-in page buttons, the providers and mappings UI, the Keycloak service of `lab-ad`, a new `docs/sign-in.md`.
- **Depends on:** WP13.0; runs beside WP13.1 to WP13.3.
- **Content:** 1. the external user model and the derived grants; 2. providers and their verification; 3. the OIDC flow and verifier (with the R119 decision); 4. MFA from `amr`; 5. the Hardened rule for local accounts; 6. UI.
- **Acceptance:** E47 against Keycloak (the owner runs the Entra ID row); the route tests of [api/README.md](../api/README.md) for the new public routes; the CSRF and cookie tests for the callback.
- **Risk:** R119, R128, R129.

#### WP13.6 LDAP and AD sign-in (10 builder-days)

- **Requirements:** IAM-12, IAM-05.
- **Owns:** the LDAP half of `crates/tenko-directory` (with the chain fetch), the directory check in `tenko-auth`, the LDAP provider UI and test dialog (with the certificate setup: the chain confirmation screen, the PEM paste and upload, the trust-store source, the plain-LDAP warning), the LDAP rows of `lab-ad` (with its private CA), the five-minute UI end-to-end test under `ui/e2e`.
- **Depends on:** WP13.5.
- **Content:** 1. find, bind and `tokenGroups`; 2. `memberOf` and group search for other directories; 3. the check and the grace; 4. user name routing; 5. UI; 6. the certificate setup of LDAPS (the owner's addition to ID-Q13, section 3.13): the chain fetch over LDAPS and StartTLS, the confirmation screen with the fingerprints and the pin, the refusal of a changed chain, the PEM paste and upload, the system trust store as the third source, the clear-text warning on the plain-LDAP option, and the private CA of the lab.
- **Contracts:** `LdapTrust`, `POST /auth/providers/ldap/chain` and `tenko auth provider ldap-chain` (sections 4.1 and 4.3), the finding codes `auth.provider.chain_changed` and `auth.provider.chain_unverified`.
- **Acceptance:** E48 against the Samba controller, including the five-minute test: with the lab's private CA, LDAPS is configured using only the UI in under five minutes, from an empty provider list to a successful "Test" that shows the groups found (a Playwright test in `ui/e2e` that makes no API call and edits no file, run by the weekly lab job, failing above 300 s, and timed once by hand at the exit); an OpenLDAP row with `memberOf` (a container in the lab).
- **Size:** 10 builder-days, one more than the 9 of the draft, for the chain fetch, the confirmation screen, the PEM alternative, the trust-store source, the warning and the UI test; the slice's total becomes 82.
- **Risk:** R127, R136.

#### WP13.7 Kerberos sign-in to the web UI (4 builder-days)

- **Requirements:** IAM-13.
- **Owns:** `GET /auth/negotiate`, the negotiate provider, the `HTTP/` SPN in the account's wizard, the sign-in page button.
- **Depends on:** WP13.1, WP13.3, WP13.5.
- **Acceptance:** E49.

#### WP13.8 Measurements, profiles and the exit document (6 builder-days)

- **Requirements:** E50 to E52; TGL-09 and the proposed rows.
- **Owns:** `bench/phase4-identity/` with its scripts and results (M45 to M49), the acceptance tests `crates/tenko/tests/acceptance_identity*.rs`, `docs/plans/identity-exit.md`, the conformance rows (with the lead).
- **Depends on:** every other package.
- **Acceptance:** E50 to E52.

Total: 82 builder-days, of which WP13.1 and WP13.2 are the critical path (about 34 days after the spike).

## 6. Order, measurements and exit checks

### 6.1 Order

WP13.0 first (the spike decides the stack). Then two lines: the Kerberos line WP13.1, WP13.2 and WP13.3 (WP13.2 and WP13.3 in parallel once WP13.1's interface is merged), then WP13.4; the directory line WP13.5 then WP13.6, which needs nothing of the Kerberos line. WP13.7 joins both. WP13.8 last. At most two builders at a time beside the other open slices (R132); the Kerberos line goes first in the lead's queue, since the owner's take-over waits for it.

### 6.2 Measurements

| # | Measurement | Threshold | Package |
|---|---|---|---|
| M45 | GSS-TSIG updates on established contexts, 1,000 updates per second for 60 s from 100 contexts, as M21 | p99 from send to answer under 250 ms; within 10 percent of M21's figure | WP13.8 |
| M46 | TKEY negotiations per second, from cold, with the M21 load generator extended | At least 500 per second with p99 under 50 ms (10,000 clients renegotiating after a restart in 20 s) | WP13.8 |
| M47 | Binary size of the stripped musl release before and after the slice | At most 4 MiB more, of which the Kerberos stack at most 3 MiB (the spike's criterion) | WP13.0, WP13.8 |
| M48 | Idle RSS of the musl binary with the home zones and no contexts, and with 10,000 contexts | No more than 0.5 MiB above the figure before the slice without contexts (M23 is already at its limit); at most 8 MiB more with 10,000 | WP13.8 |
| M49 | Sign-in latency on the Tenko side (the callback for OIDC, the bind and group read for LDAP, the Negotiate exchange), against the lab's Keycloak and Samba | p99 under 300 ms | WP13.8 |

## 7. Owner decisions

Each question lists its options, the trade-offs and the recommendation. Document changes the recommendations imply are listed in section 8 (the lead's files). The owner decided every question on 2026-10-25 as recommended, ID-Q13 with the addition recorded under it; each question ends with the decision.

Toggle rows (SECURITY-PROFILES.md, the lead's file; applied on 2026-10-25, the new rows as TGL-32 to TGL-36 in the order below):

| Toggle | Home | Standard | Hardened | Lab | Where |
|---|---|---|---|---|---|
| TGL-09 Dynamic updates from external clients (the row exists; the values are refined) | None by default; any mode per zone | TSIG; secure only for the zones the Kerberos wizard enables, nonsecure and secure allowed per zone as a deviation | TSIG or GSS-TSIG only, secure only with ownership on every zone with Kerberos, unsigned rejected | Unsigned allowed | WP13.2 |
| TGL-32 Kerberos account password rotation | 30 days | 30 days | 30 days, a failed rotation alarms | Off allowed (30 days by default) | WP13.3 |
| TGL-33 Local person accounts beside a verified directory provider | Allowed | Allowed | Break-glass only | Allowed | WP13.5 |
| TGL-34 Directory transport for LDAP | LDAPS or StartTLS, verified | LDAPS or StartTLS, verified | LDAPS only, verified | Plain allowed, with the clear-text warning | WP13.6 |
| TGL-35 Directory check interval and grace | 15 minutes, 15 minutes grace | 15 minutes, 15 minutes grace | 5 minutes, no grace | 15 minutes, 15 minutes grace | WP13.6 |
| TGL-36 Personal tokens of directory users | Allowed within TGL-05 | Allowed within TGL-05 | Not allowed (service accounts only) | Allowed | WP13.5 |

**ID-Q1. How does Tenko accept Kerberos?**
- Options: (a) the system GSSAPI library; (b) a pure-Rust stack on `sspi` and `picky-krb`; (b') Tenko's own acceptor over `picky-krb`; (c) SSPI on Windows with (b) on Linux; (d) a helper process.
- Trade-offs: section 2.3. (a) breaks the static musl binary and the distroless image and puts a keytab file on disk; (c) needs `unsafe` or `cross-krb5` and a domain-joined Windows identity, and two code paths; (d) is two artifacts for no gain under ADR 0023's threat model; (b) and (b') keep one binary, one code path, no `unsafe`, keys in the vault, and differ in dependency weight against interop already met.
- **Recommendation: (b), confirmed or replaced by (b') by the spike of WP13.0 against the criteria of section 2.4, behind the one crate `tenko-krb`.**
- **Decided (2026-10-25): (b), the pure-Rust stack on `sspi` and `picky-krb` behind `tenko-krb`, confirmed or replaced by (b') by the spike of WP13.0.**

**ID-Q2. On Windows: the same pure-Rust acceptor, or native SSPI under a gMSA (OPS-11)?**
- Options: (a) the same acceptor and keys from the vault, the service under its virtual account; (b) native SSPI with the service running as a gMSA or domain account holding the SPN.
- Trade-offs: (a) is one code path, needs no domain-joined host and no change to the MSI or to ADR 0023's Windows terms, and tests on Linux what runs on Windows; the key is in Tenko's vault rather than the LSA. (b) keeps the key in the LSA and rotates it with the gMSA, but needs `unsafe` FFI, a joined host, and a second implementation to keep in step.
- **Recommendation: (a); OPS-11 is rewritten (section 8).**
- **Decided (2026-10-25): (a), the same acceptor on Windows, keys from the vault.**

**ID-Q3. What kind of account, with which encryption types?**
- Options: (a) a computer account, AES only (`msDS-SupportedEncryptionTypes` = 24); (b) a user account; (c) a gMSA.
- Trade-offs: (a) has a computable salt, can change its own password, and is what CON-03 names; (b) works but its salt depends on the UPN and its password falls under user password policies; (c) needs an LDAP read of a constructed attribute by an allowed principal and was not verified for key versions.
- **Recommendation: (a); (b) is accepted through the keytab import.**
- **Decided (2026-10-25): (a), a computer account with AES only; a user account through the keytab import.**

**ID-Q4. Who creates the account, and who owns its password?**
- Options: (a) the administrator pre-stages it with a static PowerShell block and a one-time password, and Tenko takes the password over; (b) the administrator creates it and a keytab with `ktpass` or `msktutil` and uploads the keytab; (c) a Tenko wizard binds to LDAP with an administrator's credential and creates it.
- Trade-offs: (a) keeps every directory credential and every script out of Tenko and makes the password Tenko's alone, so rotation is possible; (b) leaves the password with the administrator and rotation manual; (c) is the least friction but hands a credential that can create directory objects to a system assumed compromisable (ADR 0023) and breaks the owner's privilege boundary.
- **Recommendation: (a) as the default, (b) supported; (c) not built.**
- **Decided (2026-10-25): (a), pre-staged with a one-time password that Tenko takes over; (b) the keytab import supported; (c) not built.**

**ID-Q5. Is the account's password rotated, and by whom?**
- Options: (a) Tenko rotates every 30 days through the change-password protocol, keeping the previous key version; (b) no rotation; (c) rotation on demand only.
- Trade-offs: (a) limits the life of a stolen key and keeps the account active for clean-up scripts, at the cost of a job that must survive a crash between the change and the commit (the pending state); (b) is simpler and is what most standalone service accounts get; (c) leaves it to memory.
- **Recommendation: (a), with the toggle row above; for an imported keytab (ID-Q4 (b)) rotation is (b) and the self-test reports the password's age.**
- **Decided (2026-10-25): (a), rotation every 30 days through the change-password protocol; none for an imported keytab.**

**ID-Q6. One account per installation, or one per node?**
- Options: (a) one account holding `DNS/<fqdn>` of every node (and `HTTP/<fqdn>`); (b) one account per node.
- Trade-offs: (a) is one key to rotate and deliver, a second node is one more SPN; (b) separates keys per node, which buys nothing while every node holds the vault's other secrets anyway.
- **Recommendation: (a).**
- **Decided (2026-10-25): (a), one account per installation.**

**ID-Q7. Ownership per name or per RRset?**
- Options: (a) per name, as Windows secures a `dnsNode`; (b) per RRset, as DNS-28 and MIG-06 say today.
- Trade-offs: (a) is what Windows clients and controllers expect and what the owner SIDs from the directory describe; (b) would let a second principal add another type at an owned name, which Windows does not allow.
- **Recommendation: (a), with DNS-28 and MIG-06 reworded.**
- **Decided (2026-10-25): (a), ownership per name.**

**ID-Q8. Which ownership rules?**
- Options: (a) Windows' rules (any authenticated principal creates, the creator owns, DnsUpdateProxy leaves names unowned, privileged groups by SID) plus Tenko's protections (locator names for privileged principals only, manual records protected, imported names claimable only by their own host, an owner hold after removal); (b) Windows' rules alone; (c) BIND's `krb5-self`/`ms-self` rules (a host updates only its own name).
- Trade-offs: (a) behaves like Windows for every client and closes the take-over's gap that an imported record has no owner; (b) would let the first authenticated client claim every imported record, the controllers' included; (c) breaks controllers, which register names that are not their own, and PTR records.
- **Recommendation: (a).**
- **Decided (2026-10-25): (a), Windows' rules plus Tenko's protections.**

**ID-Q9. How do the zone modes and the profiles combine?**
- Options: (a) the Windows modes mapped onto the existing policy (section 3.5) with TGL-09's values above; (b) a new mode field replacing `require_tsig`.
- Trade-offs: (a) changes no field of the existing API and keeps every Phase 2 zone as it is; (b) is cleaner to read but is an API change for every client of the zone settings.
- **Recommendation: (a).**
- **Decided (2026-10-25): (a), the Windows modes mapped onto the existing policy.**

**ID-Q10. Where does the slice sit, and what happens to IAM-11 to IAM-13?**
- Options: (a) Slice 13 in Phase 4 for both halves, with IAM-11 and IAM-12 moved to Phase 4 as Must and IAM-13 to Phase 4 as Should; (b) the Kerberos half in Phase 4, directory sign-in in Phase 5 as the ROADMAP says; (c) the directory half first, now.
- Trade-offs: (a) is what the owner's "right and well from the start" asks for and shares the lab and the acceptor; it adds about 25 builder-days to Phase 4. (b) keeps Phase 4 smaller and leaves the take-over's administrators on local accounts. (c) delivers SSO soonest but the take-over waits.
- **Recommendation: (a), Kerberos line first.**
- **Decided (2026-10-25): (a), Slice 13 in Phase 4 for both halves, the Kerberos line first.**

**ID-Q11. SAML?**
- Options: (a) not built, Keycloak as the bridge for a SAML-only provider; (b) built over `samael`; (c) built over a pure-Rust crate such as `saml-rs`.
- Trade-offs: (b) needs libxmlsec1 and OpenSSL, which the static binary and `deny.toml` exclude; (c) relies on a crate created in 2026 without an audit, for the protocol whose signature wrapping flaws are the classic SSO break; every reference target (Entra ID, AD FS, Okta, Keycloak) speaks OIDC.
- **Recommendation: (a); IAM-11's text drops SAML (section 8).**
- **Decided (2026-10-25): (a), SAML not built; Keycloak bridges a SAML-only provider.**

**ID-Q12. RADIUS or TACACS+?**
- Options: (a) neither; (b) RADIUS for administrators.
- Trade-offs: (b) serves sites that keep administrators in a RADIUS server with tokens; it is an MD5-based UDP protocol (Blast-RADIUS) and its crates are stale; such sites have an IdP or AD as well.
- **Recommendation: (a).**
- **Decided (2026-10-25): (a), neither RADIUS nor TACACS+.**

**ID-Q13. How does Tenko bind to LDAP?**
- Options: (a) a read-only service account finds the user and checks the directory later, the user's own bind checks the password, over LDAPS (StartTLS allowed), `tokenGroups` on AD; (b) the user's bind only, no service account; (c) SASL GSSAPI binds.
- Trade-offs: (a) allows the directory check during a session (disabled accounts and removed groups take effect); (b) needs no stored credential but can only check at sign-in; (c) needs the system GSSAPI in `ldap3`.
- **Recommendation: (a); (b) allowed under Home as a provider setting, with the check limited to sign-in.**
- **Decided (2026-10-25): (a), a read-only service account and the user's own bind over LDAPS, StartTLS allowed, `tokenGroups` on AD; (b) allowed under Home as a provider setting. The owner added: configuring LDAPS must be easy enough that nobody drops to the Lab profile to run plain LDAP with cleartext credentials, so the provider setup fetches the certificate chain of the domain controllers from the configured server, shows it with the fingerprints for confirmation and pins it, takes a pasted or uploaded PEM file or the system trust store as the other sources, and shows a clear-text warning on the plain-LDAP option (Lab only). The acceptance test is LDAPS configured against the lab's Samba AD with a private CA in under five minutes using only the UI (section 3.13, WP13.6, E48).**

**ID-Q14. How do directory groups become rights?**
- Options: (a) mappings of group to role and scope, evaluated at sign-in and at each check, held on the session, with a Tenko record created at first sign-in keyed by the immutable subject; (b) groups copied into stored grants by a synchronisation job; (c) SCIM.
- Trade-offs: (a) never leaves a stale grant beyond a check interval and needs no job; (b) grants persist when the job fails; (c) is Phase 5 and needs the IdP to push.
- **Recommendation: (a).**
- **Decided (2026-10-25): (a), mappings evaluated at sign-in and at each check.**

**ID-Q15. Do local person accounts remain beside a directory?**
- Options: (a) under Hardened only break-glass once a provider is verified, elsewhere allowed; (b) allowed everywhere; (c) break-glass only in every profile.
- Trade-offs: (a) gives Hardened one source of truth for people, keeps home use simple; (c) would be wrong for a home with one local administrator and a Keycloak for the family.
- **Recommendation: (a), the toggle row above.**
- **Decided (2026-10-25): (a), break-glass only under Hardened once a provider is verified, allowed elsewhere.**

**ID-Q16. MFA and step-up for directory users?**
- Options: (a) trust the provider's `amr` for the values the provider lists, else a Tenko factor; LDAP and Kerberos users count as password strength and enrol a Tenko factor where the profile asks; Hardened's passkey step-up met by a Tenko passkey; (b) always a Tenko factor; (c) always trust the provider.
- Trade-offs: (a) avoids double prompts where the IdP does MFA and stays strict where it cannot be seen; (b) annoys every Entra user with a second prompt; (c) trusts a claim the provider may not send.
- **Recommendation: (a).**
- **Decided (2026-10-25): (a), trust the provider's `amr` for the values it lists, else a Tenko factor.**

**ID-Q17. Personal API tokens for directory users?**
- Options: (a) allowed within TGL-05, suspended by the directory check and after 30 days without a sign-in, not under Hardened; (b) not allowed, service accounts only; (c) allowed as for local users.
- Trade-offs: (c) lets a token outlive the person's directory account; (b) is safest and the Hardened answer; (a) keeps the CLI convenient for administrators elsewhere.
- **Recommendation: (a), the toggle row above.**
- **Decided (2026-10-25): (a), allowed within TGL-05 and suspended by the directory check, not under Hardened.**

**ID-Q18. How is interoperability proven?**
- Options: (a) a weekly container lab on hosted runners (Samba AD as controller and LDAP server, MIT clients, Keycloak) plus the owner-run Windows lab and an optional Entra ID test tenant; (b) the owner-run Windows lab only; (c) Windows on hosted runners.
- Trade-offs: (a) catches regressions every week without Windows and keeps the real Windows proof for the slice's exit; (b) leaves every change unproven until the owner runs the lab; (c) a domain controller on a hosted runner per run is slow and fragile.
- **Recommendation: (a).**
- **Decided (2026-10-25): (a), the weekly container lab plus the owner-run Windows lab and an optional Entra ID tenant.**

## 8. Requirement rows touched

No new requirement IDs. Edits to the lead's files, applied on 2026-10-25 after the decisions (the IAM-12 text carries the chain-import sentence of the owner's addition to ID-Q13):

| Row | Today | Applied |
|---|---|---|
| CON-03 (constraint text) | "... an AD computer account with the SPN `DNS/<host>`, a keytab (Linux) or SSPI under that identity (Windows), and ownership per RRset ..." | "... an AD computer account with the SPN `DNS/<host>`, its AES keys held in Tenko's vault on every platform (no keytab file, no system Kerberos library, ADR 0026), and ownership per name with the Windows rules ..." |
| DNS-28 | "AD secure dynamic updates: GSS-TSIG (RFC 3645) over TKEY, SSPI on Windows and krb5 on Linux. A wizard sets up the computer account and the SPN `DNS/<host>`. Ownership is tracked per RRset, with a 'secure only' mode per zone (CON-03)." | "AD secure dynamic updates: GSS-TSIG (RFC 3645) over TKEY with Kerberos in SPNEGO, accepted by Tenko's own Kerberos acceptor on Linux and Windows (ADR 0026). A wizard takes over a pre-staged computer account with the SPN `DNS/<host>` (or imports a keytab) and rotates its password. Ownership is tracked per name with the Windows rules, and each zone has the Windows modes (none, nonsecure and secure, secure only) (CON-03)." |
| DNS-30 | "... Netlogon re-registers them every hour; the DNS client refreshes the host records every 24 h." | Adds: "Both register with GSS-TSIG in zones set to secure only (DNS-28)." |
| OPS-11 | "On Windows, Tenko runs as a gMSA or domain account so that Kerberos works (CON-03)." | "On Windows, Tenko runs under its virtual service account; Kerberos for GSS-TSIG and web sign-in uses the keys of its AD computer account from the vault, as on Linux, so neither a gMSA nor a domain account is needed (CON-03, ADR 0026)." |
| IAM-11 | "SSO via OIDC and SAML. Reference targets: AD FS, Entra ID and Okta." Phase 5, Should | "SSO via OIDC (authorization code with PKCE). Reference targets: Entra ID, AD FS, Keycloak and Okta. SAML is not built; a SAML-only provider is bridged through Keycloak (ADR 0026)." Phase 4, Must (ID-Q10) |
| IAM-12 | "LDAP/AD group mapping." Phase 5, Should | "Directory sign-in over LDAP (LDAPS or StartTLS) against AD and other directories, with nested AD groups through `tokenGroups`; directory groups of every provider map onto roles and scopes, re-checked during the session. The LDAPS setup fetches the certificate chain from the configured server, shows it with its fingerprints for confirmation and pins it; a PEM file or the system trust store are the alternatives." Phase 4, Must |
| IAM-13 | "Kerberos SPNEGO, which is expected in AD environments." Phase 5, Should | "Kerberos SPNEGO sign-in to the web UI with the acceptor of DNS-28." Phase 4, Should |
| MIG-06 | "... for ownership per RRset ..." | "... for ownership per name (the owner SID of each `dnsNode`) ..." |
| API-18 | "... Netlogon re-registration against Tenko with GSS-TSIG." | Adds: "A container lab (Samba AD, MIT clients, Keycloak) runs the GSS-TSIG, LDAP, Kerberos and OIDC rows weekly." |

ROADMAP: the Phase 4 GSS-TSIG bullet reworded as DNS-28 above and "Identity" moved from Phase 5 to Phase 4 (IAM-11 to IAM-13; SCIM and the external KEK stay in Phase 5); the help-wanted OIDC line points at this plan. SECURITY-PROFILES.md: TGL-09's values and the proposed rows of section 7. CONFORMANCE.md: section 11.

## 9. Risks

| # | Risk | Proposed resolution |
|---|---|---|
| R117 | `sspi`'s acceptor misses a Windows behaviour (the Microsoft OID, `mechListMIC`, an acceptor subkey, DCE-style flags) or its session-key interface does not give the keys a MIC needs | The spike against a recorded Windows token before anything else; (b') as the fallback; fixes sent upstream; everything behind `tenko-krb` |
| R118 | `sspi` pins pre-release crates (`picky` 7.0.0-rc, `rsa` 0.10.0-rc) and its family churns (a yanked `picky-krb` release in 2026) | Exact versions in the workspace, `cargo deny` and `cargo audit` as gates, upgrades as their own changes; (b') drops `picky` and `rsa` |
| R119 | RUSTSEC-2023-0071 in `rsa` (through `openidconnect`, and `picky` if (b)) fails `cargo deny` | Only public-key operations are used; an ignore with that reason, reviewed by the lead; or ID token verification over `aws-lc-rs` in `tenko-directory` |
| R120 | Windows does something no specification says (TKEY only over TCP, the retry after BADKEY, the context reuse, the TSIG digest of the first message) | The early probe against one real controller inside WP13.2; captures kept as test fixtures; the BIND and Samba behaviour as the reference |
| R121 | Tenko's ownership differs from Windows in a corner (tombstones, DnsUpdateProxy, a controller replacing another's record) | The table of 3.6 tested against what the Windows lab shows; the differences documented in [dns.md](../dns.md) |
| R122 | Name squatting through imported records without owners | The claim rule (own host only), the locator names for privileged principals, manual records protected |
| R123 | A crash between the KDC accepting the new password and the vault storing it loses the account | Pending keys written first; recovery by testing which key version the KDC issues; the old key kept |
| R124 | A clean-up script disables the account because it never logs on; an administrator resets its password | Rotation and the daily self-test keep it active and detect the reset; the runbook names the account's OU and says to exclude it from clean-up |
| R125 | TKEY negotiations as a denial of service (CPU for ticket decryption, memory for contexts) | Off the worker, bounds per node and per address, the negotiation timeout, M46 |
| R126 | The new parsers (SPNEGO, AP-REQ, PAC, keytab, TKEY, MIC) carry the bugs Kerberos implementations are known for | Bounds-checked readers, fuzz targets before merge (E51), no `unsafe`, recorded tokens from three implementations |
| R127 | LDAP pitfalls: the empty-password bind, filter injection, a directory that does not verify | Empty passwords refused before the bind, RFC 4515 escaping with tests, certificate verification always (plain only in Lab) |
| R128 | OIDC pitfalls: mix-up between providers, missing state or nonce, algorithm confusion, `azp` | Per-provider redirect URIs and issuers, PKCE, state and nonce, an algorithm allow-list, `azp` checked, crafted-token tests against Keycloak |
| R129 | The provider or the directory is down and administrators are locked out | Break-glass required before Hardened disables local accounts; the grace period elsewhere; local accounts kept, only disabled for sign-in |
| R130 | A more privileged account runs what a less privileged one wrote: a script generated by a compromised node and run by a domain administrator | The PowerShell block is static, in the documentation and versioned with the release; the wizard shows values, never code; no administrator credential enters Tenko (ID-Q4) |
| R131 | Samba AD in containers on hosted runners is slow or flaky (privileges, extended attributes) | Weekly job, not a pull-request gate; images pinned; the unit tests run on recorded tokens without the lab |
| R132 | Quota: this slice beside the high-availability slice, the rest of Phase 3 and Phase 4's migration work | At most two builders; the Kerberos line first; small leaf tasks split off; the lab runs while builders are idle |
| R133 | Binary size and idle memory grow (M23 is already at its limit) | M47 and M48 thresholds; `sspi` without `network_client` in the data plane if it fits, the controller's client exchanges over Tenko's own sockets |
| R134 | Forests with several domains: tickets from a child domain, SID filtering, a realm Tenko does not list | `realms` per zone; the Windows lab with one domain at the exit, a child domain as an owner-run extension; documented limit |
| R135 | Clock skew between the node and the controllers | OPS-09; the self-test's skew finding at 60 s, well before Kerberos' 300 s |
| R136 | The chain import is trust on first use: an attacker on the path at the moment of setup could present a chain of their own, and an administrator who confirms without comparing would pin it | The confirmation screen shows the fingerprints and the commands that print them on a controller; the pin is made only after the confirmation, by an administrator's interactive session; a later change of the chain is refused and shown, never pinned again silently; a PEM file from the organisation's CA is the alternative that needs no first use |

## 10. Owner actions

| When | Action |
|---|---|
| Before WP13.0 | Read the plan; answer ID-Q1 to ID-Q18 (done on 2026-10-25) |
| During WP13.0 | One Windows Server VM with a test domain (a controller and a client) to record a SPNEGO token for the spike; the lead gives the commands |
| During WP13.2 | The early probe (R120): the test controller pointed at the lab node for an hour |
| WP13.4, E44 | The Windows interop lab: two controllers and a Windows 11 client, the runbook's steps, the captures |
| WP13.5, E47 | Optional: an Entra ID test tenant with an app registration for the Entra ID row |
| The take-over at home, after the exit | Run the PowerShell block on a controller, the wizard, the zones to secure only, optionally `UpdateSecurityLevel` 256 by group policy; the runbook's checks |

## 11. Documents this slice writes

| Document | Package |
|---|---|
| ADR 0026: Kerberos and directory identity | Written as Proposed with this plan; Accepted on 2026-10-25 with the decisions; refined by WP13.0 |
| [dns.md](../dns.md) section 13 (GSS-TSIG, ownership, the modes, the audit), a new section on the Kerberos account | WP13.2, WP13.3 |
| [active-directory.md](../active-directory.md) sections 4 to 6 (section 3.9) | WP13.3, WP13.4 |
| `docs/sign-in.md` (new: providers, mappings, the profile rules, the UI) and [access.md](../access.md) (mappings beside grants) | WP13.5, WP13.6, WP13.7 |
| `docs/dns-contracts.md` (tables, routes, codes, audit actions, metrics) | WP13.0 |
| [observability.md](../observability.md) (the families of 3.11), [SECURITY-PROFILES.md](../SECURITY-PROFILES.md) (the lead's file) | WP13.8; the lead |
| `deploy/compose/lab-ad` with its README, `bench/spike-krb`, `bench/phase4-identity` | WP13.0, WP13.2, WP13.8 |
| `docs/plans/identity-status.md`, `docs/plans/identity-exit.md` | the lead; WP13.8 |
| CONFORMANCE.md rows: 2930 (TKEY, Partial: modes 3 and 5), 3645 (from Planned), 4120 (acceptor and the client exchanges, Partial), 4121 (MIC tokens; wrap not used), 4178 (acceptor), 3961 and 3962, 3244, 4757 and 8009 (Deliberately skipped: RC4; AES-SHA2 types that AD does not use), 4559, 4511 and 4513 (client, Partial), 4515, 6749 and 7636 (authorization code with PKCE), 7517 and 7519 (JWKS and JWT, through the crate) | every package |

**The trace.** `scripts/requirement-trace.mjs` traces Phases 1 to 3 and reads exit criteria only from the plans its `PHASES` table names; E43 to E52 live here and belong to Phase 4, which the script does not trace yet. This document names requirements of Phases 1 to 3 (IAM-05, IAM-06, IAM-08 to IAM-10, IAM-16, IAM-19, DNS-11, OPS-09, OPS-15, API-14, API-15, API-17), so the Phase 1 to 3 trace files count it among the documents that name them; they are regenerated with this plan. When Phase 4 gets its trace, the lead adds this plan to its entry in `PHASES`.

## 12. Sources

Read on 2026-10-25.

Specifications:

- RFC 2930, Secret Key Establishment for DNS (TKEY RR): https://www.rfc-editor.org/rfc/rfc2930.html
- RFC 3645, GSS-TSIG: https://www.rfc-editor.org/rfc/rfc3645.html
- RFC 4120, Kerberos V5 (replay cache, section 3.2.3; clock skew, section 1.6): https://www.rfc-editor.org/rfc/rfc4120.html
- RFC 4121, Kerberos V5 GSS-API mechanism version 2 (MIC tokens, section 4.2.6.1): https://www.rfc-editor.org/rfc/rfc4121.html
- RFC 4178, SPNEGO: https://www.rfc-editor.org/rfc/rfc4178.html
- RFC 3962, AES encryption for Kerberos 5: https://www.rfc-editor.org/rfc/rfc3962.html
- RFC 3244, Microsoft Windows 2000 Kerberos change password and set password protocols: https://www.rfc-editor.org/rfc/rfc3244.html
- RFC 4559, SPNEGO-based Kerberos and NTLM HTTP authentication: https://www.rfc-editor.org/rfc/rfc4559.html
- [MS-GSSA] section 3.1.5.1, the first signed TKEY response: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gssa/7a9486bd-3426-4b06-8663-8063ef4d959b
- [MS-DNSP] DNS_ZONE_UPDATE values: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d4b84209-f00c-478f-80d7-8dd0f1633d9e
- [MS-ADTS], the DC locator records and the Netlogon defaults: https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/76bc11f0-8bc2-4d6c-a643-328f479aae1b
- [MS-ADTS], msDS-ManagedPassword: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
- [MS-KILE], cryptographic material and the salt rules: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/7a7b081d-c0c6-46f4-acbf-a439664270b8

Microsoft behaviour:

- DNS_TSIG_DATA, the algorithm names: https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_tsig_dataa
- Dynamic update and the client sequence (unsigned first, then secure): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc784052(v=ws.10)
- Enable or disable DNS dynamic registration (UpdateSecurityLevel, DefaultRegistrationRefreshInterval): https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/enable-disable-dns-dynamic-registration
- Aging and scavenging: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc757041(v=ws.10)
- Zone security and the default ACL: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc780538(v=ws.10)
- DnsUpdateProxy and DHCP: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc787034(v=ws.10) and https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd334715(v=ws.10)
- DHCP DNS update credentials: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd145315(v=ws.10)
- Secure dynamic update (Windows 2000): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959275(v=technet.10)
- ktpass: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ktpass
- Keytab files and key versions: https://learn.microsoft.com/en-us/archive/blogs/pie/all-you-need-to-know-about-keytab-files
- Machine account password age: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age
- Clock synchronisation tolerance: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization
- RC4 changes for CVE-2026-20833: https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc
- Detect and remediate RC4: https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
- Kerberos over DNS observed on the wire (TCP, SPNEGO with Kerberos): https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/

Other implementations:

- BIND 9.18 reference, `tkey-gssapi-keytab` and `update-policy`: https://bind9.readthedocs.io/en/v9.18.13/chapter6.html
- ISC, CVE-2018-5741 (`krb5-subdomain` and `ms-subdomain`): https://kb.isc.org/docs/cve-2018-5741
- `nsupdate` manual (`-g`, `-o`): https://manpages.debian.org/bookworm/bind9-dnsutils/nsupdate.1.en.html
- Samba, BIND9_DLZ back end and `dns.keytab`: https://wiki.samba.org/index.php/BIND9_DLZ_DNS_Back_End
- `msktutil` manual: https://manpages.debian.org/bookworm/msktutil/msktutil.1.en.html
- `adcli` manual: https://manpages.debian.org/bookworm/adcli/adcli.8.en.html
- MIT `krb5.conf` (clockskew): https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html
- Go GSS-TSIG reference: https://pkg.go.dev/github.com/bodgit/tsig/gss

Crates:

- `sspi`: https://crates.io/api/v1/crates/sspi, https://docs.rs/sspi/latest/sspi/, https://docs.rs/sspi/latest/sspi/trait.Sspi.html, https://raw.githubusercontent.com/Devolutions/sspi-rs/master/src/kerberos/server/mod.rs, https://raw.githubusercontent.com/Devolutions/sspi-rs/master/Cargo.toml, https://github.com/Devolutions/sspi-rs/pull/595, https://github.com/Devolutions/sspi-rs/pull/774, https://github.com/Devolutions/sspi-rs/commits/master
- `picky-krb`: https://crates.io/api/v1/crates/picky-krb, https://raw.githubusercontent.com/Devolutions/picky-rs/master/picky-krb/src/lib.rs, https://raw.githubusercontent.com/Devolutions/picky-rs/master/picky-krb/src/crypto/cipher.rs, https://raw.githubusercontent.com/Devolutions/picky-rs/master/picky-krb/Cargo.toml
- `libgssapi`: https://crates.io/api/v1/crates/libgssapi, https://raw.githubusercontent.com/estokes/libgssapi/master/libgssapi-sys/build.rs
- `cross-krb5`: https://raw.githubusercontent.com/estokes/cross-krb5/master/Cargo.toml, https://raw.githubusercontent.com/estokes/cross-krb5/master/README.md
- `krb5` (pure Rust, 2026): https://github.com/ddalton/krb5
- `kerberos_keytab` (AGPL-3.0, excluded): https://crates.io/api/v1/crates/kerberos_keytab; `keytab-io`: https://crates.io/api/v1/crates/keytab-io
- `windows-sys` `AcceptSecurityContext`: https://docs.rs/windows-sys/latest/windows_sys/Win32/Security/Authentication/Identity/fn.AcceptSecurityContext.html
- `hickory-proto` record types (no TKEY): https://docs.rs/hickory-proto/latest/hickory_proto/rr/rdata/index.html
- `openidconnect`: https://crates.io/api/v1/crates/openidconnect, https://raw.githubusercontent.com/ramosbugs/openidconnect-rs/main/README.md
- `ldap3`: https://crates.io/api/v1/crates/ldap3, https://raw.githubusercontent.com/inejge/ldap3/master/Cargo.toml, https://raw.githubusercontent.com/inejge/ldap3/master/README.md, https://raw.githubusercontent.com/inejge/ldap3/master/CHANGELOG.md, https://raw.githubusercontent.com/inejge/ldap3/master/src/filter.rs
- `samael`: https://crates.io/api/v1/crates/samael, https://github.com/njaremko/samael/issues; `saml-rs`: https://docs.rs/crate/saml-rs/0.6.1
- `radius`: https://crates.io/api/v1/crates/radius; `tacacs-plus`: https://crates.io/api/v1/crates/tacacs-plus

Project documents: [REQUIREMENTS.md](../REQUIREMENTS.md), [SECURITY-PROFILES.md](../SECURITY-PROFILES.md), [active-directory.md](../active-directory.md), [dns.md](../dns.md) section 13, [access.md](../access.md), [secrets.md](../secrets.md), [MIGRATION.md](../MIGRATION.md), [phase-2-plan.md](phase-2-plan.md) sections 1.6 and 2.5, [phase-2-exit.md](phase-2-exit.md) deviation 139, [no-root-plan.md](no-root-plan.md), ADR 0012, ADR 0015, ADR 0023.
