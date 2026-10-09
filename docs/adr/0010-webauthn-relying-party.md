# ADR 0010: WebAuthn relying-party implementation without OpenSSL

- Status: Accepted
- Date: 2026-10-09

## Context

Passkeys and hardware security keys are Slice 1 login factors (IAM-06), the break-glass account logs in with a hardware security key only (IAM-09), and exit criterion E2 of the Phase 1 plan requires passkey login with a platform authenticator and with a hardware key. ARCHITECTURE.md named `webauthn-rs` as the library; it depends on `openssl` and `openssl-sys` through `webauthn-rs-core` and `webauthn-attestation-ca`, which `deny.toml` bans (risk R8). The owner decided on 2026-10-09 (plan decision Q2) that WP1.2 evaluates the OpenSSL-free relying-party crates against `cargo deny`, `cargo audit`, test coverage and maintenance, and that a minimal in-house verifier (ES256, EdDSA, RS256; attestation `none` and `packed`) is written if none passes.

What Tenko needs from a relying party: the registration and authentication ceremonies; discoverable credentials (login without a user name); the algorithms ES256 (COSE -7), EdDSA with Ed25519 (-8) and RS256 (-257, which Windows Hello uses); attestation `none` and `packed` (self attestation and an `x5c` chain); the flags UP, UV, BE and BS; the signature counter; and enough attestation detail to tell a synced passkey from an attested, non-backup-eligible hardware key (`AuthStrength::Passkey` against `AuthStrength::HardwareKey`, and the break-glass rule).

Method: every candidate went into its own scratch package under the OS temporary directory with the workspace `deny.toml`, then `cargo deny check`, `cargo audit` (advisory database of 2026-10-09) and `cargo tree -e normal` (unique crates, the candidate included). Algorithms, attestation formats and discoverable-credential support were read from the source; test functions were counted in the published crate; release history and repository activity were taken from crates.io and the repositories on 2026-10-09. Default features throughout.

| Crate | `cargo deny` | `cargo audit` | Crates | Crypto backend | ES256 / EdDSA / RS256 | `none` / `packed` | Discoverable | Tests | Maintenance |
|---|---|---|---|---|---|---|---|---|---|
| `webauthn-rs` 0.5.5 (reference) | fails: `openssl`, `openssl-sys` banned | passes | 95 | OpenSSL | yes / yes / yes | yes / yes | yes | extensive | mature, several maintainers |
| `webauthn_rp` 0.3.0 | fails: RUSTSEC-2023-0071 (`rsa` 0.9.10) | fails: RUSTSEC-2023-0071 | 90 | RustCrypto (`p256`, `p384`, `ed25519-dalek`, `rsa`) | yes / yes / yes | yes / yes | yes | 36 | since 2023-12, 10 releases, last 2025-04-03, self-hosted repository |
| `structured-webauthn` 0.1.0 (fork of `webauthn_rp`) | fails: RUSTSEC-2023-0071 (`rsa` 0.10.0-rc.19) | fails: RUSTSEC-2023-0071 | 89 | RustCrypto, adds `ml-dsa` | yes / yes / yes | yes / yes | yes | 72 | first release 2026-10-08, needs Rust 1.99 |
| `passkey-auth` 0.1.3 | passes | passes | 90 | RustCrypto (`p256`, `ed25519-dalek`, `x509-cert`) | yes / yes / **no** | yes / yes | yes | 46 | 4 releases within 5 days (2026-05), 1 contributor, no activity since |
| `passkey-server` 0.1.4 | passes | passes | 62 | RustCrypto (`p256`) | yes / **no** / **no** | yes / **no** | yes | 3 | 5 releases 2026-02 to 2026-04 |
| `caden` 0.9.0 | passes | passes | 48 | `ring`, `x509-parser` | yes / yes / yes | yes / yes | yes | 323 | since 2026-06, 4 releases, 2 contributors, 0 stars |
| `webauthn-kit` 0.4.0 | passes | passes | 55 | `ring`, `x509-parser` | yes / yes / yes | yes / yes | partial (no user-handle lookup helper) | 205 | since 2026-09-04, 9 releases in 5 weeks, last 2026-10-08, 5 open issues |
| `passki` 0.4.0 | passes | passes | 33 | `aws-lc-rs`, `x509-cert` | yes / yes / yes | yes / yes | yes | 332 | since 2026-01, 9 releases (0.1 to 0.4), 1 contributor, 1 star |
| In-house verifier (this decision) | passes | passes | 0 new | `aws-lc-rs` (already in the graph) | yes / yes / yes | yes / yes | yes | W3C vectors and a software authenticator | owned by Tenko |

Findings:

1. The `rsa` crate carries RUSTSEC-2023-0071 (Marvin attack, timing side channel) with no patched release, neither 0.9.10 nor the 0.10 release candidates. RSA signature verification is not exposed to the side channel, but the advisory fails `cargo deny` and `cargo audit`, and an ignore entry is crate-wide: it would also hide the advisory from any later use of `rsa` for decryption or signing. This rules out `webauthn_rp` and `structured-webauthn`, and also the RustCrypto stack (`p256`, `ed25519-dalek`, `rsa`) that the plan named for the in-house fallback.
2. Of the crates that pass both checks, `passkey-auth` has no RS256 and `passkey-server` has neither EdDSA nor RS256 nor `packed`, so neither supports Windows Hello. `caden` and `webauthn-kit` cover the scope but bring `ring` as a second native cryptography library next to `aws-lc-rs` (rustls and the vault), plus `x509-parser`. `passki` covers the scope on `aws-lc-rs` with the smallest graph and the most tests, and is the best technical fit.
3. None of the crates that pass is older than ten months or has more than two contributors; each has at most one repository star and a few thousand downloads, and their APIs change between minor versions (`passki` went from 0.1 to 0.4 in nine months; `webauthn-kit` released nine times in five weeks, the last on the day before this evaluation). For the login path of a product whose break-glass account depends on it, that is a bus factor of one with no external review, so none passes the maintenance criterion.
4. The WebAuthn Level 3 specification (W3C, section 16) publishes deterministic test vectors for exactly the needed scope: ES256 without attestation and with self attestation, `packed` attestation with ES256, RS256 and Ed25519 credentials under one attestation root, and negative cases (`crossOrigin`, `topOrigin`). They replace the FIDO Alliance conformance tools, which require membership.

## Decision

1. **Tenko implements a minimal WebAuthn relying-party verifier** in `tenko-auth` (module `webauthn`) on `aws-lc-rs` for every cryptographic primitive: ECDSA P-256 with SHA-256, Ed25519, RSASSA-PKCS1-v1_5 with SHA-256 (2048 to 8192 bit moduli), SHA-256, and random challenges. CBOR goes through `ciborium` and JSON through `serde_json`; attestation certificates are read with a small DER reader in the same module. No crate enters the dependency graph that is not there already.
2. **Scope** (WebAuthn Level 3, sections 7.1 and 7.2): client data type, challenge and origin (exact match against the configured origins); `crossOrigin: true` and a `topOrigin` are refused; RP ID hash; user presence always required; user verification required for passwordless login and configurable elsewhere; BS without BE refused; algorithms -7, -8 and -257 only; attestation formats `none` and `packed`. A `packed` statement with `x5c` is verified with the section 8.2.1 certificate requirements and, when the operator configures attestation trust anchors, must chain to one of them. Other formats are refused with `auth.webauthn.unsupported_attestation`. A non-zero signature counter that does not increase is refused as a possible clone.
3. **Discoverable credentials**: a login starts without a user name and with an empty allow list; the credential id and the user handle (the 16 bytes of the user's UUID) identify the account at finish.
4. **Strength**: a credential is a hardware key (`AuthStrength::HardwareKey`) when it was registered with a verified `packed` `x5c` attestation (chained to a configured anchor when there are any) and is not backup eligible, at registration and in every assertion; any other credential is a passkey (`AuthStrength::Passkey`). The break-glass account accepts only hardware keys (IAM-09); a synced passkey (BE set) is refused at registration and at login.
5. **Conformance**: the WebAuthn Level 3 vectors of sections 16.1 to 16.7, 16.10 and 16.11 are recorded fixtures (the ES384, ES512, Ed448, TPM, Android Key, Apple and FIDO U2F vectors as expected refusals); a software authenticator in the tests (P-256, Ed25519 and RSA keys from `aws-lc-rs`, and an attestation certificate it issues itself) drives both ceremonies end to end, with one negative test per check.
6. **Replaceable**: routes and storage see only the module's types; credential records store the COSE public key bytes, the algorithm, the flags and the attestation summary, not a library type. A mature OpenSSL-free crate can replace the verifier later without a data migration.

## Consequences

- Tenko owns a small piece of security-critical parsing and verification code: about 2,100 lines with their documentation (`crates/tenko-auth/src/webauthn/`), a third of them the DER reader. The scope is narrow, every check has a negative test (the W3C vectors in `tests/webauthn_vectors.rs`, the software-authenticator ceremonies in `tests/webauthn_ceremonies.rs`), the module documentation lists the specification steps it implements, and the authenticator-data and attestation-object parsers are candidates for a fuzz target (API-15).
- Windows Hello registers with attestation conveyance `none`, which every platform authenticator returns when asked, and works with RS256 or ES256. TPM, Android Key, Apple and FIDO U2F attestation statements are refused, so break-glass needs a FIDO2 security key with `packed` attestation, which current keys provide.
- Without configured trust anchors, `packed` attestation proves a self-consistent certificate but not the vendor. Hardened deployments should load the vendor root certificates; FIDO Metadata Service (MDS3) support is a Slice 3 item.
- One native cryptography library serves TLS, the vault and authentication. `aws-lc-sys` needs NASM on Windows or its `prebuilt-nasm` feature, which `tenko-auth` enables.
- The `rsa` crate stays out of the graph; the plan's fallback list (`p256`, `ed25519-dalek`, `rsa`) is superseded by this decision.

## Alternatives considered

- **`webauthn-rs`**: the most complete and best maintained relying party in Rust, but it requires OpenSSL, which `deny.toml` bans.
- **`webauthn_rp` or its fork `structured-webauthn`**: complete, but both depend on `rsa`, which fails `cargo deny` and `cargo audit`; `webauthn_rp` has had no release since April 2025.
- **`passki`**: the best technical fit (aws-lc-rs, smallest graph, most tests), rejected on maintenance (one maintainer, nine months old, API changes between minor versions). Worth re-evaluating in Slice 3 or once it reaches 1.0 with a second maintainer.
- **`caden` or `webauthn-kit`**: in scope, but they add `ring` as a second native cryptography stack and are months or weeks old.
- **`passkey-auth` or `passkey-server`**: no RS256, so no Windows Hello; `passkey-server` also lacks `packed`.
- **Ignoring RUSTSEC-2023-0071 in `deny.toml`**: verification is unaffected by the attack, but the ignore would apply to every use of `rsa` and hide the advisory where it matters.
