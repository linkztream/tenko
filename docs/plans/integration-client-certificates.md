# Plan: client certificates for integrations

- Status: Accepted. The owner decided section 10; ADR 0035 is Accepted with those decisions.
- Phase: 4, the phase after the one release 0.1.0 closes. The step is not part of the 0.1.0 scope.
- Scope: [ADR 0035](../adr/0035-integration-client-certificates.md). Integrations prove themselves with a private key that never travels and can sit in a TPM, through a client certificate of a separate integration CA, presented on a dedicated listener; service-account tokens can be bound to that key.
- Depends on: the token renewal package (IAM-20, IAM-21, TGL-46). Every change to the token files and the token dialog comes after that package is on `main` (section 8).

The decisions, their alternatives and the reasons are in the ADR and are not repeated here. Sizes: S is up to one week of building, M one to three.

Contents:

1. [Goal and exit](#1-goal-and-exit)
2. [Starting point in the code](#2-starting-point-in-the-code)
3. [The integrator's view](#3-the-integrators-view)
4. [Threat model](#4-threat-model)
5. [Requirements and toggle, drafted](#5-requirements-and-toggle-drafted)
6. [Cluster](#6-cluster)
7. [Work packages](#7-work-packages)
8. [Order and the renewal package](#8-order-and-the-renewal-package)
9. [Tests and the security review](#9-tests-and-the-security-review)
10. [Decisions of the owner](#10-decisions-of-the-owner)
11. [What the code could not settle](#11-what-the-code-could-not-settle)
12. [Documents that change](#12-documents-that-change)

## 1. Goal and exit

An integrator enrolls an automation host with `openssl` and `curl` alone, the host's key stays on the host (in a TPM where it has one), the certificate renews itself before it expires, and a service-account token bound to that key is worthless anywhere else.

| # | Exit check | Package |
|---|---|---|
| IC-E1 | A host with nothing but `openssl` and `curl` enrolls with a code, calls an API route on the integration listener with a bound token, and renews its certificate twice from a timer without a person; the same with a key in a software TPM (`swtpm` with the `tpm2-openssl` provider) | CC8 |
| IC-E2 | A bound token is refused on 8443 directly, through a trusted proxy with every forwarded certificate header of section 9.2, and through a PROXY protocol header with TLS fields; it is refused on 8445 with another account's certificate | CC8 |
| IC-E3 | An integration certificate fails the handshake on the cluster port and as a server certificate toward a node; a node certificate fails the handshake on the integration listener | CC8 |
| IC-E4 | A revocation made on one controller ends requests of that certificate on another controller of a three-controller lab at its next request, and an open HTTP/2 connection is closed | CC8 |
| IC-E5 | Deleting the service account ends its certificates and bound tokens at once on every controller | CC8 |
| IC-E6 | A rollback to the previous release refuses bound tokens (prefix check) and never opens the integration listener | CC8 |
| IC-E7 | The fuzz targets of section 9.3 run in the fuzz job; the penetration rows of section 9.2 are recorded in the security report | CC9 |
| IC-E8 | With TLS 1.2 allowed by TGL-47, a client offering only TLS 1.2 enrolls and renews, and an observer's capture shows the certificate and nothing of the requests; with it off (the default), the same client fails the handshake; under Hardened the setting is refused | CC8 |

## 2. Starting point in the code

Verified for this plan; the build checks again before relying on it.

- **The internal CA.** `crates/tenko-cluster/src/ca/authority.rs` (`InternalCa`, `CaPolicy` with root 3650, server 397 and node 365 days, `renew_before_days` 30, the root key a vault system secret of purpose `cluster.ca_key`) and `ca/certs.rs` (`issue_node_from_csr`, `csr_public_key`: PKCS#10 parsed with `x509-parser`, trailing data refused, the self-signature verified, P-256 required, everything else ignored; serials of 126 random bits; one hour of clock skew). Only server and node certificates are issued.
- **The cluster port.** `crates/tenko-cluster/src/mtls.rs`: `NodeClientVerifier` wraps `WebPkiClientVerifier` with the one root, then requires a node URI (`PeerIdentity::from_der`) and an unrevoked serial; `RevocationSet` is an `ArcSwap<HashSet<String>>`. The revocation table `cluster.revocations` (`crates/tenko-cluster/src/model.rs`, record `Revocation { node, revoked_at, not_after, controller }`) is followed on every controller by a store watch (`follow_revocations` in the node registry), so a revocation applies within a moment of replication; open connections close about 0.3 s later.
- **The API listener.** `crates/tenko-cluster/src/ca/tls.rs` `server_config` uses `with_no_client_auth`; `crates/tenko-api/src/server/listener.rs` runs the handshake and inserts `ConnInfo` (`server/forwarded.rs`: `peer`, `tls`, `mode`, `trusted`, `proxy`) into every request; the PROXY protocol reader (`server/proxy_protocol.rs`) interprets only the client bit of the SSL TLV. In `reverse_proxy` mode only trusted proxies are served.
- **Who runs the API.** Only controllers (`crates/tenko/src/serve/mod.rs` sends a node without the controller role to `node::agent`, which runs the cluster client alone). DNS and DHCP run in a controller's process until Phase 5.
- **Tokens.** `crates/tenko-auth/src/model.rs` `ScopedTokenRecord` (no `deny_unknown_fields`), stored under the SHA-256 of the text in the replicated `auth.scoped_tokens`; prefix `tnk_` checked first (`secret.rs`, `service/mod.rs` `token_of`); `holder` refuses a disabled owner or an older generation (`UserRecord::admits`); minting for a service account needs a fresh session (`require_fresh_session`, five minutes, `service/account.rs`). Deleting an account raises its generation and removes its credential rows in pages (`service/end.rs`).
- **Fuzzing.** `fuzz/Cargo.toml` has `api_proxy_protocol` and `webauthn_certificate`, and no target for the PKCS#10 parser of `POST /api/v1/nodes/enroll`, a public route. Package CC1 adds one that covers both enrollments.

## 3. The integrator's view

### 3.1 Enrollment

An administrator opens the service account, chooses "Enroll a certificate", and gets the code once, with the commands below filled in. On the automation host (POSIX shell; `example.test` stands for the controller's name):

```sh
code='tnki.<id>.<secret>.<fingerprint>'      # from the administrator, used once
api=https://tenko.example.test:8443
curl -fsS -k "$api/api/v1/integrations/ca" -o tenko-ca.pem   # public, checked on the next line
[ "$(openssl x509 -in tenko-ca.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)" = "${code##*.}" ] || exit 9
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client.key
openssl req -new -key client.key -subj /CN=tenko-integration -outform DER -out client.csr
curl -fsS -H "Authorization: Bearer $code" -H 'Content-Type: application/pkcs10' \
  --data-binary @client.csr "$api/api/v1/integrations/enroll?label=backup-host" -o client.pem
```

When 8443 uses the internal CA, the `curl` of the enrollment adds `--cacert tenko-ca.pem`; with an imported certificate or a proxy the system roots verify 8443. The integration listener is always verified with `tenko-ca.pem`.

With a TPM on Linux the key is made and used through the `tpm2-openssl` provider (`openssl genpkey -provider tpm2 …`, `openssl req -provider tpm2 -provider default -key handle:0x81000001 …`), and `curl` reaches it through its OpenSSL backend; on Windows the key is made by `certreq -new` with the Microsoft Platform Crypto Provider and used from the certificate store (`curl.exe` with Schannel, or PowerShell's `-CertificateThumbprint`). Lab package CC8 proves the Linux path; the Windows path is proved in the owner's Windows lab (section 11).

### 3.2 Use and renewal

```sh
curl -fsS --cacert tenko-ca.pem --cert client.pem --key client.key \
  -H "Authorization: Bearer $token" https://tenko.example.test:8445/api/v1/system/status
openssl req -new -key client.key -subj /CN=tenko-integration -outform DER |
  curl -fsS --cacert tenko-ca.pem --cert client.pem --key client.key \
    -H 'Content-Type: application/pkcs10' --data-binary @- \
    https://tenko.example.test:8445/api/v1/integrations/certificate/renew -o client.pem.new &&
  mv client.pem.new client.pem
```

The renewal runs from a timer (a systemd timer or a scheduled task) daily; before the last third of the lifetime it answers `integration.renew.not_due` (exit status of `curl -f` 22), which the script treats as nothing to do. `docs/integrations.md` ships the two scripts (POSIX shell and PowerShell) in full (IC-Q11).

### 3.3 Routes

| Route | Where | Who | Answer |
|---|---|---|---|
| `POST /api/v1/integrations/enrollments` | 8443 | administrator, interactive session signed in within five minutes | the code once (`Cache-Control: no-store`), its record |
| `GET /api/v1/integrations/enrollments`, `DELETE …/{id}` | 8443 | administrator | list (never the code), withdraw |
| `GET /api/v1/integrations/ca` | 8443 | public | the internal root in PEM, in every TLS mode |
| `POST /api/v1/integrations/enroll` | 8443 | public; the code is the credential | the certificate in PEM |
| `GET /api/v1/integrations/certificates` | 8443, 8445 | administrator | per account: lineage, label, serial, key digest, validity, state, last seen |
| `DELETE /api/v1/integrations/certificates/{serial}` | 8443, 8445 | administrator | revokes the lineage |
| `POST /api/v1/integrations/certificate/renew` | 8445 only | the connection's certificate | the new certificate in PEM |

## 4. Threat model

The design column assumes decision IC-Q1 (bound tokens) under Standard. "The account" means the grants of the service account; nothing in any row reaches beyond them, the owner's radius rule.

| Attacker | Today | With the renewal package alone | With this design |
|---|---|---|---|
| **Stolen token alone** (a log, a paste, a memory dump of a client) | Acts as the account from any address that reaches 8443 (or the proxy) until the token expires (90 days) or is revoked | Until the token's short expiry; cannot renew without the renewal secret; with source binding (TGL-46) only from the bound address | Nothing: 8443 refuses a bound token, and 8445 needs the key in the handshake |
| **Stolen token and renewal secret** | As above (no renewal secret exists) | Renews without end until the legitimate client renews, whose reuse detection revokes the family; source binding limits where from | Nothing: a bound token renews only over 8445 with the key |
| **A copy of the integration host's disk** (backup, snapshot, a stolen disk) | The token: as the first row | Token and renewal secret: as the second row | Key in a TPM: nothing, the key blob loads only in that TPM. Key in a file: everything until the next legitimate renewal of the token or the certificate reveals the copy (both reuse detections revoke lineage and tokens) or the certificate lapses (at most 30 days) |
| **Live compromise of the integration host** | Everything the account may do, and the token keeps working after the attacker is evicted | The same; token and secret keep working after eviction until reuse detection | Everything the account may do while the attacker is there, through the TPM if there is one. With a TPM, access ends with eviction: the key cannot be copied and the bound token is useless elsewhere. With a key in a file, as the row above after eviction |
| **Compromised `tenko` service account on a controller** | It is the authority: it reads the store and the vault (token digests, never tokens), holds the CA key and can act as any principal | The same | The same, and no wider: it can issue integration certificates, but it could already act as any account; it never sees an integration's private key, so it cannot impersonate an integration toward anything else; the cluster port of other controllers does not trust the integration root |
| **Hostile reverse proxy** | Sees every token and session cookie that passes and can replay them; asserts client addresses | Also sees the renewal secret at renewal (as the second row); source binding sees only the proxy's address | Sees no certificate integration: they reach 8445 directly with TLS end to end, and a certificate the proxy forwards is never read; people's sessions as today |
| **Hostile client on the network that reaches a listener** | 8443: the TLS handshake, HTTP parsing and the public routes (sign-in, node enrollment) | The same, plus the renewal route, which needs a token and its renewal secret | 8445 adds only the handshake up to the client certificate check: rustls' web PKI verifies the chain to the integration root before Tenko reads a byte of the certificate, and no HTTP is served before a valid one. 8443 adds two public routes: the CA root (public data) and enrollment, which needs a code and whose PKCS#10 parser is fuzzed |
| **Stolen enrollment code** | Not applicable | Not applicable | One enrollment within the hour, for that account only, from the code's source prefix if one was set. The legitimate enrollment then fails, the list shows the thief's key digest and label, and the administrator revokes |
| **Stolen certificate and key file without a token** | Not applicable | Not applicable | Can renew the certificate and nothing else; the legitimate renewal after the thief's (or before it) is reuse and revokes the lineage |

## 5. Requirements and toggle, drafted

These rows go into `docs/REQUIREMENTS.md` and `docs/SECURITY-PROFILES.md` in package CC7, after the renewal package is on `main` (it edits both files). The Phase column is 4: the step comes after release 0.1.0, which closes Phase 3 and the Kerberos line of Slice 13.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| IAM-22 | Client certificates for integrations: an administrator signed in within five minutes creates a single-use enrollment code (at most one hour, optionally limited to a source prefix) for one service account; the integrator enrolls a PKCS#10 request for an ECDSA P-256 key it generated, in a file or a TPM, with `openssl` and `curl` alone, and receives a certificate of a separate integration CA that names only that service account (`urn:tenko:service-account:<id>`, client authentication only). The key never leaves the host. Integration certificates are accepted only on the integration listener (mutual TLS 1.3, TLS 1.2 only by TGL-47, its own port), never on the API and UI listener or the cluster port, and no verifier of a node accepts one. | 4 | Must |
| IAM-23 | Certificate-bound service-account tokens in the manner of RFC 8705, bound to the key: a bound token is accepted only on the integration listener over a connection whose client certificate is valid, unrevoked, names the token's owner and carries the bound key; everywhere else it is refused. A build that does not know binding refuses a bound token. | 4 | Must |
| IAM-24 | Renewal of an integration certificate over the integration listener with the certificate alone, in the last third of its lifetime, with a new or the same key; renewal from a certificate that its lineage already replaced revokes the lineage and its bound tokens. The lifetime follows TGL-47; a lineage that does not renew raises the certificate expiry alarm (OPS-29). | 4 | Must |
| IAM-25 | Revocation of integration certificates by an administrator, by deleting or disabling the service account, by reuse of a lineage and by reuse detection of a bound token family (IAM-21); effective on every controller within the store's replication, also on open connections; a revoked key never enrolls again. A client certificate forwarded by a reverse proxy, as a header or in the PROXY protocol, is never trusted. | 4 | Must |

| ID | Toggle | Home | Standard | Hardened | Lab | Phase | Related |
|---|---|---|---|---|---|---|---|
| TGL-47 | Integration client certificates: certificate lifetime / certificate-bound tokens required for service accounts / TLS 1.2 on the integration listener (for Windows Server 2019 and older; the client certificate is then visible on the path) | 90 days / no / off | 30 days / no / off | 7 days / yes, every token an administrator creates for a service account, mirror tokens once the pusher presents a certificate / off, and turning it on is refused | 365 days / no / off | 4 | IAM-22, IAM-23, IAM-24 |

A lifetime longer than the profile's, binding switched off under Hardened, or TLS 1.2 allowed is a deviation that the UI shows. TLS 1.2 is built as the other parts of the toggle are: a field of the same settings type with the profile's default, changed through the same route and audited the same way; the listener reads it per connection, so turning it off refuses the next TLS 1.2 handshake. A tightened lifetime applies at the next renewal; a tightened requirement refuses unbound service-account tokens at their next use, so the administrator sees the affected tokens in the settings page before saving.

## 6. Cluster

- **Issuance.** The integration root and its key replicate like the existing root: the record in the store, the key in the vault, which every controller opens. Any controller issues; the root is created once with a create-if-absent precondition, so two controllers that receive the first enrollment code at the same moment end with one root.
- **Single use.** An enrollment code is consumed in the same write that records the certificate, with a precondition on the code's record, so two controllers cannot both accept it.
- **Revocation and binding** live in replicated tables (`auth.client_certs`, the token records) and every controller follows them with a watch, as for nodes: within a moment of replication, and the per-request check is the authority even before the connection is closed. An account's generation is checked at every request, so deleting or disabling the account needs no row change to take effect.
- **Nodes that are not controllers** run no API and no integration listener, never trust the integration root, and never see an integration certificate. That holds in Phase 5 for DNS-only and DHCP-only nodes as long as they run no API; a node that serves the API later is a controller in this sense and follows the tables.
- **Endpoints.** Each controller opens its own integration listener with a server certificate of the internal root for its configured host names and addresses. An integrator that should survive the loss of a controller uses a name that resolves to several controllers, and that name must be among each controller's configured names; how the enrollment answer lists the endpoints is an open point (section 11).
- **Mixed versions.** A controller of an older build has no integration listener and refuses `tnkb_` tokens; during a rolling upgrade bound tokens work on upgraded controllers only, which the upgrade notes say.

## 7. Work packages

One owner per file at a time; a file named by two packages passes from the first to the second when the first is merged on the step's branch. "Before" means the package can be built before the renewal package is on `main`.

| Package | What | Owns | Depends on | Before | Size |
|---|---|---|---|---|---|
| CC1 | The integration CA and issuance | `crates/tenko-cluster/src/ca/client.rs` (new), `ca/authority.rs`, `ca/certs.rs`, `ca/mod.rs` (appended lines), `fuzz/fuzz_targets/ca_csr.rs` (new), `fuzz/fuzz_targets/integration_identity.rs` (new), `fuzz/Cargo.toml` (appended targets) | none | yes | S |
| CC2 | The integration listener and the verified client identity | `crates/tenko-cluster/src/client_tls.rs` (new), `crates/tenko-cluster/src/lib.rs` (appended line), `crates/tenko-api/src/server/listener.rs`, `server/forwarded.rs`, `server/mod.rs`, `crates/tenko/src/serve/tls.rs`, the configuration type that holds `[cluster] listen` | CC1 | yes | M |
| CC3 | Certificate records, enrollment codes, enrollment, revocation, the watch | `crates/tenko-auth/src/client_cert/` (new: `mod.rs`, `model.rs`, `enroll.rs`, `revoke.rs`, `follow.rs`), `crates/tenko-auth/src/lib.rs` (appended line), `crates/tenko-api/src/routes/integrations.rs` (new), `crates/tenko-api/src/routes/mod.rs` (appended line) | CC1, CC2 | yes | M |
| CC4 | Certificate renewal, lineage reuse, the expiry alarm | `crates/tenko-auth/src/client_cert/renew.rs` (new), `routes/integrations.rs` (from CC3), the alarm's registration beside the existing certificate expiry alarms | CC3 | yes | S |
| CC5 | Certificate-bound tokens and TGL-47 | `crates/tenko-auth/src/model.rs`, `secret.rs` (`tnkb_`), `service/mod.rs`, `service/access.rs`, `service/end.rs`, `client_cert/mod.rs` (from CC4), `crates/tenko-api/src/routes/access.rs`, `crates/tenko-api/src/extract.rs`, `crates/tenko-core/src/auth.rs` (`Credentials` carries the connection's key digest; a `tenko-core` change, merged first), the settings type that holds `token_max_days` | CC4 and the renewal package on `main` | no | M |
| CC6a | UI: certificates of a service account, the enrollment code dialog with the filled-in commands, revoke | `ui/src/settings/access/Certificates.tsx` (new), `EnrollmentCode.tsx` (new), their tests, `ui/src/api/mock/routes-integrations.ts` (new), appended lines in the mock registry and the `sv` and `en` catalogs | CC3, CC4 | yes | S |
| CC6b | UI: binding in the token dialog, the TGL-47 setting | the token dialog's files (owned by the renewal package until it is on `main`), the security profile settings page | CC5 | no | S |
| CC7 | Documents and rows | `docs/REQUIREMENTS.md`, `docs/SECURITY-PROFILES.md`, `docs/certificates.md`, `docs/access.md`, `docs/integrations.md` (new, with both scripts), `docs/CONFORMANCE.md`, `docs/adr/README.md` | CC5 | no | S |
| CC8 | Tests across the line and the lab | `crates/tenko-api/tests/integration_listener.rs` (new), `deploy/compose/integrations/` (new lab: an `openssl` and `curl` host, `swtpm` with `tpm2-openssl`, a trusted proxy, three controllers), the end-to-end spec of the UI dialog | CC2 for the skeleton, CC5 for IC-E2 and IC-E6 | skeleton yes | M |
| CC9 | Security review: penetration round, fuzz campaign, privilege review | `docs/security/` (the round's record) | all | no | S |

What each package proves, beyond its unit tests:

- **CC1.** An integration certificate carries exactly the fields of ADR 0035 decision 2 whatever the request asked for; a node certificate cannot be issued by the integration root nor an integration certificate by the existing root (`Signer` per root, no shared constructor); the identity reader refuses every certificate of section 9.1's list. The PKCS#10 parser gets its fuzz target here (it is also the node enrollment's).
- **CC2.** Mandatory client authentication, TLS 1.3 by default and TLS 1.2 only by the third part of TGL-47 (built like the other toggles, read per connection), no tickets, the certificate request names only the integration root, no PROXY or forwarded header read, on-demand opening and closing, the per-request re-check, the kill switch per serial. `ConnInfo` gains `client: Option<Arc<ClientIdentity>>`, set only from the handshake; a comment there states that it is never set from a header.
- **CC3.** Codes (digest only, single use across controllers, source prefix, at most one hour), the enrollment checks of ADR 0035 decision 5 with one refusal code each, at most eight active lineages, the key-digest deny of revoked keys, revocation by an administrator and the watch.
- **CC4.** The renewal window and rate, the overlap of 15 minutes after the new certificate is first seen, lineage reuse, the alarm at the last sixth.
- **CC5.** Binding at creation and at a renewal over 8445, the move of bound tokens on a same-lineage renewal and on a `replaces` enrollment, the refusal on 8443 (`auth.token.certificate_required`), Hardened's refusal of unbound service-account tokens, account end revoking certificates in the same pages as tokens, reuse detection of a bound family revoking the lineage.

## 8. Order and the renewal package

```
CC1 → CC2 → CC3 → CC4 ─┬─→ CC5 → CC6b → CC7 → CC9
                       └─→ CC6a           ↑
CC8 skeleton after CC2 ······ CC8 in full after CC5
```

- CC1 to CC4, CC6a and the skeleton of CC8 touch no file of the renewal package and can be built now, on the step's branch. Until CC5 they deliver enrollment, renewal and revocation of certificates that protect nothing yet, so the branch does not merge to `main` before CC5.
- CC5, CC6b and CC7 start when the renewal package is on `main` and the step's branch is updated from it; CC5 adapts to the token format and route names that package settled.
- The step reaches `main` as one pull request after CC9, through the gate.

## 9. Tests and the security review

### 9.1 Tests in the packages

- **Issuance (CC1):** a request asking for a CA, a node URI, a role URI, server authentication, DNS names or addresses gets none; RSA, P-384 and Ed25519 keys, a broken self-signature, trailing data and an oversized request are refused with their codes; issuance by the wrong root is impossible by construction.
- **Identity reader (CC1, CC2):** refuses a certificate with no or two service-account URIs, with a node or role URI, with server authentication, with basic constraints CA, from the existing root; accepts exactly the issued form.
- **Listener (CC2):** no client certificate, a node certificate, an expired one, a revoked one, one from another installation's integration root: handshake refused, no HTTP; TLS 1.2 offered: refused while TGL-47 does not allow it, and accepted when it does, with a TLS 1.2 suite list of ECDHE and AEAD only and the Extended Master Secret required (a client without it is refused); a revoked serial on an open HTTP/2 connection: the next request refused and the connection closed; a session ticket is never issued; a PROXY header and `X-Forwarded-For` on 8445 change nothing.
- **Enrollment (CC3):** every refusal of ADR 0035 decision 5 by its code; two controllers accepting the same code in parallel: exactly one certificate; a token-authenticated or stale session creating a code: refused.
- **Renewal (CC4):** before the window, twice within an hour, from a replaced certificate (lineage revoked, bound tokens revoked), with a revoked key, with the same key (accepted, binding kept).
- **Binding (CC5):** every row of exit checks IC-E2, IC-E5 and IC-E6; a bound token with the right account but another lineage's key; a renewal of a bound token over 8443; a rollback build refusing `tnkb_`.
- **Lab (CC8):** IC-E1 to IC-E6 end to end, with the timing checks waiting on state, never on time (`docs/testing/rules.md`).

### 9.2 Rows for the penetration round (CC9)

| Row | Attempt | Expected |
|---|---|---|
| PT-IC1 | An integration certificate on the cluster port, and as a server certificate toward a node | Handshake refused (unknown issuer) |
| PT-IC2 | A node certificate, and a certificate of another installation, on the integration listener | Handshake refused |
| PT-IC3 | A bound token on 8443 with `X-SSL-Client-Cert`, `X-Forwarded-Client-Cert`, `ssl-client-cert`, `X-Client-Cert` from a trusted proxy, and with a PROXY v2 header whose SSL TLV carries client-certificate fields | `auth.token.certificate_required` each time |
| PT-IC4 | A bound token of account A with a certificate of account B on 8445 | Refused |
| PT-IC5 | A crafted PKCS#10 request (CA extension, node URI, server authentication, wrong curve, bad signature, nested length tricks) on `/integrations/enroll` | Refused, or issued without any requested field |
| PT-IC6 | Replaying a used code, racing one code on two controllers, a code outside its source prefix | One success at most, refusals by code |
| PT-IC7 | Creating a code with a token, or with a session older than five minutes | Refused |
| PT-IC8 | Resuming a TLS session after revocation; keeping an HTTP/2 connection open across revocation and across expiry | Refused at the next request |
| PT-IC9 | Re-enrolling a revoked key; renewing from a replaced certificate | Refused; lineage revoked |
| PT-IC10 | A browser that holds an integration certificate opens the UI on 8443 | No certificate prompt (no certificate request on 8443) |
| PT-IC11 | Slow handshakes and connection floods on 8445 without a certificate | Handshake timeout and connection cap hold; 8443 unaffected |
| PT-IC12 | Deleting the service account while a bound token streams events on 8445 | The stream ends; nothing after the deletion is answered |
| PT-IC13 | A `tnkb_` token against the previous release | Refused |
| PT-IC14 | TLS 1.2 with TGL-47 off; with it on, a CBC or RSA key exchange suite, renegotiation, a client without Extended Master Secret; turning it on under Hardened | Refused each time; with it on, only ECDHE and AEAD with Extended Master Secret complete |

### 9.3 Fuzzing

Every parser of network input in this step gets a target in `fuzz/` before it merges (CONTRIBUTING rule 3):

- `ca_csr`: the PKCS#10 parser and checks (`csr_public_key` and the integration checks), which also covers the node enrollment's request.
- `integration_identity`: the identity reader over arbitrary DER, and over certificates signed by a test integration root with arbitrary extensions.
- The enrollment code's text form (`tnki.…`) and the `tnkb_` prefix check join the existing token parsing target if one exists, else `ca_csr` grows a second input.

### 9.4 Privilege review

The review checks that the integration listener runs in the same process and account as 8443 with no new capability (8445 is above 1024, ADR 0023), that the integration root's key is only read by the issuing code path, that no route on 8445 is reachable without a valid certificate, and that a compromised integration host reaches nothing beyond its account's grants (section 4).

## 10. Decisions of the owner

The owner decided every question as recommended, except IC-Q4. The options that were not taken are kept here as the record of what was weighed (security, performance, usability, features).

| Question | Decided | Not taken |
|---|---|---|
| IC-Q1. What the certificate protects | Every use of a service-account token: tokens bound to the certificate's key (RFC 8705 manner) | Only the renewal call; the certificate replacing the token (later, on top) |
| IC-Q2. Where the certificate is presented | A dedicated integration listener, default port 8445, client certificate required, opened on demand | Optional client authentication on 8443; a route on the cluster port |
| IC-Q3. One root or two | A separate integration root that the cluster port and nodes never trust | The existing root, told apart by URI |
| IC-Q4. TLS versions on the integration listener | TLS 1.3 by default in every profile, with the third part of TGL-47 allowing TLS 1.2 for Windows Server 2019 and older: off in every profile, a recorded deviation when on, refused under Hardened, limited to ECDHE with AEAD suites and the Extended Master Secret. In TLS 1.2 an observer on the path sees the client certificate (account id, serial, validity, public key), never the key, a token or a request | TLS 1.3 only with no setting; TLS 1.2 on by default outside Hardened |
| IC-Q5. The server certificate on 8445 | Always from the internal root, pinned by the code's fingerprint | Following 8443's mode |
| IC-Q6. TGL-47 values and Hardened | Lifetimes 90 / 30 / 7 / 365 days (Home, Standard, Hardened, Lab); Hardened requires binding for every token an administrator creates for a service account, mirror tokens (ADR 0033) once the mirror pusher presents a certificate; plugin process tokens (ADR 0032) outside | Mirror tokens bound from the start; binding never required |
| IC-Q7. A lapsed certificate | No grace period; a new code with `replaces` moves the bound tokens | A grace period after expiry |
| IC-Q8. What reuse detection revokes | Token family reuse also revokes the lineage, and lineage reuse also revokes its bound tokens | Each revokes its own kind only |
| IC-Q9. Key types | ECDSA P-256 only | RSA 2048 and 3072 as well |
| IC-Q10. The host firewall | The installer opens 8445 where it opens 8443 | Only with an installer option |
| IC-Q11. Tooling for integrators | Documented POSIX shell and PowerShell scripts in `docs/integrations.md` | A `tenko integration` client command |

The phase was decided with them: Phase 4, after release 0.1.0.

## 11. What the code could not settle

- **The renewal package's final form.** Its token text, route names and what TGL-46 binds are not on `main`; CC5 adapts the bound token (`tnkb_`) and the bound renewal to them.
- **Two paths to confirm at the start of their package:** the configuration type that holds `[cluster] listen` (CC2), and the rate limiter of the public node enrollment route, which the integration enrollment should share (CC3).
- **Endpoints in a cluster.** Whether the enrollment answer lists every controller's integration endpoint (which needs an address per member that the member records do not hold today) or the integrator uses one name that resolves to several controllers. Recommended: the name, documented; the list later if integrators ask.
- **TPM paths outside the lab.** `swtpm` with `tpm2-openssl` proves the Linux path in CC8; Windows with the Platform Crypto Provider and `curl.exe` or PowerShell needs the owner's Windows lab.
- **The installer's firewall step** for 8445 (IC-Q10) and whether it moves the unit-hardening gates; the installer change belongs to CC2 or a small package of its own once decided.
- **An existing gap:** the node enrollment's PKCS#10 parser has no fuzz target today; `ca_csr` in CC1 closes it, and it could be split out to land earlier.

## 12. Documents that change

In CC7 unless noted: `docs/REQUIREMENTS.md` (IAM-22 to IAM-25), `docs/SECURITY-PROFILES.md` (TGL-47, the owned range), `docs/certificates.md` (the integration root, the listener, the rule against forwarded certificates), `docs/access.md` (bound tokens), `docs/integrations.md` (new: enrollment, use, renewal, both scripts, troubleshooting by refusal code), `docs/cluster.md` (the integration listener and the second root), `docs/CONFORMANCE.md` (RFC 8705 binding to the key instead of the certificate; RFC 2986 requests; RFC 5280 profile), `docs/adr/README.md` (the row of ADR 0035), the upgrade notes (bound tokens during a rolling upgrade and after a rollback), and `CHANGELOG.md` with each package.
