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
| IC-E2 | A bound token is refused on 8443 directly, through a trusted proxy with every forwarded certificate header of section 9.2, and through a PROXY protocol header with TLS fields; it is refused on 8445 with another account's certificate and with another lineage's; none of these refusals revokes anything | CC8 |
| IC-E3 | An integration certificate fails the handshake on the cluster port and as a server certificate toward a node; a node certificate fails the handshake on the integration listener | CC8 |
| IC-E4 | A revocation made on one controller ends requests of that certificate on another controller of a three-controller lab at its next request, and an open HTTP/2 connection is closed | CC8 |
| IC-E5 | Deleting the service account ends its certificates and bound tokens at once on every controller | CC8 |
| IC-E6 | A rollback to the previous release refuses bound tokens (prefix check) and never opens the integration listener | CC8 |
| IC-E7 | The fuzz targets of section 9.3 run in the fuzz job; the penetration rows of section 9.2 are recorded in the security report | CC9 |
| IC-E8 | With TLS 1.2 allowed by TGL-47, a client offering only TLS 1.2 enrolls and renews, an observer's capture shows the certificate and nothing of the requests, and no session ID or ticket is issued; with it off (the default), the same client fails the handshake; under Hardened the setting is refused | CC8 |
| IC-E9 | A certificate signed with a copy of the integration CA key but never recorded is refused at the handshake on every controller; a controller cut off from its quorum answers 503 on 8445 after 30 seconds | CC8 |

## 2. Starting point in the code

Verified for this plan; the build checks again before relying on it.

- **The internal CA.** `crates/tenko-cluster/src/ca/authority.rs` (`InternalCa`, `CaPolicy` with root 3650, server 397 and node 365 days, `renew_before_days` 30, the root key a vault system secret of purpose `cluster.ca_key`) and `ca/certs.rs` (`issue_node_from_csr`, `csr_public_key`: PKCS#10 parsed with `x509-parser`, trailing data refused, the self-signature verified, P-256 required, everything else ignored; serials of 126 random bits; one hour of clock skew). Only server and node certificates are issued.
- **The cluster port.** `crates/tenko-cluster/src/mtls.rs`: `NodeClientVerifier` wraps `WebPkiClientVerifier` with the one root, then requires a node URI (`PeerIdentity::from_der`) and an unrevoked serial; `RevocationSet` is an `ArcSwap<HashSet<String>>`. The revocation table `cluster.revocations` (`crates/tenko-cluster/src/model.rs`, record `Revocation { node, revoked_at, not_after, controller }`) is followed on every controller by a store watch (`follow_revocations` in the node registry), so a revocation applies within a moment of replication; open connections close about 0.3 s later.
- **The API listener.** `crates/tenko-cluster/src/ca/tls.rs` `server_config` uses `with_no_client_auth`; `crates/tenko-api/src/server/listener.rs` runs the handshake and inserts `ConnInfo` (`server/forwarded.rs`: `peer`, `tls`, `mode`, `trusted`, `proxy`) into every request; the PROXY protocol reader (`server/proxy_protocol.rs`) interprets only the client bit of the SSL TLV. In `reverse_proxy` mode only trusted proxies are served.
- **Who runs the API.** Only controllers (`crates/tenko/src/serve/mod.rs` sends a node without the controller role to `node::agent`, which runs the cluster client alone). DNS and DHCP run in a controller's process until Phase 5.
- **Tokens.** `crates/tenko-auth/src/model.rs` `ScopedTokenRecord` (no `deny_unknown_fields`), stored under the SHA-256 of the text in the replicated `auth.scoped_tokens`; prefix `tnk_` checked first (`secret.rs`, `service/mod.rs` `token_of`); `holder` refuses a disabled owner or a token issued under an older `tokens_generation` (`UserRecord::admits`); minting for a service account needs a fresh session (`require_fresh_session`, five minutes, `service/account.rs`). Deleting an account raises its `sessions_generation` and `tokens_generation` and removes its credential rows in pages (`service/end.rs`).
- **Node enrollment over plain HTTP** is refused outside the Lab profile and withdraws the token (`crates/tenko-api/src/routes/nodes.rs`, `refuse_plain_http`); the integration enrollment does the same.
- **The API server's limits.** One connection semaphore and one handshake timeout for every listener of the API server (`crates/tenko-api/src/server/mod.rs`, `listener.rs`), and no limit per source before the handshake; the integration listener gets its own.
- **Fuzzing.** The PKCS#10 parser `csr_public_key` is fuzzed through the cluster port's renewal request (`cluster_messages`, `crates/tenko-cluster/src/server.rs`); what the node enrollment route reads around it (the PEM in its JSON body) is not. The integration enrollment reads a DER body and two headers instead, and gets its own target (section 9.3).

## 3. The integrator's view

### 3.1 Enrollment

An administrator opens the service account, chooses "Enroll a certificate", and gets the code once, with the commands below filled in. On the automation host, as the integration's own account (POSIX shell; `example.test` stands for the controller's name):

```sh
umask 077
# enroll.code holds the code from the administrator: tnki.<code id>.<account id>.<secret>.<fingerprint>
IFS=. read -r _ id account secret fingerprint < enroll.code
api=https://tenko.example.test:8443
curl -fsS -k "$api/api/v1/integrations/ca" -o tenko-ca.pem   # public data, checked on the next line
[ "$(openssl x509 -in tenko-ca.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)" = "$fingerprint" ] || exit 9
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client.key
openssl req -new -key client.key -subj /CN=tenko-integration -outform DER -out client.csr
openssl req -in client.csr -inform DER -noout -pubkey | openssl pkey -pubin -outform DER -out client.spki
# The secret reaches Python on standard input, never as an argument.
proof=$(python3 -c '
import hashlib, hmac, sys
key = bytes.fromhex(sys.stdin.readline().strip())
message = b"tenko-integration-enroll-v1
%s
%s
" % (sys.argv[1].encode(), sys.argv[2].encode())
print(hmac.new(key, message + open(sys.argv[3], "rb").read(), hashlib.sha256).hexdigest())
' "$id" "$account" client.spki <<EOF
$secret
EOF
)
printf 'Content-Type: application/pkcs10
Tenko-Enrollment-Code: %s
Tenko-Enrollment-Proof: %s
' "$id" "$proof" > enroll.headers
curl -fsS -H @enroll.headers --data-binary @client.csr   "$api/api/v1/integrations/enroll?label=backup-host" -o client.crt
cat client.key client.crt > client.pem && rm client.key client.crt client.csr client.spki enroll.headers enroll.code
```

- The code's secret never leaves the host: the request carries the code id and the HMAC (hexadecimal). The default computes the HMAC with Python's standard library (`hmac`, `hashlib`), which reads the secret on standard input, so it is never a process argument; an automation host that runs Ansible has Python. Without Python, the fallback is `openssl dgst -sha256 -mac HMAC -macopt "hexkey:$secret" -r` over the same bytes, which shows the secret in the process arguments while it runs: `docs/integrations.md` gives it with that warning, for a host where other users cannot read process arguments (Linux `/proc` mounted with `hidepid`). PowerShell computes it in process with `[Security.Cryptography.HMACSHA256]`.
- **Test vector.** The secret `000102…1e1f` (the octets 0 to 31), the code id `0190d1c2-0000-7000-8000-000000000001`, the account id `0190d1c2-0000-7000-8000-000000000002`, and the key `3059301306072a8648ce3d020106082a8648ce3d03010703420004` followed by the octets 1 to 64 give the proof `2c7001035b8298745c7f0921f454bde9ac63c1585215a6ff15913367ef2a8f6f`. The Python default, the `openssl` fallback and PowerShell give these bytes, and the server test `the_proof_matches_the_documented_test_vector` (`crates/tenko-auth/tests/client_certs.rs`) holds the server to them; `docs/integrations.md` repeats the vector.
- Headers go to `curl` from a file (`-H @file`), never as arguments.
- When 8443 uses the internal CA, the `curl` of the enrollment adds `--cacert tenko-ca.pem`; with an imported certificate or a proxy the system roots verify 8443. The integration listener is always verified with `tenko-ca.pem`, passed per call. The root is never imported into a machine-wide trust store.
- With a TPM on Linux the key is made and used through the `tpm2-openssl` provider, with an authorization value that only the integration's account can read (`openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -pkeyopt user-auth:…`, then `-passin file:…` where the key is used), and `curl` reaches it through its OpenSSL backend. On Windows the key is made non-exportable by `certreq -new` with the Microsoft Platform Crypto Provider in the integration account's own key store and used from there (`curl.exe` with Schannel, or PowerShell with a validation callback that compares the root's fingerprint). Lab package CC8 proves the Linux path; the Windows path is proved in the owner's Windows lab (section 11).

### 3.2 Use and renewal

```sh
printf 'Authorization: Bearer %s\n' "$token" > call.headers   # the token from a file only the account reads
curl -fsS --cacert tenko-ca.pem --cert client.pem -H @call.headers \
  https://tenko.example.test:8445/api/v1/system/status
```

The renewal runs daily from a timer (a systemd timer or a scheduled task). With a key in a file it makes a fresh key every time:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out next.key
openssl req -new -key next.key -subj /CN=tenko-integration -outform DER -out next.csr
status=$(curl -sS --cacert tenko-ca.pem --cert client.pem -H 'Content-Type: application/pkcs10' \
  --data-binary @next.csr -o next.crt -w '%{http_code}' \
  https://tenko.example.test:8445/api/v1/integrations/certificate/renew)
case $status in
  201) cat next.key next.crt > next.pem && mv next.pem client.pem ;;   # one atomic switch of key and certificate
  200) ;;                                                              # not due yet: the body says until when
  *) echo "renewal refused ($status): $(cat next.crt)" >&2; rm -f next.key next.csr next.crt; exit 1 ;;
esac
rm -f next.key next.csr next.crt
```

The listener answers on `0.0.0.0:8445` by default. An address in `[integrations] listen` that is IPv6 listens on IPv6 only, so a controller whose integrations come over IPv6 lists `"[::]:8445"`, and both `"0.0.0.0:8445"` and `"[::]:8445"` when they come over both; the integrator then uses the controller's IPv6 address or a name that resolves to it.

A key in a TPM is renewed with the same key (`openssl req -provider tpm2 -provider default -key handle:… -passin file:…`). `docs/integrations.md` ships both scripts (POSIX shell and PowerShell) in full (IC-Q11), and a failed renewal makes the timer's unit fail, which the host's own monitoring sees; Tenko's expiry alarm (OPS-29) is the second net.

### 3.3 Routes

| Route | Where | Who | Answer |
|---|---|---|---|
| `POST /api/v1/integrations/enrollments` | 8443 | administrator, interactive session signed in within five minutes | the code once (`Cache-Control: no-store`), its record |
| `GET /api/v1/integrations/enrollments`, `DELETE …/{id}` | 8443 | administrator | list (never the code), withdraw |
| `GET /api/v1/integrations/ca` | 8443 | public | the internal root in PEM, in every TLS mode |
| `POST /api/v1/integrations/enroll` | 8443 | public; the code id and the HMAC are the credential; HTTPS only outside Lab | 201 and the certificate in PEM |
| `GET /api/v1/integrations/certificates` | 8443 | administrator | per account: lineage, label, serial, key digest, validity, state, first presented |
| `DELETE /api/v1/integrations/certificates/{serial}` | 8443 | administrator | revokes the lineage |
| `POST /api/v1/integrations/certificate/renew` | 8445 only | the connection's certificate | 201 and the new certificate in PEM, or 200 with `{"not_due": true, "renew_after": …}` |
| every authenticated route of the API | 8445 | a bearer token owned by the certificate's account | as on 8443 |

8445 serves no public route, reads no session cookie, and refuses a token of any other account.

## 4. Threat model

The design column assumes decision IC-Q1 (bound tokens) under Standard. "The account" means the grants of the service account; nothing in any row reaches beyond them, the owner's radius rule.

| Attacker | Today | With the renewal package alone | With this design |
|---|---|---|---|
| **Stolen token alone** (a log, a paste, a memory dump of a client) | Acts as the account from any address that reaches 8443 (or the proxy) until the token expires (90 days) or is revoked | Until the token's short expiry; cannot renew without the renewal secret; with source binding (TGL-46) only from the bound address | Nothing: a bound token is refused without the key, on 8443 and on 8445, and that refusal triggers no reuse detection, so the thief cannot revoke it either |
| **Stolen token and renewal secret** | As above (no renewal secret exists) | Renews without end until the legitimate client renews, whose reuse detection revokes the family; source binding limits where from | Nothing, as the row above: the binding is checked before the renewal secret |
| **A copy of the integration host's disk** (backup, snapshot, a stolen disk) | The token: as the first row | Token and renewal secret: as the second row | Key in a TPM: nothing; the key blob loads only in that TPM, behind its authorization value. Key in a file: everything the account may do, until the next legitimate renewal replaces the key; the copied certificate stops 15 minutes after the new one is first presented, and a renewal from it after that is reuse and revokes the lineage. A thief who never renews is cut off, not revealed: at the latest one lifetime (30 days) after the copy |
| **Live compromise of the integration host** | Everything the account may do, and the token keeps working after the attacker is evicted | The same; token and secret keep working after eviction until reuse detection | Everything the account may do while the attacker is there, through the TPM if there is one. With a TPM, access ends with eviction. With a key in a file, as the row above after eviction |
| **Compromised `tenko` service account on a controller** | It is the authority: it reads the store and the vault (token digests, never tokens), holds the CA key and can act as any principal | The same | The same, and no wider: it can record and issue integration certificates, but it could already act as any account; it never sees an integration's private key, so it cannot impersonate an integration toward anything else; the cluster port of other controllers does not trust the integration root |
| **A controller removed from the cluster that kept its data** | Its copy of the vault holds the internal CA key; node certificates it signs fail at other controllers only through their node records | The same | Integration certificates it signs have no record on the remaining controllers and are refused; it cannot write a record there |
| **Hostile reverse proxy** | Sees every token and session cookie that passes and can replay them; asserts client addresses | Also sees the renewal secret at renewal (as the second row); source binding sees only the proxy's address | Sees no certificate integration: they reach 8445 directly with TLS end to end, and a certificate the proxy forwards is never read. An enrollment through the proxy shows it the code id and an HMAC, not the code's secret, so it cannot redeem the code for its own key. People's sessions as today |
| **Hostile client on the network that reaches a listener** | 8443: the TLS handshake, HTTP parsing and the public routes (sign-in, node enrollment) | The same, plus the renewal route, which needs a token and its renewal secret | 8445 adds only the handshake up to the client certificate check, behind its own connection cap, a cap per source before the handshake and a 5-second handshake timeout: rustls verifies the chain to the integration root before Tenko reads a byte of the certificate, and no HTTP is served before a recorded one. 8443 adds two public routes: the CA root (public data) and enrollment, which needs a code id and its HMAC |
| **Stolen enrollment code** (read from the process arguments of the host, or from where it was handed over) | Not applicable | Not applicable | One enrollment within the hour, for that account only, from the code's source prefix if one was set. The legitimate enrollment then fails, the list shows the thief's key digest and label, and the administrator revokes. No token is bound to the thief's lineage unless an administrator binds one |
| **Stolen certificate and key file without a token** | Not applicable | Not applicable | Can keep the lineage's certificate renewed and nothing else; once the legitimate host has presented a successor, a renewal from the thief's copy is reuse and revokes the lineage |
| **A controller cut off from its quorum** | Keeps answering from its local copy | The same | 8445 answers 503 after 30 seconds without quorum contact, so a revocation made elsewhere cannot be outrun for longer than that |

## 5. Requirements and toggle, drafted

These rows are in `docs/REQUIREMENTS.md` and `docs/SECURITY-PROFILES.md`, which own them; the copies here keep the design readable on its own. The Phase column is 4: the step comes after release 0.1.0, which closes Phase 3 and the Kerberos line of Slice 13.

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| IAM-22 | Client certificates for integrations: an administrator signed in within five minutes creates a single-use enrollment code (at most one hour, optionally limited to a source prefix) for one service account; the integrator enrolls a PKCS#10 request for an ECDSA P-256 key it generated, in a file or a TPM, with `openssl` and `curl` alone, proving the code with an HMAC so that its secret never travels, over HTTPS only (outside Lab), and receives a certificate of a separate integration CA that names only that service account (`urn:tenko:service-account:<id>`, client authentication only). The key never leaves the host. Integration certificates are accepted only on the integration listener (its own port, TLS 1.3, TLS 1.2 only where TGL-47 allows it, with the Extended Master Secret and no session resumption), never on the API and UI listener or the cluster port, and no verifier of a node accepts one. The integration listener serves only the authenticated API routes and the renewal route, to tokens of the certificate's account, with its own connection limits. | 4 | Must |
| IAM-23 | Certificate-bound service-account tokens in the manner of RFC 8705: a token is bound at creation to a named certificate lineage of its owner and is accepted only on the integration listener over a connection whose certificate belongs to that lineage and is accepted under IAM-25. The binding is checked before anything else of the token; a bound token presented without the key is refused and audited and triggers no reuse detection. A build that does not know binding refuses a bound token, and a record whose binding was lost is refused, never read as unbound. | 4 | Must |
| IAM-24 | Renewal of an integration certificate over the integration listener with the certificate alone, in the last third of its lifetime (answered "not due" with a success and a body before that); a renewal from the current certificate while its successor is unseen replaces the successor; once the successor has been presented, a renewal from its predecessor revokes the lineage and its bound tokens. The lifetime follows TGL-47; a lineage that does not renew raises the certificate expiry alarm (OPS-29), and an expired lineage's tokens are revoked. | 4 | Must |
| IAM-25 | Only recorded integration certificates are accepted: at the handshake and at every request the serial must have a record in an accepting state for the same account, whose `tokens_generation` it does not trail; an unknown serial is refused. Revocation by an administrator, by deleting or disabling the service account, by reuse of a lineage and by reuse detection of a bound token family (IAM-21), effective on every controller within the store's replication, also on open connections; a controller cut off from its quorum for more than 30 seconds stops answering on the integration listener; a revoked key never enrolls again. A client certificate forwarded by a reverse proxy, as a header or in the PROXY protocol, is never trusted. | 4 | Must |

| ID | Toggle | Home | Standard | Hardened | Lab | Phase | Related |
|---|---|---|---|---|---|---|---|
| TGL-47 | Integration client certificates: certificate lifetime / certificate-bound tokens required for service accounts / TLS 1.2 on the integration listener (for Windows Server 2019 and older; the client certificate is then visible on the path) | 90 days / no / off | 30 days / no / off | 7 days / yes, every token an administrator creates for a service account, mirror tokens once the pusher presents a certificate / off, and turning it on is refused | 365 days / no / off | 4 | IAM-22, IAM-23, IAM-24 |

A lifetime longer than the profile's, binding switched off under Hardened, or TLS 1.2 allowed is a deviation that the UI shows; TLS 1.2 allowed also shows a warning row in the health view. TLS 1.2 is built as the other parts of the toggle are: a field of the same settings type with the profile's default, changed through the same route and audited the same way; the listener reads it per connection, so turning it off refuses the next TLS 1.2 handshake. A tightened lifetime applies at the next renewal. Tightening the binding requirement revokes the unbound tokens of service accounts in the same change, after the settings page has listed them; loosening it again revives nothing.

## 6. Cluster

- **Issuance.** The integration root and its key replicate like the existing root: the record in the store, the key in the vault, which every controller opens. Any controller issues; the root is created once with a create-if-absent precondition, so two controllers that receive the first enrollment code at the same moment end with one root.
- **Single use.** An enrollment code is consumed in the same write that records the certificate, with a precondition on the code's record, so two controllers cannot both accept it.
- **Records, revocation and binding** live in replicated tables (`auth.client_certs`, the token records). Every controller loads the certificate records in full before its listener opens and follows them with a watch, as for nodes: a change applies within a moment of replication, and the per-request check is the authority even before the connection is closed. The account's `tokens_generation` and its disabled flag are checked at every request, so deleting or disabling the account needs no row change to take effect.
- **A controller that left the cluster** keeps whatever its data directory held, the integration CA key included. A certificate it signs has no record on the remaining controllers and is refused there (ADR 0035, decision 9).
- **Cut off from the quorum.** A controller whose quorum state has been `isolated` or `electing` for more than 30 seconds answers 503 `integration.isolated` on 8445 until it hears the cluster again; enrollment and renewal need a write and fail there anyway.
- **Nodes that are not controllers** run no API and no integration listener, never trust the integration root, and never see an integration certificate. That holds in Phase 5 for DNS-only and DHCP-only nodes as long as they run no API; a node that serves the API later is a controller in this sense and follows the tables.
- **Endpoints.** Each controller opens its own integration listener with a server certificate of the internal root for its configured host names and addresses. An integrator that should survive the loss of a controller uses a name that resolves to several controllers, and that name must be among each controller's configured names; how the enrollment answer lists the endpoints is an open point (section 11).
- **Mixed versions.** A controller of an older build has no integration listener and refuses `tnkb_` tokens; during a rolling upgrade bound tokens work on upgraded controllers only, which the upgrade notes say.

## 7. Work packages

One owner per file at a time; a file named by two packages passes from the first to the second when the first is merged on the step's branch. "Before" means the package can be built before the renewal package is on `main`.

| Package | What | Owns | Depends on | Before | Size |
|---|---|---|---|---|---|
| CC1 | The integration CA and issuance (built) | `crates/tenko-cluster/src/ca/client.rs` (new), `ca/authority.rs`, `ca/certs.rs`, `ca/error.rs`, `ca/mod.rs`, `crates/tenko-cluster/tests/integration_ca.rs` (new), `fuzz/fuzz_targets/integration_identity.rs` (new), its seed, `fuzz/Cargo.toml`, `fuzz/limits.txt`, `fuzz/README.md` | none | yes | S |
| CC2 | The integration listener: TLS and its limits, the verified client identity, the route and account filter, the quorum refusal (built) | `crates/tenko-cluster/src/client_tls.rs` (new), `crates/tenko-cluster/src/lib.rs` (one line), `crates/tenko-cluster/tests/integration_tls.rs` (new), `crates/tenko-api/src/server/integration.rs` (new), `server/mod.rs`, `server/forwarded.rs`, `server/listener.rs` (the shared HTTP builder), `crates/tenko-api/src/middleware/integration.rs` (new), `middleware/mod.rs`, `middleware/metrics.rs` (which operations are public), `middleware/quorum.rs` (since when the quorum is lost), `crates/tenko-api/src/fuzzing.rs`, `crates/tenko-auth/src/client_cert/follow.rs` (from CC3: demand, policy and a change signal), `crates/tenko/src/config.rs` (`[integrations] listen`), `crates/tenko/src/serve/mod.rs`, `crates/tenko/src/serve/tls.rs` (the listener's server certificate in every mode), `deploy/tenko.example.toml` | CC1, CC3 | yes | M |
| CC2b | The installer opens 8445 where it opens 8443 (IC-Q10), and the container and compose examples document it (built) | `deploy/install.sh` (the port and its role), `crates/tenko/src/prepared.rs` (a doc comment), `deploy/proxmox/test/install-sh-test.sh` (the record's ports, the ufw row), `deploy/Dockerfile`, `deploy/compose/controller.example.yml` (a commented publish line), `deploy/README.md` (a section of its own) | CC2 | yes | S |
| CC3 | Certificate records and their in-memory index, enrollment codes, enrollment with the HMAC proof, revocation, the watch (built) | `crates/tenko-auth/src/client_cert/` (new: `mod.rs`, `model.rs`, `enroll.rs`, `revoke.rs`, `follow.rs`), `crates/tenko-auth/src/lib.rs` (one line), `crates/tenko-auth/Cargo.toml` (`ipnet`, already in the workspace), `crates/tenko-auth/tests/client_certs.rs` (new), `crates/tenko-api/src/routes/integrations.rs` (new, with the issuer over the integration CA), `crates/tenko-api/src/routes/mod.rs`, `routes/tests.rs`, `crates/tenko-api/tests/routes.rs`, `crates/tenko-api/src/middleware/idempotency.rs` (the enrollment as a ceremony, the code as a plain secret), `crates/tenko-api/src/fuzzing.rs`, `crates/tenko/src/serve/mod.rs` (the service and its task), `fuzz/fuzz_targets/integration_enroll.rs` (new) with its seeds and lines in `fuzz/Cargo.toml`, `fuzz/limits.txt` and `fuzz/README.md`, `docs/api/openapi.json` (regenerated) | CC1 | yes | M |
| CC4 | Certificate renewal (current, pending, replaced), lineage reuse, the expiry alarm (built) | `crates/tenko-auth/src/client_cert/renew.rs` (new), `client_cert/mod.rs`, `enroll.rs`, `follow.rs` (from CC3), `crates/tenko-auth/tests/client_certs.rs`, `crates/tenko-api/src/routes/integrations.rs` (the renewal route and the alarm task), `crates/tenko-api/src/middleware/integration.rs`, `middleware/mod.rs` (the renewal passes on the certificate alone; the first presentation of a successor is recorded), `middleware/idempotency.rs`, `routes/tests.rs`, `crates/tenko-api/tests/routes.rs`, `crates/tenko/src/serve/mod.rs`, `docs/api/openapi.json` | CC2, CC3 | yes | S |
| CC5 | Certificate-bound tokens and TGL-47 | `crates/tenko-auth/src/model.rs`, `secret.rs` (`tnkb_`), `service/mod.rs`, `service/access.rs`, `service/end.rs`, `client_cert/mod.rs` (from CC4), `crates/tenko-api/src/routes/access.rs`, `crates/tenko-api/src/extract.rs`, `crates/tenko-core/src/auth.rs` (`Credentials` carries the connection's certificate serial; a `tenko-core` change, merged first), the settings type that holds `token_max_days` | CC4 and the renewal package on `main` | no | M |
| CC6a | UI: the integration certificates of the access page (one row per enrolled host with its state: active, expiring, lapsed, revoked), the enrollment code dialog with the code shown once and what to do with it, waiting codes, revocation confirmed with its consequence (built) | `ui/src/settings/access/Certificates.tsx` (new), `EnrollmentCode.tsx` (new), `integrations.ts` (new: the state of a lineage), `Certificates.test.tsx` (new), `AccessPage.tsx` (one section), `ui/src/api/mock/routes-integrations.ts` (new), `ui/src/api/mock/handlers.ts` (one line), `ui/i18n/en.d/integrations.xlf` and `sv.d/integrations.xlf` (new), `ui/i18n/*.d/labels.xlf` (the audit actions of CC1 to CC4), the generated UI files | CC3, CC4 | yes | S |
| CC6b | UI: binding in the token dialog, the TGL-47 setting | the token dialog's files (owned by the renewal package until it is on `main`), the security profile settings page | CC5 | no | S |
| CC7 | Documents and rows | `docs/REQUIREMENTS.md`, `docs/SECURITY-PROFILES.md`, `docs/certificates.md`, `docs/access.md`, `docs/integrations.md` (new, with both scripts), `docs/CONFORMANCE.md`, `docs/adr/README.md` | CC5 | no | S |
| CC8 | Tests across the line and the lab | `crates/tenko-api/tests/integration_listener.rs` (new), `deploy/compose/integrations/` (new lab: an `openssl` and `curl` host, `swtpm` with `tpm2-openssl`, a trusted proxy, three controllers), the end-to-end spec of the UI dialog | CC2 for the skeleton, CC5 for IC-E2 and IC-E6 | skeleton yes | M |
| CC9 | Security review: penetration round, fuzz campaign, privilege review | `docs/security/` (the round's record) | all | no | S |

What each package proves, beyond its unit tests:

- **CC1.** An integration certificate carries exactly the fields of ADR 0035 decision 2 whatever the request asked for; a node certificate cannot be issued by the integration root nor an integration certificate by the existing root (one issuing type per root over a shared creation and loading of the root); the identity reader refuses every certificate of section 9.1's list and has its fuzz target.
- **CC2.** Mandatory client authentication, TLS 1.3 by default and TLS 1.2 only by the third part of TGL-47 (built like the other toggles, read per connection, with the Extended Master Secret required and its health row), no tickets and no session IDs, the certificate request names only the integration root, the handshake's acceptance asked of the record index (an unknown serial refused), its own connection cap, the cap per source before the handshake and the 5-second handshake timeout, no PROXY or forwarded header and no cookie read, no public route served, every token of another account refused, the 503 after 30 seconds without quorum, on-demand opening only after the first full load, the per-request re-check, the kill switch per serial. `ConnInfo` gains `client: Option<Arc<ClientIdentity>>`, set only from the handshake; a comment there states that it is never set from a header.
- **CC3.** Records with their states and the in-memory index that answers "is this serial accepted, for which account and lineage" (loaded in full, then followed); codes (digest only, single use across controllers, source prefix, at most one hour); the HMAC proof over the label, code id, account id and public key, the secret never received; plain HTTP refused and the code withdrawn outside Lab; the enrollment checks of ADR 0035 decision 5 with one refusal code each; the certificate answered only after the recording write; at most eight active lineages; the key-digest deny of revoked keys; revocation by an administrator.
- **CC4.** The renewal window and rate with 200 "not due" and 201 "renewed"; the expiry alarm as the status condition `integration.certificate_expiring` (count, label and end of the first), which the findings and the notifications of OPS-29 read like every status condition; a lost answer (a renewal from the current certificate replaces an unseen successor); the first presentation of a successor; the overlap of 15 minutes; a replaced certificate reaching the renewal route only, and reuse counted only after the successor was presented; the alarm at the last sixth.
- **CC5.** Binding at creation to a named lineage, held as the lineage id; the binding checked before expiry, reuse detection and the wrong-secret counter, and a refusal without the key that only refuses and audits; prefix and record agreeing (`tnkb_` with a lineage, `tnk_` without); the refusal on 8443 and with another lineage (`auth.token.binding_refused`); tightening TGL-47 revoking unbound service-account tokens; an expired or revoked lineage revoking its tokens; account end revoking certificates in the same pages as tokens; reuse detection of a bound family revoking the lineage.

## 8. Order and the renewal package

```
CC1 → CC3 → CC2 → CC4 ─┬─→ CC5 → CC6b → CC7 → CC9
                       └─→ CC6a           ↑
CC8 skeleton after CC2 ······ CC8 in full after CC5
```

- CC1 to CC4, CC6a and the skeleton of CC8 touch no file of the renewal package and can be built now, on the step's branch. CC3 comes before CC2 because the listener's handshake asks the record index. Until CC5 they deliver enrollment, renewal and revocation of certificates that protect nothing yet, so the branch does not merge to `main` before CC5.
- CC5, CC6b and CC7 start when the renewal package is on `main` and the step's branch is updated from it; CC5 adapts to the token format and route names that package settled.
- The step reaches `main` as one pull request after CC9, through the gate.

## 9. Tests and the security review

### 9.1 Tests in the packages

- **Issuance (CC1, built):** a request asking for a CA, a node URI, a role URI, server authentication or a DNS name gets none; P-384 and Ed25519 keys, a broken self-signature, trailing data and a non-request are refused with their codes; a lifetime outside 1 to 365 days is refused; issuance by the wrong root is impossible by construction.
- **Identity reader (CC1, built):** refuses a certificate with no or two service-account URIs, a node or role URI or a DNS name beside the account, an account id that is no identifier or not in canonical form, server authentication, any purpose, no extended key usage, basic constraints CA, trailing data, node and server certificates and the root; accepts exactly the issued form.
- **Listener (CC2):** no client certificate, a node certificate, an expired one, a revoked one, an unrecorded one signed by the integration root, one from another installation's integration root: handshake refused, no HTTP; TLS 1.2 offered: refused while TGL-47 does not allow it (the default) and accepted when it does, with ECDHE and AEAD suites only and the Extended Master Secret required (a client without it is refused); no session ID and no ticket issued in either version; a revoked serial on an open HTTP/2 connection: the next request refused and the connection closed; a PROXY header, `X-Forwarded-For` and a session cookie on 8445 change nothing; a public route and a token of another account refused; the connection caps and the handshake timeout hold; 503 after 30 seconds without quorum; the listener stays closed until the first full load.
- **Enrollment (CC3):** every refusal of ADR 0035 decision 5 by its code; a wrong HMAC, an HMAC over another key or another account; plain HTTP and an unstated scheme outside Lab (refused, code withdrawn); two controllers accepting the same code in parallel: exactly one certificate; a token-authenticated or stale session creating a code: refused; the scripts of section 3 run against the lab with the secret absent from every request.
- **Renewal (CC4):** before the window (200, not due), twice within an hour, a lost answer (renewing again from the current certificate replaces the unseen successor, no reuse), from a replaced certificate inside the overlap (accepted for every route) and after it (renewal route only; a renewal is reuse: lineage revoked, bound tokens revoked), with a revoked key, with the same key (accepted, binding kept).
- **Binding (CC5):** every row of exit checks IC-E2, IC-E5 and IC-E6; a bound token with the right account but another lineage; an old bound token presented on 8443 and three wrong renewal secrets without the key (refused and audited, the family and the lineage untouched); a `tnkb_` token whose record lost its lineage and a `tnk_` token whose record has one (both refused); tightening the requirement (unbound service-account tokens revoked, not revived by loosening); a rollback build refusing `tnkb_`.
- **Lab (CC8):** IC-E1 to IC-E9 end to end, with the timing checks waiting on state, never on time (`docs/testing/rules.md`). The lab also covers what the targeted tests of CC2 and CC4 could not reach without a real socket:
  - the listener opening on demand (closed with nothing waiting, open after a code is created, closed again after the last certificate ends) and opening only after the first load of the records;
  - a revoked certificate's open HTTP/2 connection closed in the middle of a long answer (an event stream), within a moment of the revocation on another controller;
  - the 5-second handshake timeout (a client that connects and sends nothing), the cap of 16 connections per source and the cap of 512, each beside a working integration on another source;
  - the measurement of those limits and of the 30-second quorum bound, recorded in `bench/integration-listener/` with its results file;
  - TLS 1.2 without the Extended Master Secret refused: `openssl s_client -tls1_2 -no_ems -cert … -key …` (OpenSSL 3.0 and later) against a listener that allows TLS 1.2, which must fail the handshake, while the same command without `-no_ems` succeeds;
  - a renewal whose answer is dropped (the client discards the 201) and the next day's renewal replacing the unseen successor; the first presentation of a successor replacing its predecessor; a renewal from the replaced certificate revoking the lineage.

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
| PT-IC11 | Slow handshakes and connection floods on 8445 without a certificate, from one source and from many | The handshake timeout, the cap per source and the listener's cap hold; 8443 unaffected |
| PT-IC12 | Deleting the service account while a bound token streams events on 8445 | The stream ends; nothing after the deletion is answered |
| PT-IC13 | A `tnkb_` token against the previous release | Refused |
| PT-IC14 | TLS 1.2 with TGL-47 off; with it on, a CBC or RSA key exchange suite, renegotiation, a client without Extended Master Secret, a resumption by session ID; turning it on under Hardened | Refused each time; with it on, only full ECDHE and AEAD handshakes with Extended Master Secret complete |
| PT-IC15 | A certificate signed with a copy of the integration CA key and never recorded | Handshake refused |
| PT-IC16 | Requests on 8445 to a controller cut off from its quorum, before and after a revocation made on the majority | 503 after 30 seconds; the revocation holds once it rejoins |
| PT-IC17 | An old bound token on 8443, and three wrong renewal secrets for a bound token without the key | Refused and audited; nothing revoked |
| PT-IC18 | Public routes (sign-in, enrollment, node enrollment, the CA root), a session cookie, and a token of another account on 8445 | Refused or not found; no cookie read |
| PT-IC19 | Capturing an enrollment at a hostile proxy and redeeming the code for another key; enrolling over plain HTTP outside Lab | Refused; the plain request withdraws the code |
| PT-IC20 | A renewal whose answer is dropped, then a renewal again from the current certificate | Accepted; the unseen successor withdrawn; nothing revoked |

### 9.3 Fuzzing

Every parser of network input in this step gets a target in `fuzz/` before it merges (CONTRIBUTING rule 3):

- The PKCS#10 parser itself is already fuzzed through `cluster_messages` (the cluster port's renewal request); the integration CA calls the same `csr_public_key`, so no second target is added for it.
- `integration_identity` (CC1, built): the identity reader over arbitrary DER.
- `integration_enroll` (CC3): what the enrollment route reads from a client that holds no certificate yet: the code id and proof headers and the DER body, up to the HMAC check and the request parser.
- The `tnkb_` prefix check joins `api_request_headers`, the target of what the API reads before it authenticates anyone (CC5).

### 9.4 Privilege review

The review checks that the integration listener runs in the same process and account as 8443 with no new capability (8445 is above 1024, ADR 0023), that the integration root's key is only read by the issuing code path, that no route on 8445 is reachable without a valid certificate, and that a compromised integration host reaches nothing beyond its account's grants (section 4).

## 10. Decisions of the owner

The owner decided every question as recommended, except IC-Q4. The options that were not taken are kept here as the record of what was weighed (security, performance, usability, features).

| Question | Decided | Not taken |
|---|---|---|
| IC-Q1. What the certificate protects | Every use of a service-account token: tokens bound to a certificate lineage (RFC 8705 manner) | Only the renewal call; the certificate replacing the token (later, on top) |
| IC-Q2. Where the certificate is presented | A dedicated integration listener, default port 8445, client certificate required, opened on demand | Optional client authentication on 8443; a route on the cluster port |
| IC-Q3. One root or two | A separate integration root that the cluster port and nodes never trust | The existing root, told apart by URI |
| IC-Q4. TLS versions on the integration listener | TLS 1.3 by default in every profile, with the third part of TGL-47 allowing TLS 1.2 for Windows Server 2019 and older: off in every profile, a recorded deviation when on, refused under Hardened, limited to ECDHE with AEAD suites and the Extended Master Secret. In TLS 1.2 an observer on the path sees the client certificate (account id, serial, validity, public key), never the key, a token or a request | TLS 1.3 only with no setting; TLS 1.2 on by default outside Hardened |
| IC-Q5. The server certificate on 8445 | Always from the internal root, pinned by the code's fingerprint | Following 8443's mode |
| IC-Q6. TGL-47 values and Hardened | Lifetimes 90 / 30 / 7 / 365 days (Home, Standard, Hardened, Lab); Hardened requires binding for every token an administrator creates for a service account, mirror tokens (ADR 0033) once the mirror pusher presents a certificate; plugin process tokens (ADR 0032) outside | Mirror tokens bound from the start; binding never required |
| IC-Q7. A lapsed certificate | No grace period. Recovery is a new enrollment and new tokens; the lapsed lineage's tokens are revoked and never move (a detail changed after the owner's decision, which named `replaces` moving them: whoever redeemed such a code would take over existing tokens without the old key; the owner confirms the change) | A grace period after expiry; `replaces` moving tokens, or moving them after an administrator confirms the new key's digest |
| IC-Q8. What reuse detection revokes | Token family reuse also revokes the lineage, and lineage reuse also revokes its bound tokens | Each revokes its own kind only |
| IC-Q9. Key types | ECDSA P-256 only | RSA 2048 and 3072 as well |
| IC-Q10. The host firewall | The installer opens 8445 where it opens 8443 | Only with an installer option |
| IC-Q11. Tooling for integrators | Documented POSIX shell and PowerShell scripts in `docs/integrations.md` | A `tenko integration` client command |

The phase was decided with them: Phase 4, after release 0.1.0. The design's security review then changed details within these decisions (ADR 0035 decisions 3, 5 to 10); IC-Q7 is the one where a detail the owner named changed.

## 11. What the code could not settle

- **The renewal package's final form.** Its token text, route names and what TGL-46 binds are not on `main`; CC5 adapts the bound token (`tnkb_`) and the bound renewal to them.
- **Two paths to confirm at the start of their package:** the configuration type that holds `[cluster] listen` (CC2), and the rate limiter of the public node enrollment route, which the integration enrollment should share (CC3).
- **Endpoints in a cluster.** Whether the enrollment answer lists every controller's integration endpoint (which needs an address per member that the member records do not hold today) or the integrator uses one name that resolves to several controllers. Recommended: the name, documented; the list later if integrators ask.
- **TPM paths outside the lab.** `swtpm` with `tpm2-openssl` proves the Linux path in CC8; Windows with the Platform Crypto Provider and `curl.exe` or PowerShell needs the owner's Windows lab.
- **The installer's firewall step** for 8445 (IC-Q10) is package CC2b: it touches the prepared-ports record the binary reads and the Proxmox install test, which only the install lab runs; the unit-hardening gates are not affected (no unit or drop-in changes).
- **The HMAC on a POSIX host.** The default uses Python's standard library and keeps the secret out of process arguments; the `openssl` fallback cannot, since `openssl` takes an HMAC key only as an argument, and is documented with that warning.
- **The bounds chosen here** (512 connections, 16 per source, 5 seconds of handshake, 30 seconds without quorum) are first values, accepted as such. Package CC2 measures them in the three-controller lab (a flood without certificates beside a working integration, and a cut-off controller) and records the result in `bench/integration-listener/` with a results file, as CONTRIBUTING asks of a performance claim; the constants live on the listener's settings type.

## 12. Documents that change

In CC7 unless noted: `docs/REQUIREMENTS.md` (IAM-22 to IAM-25), `docs/SECURITY-PROFILES.md` (TGL-47, the owned range), `docs/certificates.md` (the integration root, the listener, the rule against forwarded certificates), `docs/access.md` (bound tokens), `docs/integrations.md` (new: enrollment, use, renewal, both scripts, troubleshooting by refusal code), `docs/cluster.md` (the integration listener and the second root), `docs/CONFORMANCE.md` (RFC 8705 binding to a lineage instead of the certificate; RFC 2986 requests; RFC 5280 profile; RFC 2104 HMAC of the enrollment proof; RFC 7627 for TLS 1.2), `docs/adr/README.md` (the row of ADR 0035), the upgrade notes (bound tokens during a rolling upgrade and after a rollback), and `CHANGELOG.md` with each package.
