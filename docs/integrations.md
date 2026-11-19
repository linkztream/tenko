# Integrations: client certificates for automation hosts

An integration (an automation host, a backup job, a provisioning script) acts as a service account with a scoped token (`docs/access.md` section 7). A token is a bearer credential: whoever holds its text acts as the account. This page covers the step that makes a stolen token worthless: the host proves itself with a private key that never leaves it, and a token can be bound to that key.

Related: [access.md](access.md) (service accounts, tokens and section 7.7, certificate binding), [certificates.md](certificates.md) (the integration CA, section 8), [SECURITY-PROFILES.md](SECURITY-PROFILES.md) (TGL-47), [ADR 0035](adr/0035-integration-client-certificates.md) (the decisions and the alternatives), [`deploy/tenko.example.toml`](../deploy/tenko.example.toml) (the `[integrations]` section).

The requirements are IAM-22 (enrollment and the listener), IAM-23 (certificate-bound tokens), IAM-24 (renewal) and IAM-25 (only recorded certificates; revocation) in [REQUIREMENTS.md](REQUIREMENTS.md).

## 1. What it is and when to use it

Without certificates, an integration host keeps a token (and, if it renews, a renewal secret) in a file. A copy of that file, of a backup of the host, or of a log that printed the token carries the integration away, from any address that reaches the API.

With certificates:

1. An administrator creates a single-use **enrollment code** for one service account.
2. On the automation host, the integrator makes an ECDSA P-256 key (ECDSA is the Elliptic Curve Digital Signature Algorithm; P-256 is the NIST curve of 256 bits), in a file or in a TPM (Trusted Platform Module, the key store chip of the host), and sends a certificate request for it. The key never travels.
3. Tenko's **integration CA** (certificate authority) answers with a client certificate that names that service account and nothing else.
4. The host presents the certificate on the **integration listener**, a port of its own (8445 by default), which speaks mutual TLS (Transport Layer Security with a certificate on both sides).
5. A token created with `"lineage"` is **bound** to the certificate: it is accepted only on that listener, over a connection whose certificate belongs to that lineage. A bound token copied from a log or a backup is refused anywhere else, and presenting it without the key cannot revoke anything.

Use it for hosts that run unattended and hold a token: backup jobs, monitoring and provisioning scripts. Do not use it for people (sessions and passkeys cover them) or for a token that must work from an arbitrary address with nothing installed.

What each case costs an attacker:

| What the attacker has | Result |
|---|---|
| A bound token alone (from a log, a paste, a memory dump) | Nothing: refused without the key |
| A copy of the host's disk, key in a TPM | Nothing: the key loads only in that TPM, behind its authorization value |
| A copy of the host's disk, key in a file | Everything the account may do, until the next renewal replaces the key; the copied certificate stops 15 minutes after the new one is first used, and a renewal from the copy after that revokes the lineage |
| Live control of the host | Everything the account may do while the attacker is there; with a TPM, access ends with the eviction |
| An enrollment code | One enrollment within its lifetime, for that account only, from the code's network if one was set; the list of certificates then shows the key and the label, and an administrator revokes it |

Nothing in this page widens what an account may do: the token's grants and the owner's grants intersect as in `docs/access.md` section 7.

## 2. The parts

| Part | What it is |
|---|---|
| **Integration CA** | A second root, separate from the CA of the nodes and of the API certificate. It issues client certificates and nothing else ([certificates.md](certificates.md) section 8). It is created at the first enrollment code. |
| **Integration listener** | Port 8445 of each controller. Mutual TLS, TLS 1.3, only integration certificates (section 3). |
| **Enrollment code** | `tnki.<code id>.<account id>.<secret>.<fingerprint>`: single use, at most one hour, for one service account, shown once (section 4). |
| **Certificate** | ECDSA P-256, subject `CN=tenko-integration`, one URI name `urn:tenko:service-account:<account id>`, client authentication only. It lasts 90 days in Home, 30 in Standard, 7 in Hardened and 365 in Lab (TGL-47, section 9). |
| **Lineage** | The first certificate of a host and every renewal of it share one lineage id. A service account holds at most eight active lineages (one per host). |
| **Bound token** | A service-account token created with a lineage; its text starts with `tnkb_` (section 7). |

A certificate is accepted only while Tenko holds a record of it: the serial must be recorded for the same account, in a state that accepts it, and the account must still be an enabled service account whose tokens were not ended since. A certificate that is validly signed but not recorded (for example one signed with a copy of the CA key from a controller that left the cluster) is refused.

## 3. The integration listener

### 3.1 Setting and opening

`[integrations] listen` in `tenko.toml` lists socket addresses (an address and a port).

| `listen` | The listener |
|---|---|
| not set | `0.0.0.0:8445`, opened **on demand**: while an enrollment code waits or an integration certificate is valid, and closed again when neither is true |
| `["0.0.0.0:8445"]` or any list of addresses | always open on those addresses (once the records have loaded and the integration CA exists) |
| `[]` | never open |

The listener also opens only after the controller has loaded the certificate records in full at start, and it has nothing to serve before the first enrollment code exists, since the integration CA is created with it. An address that is not an address with a port stops `tenko config check` and the start with `config.invalid` naming `integrations.listen`. The setting is read at start. The installers open the port in the host firewall where they open 8443; in a container, publish it (`-p 8445:8445`, [deploy/README.md](../deploy/README.md)).

### 3.2 A host without IPv4

An address in `listen` listens for its own family only. The default, `0.0.0.0:8445`, is IPv4: on a host that has no IPv4 it serves nothing, and on a host with both families it does not serve IPv6. A controller whose integrations come over IPv6 sets:

```toml
[integrations]
listen = ["[::]:8445"]
```

and lists both addresses (`["0.0.0.0:8445", "[::]:8445"]`) when integrations come over both families. Setting the list makes the listener always open, as the table above says. The integrator then uses the controller's IPv6 address or a name that resolves to it, and the name must be among the host names and addresses the controller's server certificate was issued for (`[tls]` `host_name`, `alt_names`, `addresses`).

### 3.3 TLS

- **TLS 1.3** in every profile, ALPN (application protocol negotiation) `h2` and `http/1.1`. A client certificate of the integration CA is mandatory: a peer without one never reaches HTTP, and the certificate request names only the integration root.
- **TLS 1.2** only while TGL-47 allows it (section 9), for automation hosts whose own TLS stack has no TLS 1.3 (Windows Server 2019 and older). Only ECDHE key exchange with AES-GCM or ChaCha20-Poly1305 is offered, the Extended Master Secret (EMS, RFC 7627) is required, so a client without it fails the handshake, and there is no renegotiation. In TLS 1.2 the client certificate travels before encryption starts: an observer on the path learns the account id, the serial, the validity and the public key of the certificate, and so which host acts as which account and when. The observer never learns the key, a token or a request.
- **No session resumption** in either version: no tickets, no session IDs, no session cache. Every connection runs the full handshake, so the checks of the certificate record run at every connection.
- **The server certificate** is always one of the internal root (the root of the API certificate in mode `internal_ca`, of the cluster), issued for the controller's configured names and addresses, in every TLS mode of 8443. The integrator never installs that root in a machine-wide trust store: the scripts below pass it per call (`curl --cacert`) or compare it with the fingerprint of the enrollment code, so the root vouches for this one connection only.

### 3.4 Limits

| Limit | Value |
|---|---|
| Open connections | 512 |
| Open connections from one address, counted before the handshake | 16 |
| Time for the handshake | 5 seconds |
| Answer without quorum | 503 `integration.isolated` after 30 seconds without contact to the cluster |

The limits are the listener's own, apart from the limits of 8443, so a flood on one does not starve the other. A controller that has been `isolated` or `electing` ([cluster.md](cluster.md)) for more than 30 seconds answers every request with 503: it cannot know of a revocation made on another controller. A single controller is never isolated.

### 3.5 What it serves

- Every authenticated route of the API, as on 8443, to a bearer token **owned by the account the certificate names**. A token of another account is refused with 403 `integration.token.wrong_account`; no token is 401 `integration.token.required`.
- The renewal route, `POST /api/v1/integrations/certificate/renew`, to the certificate alone (section 8).
- No public route (sign-in, enrollment, the CA root, node enrollment): 404 `integration.public_route`. No session cookie is read.
- The certificate is checked again at **every request**: a revocation, a replacement past its overlap, an expiry or the end of the account ends a long-lived HTTP/2 connection at its next request, and the controller closes the connections of a revoked certificate.

### 3.6 Behind a reverse proxy

A client certificate that a proxy forwards is **never trusted**, in any TLS mode and any profile: no header (`X-SSL-Client-Cert`, `X-Forwarded-Client-Cert`, `ssl-client-cert` or any other) and no TLS field of the PROXY protocol is read as a certificate. People keep using 8443 through the proxy. Integrations that use certificates reach the controller's integration listener directly, or through a TCP pass-through that leaves TLS end to end (the PROXY protocol is not read on this listener, so the client address is the TCP peer). The enrollment call (section 4.5) may go through the proxy: it carries the code id and an HMAC, never the code's secret, so the proxy cannot redeem the code for a key of its own. It needs the proxy to state the scheme (`docs/certificates.md` section 7).

## 4. Enrollment

### 4.1 The administrator creates a code

**Settings → Access → Integration certificates → Enroll a host** makes a single-use code for one service account and shows it once, with what to do with it. It needs an interactive sign-in within the last five minutes; a token never creates a code. The same through the API, with the session cookie of a fresh sign-in in `cookies.txt` (`lifetime_secs` is 60 to 3600 and defaults to 3600; `source` is optional and limits the enrollment to one network):

```sh
curl -sS -b cookies.txt -H 'Origin: https://tenko.example.test' \
  -H 'Content-Type: application/json' \
  https://tenko.example.test/api/v1/integrations/enrollments \
  -d '{"account": "0190d1c2-0000-7000-8000-000000000002",
       "lifetime_secs": 900, "source": "192.0.2.0/24"}'
```

```json
{
  "enrollment": {"id": "0190d1c2-0000-7000-8000-000000000001",
                 "account": "0190d1c2-0000-7000-8000-000000000002",
                 "created_by": "0190d1c2-0000-7000-8000-000000000003",
                 "created_at": "2026-01-05T09:00:00Z", "expires_at": "2026-01-05T09:15:00Z",
                 "source": "192.0.2.0/24", "state": {"state": "pending"}, "expired": false},
  "code": "tnki.0190d1c2-0000-7000-8000-000000000001.0190d1c2-0000-7000-8000-000000000002.<64 hex digits>.<64 hex digits>",
  "server_root_sha256": "<64 hex digits>"
}
```

The answer carries `Cache-Control: no-store`. The account must be an enabled service account (403 `integration.account`); a sign-in older than five minutes is 403 `auth.step_up_required`. `GET /api/v1/integrations/enrollments` lists the codes (waiting ones, and used, withdrawn and expired ones for seven days; never a secret) and `DELETE /api/v1/integrations/enrollments/{id}` withdraws a waiting code. The administrator hands the code to the integrator over a channel only the two of them read: it is a credential until it is used or expires.

### 4.2 The code

`tnki.<code id>.<account id>.<secret>.<fingerprint>`, five parts separated by dots:

| Part | Meaning |
|---|---|
| `tnki` | The prefix of an enrollment code |
| code id | A UUID (universally unique identifier); sent in a header, not secret |
| account id | The service account's UUID |
| secret | 256 bits in 64 lower-case hexadecimal digits; **never sent**, it only keys the HMAC |
| fingerprint | The SHA-256 of the server root, 64 lower-case hexadecimal digits: the root the listener's server certificate chains to |

The controller keeps the secret as a system secret in its vault while the code can be used, and deletes it when the code is used, withdrawn or expired; the code's record never holds it.

### 4.3 The key and the request

On the automation host, as the integration's own account, the integrator makes an ECDSA P-256 key and a PKCS#10 certificate request (RFC 2986, a signed request for a certificate, sent as DER, the binary form of ASN.1) over it. Only the public key of the request is used: names, extensions and attributes in it are ignored, and the certificate has the fields of section 2 whatever the request asked for. The request's self-signature must verify and the key must be P-256 in its one canonical encoding (named curve, uncompressed point), so `openssl` and .NET produce what the server accepts. A key that was ever in a certificate of any account, or in a revoked one, never enrolls again.

### 4.4 The proof

The enrollment proves that the sender holds the code's secret without sending it. The proof is an HMAC-SHA-256 (RFC 2104, a keyed hash) keyed with the **secret as 32 octets** (the 64 hexadecimal digits decoded), over these bytes in this order:

1. the text `tenko-integration-enroll-v1`, a line feed (octet 0x0a);
2. the code id in hyphenated lower-case form, a line feed;
3. the account id in hyphenated lower-case form, a line feed;
4. the DER `SubjectPublicKeyInfo` (SPKI, the public key in its standard encoding) of the request's key: 91 octets for P-256.

The proof goes in the header `Tenko-Enrollment-Proof` as 64 lower-case hexadecimal digits.

**Test vector**, to check an implementation:

| Input | Value |
|---|---|
| Secret (32 octets, 0 to 31) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| Code id | `0190d1c2-0000-7000-8000-000000000001` |
| Account id | `0190d1c2-0000-7000-8000-000000000002` |
| SPKI (the 27 octets `3059301306072a8648ce3d020106082a8648ce3d03010703420004`, then the 64 octets 1 to 64) | `3059301306072a8648ce3d020106082a8648ce3d030107034200040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40` |
| **Proof** | `2c7001035b8298745c7f0921f454bde9ac63c1585215a6ff15913367ef2a8f6f` |

The key bytes of the vector are only a pattern: an HMAC covers bytes, not a curve point. The server test `the_proof_matches_the_documented_test_vector` (`crates/tenko-auth/tests/client_certs.rs`) holds the server to the same bytes. To check a shell, with the secret on the command line (see the warning in section 5.4):

```sh
{ printf 'tenko-integration-enroll-v1\n0190d1c2-0000-7000-8000-000000000001\n0190d1c2-0000-7000-8000-000000000002\n'
  printf '%s' 3059301306072a8648ce3d020106082a8648ce3d030107034200040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 | xxd -r -p
} | openssl dgst -sha256 -mac HMAC -macopt hexkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f -r
```

It prints the proof above, followed by ` *stdin`.

### 4.5 The call

The integrator first fetches the server root and compares it with the fingerprint of the code, then sends the request:

| Step | Call | Answer |
|---|---|---|
| The server root | `GET /api/v1/integrations/ca` on the API listener (public, PEM) | 200. Public data: trust it only when its SHA-256 equals the code's fingerprint (`openssl x509 -fingerprint -sha256`, without colons, lower case) |
| Enroll | `POST /api/v1/integrations/enroll?label=<host label>` with `Content-Type: application/pkcs10`, the DER request as the body, and the headers `Tenko-Enrollment-Code: <code id>` and `Tenko-Enrollment-Proof: <proof>` | 201, the certificate in PEM (`application/pem-certificate-chain`, `Cache-Control: no-store`) |

The label is 1 to 64 printable characters that name the host in the list of certificates. The call needs HTTPS: plain HTTP, or a proxy that does not state the scheme, is refused with 403 `integration.enroll.transport` outside the Lab profile, and over plain HTTP the code is withdrawn. The certificate and its record are written in one batch that consumes the code, and the certificate is answered only after that write committed. The refusals are in section 10. Tenko cannot tell whether the key is in a TPM; there is no key attestation in this step.

## 5. POSIX shell: enrollment, use and renewal

Needs `openssl`, `curl` 7.55 or later (for `-H @file`) and `python3` (its standard library computes the HMAC). The scripts use no other tool. Run them as the integration's own account, in a state directory only it can read (`~/.tenko-integration` by default; `umask 077` is set).

### 5.1 Enrollment

Put the code in `enroll.code` in the state directory, then run `TENKO_API=https://tenko.example.test:8443 TENKO_LABEL=backup-host ./tenko-enroll.sh`. When 8443 serves a certificate the system already trusts (an imported certificate, a proxy), add `TENKO_API_TRUST=system`; with the internal CA the script checks 8443 against the root it fetched.

```sh
#!/bin/sh
# tenko-enroll.sh: enrolls this host with a Tenko enrollment code.
# Needs: openssl, curl (7.55 or later), python3. Run it as the integration's own account.
#   TENKO_API    base URL of the API listener, for example https://tenko.example.test:8443
#   TENKO_LABEL  name of this host in the certificate list (1 to 64 of A-Z a-z 0-9 . _ -)
#   TENKO_DIR    state directory (default ~/.tenko-integration); enroll.code must be in it
#   TENKO_API_TRUST=system  when 8443 serves a certificate that the system already trusts
set -eu
umask 077
api=${TENKO_API:?set TENKO_API}
label=${TENKO_LABEL:-$(hostname)}
dir=${TENKO_DIR:-$HOME/.tenko-integration}
case $label in '' | *[!A-Za-z0-9._-]*) echo "TENKO_LABEL: use letters, digits, . _ -" >&2; exit 2 ;; esac
mkdir -p "$dir"
cd "$dir"
trap 'rm -f client.key client.csr client.spki client.crt enroll.headers' EXIT

# tnki.<code id>.<account id>.<secret>.<fingerprint of the server root>
IFS=. read -r prefix id account secret fingerprint < enroll.code
[ "$prefix" = tnki ] || { echo "enroll.code is not an enrollment code" >&2; exit 2; }

# The server root is public data; it is trusted only if it matches the fingerprint of the code.
curl -fsS -k "$api/api/v1/integrations/ca" -o tenko-ca.pem
seen=$(openssl x509 -in tenko-ca.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)
[ "$seen" = "$fingerprint" ] || { echo "the server root does not match the code" >&2; rm -f tenko-ca.pem; exit 9; }

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client.key
openssl req -new -key client.key -subj /CN=tenko-integration -outform DER -out client.csr
openssl req -in client.csr -inform DER -noout -pubkey | openssl pkey -pubin -outform DER -out client.spki

# HMAC-SHA-256 keyed with the code's secret. The secret reaches Python on standard input
# (printf is built in), so it is never an argument of a process.
proof=$(printf '%s\n' "$secret" | python3 -c '
import hashlib, hmac, sys
key = bytes.fromhex(sys.stdin.readline().strip())
head = ("tenko-integration-enroll-v1\n%s\n%s\n" % (sys.argv[1], sys.argv[2])).encode()
print(hmac.new(key, head + open(sys.argv[3], "rb").read(), hashlib.sha256).hexdigest())
' "$id" "$account" client.spki)

# Headers go from a file, never as arguments.
printf 'Content-Type: application/pkcs10\nTenko-Enrollment-Code: %s\nTenko-Enrollment-Proof: %s\n' \
  "$id" "$proof" > enroll.headers
if [ "${TENKO_API_TRUST:-}" = system ]; then set --; else set -- --cacert tenko-ca.pem; fi
status=$(curl -sS "$@" -H @enroll.headers --data-binary @client.csr \
  -o client.crt -w '%{http_code}' "$api/api/v1/integrations/enroll?label=$label")
if [ "$status" != 201 ]; then
  echo "enrollment refused ($status): $(cat client.crt)" >&2
  exit 1
fi
cat client.key client.crt > client.pem.new
mv client.pem.new client.pem
rm -f enroll.code
echo "enrolled: $dir/client.pem and $dir/tenko-ca.pem"
```

The script leaves `client.pem` (the key and the certificate, one file) and `tenko-ca.pem` (the server root) in the state directory, deletes the code, the key's loose copy and the request, and fails with exit status 9 when the root does not match the code. The code's secret stays out of every process argument: `printf` is a shell built-in and Python reads it on standard input; the headers go to `curl` from a file.

### 5.2 Use

Keep the token in a file only the account reads, and send it from a file as well:

```sh
printf 'Authorization: Bearer %s\n' "$(cat token)" > call.headers
curl -fsS --cacert tenko-ca.pem --cert client.pem -H @call.headers \
  https://tenko.example.test:8445/api/v1/access/token
```

### 5.3 Renewal

The renewal needs no token: the certificate alone authorizes it. Run it **daily** from a timer. Before the last third of the certificate's lifetime the server answers 200 with `{"not_due": true, "renew_after": ...}` and the script does nothing; after it, the server answers 201 with a new certificate and the script switches key and certificate in one rename. The script makes a fresh key every time, which is what a key in a file should do.

```sh
#!/bin/sh
# tenko-renew.sh: renews the integration certificate over the integration listener, with the
# certificate alone. Run it daily from a timer. The server answers "not due" (200) until the
# last third of the certificate's lifetime, so running it often is harmless.
#   TENKO_HOST   name of a controller, as in its server certificate (not a proxy)
#   TENKO_PORT   integration port (default 8445)
#   TENKO_DIR    state directory (default ~/.tenko-integration)
set -eu
umask 077
host=${TENKO_HOST:?set TENKO_HOST}
port=${TENKO_PORT:-8445}
dir=${TENKO_DIR:-$HOME/.tenko-integration}
cd "$dir"
trap 'rm -f next.key next.csr next.crt next.pem' EXIT

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out next.key
openssl req -new -key next.key -subj /CN=tenko-integration -outform DER -out next.csr
status=$(curl -sS --cacert tenko-ca.pem --cert client.pem -H 'Content-Type: application/pkcs10' \
  --data-binary @next.csr -o next.crt -w '%{http_code}' \
  "https://$host:$port/api/v1/integrations/certificate/renew")
case $status in
  201) # key and certificate switch in one rename
    cat next.key next.crt > next.pem
    mv next.pem client.pem ;;
  200) echo "not due yet: $(cat next.crt)" ;;
  *) echo "renewal refused ($status): $(cat next.crt)" >&2; exit 1 ;;
esac
```

A failed renewal makes the script exit non-zero, so the timer's unit fails and the host's own monitoring sees it; Tenko's expiry notice (section 8) is the second net. A systemd timer:

```ini
# /etc/systemd/system/tenko-renew.service
[Unit]
Description=Renew the Tenko integration certificate

[Service]
Type=oneshot
User=tenko-integration
Environment=TENKO_HOST=tenko.example.test
ExecStart=/usr/local/bin/tenko-renew.sh

# /etc/systemd/system/tenko-renew.timer
[Unit]
Description=Daily renewal of the Tenko integration certificate

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now tenko-renew.timer`. The host that renews must reach the controller's integration port directly (section 3.6), under a name that is in the controller's server certificate.

**First use of the new certificate.** The new certificate is *pending* on the server until it is first presented, by the next call that uses `client.pem` (a token call or the next renewal). At that moment it becomes current and its predecessor becomes replaced. If the answer to a renewal is lost, the next renewal from the old certificate replaces the unseen successor: nothing is revoked.

### 5.4 Without Python

The same HMAC with `openssl`:

```sh
{ printf 'tenko-integration-enroll-v1\n%s\n%s\n' "$id" "$account"; cat client.spki; } |
  openssl dgst -sha256 -mac HMAC -macopt "hexkey:$secret" -r | cut -d' ' -f1
```

`openssl` takes an HMAC key only as an argument, so the code's secret is visible in the process list while it runs. Use this only on a host where other users cannot read process arguments (Linux `/proc` mounted with `hidepid=2`). PowerShell computes the HMAC in process.

### 5.5 A key in a TPM (Linux)

With the `tpm2-openssl` provider the key is made in the TPM and used from there, with an authorization value that only the integration's account can read: `openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -pkeyopt user-auth:…`, then `-passin file:…` wherever the key is used, and `curl` reaches it through its OpenSSL backend. A TPM key cannot be copied, so renewal may use the same key (`openssl req -provider tpm2 -provider default -key handle:… -passin file:…`); the server accepts either. These commands are proved in the project's lab with a software TPM; check them against your `tpm2-openssl` version.

## 6. PowerShell: enrollment, use and renewal

Windows PowerShell 5.1 or later with .NET Framework 4.7.2 or later (for `CertificateRequest`), or PowerShell 7. The script keeps the key and the certificate in the integration account's own certificate store (`Cert:\CurrentUser\My`): the private key is created **not exportable** and the HMAC is computed in process. Run it as the account the automation runs as, with its profile loaded (a scheduled task with "Run whether the user is logged on or not" and a stored password, or a group-managed service account).

```powershell
# tenko-integration.ps1: enrollment, use and renewal of an integration certificate.
# Windows PowerShell 5.1 or later, .NET Framework 4.7.2 or later (CertificateRequest).
# Dot-source it, then call the functions:
#   . .\tenko-integration.ps1
#   Register-TenkoIntegration -Api https://tenko.example.test:8443 -CodeFile .\enroll.code -Label backup-host
#   Update-TenkoIntegrationCertificate -ApiHost tenko.example.test
# Run it as the integration's own Windows account: the key and the certificate live in that
# account's certificate store, and the private key is not exportable.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]12288 -bor [Net.SecurityProtocolType]::Tls12 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TenkoTrust {
    // The pinned root of the internal CA. The system's own trust is never extended.
    public static X509Certificate2 Root;
    public static readonly RemoteCertificateValidationCallback Pinned = PinnedCheck;
    public static readonly RemoteCertificateValidationCallback Anything = delegate { return true; };
    static bool PinnedCheck(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
        if (errors == SslPolicyErrors.None) return true;
        if (Root == null || certificate == null || errors != SslPolicyErrors.RemoteCertificateChainErrors) return false;
        using (X509Chain own = new X509Chain()) {
            own.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            own.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            own.ChainPolicy.ExtraStore.Add(Root);
            if (!own.Build(new X509Certificate2(certificate))) return false;
            X509Certificate2 top = own.ChainElements[own.ChainElements.Count - 1].Certificate;
            return top.Thumbprint == Root.Thumbprint;
        }
    }
}
'@

function Get-TenkoStateDir([string]$StateDir) {
    if (-not $StateDir) { $StateDir = Join-Path $env:LOCALAPPDATA 'TenkoIntegration' }
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $StateDir
}

# One HTTPS request; a client certificate is optional. The answer is the status and the body.
function Invoke-TenkoRequest {
    param([string]$Method, [string]$Uri, [byte[]]$Body, [string]$ContentType,
          [hashtable]$Headers = @{}, $ClientCertificate, [switch]$TrustAnything)
    $request = [Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.AllowAutoRedirect = $false
    $request.Timeout = 30000
    $request.ServerCertificateValidationCallback = if ($TrustAnything) { [TenkoTrust]::Anything } else { [TenkoTrust]::Pinned }
    foreach ($name in $Headers.Keys) { $request.Headers[$name] = $Headers[$name] }
    if ($ClientCertificate) { [void]$request.ClientCertificates.Add($ClientCertificate) }
    if ($Body) {
        $request.ContentType = $ContentType
        $request.ContentLength = $Body.Length
        $out = $request.GetRequestStream(); $out.Write($Body, 0, $Body.Length); $out.Dispose()
    }
    try { $response = $request.GetResponse() }
    catch [Net.WebException] { if ($null -eq $_.Exception.Response) { throw }; $response = $_.Exception.Response }
    $status = [int]$response.StatusCode
    $memory = New-Object IO.MemoryStream
    $in = $response.GetResponseStream(); $in.CopyTo($memory); $in.Dispose(); $response.Close()
    [pscustomobject]@{ Status = $status; Body = $memory.ToArray() }
}

# A P-256 key in the account's key store, not exportable. -Provider 'Microsoft Platform Crypto
# Provider' puts it in the TPM instead.
function New-TenkoKey([string]$Provider) {
    $parameters = New-Object Security.Cryptography.CngKeyCreationParameters
    $parameters.Provider = New-Object Security.Cryptography.CngProvider($Provider)
    $parameters.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
    $parameters.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
    $key = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::ECDsaP256,
        ('tenko-integration-' + [guid]::NewGuid()), $parameters)
    New-Object Security.Cryptography.ECDsaCng($key)
}

# The PKCS#10 request (DER) and the DER SubjectPublicKeyInfo of the key, in the one form the
# server accepts: named curve P-256, uncompressed point.
function New-TenkoRequest($Key) {
    $subject = New-Object Security.Cryptography.X509Certificates.X500DistinguishedName('CN=tenko-integration')
    $request = New-Object Security.Cryptography.X509Certificates.CertificateRequest($subject, $Key,
        [Security.Cryptography.HashAlgorithmName]::SHA256)
    $point = $Key.ExportParameters($false).Q
    $prefix = [byte[]](0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
                       0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04)
    [pscustomobject]@{ Csr = $request.CreateSigningRequest(); Spki = [byte[]]($prefix + $point.X + $point.Y) }
}

function ConvertTo-TenkoBytes([string]$Hex) {
    [byte[]]@(for ($i = 0; $i -lt $Hex.Length; $i += 2) { [Convert]::ToByte($Hex.Substring($i, 2), 16) })
}

# HMAC-SHA-256 keyed with the code's secret, in process: the secret is never an argument.
function Get-TenkoProof([string]$SecretHex, [string]$CodeId, [string]$AccountId, [byte[]]$Spki) {
    $head = [Text.Encoding]::ASCII.GetBytes("tenko-integration-enroll-v1`n$CodeId`n$AccountId`n")
    $hmac = New-Object Security.Cryptography.HMACSHA256(, (ConvertTo-TenkoBytes $SecretHex))
    -join ($hmac.ComputeHash([byte[]]($head + $Spki)) | ForEach-Object { $_.ToString('x2') })
}

# The certificate of the answer (PEM) joined with the key, kept in the account's store.
function Save-TenkoCertificate([byte[]]$Pem, $Key, [string]$Label, [string]$StateDir) {
    $text = [Text.Encoding]::ASCII.GetString($Pem)
    $block = [regex]::Match($text, '-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----')
    if (-not $block.Success) { throw "the answer holds no certificate: $text" }
    $der = [Convert]::FromBase64String(($block.Groups[1].Value -replace '\s', ''))
    $bare = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, $der)
    $cert = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($bare, $Key)
    $cert.FriendlyName = "tenko-integration $Label"
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
    $store.Open('ReadWrite'); $store.Add($cert); $store.Close()
    # The switch to the new certificate is one rename of one small file.
    $next = Join-Path $StateDir 'current.txt.new'
    Set-Content -Path $next -Value $cert.Thumbprint -Encoding ASCII
    Move-Item -Force -Path $next -Destination (Join-Path $StateDir 'current.txt')
    $cert
}

function Get-TenkoClientCertificate([string]$StateDir) {
    $thumbprint = (Get-Content (Join-Path (Get-TenkoStateDir $StateDir) 'current.txt') -TotalCount 1).Trim()
    $cert = Get-Item "Cert:\CurrentUser\My\$thumbprint"
    if (-not $cert.HasPrivateKey) { throw 'the certificate has no private key in this account store' }
    $cert
}

function Register-TenkoIntegration {
    param([Parameter(Mandatory)][string]$Api, [Parameter(Mandatory)][string]$CodeFile,
          [string]$Label = $env:COMPUTERNAME, [string]$StateDir,
          [string]$Provider = 'Microsoft Software Key Storage Provider')
    $StateDir = Get-TenkoStateDir $StateDir
    if ($Label -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'Label: use 1 to 64 of letters, digits, . _ -' }
    $parts = (Get-Content $CodeFile -TotalCount 1).Trim().Split('.')
    if ($parts.Count -ne 5 -or $parts[0] -ne 'tnki') { throw "$CodeFile is not an enrollment code" }
    $null, $codeId, $accountId, $secret, $fingerprint = $parts

    # The server root is public; it is trusted only if its SHA-256 matches the code.
    $answer = Invoke-TenkoRequest -Method GET -Uri "$Api/api/v1/integrations/ca" -TrustAnything
    if ($answer.Status -ne 200) { throw "the root could not be fetched ($($answer.Status))" }
    $pem = [Text.Encoding]::ASCII.GetString($answer.Body)
    $der = [Convert]::FromBase64String(([regex]::Match($pem, '-----BEGIN CERTIFICATE-----([^-]+)-----END').Groups[1].Value -replace '\s', ''))
    $root = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, $der)
    $seen = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($root.RawData) | ForEach-Object { $_.ToString('x2') })
    if ($seen -ne $fingerprint) { throw 'the server root does not match the enrollment code' }
    [TenkoTrust]::Root = $root
    Set-Content -Path (Join-Path $StateDir 'tenko-ca.pem') -Value $pem -Encoding ASCII

    $key = New-TenkoKey $Provider
    $made = New-TenkoRequest $key
    $headers = @{ 'Tenko-Enrollment-Code' = $codeId
                  'Tenko-Enrollment-Proof' = (Get-TenkoProof $secret $codeId $accountId $made.Spki) }
    $answer = Invoke-TenkoRequest -Method POST -Uri "$Api/api/v1/integrations/enroll?label=$Label" `
        -Body $made.Csr -ContentType 'application/pkcs10' -Headers $headers
    if ($answer.Status -ne 201) {
        $key.Key.Delete()
        throw "enrollment refused ($($answer.Status)): $([Text.Encoding]::UTF8.GetString($answer.Body))"
    }
    $cert = Save-TenkoCertificate $answer.Body $key $Label $StateDir
    Remove-Item $CodeFile
    "enrolled: certificate $($cert.Thumbprint), valid until $($cert.NotAfter.ToString('s'))"
}

# Run it daily from a scheduled task. Until the last third of the lifetime the server answers
# "not due", so running it often is harmless.
function Update-TenkoIntegrationCertificate {
    param([Parameter(Mandatory)][string]$ApiHost, [int]$Port = 8445, [string]$StateDir,
          [string]$Provider = 'Microsoft Software Key Storage Provider')
    $StateDir = Get-TenkoStateDir $StateDir
    $old = Get-TenkoClientCertificate $StateDir
    [TenkoTrust]::Root = New-Object Security.Cryptography.X509Certificates.X509Certificate2(
        (Join-Path $StateDir 'tenko-ca.pem'))
    $key = New-TenkoKey $Provider
    $made = New-TenkoRequest $key
    $answer = Invoke-TenkoRequest -Method POST -Uri "https://${ApiHost}:$Port/api/v1/integrations/certificate/renew" `
        -Body $made.Csr -ContentType 'application/pkcs10' -ClientCertificate $old
    $label = $old.FriendlyName -replace '^tenko-integration ', ''
    switch ($answer.Status) {
        201 {
            [void](Save-TenkoCertificate $answer.Body $key $label $StateDir)
            # The new certificate is in use from here; the old one and its key are not needed.
            $oldKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($old)
            $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
            $store.Open('ReadWrite'); $store.Remove($old); $store.Close()
            if ($oldKey -is [Security.Cryptography.ECDsaCng]) { $oldKey.Key.Delete() }
            'renewed'
        }
        200 {
            $key.Key.Delete()
            "not due yet: $([Text.Encoding]::UTF8.GetString($answer.Body))"
        }
        default {
            $key.Key.Delete()
            throw "renewal refused ($($answer.Status)): $([Text.Encoding]::UTF8.GetString($answer.Body))"
        }
    }
}

# A call with a bound token and the certificate, for example:
#   Invoke-TenkoApi -ApiHost tenko.example.test -Path /api/v1/access/token -TokenFile .\token.txt
function Invoke-TenkoApi {
    param([Parameter(Mandatory)][string]$ApiHost, [Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][string]$TokenFile, [int]$Port = 8445, [string]$StateDir)
    $StateDir = Get-TenkoStateDir $StateDir
    [TenkoTrust]::Root = New-Object Security.Cryptography.X509Certificates.X509Certificate2(
        (Join-Path $StateDir 'tenko-ca.pem'))
    $answer = Invoke-TenkoRequest -Method GET -Uri "https://${ApiHost}:$Port$Path" `
        -Headers @{ Authorization = 'Bearer ' + (Get-Content $TokenFile -TotalCount 1).Trim() } `
        -ClientCertificate (Get-TenkoClientCertificate $StateDir)
    [Text.Encoding]::UTF8.GetString($answer.Body)
}
```

Enroll once, then call the API and renew from a scheduled task:

```powershell
. .\tenko-integration.ps1
Register-TenkoIntegration -Api https://tenko.example.test:8443 -CodeFile .\enroll.code -Label backup-host
Invoke-TenkoApi -ApiHost tenko.example.test -Path /api/v1/access/token -TokenFile .\token.txt

$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `
  '-NoProfile -Command ". C:\tenko\tenko-integration.ps1; Update-TenkoIntegrationCertificate -ApiHost tenko.example.test"'
$trigger = New-ScheduledTaskTrigger -Daily -At 03:30
Register-ScheduledTask -TaskName 'Tenko certificate renewal' -Action $action -Trigger $trigger `
  -User 'EXAMPLE\svc-tenko' -Password '<the account password>'
```

Notes:

- **Trust.** The script never imports the Tenko root into a trust store. Its certificate callback accepts a server certificate only when the system trusts it, or when the chain ends in the pinned root (the root whose SHA-256 the code carries) and the name matches.
- **TLS version.** The script asks for TLS 1.3 and 1.2. Windows Server 2019 and older have no TLS 1.3 in their own stack: the listener refuses them until TGL-47 allows TLS 1.2 (section 9).
- **A key in the TPM** needs `-Provider 'Microsoft Platform Crypto Provider'` on `Register-TenkoIntegration` and `Update-TenkoIntegrationCertificate`; the script makes a fresh key at every renewal. This path is proved only in a Windows lab with a TPM.
- **The switch.** The new certificate is added to the store and `current.txt` is replaced by one rename before the old certificate and its key are deleted. If the host stops in between, the old certificate stays in use and the next renewal replaces the unseen successor.
- The bound token for the account is in `token.txt`, readable by that account only.

## 7. Bound tokens

An administrator binds a token when creating it: `"lineage"` in the creation request names one of the account's lineages (`GET /api/v1/integrations/certificates?account=<account id>` lists them; each item has `lineage`, `label`, `serial`, `state`, `not_after`). The lineage must be current or pending and of the same account, or the request is refused with 400 `auth.invalid_request` naming `lineage`.

```sh
curl -sS -b cookies.txt -H 'Origin: https://tenko.example.test' \
  -H 'Content-Type: application/json' \
  https://tenko.example.test/api/v1/access/service-accounts/0190d1c2-0000-7000-8000-000000000002/tokens \
  -d '{"name": "backup", "expires_in_days": 30, "scopes": ["metrics"],
       "lineage": "0190d1c2-0000-7000-8000-0000000000b1"}'
```

The token starts with `tnkb_`. The rules (`docs/access.md` section 7.7):

- The binding is to the **lineage**, not to one certificate as RFC 8705 has it, so a renewal (a new key, a new serial) keeps every bound token working and rewrites no token. A bound token that renews itself (IAM-20) stays bound.
- A bound token is accepted only on the integration listener, over a connection whose certificate belongs to its lineage. The binding is checked **first**, before the token's expiry, before reuse detection and before the counter of wrong renewal secrets.
- Presented without the certificate (on 8443, on 8445 with no certificate of the lineage, or with another lineage's), it is refused with 401 `auth.unauthenticated`, like an unknown token, and audited as `auth.token.binding_refused` (once a minute per token). Nothing else happens: no reuse detection, no counter, no revocation. Whoever lacks the key can neither use a bound token nor revoke it.
- A build that does not know binding refuses `tnkb_` tokens at their prefix, and a record whose binding was lost is refused, never read as unbound.
- A token never moves from one lineage to another. After a lapse or a revocation, the recovery is a new enrollment and new tokens.

To use a bound token send the certificate and the token on the integration port: with `curl`, `--cacert tenko-ca.pem --cert client.pem` and the `Authorization` header (section 5.2); with PowerShell, `Invoke-TenkoApi` (section 6).

## 8. Renewal, revocation, lapse and reuse

**Renewal.** `POST /api/v1/integrations/certificate/renew` on the integration listener, with the current certificate and a new PKCS#10 request as the body (`Content-Type: application/pkcs10`). It is accepted in the last third of the current certificate's lifetime and at most once an hour:

| Answer | Meaning |
|---|---|
| 200 `{"not_due": true, "renew_after": "<time>"}` | Not yet in the last third; nothing was issued |
| 201 and a PEM certificate | Renewed. The certificate is pending until it is first presented |
| 409 `integration.renew.too_soon` | The lineage renewed within the hour |
| 409 `integration.key.used` | The key was enrolled for another lineage |
| 403 `integration.renew.reuse` | The certificate was already replaced; the lineage is revoked (below) |
| 401 `integration.certificate.refused` | The certificate is no longer accepted |

Within a lineage there is at most one current certificate and one pending successor. A renewal from the current certificate while its successor has not been presented replaces that successor (the answer was lost). When the successor is first presented it becomes current and its predecessor becomes **replaced**: the predecessor passes for every route for 15 more minutes (the overlap), then passes the handshake for the renewal route only. Every renewal is audited (`auth.client_cert.renew`, the old and new serial and whether the key changed), and so is the first presentation (`auth.client_cert.present`). The TLS handshake of an expired certificate fails: there is no grace period.

**Reuse.** A renewal from a replaced certificate after its successor was presented means two parties hold the lineage's key: the lineage is revoked with every token bound to it. A copy of a key file therefore cannot keep renewing beside the legitimate host.

**Revocation.** An administrator revokes a whole lineage with `DELETE /api/v1/integrations/certificates/{serial}` (any serial of it; 204; no fresh sign-in needed; audited `auth.client_cert.revoke`), or in the UI under **Access → Integration certificates** with its consequence shown first. It takes effect on every controller within the store's replication, also on open connections, and the lineage's bound tokens are revoked in the same commit. The key can never enroll again. Deleting or disabling the service account ends its certificates at once; a reuse of a bound token's family (IAM-21), which can happen only once the key was proven, revokes the lineage too.

**Lapse.** A lineage whose certificates have all expired is dead: its bound tokens are removed by the hourly sweep (audited `auth.client_cert.lapse`) and never move. Recovery is a new enrollment, a new lineage and new tokens.

**The expiry notice.** A current certificate that has entered the last sixth of its lifetime without a successor raises the status condition `integration.certificate_expiring` (in `GET /api/v1/system/status` and on the start page, with the count, the label and the end of the first one), which the findings and notifications of OPS-29 read like every status condition. It means the renewal timer of that host is not working: check the unit or the scheduled task and its output.

## 9. The toggle (TGL-47)

TGL-47 ([SECURITY-PROFILES.md](SECURITY-PROFILES.md)) sets three things:

| Setting | Home | Standard | Hardened | Lab |
|---|---|---|---|---|
| Certificate lifetime | 90 days | 30 days | 7 days | 365 days |
| Certificate-bound tokens required for service accounts | no | no | yes | no |
| TLS 1.2 on the integration listener | off | off | off, and turning it on is refused | off |

It is changed with the other toggles: `PATCH /api/v1/settings/security` with `{"integrations": {"lifetime_days": 30, "require_binding": false, "allow_tls12": false}}` (a fresh sign-in; the lifetime is 1 to 365 days) or on the security settings page.

- **Lifetime.** A shorter lifetime applies at the next renewal of each lineage. A lifetime longer than Home's is a deviation the settings show.
- **Binding required.** Every token an administrator creates for a service account must then name a lineage (400 `auth.invalid_request` naming `lineage` otherwise). **Turning it on, also by switching to Hardened, removes every unbound service-account token** at once, audited per token as `auth.token.revoke`. The change reports them in `unbound_tokens_removed` (`count` and `accounts`), and `?dry_run=true` answers the same without writing anything, so look at the count first. Loosening the requirement later revives none of them.
- **TLS 1.2.** Off in every profile and refused under Hardened. Turning it on is a deviation the settings show and the audit log records, like every toggle change; while it is on the status carries the warning `integration.tls12_allowed` (on the start page and in `GET /api/v1/system/status`). It is read per connection: turning it off again refuses the next TLS 1.2 handshake. Allow it only for hosts that cannot do TLS 1.3 (section 3.3 says what an observer on the path then sees).

## 10. Troubleshooting

A handshake that fails shows no HTTP answer; the client reports a TLS error. The server log at debug level names the reason of a failed integration handshake.

| Symptom | Cause and fix |
|---|---|
| Connection refused on 8445 | The listener is closed: no enrollment code waits and no certificate is valid (the on-demand default), `listen = []`, a host firewall or container publish rule, or an IPv6-only host with the default IPv4 address (section 3.2) |
| TLS handshake fails, no HTTP answer | No client certificate sent; the certificate is of another installation, a node certificate, expired, revoked or not recorded; the server certificate does not match the name you connected to (use a name from the controller's configured names); or the client offers only TLS 1.2 (or no Extended Master Secret) while TGL-47 does not allow TLS 1.2 |
| 401 `integration.certificate.refused` | The certificate was revoked, its account was disabled or deleted, or its lineage lapsed, on a connection that was already open. Enroll again |
| 403 `integration.certificate.replaced` | A replaced certificate past its overlap was used for a call. Use the new certificate (check that the renewal script stored it) |
| 403 `integration.renew.reuse` | The renewal came from a replaced certificate: the lineage is revoked. Find the second holder of the key, then enroll again with a new code |
| 409 `integration.renew.too_soon` | The lineage renewed within the last hour |
| 404 `integration.public_route` | A route that needs no credentials (sign-in, the CA root, enrollment) was called on 8445. Call it on 8443 |
| 401 `integration.token.required`, 403 `integration.token.wrong_account` | No token, or a token of another account than the certificate's |
| 401 `auth.unauthenticated` for a `tnkb_` token | The token is bound and was presented without a certificate of its lineage, on the wrong port or with another lineage's certificate. The audit log holds `auth.token.binding_refused`. Nothing was revoked |
| 503 `integration.isolated` | The controller lost contact to its cluster more than 30 seconds ago. Use another controller, or wait for it to rejoin |
| 503 `integration.unavailable` | Integration certificates are not available on this controller |
| 401 `integration.code.invalid` | A wrong proof, an unknown or withdrawn code, or a malformed header. Check the proof against the test vector (section 4.4), that the secret is the decoded hexadecimal and that the SPKI is the canonical 91 octets |
| 401 `integration.code.used`, `integration.code.expired` | The code was used or expired. Ask for a new one |
| 403 `integration.code.source` | The enrollment came from outside the code's network |
| 403 `integration.enroll.transport` | The enrollment used plain HTTP (the code is withdrawn) or came through a proxy that did not state the scheme; use HTTPS and state `X-Forwarded-Proto` at the proxy |
| 403 `integration.account` | The account is not an enabled service account, or its tokens ended since the code was made |
| 409 `integration.key.used` | The key was enrolled before, or was in a revoked certificate. Make a new key |
| 409 `integration.lineages` | The account holds eight lineages. Revoke one that is not used |
| 415 `integration.request.media_type` | The body was not sent as `application/pkcs10` |
| 422 `integration.request.invalid` | The body is not one PKCS#10 request over a P-256 key with a valid self-signature, or is over 16 KiB |
| 422 `integration.label` | The label is empty, over 64 characters or has control characters |
| 403 `auth.step_up_required` when making a code | The session signed in more than five minutes ago, or a token was used. Sign in again |
| 422 `integration.code.lifetime` | The lifetime was outside 60 to 3600 seconds |
| 500 `integration.issuing` | The integration CA failed; see the server log |
| `tenko-enroll.sh` exits 9, or the PowerShell script says the root does not match | The server answered with a root other than the one in the code: check the address, the code and who sits on the path |

## 11. Reference

| Route | Where | Who | Answer |
|---|---|---|---|
| `POST /api/v1/integrations/enrollments` | 8443 | administrator, interactive session signed in within five minutes | 201, the code once, its record |
| `GET /api/v1/integrations/enrollments` | 8443 | administrator | the codes, never a secret |
| `DELETE /api/v1/integrations/enrollments/{id}` | 8443 | administrator | 204, the code is withdrawn |
| `GET /api/v1/integrations/ca` | 8443 | public | the server root, PEM |
| `POST /api/v1/integrations/enroll?label=` | 8443 | public; the code id and the proof are the credential; HTTPS outside Lab | 201, the certificate, PEM |
| `GET /api/v1/integrations/certificates[?account=]` | 8443 | administrator | the certificates with lineage, label, serial, key digest, validity, state and first presentation |
| `DELETE /api/v1/integrations/certificates/{serial}` | 8443 | administrator | 204, the lineage is revoked |
| `POST /api/v1/integrations/certificate/renew` | 8445 only | the connection's certificate | 200 not due, or 201 and the certificate |
| every authenticated route of the API | 8445 | a token of the certificate's account | as on 8443 |

Audit actions: `cluster.integration_ca.create` (the integration CA was created), `auth.client_cert.code_create`, `auth.client_cert.code_withdraw`, `auth.client_cert.issue` (also refused enrollments), `auth.client_cert.renew`, `auth.client_cert.present`, `auth.client_cert.revoke`, `auth.client_cert.lapse`, `auth.token.binding_refused`. Status conditions: `integration.certificate_expiring`, `integration.tls12_allowed`. Configuration: `[integrations] listen`. Toggle: TGL-47.
