# The lab round `security`

This directory holds the lab round `security` (layer 2 of
[`docs/plans/security-audit-plan.md`](../../docs/plans/security-audit-plan.md)): a check that
runs against the binary being released and leaves evidence with stable finding IDs. It looks
at the node from outside (the ports it answers on, its TLS, malformed traffic on the wire, what
its API answers without credentials, a passive web scan of the interface and the API) and
from the host (the systemd unit and the service account), the way the weekly lab smokes under
`deploy/compose/lab-*/` check behaviour. It is development and measurement tooling and is out
of scope for security reports (`SECURITY.md`), like the other lab directories.

The round installs a **throwaway** node from the binary under test, as a user installs it
(`deploy/install.sh`), and checks it. Run it only on a machine you can discard: a CI runner or
a lab VM. It is not a scanner to point at a production node.

## Running it by hand

On any Linux host with systemd as PID 1 and Docker, as root:

```sh
sudo BINARY=/path/to/tenko-<version>-linux-x86_64 bash deploy/security/round.sh
```

Settings (environment):

| Variable | Meaning |
|---|---|
| `BINARY` | The `tenko` binary under test (required). |
| `ROWS` | The groups or rows to run, space separated (`"net tls"`, `"net.tcp unit"`); empty: every row of `round.sh`. |
| `PLANT` | `listener`: the node also serves DNS over HTTPS on port 443, a listener `net.tcp` and `net.listeners` must report. This is the plan's deliberate-failure run (SA3): the planted extra listener cannot be a metrics listener on `0.0.0.0`, because the configuration accepts the metrics listener only on loopback, so DoH on 443 stands in for it. |
| `BUNDLE` | The `tar.gz` the evidence is packed into (default: a temporary file; the workflow sets it and encrypts it). |
| `KEEP` | `1`: leave the node installed and the work directory in place for hand tests. |

The scanner containers (`compose.yml`) talk to the node over a bridge network whose gateway
is the host, so they see it as another machine on the link would. Checks that need the host
(`ss`, `systemd-analyze`, `getent`) run on the host.

## The rows

One `PASS`, `FAIL` or `SKIP` line per row; a `SKIP` carries its reason. Each row also writes
one JSON line to the bundle (`rows.jsonl`): the row, the state, the duration, the tool and
version, and the paths of its raw output inside the bundle. The log of a CI run is public, so
only the row lines and counts reach it; the raw tool output, the node's journal and any crash
input go into the bundle, which the workflow encrypts with `age` before uploading.

| Row | Tool | Blocks | What it checks |
|---|---|---|---|
| `net.tcp` | nmap | yes | Only 53, 853 and 8443 (and 443 with `PLANT=listener`) are added on TCP by the install. |
| `net.udp` | nmap | yes | Only 53 is added on UDP; a port that turns `open\|filtered` fails. |
| `net.listeners` | ss (host) | yes | Every listening socket of a `tenko` process is on an expected address and port; a metrics listener, if any, only on loopback. |
| `net.cluster_port` | ss (host) | yes | 8444 is closed on a fresh node, opens when an enrolment token is created, and is closed again after the token is withdrawn and the node restarts ([`docs/cluster.md`](../../docs/cluster.md) section 7.2). A reporting sub-check: while the port is open it refuses an enrolment without a valid token. |
| `net.ipv6` | nmap | yes | The IPv6 surface is the IPv4 one (`SKIP` without IPv6 on the scan network). |
| `tls.api` | testssl.sh | yes | The API's TLS is current: TLS 1.2/1.3 only, no weak cipher, the chain verifies against the internal CA, no finding of severity Medium or above except those in `rules/testssl-allow.txt`. |
| `tls.dot` | testssl.sh | yes | The same for DoT on 853 (its certificate is the round's lab CA). |
| `tls.headers` | curl | yes | `Strict-Transport-Security` is sent; a plain-HTTP request to the TLS port is not served. |
| `unit.exposure` | systemd-analyze | yes | The installed unit's exposure level is below 2.5. |
| `unit.account` | getent (host) | yes | The service account `tenko` has a `nologin` shell, no password, no `sudo`, `cron` or `at` entry, no lingering user manager and no supplementary group. |
| `fuzz.targets` | cargo-fuzz | yes | No in-process fuzz target crashes in the release budget (`fuzz/README.md`); a crash input goes into the bundle. |
| `fuzz.dns_wire` | `dnswire.py` | yes | The running node survives malformed DNS over UDP and TCP: every probe is answered, the unit does not restart, no panic in the journal, resident memory within 20 percent of the start. |
| `web.unauth` | `nodeapi.py` | yes | Every operation of the OpenAPI document the node serves that `rules/public-operations.txt` does not name (and each `setup-only` entry of it) answers 401 or 403 without a session or a token, with a placeholder for each path parameter; the operations the document declares public are exactly the list. An operation of a module the node was installed without is not served (404 `sys.route_not_found`) and passes. |
| `web.ui_baseline` | ZAP (`zap-baseline.py`) | no, reports | The ZAP baseline scan of the web interface: a one-minute spider from the start page and the passive rules, signed in as an account with the role `viewer`, with `rules/zap-baseline.tsv`; an alert of a `FAIL` rule fails the row, every alert of a `WARN` rule is a finding of the report. |
| `web.api_baseline` | ZAP (`zap-api-scan.py -S`) | no, reports | The ZAP API scan in safe mode (the import of the node's OpenAPI document and the passive rules, no active scan) with a scoped token of the role `viewer`, the same rule file. |

"Blocks" is SA-Q1 (b) of the plan: a failing blocking row stops the release; the two ZAP rows
are listed in `SEC_REPORTING_ROWS` (`lib.sh`) and report until their rule file has been
through two releases without a new finding of High or above, then they move to blocking in
the commit that removes them from that list. The ADR 0023 invariant rows (`priv.*`, SA6) are
added by a later package.

### The web rows

`web.sh` runs last, after the other groups. At its start `nodeapi.py scan-access` creates what
the scanners use, through the API as the round's administrator: an account with the global
role `viewer` and a session of it for `web.ui_baseline`, and a scoped token of the
administrator with one grant of the role `viewer` for `web.api_baseline` (ADR 0015: `viewer`
is the narrowest role that reads the inventory; `auditor` reads only the audit log and the
system status, too little for a scan of the API). Every
request the API scan's import sends that would change something is therefore refused. At the
end of the group `nodeapi.py scan-revoke` revokes the token, ends the session, deletes the
account and checks that the token is refused. The values live in the round's private work
directory, reach the ZAP container through its environment (`ZAP_AUTH_HEADER_VALUE`, sent only
to the node's host), never its command line, and are masked as `<masked>` in every file of
the bundle before it is packed (`node/web-masking.txt` says how many files held one).

The test of `web.unauth` (SA4 of the plan) needs a build with one route's authentication
removed, which the round does not make itself. By hand, on a throwaway machine:

1. In `crates/tenko-api/src/routes/users.rs`, remove the line `Ctx(_ctx): Ctx,` from
   `list_roles` (`GET /api/v1/roles` then answers without a session).
2. Build the Linux binary (`TENKO_UI_STUB=1 cargo build --release -p tenko`) and run
   `sudo BINARY=<that binary> ROWS="web.unauth" bash deploy/security/round.sh`.
3. Expected: the round exits 1 (a blocking row failed) with this line in its log,

   ```text
   FAIL web.unauth         every operation outside the public list answers 401 or 403 without credentials
   ```

   and the row's reason in the bundle (`rows.jsonl`, `rows/web.unauth.log`) names the
   operation: `GET /api/v1/roles answered 200 (no code) without credentials`. If the route's
   `#[utoipa::path]` also gets `security()` (declared public), a second line names it:
   `declared public by the document but not in the list: GET /api/v1/roles`.

The walk itself was checked against a stand-in server that answers like the node (401 for
every operation, 404 `sys.route_not_found` for the modules that are off, one 429 first) with
`GET /api/v1/roles` answering 200: the row failed with exactly the lines above, in both
variants.

What the first dispatched run must show for the web rows: `PASS web.unauth` with the walk's
count line in `rows/web.unauth.log` reading `0 answered` (and the number of operations not
served equal to those of the DHCP and Discovery modules); both ZAP rows with a report
(`scan/zap-ui/zap-ui.json`, `scan/zap-api/zap-api.json`) and no `FAIL` rule raised, or a
finding to triage if one is; ZAP's requests carrying the scan's credential (authenticated
answers, 200, for the API's reads in `zap-api.json`, rather than 401 throughout); how many 429
answers the API scan's import met from the per-address limit (20 per second, a burst of 100);
`node/web-revoke.json` with `token_revoked` and `token_refused_after` true; and
`node/web-masking.txt` with no file removed.

## The rule files

`rules/` holds the files that turn a tool's raw output into a verdict. Change a rule only
with a reason in the file, as narrow as the tool allows.

- `rules/testssl-allow.txt`: testssl.sh finding ids the round pardons, one per line with the
  reason. Today: `BREACH` (the static web UI is Brotli-compressed but reflects no secret into
  a compressed response; the API's JSON is uncompressed) and the internal CA's missing CRL and
  OCSP (`cert_crlDistributionPoints`, `cert_ocspURL`, `cert_revocation`: the CA publishes
  neither by design, and a client pins the CA root).
- `rules/public-operations.txt`: the operations of the API that answer without a session or a
  token, `METHOD /path` as the OpenAPI document writes it, each with its reason: liveness and
  readiness, the setup flow (`GET` and `POST /setup`; the password check of the wizard is
  marked `setup-only`, since it is public only while setup is open), the sign-in steps
  (password, TOTP, recovery code, passkey), the languages of the sign-in page, node
  enrolment (the token in the body is the credential), the internal CA's root and the
  OpenAPI document; and, outside the API, the web interface's static files. `web.unauth`
  fails when the document's public operations and this list differ in either direction.
- `rules/zap-baseline.tsv`: ZAP's rule file (rule id, action, name, separated by tabs). `FAIL`
  for what the node's response headers and session cookie rule out, `WARN` for findings the
  triage reads, `IGNORE` only with the reason in the comment above it. Today's ignores:
  `10116` (ZAP is out of date: the image is pinned by digest on purpose), `10109` (the web
  interface is a single-page application by design; the alert only suggests the AJAX
  spider), and `10111`, `10112`, `10113` (informational alerts of ZAP's authentication
  helper that mark the sign-in request, the session cookie and a signed-in check, and name no
  weakness). A rule that is not listed is `WARN`, ZAP's default; every bundle carries ZAP's
  full rule list for its version (`scan/zap-ui/rules-default.tsv`).

## The report

`scripts/security-report.mjs` turns the bundle's JSON lines into the deterministic part of the
release report (`docs/security/README.md`): the layer 2 table, a finding per failed row with a
stable fingerprint, a finding per entry of a row's `findings` (the web rows: an operation that
answers without credentials, `unauth:answers:GET /api/v1/...`; a ZAP alert per plugin and path
template, `zap:10038:/api/v1/dns/zones/{id}`, with a content-hashed file of the web interface
as `index-{hash}.js`), the finding IDs carried over from the previous report, and the public
summary of SA-Q3 (b). The triage writes the judgement around it.

## The scanner images

`compose.yml` pins each scanner image by the digest of its multi-platform index, with the tag
beside it. A new version moves both the tag and the digest in one commit. Resolve a digest
with `docker buildx imagetools inspect <image>:<tag>`.
