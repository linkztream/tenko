# The lab round `security`

This directory holds the lab round `security` (layer 2 of
[`docs/plans/security-audit-plan.md`](../../docs/plans/security-audit-plan.md)): a check that
runs against the binary being released and leaves evidence with stable finding IDs. It looks
at the node from outside (the ports it answers on, its TLS, malformed traffic on the wire) and
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

| Row | Tool | What it checks |
|---|---|---|
| `net.tcp` | nmap | Only 53, 853 and 8443 (and 443 with `PLANT=listener`) are added on TCP by the install. |
| `net.udp` | nmap | Only 53 is added on UDP; a port that turns `open\|filtered` fails. |
| `net.listeners` | ss (host) | Every listening socket of a `tenko` process is on an expected address and port; a metrics listener, if any, only on loopback. |
| `net.cluster_port` | ss (host) | 8444 is closed on a fresh node, opens when an enrolment token is created, and is closed again after the token is withdrawn and the node restarts ([`docs/cluster.md`](../../docs/cluster.md) section 7.2). A reporting sub-check: while the port is open it refuses an enrolment without a valid token. |
| `net.ipv6` | nmap | The IPv6 surface is the IPv4 one (`SKIP` without IPv6 on the scan network). |
| `tls.api` | testssl.sh | The API's TLS is current: TLS 1.2/1.3 only, no weak cipher, the chain verifies against the internal CA, no finding of severity Medium or above except those in `rules/testssl-allow.txt`. |
| `tls.dot` | testssl.sh | The same for DoT on 853 (its certificate is the round's lab CA). |
| `tls.headers` | curl | `Strict-Transport-Security` is sent; a plain-HTTP request to the TLS port is not served. |
| `unit.exposure` | systemd-analyze | The installed unit's exposure level is below 2.5. |
| `unit.account` | getent (host) | The service account `tenko` has a `nologin` shell, no password, no `sudo`, `cron` or `at` entry, no lingering user manager and no supplementary group. |
| `fuzz.targets` | cargo-fuzz | No in-process fuzz target crashes in the release budget (`fuzz/README.md`); a crash input goes into the bundle. |
| `fuzz.dns_wire` | `dnswire.py` | The running node survives malformed DNS over UDP and TCP: every probe is answered, the unit does not restart, no panic in the journal, resident memory within 20 percent of the start. |

The web rows (`web.*`, SA4) and the ADR 0023 invariant rows (`priv.*`, SA6) are added by later
packages.

## The rule files

`rules/` holds the files that turn a tool's raw output into a verdict. Change a rule only
with a reason in the file, as narrow as the tool allows.

- `rules/testssl-allow.txt`: testssl.sh finding ids the round pardons, one per line with the
  reason. Today: `BREACH` (the static web UI is Brotli-compressed but reflects no secret into
  a compressed response; the API's JSON is uncompressed) and the internal CA's missing CRL and
  OCSP (`cert_crlDistributionPoints`, `cert_ocspURL`, `cert_revocation`: the CA publishes
  neither by design, and a client pins the CA root).

## The report

`scripts/security-report.mjs` turns the bundle's JSON lines into the deterministic part of the
release report (`docs/security/README.md`): the layer 2 table, a finding per failed row with a
stable fingerprint, the finding IDs carried over from the previous report, and the public
summary of SA-Q3 (b). The triage writes the judgement around it.

## The scanner images

`compose.yml` pins each scanner image by the digest of its multi-platform index, with the tag
beside it. A new version moves both the tag and the digest in one commit. Resolve a digest
with `docker buildx imagetools inspect <image>:<tag>`.
