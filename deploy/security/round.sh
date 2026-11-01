#!/usr/bin/env bash
# The lab round `security` (layer 2 of docs/plans/security-audit-plan.md): it installs the
# node under test from the binary given, as a user installs it, completes first-run setup
# through the API under the Standard profile, then runs the row groups net, tls and unit of
# section 4.2 against it, the fuzz group (deploy/security/fuzz.sh) and, last, the web group
# (deploy/security/web.sh), and packs the evidence into a bundle.
#
# Run by hand on any Linux host with systemd and Docker, as root:
#   sudo BINARY=<path to the tenko binary> bash deploy/security/round.sh
#   sudo BINARY=<path> ROWS="net tls" bash deploy/security/round.sh   # one or more groups
#   sudo BINARY=<path> ROWS="web" bash deploy/security/round.sh       # the web rows only
#   sudo BINARY=<path> SOURCE=<checkout of the binary's tag> bash deploy/security/round.sh
#                                                                     # a binary built from another
#                                                                     # commit: that source's fuzz
#                                                                     # targets run (default: this checkout)
#   sudo BINARY=<path> PLANT=listener bash deploy/security/round.sh   # DoH on 443, a planted
#                                                                     # extra listener
#
# Settings (environment):
#   BINARY    the tenko binary under test (required)
#   ROWS      the groups or rows to run, space separated; empty: every row of this script
#   PLANT     "listener": the node also serves DoH on 443, which net.tcp and net.listeners
#             must report (the plan's SA3 deliberate-failure run)
#   BUNDLE    the tar.gz the evidence is packed into (default: a file in a temporary dir;
#             the workflow sets it so the job can encrypt and upload it)
#   KEEP      1: leave the node installed and the work directory in place (hand tests)
#   SEC_PUBLIC_REASONS  1: print each FAIL row's reason sentence after its line (rehearsals
#                     against a throwaway node; the workflow's `reasons` input)
#   SEC_SKIP_INSTALL  1: do not install; test a node round.sh installed in a previous run
#                     with KEEP=1 (the work directory is reused). For development.
#
# The scanners run in containers (deploy/security/compose.yml) on a bridge network whose
# gateway is the host (nmap, testssl.sh and ZAP alike), so they reach the node as another
# machine on the link would. Checks that need the host (ss, systemd-analyze, getent) and the
# API client of the web rows (nodeapi.py) run on the host. The log carries only the
# row lines and counts (it is public on a public repository, section 4.6); the raw scanner
# output and the node's journal go into the bundle, which the caller encrypts.

set -Eeuo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

: "${BINARY:?set BINARY to the tenko binary under test}"
BINARY="$(readlink -f "$BINARY")"
[[ -x "$BINARY" ]] || { echo "round: BINARY is not an executable file: $BINARY" >&2; exit 2; }

[[ "$(id -u)" == 0 ]] || { echo "round: run as root (install.sh, ss and systemd-analyze need it)" >&2; exit 2; }

plant="${PLANT:-}"
keep="${KEEP:-0}"

# The private work directory (the setup token, the API session, the lab CA key) and the
# evidence bundle directory. WORK is never in the bundle.
WORK="$(mktemp -d /tmp/tenko-sec-work.XXXXXX)"
export WORK
EVIDENCE="$(mktemp -d /tmp/tenko-sec-evidence.XXXXXX)"
export EVIDENCE
BUNDLE="${BUNDLE:-$(mktemp -u /tmp/tenko-sec-bundle.XXXXXX.tar.gz)}"

# shellcheck source=deploy/security/lib.sh
. "$here/lib.sh"

# The node under test: the API on 8443, DNS on 53, DoT on 853; addresses in node.env.
API_URL="" API_CA="" API_STATE="" DATA_DIR=""
# The host's address on the scan network, which the scanners aim at. The compose network's
# gateway is the host (deploy/security/compose.yml); on the runner that is this address.
SCAN_TARGET=tenko.example.test
SCAN_IP6=""

# The round's own standard output and error, kept on spare descriptors: a check runs with
# its output redirected into its row's log, and when it ends the shell (an unbound variable
# under `set -u`, a failed command outside a row) the exit path must still reach the log.
exec {round_stdout}>&1 {round_stderr}>&2
# 1 once main() has packed the bundle; until then the exit path packs it.
round_packed=0

# round_stopped <line>: the ERR trap. It runs where `set -e` is about to end the round and
# prints the position only (the function and the line, never the command or a value), to
# the round's standard output so the public log shows where the round stopped. A failure
# inside a command substitution or another subshell does not end the round and is not
# reported.
round_stopped() {
  ((BASH_SUBSHELL == 0)) || return 0
  printf 'round: stopped in %s, line %s\n' "${FUNCNAME[1]:-round.sh}" "$1" >&"$round_stdout"
}
trap 'round_stopped "$LINENO"' ERR

# round_finish_early <status>: the exit path of a round that ends before main() packed the
# bundle. It records the row that was running as failed, prints the tally, and packs the
# bundle so the workflow still encrypts and uploads it; the exit status stays non-zero.
round_finish_early() {
  echo "round: stopped with status $1 before the end of the round"
  row_abort "$1"
  echo
  rows_tally
  mkdir -p "$EVIDENCE/node"
  journalctl -u tenko --no-pager >"$EVIDENCE/node/journal.txt" 2>&1 || true
  if declare -F web_mask_evidence >/dev/null; then web_mask_evidence; fi
  if bundle_pack "$BUNDLE"; then
    echo "round: evidence packed into $BUNDLE"
  fi
}

cleanup() {
  local status=$?
  set +e
  trap - ERR
  exec 1>&"$round_stdout" 2>&"$round_stderr"
  if ((round_packed == 0)) && [[ -d "$EVIDENCE" ]]; then
    ((status != 0)) || status=1
    round_finish_early "$status"
  fi
  if [[ "$keep" != 1 ]]; then
    SEC_OUT="$EVIDENCE/scan" SEC_IN="$WORK/in" \
      docker compose -f "$here/compose.yml" down --remove-orphans >/dev/null 2>&1 || true
    if [[ "${SEC_SKIP_INSTALL:-0}" != 1 ]]; then
      bash "$repo/deploy/install.sh" --yes --uninstall --purge >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
  else
    echo "round: KEEP=1, the node and $WORK are left in place" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

api() { python3 -I "$here/nodeapi.py" --state "$API_STATE" "$@"; }

# ── Install and set the node up ───────────────────────────────────────────────────────────
install_node() {
  if [[ "${SEC_SKIP_INSTALL:-0}" == 1 && -f "$WORK/node.env" ]]; then
    echo "round: SEC_SKIP_INSTALL=1, reusing the installed node"
  else
    BINARY="$BINARY" WORK="$WORK" EVIDENCE="$EVIDENCE" PLANT="$plant" \
      bash "$here/install-node.sh"
  fi
  # shellcheck source=/dev/null
  . "$WORK/node.env"
}

# Scanners read the CA files from WORK/in; compose mounts it read-only at /in.
compose_run() {
  SEC_OUT="$EVIDENCE/scan" SEC_IN="$WORK/in" \
    docker compose -f "$here/compose.yml" run --rm --no-TTY "$@"
}

# ── net.* : the network surface as a scanner on the link sees it ────────────────────────────
# Scans run against the host address the compose gateway gives, before and after the install,
# so the rows attribute the ports the install added.

nmap_scan() {
  # nmap_scan <tag> <nmap args...>: writes scan/<tag>.xml and scan/<tag>.nmap, returns the
  # open ports (proto/port) on standard output.
  local tag="$1"; shift
  mkdir -p "$EVIDENCE/scan"
  compose_run nmap -oX "/out/${tag}.xml" -oN "/out/${tag}.nmap" "$@" "${NMAP_TARGET:-$SCAN_TARGET}" >/dev/null 2>&1 || true
  # The open ports from the XML, as proto/port lines.
  python3 -I - "$EVIDENCE/scan/${tag}.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(0)
for port in root.iter("port"):
    state = port.find("state")
    if state is not None and state.get("state") == "open":
        print(f"{port.get('protocol')}/{port.get('portid')}")
PY
}

# The ports the install is expected to add on the scan network: the API (8443), DoT (853),
# DNS (53/tcp). DoH on 443 is added only with PLANT=listener (and must then show as a
# finding). DNS on 53/udp is a net.udp matter.
expected_tcp() {
  printf 'tcp/53\ntcp/853\ntcp/8443\n'
  if [[ "$plant" == listener ]]; then printf 'tcp/443\n'; fi
}

# The baseline, captured before the install so the net rows attribute only the ports the
# install added. Filled by baseline_capture() in main(), before install_node(). A host has
# listeners of its own on IPv6 as on IPv4 (sshd on ::, a CI runner's agent, Docker), so
# net.ipv6 gets a baseline too when the scan network has IPv6; BEFORE_TCP6_OK says whether
# that scan completed.
BEFORE_TCP="" BEFORE_UDP="" BEFORE_TCP6="" BEFORE_TCP6_OK=0
# The TCP ports net.tcp saw the install add, for net.ipv6 (empty until net.tcp ran).
ADDED_TCP=""

# scan_ip6: the host's IPv6 address on the scan network (its gateway), empty without IPv6.
# The network exists once a scanner has run on it.
scan_ip6() {
  docker network inspect tenkosec_scan --format '{{range .IPAM.Config}}{{.Gateway}} {{end}}' 2>/dev/null |
    tr ' ' '\n' | grep ':' | head -n 1 || true
}

# nmap_completed <tag>: the scan wrote its XML and ran to its end.
nmap_completed() { grep -qs '<finished ' "$EVIDENCE/scan/$1.xml"; }

baseline_capture() {
  mkdir -p "$WORK/in" "$EVIDENCE/scan"
  echo "round: baseline scan of the host before the install"
  BEFORE_TCP="$(nmap_scan tcp-before -sT -p- --open -Pn 2>/dev/null)"
  BEFORE_UDP="$(nmap_scan udp-before -sU --top-ports 1000 -p U:53,67,68,123,161,547,5353,9464 --open -Pn 2>/dev/null)"
  SCAN_IP6="$(scan_ip6)"
  if [[ -n "$SCAN_IP6" ]] && wanted net.ipv6; then
    BEFORE_TCP6="$(NMAP_TARGET="$SCAN_IP6" nmap_scan tcp6-before -6 -sT -p- --open -Pn 2>/dev/null)"
    if nmap_completed tcp6-before; then BEFORE_TCP6_OK=1; fi
  fi
}

row_net_tcp() {
  row_tool=nmap
  row_version="$(compose_run nmap --version 2>/dev/null | head -n 1)"
  local before after added expected unexpected
  before="$BEFORE_TCP"
  evidence_add scan/tcp-before.nmap scan/tcp-before.xml
  after="$(nmap_scan tcp-after -sT -p- --open -Pn)"
  evidence_add scan/tcp-after.nmap scan/tcp-after.xml
  added="$(comm -13 <(printf '%s\n' "$before" | sort -u) <(printf '%s\n' "$after" | sort -u))"
  ADDED_TCP="$added"
  expected="$(expected_tcp | sort -u)"
  unexpected="$(comm -23 <(printf '%s\n' "$added" | grep -v '^$' | sort -u) <(printf '%s\n' "$expected"))"
  {
    echo "ports before the install:"; printf '%s\n' "$before"
    echo "ports after the install:"; printf '%s\n' "$after"
    echo "added by the install:"; printf '%s\n' "$added"
    echo "expected to be added:"; printf '%s\n' "$expected"
  } >>"$EVIDENCE/rows/net.tcp.log"
  if [[ -n "$unexpected" ]]; then
    row_reason="the install opened TCP ports beyond {53,853,8443}: $(echo "$unexpected" | tr '\n' ' ')"
    return 1
  fi
  # Every expected port that is a plain part of the install must be present (443 only with
  # the plant). The net.listeners row attributes each; here the count is enough.
  local missing
  missing="$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$added" | grep -v '^$' | sort -u))"
  if [[ -n "$missing" ]]; then
    row_reason="the install did not open the expected TCP ports: $(echo "$missing" | tr '\n' ' ')"
    return 1
  fi
}

row_net_udp() {
  row_tool=nmap
  row_version="$(compose_run nmap --version 2>/dev/null | head -n 1)"
  # The 1000 most common UDP ports plus the ones a DDI node might touch. A port that turns
  # open|filtered after the install fails the row, since Linux answers a closed UDP port
  # with an ICMP unreachable; only 53 should be open.
  local extra=53,67,68,123,161,547,5353,9464 before after added
  before="$BEFORE_UDP"
  evidence_add scan/udp-before.nmap scan/udp-before.xml
  after="$(nmap_scan udp-after -sU --top-ports 1000 -p "U:${extra}" --open -Pn)"
  evidence_add scan/udp-after.nmap scan/udp-after.xml
  added="$(comm -13 <(printf '%s\n' "$before" | sort -u) <(printf '%s\n' "$after" | sort -u) | grep -v '^$')"
  {
    echo "UDP open|filtered after the install:"; printf '%s\n' "$after"
    echo "added by the install:"; printf '%s\n' "$added"
  } >>"$EVIDENCE/rows/net.udp.log"
  if [[ "$(printf '%s\n' "$added" | sort -u)" != "udp/53" ]]; then
    row_reason="the install added UDP ports other than 53: $(echo "$added" | tr '\n' ' ')"
    return 1
  fi
}

row_net_listeners() {
  # ss as root on the host, every listening socket of the unit's processes attributed to its
  # port; the metrics listener, when present, only on loopback.
  row_tool=ss
  row_version="$(ss --version 2>/dev/null | head -n 1)"
  local pids sockets
  pids="$(systemctl show -p MainPID --value tenko 2>/dev/null)"
  ss -tulpnH >"$EVIDENCE/node/ss-all.txt" 2>&1 || true
  evidence_add node/ss-all.txt
  # The sockets of the cgroup of the unit: match the process name tenko.
  sockets="$(ss -tulpnH 2>/dev/null | grep -F 'users:(("tenko' || true)"
  printf '%s\n' "$sockets" >>"$EVIDENCE/rows/net.listeners.log"
  if [[ -z "$sockets" ]]; then
    row_reason="no listening socket of a tenko process was found (MainPID $pids)"
    return 1
  fi
  local bad="" line local_addr
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    # The local address is the fifth field of ss -H output.
    local_addr="$(awk '{print $5}' <<<"$line")"
    local port="${local_addr##*:}" host="${local_addr%:*}"
    case "$port" in
      53 | 853 | 8443 | 8444) ;;
      443)
        [[ "$plant" == listener ]] || bad+="unexpected listener on 443: $local_addr"$'\n'
        ;;
      9464)
        # The metrics listener must be on loopback only (section 4.2).
        case "$host" in 127.0.0.1 | "[::1]" | "::1") ;; *) bad+="metrics listener not on loopback: $local_addr"$'\n' ;; esac
        ;;
      *) bad+="listener on an unexpected port: $local_addr"$'\n' ;;
    esac
  done <<<"$sockets"
  if [[ "$plant" == listener ]]; then
    # The plant is a reported finding, not a silent pass: DoH on 443 must be present.
    grep -q ':443 ' <<<"$sockets" || grep -q ':443$' <<<"$sockets" ||
      { row_reason="PLANT=listener but no DoH listener on 443 was found"; return 1; }
  fi
  if [[ -n "$bad" ]]; then
    row_reason="$(echo "$bad" | tr '\n' ';')"
    return 1
  fi
}

row_net_cluster_port() {
  # docs/cluster.md 7.2: with [cluster] listen unset the port opens on demand and, after a
  # restart with no token waiting and no node enrolled, is closed again. The on-demand
  # listener is not closed when the token is withdrawn (SF-0001 of the report); this row
  # checks the documented state (closed after a restart), and a reporting sub-check that the
  # open listener refuses enrolment without a valid token.
  row_tool=ss
  local id state
  # Closed on a fresh node (no token, no enrolment).
  if cluster_port_open; then
    row_reason="8444 is open on a fresh node with no enrolment token waiting"
    return 1
  fi
  # A token opens it.
  api post /nodes/enrolments '{"roles": ["probe"], "expires_in_secs": 300}' >"$WORK/enrol.json" 2>>"$EVIDENCE/rows/net.cluster_port.log" ||
    { row_reason="an enrolment token could not be created"; return 1; }
  id="$(jq -r '.enrolment.id' "$WORK/enrol.json")"
  sleep 2
  if ! cluster_port_open; then
    row_reason="8444 did not open after an enrolment token was created"
    return 1
  fi
  # The reporting sub-check: while the port is open, an enrolment attempt without a valid
  # token is refused (recorded in the log; it does not block, SF-0001 holds the blocking
  # concern about the port staying open).
  cluster_refuses_without_token >>"$EVIDENCE/rows/net.cluster_port.log" 2>&1 &&
    echo "sub-check: the open cluster port refuses enrolment without a valid token (PASS, reporting)" >>"$EVIDENCE/rows/net.cluster_port.log" ||
    echo "sub-check: the open cluster port did NOT refuse an unauthenticated probe (reporting)" >>"$EVIDENCE/rows/net.cluster_port.log"
  # Withdraw the token and restart; the documented state is that 8444 is then closed.
  api delete "/nodes/enrolments/$id" >/dev/null 2>>"$EVIDENCE/rows/net.cluster_port.log" || true
  systemctl restart tenko >>"$EVIDENCE/rows/net.cluster_port.log" 2>&1
  wait_api_ready
  sleep 2
  if cluster_port_open; then
    row_reason="8444 is still open after the token was withdrawn and the node restarted (docs/cluster.md 7.2 says it should be closed); see SF-0001"
    return 1
  fi
  evidence_add node/ss-all.txt
}

cluster_port_open() {
  ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE '(:|\])8444$'
}

cluster_refuses_without_token() {
  # A gRPC enrolment without a token cannot succeed; a plain TLS probe of 8444 that gets no
  # certificate it trusts is enough to show the port does not hand anything out. Use openssl
  # to show the handshake needs the internal CA and a client certificate.
  local host="${API_URL#https://}"; host="${host%%:*}"
  echo | timeout 5 openssl s_client -connect "127.0.0.1:8444" -servername "$host" 2>&1 |
    grep -qiE 'verify error|unable to get local issuer|handshake failure|tlsv1|certificate required|no peer certificate'
}

wait_api_ready() {
  for _ in $(seq 1 60); do
    "$BINARY" health --url "https://localhost:8443" --ca-file "$DATA_DIR/tls/ca-root.pem" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

row_net_ipv6() {
  # net.tcp against the host's IPv6 address on the scan network, with the same baseline
  # treatment: the TCP ports the install added on IPv6 must be among those it added on IPv4
  # (net.tcp's, or the expected set when net.tcp did not run). A port the host had open on
  # IPv6 before the install is not the node's. SKIP without IPv6 on the scan network or
  # without a completed baseline scan.
  row_tool=nmap
  if [[ -z "$SCAN_IP6" ]]; then
    row_skip="no IPv6 address on the scan network"
    return 0
  fi
  if [[ "$BEFORE_TCP6_OK" != 1 ]]; then
    row_skip="the IPv6 baseline scan before the install did not complete"
    return 0
  fi
  local after added added4 unexpected missing
  evidence_add scan/tcp6-before.nmap scan/tcp6-before.xml
  after="$(NMAP_TARGET="$SCAN_IP6" nmap_scan tcp6-after -6 -sT -p- --open -Pn)"
  evidence_add scan/tcp6-after.nmap scan/tcp6-after.xml
  if ! nmap_completed tcp6-after; then
    row_reason="the IPv6 scan after the install did not complete"
    return 1
  fi
  added="$(comm -13 <(printf '%s\n' "$BEFORE_TCP6" | sort -u) <(printf '%s\n' "$after" | sort -u) | grep -v '^$' || true)"
  if [[ -n "$ADDED_TCP" ]]; then
    added4="$(printf '%s\n' "$ADDED_TCP" | grep -v '^$' | sort -u)"
  else
    added4="$(expected_tcp | sort -u)"
  fi
  unexpected="$(comm -23 <(printf '%s\n' "$added" | sort -u) <(printf '%s\n' "$added4"))"
  missing="$(comm -13 <(printf '%s\n' "$added" | sort -u) <(printf '%s\n' "$added4"))"
  {
    echo "IPv6 ports before the install:"; printf '%s\n' "$BEFORE_TCP6"
    echo "IPv6 ports after the install:"; printf '%s\n' "$after"
    echo "added on IPv6 by the install:"; printf '%s\n' "$added"
    echo "added on IPv4 by the install (the reference):"; printf '%s\n' "$added4"
    echo "added on IPv4 but not on IPv6 (not a failure: the node may listen on IPv4 only):"
    printf '%s\n' "$missing"
  } >>"$EVIDENCE/rows/net.ipv6.log"
  if [[ -n "$unexpected" ]]; then
    row_reason="the install added TCP ports on IPv6 beyond those it added on IPv4: $(echo "$unexpected" | tr '\n' ' ')"
    return 1
  fi
}

# ── tls.* : the transport security of the API and DoT ───────────────────────────────────────
testssl_run() {
  # testssl_run <tag> <host:port> [extra args...]: runs testssl.sh with the run's CA added,
  # writes scan/<tag>.json, returns its path on standard output.
  local tag="$1" target="$2"; shift 2
  # The image runs as its own unprivileged user, which cannot write to /out (the bundle's
  # scan/, root's): it writes into scan/testssl-<tag>/, writable for it during the scan only,
  # and the JSON is moved into scan/ afterwards. Its console output goes to the row's log.
  local dir="$EVIDENCE/scan/testssl-$tag"
  install -d -m 0777 "$dir"
  compose_run testssl \
    --jsonfile "/out/testssl-${tag}/${tag}.json" --add-ca /in/ca-root.pem --warnings batch --quiet \
    --severity MEDIUM "$@" "$target" >>"$EVIDENCE/rows/${tag}.log" 2>&1 || true
  if [[ -f "$dir/$tag.json" ]]; then
    install -m 0644 "$dir/$tag.json" "$EVIDENCE/scan/$tag.json"
  fi
  rm -rf "$dir"
  echo "$EVIDENCE/scan/${tag}.json"
}

# testssl_findings <json file>: every finding of severity MEDIUM or above that the allow
# list does not pardon, one `id severity` per line. The allow list (rules/testssl-allow.txt)
# names ids to ignore, one per line, '#' comments.
testssl_findings() {
  local json="$1" allow="$here/rules/testssl-allow.txt"
  python3 -I - "$json" "$allow" <<'PY'
import json, sys
# FATAL is testssl.sh's "the scan could not be done" (scanProblem): no verdict, so a failure.
order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "FATAL": 4}
allow = set()
try:
    with open(sys.argv[2], encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                allow.add(line)
except FileNotFoundError:
    pass
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        doc = json.load(f)
except Exception:
    print("NO_JSON scan produced no JSON")
    sys.exit(0)
findings = doc if isinstance(doc, list) else doc.get("scanResult", [])
def walk(items):
    for it in items:
        sev = (it.get("severity") or "").upper()
        fid = it.get("id", "?")
        if order.get(sev, 0) >= 2 and fid not in allow:
            print(f"{fid} {sev}")
if findings and isinstance(findings[0], dict) and "severity" in findings[0]:
    walk(findings)
else:
    for host in findings:
        for key in ("protocols", "ciphers", "serverDefaults", "vulnerabilities", "fs", "cert", "cert_chain"):
            walk(host.get(key, []) if isinstance(host, dict) else [])
        if isinstance(host, dict):
            walk([v for v in host.values() if isinstance(v, dict) and "severity" in v])
PY
}

row_tls_api() {
  row_tool=testssl.sh
  local json bad
  json="$(testssl_run tls.api "${API_URL#https://}")"
  evidence_add scan/tls.api.json
  bad="$(testssl_findings "$json")"
  printf 'findings MEDIUM or above, allow list applied:\n%s\n' "${bad:-none}" >>"$EVIDENCE/rows/tls.api.log"
  if [[ -n "$bad" ]]; then
    row_reason="the API's TLS has findings the allow list does not pardon: $(echo "$bad" | tr '\n' ';')"
    return 1
  fi
}

row_tls_dot() {
  row_tool=testssl.sh
  local host json bad
  host="${API_URL#https://}"; host="${host%%:*}"
  # DoT is TLS directly on 853 (no STARTTLS); the lab CA issued its certificate.
  json="$(testssl_run tls.dot "${host}:853" --add-ca /in/lab-ca.pem)"
  evidence_add scan/tls.dot.json
  bad="$(testssl_findings "$json")"
  printf 'findings MEDIUM or above, allow list applied:\n%s\n' "${bad:-none}" >>"$EVIDENCE/rows/tls.dot.log"
  if [[ -n "$bad" ]]; then
    row_reason="DoT's TLS has findings the allow list does not pardon: $(echo "$bad" | tr '\n' ';')"
    return 1
  fi
}

row_tls_headers() {
  # curl -sI against /: Strict-Transport-Security present (the Standard profile sets hsts),
  # and no plain-HTTP listener answers on 8443.
  row_tool=curl
  row_version="$(curl --version 2>/dev/null | head -n 1)"
  local host headers
  host="${API_URL#https://}"; host="${host%%:*}"
  headers="$(curl -sSI --cacert "$API_CA" --resolve "${API_URL#https://}:127.0.0.1" "$API_URL/" 2>>"$EVIDENCE/rows/tls.headers.log" | tr -d '\r')"
  printf '%s\n' "$headers" >>"$EVIDENCE/rows/tls.headers.log"
  if ! grep -qi '^strict-transport-security:' <<<"$headers"; then
    row_reason="no Strict-Transport-Security header on an HTTPS answer"
    return 1
  fi
  # A plain HTTP request to the TLS port must not be served as HTTP (the listener answers a
  # TLS alert, not an HTTP response).
  # The same name mapping as above, so the request reaches the node rather than failing to
  # resolve (which would also read 000). curl prints 000 itself when no HTTP answer came, and
  # exits non-zero then; its exit status goes to the log.
  local plain curl_rc=0
  plain="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' --resolve "${API_URL#https://}:127.0.0.1" \
    "http://${API_URL#https://}/" 2>/dev/null)" || curl_rc=$?
  [[ -n "$plain" ]] || plain=000
  echo "plain HTTP to the TLS port returned status: $plain (curl exit status $curl_rc)" >>"$EVIDENCE/rows/tls.headers.log"
  if ((curl_rc == 6 || curl_rc == 7)); then
    row_reason="the plain-HTTP probe did not reach the API port (curl exit status $curl_rc)"
    return 1
  fi
  if [[ "$plain" != 000 && "$plain" != 400 ]]; then
    row_reason="a plain-HTTP request to the TLS port was answered (status $plain)"
    return 1
  fi
}

# ── unit.* : the installed systemd unit and the service account ─────────────────────────────
row_unit_exposure() {
  row_tool=systemd-analyze
  row_version="$(systemd-analyze --version 2>/dev/null | head -n 1)"
  local score value
  systemctl daemon-reload
  systemd-analyze security --no-pager tenko.service >"$EVIDENCE/node/exposure.txt" 2>&1 || true
  evidence_add node/exposure.txt
  score="$(grep 'Overall exposure level' "$EVIDENCE/node/exposure.txt" || true)"
  if [[ -z "$score" ]]; then
    row_reason="systemd-analyze security printed no overall exposure level"
    return 1
  fi
  value="$(sed -E 's/.*:[^0-9]*([0-9]+\.[0-9]+).*/\1/' <<<"$score")"
  echo "$score" >>"$EVIDENCE/rows/unit.exposure.log"
  if ! awk -v v="$value" 'BEGIN{exit !(v < 2.5)}'; then
    row_reason="the exposure level is $value, the gate is below 2.5"
    return 1
  fi
}

row_unit_account() {
  # getent passwd tenko: nologin shell, no password; no sudo rule, cron or at entry; no
  # lingering user manager.
  row_tool=getent
  local pw shell problems=""
  pw="$(getent passwd tenko || true)"
  echo "passwd: $pw" >>"$EVIDENCE/rows/unit.account.log"
  [[ -n "$pw" ]] || { row_reason="the service account tenko does not exist"; return 1; }
  shell="${pw##*:}"
  case "$shell" in */nologin | */false) ;; *) problems+="login shell is $shell; " ;; esac
  # A password hash other than ! or * in /etc/shadow is a set password.
  local hash
  hash="$(getent shadow tenko 2>/dev/null | cut -d: -f2 || true)"
  case "$hash" in "" | "!" | "*" | "!!") ;; *) problems+="the account has a password hash; " ;; esac
  # No sudo rule.
  if (sudo -nl -U tenko 2>/dev/null | grep -qvE 'not allowed|may not run'); then
    sudo -nl -U tenko 2>&1 | tee -a "$EVIDENCE/rows/unit.account.log" >/dev/null || true
    grep -rqs tenko /etc/sudoers /etc/sudoers.d 2>/dev/null && problems+="a sudoers entry names tenko; "
  fi
  # No cron or at entry.
  { crontab -l -u tenko 2>/dev/null | grep -q . && problems+="a crontab exists for tenko; "; } || true
  grep -rqs '^tenko$' /var/spool/cron/atjobs 2>/dev/null && problems+="an at job for tenko; "
  # No lingering user manager (loginctl show-user tenko Linger=yes).
  if loginctl show-user tenko 2>/dev/null | grep -q 'Linger=yes'; then
    problems+="the user manager lingers; "
  fi
  # No supplementary group.
  local groups
  groups="$(id -Gn tenko 2>/dev/null || true)"
  [[ "$groups" == tenko || -z "$groups" ]] || problems+="supplementary groups: $groups; "
  echo "checks: ${problems:-all passed}" >>"$EVIDENCE/rows/unit.account.log"
  if [[ -n "$problems" ]]; then
    row_reason="$problems"
    return 1
  fi
}

# ── Run ─────────────────────────────────────────────────────────────────────────────────────
main() {
  echo "round: binary under test $("$BINARY" --version 2>/dev/null || echo "$BINARY")"
  echo "round: bundle $BUNDLE, groups ${ROWS:-all}"
  # The net rows compare the ports before and after the install, so the baseline scan runs
  # first, while nothing of the node is up (systemd-resolved's stub is on 127.0.0.53, not on
  # the scan address, so it is not attributed to the install).
  if wanted net.tcp || wanted net.udp || wanted net.ipv6; then
    baseline_capture
  fi
  install_node

  # The scan target's IPv6 address, if the scan network has one (baseline_capture sets it
  # when the net rows run).
  [[ -n "$SCAN_IP6" ]] || SCAN_IP6="$(scan_ip6)"

  row net.tcp "only 53, 853 and 8443 were added on TCP" row_net_tcp
  row net.udp "only 53 was added on UDP" row_net_udp
  row net.listeners "every tenko listener is on an expected address and port" row_net_listeners
  row net.cluster_port "8444 is closed after a restart with no token waiting (docs/cluster.md 7.2)" row_net_cluster_port
  row net.ipv6 "the IPv6 surface is the IPv4 one" row_net_ipv6

  row tls.api "the API's TLS is current (TLS 1.2/1.3, no weak cipher, chain verifies)" row_tls_api
  row tls.dot "DoT's TLS is current" row_tls_dot
  row tls.headers "the API sends the transport headers the profile asks for" row_tls_headers

  row unit.exposure "the installed unit keeps its exposure score below 2.5" row_unit_exposure
  row unit.account "the service account is what ADR 0023 says" row_unit_account

  # SA5: the fuzz rows, when selected. fuzz.sh is sourced so it shares the row helper, the
  # bundle and the node under test.
  if wanted fuzz.targets || wanted fuzz.dns_wire || [[ " ${ROWS:-} " == *" fuzz "* ]]; then
    # shellcheck source=deploy/security/fuzz.sh
    . "$here/fuzz.sh"
    run_fuzz_rows
  fi

  # SA4: the web rows, after the other groups. web.sh is sourced like fuzz.sh; it creates
  # the scanners' viewer session and token at its start and revokes them at its end.
  local web=0
  # shellcheck source=deploy/security/web.sh
  . "$here/web.sh"
  if web_wanted; then
    web=1
    run_web_rows
  fi

  echo
  rows_tally
  # The node's journal goes into the bundle (not the public log).
  journalctl -u tenko --no-pager >"$EVIDENCE/node/journal.txt" 2>&1 || true
  # The scan secrets are masked once more, now that the journal is in the bundle too.
  ((web == 0)) || web_mask_evidence

  bundle_pack "$BUNDLE"
  round_packed=1
  echo "round: evidence packed into $BUNDLE"
  if ((rows_blocking_failed > 0)); then
    echo "round: $rows_blocking_failed blocking row(s) failed" >&2
    exit 1
  fi
}

main "$@"
