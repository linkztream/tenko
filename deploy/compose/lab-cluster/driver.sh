#!/usr/bin/env bash
# The cluster lab's steps, run from inside the lab network: smoke.sh (on the host) starts the
# driver container (the service `client`, deploy/compose/driver) and runs this script in it
# with driver/host.sh lab_run. smoke.sh's header lists the steps and the settings; this
# script talks to HAProxy and the controllers on the lab network (curl), writes the files of
# the run into the lab volume (/work), and asks the host with ctl (driver/ctl.sh) for every
# container operation: starting and killing services, their health, the setup token, the
# command lines inside the controllers and probes, the partition.
#
# The environment smoke.sh passes: LAB_PORT, RATE, SECONDS_UNDER_LOAD, WAIT_SECS, KEEP,
# TENKO_IMAGE (for the summary).

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/compose/driver/ctl.sh
source "$here/../driver/ctl.sh"

lab_port="${LAB_PORT:-28443}"
rate="${RATE:-100}"
seconds_under_load="${SECONDS_UNDER_LOAD:-30}"
wait_secs="${WAIT_SECS:-300}"
keep="${KEEP:-0}"
# The address a browser on the host uses (HAProxy published on its loopback); the driver
# reaches the same HAProxy on the lab network, with the same name, port and origin (curl
# below).
url="https://localhost:$lab_port"
inner_url="https://haproxy:8443"
tenko_bin=/usr/local/bin/tenko
admin=lab-admin
resume_limit=15
# The load's addresses are spread over this many /64 prefixes.
prefixes=20

# The lab volume.
work=/work
status=0
summary=()

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'smoke: %s\n' "$*" >&2; exit 1; }
ok() {
  local line
  line="$(printf 'ok  %-34s %s' "$1" "$2")"
  summary+=("$line")
  printf '%s\n' "$line"
}
# curl: every request for $url goes to HAProxy's address on the lab network.
curl() { command curl --connect-to "localhost:$lab_port:haproxy:8443" "$@"; }

# retry <seconds> <description> <command...>: runs the command every 2 seconds until it
# succeeds or the time is up.
retry() {
  local limit="$1" what="$2" waited=0
  shift 2
  until "$@" >/dev/null 2>&1; do
    if ((waited >= limit)); then
      fail "timed out after ${limit}s waiting for: $what"
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

# At the end, also after a failure: the summary lines to the host, which prints them after
# the services' logs.
cleanup() {
  status=$?
  set +e
  trap - EXIT
  wait
  local line
  for line in "${summary[@]}"; do
    lab_summary "$line"
  done
  exit "$status"
}
trap cleanup EXIT

ok "image" "$TENKO_IMAGE"

step "generate the lab certificate and the key-encryption keys"
mkdir -p "$work/tls" "$work/public"
(
  cd "$work/tls"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=Tenko lab CA" -keyout ca.key -out ca.pem \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
  printf '%s\n' \
    "subjectAltName=DNS:localhost,DNS:haproxy,DNS:tenko.example.test,IP:127.0.0.1" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" >server.ext
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile server.ext -out server.pem 2>/dev/null
  cat server.pem ca.pem server.key >haproxy.pem
  rm -f ca.key server.csr server.ext ca.srl
  # The containers' users (65532 for tenko, 99 for haproxy) are not the owner (the
  # driver's root writes the volume).
  chmod 0444 ca.pem haproxy.pem
  chmod 0400 server.key
)
# The lab CA alone for the controllers and probes (/lab/ca.pem); HAProxy mounts tls/.
cp "$work/tls/ca.pem" "$work/public/ca.pem"
chmod 0444 "$work/public/ca.pem"
# One key-encryption key per controller, each in a directory of its own that only that
# controller mounts (/run/secrets/kek_N).
for n in 1 2 3; do
  mkdir -p "$work/kek-$n"
  head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/kek-$n/kek_$n"
  chmod 0444 "$work/kek-$n/kek_$n"
  chmod 0755 "$work/kek-$n"
done
chmod 0755 "$work" "$work/tls" "$work/public"
ca="$work/tls/ca.pem"
jar="$work/cookies"
ok "certificate" "lab CA and HAProxy certificate for localhost and haproxy"

# api <method> <path> [json body]: one request through HAProxy with the session in the
# cookie jar; prints the body and fails on a status of 400 or more.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS --fail-with-body --max-time 30 --cacert "$ca" -b "$jar" -X "$method"
    -H "Origin: $url" -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid)")
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: application/json" --data "$body")
  fi
  curl "${args[@]}" "$url/api/v1$path"
}

# json <python expression over j>: evaluates the expression on the JSON of standard input.
json() { python3 -c "import json,sys; j=json.load(sys.stdin); print($1)"; }

login() {
  rm -f "$jar"
  curl -sS --fail-with-body --max-time 30 --cacert "$ca" -c "$jar" -b "$jar" \
    -H "Origin: $url" -H "Content-Type: application/json" \
    --data "{\"user_name\":\"$admin\",\"password\":\"$password\"}" \
    "$url/api/v1/auth/login/password" >/dev/null
}

# healthy <service>: the service's container health check passes (the host reads it).
healthy() { ctl healthy "$1"; }

# The members view through HAProxy.
members() { api GET /cluster/members; }
voters() { members | json "sum(1 for m in j['members'] if m['role'] == 'voter')"; }
three_voters() { [[ "$(voters)" == 3 ]]; }
# The service name of the leader: the host of its cluster port.
leader_service() {
  members | json "next(m['address'].split(':')[0] for m in j['members'] if m['leader'])"
}

# The digests through HAProxy: every member that answers holds the same state at the
# same revision, and at least `$1` members answer.
digests_agree() {
  api GET /cluster/digests | python3 -c "
import json, sys
report = json.load(sys.stdin)
answered = [m for m in report['members'] if m.get('sha256')]
same = len({(m['sha256'], m['revision']) for m in answered}) == 1
sys.exit(0 if same and len(answered) >= $1 else 1)"
}

step "start controller-1 and HAProxy"
ctl up controller-1 haproxy >/dev/null
retry "$wait_secs" "controller-1 to become healthy" healthy controller-1
ok "controller-1" "healthy"

step "first-run setup through HAProxy"
# An administrator's password: at least 12 characters and not digits only, in every profile.
password="Lab-$(od -An -N9 -tx1 /dev/urandom | tr -d ' \n')-Aa1"
if [[ "$keep" == 1 ]]; then
  # For hand tests on a kept lab; the file goes with the lab volume.
  (umask 077 && printf '%s\n' "$password" >"$work/admin-password")
fi
setup_token="$(ctl setup-token controller-1 | tr -d '\r\n')"
[[ -n "$setup_token" ]] || fail "no setup token"
retry 60 "HAProxy to see controller-1" curl -sS --fail --cacert "$ca" "$url/api/v1/health/ready"
ctl exec controller-1 -e "TENKO_SETUP_TOKEN=$setup_token" --stdin "$password" -- \
  "$tenko_bin" setup --url "$inner_url" --ca-file /lab/ca.pem \
  --admin "$admin" --host-name localhost --password-stdin
login
ok "setup" "administrator $admin through $url"

join() {
  local service="$1" answer token fingerprint
  # A controller token needs a sign-in within the last five minutes.
  login
  answer="$(api POST /nodes/enrollments '{"roles":["controller"]}')"
  token="$(printf '%s' "$answer" | json "j['token']")"
  fingerprint="$(printf '%s' "$answer" | json "j['ca_fingerprint']")"
  ctl run "$service" -e "TENKO_ENROLL_TOKEN=$token" -- \
    "$tenko_bin" cluster join --controller "$inner_url" \
    --ca-fingerprint "$fingerprint" --address "$service:8444" --listen 0.0.0.0:8444 \
    --name "$service" --config /var/lib/tenko/tenko.toml --data-dir /var/lib/tenko
  ctl up "$service" >/dev/null
  retry "$wait_secs" "$service to become healthy" healthy "$service"
}

step "join controller-2 and controller-3"
join controller-2
join controller-3
retry 120 "three voters" three_voters
ok "join" "three voters, leader $(leader_service)"

step "enroll and start the probes"
for n in 1 2; do
  answer="$(api POST /nodes/enrollments "{\"roles\":[\"probe\"],\"name\":\"probe-$n\"}")"
  token="$(printf '%s' "$answer" | json "j['token']")"
  fingerprint="$(printf '%s' "$answer" | json "j['ca_fingerprint']")"
  ctl run "probe-$n" -e "TENKO_ENROLL_TOKEN=$token" -- "$tenko_bin" \
    node enroll --controller "$inner_url" --ca-fingerprint "$fingerprint" \
    --data-dir /var/lib/tenko
done
ctl up probe-1 probe-2 >/dev/null
probe_ok() { ctl exec "$1" -- "$tenko_bin" node status --check --data-dir /var/lib/tenko; }
for n in 1 2; do
  retry 120 "probe-$n connected" probe_ok "probe-$n"
done
ok "probes" "probe-1 and probe-2 enrolled and connected"

# write_one <number> <file>: one address create; appends "start end status" to the file.
write_one() {
  local start end answer code problem
  start="$(date +%s.%N)"
  answer="$(curl -s -w '\n%{http_code}' --max-time 10 --cacert "$ca" -b "$jar" \
    -H "Origin: $url" -H "Content-Type: application/json" \
    -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid)" \
    --data "{\"ip\":\"2001:db8:5:$(printf '%x::%x:%x' $(($1 % prefixes)) $(($1 / prefixes >> 16)) $(($1 / prefixes & 65535)))\"}" \
    "$url/api/v1/addresses" || true)"
  end="$(date +%s.%N)"
  code="${answer##*$'\n'}"
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  # The stable code of a refusal, such as 503/sys.store.no_quorum.
  problem="$(printf '%s' "$answer" | grep -o '"code":"[a-z_.]*"' | head -n 1 | cut -d'"' -f4 || true)"
  if [[ -n "$problem" ]]; then
    code="$code/$problem"
  fi
  printf '%s %s %s\n' "$start" "$end" "$code" >>"$2"
}

# load <seconds> <rate> <first number> <file>: open loop, a tenth of the rate every 100 ms.
load() {
  local seconds="$1" per_tick=$(($2 / 10)) number="$3" file="$4" until
  until=$(($(date +%s) + seconds))
  while (($(date +%s) < until)); do
    for ((k = 0; k < per_tick; k++)); do
      number=$((number + 1))
      write_one "$number" "$file" &
    done
    sleep 0.1
  done
  wait
}

# report <file> <fault time or -> <limit>: prints the counts and the time writes resumed
# after the fault; fails when they did not resume within the limit or a write before the
# fault failed.
report() {
  python3 - "$@" <<'PY'
import sys
rows = [line.split() for line in open(sys.argv[1]) if line.strip()]
rows = [(float(s), float(e), c) for s, e, c in rows]
fault = None if sys.argv[2] == "-" else float(sys.argv[2])
limit = float(sys.argv[3])
good = [r for r in rows if r[2].startswith("2")]
span = max(e for _, e, _ in rows) - min(s for s, _, _ in rows)
text = f"{len(rows)} writes, {len(good)} committed ({len(good) / span:.0f}/s)"
codes = {}
for _, _, code in rows:
    if not code.startswith("2"):
        codes[code] = codes.get(code, 0) + 1
if codes:
    text += " [" + ", ".join(f"{count}x HTTP {code}" for code, count in sorted(codes.items())) + "]"
# Concurrent creates that invalidated each other's plans are the load's own contention, not
# an outage of the cluster; they are counted above and not held against it.
def failed(row):
    return not row[2].startswith("2") and row[2] != "503/ipam.contended"
if fault is None:
    count = sum(1 for r in rows if failed(r))
    print(text + f", {count} failed")
    sys.exit(1 if count else 0)
before = [r for r in rows if r[1] < fault and failed(r)]
after = [r[1] - fault for r in good if r[0] >= fault]
resumed = min(after) if after else None
print(text + f", {len(before)} failed before the fault, writes resumed "
      + (f"{resumed:.1f} s after it" if resumed is not None else "never"))
sys.exit(0 if resumed is not None and resumed < limit and not before else 1)
PY
}

step "kill the leader under $rate writes/s"
# The creates spread over several prefixes: creates in one prefix plan against the same
# prefix and invalidate each other's plans (503 ipam.contended).
for ((k = 0; k < prefixes; k++)); do
  api POST /prefixes "{\"cidr\":\"2001:db8:5:$(printf '%x' "$k")::/64\",\"description\":\"lab load\"}" >/dev/null
done
killed="$(leader_service)"
load "$seconds_under_load" "$rate" 0 "$work/kill.txt" &
load_pid=$!
sleep 10
fault_at="$(date +%s.%N)"
ctl kill "$killed" >/dev/null
wait "$load_pid"
line="$(report "$work/kill.txt" "$fault_at" "$resume_limit")" || fail "kill the leader: $line"
ok "kill the leader ($killed)" "$line"
retry 60 "the survivors' digests to agree" digests_agree 2
ok "digests after the kill" "the two survivors agree"

step "restart $killed"
ctl up "$killed" >/dev/null
retry "$wait_secs" "$killed to become healthy" healthy "$killed"
retry 120 "three voters" three_voters
retry 90 "all three digests to agree" digests_agree 3
for n in 1 2; do
  retry 120 "probe-$n connected" probe_ok "probe-$n"
done
ok "restart" "$killed is back, three voters agree, now led by $(leader_service); probes connected"

step "partition a follower with docker network disconnect"
leader="$(leader_service)"
for candidate in controller-1 controller-2 controller-3; do
  if [[ "$candidate" != "$leader" ]]; then
    cut="$candidate"
    break
  fi
done
# Its own port: the command line inside its container over the loopback, signed in before
# the cut (the sign-in writes, which an isolated controller refuses).
ctl exec "$cut" -e TENKO_CREDENTIALS=/tmp/lab-credentials.json --stdin "$password" -- \
  "$tenko_bin" login --url http://127.0.0.1:8443 --user "$admin" --password-stdin >/dev/null
own_state() {
  ctl exec "$cut" -e TENKO_CREDENTIALS=/tmp/lab-credentials.json -- \
    "$tenko_bin" cluster status --json | json "j['quorum']['state']"
}
lost_quorum() { [[ "$(own_state)" =~ ^(isolated|electing)$ ]]; }
back() { [[ "$(own_state)" == healthy ]]; }
ctl disconnect "$cut" lab
retry 60 "$cut to count itself cut off" lost_quorum
ok "partition ($cut)" "its own port reports $(own_state)"
# HAProxy takes the cut controller out after two failed checks (2 s apart, 1 s each).
sleep 8
load 5 20 1000000 "$work/partition.txt"
line="$(report "$work/partition.txt" - 0)" || fail "writes on the majority: $line"
ok "majority writes" "$line"
ctl connect "$cut" lab
retry 90 "$cut healthy again" back
retry 90 "all three digests to agree after the heal" digests_agree 3
ok "heal" "$cut is back and the three digests agree"

step "renewal, refused enrollments and revocation"
# A renewal before the certificate's window is refused: a new certificate has a year.
early="$(ctl exec probe-1 --merge -- "$tenko_bin" node renew --data-dir /var/lib/tenko 2>&1 || true)"
[[ "$early" == *"not due for renewal"* ]] || fail "an early renewal was not refused: $early"
ok "renewal before its window" "refused as not due"

# Thirty enrollments with an invalid token, on one controller (the session cookie keeps
# HAProxy on one): ten audit records one by one and one summary at the end of the minute.
login
for _ in $(seq 30); do
  curl -s -o /dev/null --max-time 10 --cacert "$ca" -b "$jar" -H "Origin: $url" \
    -H "Content-Type: application/json" --data '{"token":"x","csr":""}' \
    "$url/api/v1/nodes/enroll" || true
done
refusals() {
  api GET "/audit?action=cluster.node.enroll&limit=200" | python3 -c "
import json, sys
items = json.load(sys.stdin)['items']
summary = [r for r in items if 'cluster.enrollment.refusals' in json.dumps(r)]
one = sum(1 for r in items if 'cluster.enrollment.invalid_token' in json.dumps(r) and r not in summary)
print(one, len(summary), summary[0] if summary else '')"
}
summarized() { [[ "$(refusals)" == "10 1 "* ]]; }
retry 120 "the summary of the refused enrollments" summarized
ok "refused enrollments" "30 refused: 10 recorded one by one, 20 in one summary"

# probe-2 revoked through the API: the controller it is connected to closes its
# connection and the probe reports the state revoked. It is the installation's first
# revocation, so every controller's revocation list was empty before it.
probe2="$(api GET /nodes | json "next(n['id'] for n in j['items'] if n['name'] == 'probe-2')")"
holder="$(api GET "/nodes/$probe2" | json "(j.get('connection') or {}).get('controller')")"
api DELETE "/nodes/$probe2" >/dev/null
probe2_state() {
  ctl exec probe-2 -- "$tenko_bin" node status --json --data-dir /var/lib/tenko |
    json "(j.get('process') or {}).get('state')"
}
revoked() { [[ "$(probe2_state)" == revoked ]]; }
retry 30 "probe-2 to report itself revoked" revoked
retry 60 "probe-1 still connected" probe_ok probe-1
ok "revocation" "probe-2 (connected to controller node $holder) cut off and revoked; probe-1 connected"

step "OK: the cluster lab passed"
