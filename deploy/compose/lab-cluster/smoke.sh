#!/usr/bin/env bash
# Smoke test of the compose cluster lab (deploy/compose/lab-cluster, WP3.1c, E9 on one
# Docker host).
#
# What it does, printing one summary line per step at the end:
#   1. builds the image tenko:lab from the repository (docker build -f deploy/Dockerfile),
#      unless IMAGE=<tag> names an image that exists already;
#   2. generates a lab CA and the HAProxy certificate with openssl, and one key-encryption
#      key per controller, into a temporary work directory;
#   3. starts controller-1 and HAProxy, runs first-run setup through HAProxy and signs in;
#   4. creates two controller tokens and joins controller-2 and controller-3 with
#      `tenko cluster join` in their own containers before their first start, then waits
#      until the cluster has three voters;
#   5. enrols the two probes and starts them;
#   6. writes 100 addresses per second through HAProxy, kills the leader with
#      `docker compose kill` during the load, checks that writes resume within 15 s and that
#      the surviving controllers' state digests agree, restarts the killed controller and
#      checks that all three agree and both probes are connected;
#   7. disconnects a follower from the lab network (the fault service runs
#      `docker network disconnect`), checks through its own port that it lost its quorum and
#      that the majority keeps taking writes, connects it again and checks the digests;
#   8. tears everything down (containers, volumes, network, work directory), also when a
#      step fails, after printing the logs of every service. KEEP=1 leaves the lab running.
#
# Needs: bash, Docker with the compose and buildx plugins, curl, openssl and python3 on the
# host. Run it from the repository root without arguments:
#   bash deploy/compose/lab-cluster/smoke.sh
#   IMAGE=tenko:lab bash deploy/compose/lab-cluster/smoke.sh     # skip the build
#   KEEP=1 bash deploy/compose/lab-cluster/smoke.sh              # keep the lab for hand tests
#
# The lab's containers talk to each other on the bridge network 198.51.100.0/24
# (documentation addresses) and to nothing else; HAProxy is published on 127.0.0.1 only.
# Only the image build and the first pull of haproxy and docker:cli reach out, to the
# registries and package mirrors.
#
# Settings (environment, all optional):
#   IMAGE           an existing image to test; default: build tenko:lab
#   LAB_PORT        the loopback port of HAProxy (default 28443)
#   RATE, SECONDS_UNDER_LOAD   the write load (default 100 writes/s for 30 s around the kill)
#   WAIT_SECS       how long to wait for a controller to become healthy (default 300)
#   KEEP            1: do not tear the lab down at the end (README.md says how to later)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
compose_file="$here/compose.yml"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkolab}"
export LAB_PORT="${LAB_PORT:-28443}"
rate="${RATE:-100}"
seconds_under_load="${SECONDS_UNDER_LOAD:-30}"
wait_secs="${WAIT_SECS:-300}"
keep="${KEEP:-0}"
url="https://localhost:$LAB_PORT"
inner_url="https://haproxy:8443"
network="${COMPOSE_PROJECT_NAME}_lab"
tenko_bin=/usr/local/bin/tenko
admin=lab-admin
resume_limit=15
# The load's addresses are spread over this many /64 prefixes.
prefixes=20

built_here=0
if [[ -n "${IMAGE:-}" ]]; then
  export TENKO_IMAGE="$IMAGE"
else
  export TENKO_IMAGE=tenko:lab
  built_here=1
fi

work=""
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
compose() { docker compose -f "$compose_file" --profile probes --profile fault "$@"; }

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

cleanup() {
  status=$?
  set +e
  trap - EXIT
  if ((status != 0)); then
    printf '\n==> FAILED (status %s): logs of the services\n' "$status" >&2
    for service in controller-1 controller-2 controller-3 probe-1 probe-2 haproxy; do
      printf '\n--- %s ---\n' "$service" >&2
      compose logs --no-color --tail 150 "$service" >&2 2>&1
    done
    docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" >&2 2>&1
  fi
  if ((${#summary[@]} > 0)); then
    printf '\n==> summary\n'
    printf '%s\n' "${summary[@]}"
  fi
  if [[ "$keep" == 1 && $status -eq 0 ]]; then
    printf '\n==> KEEP=1: the lab keeps running at %s (CA %s/tls/ca.pem)\n' "$url" "$work"
    printf 'tear it down with: LAB_DIR=%s docker compose -f %s --profile probes --profile fault down --volumes\n' \
      "$work" "$compose_file"
    exit "$status"
  fi
  printf '\n==> tear down\n'
  compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
  if [[ -n "$work" ]]; then
    rm -rf "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

step "check the tools"
for tool in docker curl openssl python3; do
  command -v "$tool" >/dev/null || fail "$tool not found"
done
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is missing"
docker info >/dev/null 2>&1 || fail "cannot talk to the Docker daemon"

if ((built_here)); then
  step "build the image $TENKO_IMAGE (UI bundle and release binary; this takes a while)"
  docker build -f "$repo/deploy/Dockerfile" -t "$TENKO_IMAGE" "$repo"
else
  step "use the existing image $TENKO_IMAGE"
  docker image inspect "$TENKO_IMAGE" >/dev/null 2>&1 || fail "image $TENKO_IMAGE not found"
fi
ok "image" "$TENKO_IMAGE"

step "generate the lab certificate and the key-encryption keys"
work="$(mktemp -d)"
export LAB_DIR="$work"
mkdir -p "$work/tls" "$work/secrets"
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
  # The containers' users (65532 for tenko, 99 for haproxy) are not the owner; the work
  # directory itself is private to this user.
  chmod 0444 ca.pem haproxy.pem
  chmod 0400 server.key
)
for n in 1 2 3; do
  head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/kek_$n"
  chmod 0444 "$work/secrets/kek_$n"
done
chmod 0755 "$work"
ca="$work/tls/ca.pem"
jar="$work/cookies"
compose config --quiet
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

healthy() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$1")")" == healthy ]]; }

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
compose up -d --no-build controller-1 haproxy
retry "$wait_secs" "controller-1 to become healthy" healthy controller-1
ok "controller-1" "healthy"

step "first-run setup through HAProxy"
# The Home profile's password preset is the PIN: digits only.
password="$(od -An -N8 -tu1 /dev/urandom | tr -d ' \n' | cut -c1-12)"
if [[ "$keep" == 1 ]]; then
  # For hand tests on a kept lab; the file goes with the work directory.
  (umask 077 && printf '%s\n' "$password" >"$work/admin-password")
fi
setup_token="$(compose exec -T controller-1 "$tenko_bin" setup token | tr -d '\r\n')"
[[ -n "$setup_token" ]] || fail "no setup token"
retry 60 "HAProxy to see controller-1" curl -sS --fail --cacert "$ca" "$url/api/v1/health/ready"
printf '%s\n' "$password" | compose exec -T -e "TENKO_SETUP_TOKEN=$setup_token" controller-1 \
  "$tenko_bin" setup --url "$inner_url" --ca-file /lab/ca.pem \
  --admin "$admin" --host-name localhost --password-stdin
login
ok "setup" "administrator $admin through $url"

join() {
  local service="$1" answer token fingerprint
  # A controller token needs a sign-in within the last five minutes.
  login
  answer="$(api POST /nodes/enrolments '{"roles":["controller"]}')"
  token="$(printf '%s' "$answer" | json "j['token']")"
  fingerprint="$(printf '%s' "$answer" | json "j['ca_fingerprint']")"
  compose run --rm -T --no-deps --use-aliases -e "TENKO_ENROL_TOKEN=$token" \
    --entrypoint "$tenko_bin" "$service" cluster join --controller "$inner_url" \
    --ca-fingerprint "$fingerprint" --address "$service:8444" --listen 0.0.0.0:8444 \
    --name "$service" --config /var/lib/tenko/tenko.toml --data-dir /var/lib/tenko
  compose up -d --no-build "$service"
  retry "$wait_secs" "$service to become healthy" healthy "$service"
}

step "join controller-2 and controller-3"
join controller-2
join controller-3
retry 120 "three voters" three_voters
ok "join" "three voters, leader $(leader_service)"

step "enrol and start the probes"
for n in 1 2; do
  answer="$(api POST /nodes/enrolments "{\"roles\":[\"probe\"],\"name\":\"probe-$n\"}")"
  token="$(printf '%s' "$answer" | json "j['token']")"
  fingerprint="$(printf '%s' "$answer" | json "j['ca_fingerprint']")"
  compose run --rm -T --no-deps -e "TENKO_ENROL_TOKEN=$token" --entrypoint "$tenko_bin" \
    "probe-$n" node enrol --controller "$inner_url" --ca-fingerprint "$fingerprint" \
    --data-dir /var/lib/tenko
done
compose up -d --no-build probe-1 probe-2
probe_ok() { compose exec -T "$1" "$tenko_bin" node status --check --data-dir /var/lib/tenko; }
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
compose kill "$killed"
wait "$load_pid"
line="$(report "$work/kill.txt" "$fault_at" "$resume_limit")" || fail "kill the leader: $line"
ok "kill the leader ($killed)" "$line"
retry 60 "the survivors' digests to agree" digests_agree 2
ok "digests after the kill" "the two survivors agree"

step "restart $killed"
compose up -d --no-build "$killed"
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
printf '%s\n' "$password" | compose exec -T -e TENKO_CREDENTIALS=/tmp/lab-credentials.json "$cut" \
  "$tenko_bin" login --url http://127.0.0.1:8443 --user "$admin" --password-stdin >/dev/null
own_state() {
  compose exec -T -e TENKO_CREDENTIALS=/tmp/lab-credentials.json "$cut" \
    "$tenko_bin" cluster status --json | json "j['quorum']['state']"
}
lost_quorum() { [[ "$(own_state)" =~ ^(isolated|electing)$ ]]; }
back() { [[ "$(own_state)" == healthy ]]; }
container="$(compose ps -q "$cut")"
compose run --rm -T fault network disconnect "$network" "$container"
retry 60 "$cut to count itself cut off" lost_quorum
ok "partition ($cut)" "its own port reports $(own_state)"
# HAProxy takes the cut controller out after two failed checks (2 s apart, 1 s each).
sleep 8
load 5 20 1000000 "$work/partition.txt"
line="$(report "$work/partition.txt" - 0)" || fail "writes on the majority: $line"
ok "majority writes" "$line"
compose run --rm -T fault network connect --alias "$cut" "$network" "$container"
retry 90 "$cut healthy again" back
retry 90 "all three digests to agree after the heal" digests_agree 3
ok "heal" "$cut is back and the three digests agree"

step "OK: the cluster lab passed"
