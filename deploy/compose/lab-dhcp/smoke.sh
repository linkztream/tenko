#!/usr/bin/env bash
# Smoke test of the compose DHCP lab (deploy/compose/lab-dhcp, WP7.6): four client
# networks behind one gateway (ISC's dhcrelay) that relays every one of them to one Tenko
# node, the topology of E23.
#
# What it does, printing one PASS, FAIL or SKIP line per row (README.md lists the rows):
#   1. builds the tools image (Debian's dhcrelay, dhclient, perfdhcp, udhcpc) and the node's
#      image: tenko:lab from deploy/Dockerfile (the static musl binary), or with NODE=example
#      the engine's example server from example.Dockerfile, unless IMAGE=<tag> or
#      EXAMPLE_IMAGE=<tag> names an image that exists already;
#   2. starts the gateway, the node's namespace, the node, the four clients and the tester;
#   3. with the binary (NODE=tenko, the default): the first-run setup through the API under
#      the Lab profile; the four networks as IPAM prefixes with a dhcp_pool range each and
#      a scope each (lease 60 s, so that T1 comes after 30 s), option 3 per scope (the
#      gateway's address on the network) and options 6, 15 and 42 for the server; then the
#      rows: a lease on each network through the relay from the right scope with options 3,
#      6 and 42; option 82 on the lease row (giaddr and the circuit-id dhcrelay adds); the
#      link selection sub-option choosing another network's scope; perfdhcp and udhcpc;
#      every client renews at T1 (unicast through the gateway); a reservation wins over the
#      dynamic lease; a deny filter refuses a client and its removal admits it again; a
#      release reaches the lease row; a restart of the node keeps the leases and the
#      clients keep their addresses;
#      WP8.4, E27's class and PXE rows: a vendor-class, a MAC-wildcard and a user-class
#      policy select their range and option 15 for dhclient clients; QEMU in BIOS mode
#      with its iPXE ROM and in UEFI mode with OVMF boot to an iPXE menu from the lab's
#      TFTP and HTTP server (the pxe profile, pxe.Dockerfile), with their architecture on
#      their lease rows; a UEFI HTTP boot client gets its URL; the proxy DHCP listener
#      answers the boot server discovery on port 4011;
#   3'. with NODE=example: the rows the example server can answer (it serves one scope,
#      198.18.0.0/15, selected by option 118 or link selection, with the in-memory
#      reference store): relay-test.py with option 118 (offer, ack, renewal, release) and
#      with the link selection sub-option, and perfdhcp; the other rows are SKIP lines;
#   4. tears everything down (containers, volumes, networks, work directory), also when a
#      step fails, after printing the logs of every service. KEEP=1 leaves the lab running.
#
# Needs: bash, Docker with the compose plugin (and buildx for the builds), and with the
# binary curl and python3 on the host (the host reaches the node's API on the lab network).
# Run it from the repository root without arguments:
#   bash deploy/compose/lab-dhcp/smoke.sh
#   IMAGE=tenko:lab bash deploy/compose/lab-dhcp/smoke.sh          # skip the build
#   NODE=example bash deploy/compose/lab-dhcp/smoke.sh             # the example server
#   KEEP=1 bash deploy/compose/lab-dhcp/smoke.sh                   # keep the lab
#
# The containers talk on four bridge networks inside 192.0.2.0/24 (documentation addresses)
# and to nothing else; nothing is published on the host. Only the image builds and the
# first pull of the base images reach out.
#
# Settings (environment, all optional):
#   NODE            tenko (the binary, default) or example (the engine's example server)
#   IMAGE           an existing Tenko image to test; default: build tenko:lab
#   EXAMPLE_IMAGE   an existing example server image; default: build
#                   tenko-dhcp-lab-example:latest (NODE=example only)
#   TOOLS_IMAGE     an existing tools image; default: build tenko-dhcp-lab-tools:latest
#   WAIT_SECS       how long to wait for Tenko to become healthy (default 300)
#   KEEP            1: do not tear the lab down at the end, also after a failure
#   PXE             0: leave E27's PXE rows out (WP8.4; they build the pxe image and run
#                   QEMU, with KVM where /dev/kvm exists)
#   PXE_IMAGE       an existing pxe image (with PXE_IMAGE_PREBUILT=1); default: build
#                   tenko-dhcp-lab-pxe:latest
#   PXE_WAIT_SECS   how long a machine may take to boot to the menu (default 300)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
compose_file="$here/compose.yml"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tenkodhcplab}"
node="${NODE:-tenko}"
wait_secs="${WAIT_SECS:-300}"
keep="${KEEP:-0}"
node_ip=192.0.2.10
tester_ip=192.0.2.20
api_base="http://$node_ip:8443"
# The networks: name, prefix, the gateway's address on it, the pool, the client's MAC.
networks=(servers lan iot guest)
declare -A prefix=([servers]=192.0.2.0/26 [lan]=192.0.2.64/26 [iot]=192.0.2.128/26 [guest]=192.0.2.192/26)
declare -A gateway=([servers]=192.0.2.2 [lan]=192.0.2.66 [iot]=192.0.2.130 [guest]=192.0.2.194)
declare -A pool_first=([servers]=192.0.2.30 [lan]=192.0.2.94 [iot]=192.0.2.158 [guest]=192.0.2.222)
declare -A pool_last=([servers]=192.0.2.59 [lan]=192.0.2.123 [iot]=192.0.2.187 [guest]=192.0.2.251)
declare -A client_mac=([servers]=00:00:5e:00:53:05 [lan]=00:00:5e:00:53:45 [iot]=00:00:5e:00:53:85 [guest]=00:00:5e:00:53:c5)
# The options of E23: DNS servers (6) and NTP servers (42) for every client.
dns_server=192.0.2.53
ntp_server=192.0.2.123
# The reservation row: client-lan's MAC gets this address, outside the pool.
reserved_ip=192.0.2.80
lease_secs=60
# The example server's scope (198.18.0.0/15, the benchmarking range of RFC 2544).
example_net=198.18.0.0/15
example_link=198.18.0.0

case "$node" in
  tenko | example) ;;
  *) printf 'smoke: NODE must be tenko or example, not %s\n' "$node" >&2; exit 2 ;;
esac
export TOOLS_IMAGE="${TOOLS_IMAGE:-tenko-dhcp-lab-tools:latest}"
build_tools=1
[[ -n "${TOOLS_IMAGE_PREBUILT:-}" ]] && build_tools=0
if [[ -n "${IMAGE:-}" ]]; then
  export TENKO_IMAGE="$IMAGE"
  build_tenko=0
else
  export TENKO_IMAGE=tenko:lab
  build_tenko=1
fi
if [[ -n "${EXAMPLE_IMAGE:-}" ]]; then
  build_example=0
else
  export EXAMPLE_IMAGE=tenko-dhcp-lab-example:latest
  build_example=1
fi

work=""
cookie=""
status=0
rows_failed=0
summary=()

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'smoke: %s\n' "$*" >&2; exit 1; }
ok() {
  local line
  line="$(printf 'ok   %-22s %s' "$1" "$2")"
  summary+=("$line")
  printf '%s\n' "$line"
}
compose() { docker compose -f "$compose_file" --profile "$node" "$@"; }

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

# within <seconds> <command...>: like retry, every half second, without failing.
within() {
  local limit_ms=$(($1 * 1000)) began now
  shift
  began="$(date +%s%3N)"
  while true; do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    now="$(date +%s%3N)"
    ((now - began >= limit_ms)) && return 1
    sleep 0.5
  done
}

# row <name> <what> <command...>: one PASS or FAIL line; a failed check runs once more
# with a trace for the log.
row() {
  local name="$1" what="$2" line
  shift 2
  if "$@"; then
    line="$(printf 'PASS %-22s %s' "$name" "$what")"
  else
    line="$(printf 'FAIL %-22s %s' "$name" "$what")"
    rows_failed=$((rows_failed + 1))
    (set -x; "$@") >&2 2>&1 || true
  fi
  summary+=("$line")
  printf '%s\n' "$line"
}
skip() {
  local line
  line="$(printf 'SKIP %-22s %s' "$1" "$2")"
  summary+=("$line")
  printf '%s\n' "$line"
}

cleanup() {
  status=$?
  set +e
  trap - EXIT
  if ((status != 0)); then
    printf '\n==> FAILED (status %s): logs of the services\n' "$status" >&2
    for service in relay netns tenko node-example tester client-servers client-lan client-iot client-guest; do
      printf '\n--- %s ---\n' "$service" >&2
      compose logs --no-color --tail 200 "$service" >&2 2>&1
    done
    # WP8.4: the boot server's and the machines' logs.
    for service in bootsrv pxe-bios pxe-uefi; do
      printf '\n--- %s ---\n' "$service" >&2
      pxe_compose logs --no-color --tail 100 "$service" >&2 2>&1
    done
    pxe_compose exec -T bootsrv sh -c 'tail -n 50 /run/lab/*.log' >&2 2>&1
    docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" >&2 2>&1
  fi
  if ((${#summary[@]} > 0)); then
    printf '\n==> summary (node: %s)\n' "$node"
    printf '%s\n' "${summary[@]}"
  fi
  if [[ "$keep" == 1 ]]; then
    printf '\n==> KEEP=1: the lab keeps running; for example\n'
    printf '    LAB_DIR=%s docker compose -f %s --profile %s exec client-lan dhclient -v -1 -cf /lab/dhclient.conf -sf /lab/client-script.sh eth0\n' \
      "$work" "$compose_file" "$node"
    printf 'tear it down with: LAB_DIR=%s docker compose -f %s --profile %s down --volumes\n' \
      "$work" "$compose_file" "$node"
    exit "$status"
  fi
  printf '\n==> tear down\n'
  # WP8.4: the pxe profile's services too.
  pxe_compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1
  compose down --volumes --remove-orphans --timeout 30 >/dev/null 2>&1
  if [[ -n "$work" ]]; then
    rm -rf "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------
# The clients

# dhclient in a client container: -1 tries once (the timeout of dhclient.conf) and goes
# to the background with the lease; the lease file and the pid stay in /run/lab.
dhclient_in() {
  local service="$1"
  shift
  compose exec -T "$service" dhclient -v -cf /lab/dhclient.conf -sf /lab/client-script.sh \
    -lf /run/lab/dhclient.leases -pf /run/lab/dhclient.pid "$@" eth0
}
# The last event line of a client's script (client-script.sh), and a field of it.
last_event() { compose exec -T "client-$1" sh -c 'tail -n 1 /run/lab/events 2>/dev/null' | tr -d '\r'; }
event_field() { sed -n "s/.* $1=\\([^ ]*\\).*/\\1/p"; }
forget() { compose exec -T "$1" rm -f /run/lab/dhclient.leases; }
events_of() { compose exec -T "client-$1" sh -c 'cat /run/lab/events 2>/dev/null' | tr -d '\r'; }

# in_pool <address> <network name>
in_pool() {
  python3 - "$1" "${pool_first[$2]}" "${pool_last[$2]}" <<'PY'
import ipaddress, sys
a, f, l = (ipaddress.IPv4Address(x) for x in sys.argv[1:])
sys.exit(0 if f <= a <= l else 1)
PY
}

declare -A leased=()

# lease_ok <network>: the client got an address of its pool with options 3, 6 and 42.
lease_ok() {
  local net="$1" line ip
  dhclient_in "client-$net" -1 >/dev/null 2>&1 || return 1
  line="$(last_event "$net")"
  [[ "$line" == BOUND* || "$line" == REBOOT* ]] || return 1
  ip="$(event_field ip <<<"$line")"
  leased[$net]="$ip"
  in_pool "$ip" "$net" &&
    [[ "$(event_field routers <<<"$line")" == "${gateway[$net]}" ]] &&
    [[ "$(event_field dns <<<"$line")" == "$dns_server" ]] &&
    [[ "$(event_field ntp <<<"$line")" == "$ntp_server" ]]
}

# renewed <network>: a RENEW event with the same address, after the first binding.
renewed() {
  events_of "$1" | grep -q "^RENEW ip=${leased[$1]} "
}

# ---------------------------------------------------------------------------------------
# The API (the binary only)

# api <method> <path> [<json>]: a request with the session; prints the body, returns 0
# for a 2xx status and leaves the status in $api_status.
api() {
  local method="$1" path="$2" body="${3:-}" out
  out="$work/api.out"
  local args=(-sS -o "$out" -w '%{http_code}' -X "$method" -H "Origin: $api_base"
    -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid)")
  [[ -n "$cookie" ]] && args+=(-H "Cookie: $cookie")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data "$body")
  api_status="$(curl "${args[@]}" "$api_base/api/v1$path")" || api_status=000
  cat "$out"
  [[ "$api_status" == 2* ]]
}
# field <expression>: a value of the JSON on standard input (`d` is the document).
field() { python3 -c "import json,sys; d=json.load(sys.stdin); v=($1); print('' if v is None else v)"; }
must() {
  local what="$1"
  shift
  "$@" >/dev/null || fail "$what ($api_status: $(cat "$work/api.out"))"
}

healthy() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q tenko)")" == healthy ]]; }

lab_setup() {
  local token password setup
  token="$(compose exec -T tenko /usr/local/bin/tenko setup token --data-dir /var/lib/tenko | tr -d '\r\n')"
  [[ -n "$token" ]] || fail "setup: no setup token"
  # The Lab profile's password policy is a PIN of digits.
  password="$(od -An -N4 -tu4 /dev/urandom | tr -dc '0-9')"
  setup="{\"setup_token\": \"$token\", \"profile\": \"lab\", \"admin\": {\"name\": \"labadmin\", \"display_name\": \"Lab Admin\", \"password\": \"$password\"}, \"host_name\": \"tenko.example.test\", \"language\": \"en\"}"
  cookie="$(curl -sS -D - -o "$work/api.out" -H "Origin: $api_base" -H "Content-Type: application/json" \
    --data "$setup" "$api_base/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)"
  [[ -n "$cookie" ]] || fail "setup: the setup did not sign in: $(cat "$work/api.out")"
  ok "setup" "Tenko is set up under the Lab profile"
}

configure() {
  local net id
  must "the server's options" api PUT /dhcp/option-sets/server \
    "{\"values\": [{\"code\": 6, \"typed\": {\"ipv4\": {\"values\": [\"$dns_server\"]}}}, {\"code\": 42, \"typed\": {\"ipv4\": {\"values\": [\"$ntp_server\"]}}}, {\"code\": 15, \"typed\": {\"text\": \"example.test\"}}]}"
  for net in "${networks[@]}"; do
    must "the prefix of $net" api POST /prefixes "{\"cidr\": \"${prefix[$net]}\", \"description\": \"lab network $net\"}"
    id="$(field "d['item']['id']" <"$work/api.out")"
    must "the pool of $net" api POST "/prefixes/$id/ranges" \
      "{\"first\": \"${pool_first[$net]}\", \"last\": \"${pool_last[$net]}\", \"role\": \"dhcp_pool\"}"
    must "the scope of $net" api POST /dhcp/scopes \
      "{\"prefix\": \"$id\", \"lease\": {\"default_secs\": $lease_secs, \"min_secs\": $lease_secs, \"max_secs\": $((lease_secs * 2))}}"
    must "option 3 of $net" api PUT "/dhcp/option-sets/scope:$id" \
      "{\"values\": [{\"code\": 3, \"typed\": {\"ipv4\": {\"values\": [\"${gateway[$net]}\"]}}}]}"
  done
  ok "configuration" "four prefixes with a pool and a scope each, options 3, 6, 15 and 42"
}

# lease_row <address>: the lease row of an address (GET /dhcp/leases/{addr}).
lease_json() { api GET "/dhcp/leases/$1"; }
# relay_on_lease <network>: the lease of the network's client holds giaddr (the gateway's
# address on the network) and the circuit-id dhcrelay adds (the network's name).
relay_on_lease() {
  local net="$1" want
  want="$(printf '%s' "$net" | od -An -v -tx1 | tr -d ' \n')"
  lease_json "${leased[$net]}" >/dev/null || return 1
  [[ "$(field "d['relay']['giaddr']" <"$work/api.out")" == "${gateway[$net]}" ]] &&
    [[ "$(field "(d['relay'].get('circuit_id') or '').lower()" <"$work/api.out")" == "$want" ]]
}
lease_state_is() {
  lease_json "$1" >/dev/null && [[ "$(field "d['state']" <"$work/api.out")" == "$2" ]]
}
# The active leases that are still running in 5 seconds: "address client end" per line,
# sorted (a 60-second lease may end between two reads, so the ones about to end are left
# out).
active_leases() {
  api GET "/dhcp/leases?limit=1000" >/dev/null || return 1
  python3 - "$work/api.out" <<'PY'
import datetime, json, re, sys
d = json.load(open(sys.argv[1]))
soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)
def at(text):
    text = re.sub(r"(\.\d{6})\d+", r"\1", text).replace("Z", "+00:00")
    return datetime.datetime.fromisoformat(text)
for l in sorted(d["items"], key=lambda l: l["addr"]):
    if l["state"] == "active" and at(l["ends"]) > soon:
        print(l["addr"], l["client"]["chaddr"], l["ends"])
PY
}
# every_lease_kept: each lease active before the restart and not ended yet is listed after
# it, active, for the same client.
every_lease_kept() {
  api GET "/dhcp/leases?limit=1000" >/dev/null || return 1
  python3 - "$work/api.out" "$work/leases.before" <<'PY'
import datetime, json, re, sys
d = json.load(open(sys.argv[1]))
now = datetime.datetime.now(datetime.timezone.utc)
def at(text):
    text = re.sub(r"(\.\d{6})\d+", r"\1", text).replace("Z", "+00:00")
    return datetime.datetime.fromisoformat(text)
held = {l["addr"]: l for l in d["items"] if l["state"] == "active"}
missing = []
for line in open(sys.argv[2]):
    addr, chaddr, ends = line.split()
    if at(ends) <= now:
        continue
    if addr not in held or held[addr]["client"]["chaddr"] != chaddr:
        missing.append(addr)
print("missing after the restart:", missing or "none")
sys.exit(1 if missing else 0)
PY
}

# ---------------------------------------------------------------------------------------
# The tester's rows (both nodes)

# relay_test <expected network> <arguments...>: relay-test.py from the tester.
relay_test() {
  local expect="$1"
  shift
  compose exec -T tester python3 /lab/relay-test.py --server "$node_ip" --giaddr "$tester_ip" \
    --expect "$expect" "$@"
}

# perfdhcp_ok <clients> [<options...>]: perfdhcp as a relay from the tester, every 4-way
# exchange answered (no drops in DISCOVER-OFFER or REQUEST-ACK).
perfdhcp_ok() {
  local n="$1" out
  shift
  out="$(compose exec -T tester perfdhcp -4 -l "$tester_ip" -r "$n" -R "$n" -n "$n" -p 30 \
    -W 2000000 "$@" "$node_ip" 2>&1)" || true
  printf '%s\n' "$out" >"$work/perfdhcp.out"
  python3 - "$work/perfdhcp.out" "$n" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
n = int(sys.argv[2])
blocks = re.findall(r"Statistics for: ([^*\n]+)\*+\s+sent packets: (\d+)\s+received packets: (\d+)\s+drops: (\d+)", text)
got = {name: (int(s), int(r), int(d)) for name, s, r, d in blocks}
ok = all(got.get(k, (0, 0, 1))[1] == n and got[k][2] == 0 for k in ("DISCOVER-OFFER", "REQUEST-ACK"))
print(got)
sys.exit(0 if ok else 1)
PY
}

# udhcpc_ok <network>: BusyBox's udhcpc gets an address of the network's pool (it quits
# with the lease, -q, and leaves the interface alone, -s /bin/true).
udhcpc_ok() {
  local out
  out="$(compose exec -T "client-$1" busybox udhcpc -i eth0 -n -q -t 5 -T 2 -s /bin/true 2>&1)" || return 1
  local ip
  ip="$(sed -n 's/.*lease of \([0-9.]*\) obtained.*/\1/p' <<<"$out" | head -n 1)"
  [[ -n "$ip" ]] && in_pool "$ip" "$1"
}

# ---------------------------------------------------------------------------------------
# WP8.4: E27's class and PXE rows (docs/dhcp.md section 16), with the binary only. Three
# policies over classes of the request select their range and options for real dhclient
# clients: a vendor class on guest, a MAC wildcard on iot (with its lease time), a user
# class on servers. Then the boot policies of lan (iPXE's user class first, then UEFI HTTP
# boot, UEFI and BIOS by option 93) with option 150 naming the boot server, the boot server
# (TFTP and HTTP), QEMU in BIOS mode with its iPXE ROM and in UEFI mode with OVMF booting
# to the menu over TFTP and HTTP, their lease rows with their architecture, a UEFI HTTP
# boot client (relay-test.py) getting its URL and fetching it, and the proxy DHCP listener
# answering the boot server discovery. PXE=0 leaves the PXE rows out.

pxe_rows="${PXE:-1}"
pxe_wait="${PXE_WAIT_SECS:-300}"
export PXE_IMAGE="${PXE_IMAGE:-tenko-dhcp-lab-pxe:latest}"
boot_ip=192.0.2.21
declare -A vm_mac=([bios]=00:00:5e:00:53:a0 [uefi]=00:00:5e:00:53:a1)
declare -A vm_platform=([bios]=pcbios [uefi]=efi)
declare -A vm_arch=([bios]=0 [uefi]="7 9")

# The lab with the pxe profile, and with KVM for the machines where the host has it.
pxe_compose() {
  local files=(-f "$compose_file")
  if [[ -e /dev/kvm ]]; then
    files+=(-f "$here/compose.kvm.yml")
  fi
  docker compose "${files[@]}" --profile "$node" --profile pxe "$@"
}

# scope_of <network>: the prefix identifier of the network's scope.
scope_of() {
  api GET "/dhcp/scopes?limit=1000" >/dev/null || return 1
  python3 - "$work/api.out" "${prefix[$1]}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(next(s["prefix"] for s in d["items"] if s["cidr"] == sys.argv[2]))
PY
}

# new_class <name> <matches JSON>: creates a class and prints its identifier.
new_class() {
  must "the class $1" api POST /dhcp/classes "{\"name\": \"$1\", \"matches\": $2}"
  field "d['id']" <"$work/api.out"
}

# new_policy <scope> <name> <order> <class> <action JSON> <options JSON>: a policy of the
# scope over the class, with the action and the option set.
new_policy() {
  local id
  must "the policy $2" api POST /dhcp/policies \
    "{\"name\": \"$2\", \"scope\": \"$1\", \"order\": $3, \"condition\": {\"join\": \"or\", \"terms\": [{\"class\": \"$4\"}]}, \"action\": $5}"
  id="$(field "d['id']" <"$work/api.out")"
  must "the options of the policy $2" api PUT "/dhcp/option-sets/policy:$id" "{\"values\": $6}"
}

text_option() { printf '{"code": %s, "typed": {"text": "%s"}}' "$1" "$2"; }

# fresh <network>: the network's client releases its lease and forgets it.
fresh() {
  dhclient_in "client-$1" -r >/dev/null 2>&1 || true
  forget "client-$1"
}

# class_lease_ok <network> <dhclient configuration> <first> <last> <domain> [<lease>]:
# dhclient with the configuration gets an address of the range with option 15 (and the
# lease time).
class_lease_ok() {
  local net="$1" line ip
  compose exec -T "client-$net" dhclient -v -cf "/lab/$2" -sf /lab/client-script.sh \
    -lf /run/lab/dhclient.leases -pf /run/lab/dhclient.pid -1 eth0 >/dev/null 2>&1 || return 1
  line="$(last_event "$net")"
  [[ "$line" == BOUND* || "$line" == REBOOT* ]] || return 1
  ip="$(event_field ip <<<"$line")"
  printf '%s: %s\n' "$net" "$line" >&2
  python3 -c 'import ipaddress, sys; a, f, l = (ipaddress.IPv4Address(x) for x in sys.argv[1:]); sys.exit(0 if f <= a <= l else 1)' \
    "$ip" "$3" "$4" &&
    [[ "$(event_field domain <<<"$line")" == "$5" ]] &&
    { [[ -z "${6:-}" ]] || [[ "$(event_field lease <<<"$line")" == "$6" ]]; }
}

class_rows() {
  local guest iot servers printers wildcard ops
  step "E27: classes and policies"
  guest="$(scope_of guest)" && iot="$(scope_of iot)" && servers="$(scope_of servers)" ||
    fail "the scopes"
  printers="$(new_class printers '[{"vendor_class": {"value": "Printer", "prefix": true}}]')"
  wildcard="$(new_class iot-wildcard '[{"mac": {"pattern": "00:00:5e:00:*:85"}}]')"
  ops="$(new_class ops '[{"user_class": {"value": "lab-ops"}}]')"
  new_policy "$guest" printers 1 "$printers" \
    '{"range": {"first": "192.0.2.230", "last": "192.0.2.234"}}' \
    "[$(text_option 15 printers.example.test)]"
  new_policy "$iot" iot-devices 1 "$wildcard" \
    '{"range": {"first": "192.0.2.170", "last": "192.0.2.175"}, "lease": {"default_secs": 120, "min_secs": 120, "max_secs": 120}}' \
    "[$(text_option 15 iot.example.test)]"
  new_policy "$servers" ops 1 "$ops" \
    '{"range": {"first": "192.0.2.50", "last": "192.0.2.54"}}' \
    "[$(text_option 15 ops.example.test)]"
  ok "classes" "three classes (vendor class, MAC wildcard, user class) and a policy each"
  for net in guest iot servers; do
    fresh "$net"
  done
  row "class.vendor" "vendor class Printer-Lab-1 on guest: an address of .230 to .234, option 15 printers.example.test" \
    within 30 class_lease_ok guest dhclient-printer.conf 192.0.2.230 192.0.2.234 printers.example.test
  row "class.mac-wildcard" "MAC 00:00:5e:00:*:85 on iot: an address of .170 to .175, option 15 iot.example.test, 120 s" \
    within 30 class_lease_ok iot dhclient.conf 192.0.2.170 192.0.2.175 iot.example.test 120
  row "class.user" "user class lab-ops on servers: an address of .50 to .54, option 15 ops.example.test" \
    within 30 class_lease_ok servers dhclient-ops.conf 192.0.2.50 192.0.2.54 ops.example.test
}

boot_log_has() { pxe_compose exec -T bootsrv grep -q -F -- "$2" "/run/lab/$1.log"; }
http_fetch_ok() {
  compose exec -T tester python3 -c 'import sys, urllib.request; sys.exit(0 if urllib.request.urlopen(sys.argv[1], timeout=5).status == 200 else 1)' "$1"
}

# pxe_boot_ok <bios|uefi>: the machine boots to the menu: it fetched /done over HTTP with
# its platform and MAC address within PXE_WAIT_SECS, after its boot script by TFTP.
pxe_boot_ok() {
  local vm="$1" mac
  mac="${vm_mac[$vm]//:/-}"
  pxe_compose up -d "pxe-$vm" >/dev/null 2>&1 || return 1
  within "$pxe_wait" boot_log_has http "GET /done?platform=${vm_platform[$vm]}&mac=$mac" &&
    boot_log_has tftp "boot.ipxe"
}

# pxe_lease_ok <bios|uefi>: the machine's lease row holds its architecture (option 93: 0
# for BIOS, 7 or 9 for UEFI x64) and the PXEClient vendor class.
pxe_lease_ok() {
  api GET "/dhcp/leases?limit=1000" >/dev/null || return 1
  python3 - "$work/api.out" "${vm_mac[$1]}" "${vm_arch[$1]}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
want = sys.argv[2].replace(":", "").lower()
def mac(lease):
    return str(lease["client"]["chaddr"]).replace(":", "").replace("-", "").lower()
rows = [l for l in d["items"] if mac(l) == want]
arches = {int(a) for a in sys.argv[3].split()}
ok = any((l.get("fingerprint") or {}).get("architecture") in arches
         and (l["fingerprint"].get("vendor_class") or "").startswith("PXEClient") for l in rows)
print(rows[:1])
sys.exit(0 if ok else 1)
PY
}

pxe_rows() {
  local lan ipxe http uefi bios
  step "E27: network boot"
  if [[ -z "${PXE_IMAGE_PREBUILT:-}" ]]; then
    docker build -f "$here/pxe.Dockerfile" -t "$PXE_IMAGE" "$here"
  fi
  lan="$(scope_of lan)" || fail "the scope of lan"
  must "the boot server of lan" api PUT "/dhcp/option-sets/scope:$lan" \
    "{\"values\": [{\"code\": 3, \"typed\": {\"ipv4\": {\"values\": [\"${gateway[lan]}\"]}}}, {\"code\": 150, \"typed\": {\"ipv4\": {\"values\": [\"$boot_ip\"]}}}]}"
  ipxe="$(new_class ipxe '[{"user_class": {"value": "iPXE"}}]')"
  http="$(new_class http-boot '[{"vendor_class": {"value": "HTTPClient", "prefix": true}}]')"
  uefi="$(new_class uefi '[{"architecture": {"code": 7}}, {"architecture": {"code": 9}}]')"
  bios="$(new_class bios '[{"architecture": {"code": 0}}]')"
  new_policy "$lan" ipxe 1 "$ipxe" '{}' "[$(text_option 67 boot.ipxe)]"
  new_policy "$lan" http-boot 2 "$http" '{}' "[$(text_option 67 "http://$boot_ip/ipxe.efi")]"
  new_policy "$lan" uefi 3 "$uefi" '{}' "[$(text_option 67 ipxe.efi)]"
  new_policy "$lan" bios 4 "$bios" '{}' "[$(text_option 67 undionly.kpxe)]"
  pxe_compose up -d bootsrv
  retry 60 "the boot server" http_fetch_ok "http://$boot_ip/boot.ipxe"
  ok "boot" "the boot policies of lan, option 150 $boot_ip, the boot server (TFTP and HTTP)"
  row "pxe.bios" "QEMU in BIOS mode with its iPXE ROM boots to the menu: boot.ipxe by TFTP, the menu by HTTP" \
    pxe_boot_ok bios
  row "pxe.bios.lease" "the BIOS machine's lease row holds architecture 0 and PXEClient" pxe_lease_ok bios
  pxe_compose stop pxe-bios >/dev/null 2>&1 || true
  row "pxe.uefi" "QEMU in UEFI mode (OVMF) boots to the menu: by TFTP and HTTP" pxe_boot_ok uefi
  row "pxe.uefi.lease" "the UEFI machine's lease row holds architecture 7 or 9 and PXEClient" pxe_lease_ok uefi
  pxe_compose stop pxe-uefi >/dev/null 2>&1 || true
  http_boot_ok() {
    relay_test "${prefix[lan]}" --link "${prefix[lan]%/*}" --mac 00:00:5e:00:53:a2 \
      --circuit tester --vendor-class HTTPClient:Arch:00016:UNDI:003001 --arch 16 \
      --expect-file "http://$boot_ip/ipxe.efi" --expect-vendor HTTPClient --release &&
      http_fetch_ok "http://$boot_ip/ipxe.efi"
  }
  row "pxe.http-boot" "a UEFI HTTP boot client gets its URL in file and option 60 HTTPClient, and fetches it" \
    http_boot_ok
  row "pxe.proxy" "proxy DHCP on 4011 answers the boot server discovery: no address, ipxe.efi" \
    relay_test "${prefix[lan]}" --link "${prefix[lan]%/*}" --mac 00:00:5e:00:53:a3 \
    --circuit tester --vendor-class PXEClient:Arch:00007:UNDI:003016 --arch 7 \
    --expect-file ipxe.efi --proxy-port 4011 --release
}
# End WP8.4.

# ---------------------------------------------------------------------------------------
# Build and start

if ((build_tools)); then
  step "build the tools image $TOOLS_IMAGE"
  docker build -f "$here/tools.Dockerfile" -t "$TOOLS_IMAGE" "$here"
fi
ok "tools" "$TOOLS_IMAGE (dhcrelay, dhclient, perfdhcp, udhcpc)"

if [[ "$node" == tenko ]]; then
  if ((build_tenko)); then
    step "build $TENKO_IMAGE from deploy/Dockerfile (the static musl binary)"
    docker build -f "$repo/deploy/Dockerfile" -t "$TENKO_IMAGE" "$repo"
  else
    docker image inspect "$TENKO_IMAGE" >/dev/null 2>&1 || fail "image $TENKO_IMAGE not found"
  fi
  ok "image" "$TENKO_IMAGE"
else
  if ((build_example)); then
    step "build $EXAMPLE_IMAGE from example.Dockerfile (the example server, static musl)"
    docker build -f "$here/example.Dockerfile" -t "$EXAMPLE_IMAGE" "$repo"
  else
    docker image inspect "$EXAMPLE_IMAGE" >/dev/null 2>&1 || fail "image $EXAMPLE_IMAGE not found"
  fi
  ok "image" "$EXAMPLE_IMAGE (the example server, not the binary)"
fi

work="$(mktemp -d)"
export LAB_DIR="$work"
mkdir -p "$work/secrets"
head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/kek"
chmod 0444 "$work/secrets/kek"
cat >"$work/tenko.toml" <<TOML
# The DHCP lab's node (written by smoke.sh).
roles = "controller,dhcp"
modules = ["ipam", "dhcp"]

[profile]
# The Lab profile: plain HTTP is allowed.
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["0.0.0.0:8443"]

[dhcp]
# Relay mode on the node's address: the gateway relays every network, the node's own too.
listen = [{ address = "$node_ip", mode = "relay" }]
workers = 2
# WP8.4: the proxy DHCP listener of E27's PXE rows, on port 4011.
proxy = ["$node_ip"]
TOML
chmod 0444 "$work/tenko.toml"
chmod 0755 "$work"
compose config --quiet
# A lab left over from an interrupted run goes first.
compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true

step "start the gateway, the node and the clients"
compose up -d
if [[ "$node" == tenko ]]; then
  retry "$wait_secs" "tenko to become healthy" healthy
  lab_setup
  configure
else
  retry 60 "the example server to start" \
    sh -c "docker compose -f '$compose_file' --profile example logs node-example 2>&1 | grep -q serving"
fi
# The gateway renames its interfaces and starts dhcrelay.
retry 60 "dhcrelay to start" sh -c "docker compose -f '$compose_file' --profile '$node' logs relay 2>&1 | grep -q 'Sending on'"
ok "lab" "gateway, node ($node), four clients and the tester are up"

# ---------------------------------------------------------------------------------------
# The rows

step "rows"
if [[ "$node" == tenko ]]; then
  for net in "${networks[@]}"; do
    row "lease.$net" "a client on $net gets ${prefix[$net]} through the relay with options 3, 6, 42" lease_ok "$net"
  done
  for net in "${networks[@]}"; do
    row "relay.$net" "the lease row on $net holds giaddr ${gateway[$net]} and circuit-id $net (option 82)" relay_on_lease "$net"
  done
  row "link-selection" "option 82 link selection from servers picks the iot scope, echoed" \
    relay_test "${prefix[iot]}" --link "${prefix[iot]%/*}" --mac 00:00:5e:00:53:21 --circuit tester --release
  row "perfdhcp" "perfdhcp as a relay: 10 4-way exchanges, no drops" perfdhcp_ok 10
  row "udhcpc" "BusyBox udhcpc on servers gets an address of the pool" udhcpc_ok servers
  for net in "${networks[@]}"; do
    row "renew.$net" "the client on $net renews its address at T1 through the gateway" within 60 renewed "$net"
  done

  step "a reservation for client-lan's MAC at $reserved_ip"
  must "the reserved host" api POST /hosts \
    "{\"name\": \"lab-reserved\", \"mode\": \"reserved\", \"interfaces\": [{\"name\": \"eth0\", \"mac\": \"${client_mac[lan]}\"}]}"
  host="$(field "d['item']['id']" <"$work/api.out")"
  must "the reserved host's interface" api GET "/hosts/$host/interfaces"
  iface="$(field "d['items'][0]['id']" <"$work/api.out")"
  must "the reserved address" api POST /addresses "{\"ip\": \"$reserved_ip\", \"interface\": \"$iface\"}"
  dhclient_in client-lan -r >/dev/null 2>&1 || true
  forget client-lan
  reserved_ok() {
    dhclient_in client-lan -1 >/dev/null 2>&1 || return 1
    [[ "$(last_event lan | event_field ip)" == "$reserved_ip" ]]
  }
  row "reservation" "a reservation wins: client-lan gets $reserved_ip after its dynamic lease" within 30 reserved_ok
  leased[lan]="$reserved_ip"

  step "a deny filter for client-guest's MAC"
  must "the deny filter" api POST /dhcp/filters "{\"mac\": \"${client_mac[guest]}\", \"kind\": \"deny\", \"note\": \"lab\"}"
  filter="$(field "d['id']" <"$work/api.out")"
  dhclient_in client-guest -r >/dev/null 2>&1 || true
  # Without its lease file dhclient starts with a DISCOVER and has no old lease to fall
  # back to when nobody answers.
  forget client-guest
  denied() { ! dhclient_in client-guest -1 >/dev/null 2>&1; }
  row "filter.deny" "a deny filter: client-guest gets no lease" denied
  must "the filter's removal" api DELETE "/dhcp/filters/$filter"
  row "filter.removed" "without the filter client-guest gets a lease again" within 30 lease_ok guest

  step "a release from client-iot"
  released_ip="${leased[iot]}"
  dhclient_in client-iot -r >/dev/null 2>&1 || true
  row "release" "dhclient -r: the lease of $released_ip is released" within 10 lease_state_is "$released_ip" released

  step "restart the node"
  active_leases >"$work/leases.before" || fail "the lease list"
  [[ -s "$work/leases.before" ]] || fail "no active lease before the restart"
  compose restart tenko
  retry "$wait_secs" "tenko to become healthy again" healthy
  row "restart.leases" "after a restart the node still holds the $(wc -l <"$work/leases.before") active leases for their clients" within 30 every_lease_kept
  kept_address() {
    # Stop the running dhclient without a release; the lease file keeps the address.
    dhclient_in client-lan -x >/dev/null 2>&1 || true
    dhclient_in client-lan -1 >/dev/null 2>&1 || return 1
    [[ "$(last_event lan | event_field ip)" == "$reserved_ip" ]]
  }
  row "restart.client" "after the restart client-lan asks again (INIT-REBOOT) and keeps $reserved_ip" kept_address

  # WP8.4: E27's class and PXE rows.
  class_rows
  if [[ "$pxe_rows" == 1 ]]; then
    pxe_rows
  else
    skip "pxe" "PXE=0: the network boot rows are left out"
  fi
else
  for net in "${networks[@]}"; do
    skip "lease.$net" "the example server has one scope, which giaddr on $net does not select"
  done
  row "subnet-selection" "relay-test with option 118: offer, ack, renewal, release in $example_net, option 82 echoed" \
    relay_test "$example_net" --subnet-selection "$example_link" --mac 00:00:5e:00:53:21 --renew --release
  row "link-selection" "relay-test with option 82 link selection: the scope of $example_net, echoed" \
    relay_test "$example_net" --link "$example_link" --mac 00:00:5e:00:53:22 --release
  row "perfdhcp" "perfdhcp as a relay with option 118: 50 4-way exchanges, no drops" \
    perfdhcp_ok 50 -o "118,c6120000"
  skip "renew, reservation" "need the configuration service: the binary (NODE=tenko)"
  skip "filter, release" "need the configuration service and the lease routes: the binary"
  skip "restart" "the example server keeps its leases in memory"
  # WP8.4: E27's class and PXE rows need the configuration service.
  skip "class, pxe" "classes, policies and network boot need the configuration service: the binary"
fi

((rows_failed == 0)) || fail "$rows_failed row(s) failed"
step "OK: the DHCP lab passed (node: $node)"
