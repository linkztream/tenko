#!/usr/bin/env bash
# The DHCP lab's rows, run from inside the lab network: smoke.sh (on the host) starts the
# driver container (the service `driver`, deploy/compose/driver) and runs this script in it
# with driver/host.sh lab_run, once per round: ROUNDS=dhcp6 in the round's own project
# (compose.dhcp6.yml, dhcp6.sh), ROUNDS=default in the project of compose.yml. smoke.sh's
# header lists the steps and the settings; this script calls the node's API at its address
# on the lab network (curl), writes the files of the run into the lab volume (/work), and
# asks the host with ctl (driver/ctl.sh) for every container operation: starting and
# stopping services, their health and logs, the setup token, the clients' dhclient,
# udhcpc and networkd, the tester's relay agents and perfdhcp, the Kea checks.
#
# The environment smoke.sh passes: ROUNDS (one round), NODE, WAIT_SECS, PXE, PXE_WAIT_SECS,
# KEA, and the image names for the summary (TOOLS_IMAGE, TENKO_IMAGE, EXAMPLE_IMAGE,
# NETWORKD_IMAGE, TENKO_PROBE_IMAGE).

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/compose/driver/ctl.sh
source "$here/../driver/ctl.sh"

node="${NODE:-tenko}"
wait_secs="${WAIT_SECS:-300}"
rounds="${ROUNDS:-default}"
run_dhcp6=0
case "$rounds" in
  default) ;;
  dhcp6) run_dhcp6=1 ;;
  *) printf 'smoke: the driver runs one round, default or dhcp6, not %s\n' "$rounds" >&2; exit 2 ;;
esac
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

# The lab volume, and in it the node's files (/lab in the node) and its key (/run/secrets).
work=/work
node_dir="$work/node"
cookie=""
status=0
rows_failed=0
summary=()

# admin_password: a random password for a lab administrator. An administrator's password has
# at least 12 characters and is not digits only, in every profile.
admin_password() { printf 'Lab-%s-Aa1' "$(od -An -N9 -tx1 /dev/urandom | tr -d ' \n')"; }

# WP9.1: the round dhcp6 (ROUNDS=dhcp6): its functions only; it runs in dhcp6_round below.
# shellcheck source=deploy/compose/lab-dhcp/dhcp6.sh
source "$here/dhcp6.sh"

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'smoke: %s\n' "$*" >&2; exit 1; }
ok() {
  local line
  line="$(printf 'ok   %-22s %s' "$1" "$2")"
  summary+=("$line")
  printf '%s\n' "$line"
}

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

# At the end, also after a failure: the summary lines to the host, which prints them after
# the services' logs. A round whose rows failed but that ran to its end exits 3, so that
# smoke.sh goes on to the next round as it did when both ran in one script.
cleanup() {
  status=$?
  set +e
  trap - EXIT
  local line
  for line in "${summary[@]}"; do
    lab_summary "$line"
  done
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
  ctl exec "$service" -- dhclient -v -cf /lab/dhclient.conf -sf /lab/client-script.sh \
    -lf /run/lab/dhclient.leases -pf /run/lab/dhclient.pid "$@" eth0
}
# The last event line of a client's script (client-script.sh), and a field of it.
last_event() { ctl exec "client-$1" -- sh -c 'tail -n 1 /run/lab/events 2>/dev/null' | tr -d '\r'; }
event_field() { sed -n "s/.* $1=\\([^ ]*\\).*/\\1/p"; }
forget() { ctl exec "$1" -- rm -f /run/lab/dhclient.leases; }
events_of() { ctl exec "client-$1" -- sh -c 'cat /run/lab/events 2>/dev/null' | tr -d '\r'; }

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

healthy() { ctl healthy tenko; }

lab_setup() {
  local token password setup
  token="$(ctl setup-token tenko | tr -d '\r\n')"
  [[ -n "$token" ]] || fail "setup: no setup token"
  password="$(admin_password)"
  setup="{\"setup_token\": \"$token\", \"profile\": \"lab\", \"admin\": {\"name\": \"labadmin\", \"display_name\": \"Lab Admin\", \"password\": \"$password\"}, \"host_name\": \"tenko.example.test\", \"language\": \"en\"}"
  cookie="$(curl -sS -D - -o "$work/api.out" -H "Origin: $api_base" -H "Content-Type: application/json" \
    --data "$setup" "$api_base/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(\(__Host-\)\{0,1\}tenko_session=[^;]*\).*/\1/p' | head -n 1)"
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
  # The gateway is the one trusted relay agent, bound to the lab's networks (all four in
  # 192.0.2.0/24); the tester joins it in the rows below.
  must "the trusted relays" api PUT /dhcp/settings \
    "{\"trusted_relays\": [{\"relay\": \"${gateway[servers]}/32\", \"links\": [\"192.0.2.0/24\"]}]}"
  ok "configuration" "four prefixes with a pool and a scope each, options 3, 6, 15 and 42, the gateway as the trusted relay"
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
  ctl exec tester -- python3 /lab/relay-test.py --server "$node_ip" --giaddr "$tester_ip" \
    --expect "$expect" "$@"
}

# untrusted_refused: relay-test.py from the tester, which is not a trusted relay, gets no
# answer, and GET /system/status names the tester in dhcp.relay.untrusted.
untrusted_refused() {
  if relay_test "${prefix[iot]}" --link "${prefix[iot]%/*}" --mac 00:00:5e:00:53:2a \
    --timeout 2 >/dev/null 2>&1; then
    return 1
  fi
  api GET /system/status >/dev/null || return 1
  python3 - "$work/api.out" "$tester_ip" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
rows = [w for w in d.get("warnings", []) if w.get("code") == "dhcp.relay.untrusted"]
print(json.dumps(rows), file=sys.stderr)
sys.exit(0 if any(sys.argv[2] in w.get("params", {}).get("senders", "") for w in rows) else 1)
PY
}

# offers_limited: with an offer rate of 2 new clients a second per scope (a burst of 20),
# perfdhcp's 40 new clients at once are not all answered, and GET /system/status names the
# limit in dhcp.limit.refused; the limits go back to the profile (none under Lab) after.
offers_limited() {
  local result=0
  must "an offer rate of 2 a second" api PUT /dhcp/settings '{"limits": {"offers_per_second": 2}}'
  if perfdhcp_ok 40; then
    result=1
  elif api GET /system/status >/dev/null; then
    python3 - "$work/api.out" <<'PY' || result=1
import json, sys
d = json.load(open(sys.argv[1]))
rows = [w for w in d.get("warnings", []) if w.get("code") == "dhcp.limit.refused"]
print(json.dumps(rows), file=sys.stderr)
sys.exit(0 if any("offers_per_second" in w.get("params", {}).get("limits", "") for w in rows) else 1)
PY
  else
    result=1
  fi
  must "the limits back to the profile" api PUT /dhcp/settings '{"limits": {}}'
  pool_state servers
  # The burst's clients (and the ten of the row perfdhcp) hold every address of the servers
  # pool left until their 60 s leases end, and they never come back: their leases are
  # released, so that the next new client of the pool (the row udhcpc) gets an address.
  release_strangers servers
  pool_state servers
  return "$result"
}

# perfdhcp_ok <clients> [<options...>]: perfdhcp as a relay from the tester, every 4-way
# exchange answered (no drops in DISCOVER-OFFER or REQUEST-ACK).
perfdhcp_ok() {
  local n="$1" out
  shift
  out="$(ctl exec tester --merge -- perfdhcp -4 -l "$tester_ip" -r "$n" -R "$n" -n "$n" -p 30 \
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

# pool_state <network>: for the log, the active leases in the network's pool (of how many
# addresses) and the node's counters of requests dropped for a full pool and for a limit.
pool_state() {
  api GET "/dhcp/leases?limit=1000" >/dev/null || return 0
  python3 - "$work/api.out" "${pool_first[$1]}" "${pool_last[$1]}" <<'PY' >&2
import ipaddress, json, sys
d = json.load(open(sys.argv[1]))
first, last = (ipaddress.IPv4Address(x) for x in sys.argv[2:4])
active = [l for l in d["items"] if l["state"] == "active" and first <= ipaddress.ip_address(l["addr"]) <= last]
print("pool %s-%s: %d of %d addresses in active leases" % (first, last, len(active), int(last) - int(first) + 1))
PY
  api GET /metrics >/dev/null &&
    grep -E '^tenko_dhcp_dropped_total\{reason="(pool_full|limited)"' "$work/api.out" >&2 || true
}

# release_strangers <network>: releases the active leases in the network's pool whose client
# is none of the lab's own clients (POST /dhcp/leases/{addr}/release).
release_strangers() {
  local addr
  api GET "/dhcp/leases?limit=1000" >/dev/null || fail "the lease list ($api_status)"
  for addr in $(python3 - "$work/api.out" "${pool_first[$1]}" "${pool_last[$1]}" "${client_mac[@]}" <<'PY'
import ipaddress, json, sys
d = json.load(open(sys.argv[1]))
first, last = (ipaddress.IPv4Address(x) for x in sys.argv[2:4])
own = {m.replace(":", "").lower() for m in sys.argv[4:]}
for l in d["items"]:
    mac = str(l["client"]["chaddr"]).replace(":", "").replace("-", "").lower()
    if l["state"] == "active" and first <= ipaddress.ip_address(l["addr"]) <= last and mac not in own:
        print(l["addr"])
PY
  ); do
    must "the release of $addr" api POST "/dhcp/leases/$addr/release"
  done
}

# udhcpc_ok <network>: BusyBox's udhcpc gets an address of the network's pool (it quits
# with the lease, -q, and leaves the interface alone, -s /bin/true).
udhcpc_ok() {
  local out
  out="$(ctl exec "client-$1" --merge -- busybox udhcpc -i eth0 -n -q -t 5 -T 2 -s /bin/true 2>&1)" || {
    printf '%s\n' "$out" >&2
    pool_state "$1"
    return 1
  }
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
boot_ip=192.0.2.21
declare -A vm_mac=([bios]=00:00:5e:00:53:a0 [uefi]=00:00:5e:00:53:a1)
declare -A vm_platform=([bios]=pcbios [uefi]=efi)
declare -A vm_arch=([bios]=0 [uefi]="7 9")
# The machines run with KVM where the host has it (smoke.sh adds compose.kvm.yml).

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
  ctl exec "client-$net" -- dhclient -v -cf "/lab/$2" -sf /lab/client-script.sh \
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

boot_log_has() { ctl exec bootsrv -- grep -q -F -- "$2" "/run/lab/$1.log"; }
http_fetch_ok() {
  ctl exec tester -- python3 -c 'import sys, urllib.request; sys.exit(0 if urllib.request.urlopen(sys.argv[1], timeout=5).status == 200 else 1)' "$1"
}

# pxe_boot_ok <bios|uefi>: the machine boots to the menu: it fetched /done over HTTP with
# its platform and MAC address within PXE_WAIT_SECS, after its boot script by TFTP.
pxe_boot_ok() {
  local vm="$1" mac
  mac="${vm_mac[$vm]//:/-}"
  ctl up "pxe-$vm" >/dev/null 2>&1 || return 1
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
  # smoke.sh built the pxe image (PXE_IMAGE) before the run.
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
  ctl up bootsrv >/dev/null
  retry 60 "the boot server" http_fetch_ok "http://$boot_ip/boot.ipxe"
  ok "boot" "the boot policies of lan, option 150 $boot_ip, the boot server (TFTP and HTTP)"
  row "pxe.bios" "QEMU in BIOS mode with its iPXE ROM boots to the menu: boot.ipxe by TFTP, the menu by HTTP" \
    pxe_boot_ok bios
  row "pxe.bios.lease" "the BIOS machine's lease row holds architecture 0 and PXEClient" pxe_lease_ok bios
  ctl stop pxe-bios >/dev/null 2>&1 || true
  row "pxe.uefi" "QEMU in UEFI mode (OVMF) boots to the menu: by TFTP and HTTP" pxe_boot_ok uefi
  row "pxe.uefi.lease" "the UEFI machine's lease row holds architecture 7 or 9 and PXEClient" pxe_lease_ok uefi
  ctl stop pxe-uefi >/dev/null 2>&1 || true
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
# WP9.3: E30's DHCPv4 rows (docs/dhcp.md section 18), with the binary only. The node's
# configuration as it stands after the rows above (four scopes, a reservation, classes and
# policies, the boot policies when the PXE rows ran) plus one policy whose DDNS action Kea
# cannot express is exported with its leases through GET /dhcp/export. Kea 2.6 (the kea
# profile, kea.Dockerfile) checks the configuration with `kea-dhcp4 -t`; the report must
# name the policy; then the node stops and Kea starts from the export on the node's
# address: client-lan gets its reservation with options 3 and 6, and client-iot keeps
# the address of its exported lease. KEA=0 leaves the rows out.

kea_rows_on="${KEA:-1}"

# kea_files: the export's answer in $work/export.json split into the files the command
# line writes (tenko dhcp export --out).
kea_files() {
  python3 - "$work/export.json" "$work/kea" <<'PY'
import json, os, sys
answer = json.load(open(sys.argv[1]))
out = sys.argv[2]
os.makedirs(out, exist_ok=True)
json.dump(answer["dhcp4"], open(os.path.join(out, "kea-dhcp4.json"), "w"), indent=2)
open(os.path.join(out, "kea-leases4.csv"), "w").write(answer.get("leases4_csv") or "")
json.dump({"entries": answer.get("losses", [])}, open(os.path.join(out, "kea-export-report.json"), "w"), indent=2)
PY
  chmod -R a+rX "$work/kea"
}

# kea_check: kea-dhcp4 -t on the exported configuration, in a container of the Kea image
# without a network (the host runs it, with the lab volume's kea/ at /lab/kea).
kea_check() {
  local status=0
  ctl kea-check 4 >"$work/kea-check.out" 2>&1 || status=$?
  cat "$work/kea-check.out" >&2
  return "$status"
}
kea_listens() { [[ "$(ctl logs kea)" == *DHCP4_STARTED* ]]; }

# report_names <code> <text>: an entry of the loss report with the code names the text.
report_names() {
  python3 - "$work/kea/kea-export-report.json" "$1" "$2" <<'PY'
import json, sys
entries = json.load(open(sys.argv[1]))["entries"]
hits = [e for e in entries if e["code"] == sys.argv[2] and sys.argv[3] in (e["location"].get("sheet") or "")]
print(hits or entries)
sys.exit(0 if hits else 1)
PY
}

# exported_lease <mac>: the address of the client's lease in the exported lease file.
exported_lease() {
  awk -F, -v mac="$1" '$2 == mac && $10 == 0 { print $1 }' "$work/kea/kea-leases4.csv" | head -n 1
}

kea_rows() {
  local lan names iot_ip version
  step "E30: the Kea export"
  # smoke.sh built the kea image (KEA_IMAGE) before the run.
  version="$(ctl kea-version 4 2>/dev/null | sed -n 1p | tr -d '\r')"
  lan="$(scope_of lan)" || fail "the scope of lan"
  names="$(new_class lab-names '[{"host_name": {"value": "lab-", "prefix": true}}]')"
  new_policy "$lan" lab-names 9 "$names" '{"ddns": {"enabled": true}}' '[]'
  must "the export" api GET "/dhcp/export?format=kea&leases=true"
  cp "$work/api.out" "$work/export.json"
  kea_files || fail "the export's files"
  ok "export" "GET /dhcp/export: $(wc -l <"$work/kea/kea-leases4.csv") lease file line(s), Kea image $version"
  row "export.kea" "kea-dhcp4 -t ($version) accepts the exported configuration" kea_check
  row "export.kea.report" "the loss report names the policy lab-names, whose DDNS action Kea cannot express" \
    report_names export.kea.policy.ddns lab-names
  iot_ip="$(exported_lease "${client_mac[iot]}")"
  step "stop the node and start Kea from the export on $node_ip"
  ctl stop tenko >/dev/null
  ctl up kea >/dev/null
  retry 60 "Kea to listen" kea_listens
  kea_reserved_ok() {
    local line
    dhclient_in client-lan -x >/dev/null 2>&1 || true
    forget client-lan
    dhclient_in client-lan -1 >/dev/null 2>&1 || return 1
    line="$(last_event lan)"
    printf 'lan: %s\n' "$line" >&2
    [[ "$(event_field ip <<<"$line")" == "$reserved_ip" ]] &&
      [[ "$(event_field routers <<<"$line")" == "${gateway[lan]}" ]] &&
      [[ "$(event_field dns <<<"$line")" == "$dns_server" ]]
  }
  row "export.kea.reservation" "Kea from the export gives client-lan its reservation $reserved_ip with options 3 and 6" \
    within 60 kea_reserved_ok
  kea_lease_ok() {
    local line
    [[ -n "$iot_ip" ]] || return 1
    dhclient_in client-iot -x >/dev/null 2>&1 || true
    dhclient_in client-iot -1 >/dev/null 2>&1 || return 1
    line="$(last_event iot)"
    printf 'iot: %s (exported %s)\n' "$line" "$iot_ip" >&2
    [[ "$(event_field ip <<<"$line")" == "$iot_ip" ]]
  }
  row "export.kea.lease" "client-iot keeps ${iot_ip:-its address} from the exported lease file (INIT-REBOOT to Kea)" \
    within 60 kea_lease_ok
  ctl logs kea | tail -n 40 >&2 || true
  ctl stop kea >/dev/null 2>&1 || true
}
# End WP9.3.

# ---------------------------------------------------------------------------------------
# Start (smoke.sh built the images and started this driver)

# Once per smoke: the second round's driver has TOOLS_LINE=0.
if [[ "${TOOLS_LINE:-1}" == 1 ]]; then
  ok "tools" "$TOOLS_IMAGE (dhcrelay, dhclient, perfdhcp, udhcpc)"
fi

# WP9.1: the round dhcp6 (dhcp6.sh), in its own compose project; smoke.sh runs it first.
if ((run_dhcp6)); then
  dhcp6_round
  if ((rows_failed > 0)); then
    # The round ran to its end: smoke.sh prints its logs, goes on to the next round and
    # fails at the end.
    printf 'smoke: %s row(s) failed\n' "$rows_failed" >&2
    lab_rows_failed "$rows_failed"
    exit 0
  fi
  step "OK: the round dhcp6 passed"
  exit 0
fi

if [[ "$node" == tenko ]]; then
  ok "image" "$TENKO_IMAGE"
else
  ok "image" "$EXAMPLE_IMAGE (the example server, not the binary)"
fi

mkdir -p "$work/secrets" "$node_dir"
head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/kek"
chmod 0444 "$work/secrets/kek"
cat >"$node_dir/tenko.toml" <<TOML
# The DHCP lab's node (written by driver.sh).
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
chmod 0444 "$node_dir/tenko.toml"
chmod 0755 "$work" "$work/secrets" "$node_dir"

example_serving() { [[ "$(ctl logs node-example)" == *serving* ]]; }
relay_sending() { [[ "$(ctl logs relay)" == *'Sending on'* ]]; }

step "start the gateway, the node and the clients"
if [[ "$node" == tenko ]]; then
  ctl up relay netns tenko client-servers client-lan client-iot client-guest tester >/dev/null
  retry "$wait_secs" "tenko to become healthy" healthy
  lab_setup
  configure
else
  ctl up relay netns node-example client-servers client-lan client-iot client-guest tester >/dev/null
  retry 60 "the example server to start" example_serving
fi
# The gateway renames its interfaces and starts dhcrelay.
retry 60 "dhcrelay to start" relay_sending
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
  row "relay.untrusted" "the tester, not a trusted relay, is refused and named in dhcp.relay.untrusted" \
    untrusted_refused
  must "the tester as a trusted relay" api PUT /dhcp/settings \
    "{\"trusted_relays\": [{\"relay\": \"${gateway[servers]}/32\", \"links\": [\"192.0.2.0/24\"]}, {\"relay\": \"$tester_ip/32\", \"links\": [\"192.0.2.0/24\"]}]}"
  row "link-selection" "option 82 link selection from servers picks the iot scope, echoed" \
    relay_test "${prefix[iot]}" --link "${prefix[iot]%/*}" --mac 00:00:5e:00:53:21 --circuit tester --release
  row "perfdhcp" "perfdhcp as a relay: 10 4-way exchanges, no drops" perfdhcp_ok 10
  row "limit.offers" "an offer rate of 2 a second holds back a burst of 40 new clients and is named in dhcp.limit.refused (the limit and the burst's leases are undone after)" \
    offers_limited
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
  ctl restart tenko >/dev/null
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
  # WP9.3: E30's DHCPv4 rows, last: they stop the node.
  if [[ "$kea_rows_on" == 1 ]]; then
    kea_rows
  else
    skip "export.kea" "KEA=0: the Kea export rows are left out"
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
