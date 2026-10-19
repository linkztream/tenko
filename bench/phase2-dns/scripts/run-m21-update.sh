#!/usr/bin/env bash
# M21 (dynamic update rate end to end, docs/plans/phase-2-plan.md section 6): 1,000 RFC 2136
# updates per second sustained for 60 s against one node, the p99 from the send of an update
# to its answer under 250 ms.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# (or the binary of the container image, docker cp from tenko:<tag>:/usr/local/bin/tenko).
# A dynamically linked --server-binary is refused with a warning (--allow-dynamic overrides;
# the run is then marked not publishable). Windows runs (Git Bash) use the release build.
# Every figure is a single-node figure (plan section 2.10) and, with the load generator on the
# same host, a loopback figure: an upper bound, labelled so.
#
# 1. A new node: `tenko serve --roles controller,dns` with an empty data directory, the API
#    on loopback (reverse-proxy mode, plain HTTP from the trusted loopback), the DNS role on
#    --dns-port of loopback, the metrics listener on --metrics-port.
# 2. Setup through the API with curl under the Home profile (the Standard profile asks an
#    administrator for a second factor first; for updates both follow the zone's require_tsig,
#    TGL-09); a TSIG key `update.example.test` (hmac-sha256, a secret generated for the run)
#    imported; an access list naming the key; the primary zone example.test with that list
#    in update.allowed and require_tsig.
# 3. The load: the example update_load of tenko-dns (--load PATH, built with
#    `cargo build -p tenko-dns --release --example update_load`): --rate updates per second
#    (default 1000) for --duration seconds (default 60) after --warmup seconds (default 5),
#    paced, signed with the key, each replacing the A RRset of one of --names owners (default
#    1000); every answer checked for its RCODE and its TSIG. Repeated --repeats times
#    (default 1) on the same node.
# 4. After the load: the node's RSS (Windows: the working set; Linux: VmRSS) and its update
#    counters (`tenko_dns_updates_total` from the metrics listener).
# Thresholds: every update answered NOERROR (none lost), the answered rate at least 99 % of
# --rate, the p99 under 250 ms.
#
# Usage: run-m21-update.sh --server-binary PATH --load PATH [options]
#   --rate N            updates per second (default 1000)
#   --duration SECS     measured seconds (default 60)
#   --warmup SECS       seconds before the measurement (default 5)
#   --names N           owners the updates rotate over (default 1000)
#   --repeats N         load runs on the node (default 1)
#   --loopback ADDR     the loopback address (default $PHASE2_DNS_LOOPBACK or 127.0.0.1)
#   --port N            the API port (default 18454)
#   --dns-port N        the DNS port (default 15354)
#   --dns-address ADDR  the address of the DNS role (default the loopback address; a local
#                       address of another interface where loopback drops UDP, as WSL2 in
#                       VirtioProxy mode does: the figure is then a same-host figure, noted)
#   --metrics-port N    the metrics listener's port (default 19464)
#   --label TEXT        a label for the result lines (default the OS and the binary's version)
#   --allow-dynamic     do not refuse a dynamically linked binary on Linux
#   --out FILE          result file (default results/raw/m21-<stamp>.jsonl)
#   --print-plan        print this text and exit
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER_BINARY=""; LOAD=""; RATE=1000; DURATION=60; WARMUP=5; NAMES=1000; REPEATS=1
LOOPBACK="${PHASE2_DNS_LOOPBACK:-127.0.0.1}"; PORT=18454; DNS_PORT=15354; METRICS_PORT=19464; DNS_ADDRESS=""
LABEL=""; ALLOW_DYNAMIC=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --load) LOAD="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --names) NAMES="$2"; shift 2 ;;
    --repeats) REPEATS="$2"; shift 2 ;;
    --loopback) LOOPBACK="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --dns-port) DNS_PORT="$2"; shift 2 ;;
    --dns-address) DNS_ADDRESS="$2"; shift 2 ;;
    --metrics-port) METRICS_PORT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --print-plan|-h|--help) sed -n '2,47p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SERVER_BINARY" ] || die "--server-binary PATH (tenko) is required"
[ -x "$SERVER_BINARY" ] || die "server binary not found: $SERVER_BINARY"
[ -n "$LOAD" ] || die "--load PATH (the update_load example of tenko-dns) is required"
[ -x "$LOAD" ] || die "load generator not found: $LOAD"
command -v curl >/dev/null 2>&1 || die "curl is required"
[ -n "$DNS_ADDRESS" ] || DNS_ADDRESS="$LOOPBACK"
LINUX=0
[ "$(uname -s)" = Linux ] && LINUX=1
URL="http://$LOOPBACK:$PORT"
ZONE="example.test"
KEY="update.example.test"

[ -n "$OUT" ] || OUT="$ROOT/results/raw/m21-$STAMP.jsonl"
mkdir -p "$(dirname "$OUT")"
META="${OUT%.jsonl}.meta.txt"
: > "$META"
WORK="$(mktemp -d)"
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }
VERSION="$("$SERVER_BINARY" --version 2>&1 | head -n 1)"
[ -n "$LABEL" ] || LABEL="$(uname -s) $VERSION"

note "run-m21-update: rate=$RATE/s duration=${DURATION}s warmup=${WARMUP}s names=$NAMES repeats=$REPEATS (loopback figures)"
note "$(machine_line)"
note "server: $VERSION at $SERVER_BINARY"
note "load: $LOAD"
check_linkage "$SERVER_BINARY" "$ALLOW_DYNAMIC"

SRV=""
stop_pid() {
  [ -n "$1" ] || return 0
  local winpid=""
  [ -r "/proc/$1/winpid" ] && winpid="$(cat "/proc/$1/winpid")"
  kill "$1" 2>/dev/null
  [ -z "$winpid" ] || taskkill //F //T //PID "$winpid" >/dev/null 2>&1
  wait "$1" 2>/dev/null
  return 0
}
cleanup() {
  local status=$?
  stop_pid "$SRV"; rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT

# The resident memory of the server in MiB.
rss_mib() {
  if [ "$LINUX" = 1 ]; then
    awk '/VmRSS/ { printf "%.1f", $2 / 1024 }' "/proc/$SRV/status" 2>/dev/null
  else
    local winpid; winpid="$(native_pid "$SRV")"
    tasklist //FI "PID eq $winpid" //FO CSV //NH 2>/dev/null |
      awk -F'","' '{ gsub(/[^0-9]/, "", $5); printf "%.1f", $5 / 1024 }'
  fi
}

COOKIE=""
# api <method> <path> [<json>]: a request with the session; the body in $WORK/api.out, the
# status in $API_STATUS; true for a 2xx status.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -o "$WORK/api.out" -w '%{http_code}' -X "$method" -H "Origin: $URL"
    -H "Idempotency-Key: m21-$RANDOM-$RANDOM-$RANDOM")
  [ -n "$COOKIE" ] && args+=(-H "Cookie: $COOKIE")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" --data "$body")
  API_STATUS="$(curl "${args[@]}" "$URL/api/v1$path")" || API_STATUS=000
  [ "${API_STATUS#2}" != "$API_STATUS" ]
}
# The first "id" of the JSON in $WORK/api.out.
first_id() { grep -o '"id": *"[^"]*"' "$WORK/api.out" | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/'; }

# 1. The node.
mkdir -p "$WORK/data"
cat > "$WORK/tenko.toml" <<TOML
data_dir = "$(native_path "$WORK")/data"
roles = "controller,dns"
modules = ["ipam", "dns"]

[server]
listen = ["$LOOPBACK:$PORT"]
allowed_origins = ["$URL"]

[tls]
mode = "reverse_proxy"
public_host = "localhost"
trusted_proxies = ["$LOOPBACK"]

[kek]
provider = "file"
path = "$(native_path "$WORK")/kek.key"

[hibp]
online = false

[updates]
air_gapped = true

[metrics]
listen = "$LOOPBACK:$METRICS_PORT"

[dns]
listen = ["$DNS_ADDRESS:$DNS_PORT"]
TOML
"$SERVER_BINARY" serve --config "$(native_path "$WORK/tenko.toml")" >> "${OUT%.jsonl}.server.log" 2>&1 &
SRV=$!
tries=300
while [ "$tries" -gt 0 ] && [ ! -s "$WORK/data/setup-token" ]; do sleep 0.2; tries=$((tries - 1)); done
[ -s "$WORK/data/setup-token" ] || die "the node did not write its setup token"
tries=100
while [ "$tries" -gt 0 ] && ! curl -sS -o /dev/null "$URL/api/v1/health" 2>/dev/null; do sleep 0.2; tries=$((tries - 1)); done

# 2. Setup, key, list, zone.
# The Home profile's password policy is a PIN of digits.
PASSWORD="7$(printf '%07d' $((RANDOM * RANDOM % 10000000)))"
SETUP="{\"setup_token\": \"$(head -n 1 "$WORK/data/setup-token" | tr -d '\r\n')\", \"profile\": \"home\", \"admin\": {\"name\": \"bench\", \"display_name\": \"Bench\", \"password\": \"$PASSWORD\"}, \"host_name\": \"localhost\", \"language\": \"en\"}"
COOKIE="$(curl -sS -D - -o "$WORK/api.out" -H "Origin: $URL" -H "Content-Type: application/json" \
  --data "$SETUP" "$URL/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)"
[ -n "$COOKIE" ] || die "the setup did not sign in: $(cat "$WORK/api.out")"
SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '\r\n')"
printf '%s\n' "$SECRET" > "$WORK/key.b64"
api POST /dns/keys "{\"name\": \"$KEY\", \"secret\": \"$SECRET\"}" || die "the key was refused ($API_STATUS): $(cat "$WORK/api.out")"
api POST /dns/acls "{\"name\": \"m21-updaters\", \"entries\": [{\"kind\": \"key\", \"name\": \"$KEY\"}]}" ||
  die "the access list was refused ($API_STATUS): $(cat "$WORK/api.out")"
ACL="$(first_id)"
api POST /dns/zones "{\"name\": \"$ZONE\", \"kind\": \"primary\", \"serial\": \"counter\", \"soa\": {\"mname\": \"ns1.example.test\", \"rname\": \"hostmaster.example.test\"}, \"name_servers\": [\"ns1.example.test\"], \"update\": {\"allowed\": [\"$ACL\"], \"require_tsig\": true, \"may_replace_ipam\": false}}" ||
  die "the zone was refused ($API_STATUS): $(cat "$WORK/api.out")"
note "node: $URL, DNS on $DNS_ADDRESS:$DNS_PORT, profile home, zone $ZONE with the key $KEY"
[ "$DNS_ADDRESS" = "$LOOPBACK" ] || note "the DNS role is on $DNS_ADDRESS, not on loopback: a same-host figure"

# The update path follows the zones and keys of the store: wait until one update goes through.
tries=50
until "$LOAD" --target "$DNS_ADDRESS:$DNS_PORT" --zone "$ZONE" --key "$KEY" --secret-file "$(native_path "$WORK/key.b64")" \
  --rate 10 --duration 1 --warmup 0 --names 10 --timeout 1000 2>/dev/null | grep -q '"noerror": [1-9]'; do
  tries=$((tries - 1))
  [ "$tries" -gt 0 ] || die "the node did not take updates"
  sleep 0.2
done

# 3. The load.
for repeat in $(seq 1 "$REPEATS"); do
  say "load $repeat/$REPEATS: $RATE/s for ${DURATION}s"
  "$LOAD" --target "$DNS_ADDRESS:$DNS_PORT" --zone "$ZONE" --key "$KEY" --secret-file "$(native_path "$WORK/key.b64")" \
    --rate "$RATE" --duration "$DURATION" --warmup "$WARMUP" --names "$NAMES" \
    --label "$LABEL run $repeat" --out "$(native_path "$OUT")" | tee -a "$META"
done

# 4. After the load.
note "rss after the load: $(rss_mib) MiB"
curl -sS "http://$LOOPBACK:$METRICS_PORT/metrics" 2>/dev/null | grep '^tenko_dns_update' | while read -r line; do note "metric: $line"; done
note "results: $OUT"
awk -v rate="$RATE" '
  {
    p99 = $0; sub(/.*"p99_ms": /, "", p99); sub(/[,}].*/, "", p99)
    lost = $0; sub(/.*"lost": /, "", lost); sub(/[,}].*/, "", lost)
    got = $0; sub(/.*"answered_per_s": /, "", got); sub(/[,}].*/, "", got)
    noerr = $0; sub(/.*"noerror": /, "", noerr); sub(/[,}].*/, "", noerr)
    sent = $0; sub(/.*"sent": /, "", sent); sub(/[,}].*/, "", sent)
    verdict = (p99 + 0 < 250 && lost + 0 == 0 && noerr + 0 == sent + 0 && got + 0 >= 0.99 * rate) ? "PASS" : "FAIL"
    printf "M21 %s: answered %s/s, p99 %s ms, lost %s, noerror %s of %s\n", verdict, got, p99, lost, noerr, sent
  }' "$OUT" | tail -n "$REPEATS" | while read -r line; do note "$line"; done
