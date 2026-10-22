#!/usr/bin/env bash
# M31 (DDNS rate end to end, WP8.3): leases acknowledged per second with option 81 names, and
# the time from the ACK to the name being answered by the DNS role of the same node, against
# a baseline DORA at the same rate with no names.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
#   cargo build -p tenko-dhcp --release --locked --example ddns_load --target x86_64-unknown-linux-musl
# A dynamically linked --server-binary is refused with a warning (--allow-dynamic overrides;
# the run is then marked not publishable). Windows runs (Git Bash) use the release builds
# (`cargo build -p tenko --release --locked` and the same with `-p tenko-dhcp --example
# ddns_load`). Every figure is a single-node figure and, with the load generator on the same
# host, a loopback figure from an own client (the stand-in for perfdhcp): an upper bound,
# labelled so.
#
# 1. A new node: `tenko serve` with roles controller,dns,dhcp and modules ipam, dns, dhcp, an
#    empty data directory, the API on loopback (reverse-proxy mode, plain HTTP from the
#    trusted loopback), the DNS role on --dns-port, the DHCP relay-mode listener on
#    --dhcp-port of loopback (replies to --relay-port, 4 workers), the metrics listener on
#    --metrics-port.
# 2. Setup through the API with curl under the Home profile: the primary zones
#    lan.example.test and 18.198.in-addr.arpa and 19.198.in-addr.arpa, the prefix
#    198.18.0.0/15 (RFC 2544's benchmarking range) with the range 198.18.0.10 to
#    198.19.255.250 (dhcp_pool, about 131,000 addresses) and its scope: one-hour leases,
#    DDNS on, the forward zone named.
# 3. The wait: the load tool with no names until the DHCP listener answers (at most 30 s).
# 4. The runs: the example ddns_load of tenko-dhcp (--load PATH) with names on, --rate
#    exchanges per second (default 1000) for --duration seconds (default 60) after --warmup
#    seconds (default 5), --repeats times (default 1), each run with a prefix of its own
#    (m31a, m31b, ...) and a client offset of its own (new clients: every client is used once
#    and takes a new address), then one baseline run with no names at the same rate and
#    duration. The pool is the limit: all runs together start rate * (warmup + duration)
#    exchanges each, and the script refuses a plan that needs more addresses than the pool
#    holds. Between runs it waits for the DDNS queue to empty.
# 5. After the runs: the node's RSS (Windows: the working set; Linux: VmRSS), the counters
#    `tenko_dhcp_ddns` and `tenko_dhcp_ddns_queue` and the count of
#    `tenko_dhcp_exchange_duration_seconds` from the metrics listener, into the meta file.
# 6. The results: the load tool's JSON lines in the out file; the summary lines echoed.
#
# Usage: run-m31-ddns.sh [--server-binary PATH] [--load PATH] [options]
#   --server-binary PATH  tenko (default <target dir>/release/tenko[.exe])
#   --load PATH           the ddns_load example (default <target dir>/release/examples/...)
#   --rate N              exchanges started per second (default 1000)
#   --duration SECS       measured seconds (default 60)
#   --warmup SECS         seconds before the measurement (default 5)
#   --repeats N           runs with names on (default 1); one baseline run follows
#   --baseline-only       only the baseline run (no names), on its own fresh node
#   --no-baseline         only the runs with names
#   --snapshot-every N    [store] snapshot_every_entries of the node (default: the default)
#   --loopback ADDR       the loopback address (default 127.0.0.1)
#   --port N              the API port (default 18455)
#   --dns-port N          the DNS port (default 15354)
#   --dhcp-port N         the DHCP server port (default 6767)
#   --relay-port N        the port the replies go to, the load tool's (default 6868)
#   --metrics-port N      the metrics listener's port (default 19465)
#   --label TEXT          a label for the result lines (default the OS and the binary's version)
#   --allow-dynamic       do not refuse a dynamically linked binary on Linux
#   --out FILE            result file (default bench/phase3-dhcp/results/raw/m31-<stamp>.jsonl)
#   --print-plan          print this text and exit
# Experiments, from the environment: ROLES (default controller,dns,dhcp) and
# RECONCILER_DEBOUNCE (the IPAM reconciler's debounce in seconds, 0 to 300).
set -u
export LC_ALL=C
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SELF/../../.." && pwd)"
# shellcheck source=../../phase2-dns/scripts/lib.sh
. "$SELF/../../phase2-dns/scripts/lib.sh"

EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
SERVER_BINARY="$TARGET_DIR/release/tenko$EXE"; LOAD="$TARGET_DIR/release/examples/ddns_load$EXE"
RATE=1000; DURATION=60; WARMUP=5; REPEATS=1; BASELINE_ONLY=0; NO_BASELINE=0; SNAPSHOT_EVERY=""
LOOPBACK="127.0.0.1"; PORT=18455; DNS_PORT=15354; DHCP_PORT=6767; RELAY_PORT=6868; METRICS_PORT=19465
LABEL=""; ALLOW_DYNAMIC=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --load) LOAD="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --repeats) REPEATS="$2"; shift 2 ;;
    --baseline-only) BASELINE_ONLY=1; shift ;;
    --no-baseline) NO_BASELINE=1; shift ;;
    --snapshot-every) SNAPSHOT_EVERY="$2"; shift 2 ;;
    --loopback) LOOPBACK="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --dns-port) DNS_PORT="$2"; shift 2 ;;
    --dhcp-port) DHCP_PORT="$2"; shift 2 ;;
    --relay-port) RELAY_PORT="$2"; shift 2 ;;
    --metrics-port) METRICS_PORT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --print-plan|-h|--help) sed -n '2,61p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -x "$SERVER_BINARY" ] || die "server binary not found: $SERVER_BINARY (--server-binary PATH)"
[ -x "$LOAD" ] || die "load generator not found: $LOAD (--load PATH, the ddns_load example of tenko-dhcp)"
command -v curl >/dev/null 2>&1 || die "curl is required"
case "$RATE$DURATION$WARMUP$REPEATS" in *[!0-9]*|"") die "--rate, --duration, --warmup and --repeats are whole numbers" ;; esac
[ "$RATE" -ge 1 ] && [ "$DURATION" -ge 1 ] && [ "$REPEATS" -ge 1 ] || die "--rate, --duration and --repeats must be at least 1"
[ "$BASELINE_ONLY" = 1 ] && [ "$NO_BASELINE" = 1 ] && die "--baseline-only and --no-baseline exclude each other"
[ "$BASELINE_ONLY" = 1 ] && REPEATS=0
LINUX=0
[ "$(uname -s)" = Linux ] && LINUX=1
URL="http://$LOOPBACK:$PORT"
ZONE="lan.example.test"
NETWORK="198.18.0.0"

# Every exchange of every run takes a new address from the pool, which holds 131,000 and
# some; the probe runs of step 3 take 20.
PER_RUN=$((RATE * (WARMUP + DURATION)))
NEEDED=$((PER_RUN * (REPEATS + 1) + 20))
[ "$NEEDED" -le 131000 ] ||
  die "$((REPEATS + 1)) runs of $PER_RUN exchanges need $NEEDED addresses, the pool holds about 131,000: lower --rate, --duration or --repeats"
# Clients per run, and the offset between the runs' client numbers.
CLIENTS=$((PER_RUN + 1000))
STEP=$(((CLIENTS + 99999) / 100000 * 100000))
BASE_OFFSET=900000
[ $((REPEATS * STEP)) -le "$BASE_OFFSET" ] || BASE_OFFSET=$((REPEATS * STEP))
PROBE_OFFSET=$((BASE_OFFSET + STEP))

[ -n "$OUT" ] || OUT="$SELF/../results/raw/m31-$STAMP.jsonl"
mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
META="${OUT%.jsonl}.meta.txt"
: > "$META"
WORK="$(mktemp -d)"
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }
VERSION="$("$SERVER_BINARY" --version 2>&1 | head -n 1)"
[ -n "$LABEL" ] || LABEL="$(uname -s) $VERSION"

note "run-m31-ddns: rate=$RATE/s duration=${DURATION}s warmup=${WARMUP}s repeats=$REPEATS + 1 baseline (loopback figures)"
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
    -H "Idempotency-Key: m31-$RANDOM-$RANDOM-$RANDOM")
  [ -n "$COOKIE" ] && args+=(-H "Cookie: $COOKIE")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" --data "$body")
  API_STATUS="$(curl "${args[@]}" "$URL/api/v1$path")" || API_STATUS=000
  [ "${API_STATUS#2}" != "$API_STATUS" ]
}
# The first "id" of the JSON in $WORK/api.out.
first_id() { grep -o '"id": *"[^"]*"' "$WORK/api.out" | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/'; }
# A number out of a result line: json_num KEY LINE.
json_num() { printf '%s' "$2" | sed -n "s/.*\"$1\": \([^,}]*\).*/\1/p"; }
# The value of a metrics line whose name (with labels) starts with $1, summed.
metric_sum() {
  curl -sS "http://$LOOPBACK:$METRICS_PORT/metrics" 2>/dev/null |
    awk -v name="$1" 'index($0, name) == 1 { sum += $NF } END { printf "%d", sum }'
}

# 1. The node.
mkdir -p "$WORK/data"
cat > "$WORK/tenko.toml" <<TOML
data_dir = "$(native_path "$WORK")/data"
roles = "${ROLES:-controller,dns,dhcp}"
modules = ["ipam", "dns", "dhcp"]

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
listen = ["$LOOPBACK:$DNS_PORT"]

[dhcp]
listen = [{ address = "$LOOPBACK", mode = "relay" }]
port = $DHCP_PORT
relay_port = $RELAY_PORT
workers = 4
TOML
if [ -n "$SNAPSHOT_EVERY" ]; then
  printf '\n[store]\nsnapshot_every_entries = %s\nsnapshot_every_log_mib = 4096\n' "$SNAPSHOT_EVERY" >> "$WORK/tenko.toml"
  note "store: a snapshot every $SNAPSHOT_EVERY entries or 4,096 MiB of log (an experiment, not the default)"
fi
"$SERVER_BINARY" serve --config "$(native_path "$WORK/tenko.toml")" >> "${OUT%.jsonl}.server.log" 2>&1 &
SRV=$!
tries=300
while [ "$tries" -gt 0 ] && [ ! -s "$WORK/data/setup-token" ]; do sleep 0.2; tries=$((tries - 1)); done
[ -s "$WORK/data/setup-token" ] || die "the node did not write its setup token"
tries=100
while [ "$tries" -gt 0 ] && ! curl -sS -o /dev/null "$URL/api/v1/health" 2>/dev/null; do sleep 0.2; tries=$((tries - 1)); done

# 2. Setup, zones, prefix, range, scope.
# The Home profile's password policy is a PIN of digits.
PASSWORD="7$(printf '%07d' $((RANDOM * RANDOM % 10000000)))"
SETUP="{\"setup_token\": \"$(head -n 1 "$WORK/data/setup-token" | tr -d '\r\n')\", \"profile\": \"home\", \"admin\": {\"name\": \"bench\", \"display_name\": \"Bench\", \"password\": \"$PASSWORD\"}, \"host_name\": \"localhost\", \"language\": \"en\"}"
COOKIE="$(curl -sS -D - -o "$WORK/api.out" -H "Origin: $URL" -H "Content-Type: application/json" \
  --data "$SETUP" "$URL/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)"
[ -n "$COOKIE" ] || die "the setup did not sign in: $(cat "$WORK/api.out")"
zone_body() {
  printf '{"name": "%s", "kind": "primary", "serial": "counter", "soa": {"mname": "ns1.example.test", "rname": "hostmaster.example.test"}, "name_servers": ["ns1.example.test"]}' "$1"
}
api POST /dns/zones "$(zone_body "$ZONE")" || die "the zone was refused ($API_STATUS): $(cat "$WORK/api.out")"
FORWARD="$(first_id)"
[ -n "$FORWARD" ] || die "no zone id in: $(cat "$WORK/api.out")"
for reverse in 18.198.in-addr.arpa 19.198.in-addr.arpa; do
  api POST /dns/zones "$(zone_body "$reverse")" || die "the zone $reverse was refused ($API_STATUS): $(cat "$WORK/api.out")"
done
api POST /prefixes "{\"cidr\": \"$NETWORK/15\"}" || die "the prefix was refused ($API_STATUS): $(cat "$WORK/api.out")"
PREFIX_ID="$(first_id)"
[ -n "$PREFIX_ID" ] || die "no prefix id in: $(cat "$WORK/api.out")"
api POST "/prefixes/$PREFIX_ID/ranges" '{"first": "198.18.0.10", "last": "198.19.255.250", "role": "dhcp_pool"}' ||
  die "the range was refused ($API_STATUS): $(cat "$WORK/api.out")"
api POST /dhcp/scopes "{\"prefix\": \"$PREFIX_ID\", \"lease\": {\"default_secs\": 3600, \"min_secs\": 3600, \"max_secs\": 3600}, \"ddns\": {\"enabled\": true, \"forward_zone\": \"$FORWARD\"}}" ||
  die "the scope was refused ($API_STATUS): $(cat "$WORK/api.out")"
note "node: $URL, DNS on $LOOPBACK:$DNS_PORT, DHCP relay listener on $LOOPBACK:$DHCP_PORT (replies to $RELAY_PORT), profile home"
note "scope: $NETWORK/15, pool 198.18.0.10 to 198.19.255.250, leases 3600 s, DDNS into $ZONE (zone $FORWARD)"
if [ -n "${RECONCILER_DEBOUNCE:-}" ]; then
  # An experiment: the IPAM reconciler runs on every change of dns.rrsets after its debounce.
  api GET /settings/reconciler || die "the reconciler settings were not read ($API_STATUS)"
  sed "s/\"debounce_secs\": *[0-9]*/\"debounce_secs\": $RECONCILER_DEBOUNCE/" "$WORK/api.out" > "$WORK/reconciler.json"
  api PUT /settings/reconciler "$(cat "$WORK/reconciler.json")" ||
    die "the reconciler settings were refused ($API_STATUS): $(cat "$WORK/api.out")"
  note "reconciler: debounce $RECONCILER_DEBOUNCE s (an experiment, not the default)"
fi

# One run of the load tool: load_run NAMES PREFIX OFFSET [OUT]; the tool's line on stdout.
load_run() {
  local names="$1" prefix="$2" offset="$3"; shift 3
  "$LOAD" --server "$LOOPBACK:$DHCP_PORT" --bind "$LOOPBACK:$RELAY_PORT" --dns "$LOOPBACK:$DNS_PORT" \
    --zone "$ZONE" --subnet "$NETWORK" --names "$names" --prefix "$prefix" --offset "$offset" "$@"
}

# 3. Wait until the DHCP listener answers (and the scope has reached it).
acked=0
waited=$SECONDS
while [ $((SECONDS - waited)) -lt 30 ]; do
  line="$(load_run off probe "$PROBE_OFFSET" --clients 20 --rate 10 --seconds 1 --warmup 0 2>/dev/null)"
  acked="$(printf '%s' "$line" | sed -n 's/.* acked \([0-9]*\),.*/\1/p')"
  [ "${acked:-0}" -ge 1 ] && break
  sleep 0.5
done
[ "${acked:-0}" -ge 1 ] || die "the DHCP listener did not answer within 30 s (see ${OUT%.jsonl}.server.log)"

# Waits until the DDNS queue of the node is empty (at most 60 s).
settle() {
  local tries=60
  while [ "$tries" -gt 0 ] && [ "$(metric_sum tenko_dhcp_ddns_queue)" -gt 0 ]; do
    sleep 1; tries=$((tries - 1))
  done
  sleep 2
}

# 4. The runs.
for repeat in $(seq 1 "$REPEATS"); do
  letter="$(printf "\\$(printf '%03o' $((96 + repeat)))")"
  prefix="m31$letter"
  say "run $repeat/$REPEATS: names on, $RATE/s for ${DURATION}s after ${WARMUP}s, prefix $prefix, offset $(((repeat - 1) * STEP))"
  load_run on "$prefix" $(((repeat - 1) * STEP)) --clients "$CLIENTS" --rate "$RATE" --seconds "$DURATION" \
    --warmup "$WARMUP" --label "$LABEL run $repeat" --out "$(native_path "$OUT")" | tee -a "$META"
  settle
done
RUNS="$REPEATS"
if [ "$NO_BASELINE" = 0 ]; then
  RUNS=$((REPEATS + 1))
  say "baseline: names off, $RATE/s for ${DURATION}s after ${WARMUP}s, offset $BASE_OFFSET"
  load_run off m31base "$BASE_OFFSET" --clients "$CLIENTS" --rate "$RATE" --seconds "$DURATION" \
    --warmup "$WARMUP" --label "$LABEL baseline" --out "$(native_path "$OUT")" | tee -a "$META"
fi

# 5. After the runs.
note "rss after the runs: $(rss_mib) MiB"
# The whole metrics page beside the results (the commit histograms of the store and the
# lease path, the reconciler's counters), for the attribution of the tail.
curl -sS "http://$LOOPBACK:$METRICS_PORT/metrics" > "${OUT%.jsonl}.metrics.txt" 2>/dev/null
curl -sS "http://$LOOPBACK:$METRICS_PORT/metrics" 2>/dev/null |
  grep -E '^(tenko_dhcp_ddns|tenko_dhcp_exchange_duration_seconds_count)' | while read -r line; do note "metric: $line"; done
note "metric sum: tenko_dhcp_exchange_duration_seconds_count $(metric_sum tenko_dhcp_exchange_duration_seconds_count)"

# 6. The results.
note "results: $OUT"
while read -r line; do
  names="$(printf '%s' "$line" | sed -n 's/.*"names": \([a-z]*\),.*/\1/p')"
  note "M31 names=$names: started $(json_num started "$line"), acked $(json_num acked "$line"), lost $(json_num lost "$line"), \
$(json_num achieved_per_s "$line")/s, exchange ms p50 $(json_num exchange_p50_ms "$line") p99 $(json_num exchange_p99_ms "$line") \
max $(json_num exchange_max_ms "$line")$([ "$names" = true ] && printf ', ddns answered %s lost %s, ack-to-answer ms p50 %s p99 %s max %s' \
    "$(json_num ddns_answered "$line")" "$(json_num ddns_lost "$line")" "$(json_num ddns_p50_ms "$line")" \
    "$(json_num ddns_p99_ms "$line")" "$(json_num ddns_max_ms "$line")")"
done < <(tail -n "$RUNS" "$OUT")
