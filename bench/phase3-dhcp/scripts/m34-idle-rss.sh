#!/usr/bin/env bash
# M34 (OPS-15, E32) on Linux: idle memory of `tenko serve` with every role, the dhcp role
# serving three scopes with 200 leases. The Linux equivalent of m34-idle-rss.ps1: the M9
# procedure of bench/phase1-server/m9-idle-rss.sh (memory read from /proc/<pid>/status) with
# the roles controller, dns, dhcp and probe.
#
# A fresh single node starts with a DNS listener and a relay-mode DHCP listener on loopback
# ports; first-run setup goes through the API under the Home profile; three IPAM networks on
# the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) get a `dhcp_pool`
# range, a scope with one-hour leases and the options 3, 6 and 42; the example's load client
# (`dhcp_server load`, a relay agent that selects the scope with option 118) gives the
# clients a lease across the three scopes. With --prefixes N the M9 data set of N prefixes
# (one /8 and four /16 supernets, the rest /24 networks, as m9-idle-rss.sh creates them) is
# added first. The server is then left idle and sampled, and stopped with SIGTERM.
#
# The verdict is against 100 MB read as 100,000,000 bytes (95.37 MiB), as in M9, on VmRSS.
# Measure the binary that ships, the static musl build:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
#   cargo build -p tenko-dhcp --release --locked --example dhcp_server --target x86_64-unknown-linux-musl
# A dynamically linked binary is reported with a warning; its allocator keeps the start-up
# peak. Without `dhcp` in --roles no scopes and no leases are made: the baseline.
#
# Nothing secret is written out: the setup token is read from the data directory, the
# administrator PIN is generated for the run and never printed, and the server log is
# redacted before it is copied to the output directory. Needs curl and python3.
#
# Usage:
#   m34-idle-rss.sh --binary PATH --load-client PATH [--roles controller,dns,dhcp,probe]
#                   [--prefixes 0] [--leases 200] [--port 18443] [--dns-port 15353]
#                   [--dhcp-port 6767] [--relay-port 6868] [--workers 0]
#                   [--idle-secs 600] [--interval-secs 30] [--workdir DIR] [--outdir DIR]
#                   [--kek platform|file] [--keep-data]
# The port options let several runs go at once. The raw output (a CSV of the samples, the
# summary, the redacted server logs) goes to --outdir, default
# bench/phase3-dhcp/results/raw, which git ignores.

set -u
export LC_ALL=C

BINARY=""
LOAD_CLIENT=""
ROLES="controller,dns,dhcp,probe"
PREFIXES=0
LEASES=200
PORT=18443
DNS_PORT=15353
DHCP_PORT=6767
RELAY_PORT=6868
WORKERS=0
IDLE_SECS=600
INTERVAL=30
WORKDIR=""
OUTDIR=""
KEK=platform
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --load-client) LOAD_CLIENT="$2"; shift 2 ;;
    --roles) ROLES="$2"; shift 2 ;;
    --prefixes) PREFIXES="$2"; shift 2 ;;
    --leases) LEASES="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --dns-port) DNS_PORT="$2"; shift 2 ;;
    --dhcp-port) DHCP_PORT="$2"; shift 2 ;;
    --relay-port) RELAY_PORT="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --idle-secs) IDLE_SECS="$2"; shift 2 ;;
    --interval-secs) INTERVAL="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --kek) KEK="$2"; shift 2 ;;
    --keep-data) KEEP=1; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BINARY" ] || { echo "--binary is required" >&2; exit 2; }
[ -x "$BINARY" ] || { echo "not executable: $BINARY" >&2; exit 2; }
[ -n "$LOAD_CLIENT" ] || { echo "--load-client is required" >&2; exit 2; }
[ -x "$LOAD_CLIENT" ] || { echo "not executable: $LOAD_CLIENT" >&2; exit 2; }
{ [ "$PREFIXES" -eq 0 ] || [ "$PREFIXES" -ge 6 ]; } || { echo "--prefixes must be 0 or at least 6" >&2; exit 2; }
[ "$KEK" = platform ] || [ "$KEK" = file ] || { echo "--kek is platform or file" >&2; exit 2; }
command -v curl > /dev/null || { echo "curl is needed" >&2; exit 2; }
command -v python3 > /dev/null || { echo "python3 is needed" >&2; exit 2; }
case ",$ROLES," in *,dhcp,*) WITH_DHCP=1 ;; *) WITH_DHCP=0 ;; esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
TAG="m34-linux-$STAMP-p$PORT"
[ -n "$OUTDIR" ] || OUTDIR="$HERE/../results/raw"
[ -n "$WORKDIR" ] || WORKDIR="$(mktemp -d /tmp/tenko-m34-XXXXXX)"
mkdir -p "$WORKDIR" "$OUTDIR"

DATA="$WORKDIR/data"
CFG="$WORKDIR/tenko.toml"
OUTLOG="$WORKDIR/server.out.log"
ERRLOG="$WORKDIR/server.err.log"
BASE="https://localhost:$PORT"
API="$BASE/api/v1"
CSV="$OUTDIR/$TAG.csv"
SUMMARY="$OUTDIR/$TAG-summary.txt"

T0=$(date +%s.%N)
now() { awk -v a="$(date +%s.%N)" -v b="$T0" 'BEGIN { printf "%.1f", a - b }'; }
say() { printf '[%7ss] %s\n' "$(now)" "$1"; }
note() { say "$1"; printf '%s\n' "$1" >> "$SUMMARY"; }

: > "$SUMMARY"
SERVER_PID=0
TOKEN=""
COOKIE=""

cleanup() {
  if [ "$SERVER_PID" -ne 0 ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -KILL "$SERVER_PID" 2>/dev/null
  fi
  for f in server.out.log server.err.log; do
    if [ -f "$WORKDIR/$f" ]; then
      if [ -n "$TOKEN" ]; then
        sed "s/$TOKEN/<redacted>/g" "$WORKDIR/$f" > "$OUTDIR/$TAG-$f"
      else
        cp "$WORKDIR/$f" "$OUTDIR/$TAG-$f"
      fi
    fi
  done
  [ "$KEEP" -eq 1 ] || rm -rf "$WORKDIR"
  echo "raw output: $OUTDIR ($TAG*)"
}
trap cleanup EXIT

die() { note "FAILED: $1"; exit 1; }

# kB value of a /proc/<pid>/status field, in MiB.
field() { awk -v k="$1:" '$1 == k { printf "%.2f", $2 / 1024 }' "/proc/$SERVER_PID/status"; }
threads() { awk '$1 == "Threads:" { print $2 }' "/proc/$SERVER_PID/status"; }

echo "t_s,phase,rss_mib,hwm_mib,rss_anon_mib,rss_file_mib,vmsize_mib,threads" > "$CSV"
LAST_RSS=""; LAST_HWM=""; LAST_ANON=""; LAST_FILE=""; LAST_THREADS=""
sample() {
  local phase="$1"
  LAST_RSS=$(field VmRSS); LAST_HWM=$(field VmHWM); LAST_ANON=$(field RssAnon)
  LAST_FILE=$(field RssFile); LAST_THREADS=$(threads)
  echo "$(now),$phase,$LAST_RSS,$LAST_HWM,$LAST_ANON,$LAST_FILE,$(field VmSize),$LAST_THREADS" >> "$CSV"
}

# One API call with the session cookie; retries a 429 (the API's rate limit after many
# writes) and a 503 (a role not yet ready) like a client would. The answer is in api.out.
# The server's certificate is its own CA's and the address is loopback: -k.
api() {
  local method="$1" path="$2" body="${3:-}" extra="${4:-}" code="" try
  local args=(-sk -o "$WORKDIR/api.out" -w '%{http_code}' -X "$method" -H "Origin: $BASE" -H "Cookie: $COOKIE")
  [ -z "$body" ] || args+=(-H "Content-Type: application/json" --data "$body")
  [ -z "$extra" ] || args+=(-H "$extra")
  for try in $(seq 1 30); do
    code=$(curl "${args[@]}" "$API$path") || code=000
    case "$code" in
      2*) return 0 ;;
      429 | 503) sleep 2 ;;
      *) say "$method $path failed ($code): $(cat "$WORKDIR/api.out" 2> /dev/null)"; return 1 ;;
    esac
  done
  say "$method $path failed after 30 tries ($code)"
  return 1
}
# A value of the last answer: json_get "d['item']['id']".
json_get() { python3 -c "import json; d = json.load(open('$WORKDIR/api.out')); print($1)"; }
hex4() { printf '%02x%02x%02x%02x' "$1" "$2" "$3" "$4"; }

# ---- machine ------------------------------------------------------------------------------
CPU=$(awk -F: '/model name/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo)
note "machine: $CPU, $(nproc) logical CPUs, $(awk '/MemTotal/ { printf "%.1f", $2 / 1048576 }' /proc/meminfo) GiB RAM, $(. /etc/os-release; echo "$PRETTY_NAME"), kernel $(uname -r)"
LINKAGE=dynamic
if ldd "$BINARY" 2>&1 | grep -Eq 'statically linked|not a dynamic executable'; then LINKAGE=static; fi
note "binary: $BINARY ($(awk -v s="$(stat -c %s "$BINARY")" 'BEGIN { printf "%.1f", s / 1048576 }') MiB, $LINKAGE), $("$BINARY" --version)"
[ "$LINKAGE" = static ] || note "WARNING: a dynamically linked binary; the shipped Linux binary is the static musl build"
note "work dir: $WORKDIR; filesystem: $(df -PT "$WORKDIR" | awk 'NR == 2 { print $2 }')"
note "kek provider: $KEK"
note "roles: $ROLES; DNS on 127.0.0.1:$DNS_PORT; DHCP relay listener on 127.0.0.1:$DHCP_PORT, replies to relays on $RELAY_PORT"

# ---- configuration ------------------------------------------------------------------------
{
  echo "data_dir = \"$DATA\""
  echo "roles = \"$ROLES\""
  echo
  echo '[server]'
  echo "listen = [\"127.0.0.1:$PORT\"]"
  echo
  echo '[hibp]'
  echo 'online = false'
  if [ "$KEK" = file ]; then
    echo
    echo '[kek]'
    echo 'provider = "file"'
    echo "path = \"$WORKDIR/kek.key\""
  fi
  echo
  echo '[dns]'
  echo "listen = [\"127.0.0.1:$DNS_PORT\"]"
  echo
  echo '[dhcp]'
  echo 'listen = [{ address = "127.0.0.1", mode = "relay" }]'
  echo "port = $DHCP_PORT"
  echo "relay_port = $RELAY_PORT"
  echo "workers = $WORKERS"
} > "$CFG"

# Throwaway administrator PIN for this run (Home profile: digits only). Never printed.
new_pin() { shuf -i 0-9 -n 6 | tr -d '\n'; }
PIN=$(new_pin)

# ---- start --------------------------------------------------------------------------------
"$BINARY" serve --roles "$ROLES" --config "$CFG" > "$OUTLOG" 2> "$ERRLOG" &
SERVER_PID=$!
START=$(date +%s.%N)
note "server pid $SERVER_PID"

ready=0
for _ in $(seq 1 1200); do
  kill -0 "$SERVER_PID" 2>/dev/null || die "the server exited at start"
  sample start
  if grep -q ' ready at ' "$OUTLOG" 2>/dev/null && grep -Eq '^={20,}$' "$OUTLOG"; then ready=1; break; fi
  sleep 0.1
done
[ "$ready" -eq 1 ] || die "the server did not become ready in 120 s"
READY_AFTER=$(awk -v a="$(date +%s.%N)" -v b="$START" 'BEGIN { printf "%.1f", a - b }')
if [ -f "$DATA/setup-token" ]; then
  TOKEN=$(tr -d ' \r\n' < "$DATA/setup-token")
fi
[ -n "$TOKEN" ] || die "no setup token in $DATA/setup-token"
sample ready
note "ready after $READY_AFTER s; RSS $LAST_RSS MiB, HWM $LAST_HWM MiB, anon $LAST_ANON MiB, file $LAST_FILE MiB"

# ---- setup --------------------------------------------------------------------------------
for _ in 1 2 3 4 5; do
  COOKIE=$(curl -sk -D - -o "$WORKDIR/api.out" -H "Origin: $BASE" -H "Content-Type: application/json" \
    --data "{\"setup_token\": \"$TOKEN\", \"profile\": \"home\", \"host_name\": \"localhost\", \"language\": \"en\", \"admin\": {\"name\": \"admin\", \"display_name\": \"Bench\", \"password\": \"$PIN\"}}" \
    "$API/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)
  [ -z "$COOKIE" ] || break
  PIN=$(new_pin) # a PIN the policy refuses (a trivial one): another
done
[ -n "$COOKIE" ] || die "setup failed: $(sed "s/$TOKEN/<token>/g" "$WORKDIR/api.out")"
note "setup complete (Home profile), session open"
sample setup

# ---- the M9 data set (optional) -----------------------------------------------------------
if [ "$PREFIXES" -gt 0 ]; then
  CIDRS=("10.0.0.0/8 supernet")
  for a in 1 2 3 4; do CIDRS+=("10.$a.0.0/16 supernet"); done
  n=0
  while [ "${#CIDRS[@]}" -lt "$PREFIXES" ]; do
    CIDRS+=("10.$((1 + n % 4)).$((n / 4)).0/24 network")
    n=$((n + 1))
  done
  failures=0
  for entry in "${CIDRS[@]}"; do
    set -- $entry
    api POST /prefixes "{\"cidr\": \"$1\", \"role\": \"$2\"}" || failures=$((failures + 1))
  done
  sample data-set
  note "the M9 data set: $((${#CIDRS[@]} - failures)) of ${#CIDRS[@]} prefixes ($failures failures)"
fi

# ---- the three home scopes ----------------------------------------------------------------
# network, first and last pool address, the first three octets.
HOMES=("192.0.2.0/24 192.0.2.100 192.0.2.199 192 0 2"
  "198.51.100.0/24 198.51.100.100 198.51.100.199 198 51 100"
  "203.0.113.0/24 203.0.113.100 203.0.113.199 203 0 113")
if [ "$WITH_DHCP" -eq 0 ]; then
  HOMES=()
  note "no dhcp role: no scopes and no leases (the baseline)"
fi
for entry in "${HOMES[@]}"; do
  set -- $entry
  api POST /prefixes "{\"cidr\": \"$1\", \"role\": \"network\"}" || die "prefix $1"
  prefix=$(json_get "d['item']['id']")
  api POST "/prefixes/$prefix/ranges" "{\"first\": \"$2\", \"last\": \"$3\", \"role\": \"dhcp_pool\"}" || die "pool of $1"
  api POST /dhcp/scopes "{\"prefix\": \"$prefix\", \"lease\": {\"default_secs\": 3600, \"min_secs\": 600, \"max_secs\": 7200}}" || die "scope $1"
  api PUT "/dhcp/option-sets/scope:$prefix" \
    "{\"values\": [{\"code\": 3, \"data\": \"$(hex4 "$4" "$5" "$6" 1)\"}, {\"code\": 6, \"data\": \"$(hex4 "$4" "$5" "$6" 53)\"}, {\"code\": 42, \"data\": \"$(hex4 "$4" "$5" "$6" 123)\"}]}" \
    "If-Match: 0" || die "options of $1"
done
[ "$WITH_DHCP" -eq 0 ] || note "three scopes with pools of 100 addresses and the options 3, 6 and 42"
sleep 3 # the role takes the scopes from the feed

# ---- the leases ---------------------------------------------------------------------------
if [ "$WITH_DHCP" -eq 1 ]; then
  per=$(((LEASES + 2) / 3))
  left=$LEASES
  for entry in "${HOMES[@]}"; do
    set -- $entry
    n=$((per < left ? per : left))
    left=$((left - n))
    [ "$n" -gt 0 ] || continue
    subnet="${1%/*}"
    out=$("$LOAD_CLIENT" load --server "127.0.0.1:$DHCP_PORT" --bind "127.0.0.1:$RELAY_PORT" --mode dora \
      --clients "$n" --window 8 --seconds 60 --subnet "$subnet" 2>&1 | tr '\n' ' ')
    note "load client on $1: $out"
  done
  listed=0
  cursor=""
  while :; do
    q="/dhcp/leases?limit=500"
    [ -z "$cursor" ] || q="$q&cursor=$cursor"
    api GET "$q" || break
    read -r count cursor < <(json_get "len(d.get('items') or []), d.get('next_cursor') or ''")
    listed=$((listed + count))
    [ -n "$cursor" ] || break
  done
  note "leases listed by GET /dhcp/leases: $listed"
fi
sample load-end
note "peak during start-up, setup and the fill: VmHWM $LAST_HWM MiB (now RSS $LAST_RSS MiB, anon $LAST_ANON MiB, file $LAST_FILE MiB)"
LOAD_HWM=$LAST_HWM

# ---- idle ---------------------------------------------------------------------------------
note "idle phase: $IDLE_SECS s, one sample every $INTERVAL s"
IDLE_START=$(date +%s.%N)
COUNT=$((IDLE_SECS / INTERVAL))
IDLE_FILE="$WORKDIR/idle.txt"
: > "$IDLE_FILE"
for k in $(seq 0 "$COUNT"); do
  due=$((k * INTERVAL))
  wait_s=$(awk -v a="$(date +%s.%N)" -v b="$IDLE_START" -v d="$due" 'BEGIN { w = d - (a - b); if (w < 0) w = 0; printf "%.3f", w }')
  sleep "$wait_s"
  kill -0 "$SERVER_PID" 2>/dev/null || die "the server exited during the idle phase"
  sample idle
  echo "$LAST_RSS" >> "$IDLE_FILE"
  say "idle $(printf '%4s' "$due") s: RSS $LAST_RSS MiB, HWM $LAST_HWM MiB, anon $LAST_ANON MiB, file $LAST_FILE MiB, threads $LAST_THREADS"
done
FINAL_RSS=$LAST_RSS
sample idle-end
END_HWM=$LAST_HWM

STATS=$(sort -n "$IDLE_FILE" | awk '{ v[NR] = $1 } END {
  m = (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
  printf "min %.2f median %.2f max %.2f", v[1], m, v[NR] }')
MAX_RSS=$(sort -n "$IDLE_FILE" | tail -n 1)
note "idle VmRSS MiB: $STATS final $FINAL_RSS"
note "peak at the end of the run: VmHWM $END_HWM MiB; start-up and fill peak: VmHWM $LOAD_HWM MiB"
# OPS-15 says 100 MB; read as 100,000,000 bytes (95.37 MiB), the stricter reading.
if awk -v m="$MAX_RSS" 'BEGIN { exit !(m * 1048576 < 100000000) }'; then VERDICT=PASS; else VERDICT=FAIL; fi
note "verdict against 100 MB = 100,000,000 bytes = 95.37 MiB (largest idle VmRSS $MAX_RSS MiB = $(awk -v m="$MAX_RSS" 'BEGIN { printf "%.1f", m * 1.048576 }') MB): $VERDICT"

# ---- stop ---------------------------------------------------------------------------------
STOP_AT=$(date +%s.%N)
kill -TERM "$SERVER_PID"
wait "$SERVER_PID"
EXIT_CODE=$?
SERVER_PID=0
note "graceful stop (SIGTERM): exit status $EXIT_CODE after $(awk -v a="$(date +%s.%N)" -v b="$STOP_AT" 'BEGIN { printf "%.1f", a - b }') s"
exit 0
