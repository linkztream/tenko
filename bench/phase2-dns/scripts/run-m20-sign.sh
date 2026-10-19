#!/usr/bin/env bash
# M20 (signing time and re-sign rate, docs/plans/phase-2-plan.md section 6): the Spike A
# million-record data set signed under 5 minutes with each algorithm, NSEC and NSEC3, and a
# 100-record change re-signed under 1 s.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# A dynamically linked --server-binary is refused with a warning (--allow-dynamic overrides;
# the run is then marked not publishable). Windows runs (Git Bash) use the release build.
# Every figure is a single-node figure (plan section 2.10): one `tenko serve --roles
# controller` signs through its own store and vault.
#
# 1. Data. `zonegen --records N` (default 1,000,000) writes example.test.zone: N A records
#    host-{n}, the SOA, the NS and the glue (N + 3 RRsets, the Spike A data set).
# 2. Per case in --cases (default "ecdsa:nsec ecdsa:nsec3 ed25519:nsec ed25519:nsec3"): a new
#    node with an empty data directory; setup and login through the client; the zone created
#    with the counter serial; the file imported with `tenko dns import --replace` (the import
#    job, timed but not part of M20).
# 3. Full signing. `tenko dns dnssec enable example.test` with the case's algorithm and
#    denial; the time runs from the command until `tenko dns dnssec status` shows a signed
#    serial: the signer generates the keys, signs every RRset and builds the chain in one
#    full pass, written in chunks. Threshold: 300 s.
# 4. Re-signing a change. --change records (default 100) of new names `m20-{k}` are imported
#    without --replace (one store write of 100 RRsets, the import's journal entry). The time
#    runs from the start of the import command until the status shows the serial of the
#    signer's pass after it (the zone's serial before plus two: the import's step and the
#    pass's step): the import job and the client's wait for it, the signer's watch, its
#    incremental pass (the 100 RRsets, their NSEC or NSEC3 neighbours and the apex) and its
#    write, so the figure is an upper bound of the re-signing alone; the time after the
#    import command returned is noted beside it. Repeated --repeats times (default 5), each
#    with new names; the median and the largest are reported. Threshold: 1 s.
# 5. The node's RSS after the full pass is read from the process (Windows: the working set;
#    Linux: VmRSS).
#
# Usage: run-m20-sign.sh --server-binary PATH [options]
#   --harness PATH      the phase2-dns binary (default $HARNESS or phase2-dns on the PATH)
#   --records N         A records in the zone (default 1000000)
#   --cases LIST        algorithm:denial pairs (default above)
#   --change N          records of the change (default 100)
#   --repeats N         changes per case (default 5)
#   --data DIR          where the zone files go (default data/ of the harness)
#   --loopback ADDR     the API's loopback address (default $PHASE2_DNS_LOOPBACK or 127.0.0.1)
#   --port N            the API port (default 18453)
#   --allow-dynamic     do not refuse a dynamically linked binary on Linux
#   --out FILE          result file (default results/raw/m20-<stamp>.jsonl)
#   --print-plan        print this text and exit
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER_BINARY=""; HARNESS="${HARNESS:-phase2-dns}"; RECORDS=1000000
CASES="ecdsa:nsec ecdsa:nsec3 ed25519:nsec ed25519:nsec3"; CHANGE=100; REPEATS=5
DATA_ROOT="$ROOT/data"; LOOPBACK="${PHASE2_DNS_LOOPBACK:-127.0.0.1}"; PORT=18453
ALLOW_DYNAMIC=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --harness) HARNESS="$2"; shift 2 ;;
    --records) RECORDS="$2"; shift 2 ;;
    --cases) CASES="$2"; shift 2 ;;
    --change) CHANGE="$2"; shift 2 ;;
    --repeats) REPEATS="$2"; shift 2 ;;
    --data) DATA_ROOT="$2"; shift 2 ;;
    --loopback) LOOPBACK="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --print-plan|-h|--help) sed -n '2,48p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SERVER_BINARY" ] || die "--server-binary PATH (tenko) is required"
[ -x "$SERVER_BINARY" ] || die "server binary not found: $SERVER_BINARY"
command -v "$HARNESS" >/dev/null 2>&1 || [ -x "$HARNESS" ] || die "harness not found: $HARNESS"
LINUX=0
[ "$(uname -s)" = Linux ] && LINUX=1
URL="http://$LOOPBACK:$PORT"
ZONE="example.test"
PASSWORD="73915482"

[ -n "$OUT" ] || OUT="$ROOT/results/raw/m20-$STAMP.jsonl"
mkdir -p "$(dirname "$OUT")"
META="${OUT%.jsonl}.meta.txt"
: > "$META"
WORK="$(mktemp -d)"
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }

note "run-m20-sign: records=$RECORDS cases=[$CASES] change=$CHANGE repeats=$REPEATS"
note "$(machine_line)"
note "server: $("$SERVER_BINARY" --version 2>&1 | head -n 1) at $SERVER_BINARY"
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

# Seconds since 1970 with milliseconds.
now() { date +%s.%3N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'; }

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

# 1. Data.
DATA="$DATA_ROOT/m20-$RECORDS"
if [ ! -f "$DATA/example.test.zone" ]; then
  say "zonegen: $RECORDS records into $DATA"
  "$HARNESS" zonegen --records "$RECORDS" --queries 1 --out-dir "$DATA" > /dev/null || die "zonegen failed"
fi
note "zone file: $DATA/example.test.zone, $(grep -c ' A ' "$DATA/example.test.zone") A records"

# A call reset by the peer before it was answered is made again, up to five times a second
# apart, and noted in the log with the socket states of the API's port (seen on WSL2
# loopback after long passes; the node itself kept running).
client() {
  local status=0 tries=0
  TENKO_CREDENTIALS="$WORK/credentials" "$SERVER_BINARY" "$@" --url "$URL" 2> "$WORK/client.err" || status=$?
  while [ "$status" -ne 0 ] && [ "$tries" -lt 5 ] && grep -q 'Connection reset by peer' "$WORK/client.err"; do
    tries=$((tries + 1))
    note "retry $tries after a connection reset: tenko $*" >&2
    if command -v ss > /dev/null; then
      note "  sockets of port $PORT: $(ss -tan "( sport = :$PORT or dport = :$PORT )" | awk 'NR > 1 { print $1 }' | sort | uniq -c | tr -s ' \n' ' ')" >&2
    fi
    sleep 1
    status=0
    TENKO_CREDENTIALS="$WORK/credentials" "$SERVER_BINARY" "$@" --url "$URL" 2> "$WORK/client.err" || status=$?
  done
  cat "$WORK/client.err" >&2
  return "$status"
}

start_node() {
  rm -rf "$WORK/data" "$WORK/credentials"
  mkdir -p "$WORK/data"
  cat > "$WORK/tenko.toml" <<TOML
data_dir = "$(native_path "$WORK")/data"
roles = "controller"
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
TOML
  "$SERVER_BINARY" serve --config "$(native_path "$WORK/tenko.toml")" >> "${OUT%.jsonl}.server.log" 2>&1 &
  SRV=$!
  local tries=300
  while [ "$tries" -gt 0 ] && [ ! -s "$WORK/data/setup-token" ]; do sleep 0.2; tries=$((tries - 1)); done
  [ -s "$WORK/data/setup-token" ] || die "the node did not write its setup token"
  # The token file is written before the API listens.
  tries=100
  while [ "$tries" -gt 0 ] && ! client health > /dev/null 2>&1; do sleep 0.2; tries=$((tries - 1)); done
  printf '%s\n' "$PASSWORD" | client setup --setup-token "$(head -n 1 "$WORK/data/setup-token")" \
    --admin bench --host-name localhost --password-stdin > /dev/null || die "setup failed"
  printf '%s\n' "$PASSWORD" | client login --user bench --password-stdin > /dev/null || die "login failed"
}

# The value after "label:" in the status text, or empty.
status_value() {
  client dns dnssec status "$ZONE" 2>/dev/null | awk -v label="$1:" 'index($0, label) == 1 { print $NF; exit }'
}

zone_serial() {
  client dns zone get "$ZONE" --json | tr ',' '\n' | awk -F: '/"soa_serial"/ { gsub(/[^0-9]/, "", $2); print $2; exit }'
}

case_flags() {
  local algorithm="${1%%:*}" denial="${1##*:}"
  case "$algorithm" in
    ecdsa) printf -- '--algorithm ecdsap256sha256' ;;
    ed25519) printf -- '--algorithm ed25519' ;;
    *) die "unknown algorithm in $1" ;;
  esac
  [ "$denial" = nsec3 ] && printf -- ' --nsec3'
  return 0
}

for spec in $CASES; do
  say "case $spec"
  start_node
  client dns zone create "$ZONE" --kind primary --ns ns1 --mname ns1 --rname "hostmaster@$ZONE" \
    --serial counter > /dev/null || die "zone create failed"
  t0=$(now)
  client dns import "$ZONE" "$(native_path "$DATA/example.test.zone")" --replace --wait-secs 3600 > /dev/null \
    || die "import failed"
  t1=$(now)
  import_secs=$(elapsed "$t0" "$t1")
  note "$spec: import of $RECORDS records in ${import_secs} s"

  # 3. Full signing.
  # shellcheck disable=SC2046
  t0=$(now)
  client dns dnssec enable "$ZONE" $(case_flags "$spec") > /dev/null || die "enable failed"
  while [ -z "$(status_value "signed serial")" ]; do sleep 0.2; done
  t1=$(now)
  sign_secs=$(elapsed "$t0" "$t1")
  rss=$(rss_mib)
  note "$spec: full signing in ${sign_secs} s (threshold 300 s), RSS ${rss} MiB"

  # 4. Changes.
  changes=""
  for round in $(seq 1 "$REPEATS"); do
    file="$WORK/change-$round.zone"
    {
      printf '$ORIGIN %s.\n$TTL 300\n' "$ZONE"
      for k in $(seq 1 "$CHANGE"); do printf 'm20-%s-%s A 192.0.2.%s\n' "$round" "$k" $(( (k % 254) + 1 )); done
    } > "$file"
    before=$(zone_serial)
    t0=$(now)
    client dns import "$ZONE" "$(native_path "$file")" --wait-secs 600 > /dev/null || die "change import failed"
    t1=$(now)
    # The import moves the serial by one, the signer's pass by one more (counter serial).
    while :; do
      signed=$(status_value "signed serial")
      [ -n "$signed" ] && [ "$signed" -ge "$((before + 2))" ] && break
      sleep 0.02
    done
    t2=$(now)
    secs=$(elapsed "$t0" "$t2")
    after_import=$(elapsed "$t1" "$t2")
    changes="$changes $secs"
    note "$spec: change $round ($CHANGE records) signed ${secs} s after the import started, ${after_import} s after it returned (serial $before -> $signed)"
  done
  median=$(printf '%s\n' $changes | sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }')
  largest=$(printf '%s\n' $changes | sort -n | tail -n 1)
  note "$spec: change median ${median} s, largest ${largest} s (threshold 1 s)"
  printf '{"case":"%s","records":%s,"import_secs":%s,"sign_secs":%s,"rss_mib":%s,"change_records":%s,"change_secs":[%s],"change_median":%s,"change_max":%s}\n' \
    "$spec" "$RECORDS" "$import_secs" "$sign_secs" "${rss:-0}" "$CHANGE" \
    "$(printf '%s\n' $changes | paste -sd, -)" "$median" "$largest" >> "$OUT"
  stop_pid "$SRV"; SRV=""
done
note "results: $OUT"
