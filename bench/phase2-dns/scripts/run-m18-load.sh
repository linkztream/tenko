#!/usr/bin/env bash
# M18 (zone load and index memory, docs/plans/phase-2-plan.md section 6): the Spike A data
# set at 1 M and 6 M RRsets loaded through the zone file import and the feed in under 60 s,
# the index under 1.5 GiB at 6 M. The procedure of results/2026-10-17-m18-zone-load.md as a
# script.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# A dynamically linked --server-binary is refused with a warning (--allow-dynamic overrides;
# the run is then marked not publishable). Windows runs (Git Bash) use the release build.
# Every figure is a single-node figure (plan section 2.10).
#
# 1. Data. `zonegen --records N` writes example.test (N A records host-{n}) and the three
#    reverse zones with a PTR record for every fifth host: 1.2 N RRsets in four zones.
# 2. A new node (`--roles`, default controller,dns; [dns] and [runtime] workers 4, a key
#    file, the TLS mode reverse_proxy on loopback, the store at its defaults); setup and
#    login through the client; the RSS before the import.
# 3. Import. The four zones are created, then the three reverse zones and example.test are
#    imported with `tenko dns import --replace`, one after the other, each timed by the
#    client. With the dns role, the load generator then asks for host-{N-1}.example.test
#    over TCP once a second until it is answered: the import to serving time (resolution
#    about 1 s). TCP because UDP on WSL2 loopback was seen to go unanswered (2026-10-19)
#    while the same role answered over TCP; both transports read the same index.
#    The RSS after the import.
# 4. Restart. The node is stopped with SIGTERM and started again on the same data; the
#    start step lines `store` and `dns` of its log give the load from the store and the
#    index's own count of its bases. The RSS 3 s after the role answers.
# 5. Baseline. An empty node with the same configuration; its RSS at ready.
#
# Usage: run-m18-load.sh --server-binary PATH [options]
#   --harness PATH      the phase2-dns binary (default $HARNESS or phase2-dns on the PATH)
#   --records N         A records in example.test (default 1000000)
#   --roles LIST        the node's roles (default controller,dns; controller alone measures
#                       the import without the feed)
#   --data DIR          where the zone files go (default data/ of the harness)
#   --loopback ADDR     the API's and the role's loopback address (default 127.0.0.1)
#   --port N            the API port (default 18454); the role answers on N + 1
#   --allow-dynamic     do not refuse a dynamically linked binary on Linux
#   --out FILE          result file (default results/raw/m18-<stamp>.jsonl)
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER_BINARY=""; HARNESS="${HARNESS:-phase2-dns}"; RECORDS=1000000; ROLES="controller,dns"
DATA_ROOT="$ROOT/data"; LOOPBACK="${PHASE2_DNS_LOOPBACK:-127.0.0.1}"; PORT=18454
ALLOW_DYNAMIC=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --harness) HARNESS="$2"; shift 2 ;;
    --records) RECORDS="$2"; shift 2 ;;
    --roles) ROLES="$2"; shift 2 ;;
    --data) DATA_ROOT="$2"; shift 2 ;;
    --loopback) LOOPBACK="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,37p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SERVER_BINARY" ] || die "--server-binary PATH (tenko) is required"
[ -x "$SERVER_BINARY" ] || die "server binary not found: $SERVER_BINARY"
command -v "$HARNESS" >/dev/null 2>&1 || [ -x "$HARNESS" ] || die "harness not found: $HARNESS"
LINUX=0
[ "$(uname -s)" = Linux ] && LINUX=1
DNS_ROLE=0
case ",$ROLES," in *,dns,*) DNS_ROLE=1 ;; esac
URL="http://$LOOPBACK:$PORT"
DNS_TARGET="$LOOPBACK:$((PORT + 1))"
PASSWORD="73915482"
FORWARD="example.test"
REVERSE="2.0.192.in-addr.arpa 100.51.198.in-addr.arpa 113.0.203.in-addr.arpa"

[ -n "$OUT" ] || OUT="$ROOT/results/raw/m18-$STAMP.jsonl"
mkdir -p "$(dirname "$OUT")"
META="${OUT%.jsonl}.meta.txt"
LOG="${OUT%.jsonl}.server.log"
: > "$META"
WORK="$(mktemp -d)"
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }

note "run-m18-load: records=$RECORDS roles=$ROLES"
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

now() { date +%s.%3N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }

# The resident memory of the server in MiB (Windows: the working set; Linux: VmRSS).
rss_mib() {
  if [ "$LINUX" = 1 ]; then
    awk '/VmRSS/ { printf "%.1f", $2 / 1024 }' "/proc/$SRV/status" 2>/dev/null
  else
    tasklist //FI "PID eq $(native_pid "$SRV")" //FO CSV //NH 2>/dev/null |
      awk -F'","' '{ gsub(/[^0-9]/, "", $5); printf "%.1f", $5 / 1024 }'
  fi
}

# 1. Data.
DATA="$DATA_ROOT/m18-$RECORDS"
if [ ! -f "$DATA/$FORWARD.zone" ]; then
  say "zonegen: $RECORDS records into $DATA"
  "$HARNESS" zonegen --records "$RECORDS" --queries 1 --out-dir "$DATA" > /dev/null || die "zonegen failed"
fi
printf '%s A\n' "host-$((RECORDS - 1)).$FORWARD" > "$WORK/last.txt"

# Asks for the last host name over TCP until it is answered, at most $1 tries of about 1 s.
wait_served() {
  local tries="$1" out n
  while [ "$tries" -gt 0 ]; do
    out=$("$HARNESS" load --target "$DNS_TARGET" --names "$WORK/last.txt" --transport tcp \
      --clients 1 --inflight 1 --duration 1s --warmup 0s --timeout 200ms 2>/dev/null || true)
    n=$(printf '%s\n' "$out" | awk '$1 == "received" { gsub(",", "", $2); print $2 }')
    [ "${n:-0}" -gt 0 ] && return 0
    tries=$((tries - 1))
  done
  return 1
}

client() {
  TENKO_CREDENTIALS="$WORK/credentials" "$SERVER_BINARY" "$@" --url "$URL"
}

write_config() {
  cat > "$WORK/tenko.toml" <<TOML
data_dir = "$(native_path "$WORK")/data"
roles = "$ROLES"
modules = ["ipam", "dns"]

[server]
listen = ["$LOOPBACK:$PORT"]
allowed_origins = ["$URL"]

[runtime]
workers = 4

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

[dns]
listen = ["$DNS_TARGET"]
workers = 4
TOML
}

# Starts the server on the data directory as it is and waits until the API answers.
start_server() {
  "$SERVER_BINARY" serve --config "$(native_path "$WORK/tenko.toml")" >> "$LOG" 2>&1 &
  SRV=$!
  local tries=600
  while [ "$tries" -gt 0 ] && ! client health > /dev/null 2>&1; do
    kill -0 "$SRV" 2>/dev/null || die "the server exited at start (see $LOG)"
    sleep 0.2; tries=$((tries - 1))
  done
  [ "$tries" -gt 0 ] || die "the API did not answer within 120 s"
}

# A new node on an empty data directory, set up and logged in.
fresh_node() {
  rm -rf "$WORK/data" "$WORK/credentials" "$WORK/kek.key"
  mkdir -p "$WORK/data"
  write_config
  start_server
  printf '%s\n' "$PASSWORD" | client setup --setup-token "$(head -n 1 "$WORK/data/setup-token")" \
    --admin bench --host-name localhost --password-stdin > /dev/null || die "setup failed"
  printf '%s\n' "$PASSWORD" | client login --user bench --password-stdin > /dev/null || die "login failed"
}

# 2. A new node.
fresh_node
sleep 2
rss_empty_before=$(rss_mib)
note "node ready, RSS before the import ${rss_empty_before} MiB"

# 3. Import.
for zone in $REVERSE $FORWARD; do
  client dns zone create "$zone" --kind primary --ns "ns1.$FORWARD." --mname "ns1.$FORWARD." \
    --rname "hostmaster@$FORWARD" --serial counter > /dev/null || die "zone create $zone failed"
done
jobs=""
t_start=$(now)
for zone in $REVERSE $FORWARD; do
  t0=$(now)
  client dns import "$zone" "$(native_path "$DATA/$zone.zone")" --replace --wait-secs 3600 > /dev/null \
    || die "import of $zone failed"
  secs=$(elapsed "$t0" "$(now)")
  jobs="$jobs $secs"
  note "import $zone: $secs s"
done
t_imported=$(now)
import_secs=$(elapsed "$t_start" "$t_imported")
served_secs=null
if [ "$DNS_ROLE" = 1 ]; then
  wait_served 3600 || die "the role did not answer the last name"
  served_secs=$(elapsed "$t_start" "$(now)")
  note "import to serving the last name: $served_secs s (the import jobs: $import_secs s)"
else
  note "import jobs: $import_secs s (no dns role)"
fi
sleep 3
rss_after_import=$(rss_mib)
note "RSS after the import: $rss_after_import MiB"
du_store=$(du -sm "$WORK/data" | awk '{ print $1 }')
note "data directory after the import: $du_store MiB"

# 4. Restart.
stop_pid "$SRV"; SRV=""
log_lines=$(wc -l < "$LOG")
t0=$(now)
start_server
restart_api=$(elapsed "$t0" "$(now)")
dns_line=""
if [ "$DNS_ROLE" = 1 ]; then
  wait_served 600 || die "the role did not answer after the restart"
  tries=50
  while [ "$tries" -gt 0 ]; do
    dns_line=$(tail -n "+$((log_lines + 1))" "$LOG" | grep -o 'step [0-9]*/[0-9]* dns ready in [^"]*' | head -n 1)
    [ -n "$dns_line" ] && break
    sleep 0.2; tries=$((tries - 1))
  done
fi
store_line=$(tail -n "+$((log_lines + 1))" "$LOG" | grep -o 'step [0-9]*/[0-9]* store ready in [0-9]* ms' | head -n 1)
sleep 3
rss_restart=$(rss_mib)
hwm_restart=""
[ "$LINUX" = 1 ] && hwm_restart=$(awk '/VmHWM/ { printf "%.1f", $2 / 1024 }' "/proc/$SRV/status")
note "restart: API after $restart_api s; $store_line"
note "restart: $dns_line"
note "RSS after the restart: $rss_restart MiB (peak VmHWM ${hwm_restart:-n/a} MiB)"
stop_pid "$SRV"; SRV=""

# 5. Baseline.
fresh_node
sleep 2
rss_empty=$(rss_mib)
note "empty node at ready: RSS $rss_empty MiB"
stop_pid "$SRV"; SRV=""

dns_ms=$(printf '%s\n' "$dns_line" | sed -n 's/.* ready in \([0-9]*\) ms.*/\1/p')
store_ms=$(printf '%s\n' "$store_line" | sed -n 's/.* ready in \([0-9]*\) ms.*/\1/p')
index_mib=$(printf '%s\n' "$dns_line" | sed -n 's/.*index bases \([0-9.]*\) MiB.*/\1/p')
printf '{"records":%s,"roles":"%s","import_jobs_secs":[%s],"import_secs":%s,"served_secs":%s,"rss_before_import_mib":%s,"rss_after_import_mib":%s,"data_dir_mib":%s,"restart_store_ms":%s,"restart_dns_ms":%s,"index_bases_mib":%s,"rss_after_restart_mib":%s,"hwm_after_restart_mib":%s,"rss_empty_mib":%s}\n' \
  "$RECORDS" "$ROLES" "$(printf '%s\n' $jobs | paste -sd, -)" "$import_secs" "$served_secs" \
  "${rss_empty_before:-null}" "${rss_after_import:-null}" "${du_store:-null}" "${store_ms:-null}" \
  "${dns_ms:-null}" "${index_mib:-null}" "${rss_restart:-null}" "${hwm_restart:-null}" "${rss_empty:-null}" >> "$OUT"
note "results: $OUT"
