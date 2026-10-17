#!/usr/bin/env bash
# M16 (QPS per core, loopback) and M22 (metrics cost on the query path): the load generator
# against a DNS server on the same host.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# A dynamically linked --server-binary is refused on Linux with a warning (--allow-dynamic
# overrides; such a run is marked not publishable). Windows runs use the release build.
#
# Every figure is a single-node figure (plan section 2.10): one server process, the load
# generator on the same host. Loopback numbers are upper bounds and are labelled so.
#
# For every combination of transport, metrics switch and worker count the script starts the
# server, waits until it answers, runs the load generator for one measured window while it
# samples the server's CPU and RSS by pid, and stops the server. One JSON line per run goes to
# the output file; the harness "report" subcommand turns the file into the Markdown tables.
#
# Usage:
#   run-loopback.sh --server-cmd CMD --names FILE [options]
#   run-loopback.sh --server-pid PID --names FILE [options]     (a server that is already running)
#
# Options:
#   --server-cmd CMD    command that starts the server in the foreground. {listen}, {workers} and
#                       {metrics} are replaced in it ({metrics} by "on" or "off"). It is
#                       split at spaces (no quoting) and started directly, so the pid is the
#                       server's own. Example (Spike B):
#                       "spike-b-udp serve --backend domain --mode tokio --workers {workers} --listen {listen}"
#   --server-pid PID    measure a running server; only one configuration (the workers and
#                       metrics lists must then hold one value or be "none")
#   --server-binary P   the server binary, for the linkage check and the meta file
#   --allow-dynamic     do not refuse a dynamically linked binary on Linux
#   --names FILE        query file (zonegen writes queries.txt)
#   --harness PATH      the phase2-dns binary (default: $HARNESS or phase2-dns on the PATH)
#   --listen ADDR       address the server listens on (default 127.0.0.1:5399; on Windows UDP
#                       5353 is held by the system mDNS responder)
#   --workers LIST      worker counts, space separated, or "none" if the server has no worker
#                       setting (default "1 2 4 8 16")
#   --transports LIST   "udp", "tcp" or "udp tcp" (default "udp tcp"; the TCP server must listen
#                       on the same port)
#   --metrics LIST      "off on" to run both settings, or "none" if the server has no metrics
#                       switch (default none)
#   --clients N         load generator sockets/connections (default 8)
#   --inflight N        queries in flight per client (default 32)
#   --duration D        measured window (default 30s); --warmup D (default 2s)
#   --runs N            repetitions of every configuration (default 1)
#   --require-aa        count responses without AA as errors (authoritative server)
#   --label NAME        label in the result records (default: the server program's name)
#   --out FILE          result file (default results/raw/loopback-<stamp>.jsonl)
#   --settle SECONDS    pause after the server answers (default 1)
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER_CMD=""; SERVER_PID=""; SERVER_BINARY=""; ALLOW_DYNAMIC=0; NAMES=""
HARNESS="${HARNESS:-phase2-dns}"; LISTEN="127.0.0.1:5399"
WORKERS="1 2 4 8 16"; TRANSPORTS="udp tcp"; METRICS="none"
CLIENTS=8; INFLIGHT=32; DURATION=30s; WARMUP=2s; RUNS=1; REQUIRE_AA=0; LABEL=""; OUT=""; SETTLE=1

while [ $# -gt 0 ]; do
  case "$1" in
    --server-cmd) SERVER_CMD="$2"; shift 2 ;;
    --server-pid) SERVER_PID="$2"; shift 2 ;;
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --names) NAMES="$2"; shift 2 ;;
    --harness) HARNESS="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --transports) TRANSPORTS="$2"; shift 2 ;;
    --metrics) METRICS="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --inflight) INFLIGHT="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --require-aa) REQUIRE_AA=1; shift ;;
    --label) LABEL="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
    -h|--help) sed -n '2,46p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$NAMES" ] && [ -f "$NAMES" ] || die "--names FILE is required (phase2-dns zonegen --records 100000 --out-dir data/100000)"
[ -n "$SERVER_CMD" ] || [ -n "$SERVER_PID" ] || die "give --server-cmd or --server-pid"
[ -z "$SERVER_CMD" ] || [ -z "$SERVER_PID" ] || die "--server-cmd and --server-pid exclude each other"
command -v "$HARNESS" >/dev/null 2>&1 || [ -x "$HARNESS" ] || die "harness not found: $HARNESS (cargo build --release in bench/phase2-dns)"
if [ -n "$SERVER_PID" ]; then
  set -- $WORKERS
  [ $# -le 1 ] || die "--server-pid measures one configuration; give one --workers value or none"
  set -- $METRICS
  [ $# -le 1 ] || die "--server-pid measures one configuration; give one --metrics value or none"
fi
[ -n "$LABEL" ] || LABEL="$(basename "${SERVER_CMD%% *}" .exe)"
[ -n "$OUT" ] || OUT="$ROOT/results/raw/loopback-$STAMP.jsonl"
mkdir -p "$(dirname "$OUT")"
META="${OUT%.jsonl}.meta.txt"
: > "$META"

note "run-loopback: label=$LABEL names=$NAMES ($(wc -l < "$NAMES") queries) listen=$LISTEN"
note "$(machine_line)"
note "harness: $("$HARNESS" --version 2>&1) at $HARNESS"
note "load: clients=$CLIENTS inflight=$INFLIGHT warmup=$WARMUP duration=$DURATION runs=$RUNS transports=[$TRANSPORTS] workers=[$WORKERS] metrics=[$METRICS]"
note "loopback numbers are upper bounds: client and server share this host and its CPUs"
check_linkage "$SERVER_BINARY" "$ALLOW_DYNAMIC"

SRV=""
stop_server() {
  [ -z "$SRV" ] && return 0
  # Windows: the MSYS kill may leave the native process; stop it by Windows pid too.
  local winpid=""
  [ -r "/proc/$SRV/winpid" ] && winpid="$(cat "/proc/$SRV/winpid")"
  kill "$SRV" 2>/dev/null
  [ -z "$winpid" ] || taskkill //F //PID "$winpid" >/dev/null 2>&1
  wait "$SRV" 2>/dev/null
  SRV=""
}
trap stop_server EXIT

run_one() {
  local transport="$1" workers="$2" metrics="$3" run="$4" pid cmd
  local -a args argv
  if [ -n "$SERVER_CMD" ]; then
    cmd="${SERVER_CMD//\{listen\}/$LISTEN}"
    cmd="${cmd//\{workers\}/$workers}"
    cmd="${cmd//\{metrics\}/$metrics}"
    note "start: $cmd"
    read -r -a argv <<< "$cmd"
    "${argv[@]}" > "${OUT%.jsonl}.server-$transport-w$workers-m$metrics-r$run.log" 2>&1 &
    SRV=$!
    pid="$(native_pid "$SRV")"
    wait_ready "$HARNESS" "$LISTEN" "$NAMES" || { stop_server; die "the server did not answer on $LISTEN"; }
    sleep "$SETTLE"
  else
    pid="$SERVER_PID"
  fi
  args=(load --target "$LISTEN" --names "$NAMES" --transport "$transport" --clients "$CLIENTS"
        --inflight "$INFLIGHT" --duration "$DURATION" --warmup "$WARMUP" --server-pid "$pid"
        --label "$LABEL" --json "$OUT")
  [ "$workers" = none ] || args+=(--workers "$workers")
  [ "$metrics" = none ] || args+=(--metrics "$metrics")
  [ "$REQUIRE_AA" = 0 ] || args+=(--require-aa)
  say "run: $transport workers=$workers metrics=$metrics (run $run of $RUNS)"
  "$HARNESS" "${args[@]}" 2>&1 | tee -a "${OUT%.jsonl}.log"
  [ "${PIPESTATUS[0]}" = 0 ] || note "the load run failed: $transport workers=$workers metrics=$metrics"
  stop_server
}

for transport in $TRANSPORTS; do
  for metrics in $METRICS; do
    for workers in $WORKERS; do
      for run in $(seq 1 "$RUNS"); do
        run_one "$transport" "$workers" "$metrics" "$run"
      done
    done
  done
done

say "results: $OUT"
say "tables:  $HARNESS report --input $OUT"
