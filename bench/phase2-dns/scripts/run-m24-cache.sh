#!/usr/bin/env bash
# M24 (cache behaviour, docs/plans/phase-2-plan.md section 6): the hit ratio, the latency and
# the memory of the resolver's cache at its bound in a 1 M-name mixed run, and serve-stale
# answers while the upstream is cut.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# A dynamically linked --server-binary is refused with a warning (--allow-dynamic overrides;
# the run is then marked not publishable). Windows runs (Git Bash) use the release build. The
# upstream is the engine's example server (crates/tenko-dns/examples/authoritative.rs), built
# the same way:
#   cargo build -p tenko-dns --example authoritative --release --locked [--target ...]
#
# Every figure is a single-node figure (plan section 2.10): one resolver node (`tenko serve
# --roles controller,dns`, the cache under test), one upstream process serving the zonegen
# zone, the load generator, all on this host. Loopback numbers are upper bounds.
#
# 1. Data. `zonegen --records N --queries N` (N = --names, default 1,000,000) writes the zone's
#    query file: N queries sampled with replacement from the N names, 5 percent NXDOMAIN. The
#    mixed file adds a hot set: the first --hot lines (default 10,000) repeated until they are
#    --hot-share percent (default 80) of the lines. The load generator picks lines uniformly,
#    so 80 percent of the queries ask 10,000 names and 20 percent ask the whole population.
# 2. Upstream. The example server answers the same N names on port 5400.
# 3. Resolver, per cache bound in --entries (default "100000 1000000"): `tenko serve` with
#    the default forwarder at the upstream, the cache bound to that many entries (max_bytes
#    raised so that the entry bound is the one that binds) and prefetch on, its DNS on port
#    5300 and its metrics on a loopback listener. Pass 1 warms the cache (closed loop,
#    --warm), pass 2 is the measured window (closed loop, --duration), pass 3 a paced run at
#    --qps. The cache counters (hits, misses, stale, entries) are read from /metrics before
#    and after each pass; the load generator samples the resolver's CPU and RSS.
# 4. Serve-stale. A resolver whose entries live 5 seconds (max_ttl_secs = 5, stale budget
#    400 ms) is warmed with the hot set, then a paced run of --cut-total seconds asks the hot
#    set while the upstream is cut from second 10 for --cut seconds: on Linux the upstream is
#    stopped (SIGSTOP) and resumed (SIGCONT), so its queries time out; elsewhere it is killed
#    and started again, so its port refuses them. Expect: no errors, answers from the stale
#    entries while it is cut (the stale counter), and the refresh after it is back.
#
# Usage: run-m24-cache.sh --server-binary PATH --upstream-binary PATH [options]
#   --harness PATH          the phase2-dns binary (default $HARNESS or phase2-dns on the PATH)
#   --names N               names in the zone and queries in the file (default 1000000)
#   --entries LIST          cache bounds to measure (default "100000 1000000")
#   --hot N, --hot-share P  the hot set and its share of the queries (10000, 80)
#   --workers N             UDP workers of the resolver (default 2)
#   --clients N, --inflight N   load generator sockets and queries in flight (4, 32)
#   --warm D, --duration D  the warm-up and the measured pass (60s, 30s)
#   --qps R                 the paced pass and the serve-stale run (default 20000)
#   --cut S, --cut-total S  seconds the upstream is cut, and the length of that run (30, 60)
#   --data DIR              where the zone and query files go (default data/ of the harness)
#   --loopback ADDR         the loopback address of the three processes (default
#                           $PHASE2_DNS_LOOPBACK or 127.0.0.1)
#   --allow-dynamic         do not refuse a dynamically linked binary on Linux
#   --out FILE              result file (default results/raw/m24-<stamp>.jsonl)
#   --print-plan            print this text and exit
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER_BINARY=""; UPSTREAM_BINARY=""; ALLOW_DYNAMIC=0; HARNESS="${HARNESS:-phase2-dns}"
NAMES_COUNT=1000000; ENTRIES="100000 1000000"; HOT=10000; HOT_SHARE=80; WORKERS=2
CLIENTS=4; INFLIGHT=32; WARM=60s; DURATION=30s; QPS=20000; CUT=30; CUT_TOTAL=60; OUT=""
DATA_ROOT="$ROOT/data"
LOOPBACK="${PHASE2_DNS_LOOPBACK:-127.0.0.1}"

while [ $# -gt 0 ]; do
  case "$1" in
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --upstream-binary) UPSTREAM_BINARY="$2"; shift 2 ;;
    --harness) HARNESS="$2"; shift 2 ;;
    --names) NAMES_COUNT="$2"; shift 2 ;;
    --entries) ENTRIES="$2"; shift 2 ;;
    --hot) HOT="$2"; shift 2 ;;
    --hot-share) HOT_SHARE="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --inflight) INFLIGHT="$2"; shift 2 ;;
    --warm) WARM="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --qps) QPS="$2"; shift 2 ;;
    --cut) CUT="$2"; shift 2 ;;
    --cut-total) CUT_TOTAL="$2"; shift 2 ;;
    --data) DATA_ROOT="$2"; shift 2 ;;
    --loopback) LOOPBACK="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --print-plan|-h|--help) sed -n '2,54p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

LINUX=0
[ "$(uname -s)" = Linux ] && LINUX=1
DNS="$LOOPBACK:5300"; UPSTREAM="$LOOPBACK:5400"; METRICS="$LOOPBACK:19464"; API="$LOOPBACK:18443"
[ -n "$SERVER_BINARY" ] || die "--server-binary PATH (tenko) is required"
[ -n "$UPSTREAM_BINARY" ] || die "--upstream-binary PATH (the example authoritative) is required"
[ -x "$UPSTREAM_BINARY" ] || die "upstream binary not found: $UPSTREAM_BINARY"
command -v "$HARNESS" >/dev/null 2>&1 || [ -x "$HARNESS" ] || die "harness not found: $HARNESS"
command -v curl >/dev/null 2>&1 || die "curl is needed to read the resolver's metrics"
[ "$CUT" -lt "$((CUT_TOTAL - 10))" ] || die "--cut must end before --cut-total"

[ -n "$OUT" ] || OUT="$ROOT/results/raw/m24-$STAMP.jsonl"
mkdir -p "$(dirname "$OUT")"
META="${OUT%.jsonl}.meta.txt"
: > "$META"
WORK="$(mktemp -d)"
# The path tenko reads in its configuration file (a Windows path under Git Bash).
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }

note "run-m24-cache: names=$NAMES_COUNT entries=[$ENTRIES] hot=$HOT share=$HOT_SHARE% workers=$WORKERS"
note "$(machine_line)"
note "harness: $("$HARNESS" --version 2>&1) at $HARNESS"
note "load: clients=$CLIENTS inflight=$INFLIGHT warm=$WARM duration=$DURATION qps=$QPS cut=${CUT}s of ${CUT_TOTAL}s"
note "loopback numbers are upper bounds: resolver, upstream and load generator share this host"
check_linkage "$SERVER_BINARY" "$ALLOW_DYNAMIC"
check_linkage "$UPSTREAM_BINARY" "$ALLOW_DYNAMIC"

UP=""; SRV=""
# Stops a background process; under Git Bash the native process too.
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
  [ -z "$UP" ] || [ "$LINUX" = 0 ] || kill -CONT "$UP" 2>/dev/null
  stop_pid "$SRV"; stop_pid "$UP"; rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT

# 1. Data.
DATA="$DATA_ROOT/m24-$NAMES_COUNT"
if [ ! -f "$DATA/queries.txt" ]; then
  say "zonegen: $NAMES_COUNT names and queries into $DATA"
  "$HARNESS" zonegen --records "$NAMES_COUNT" --queries "$NAMES_COUNT" --out-dir "$DATA" > /dev/null \
    || die "zonegen failed"
fi
MIXED="$DATA/mixed-$HOT-$HOT_SHARE.txt"
HOTFILE="$DATA/hot-$HOT.txt"
head -n "$HOT" "$DATA/queries.txt" > "$HOTFILE"
if [ ! -f "$MIXED" ]; then
  repeats=$(( (NAMES_COUNT * HOT_SHARE) / ((100 - HOT_SHARE) * HOT) ))
  [ "$repeats" -ge 1 ] || repeats=1
  { cat "$DATA/queries.txt"; for _ in $(seq 1 "$repeats"); do cat "$HOTFILE"; done; } > "$MIXED"
fi
note "mixed file: $MIXED, $(wc -l < "$MIXED") lines, $(sort -u "$MIXED" | wc -l) distinct questions"

# Nothing may answer on the ports yet: a process left from another run would be measured.
for address in "$UPSTREAM" "$DNS"; do
  answered=$("$HARNESS" load --target "$address" --names "$HOTFILE" --clients 1 --inflight 1 \
    --duration 1s --warmup 0s --timeout 200ms 2>/dev/null |
    awk '($1 == "received" || $1 == "errors") { gsub(",", "", $2); n += $2 } END { print n + 0 }')
  [ "$answered" = 0 ] || die "something already answers on $address: stop it first"
done

# 2. Upstream.
start_upstream() {
  "$UPSTREAM_BINARY" --listen "$UPSTREAM" --names "$NAMES_COUNT" --workers 2 --metrics off \
    >> "${OUT%.jsonl}.upstream.log" 2>&1 &
  UP=$!
  wait_ready "$HARNESS" "$UPSTREAM" "$HOTFILE" 120 || die "the upstream did not answer on $UPSTREAM"
}
start_upstream
note "upstream: $UPSTREAM_BINARY on $UPSTREAM"

# One counter or gauge from the resolver's metrics, summed over its series; 0 when absent.
metric() {
  curl -s -m 5 --interface "$LOOPBACK" "http://$METRICS/metrics" | awk -v name="$1" '
    index($0, name) == 1 { n = split($0, f, " "); sum += f[n] } END { printf "%d\n", sum + 0 }'
}

# The configuration of a resolver: $1 entries, $2 max TTL, $3 stale budget in ms.
write_config() {
  cat > "$WORK/tenko.toml" <<TOML
data_dir = "$(native_path "$WORK")/data"
roles = "controller,dns"
modules = ["ipam", "dns"]

[server]
listen = ["$API"]

[metrics]
listen = "$METRICS"

[hibp]
online = false

[updates]
air_gapped = true

[dns]
listen = ["$DNS"]
workers = $WORKERS
forwarders = ["$UPSTREAM"]
forward_timeout_ms = 1000
forward_retries = 1

[dns.cache]
entries = $1
max_bytes = 8589934592
max_ttl_secs = $2
stale_answer_ms = $3
prefetch = true
TOML
}

# Waits until the resolver answers recursive queries (wait_ready asks without RD, which a
# resolver refuses).
wait_resolver() {
  local tries=120 out n
  while [ "$tries" -gt 0 ]; do
    out=$("$HARNESS" load --target "$DNS" --names "$HOTFILE" --rd --clients 1 --inflight 1 \
      --duration 1s --warmup 0s --timeout 500ms 2>/dev/null || true)
    n=$(printf '%s\n' "$out" | awk '$1 == "received" { gsub(",", "", $2); print $2 }')
    [ "${n:-0}" -gt 0 ] && return 0
    tries=$((tries - 1))
  done
  return 1
}

start_resolver() {
  rm -rf "$WORK/data"
  write_config "$@"
  "$SERVER_BINARY" serve --config "$(native_path "$WORK/tenko.toml")" \
    > "${OUT%.jsonl}.server-$1-$2.log" 2>&1 &
  SRV=$!
  wait_resolver || die "the resolver did not answer on $DNS"
  sleep 1
}

# A load pass: $1 label, $2 names file, then load generator arguments.
pass() {
  local label="$1" names="$2" h0 m0 s0 h1 m1 s1 entries
  shift 2
  h0=$(metric tenko_dns_cache_hits_total); m0=$(metric tenko_dns_cache_misses_total)
  s0=$(metric tenko_dns_cache_stale_total)
  say "pass: $label"
  "$HARNESS" load --target "$DNS" --names "$names" --rd --server-pid "$(native_pid "$SRV")" \
    --workers "$WORKERS" --label "$label" --json "$OUT" "$@" 2>&1 | tee -a "${OUT%.jsonl}.log"
  [ "${PIPESTATUS[0]}" = 0 ] || note "the load pass failed: $label"
  h1=$(metric tenko_dns_cache_hits_total); m1=$(metric tenko_dns_cache_misses_total)
  s1=$(metric tenko_dns_cache_stale_total); entries=$(metric tenko_dns_cache_entries)
  note "cache $label: hits $((h1 - h0)) misses $((m1 - m0)) stale $((s1 - s0)) entries $entries hit_ratio $(awk -v h=$((h1 - h0)) -v m=$((m1 - m0)) 'BEGIN { if (h + m > 0) printf "%.4f", h / (h + m); else print "n/a" }')"
}

# 3. The cache at its bound.
for entries in $ENTRIES; do
  start_resolver "$entries" 86400 1800
  note "resolver: $SERVER_BINARY, cache bound $entries entries"
  pass "m24-warm-$entries" "$MIXED" --clients "$CLIENTS" --inflight "$INFLIGHT" --duration "$WARM" --warmup 0s --timeout 3s
  pass "m24-closed-$entries" "$MIXED" --clients "$CLIENTS" --inflight "$INFLIGHT" --duration "$DURATION" --warmup 2s --timeout 3s
  pass "m24-paced-$entries" "$MIXED" --clients "$CLIENTS" --inflight "$INFLIGHT" --duration "$DURATION" --warmup 2s --timeout 3s --qps "$QPS"
  stop_pid "$SRV"; SRV=""
done

# 4. Serve-stale under an upstream cut.
start_resolver 100000 5 400
note "resolver: $SERVER_BINARY, entries live 5 s, stale budget 400 ms"
pass "m24-stale-warm" "$HOTFILE" --clients "$CLIENTS" --inflight "$INFLIGHT" --duration 10s --warmup 0s --timeout 3s
if [ "$LINUX" = 1 ]; then
  ( sleep 10; kill -STOP "$UP"; say "upstream stopped (SIGSTOP)"
    sleep "$CUT"; kill -CONT "$UP"; say "upstream resumed (SIGCONT)" ) &
  CUTTER=$!
  pass "m24-stale-cut" "$HOTFILE" --clients "$CLIENTS" --inflight "$INFLIGHT" --duration "${CUT_TOTAL}s" --warmup 0s --timeout 3s --qps "$QPS"
  wait "$CUTTER"
else
  # A background subshell cannot restart the upstream for this shell, so the cut runs in the
  # foreground around a load pass of its own.
  ( sleep 10; stop_pid "$UP"; say "upstream killed" ) &
  CUTTER=$!
  (
    sleep $((10 + CUT))
    "$UPSTREAM_BINARY" --listen "$UPSTREAM" --names "$NAMES_COUNT" --workers 2 --metrics off \
      >> "${OUT%.jsonl}.upstream.log" 2>&1 &
    echo "$!" > "$WORK/upstream.pid"
    wait
  ) &
  pass "m24-stale-cut" "$HOTFILE" --clients "$CLIENTS" --inflight "$INFLIGHT" --duration "${CUT_TOTAL}s" --warmup 0s --timeout 3s --qps "$QPS"
  wait "$CUTTER"
  UP="$(cat "$WORK/upstream.pid" 2>/dev/null)"
  [ -n "$UP" ] || die "the upstream was not started again"
  say "upstream started again after ${CUT}s"
fi
pass "m24-stale-after" "$HOTFILE" --clients "$CLIENTS" --inflight "$INFLIGHT" --duration 10s --warmup 0s --timeout 3s --qps "$QPS"

say "results: $OUT"
say "meta:    $META"
say "tables:  $HARNESS report --input $OUT"
