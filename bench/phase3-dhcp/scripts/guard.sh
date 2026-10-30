#!/usr/bin/env bash
# The gate guard for the DHCP lease commit path (WP9.6): a change that costs commit time or
# store bytes per lease fails the gate visibly. One short run on loopback, the figures
# against bench/phase3-dhcp/guard.toml.
#
# A fresh `tenko serve` (roles controller and dhcp, the Lab profile, loopback ports above
# 1024, a throw-away data directory, started as the calling user) gets the bench scope
# through its API exactly as node-setup.sh creates it (198.18.0.0/15, one dhcp_pool range).
# The example's own load client (`dhcp_server load`, a relay agent; no perfdhcp) then runs
# two phases of DISCOVER, OFFER, REQUEST, ACK against the dhcp listener:
#
#   1. open loop, 12,000 clients at 1,000 exchanges per second for 10 s: the commit time of
#      the lease path at a rate the node keeps up with;
#   2. closed loop, 100,000 clients with 64 exchanges in flight for 10 s (--rate 0): the
#      ceiling of the commit path. If the node is faster than 10,000 per second the clients
#      run out before the 10 s, which the rate (completed over elapsed) allows for. Clients
#      are told apart by their index, so the first 12,000 of phase 2 meet the leases of
#      phase 1; the pool of 131,000 addresses does not run dry.
#
# The figures (guard.toml says how the thresholds were set):
#
#   commit_avg_ms      delta _sum over delta _count of tenko_dhcp_commit_duration_seconds
#                      (the metrics listener, one port above the API port) across phase 1,
#                      in milliseconds
#   closed_loop_per_s  the rate the load client prints for phase 2 (completed over elapsed)
#   bytes_per_lease    growth of the data directory (du -sk) from the stopped server after
#                      setup to the cleanly stopped server after phase 2, over the leases
#                      the gauge tenko_dhcp_leases (all states) counts at the end
#   rows_per_lease     not produced: the node exposes no store row count
#
# The server stops with SIGTERM before each size is read, so that redb trims its files.
# On Windows (Git Bash) kill ends a native process without the signal reaching it; the
# sizes are then those of a stopped, not cleanly closed, store.
#
# Build the two binaries once (release builds; the Linux target that ships is the static
# musl build, see run-loopback.sh: add --target x86_64-unknown-linux-musl to both):
#   cargo build -p tenko --release --locked
#   cargo build -p tenko-dhcp --release --locked --example dhcp_server
#
# Usage:
#   guard.sh --binary PATH_TO_TENKO --example PATH_TO_DHCP_SERVER_EXAMPLE
#            [--thresholds bench/phase3-dhcp/guard.toml] [--dir WORKDIR] [--workers 4]
#            [--keep]
# --dir names a work directory that does not exist or is empty; without it a directory
# under $TMPDIR is made. The work directory is removed at the end unless --keep. Needs
# bash, curl, python3 (or python), node and du. Nothing runs as root. The run takes under
# two minutes and ends with one line, GUARD OK or GUARD FAIL.
#
# The thresholds are in guard.toml. A change that costs commit time or store bytes per
# lease must raise them in the same commit.
#
# Exit codes: 0 every figure is within its limit, 1 a figure is worse, 2 the run itself
# failed (bad option, a missing tool, the server did not start).
set -u
export LC_ALL=C

BINARY=""; EXAMPLE=""; THRESHOLDS=""; WORK=""; KEEP=0; WORKERS=4
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PID=""; CREATED=0

say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$1"; }
die() { printf 'GUARD FAIL (run error): %s\n' "$1" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --example) EXAMPLE="${2:-}"; shift 2 ;;
    --thresholds) THRESHOLDS="${2:-}"; shift 2 ;;
    --dir) WORK="${2:-}"; shift 2 ;;
    --workers) WORKERS="${2:-}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$BINARY" ] && [ -f "$BINARY" ] || die "--binary must name the built tenko binary"
[ -n "$EXAMPLE" ] && [ -f "$EXAMPLE" ] || die "--example must name the built dhcp_server example"
[ -n "$THRESHOLDS" ] || THRESHOLDS="$HERE/../guard.toml"
[ -f "$THRESHOLDS" ] || die "thresholds file $THRESHOLDS not found"
case "$WORKERS" in ''|*[!0-9]*) die "--workers must be a number" ;; esac

for tool in curl node du awk; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is needed"
done
# python3 is a Microsoft Store stub on some Windows machines: probe it, fall back to python.
PY=""
for candidate in python3 python; do
  if "$candidate" -c 'import json' >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[ -n "$PY" ] || die "python3 (or python) is needed"

abs() { (cd "$(dirname "$1")" && printf '%s/%s' "$(pwd)" "$(basename "$1")"); }
BINARY="$(abs "$BINARY")"; EXAMPLE="$(abs "$EXAMPLE")"; THRESHOLDS="$(abs "$THRESHOLDS")"

# The work directory: a path the native binaries also understand (C:/... on Windows).
if [ -z "$WORK" ]; then
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/guard.XXXXXX")" || die "cannot make a work directory"
  CREATED=1
else
  if [ -e "$WORK" ]; then
    [ -d "$WORK" ] && [ -z "$(ls -A "$WORK")" ] || die "--dir $WORK exists and is not empty"
  else
    mkdir -p "$WORK" || die "cannot make $WORK"
    CREATED=1
  fi
fi
if command -v cygpath >/dev/null 2>&1; then WORK="$(cygpath -m "$WORK")"; else WORK="$(cd "$WORK" && pwd)"; fi

stop_server() {
  # Also after a failed start: node-setup.sh leaves the pid in the work directory.
  [ -n "$SERVER_PID" ] || SERVER_PID="$(cat "$WORK/server.pid" 2>/dev/null)"
  [ -n "$SERVER_PID" ] || return 0
  kill -TERM "$SERVER_PID" 2>/dev/null
  for _ in $(seq 1 150); do
    kill -0 "$SERVER_PID" 2>/dev/null || { SERVER_PID=""; rm -f "$WORK/server.pid"; sleep 1; return 0; }
    sleep 0.2
  done
  kill -KILL "$SERVER_PID" 2>/dev/null
  sleep 1
  SERVER_PID=""
  rm -f "$WORK/server.pid"
}
cleanup() {
  stop_server
  if [ "$KEEP" -eq 1 ]; then
    say "kept $WORK"
  elif [ "$CREATED" -eq 1 ] && [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# Free loopback ports: a TCP port with its neighbour above (API and metrics), and two UDP
# ports (the dhcp listener and the load client's relay address).
read -r API_PORT DHCP_PORT RELAY_PORT < <("$PY" - <<'PY' | tr -d '\015'
import random, socket
def free(kind, port):
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()
while True:
    base = random.randrange(20000, 60000)
    if all(free(socket.SOCK_STREAM, p) for p in (base, base + 1)) and \
       free(socket.SOCK_DGRAM, base + 2) and free(socket.SOCK_DGRAM, base + 3):
        print(base, base + 2, base + 3)
        break
PY
)
[ -n "${API_PORT:-}" ] || die "no free loopback ports"
METRICS_URL="http://127.0.0.1:$((API_PORT + 1))/metrics"

mkdir -p "$WORK/bin" "$WORK/shim"
ext=""; case "$BINARY" in *.exe) ext=".exe" ;; esac
cp "$BINARY" "$WORK/bin/server$ext" && chmod +x "$WORK/bin/server$ext" || die "cannot copy the binary"
# node-setup.sh calls python3: when only python works, give it a python3 of its own.
if [ "$PY" != "python3" ]; then
  printf '#!/usr/bin/env bash\nexec %s "$@"\n' "$PY" >"$WORK/shim/python3"
  chmod +x "$WORK/shim/python3"
  export PATH="$(cd "$WORK/shim" && pwd):$PATH"
fi

# metric NAME: the sum of the samples of one family or series (labels ignored).
metric() {
  curl -fsS "$METRICS_URL" 2>/dev/null | awk -v n="$1" '
    /^#/ { next }
    { name = $1; sub(/\{.*/, "", name) }
    name == n { sum += $NF; seen = 1 }
    END { if (seen) printf "%.12g\n", sum; else print "NaN" }'
}
size_kb() { du -sk "$WORK/data" | awk '{ print $1 }'; }

wait_ready() {
  for _ in $(seq 1 120); do
    curl -fsS "http://127.0.0.1:$API_PORT/api/v1/health/ready" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

say "starting a fresh node (api $API_PORT, dhcp $DHCP_PORT, relay $RELAY_PORT)"
bash "$HERE/node-setup.sh" start "$WORK" 127.0.0.1 "$DHCP_PORT" "$RELAY_PORT" "$API_PORT" "$WORKERS" server.log \
  || { [ -f "$WORK/server.log" ] && tail -n 20 "$WORK/server.log" >&2; die "node-setup.sh failed"; }
SERVER_PID="$(cat "$WORK/server.pid" 2>/dev/null)"
[ -n "$SERVER_PID" ] || die "no server pid"

# The baseline size is read from a stopped server; the same node starts again on the same
# data directory and configuration (the launch lines of node-setup.sh).
say "stopping to read the baseline size"
stop_server
BEFORE_KB="$(size_kb)"
say "starting again on the same data directory (baseline ${BEFORE_KB} KiB)"
(
  cd "$WORK" || exit 1
  TENKO_KEK__PROVIDER=file TENKO_KEK__PATH="$WORK/kek" TENKO_HIBP__ONLINE=false \
    TENKO_UPDATES__AIR_GAPPED=true \
    nohup bin/server serve --config "$WORK/tenko.toml" >>"$WORK/server.log" 2>&1 </dev/null &
  echo $! >"$WORK/server.pid"
)
SERVER_PID="$(cat "$WORK/server.pid")"
wait_ready || { tail -n 20 "$WORK/server.log" >&2; die "the node did not become ready again"; }
sleep 3  # the role takes the scope from the feed
kill -0 "$SERVER_PID" 2>/dev/null || die "the node exited at the restart"

run_load() {
  # run_load NAME CLIENTS RATE: one 10 s phase; the load client's line goes to $WORK/NAME.out
  local limit=()
  command -v timeout >/dev/null 2>&1 && limit=(timeout 90)
  "${limit[@]}" "$EXAMPLE" load --server "127.0.0.1:$DHCP_PORT" --bind "127.0.0.1:$RELAY_PORT" \
    --mode dora --clients "$2" --rate "$3" --window 64 --seconds 10 >"$WORK/$1.out" 2>&1 \
    || { cat "$WORK/$1.out" >&2; die "the load client failed in phase $1"; }
  say "$(tr -d '\r' <"$WORK/$1.out" | tail -n 1)"
}

SUM0="$(metric tenko_dhcp_commit_duration_seconds_sum)"
COUNT0="$(metric tenko_dhcp_commit_duration_seconds_count)"
LEASES0="$(metric tenko_dhcp_leases)"
# A family with no sample yet is absent from the text: count it as zero.
[ "$SUM0" != "NaN" ] || SUM0=0
[ "$COUNT0" != "NaN" ] || COUNT0=0
[ "$LEASES0" != "NaN" ] || LEASES0=0

say "phase 1: open loop, 1,000 exchanges per second for 10 s"
run_load open 12000 1000
SUM1="$(metric tenko_dhcp_commit_duration_seconds_sum)"
COUNT1="$(metric tenko_dhcp_commit_duration_seconds_count)"
[ "$COUNT1" != "NaN" ] || die "the metrics listener at $METRICS_URL has no tenko_dhcp_commit_duration_seconds"

say "phase 2: closed loop, 64 in flight for 10 s"
run_load closed 100000 0
COUNT2="$(metric tenko_dhcp_commit_duration_seconds_count)"
LEASES2="$(metric tenko_dhcp_leases)"

say "stopping the node to read the final size"
stop_server
AFTER_KB="$(size_kb)"

FIGURES="$WORK/figures.json"
"$PY" - "$FIGURES" "$WORK/closed.out" "$SUM0" "$COUNT0" "$SUM1" "$COUNT1" "$COUNT2" \
  "$LEASES0" "$LEASES2" "$BEFORE_KB" "$AFTER_KB" <<'PY' || die "cannot compute the figures"
import json, re, sys
out, closed = sys.argv[1], sys.argv[2]
sum0, count0, sum1, count1, count2, leases0, leases2, before, after = (float(v) for v in sys.argv[3:])
def finite(x):
    return x == x
line = open(closed).read().strip().splitlines()[-1]
m = re.search(r"([0-9]+) per second over", line)
phase1 = count1 - count0
leases = leases2 - leases0 if finite(leases2) and finite(leases0) else float("nan")
figures = {
    "commit_avg_ms": (sum1 - sum0) / phase1 * 1000.0 if finite(phase1) and phase1 > 0 else None,
    "closed_loop_per_s": float(m.group(1)) if m else None,
    "bytes_per_lease": (after - before) * 1024.0 / leases if finite(leases) and leases > 0 else None,
    "details": {
        "phase1_commits": phase1,
        "phase2_commits": count2 - count1,
        "leases": leases,
        "data_dir_kib_before": before,
        "data_dir_kib_after": after,
    },
}
json.dump(figures, open(out, "w"), indent=2)
PY
say "figures: $(tr -d '\r\n ' <"$FIGURES")"

node "$HERE/guard-check.mjs" --thresholds "$THRESHOLDS" --figures "$FIGURES"
code=$?
summary="$("$PY" - "$FIGURES" <<'PY'
import json, sys
f = json.load(open(sys.argv[1]))
def v(key, unit, digits):
    x = f.get(key)
    return "%s=missing" % key if x is None else "%s=%.*f%s" % (key, digits, x, unit)
print(" ".join([v("commit_avg_ms", "ms", 3), v("closed_loop_per_s", "/s", 0), v("bytes_per_lease", "B", 0)]))
PY
)"
summary="${summary//$'\r'/}"
case "$code" in
  0) printf 'GUARD OK %s\n' "$summary"; exit 0 ;;
  1) printf 'GUARD FAIL %s (see the FAIL lines above and %s)\n' "$summary" "$THRESHOLDS"; exit 1 ;;
  *) printf 'GUARD FAIL (run error) guard-check.mjs exited %s\n' "$code"; exit 2 ;;
esac
