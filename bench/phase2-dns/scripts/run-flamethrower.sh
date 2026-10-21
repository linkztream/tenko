#!/usr/bin/env bash
# M17 (one node over a real link): flamethrower from another host against one Tenko node.
# Flamethrower (DNS-OARC) complements dnsperf: it sends over UDP, TCP, DoT and DoH, so it is
# the tool for the DoT and DoH figures of Slice 5 and for TCP at many connections.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# Pass --server-binary only when the script runs on the server host; otherwise record `ldd`
# of the binary on the server host in the results file. A dynamically linked binary is refused
# on Linux with a warning.
#
# Every figure is a single-node figure (plan section 2.10): one Tenko process on the server
# host, flamethrower on a different host (a VM and the workstation, per the plan).
#
# Flamethrower is not installed by this repository. Build or install it on the load host
# (https://github.com/DNS-OARC/flamethrower, binary "flame") and check the flags below against
# `flame -h` of that version. Run with flamethrower 0.12.0 for M17 (2026-10-21). If a
# spelling differs, pass the corrected generator arguments with --generator-args (they
# replace the default "-g file -f NAMES").
#
# The query file is the one zonegen writes (queries.txt, "name TYPE" per line):
#   phase2-dns zonegen --records 1000000 --out-dir data/1000000
# Give flame a file of about 100,000 lines (`head -n 100000 queries.txt`): flame 0.12 reads
# the whole file before it sends and its time limit runs from before the read, so with the
# million lines of queries.txt a 30 s run stops after the first burst.
#
# What one step does:
#   flame -p PORT -P PROTOCOL -c TCOUNT -q QCOUNT -l DURATION [-Q QPS] -o OUT.json
#         -g file -f NAMES SERVER
# The steps are total rates (--rates); flame's -Q is the rate of the whole process (checked
# with 0.12.0: -c 10 -Q 1000 sends 1,000 per second), and 0 runs without a rate limit,
# flamethrower's own pacing (the saturation run: --generators times --batch queries per
# millisecond at most, from one thread).
#
# What flame 0.12.0 showed against Tenko (M17, results/2026-10-21-m17-real-link.md): over
# TCP it opens a connection per burst, so its TCP rate measures connection set-up; over DoT
# every answer waits about 40 ms (dnsperf over DoT against the same node: 0.1 ms), the
# pattern of a small write held back until a delayed acknowledgement; over DoH it gets no
# answer at all, while curl and h2load get every answer from the same listener. The DoT
# and DoH figures of M17 therefore come from dnsperf (DoT) and h2load (DoH).
#
# Fields to record for the results file: from flamethrower's summary and its JSON output
#   total requests sent, total responses received, timeouts and errors, average latency with
#   minimum and maximum, the response codes (NOERROR, NXDOMAIN) and the achieved rate per
#   second. And from the server host (scripts/server-cpu.sh PID before and after each step):
#   the server's CPU seconds and RSS. And the link: both hosts' CPU model and core count, the
#   NIC speed, the path between them, the MTU, the ping RTT, the kernel version and the
#   flamethrower version.
#
# Usage:
#   run-flamethrower.sh --server ADDR --names FILE [options]
# Options:
#   --server ADDR        server IP address (required)
#   --port N             server port (default 53; 853 for dot, 443 for doh)
#   --names FILE         query file (required)
#   --protocol P         udp, tcp, dot or doh (default udp)
#   --rates LIST         space separated total rates, queries per second (default "0")
#   --duration SECONDS   length of a step (default 60)
#   --generators N       flame -c, traffic generators (default 10)
#   --batch N            flame -q, queries per generator per burst (default 10)
#   --generator-args ARGS  replaces the default "-g file -f NAMES"
#   --server-binary P    the server binary on this host, for the linkage check
#   --allow-dynamic      do not refuse a dynamically linked binary on Linux
#   --extra "ARGS"       further flame arguments
#   --out-dir DIR        output directory (default results/raw/flame-<stamp>)
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER=""; PORT=53; NAMES=""; PROTOCOL=udp; RATES="0"; DURATION=60; GENERATORS=10; BATCH=10
GENARGS=""; SERVER_BINARY=""; ALLOW_DYNAMIC=0; EXTRA=""; OUTDIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --names) NAMES="$2"; shift 2 ;;
    --protocol) PROTOCOL="$2"; shift 2 ;;
    --rates) RATES="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --generators) GENERATORS="$2"; shift 2 ;;
    --batch) BATCH="$2"; shift 2 ;;
    --generator-args) GENARGS="$2"; shift 2 ;;
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --extra) EXTRA="$2"; shift 2 ;;
    --out-dir) OUTDIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,65p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SERVER" ] || die "--server ADDR is required"
[ -n "$NAMES" ] && [ -f "$NAMES" ] || die "--names FILE is required (phase2-dns zonegen ...)"
case "$PROTOCOL" in udp|tcp|dot|doh) ;; *) die "--protocol is udp, tcp, dot or doh" ;; esac
command -v flame >/dev/null 2>&1 || die "flame (flamethrower) is not installed on this host; this script installs nothing"
[ -n "$GENARGS" ] || GENARGS="-g file -f $NAMES"
[ -n "$OUTDIR" ] || OUTDIR="$ROOT/results/raw/flame-$STAMP"
mkdir -p "$OUTDIR"
META="$OUTDIR/meta.txt"
: > "$META"

note "run-flamethrower: server=$SERVER:$PORT protocol=$PROTOCOL names=$NAMES ($(wc -l < "$NAMES") queries)"
note "$(machine_line)"
note "flame: $(flame --version 2>&1 | head -1)"
note "load: generators=$GENERATORS batch=$BATCH duration=${DURATION}s rates=[$RATES] generator-args=[$GENARGS]"
note "the load host is not the server host; record the server host and the link in the results file"
check_linkage "$SERVER_BINARY" "$ALLOW_DYNAMIC"

printf 'rate\tsent\treceived\ttimeouts\tqps\tavg_latency_ms\tmax_latency_ms\tnoerror\tnxdomain\ttcp_connections\n' > "$OUTDIR/summary.tsv"
for rate in $RATES; do
  out="$OUTDIR/step-$PROTOCOL-rate$rate"
  args=(-p "$PORT" -P "$PROTOCOL" -c "$GENERATORS" -q "$BATCH" -l "$DURATION" -o "$out.json")
  [ "$rate" = 0 ] || args+=(-Q "$rate")
  # shellcheck disable=SC2206
  args+=($GENARGS)
  # shellcheck disable=SC2206
  [ -z "$EXTRA" ] || args+=($EXTRA)
  say "step: rate=$rate  flame ${args[*]} $SERVER"
  flame "${args[@]}" "$SERVER" > "$out.txt" 2>&1 || note "flame exited with an error at rate $rate (see $out.txt)"
  # The summary's "avg resp" is not a number in 0.12.0, so the mean latency is the mean of
  # the per-second lines weighted by their answers; the rate is the answers over --duration.
  awk -v rate="$rate" -v secs="$DURATION" '
    /^[0-9.]+s: send:/ {
      if (match($0, / recv: [0-9]+/)) { r = substr($0, RSTART + 7, RLENGTH - 7) + 0 } else r = 0
      if (match($0, /resp: [0-9.]+\/[0-9.]+\/[0-9.]+ms/)) {
        split(substr($0, RSTART + 6, RLENGTH - 8), m, "/"); w += r * m[2]; n += r; if (m[3] > mx) mx = m[3]
      }
    }
    /^total sent/  { sent = $4 }
    /^total rcvd/  { rcvd = $4 }
    /^timeouts/    { to = $3 }
    /^tcp conn/    { tcp = $4 }
    /NOERROR:/     { ne = $2 }
    /NXDOMAIN:/    { nx = $2 }
    END {
      printf "%s\t%s\t%s\t%s\t%.0f\t%s\t%s\t%s\t%s\t%s\n", rate, sent, rcvd, to, rcvd / secs,
        (n > 0 ? sprintf("%.3f", w / n) : ""), mx, ne, nx, tcp
    }' "$out.txt" >> "$OUTDIR/summary.tsv"
done

say "raw output: $OUTDIR (one .txt summary and one .json per step, summary.tsv)"
cat "$OUTDIR/summary.tsv"
