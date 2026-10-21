#!/usr/bin/env bash
# M17 (one node over a real link): dnsperf from another host against one Tenko node.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# The server runs on another host or VM, so this script cannot see its binary: pass the path
# the server host uses with --server-binary only when it is run there (the linkage check is
# then done here); otherwise record `ldd` of the binary on the server host in the results file.
#
# Every figure is a single-node figure (plan section 2.10): one Tenko process on the server
# host, dnsperf on a different host (a VM and the workstation, per the plan).
#
# The query file is the one zonegen writes (queries.txt, "name TYPE" per line, the dnsperf
# input format). Generate it with the zone the server loads:
#   phase2-dns zonegen --records 1000000 --out-dir data/1000000
#
# dnsperf is not installed by this repository. Install it on the load host from the package
# manager (dnsperf, DNS-OARC) and check the flags below against `dnsperf -h` of that version;
# the spellings are those of dnsperf 2.x.
#
# What one step does: dnsperf -s SERVER -p PORT -d FILE -m udp|tcp -l SECONDS -c CLIENTS
#   -T THREADS -q OUTSTANDING [-Q MAXQPS] [-e] -S 5
# Steps are the rates in --rates (queries per second, 0 = unlimited, the saturation run).
# Raw output of every step goes to results/raw/dnsperf-<stamp>/, and the summary fields are
# collected in summary.tsv next to it.
#
# Fields to record for the results file (dnsperf prints all of them):
#   Queries sent / completed / lost, Response codes (NOERROR, NXDOMAIN), Run time, Queries per
#   second, Average Latency (s) with min, max and standard deviation. p50/p99/p99.9 come from
#   the latency histogram when the run has --extra "-O latency-histogram" (dnsperf 2.x): the
#   upper edge of the histogram bucket that holds the quantile, in microseconds, in the
#   columns p50_us, p99_us and p999_us of summary.tsv, beside runtime_s.
#   And, from the server host (scripts/server-cpu.sh PID before and after each step): the
#   server's CPU seconds and RSS, so that QPS per server core can be computed.
#   And the link: both hosts' CPU model and core count, the NIC speed, the one-way path (same
#   hypervisor, same switch), the MTU, `ping` RTT, and the kernel and dnsperf versions.
#
# Usage:
#   run-dnsperf.sh --server ADDR --names FILE [options]
# Options:
#   --server ADDR       server IP address (required)
#   --port N            server port (default 53)
#   --names FILE        query file (required)
#   --transport T       udp, tcp or dot (default udp; dnsperf 2.14 also speaks DoT)
#   --rates LIST        space separated steps, queries per second (default "0"; 0 = unlimited)
#   --duration SECONDS  length of a step (default 60)
#   --clients N         dnsperf -c, client sockets per thread (default 32)
#   --threads N         dnsperf -T, load threads (default 4)
#   --outstanding N     dnsperf -q, queries in flight per thread (default 1000)
#   --no-edns           do not send an OPT record (default: -e, EDNS0)
#   --server-binary P   the server binary on this host, for the linkage check
#   --allow-dynamic     do not refuse a dynamically linked binary on Linux
#   --extra "ARGS"      further dnsperf arguments
#   --out-dir DIR       output directory (default results/raw/dnsperf-<stamp>)
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER=""; PORT=53; NAMES=""; TRANSPORT=udp; RATES="0"; DURATION=60; CLIENTS=32; THREADS=4
OUTSTANDING=1000; EDNS=1; SERVER_BINARY=""; ALLOW_DYNAMIC=0; EXTRA=""; OUTDIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --names) NAMES="$2"; shift 2 ;;
    --transport) TRANSPORT="$2"; shift 2 ;;
    --rates) RATES="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --outstanding) OUTSTANDING="$2"; shift 2 ;;
    --no-edns) EDNS=0; shift ;;
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --extra) EXTRA="$2"; shift 2 ;;
    --out-dir) OUTDIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,54p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SERVER" ] || die "--server ADDR is required"
[ -n "$NAMES" ] && [ -f "$NAMES" ] || die "--names FILE is required (phase2-dns zonegen ...)"
case "$TRANSPORT" in udp|tcp|dot) ;; *) die "--transport is udp, tcp or dot" ;; esac
command -v dnsperf >/dev/null 2>&1 || die "dnsperf is not installed on this host (package dnsperf; this script installs nothing)"
[ -n "$OUTDIR" ] || OUTDIR="$ROOT/results/raw/dnsperf-$STAMP"
mkdir -p "$OUTDIR"
META="$OUTDIR/meta.txt"
: > "$META"

note "run-dnsperf: server=$SERVER:$PORT transport=$TRANSPORT names=$NAMES ($(wc -l < "$NAMES") queries)"
note "$(machine_line)"
note "dnsperf: $(dnsperf -V 2>&1 | head -1)"
note "load: clients=$CLIENTS threads=$THREADS outstanding=$OUTSTANDING duration=${DURATION}s edns=$EDNS rates=[$RATES]"
note "the load host is not the server host; record the server host and the link in the results file"
check_linkage "$SERVER_BINARY" "$ALLOW_DYNAMIC"

printf 'rate\tsent\tcompleted\tlost\tqps\tavg_latency_s\tmin_latency_s\tmax_latency_s\tnoerror\tnxdomain\tp50_us\tp99_us\tp999_us\truntime_s\n' > "$OUTDIR/summary.tsv"

# dnsperf prints a line per timed-out query; with a saturating load that is most of the
# output, so it is suppressed where the installed version knows the option (2.x).
QUIET=()
dnsperf -H 2>&1 | grep -q 'suppress=' && QUIET=(-O suppress=timeout)

for rate in $RATES; do
  out="$OUTDIR/step-$TRANSPORT-rate$rate.txt"
  args=(-s "$SERVER" -p "$PORT" -d "$NAMES" -m "$TRANSPORT" -l "$DURATION" -c "$CLIENTS"
        -T "$THREADS" -q "$OUTSTANDING" -S 5 "${QUIET[@]}")
  [ "$EDNS" = 1 ] && args+=(-e)
  [ "$rate" = 0 ] || args+=(-Q "$rate")
  # shellcheck disable=SC2206
  [ -z "$EXTRA" ] || args+=($EXTRA)
  say "step: rate=$rate  dnsperf ${args[*]}"
  dnsperf "${args[@]}" > "$out" 2>&1 || note "dnsperf exited with an error at rate $rate (see $out)"
  # The percentiles come from the latency histogram (-O latency-histogram, "lo - hi: count"
  # per bucket): the upper edge of the bucket in which the cumulative count reaches the
  # quantile, in microseconds. Without that option the three columns stay empty.
  awk -v rate="$rate" '
    function q(p,   i, s) {
      if (total == 0) return ""
      s = 0
      for (i = 1; i <= n; i++) { s += c[i]; if (s >= p * total) return sprintf("%.0f", hi[i] * 1e6) }
      return sprintf("%.0f", hi[n] * 1e6)
    }
    /Queries sent:/        { sent = $3 }
    /Queries completed:/   { completed = $3 }
    /Queries lost:/        { lost = $3 }
    /Run time \(s\):/      { runtime = $4 }
    /Queries per second:/  { qps = $4 }
    # Over DoT dnsperf prints a second latency block for the connections; the first block
    # belongs to the queries.
    /Average Latency/ && !avg { avg = $4; min = $6; max = $8; sub(",", "", avg); sub(",", "", min); sub(/\)/, "", max) }
    /Response codes:/      { for (i = 3; i < NF; i++) { if ($i == "NOERROR") noerror = $(i + 1); if ($i == "NXDOMAIN") nx = $(i + 1) } }
    /Latency bucket/       { block++ }
    block == 1 && /^ *[0-9.]+ - [0-9.]+: +[0-9]+$/ { n++; hi[n] = $3 + 0; c[n] = $4 + 0; total += $4 }
    END { printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", rate, sent, completed, lost, qps, avg, min, max, noerror, nx, q(0.5), q(0.99), q(0.999), runtime }
  ' "$out" >> "$OUTDIR/summary.tsv"
done

say "raw output and summary: $OUTDIR"
cat "$OUTDIR/summary.tsv"
