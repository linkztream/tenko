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
#   second, Average Latency (s) with min, max and standard deviation. Add p50/p99/p99.9 from the
#   latency histogram if the installed dnsperf has one (dnsperf -h, look for latency-histogram
#   under -O), else take them from flamethrower (run-flamethrower.sh) or the harness.
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
#   --transport T       udp or tcp (default udp)
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
    -h|--help) sed -n '2,52p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SERVER" ] || die "--server ADDR is required"
[ -n "$NAMES" ] && [ -f "$NAMES" ] || die "--names FILE is required (phase2-dns zonegen ...)"
[ "$TRANSPORT" = udp ] || [ "$TRANSPORT" = tcp ] || die "--transport is udp or tcp"
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

printf 'rate\tsent\tcompleted\tlost\tqps\tavg_latency_s\tmin_latency_s\tmax_latency_s\tnoerror\tnxdomain\n' > "$OUTDIR/summary.tsv"

for rate in $RATES; do
  out="$OUTDIR/step-$TRANSPORT-rate$rate.txt"
  args=(-s "$SERVER" -p "$PORT" -d "$NAMES" -m "$TRANSPORT" -l "$DURATION" -c "$CLIENTS"
        -T "$THREADS" -q "$OUTSTANDING" -S 5)
  [ "$EDNS" = 1 ] && args+=(-e)
  [ "$rate" = 0 ] || args+=(-Q "$rate")
  # shellcheck disable=SC2206
  [ -z "$EXTRA" ] || args+=($EXTRA)
  say "step: rate=$rate  dnsperf ${args[*]}"
  dnsperf "${args[@]}" > "$out" 2>&1 || note "dnsperf exited with an error at rate $rate (see $out)"
  awk -v rate="$rate" '
    /Queries sent:/        { sent = $3 }
    /Queries completed:/   { completed = $3 }
    /Queries lost:/        { lost = $3 }
    /Queries per second:/  { qps = $4 }
    /Average Latency/      { avg = $4; min = $6; max = $8; sub(",", "", avg); sub(",", "", min) }
    /NOERROR/              { noerror = $2 }
    /NXDOMAIN/             { nx = $2 }
    END { printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", rate, sent, completed, lost, qps, avg, min, max, noerror, nx }
  ' "$out" >> "$OUTDIR/summary.tsv"
done

say "raw output and summary: $OUTDIR"
cat "$OUTDIR/summary.tsv"
