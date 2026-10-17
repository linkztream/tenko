#!/usr/bin/env bash
# M24 (cache behaviour): SKELETON. The resolver and its cache arrive with WP5.1 (Slice 5), so
# this script documents the plan and runs nothing yet; it prints the plan and exits with 3.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# A dynamically linked --server-binary is refused on Linux with a warning, as in the other
# scripts, so the skeleton already takes the option.
#
# Plan (docs/plans/phase-2-plan.md, section 6, M24): hit ratio and p99 at a 1 M-name mixed
# run, and serve-stale answers under an upstream cut. Every figure is a single-node figure
# (section 2.10): one resolver node, one stub upstream, all on this host or on two hosts.
#
# 1. Data. The upstream serves the 1 M-name zone:
#      phase2-dns zonegen --records 1000000 --out-dir data/1000000
#    The upstream is a second authoritative process: the Spike B responder, or a second Tenko
#    node (its address in the zone is irrelevant). The query file is sampled with replacement
#    from the zone; for a cache run raise --queries (for example 10 M) so that a 1 M-name
#    population is hit more than once, and add --nx-percent for negative-cache entries.
# 2. Resolver. Start `tenko serve --roles dns` as a forwarder to the upstream with the cache
#    sized for 1 M names. The load generator sets recursion desired:
#      phase2-dns load --rd ... (without --require-aa: a cached answer is not authoritative)
# 3. Warm and measure. Pass 1 warms the cache (every name once; the hit ratio is then the
#    steady state), pass 2 is the measured window (30 s or longer, closed loop and one paced
#    run at half the saturation rate). Record per pass: QPS, p50/p99/p99.9, and from the
#    resolver's own counters the cache hits, misses, evictions and the hit ratio. The mixed
#    run uses a skewed popularity: take the query file from zonegen and weight it by running
#    it twice with different seeds (a hot subset repeated) until WP5.1 defines the mix.
# 4. Serve-stale. While a paced run is going, stop the upstream (SIGSTOP or kill) for 60 s,
#    then resume it. Expect: answers keep coming from the stale cache (success ratio near the
#    hit ratio, p99 not worse than the cached p99 plus the upstream timeout for misses), the
#    resolver counts stale answers, and the cache refreshes after the upstream returns.
#
# Gaps the harness needs by WP5.1: a per-second time series in the result record (the upstream
# cut is a transient, the window summary hides it), a query file with a popularity skew, and
# the resolver's counters read through the API at the start and the end of the window.
#
# Usage: run-m24-cache.sh [--server-binary PATH] [--allow-dynamic] [--print-plan]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SERVER_BINARY=""; ALLOW_DYNAMIC=0
while [ $# -gt 0 ]; do
  case "$1" in
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --print-plan) shift ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

check_linkage "$SERVER_BINARY" "$ALLOW_DYNAMIC"
sed -n '2,36p' "$0"
echo
echo "run-m24-cache.sh: not implemented, the resolver does not exist yet (WP5.1)." >&2
exit 3
