#!/usr/bin/env bash
# M25 (block list compile and match, docs/plans/phase-2-plan.md section 6): a generated list
# of 1 M names compiles under 2 s, and the match cost of the query path's matcher is constant
# per label.
#
# The measurement is the engine's example lists_bench (crates/tenko-dns/examples/lists_bench.rs),
# which calls the same compiler and matcher the tenko binary links. Build it like the binary
# that ships: on Linux the static musl build, on Windows the release build:
#   cargo build -p tenko-dns --example lists_bench --release --locked [--target x86_64-unknown-linux-musl]
# A dynamically linked --binary is refused on Linux (--allow-dynamic overrides; the run is
# then marked not publishable).
#
# 1. Data. --names distinct names of two to four labels from a fixed seed, written as a
#    hosts file (`0.0.0.0 name`) and as a domain list, in memory.
# 2. Compile. Each text is parsed and compiled into the stored version, and the matcher is
#    built from the version's bytes; each step --rounds times, the median reported. The
#    threshold is on the sum of the two (parse, compile and matcher) for 1 M names.
# 3. Match. For query names of 2, 4 and 8 labels, --lookups names (half at or below a listed
#    name, half not listed) are matched --rounds times; the median time per lookup and per
#    label is reported. Constant per label: the time per lookup grows with the labels at
#    most linearly, so the time per label does not grow with the labels.
#
# Every figure is a single-node, single-thread figure (plan section 2.10).
#
# Usage: run-m25-lists.sh --binary PATH [options]
#   --names N       names in the list (default 1000000)
#   --lookups N     lookups per label count (default 100000)
#   --rounds N      repetitions of every step, the median reported (default 5)
#   --allow-dynamic do not refuse a dynamically linked binary on Linux
#   --out FILE      result file (default results/raw/m25-<stamp>.jsonl)
#   --print-plan    print this text and exit
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

BINARY=""; NAMES_COUNT=1000000; LOOKUPS=100000; ROUNDS=5; ALLOW_DYNAMIC=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --names) NAMES_COUNT="$2"; shift 2 ;;
    --lookups) LOOKUPS="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --print-plan|-h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$BINARY" ] || die "--binary PATH (the lists_bench example) is required"
[ -x "$BINARY" ] || die "binary not found: $BINARY"
[ -n "$OUT" ] || OUT="$ROOT/results/raw/m25-$STAMP.jsonl"
mkdir -p "$(dirname "$OUT")"
META="${OUT%.jsonl}.meta.txt"
: > "$META"

note "run-m25-lists: names=$NAMES_COUNT lookups=$LOOKUPS rounds=$ROUNDS"
note "$(machine_line)"
check_linkage "$BINARY" "$ALLOW_DYNAMIC"

LOG="${OUT%.jsonl}.log"
if ! "$BINARY" --names "$NAMES_COUNT" --lookups "$LOOKUPS" --rounds "$ROUNDS" > "$OUT" 2> "$LOG"; then
  cat "$LOG" >&2
  die "lists_bench failed; see $LOG"
fi
cat "$LOG"

# The verdict: compile plus matcher under 2 s for both forms at 1 M names, and the time per
# label at 8 labels not above the time per label at 2 labels.
total_max=$(grep '"figure":"compile"' "$OUT" | sed 's/.*"total_s":\([0-9.]*\).*/\1/' | sort -g | tail -1)
per2=$(grep '"labels":2,' "$OUT" | sed 's/.*"ns_per_label":\([0-9.]*\).*/\1/')
per8=$(grep '"labels":8,' "$OUT" | sed 's/.*"ns_per_label":\([0-9.]*\).*/\1/')
verdict=$(awk -v t="$total_max" -v a="$per2" -v b="$per8" -v n="$NAMES_COUNT" 'BEGIN {
  ok = (t < 2.0 && b <= a);
  printf "%s: compile and matcher at most %.3f s for %d names (threshold 2 s); %.1f ns per label at 2 labels, %.1f at 8", ok ? "PASS" : "FAIL", t, n, a, b
}')
note "Verdict: $verdict"
note "results: $OUT"
