#!/usr/bin/env bash
# Runs the measurements of the cluster lab (WP3.1c) on this machine and summarizes them.
#
# M1, M3, M4, M6 and M12 are ignored integration tests of the `tenko` package
# (crates/tenko/tests/cluster_measure.rs, and the M6 scenario in cluster_membership.rs). This
# script builds the test binaries once, runs the selected tests one after another (never in
# parallel), then runs the summary test, which reads every JSON file in the results directory
# and writes summary.md next to them.
#
# It sets TENKO_LAB_RESULTS to the absolute path of the output directory and TENKO_UI_STUB=1
# unless that is already set, for the cargo processes it starts only. The first failing test
# stops the run; the summary is still written for the results that exist, and the script exits
# with the status of the failed test. It runs from anywhere; cargo must be on the PATH.
#
# Usage:
#   run.sh [--out DIR] [--only M1,M3,M4,M6,M12] [--seconds N] [--m3-runs N]
#
#   --out DIR      raw JSON, environment.txt and summary.md go here
#                  (default: results/raw/<yyyy-MM-dd-HHmm> next to this script, git-ignored)
#   --only LIST    comma-separated measurements to run (default: all)
#   --seconds N    shorten the timed phases to N seconds (TENKO_LAB_SECONDS), a quick check
#   --m3-runs N    number of M3 failover runs (TENKO_LAB_M3_RUNS, default 20)
#   -h, --help     this text
#
# Example, the quick check:
#   run.sh --seconds 10 --m3-runs 2

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

OUT=""
ONLY=""
SECONDS_OPT=""
M3_RUNS=""

usage() { sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ $# -ge 2 ] || { echo "--out needs a value" >&2; exit 2; }; OUT="$2"; shift 2 ;;
    --only) [ $# -ge 2 ] || { echo "--only needs a value" >&2; exit 2; }; ONLY="$2"; shift 2 ;;
    --seconds) [ $# -ge 2 ] || { echo "--seconds needs a value" >&2; exit 2; }; SECONDS_OPT="$2"; shift 2 ;;
    --m3-runs) [ $# -ge 2 ] || { echo "--m3-runs needs a value" >&2; exit 2; }; M3_RUNS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

is_positive() { case "$1" in ''|*[!0-9]*) return 1 ;; *) [ "$1" -ge 1 ] ;; esac; }
if [ -n "$SECONDS_OPT" ] && ! is_positive "$SECONDS_OPT"; then echo "--seconds must be a positive integer" >&2; exit 2; fi
if [ -n "$M3_RUNS" ] && ! is_positive "$M3_RUNS"; then echo "--m3-runs must be a positive integer" >&2; exit 2; fi
command -v cargo >/dev/null 2>&1 || { echo "cargo is not on the PATH" >&2; exit 2; }

# The measurements in the order they run: the short ones first, M3 (about 20 minutes) last.
# Each entry: name:test binary:test name.
CATALOG=(
  "M12:cluster_measure:m12_forwarded_write_latency"
  "M4:cluster_measure:m4_steady_writes_and_the_catch_up_of_an_empty_controller"
  "M1:cluster_measure:m1_reads_on_a_follower_during_a_snapshot_install"
  "M6:cluster_membership:a_member_rejoins_with_an_empty_data_directory"
  "M3:cluster_measure:m3_failover_under_load"
)

SELECTED=()
if [ -n "$ONLY" ]; then
  WANTED=",$(printf '%s' "$ONLY" | tr 'a-z ' 'A-Z,' | tr -s ','),"
  for name in $(printf '%s' "$ONLY" | tr 'a-z,' 'A-Z '); do
    case "$name" in
      M1|M3|M4|M6|M12) ;;
      *) echo "unknown measurement '$name'; choose among M1, M3, M4, M6, M12" >&2; exit 2 ;;
    esac
  done
  for entry in "${CATALOG[@]}"; do
    name="${entry%%:*}"
    case "$WANTED" in *",$name,"*) SELECTED+=("$entry") ;; esac
  done
else
  SELECTED=("${CATALOG[@]}")
fi
[ "${#SELECTED[@]}" -gt 0 ] || { echo "no measurement selected" >&2; exit 2; }

[ -n "$OUT" ] || OUT="$HERE/results/raw/$(date +%Y-%m-%d-%H%M)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# ---- environment record -------------------------------------------------------------------
CPU="$(awk -F: '/model name/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo)"
MEM_GIB="$(awk '/MemTotal/ { printf "%.1f", $2 / 1048576 }' /proc/meminfo)"
OS_NAME="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>&1 || true)"
if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null || true)" ]; then
  COMMIT="$COMMIT (uncommitted changes in the working tree)"
fi
NAMES=""
for entry in "${SELECTED[@]}"; do NAMES="${NAMES:+$NAMES, }${entry%%:*}"; done

{
  echo "machine: ${CPU:-unknown}, $(nproc) logical CPUs, $MEM_GIB GiB RAM"
  echo "os: $OS_NAME, $(uname -sr)"
  echo "rustc: $(rustc --version)"
  echo "commit: $COMMIT"
  echo "date: $(date '+%Y-%m-%d %H:%M')"
  echo "measurements: $NAMES"
  echo "seconds: ${SECONDS_OPT:-default}"
  echo "m3 runs: ${M3_RUNS:-default}"
  echo "profile: test (debug)"
} | tee "$OUT/environment.txt"

# ---- run ----------------------------------------------------------------------------------
# The variables are exported for the cargo processes only: the script is its own process, so
# the caller's environment is untouched.
export TENKO_LAB_RESULTS="$OUT"
export TENKO_UI_STUB="${TENKO_UI_STUB:-1}"
[ -z "$SECONDS_OPT" ] || export TENKO_LAB_SECONDS="$SECONDS_OPT"
[ -z "$M3_RUNS" ] || export TENKO_LAB_M3_RUNS="$M3_RUNS"

cd "$REPO"

echo
echo "== build"
cargo test -p tenko --locked --test cluster_measure --test cluster_membership --no-run

FAILURE=0
for entry in "${SELECTED[@]}"; do
  IFS=: read -r name binary test <<< "$entry"
  echo
  echo "== $name ($binary: $test)"
  started=$(date +%s)
  status=0
  cargo test -p tenko --locked --test "$binary" -- --ignored --exact --nocapture "$test" || status=$?
  took=$(awk -v a="$(date +%s)" -v b="$started" 'BEGIN { printf "%.1f", (a - b) / 60 }')
  if [ "$status" -ne 0 ]; then
    echo "$name FAILED with status $status after $took min"
    FAILURE=$status
    break
  fi
  echo "$name finished in $took min"
done

if ls "$OUT"/*.json >/dev/null 2>&1; then
  echo
  echo "== summary"
  status=0
  cargo test -p tenko --locked --test cluster_measure -- --ignored --exact --nocapture summary_of_the_results || status=$?
  if [ "$status" -ne 0 ] && [ "$FAILURE" -eq 0 ]; then FAILURE=$status; fi
  if [ -f "$OUT/summary.md" ]; then echo; echo "summary: $OUT/summary.md"; fi
else
  echo
  echo "no result files in $OUT; no summary"
  if [ "$FAILURE" -eq 0 ]; then FAILURE=1; fi
fi
exit "$FAILURE"
