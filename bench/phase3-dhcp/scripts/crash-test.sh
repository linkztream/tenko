#!/usr/bin/env bash
# E24 / M32 of docs/plans/phase-3-plan.md (WP7.2): crash and restart of one node under lease
# load, the rebuild of a 100,000-lease table from the store, and the commit latency of the
# lease path. Every figure is a single-node figure (plan section 2.12).
#
# The `dhcp` role does not exist in the binary before WP7.5, so the node is the test-only
# entry point of crates/tenko-dhcp/tests/lease_crash.rs: a child process of the test binary
# that opens the Raft store, rebuilds its lease table, and runs 200 clients (request, renew,
# release) through the reference allocator, the offer hold and the production lease store;
# it prints a line per ACK after the durable commit. The harness kills it at a pseudo-random
# moment (SIGKILL on Unix, TerminateProcess on Windows; the pid of the child it started),
# reopens the data directory and checks the rows, the rebuilt table, the client index, the
# history and every ACK received: no acknowledged lease lost, no address on two clients.
# Repeated --kills times on one data directory.
#
# The test binaries are release builds (cargo's --release profile, the same optimisation as
# the shipped binary). On Linux the shipped binary is the static musl build; pass
# --target x86_64-unknown-linux-musl through --cargo-args to build the tests for it.
#
# Steps, one release test at a time:
#   1. the commit latency: --rate renewals per second for --secs seconds, from the hand-off
#      to the completion that releases the ACK (`LATENCY` line);
#   2. the rebuild: 100,000 lease rows (and their client index rows) written, the store
#      closed and opened again, the table rebuilt (`REBUILD` line; threshold 5 s);
#   3. the crash test: --kills kills (`kill N:` lines, then `CRASH OK`).
# The lines go to the result file (default results/raw/m32-<stamp>.txt).
#
# Usage: crash-test.sh [--kills N] [--rate N] [--secs N] [--leases N] [--out FILE]
#                      [--cargo-args "..."] [--print-plan]
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$BENCH/../.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"

KILLS=20; RATE=1000; SECS=10; LEASES=100000; OUT=""; CARGO_ARGS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --kills) KILLS="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --secs) SECS="$2"; shift 2 ;;
    --leases) LEASES="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --cargo-args) CARGO_ARGS="$2"; shift 2 ;;
    --print-plan) sed -n '2,/^set -u/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$BENCH/results/raw"
[ -n "$OUT" ] || OUT="$BENCH/results/raw/m32-$STAMP.txt"
: > "$OUT"

say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$1"; }
note() { say "$1"; printf '%s\n' "$1" >> "$OUT"; }

note "run: $STAMP, kills $KILLS, rate $RATE/s for $SECS s, rebuild of $LEASES leases"
note "commit: $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
note "machine: $(uname -srm)"
note "rustc: $(rustc --version 2>/dev/null || echo unknown)"

cd "$REPO" || exit 2
export TENKO_LEASE_FIGURES="$OUT"
export TENKO_REBUILD_LEASES="$LEASES"
export TENKO_LATENCY_RATE="$RATE"
export TENKO_LATENCY_SECS="$SECS"
export TENKO_CRASH_KILLS="$KILLS"
report="$OUT.crash"
export TENKO_CRASH_REPORT="$report"

# One release test at a time, the latency first: it runs on a quiet disk, before the crash
# test's twenty data directories are written and removed.
step() {
  local name="$1" test="$2"
  say "$name"
  # shellcheck disable=SC2086
  if ! cargo nextest run --release --locked -p tenko-dhcp $CARGO_ARGS --test "$test" \
      --run-ignored all -E "test(=$3)" --test-threads 1 --no-capture; then
    note "FAILED: $name, see the output above"
    [ -f "$report" ] && cat "$report" >> "$OUT"
    exit 1
  fi
}
step "the commit latency" lease_rebuild commit_latency_at_a_paced_rate
step "the rebuild" lease_rebuild a_large_table_rebuilds_from_the_store_in_time
step "the crash test" lease_crash the_node_loses_no_acknowledged_lease
cat "$report" >> "$OUT"
rm -f "$report"
note "result file: $OUT"
