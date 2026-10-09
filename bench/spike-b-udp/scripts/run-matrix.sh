#!/usr/bin/env bash
# Runs the throughput/latency matrix used for the results files.
#
# Usage (from bench/spike-b-udp):
#   scripts/run-matrix.sh <out.jsonl> [extra matrix flags, e.g. --reuseport]
#
# Environment:
#   BIN     server/load binary (default target/release/spike-b-udp)
#   LISTEN  address to serve on (default 127.0.0.1:5399; on Windows UDP 5353
#           is usually held by the system mDNS responder)
#
# Every throughput configuration keeps 256 queries in flight, spread over
# 8, 32 or 64 client sockets (more source ports matter for SO_REUSEPORT,
# which balances by flow hash). The report keeps the best of the three per
# (backend, mode, reuseport, workers).
set -euo pipefail

OUT=${1:?usage: run-matrix.sh <out.jsonl> [extra matrix flags]}
shift
BIN=${BIN:-target/release/spike-b-udp}
LISTEN=${LISTEN:-127.0.0.1:5399}
COMMON=(--listen "$LISTEN" --duration 20s --warmup 2s --workers 1,2,4,8,16,32)

"$BIN" matrix "${COMMON[@]}" --clients 8 --inflight 32 --out "$OUT" "$@"
"$BIN" matrix "${COMMON[@]}" --clients 32 --inflight 8 --out "$OUT" "$@"
"$BIN" matrix "${COMMON[@]}" --clients 64 --inflight 4 --out "$OUT" "$@"
