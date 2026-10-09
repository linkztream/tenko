#!/usr/bin/env bash
# Unloaded round-trip latency: one client, one query in flight, one worker.
#
# Usage (from bench/spike-b-udp): scripts/run-unloaded.sh <out.jsonl>
set -euo pipefail

OUT=${1:?usage: run-unloaded.sh <out.jsonl>}
BIN=${BIN:-target/release/spike-b-udp}
LISTEN=${LISTEN:-127.0.0.1:5399}

"$BIN" matrix --listen "$LISTEN" --duration 20s --warmup 2s --workers 1 \
    --clients 1 --inflight 1 --label unloaded --out "$OUT"
