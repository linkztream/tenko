#!/usr/bin/env bash
# Paired backend comparison: domain and hickory run back to back with the
# same settings, five rounds, alternating which backend goes first, so that
# slow drifts in machine load hit both backends alike.
#
# Usage (from bench/spike-b-udp): scripts/run-ab.sh <out.jsonl> [extra matrix flags]
set -euo pipefail

OUT=${1:?usage: run-ab.sh <out.jsonl> [extra matrix flags]}
shift
BIN=${BIN:-target/release/spike-b-udp}
LISTEN=${LISTEN:-127.0.0.1:5399}

for round in 1 2 3 4 5; do
    if (( round % 2 )); then order=domain,hickory; else order=hickory,domain; fi
    for mode in tokio threads; do
        for workers in 1 4; do
            "$BIN" matrix --listen "$LISTEN" --duration 10s --warmup 2s \
                --backends "$order" --modes "$mode" --workers "$workers" \
                --clients 8 --inflight 32 --label "ab-round-$round" --out "$OUT" "$@"
        done
    done
done
