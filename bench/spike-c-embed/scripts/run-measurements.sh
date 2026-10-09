#!/usr/bin/env bash
# Runs every measurement of the spike against the binaries built by build-variants.sh.
# Each run writes its full output to results/raw/<name>.log; the last line of every log
# is `RESULT {json}`.
#
# Usage: scripts/run-measurements.sh [section...]
#   sections: bundle binsize cold idle sse fanout http (default: all)
set -euo pipefail
# Git Bash would otherwise rewrite arguments such as `--path /` into Windows paths.
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

RAW=results/raw
BIN=$RAW/bin
EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; esac
M=target/release/measure$EXE
PORT=18631
JS=$(cd ../../ui/dist && ls assets/*.js | head -n 1)

run() {
    local name=$1
    shift
    echo "=== $name: measure $*"
    "$M" "$@" --port "$PORT" 2>&1 | tee "$RAW/$name.log" | tail -n 1
}

want() {
    [ $# -eq 0 ] && return 0
    local s
    for s in "${SECTIONS[@]}"; do [ "$s" = "$1" ] && return 0; done
    return 1
}
SECTIONS=("$@")
[ ${#SECTIONS[@]} -eq 0 ] && SECTIONS=(bundle binsize cold idle sse fanout http)

if want bundle; then
    "$M" bundle --dir ../../ui/dist 2>&1 | tee "$RAW/bundle-ui.log" | tail -n 1
    "$M" bundle --dir "$RAW/synthetic-dist" 2>&1 | tee "$RAW/bundle-synthetic.log" | tail -n 1
fi

if want binsize; then
    "$M" binsize "$BIN"/*"$EXE" 2>&1 | tee "$RAW/binsize.log" | tail -n 1
fi

if want cold; then
    # incdir-empty is left out: it has no index.html, so GET / is a 404.
    for v in incdir-pre rustembed-pre codegen-pre rustembed-deflate incdir-runtime \
             incdir-pre-large rustembed-pre-large codegen-pre-large rustembed-deflate-large; do
        run "cold-$v" cold-start --server "$BIN/$v$EXE" --runs 10 --warmup 1
    done
    run cold-incdir-pre-w2 cold-start --server "$BIN/incdir-pre$EXE" --runs 10 --warmup 1 \
        --server-arg=--workers --server-arg=2
fi

if want idle; then
    for v in incdir-empty incdir-pre codegen-pre rustembed-pre rustembed-deflate incdir-runtime \
             incdir-pre-large codegen-pre-large rustembed-deflate-large; do
        run "idle-$v" idle-rss --server "$BIN/$v$EXE" --wait-secs 10
    done
    for w in 1 2 4; do
        run "idle-incdir-pre-w$w" idle-rss --server "$BIN/incdir-pre$EXE" --wait-secs 10 \
            --server-arg=--workers --server-arg="$w"
    done
fi

if want sse; then
    run sse-rss-raw sse-rss --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 100,1000,5000,10000,20000 --connect-timeout-secs 60
    run sse-rss-axum sse-rss --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events/axum \
        --clients 100,1000,5000,10000,20000 --connect-timeout-secs 60
    run sse-rss-raw-w4 sse-rss --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 100,1000,5000,10000 --connect-timeout-secs 60 --server-arg=--workers --server-arg=4
fi

if want fanout; then
    run fanout-raw fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 1000 --rate 100 --duration-secs 10
    run fanout-axum fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events/axum \
        --clients 1000 --rate 100 --duration-secs 10
    run fanout-raw-5000 fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 5000 --rate 100 --duration-secs 10
    # Same load with 4 server worker threads instead of one per logical CPU.
    run fanout-raw-w4 fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 1000 --rate 100 --duration-secs 10 --server-arg=--workers --server-arg=4
    run fanout-axum-w4 fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events/axum \
        --clients 1000 --rate 100 --duration-secs 10 --server-arg=--workers --server-arg=4
    # Coalescing: one write per client per 50 ms tick instead of one per event.
    run fanout-raw-c50 fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 1000 --rate 100 --duration-secs 10 --server-arg=--coalesce-ms --server-arg=50
    run fanout-raw-c50-w4 fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 1000 --rate 100 --duration-secs 10 --server-arg=--coalesce-ms --server-arg=50 \
        --server-arg=--workers --server-arg=4
    run fanout-raw-5000-w4 fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 5000 --rate 100 --duration-secs 10 --server-arg=--workers --server-arg=4
    run fanout-raw-5000-c50-w4 fanout --threads 8 --server "$BIN/incdir-pre$EXE" --path /api/events \
        --clients 5000 --rate 100 --duration-secs 10 --server-arg=--coalesce-ms --server-arg=50 \
        --server-arg=--workers --server-arg=4
fi

if want http; then
    for enc in none br gzip; do
        args=()
        [ "$enc" != none ] && args=(--accept-encoding "$enc")
        run "http-pre-index-$enc" http-load --threads 16 --server "$BIN/incdir-pre$EXE" --path / "${args[@]}"
        run "http-pre-js-$enc" http-load --threads 16 --server "$BIN/incdir-pre$EXE" --path "/$JS" "${args[@]}"
        run "http-runtime-index-$enc" http-load --threads 16 --server "$BIN/incdir-runtime$EXE" --path / "${args[@]}"
        run "http-runtime-js-$enc" http-load --threads 16 --server "$BIN/incdir-runtime$EXE" --path "/$JS" "${args[@]}"
    done
    run http-pre-health-none http-load --threads 16 --server "$BIN/incdir-pre$EXE" --path /api/health
fi
