#!/usr/bin/env bash
# M26 to M28 on loopback (WP7.3): the DHCPv4 engine's example server against a load client
# on the same host.
#
#   M26  4-way exchanges per second (DISCOVER, OFFER, REQUEST, ACK), every lease committed
#        before the ACK, closed loop (the ceiling) per worker count
#   M27  renewals per second (REQUEST and ACK on existing leases) after a fill
#   M28  latency from DISCOVER to ACK at fixed rates (open loop), and the server's own
#        commit and step times
#
# The server is crates/tenko-dhcp/examples/dhcp_server.rs (`serve`): the engine's relay
# listener over one scope of 198.18.0.0/15 (RFC 2544's benchmarking range, about 131,000
# pool addresses), the in-memory store (`mem`, MemLeaseStore) or the queue store (`queue`,
# the hand-off and completion with no rows kept). The load client is the same example's
# `load` subcommand, a relay agent; perfdhcp rows follow in WP7.6 on Linux (perfdhcp -r and
# -R as the bench README says), with the same server.
#
# Linux runs use the static musl build of the example, the shipped target:
#   cargo build -p tenko-dhcp --release --locked --example dhcp_server \
#     --target x86_64-unknown-linux-musl
# A dynamically linked binary is refused on Linux (--allow-dynamic overrides and marks the
# run not publishable). Windows runs use the release build. Every figure is a single-node
# figure; loopback figures are upper bounds and labelled so.
#
# Usage:
#   run-loopback.sh --binary PATH [--workers "1 2 4 8"] [--stores "mem queue"]
#                   [--clients 100000] [--window 64] [--rates "1000"] [--renew-seconds 20]
#                   [--mem-clients 10000] [--out FILE] [--allow-dynamic]
#
# MemLeaseStore keeps its client index by walking the scope's rows on every commit (it is
# the contracts' oracle, not a production store), so its rows use --mem-clients clients;
# the queue store and the example's hash lease table take --clients.
set -u
export LC_ALL=C

BINARY=""; WORKERS="1 2 4 8"; STORES="queue mem"; CLIENTS=100000; WINDOW=64
RATES="1000"; RENEW_SECONDS=20; OUT=""; ALLOW_DYNAMIC=0; MEM_CLIENTS=10000
SERVER_PORT=6767; RELAY_PORT=6868

say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$1"; }
die() { printf 'error: %s\n' "$1" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --stores) STORES="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --mem-clients) MEM_CLIENTS="$2"; shift 2 ;;
    --window) WINDOW="$2"; shift 2 ;;
    --rates) RATES="$2"; shift 2 ;;
    --renew-seconds) RENEW_SECONDS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$BINARY" ] && [ -x "$BINARY" ] || die "--binary must name the built dhcp_server example"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -n "$OUT" ] || OUT="$HERE/../results/raw/loopback-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$OUT")"

if [ "$(uname -s)" = "Linux" ]; then
  if file -L "$BINARY" | grep -q 'dynamically linked'; then
    [ "$ALLOW_DYNAMIC" = 1 ] || die "a dynamically linked binary on Linux: build the musl target"
    say "warning: dynamically linked binary, the run is not publishable" | tee -a "$OUT"
  fi
fi
{
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) $(uname -srm)"
  echo "# binary $BINARY"
  echo "# workers '$WORKERS' stores '$STORES' clients $CLIENTS window $WINDOW rates '$RATES'"
} >> "$OUT"

# Runs one server configuration around one load command.
run() {
  local workers="$1" store="$2" seconds="$3"; shift 3
  "$BINARY" serve --listen "127.0.0.1:$SERVER_PORT" --relay-port "$RELAY_PORT" \
    --workers "$workers" --store "$store" --seconds "$seconds" --idle-exit 3 \
    > "$OUT.server" 2>&1 &
  local pid=$!
  sleep 1
  say "workers $workers, store $store: load $*" | tee -a "$OUT"
  "$BINARY" load --server "127.0.0.1:$SERVER_PORT" --bind "127.0.0.1:$RELAY_PORT" "$@" \
    | tee -a "$OUT"
  wait "$pid"
  sed 's/^/  /' "$OUT.server" | tee -a "$OUT"
  rm -f "$OUT.server"
}

for store in $STORES; do
  clients="$CLIENTS"
  [ "$store" = mem ] && clients="$MEM_CLIENTS"
  for workers in $WORKERS; do
    # M26: the closed-loop ceiling; the server stops 3 s after the load has finished.
    run "$workers" "$store" 600 --mode dora --clients "$clients" --window "$WINDOW" --seconds 300
  done
  # M27: renewals after a fill, at the largest worker count.
  last="${WORKERS##* }"
  run "$last" "$store" 900 --mode renew --clients "$clients" \
    --window "$WINDOW" --seconds "$RENEW_SECONDS"
  # M28: the latency at fixed rates, open loop.
  for rate in $RATES; do
    count=$((rate * 20))
    run "$last" "$store" 40 --mode dora --clients "$count" --rate "$rate" --seconds 25
  done
done
say "results in $OUT"
