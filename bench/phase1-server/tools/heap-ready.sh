#!/usr/bin/env bash
# heap-ready.sh BINARY PORT LABEL
#
# Starts a fresh single-node controller (the M9 configuration) under heapshim.so, waits
# until it is ready (start-up takes minutes under the shim), waits 10 s more, dumps the
# allocation tables, stops the server and writes the report of heapsym.py to
# $HEAP_OUT/LABEL.txt (default /tmp/tenko-heap). glibc targets only; needs gcc, python3
# and addr2line (binutils), and a binary with its symbol table (not stripped).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=$1; PORT=$2; LABEL=$3
OUT=${HEAP_OUT:-/tmp/tenko-heap}; mkdir -p "$OUT"
gcc -O2 -shared -fPIC -o "$OUT/heapshim.so" "$HERE/heapshim.c" -ldl -lpthread
rm -f "$OUT/$LABEL.dump" "$OUT/$LABEL.dump.trigger" "$OUT/$LABEL.dump.stats"
W=$(mktemp -d /tmp/tenko-heap-XXXXXX); D=$W/data
printf 'data_dir = "%s"\nroles = "controller"\n\n[server]\nlisten = ["127.0.0.1:%s"]\n\n[hibp]\nonline = false\n' "$D" "$PORT" > "$W/tenko.toml"
HEAPSHIM_OUT="$OUT/$LABEL.dump" LD_PRELOAD="$OUT/heapshim.so" \
  "$BIN" serve --roles controller --config "$W/tenko.toml" > "$W/out.log" 2> "$W/err.log" &
P=$!
for _ in $(seq 1 6000); do grep -q ' ready at ' "$W/out.log" 2>/dev/null && break; sleep 0.1; done
sleep 10
grep -E '^(VmRSS|RssAnon)' "/proc/$P/status" | tr -s ' \t' ' ' | tr '\n' ';'; echo
touch "$OUT/$LABEL.dump.trigger"
for _ in $(seq 1 300); do [ -e "$OUT/$LABEL.dump.trigger" ] || break; sleep 1; done
kill -TERM "$P"; wait "$P"; echo "exit $?"
python3 "$HERE/heapsym.py" "$OUT/$LABEL.dump" "$BIN" 45 > "$OUT/$LABEL.txt"
echo "report: $OUT/$LABEL.txt"
rm -rf "$W"
