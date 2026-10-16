#!/usr/bin/env bash
# ready-probe.sh BINARY PORT LABEL [SETTLE_SECS]
#
# Starts a fresh single-node controller (the M9 configuration), waits until it is ready,
# waits SETTLE_SECS more (default 10), copies /proc/<pid>/{status,smaps_rollup,smaps,maps}
# and the thread names to $PROBE_OUT/LABEL (default /tmp/tenko-probe/LABEL), prints the
# resident and anonymous memory by kind of mapping, and stops the server with SIGTERM.
#
# The environment is passed through, so glibc tunables can be tried directly:
#   MALLOC_ARENA_MAX=1 ready-probe.sh /path/to/tenko 18461 arena1
set -u
export LC_ALL=C
BIN=$1; PORT=$2; LABEL=$3; SETTLE=${4:-10}
W=$(mktemp -d /tmp/tenko-probe-XXXXXX); D=$W/data
OUT=${PROBE_OUT:-/tmp/tenko-probe}/$LABEL; mkdir -p "$OUT"
printf 'data_dir = "%s"\nroles = "controller"\n\n[server]\nlisten = ["127.0.0.1:%s"]\n\n[hibp]\nonline = false\n' "$D" "$PORT" > "$W/tenko.toml"
"$BIN" serve --roles controller --config "$W/tenko.toml" > "$W/out.log" 2> "$W/err.log" &
P=$!
for _ in $(seq 1 600); do grep -q ' ready at ' "$W/out.log" 2>/dev/null && break; sleep 0.1; done
sleep "$SETTLE"
for f in status smaps_rollup smaps maps; do cp "/proc/$P/$f" "$OUT/$f"; done
for t in /proc/$P/task/*; do cat "$t/comm"; done | sort | uniq -c | sort -rn > "$OUT/threads"
# Group the mappings: the binary by permission, glibc's main heap, thread-stack-sized and
# arena-sized anonymous mappings, other anonymous mappings, shared libraries.
awk -v bin="$(basename "$BIN")" '
/^[0-9a-f]+-[0-9a-f]+ / {
  split($1, a, "-"); size = (strtonum("0x" a[2]) - strtonum("0x" a[1])) / 1024
  name = ($6 == "" ? "[anon]" : $6); perm = $2; next }
/^Rss:/ { rss = $2 }
/^Anonymous:/ {
  an = $2; key = name
  if (index(name, bin) > 0) key = "binary " perm
  else if (name == "[anon]" && size >= 8000 && size <= 8200) key = "[anon 8MiB thread-stack-sized]"
  else if (name == "[anon]" && size >= 65000 && size <= 65540) key = "[anon 64MiB arena-sized]"
  else if (name == "[anon]") key = "[anon other]"
  R[key] += rss; A[key] += an; N[key]++ }
END { for (k in R) printf "%-34s n=%4d rss=%9.2f MiB anon=%9.2f MiB\n", k, N[k], R[k] / 1024, A[k] / 1024 }' \
  "$OUT/smaps" | sort -k4 -t= -rn > "$OUT/by-mapping"
kill -TERM "$P"; wait "$P"; echo "exit $?" > "$OUT/exit"
grep -E '^(VmRSS|VmHWM|RssAnon|RssFile|Threads)' "$OUT/status" | tr -s ' \t' ' ' | tr '\n' ';'; echo
cat "$OUT/by-mapping"; echo "-- threads"; cat "$OUT/threads"
rm -rf "$W"
