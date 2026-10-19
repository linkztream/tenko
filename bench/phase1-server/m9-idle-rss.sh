#!/usr/bin/env bash
# M9 (OPS-15) on Linux: idle memory of `tenko serve` (default `--roles controller`).
#
# Starts a fresh single-node controller, completes first-run setup and logs in with the CLI,
# creates a small IPAM data set with `tenko prefix create`, leaves the server idle, samples
# /proc/<pid>/status, stops the server with SIGTERM and checks its exit status.
#
# Nothing secret is written out: the setup token goes to the CLI through the environment,
# the administrator password is generated for the run and goes through standard input, and
# the server log is redacted before it is copied to the output directory.
#
# Usage:
#   m9-idle-rss.sh --binary PATH [--port 18444] [--prefixes 200] [--idle-secs 600]
#                  [--interval-secs 30] [--workdir DIR] [--outdir DIR]
#                  [--kek platform|file] [--keep-data]
#                  [--roles controller[,probe][,dns]] [--dns-port 15353]
#
# With the dns role the node answers on 127.0.0.1:<dns-port> (the default port 53 needs
# privileges); every other `[dns]` key keeps its default.
#
# Put the work directory on a fast disk (default: a new directory under /tmp).
#
# Measure the binary that ships: the static musl build,
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# that is target/x86_64-unknown-linux-musl/release/tenko. A glibc build is reported with a
# warning; its allocator keeps the start-up peak (results/2026-10-16-m9-linux-memory.md).

set -u
export LC_ALL=C

BINARY=""
PORT=18444
PREFIXES=200
IDLE_SECS=600
INTERVAL=30
WORKDIR=""
OUTDIR=""
KEK=platform
KEEP=0
ROLES=controller
DNS_PORT=15353

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --prefixes) PREFIXES="$2"; shift 2 ;;
    --idle-secs) IDLE_SECS="$2"; shift 2 ;;
    --interval-secs) INTERVAL="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --kek) KEK="$2"; shift 2 ;;
    --keep-data) KEEP=1; shift ;;
    --roles) ROLES="$2"; shift 2 ;;
    --dns-port) DNS_PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BINARY" ] || { echo "--binary is required" >&2; exit 2; }
[ -x "$BINARY" ] || { echo "not executable: $BINARY" >&2; exit 2; }
[ "$PREFIXES" -ge 6 ] || { echo "--prefixes must be at least 6" >&2; exit 2; }
[ "$KEK" = platform ] || [ "$KEK" = file ] || { echo "--kek is platform or file" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
TAG="linux-$STAMP"
[ -n "$OUTDIR" ] || OUTDIR="$HERE/results/raw"
[ -n "$WORKDIR" ] || WORKDIR="$(mktemp -d /tmp/tenko-m9-XXXXXX)"
mkdir -p "$WORKDIR" "$OUTDIR"

DATA="$WORKDIR/data"
CFG="$WORKDIR/tenko.toml"
CRED="$WORKDIR/credentials.json"
OUTLOG="$WORKDIR/server.out.log"
ERRLOG="$WORKDIR/server.err.log"
CA="$DATA/tls/ca-root.pem"
URL="https://localhost:$PORT"
CSV="$OUTDIR/m9-$TAG.csv"
SUMMARY="$OUTDIR/m9-$TAG-summary.txt"

T0=$(date +%s.%N)
now() { awk -v a="$(date +%s.%N)" -v b="$T0" 'BEGIN { printf "%.1f", a - b }'; }
say() { printf '[%7ss] %s\n' "$(now)" "$1"; }
note() { say "$1"; printf '%s\n' "$1" >> "$SUMMARY"; }

: > "$SUMMARY"
SERVER_PID=0
TOKEN=""

cleanup() {
  if [ "$SERVER_PID" -ne 0 ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -KILL "$SERVER_PID" 2>/dev/null
  fi
  for f in server.out.log server.err.log; do
    if [ -f "$WORKDIR/$f" ]; then
      if [ -n "$TOKEN" ]; then
        sed "s/$TOKEN/<redacted>/g" "$WORKDIR/$f" > "$OUTDIR/m9-$TAG-$f"
      else
        cp "$WORKDIR/$f" "$OUTDIR/m9-$TAG-$f"
      fi
    fi
  done
  [ "$KEEP" -eq 1 ] || rm -rf "$WORKDIR"
  echo "raw output: $OUTDIR (m9-$TAG*)"
}
trap cleanup EXIT

die() { note "FAILED: $1"; exit 1; }

# kB value of a /proc/<pid>/status field, in MiB.
field() { awk -v k="$1:" '$1 == k { printf "%.2f", $2 / 1024 }' "/proc/$SERVER_PID/status"; }
threads() { awk '$1 == "Threads:" { print $2 }' "/proc/$SERVER_PID/status"; }

echo "t_s,phase,rss_mib,hwm_mib,rss_anon_mib,rss_file_mib,vmsize_mib,threads" > "$CSV"
LAST_RSS=""; LAST_HWM=""; LAST_ANON=""; LAST_FILE=""; LAST_THREADS=""
sample() {
  local phase="$1"
  LAST_RSS=$(field VmRSS); LAST_HWM=$(field VmHWM); LAST_ANON=$(field RssAnon)
  LAST_FILE=$(field RssFile); LAST_THREADS=$(threads)
  echo "$(now),$phase,$LAST_RSS,$LAST_HWM,$LAST_ANON,$LAST_FILE,$(field VmSize),$LAST_THREADS" >> "$CSV"
}

# ---- machine ------------------------------------------------------------------------------
CPU=$(awk -F: '/model name/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo)
note "machine: $CPU, $(nproc) logical CPUs, $(awk '/MemTotal/ { printf "%.1f", $2 / 1048576 }' /proc/meminfo) GiB RAM, $(. /etc/os-release; echo "$PRETTY_NAME"), kernel $(uname -r)"
LINKAGE=dynamic
if ldd "$BINARY" 2>&1 | grep -Eq 'statically linked|not a dynamic executable'; then LINKAGE=static; fi
note "binary: $BINARY ($(awk -v s="$(stat -c %s "$BINARY")" 'BEGIN { printf "%.1f", s / 1048576 }') MiB, $LINKAGE), $("$BINARY" --version)"
[ "$LINKAGE" = static ] || note "WARNING: a dynamically linked binary; the shipped Linux binary is the static musl build"
note "work dir: $WORKDIR; filesystem: $(df -PT "$WORKDIR" | awk 'NR == 2 { print $2 }')"
note "kek provider: $KEK"
note "roles: $ROLES"

# ---- configuration ------------------------------------------------------------------------
{
  echo "data_dir = \"$DATA\""
  echo "roles = \"$ROLES\""
  echo
  echo '[server]'
  echo "listen = [\"127.0.0.1:$PORT\"]"
  echo
  echo '[hibp]'
  echo 'online = false'
  if [ "$KEK" = file ]; then
    echo
    echo '[kek]'
    echo 'provider = "file"'
    echo "path = \"$WORKDIR/kek.key\""
  fi
  case ",$ROLES," in
    *,dns,*)
      echo
      echo '[dns]'
      echo "listen = [\"127.0.0.1:$DNS_PORT\"]"
      ;;
  esac
} > "$CFG"

# Throwaway administrator PIN for this run (Home profile: digits only). Never printed.
new_pin() { shuf -i 0-9 -n 6 | tr -d '\n'; }
PIN=$(new_pin)

# ---- start --------------------------------------------------------------------------------
"$BINARY" serve --roles "$ROLES" --config "$CFG" > "$OUTLOG" 2> "$ERRLOG" &
SERVER_PID=$!
START=$(date +%s.%N)
note "server pid $SERVER_PID"

ready=0
for _ in $(seq 1 1200); do
  kill -0 "$SERVER_PID" 2>/dev/null || die "the server exited at start"
  sample start
  if grep -q ' ready at ' "$OUTLOG" 2>/dev/null && grep -Eq '^={20,}$' "$OUTLOG"; then ready=1; break; fi
  sleep 0.1
done
[ "$ready" -eq 1 ] || die "the server did not become ready in 120 s"
READY_AFTER=$(awk -v a="$(date +%s.%N)" -v b="$START" 'BEGIN { printf "%.1f", a - b }')
# The server writes the setup token to <data_dir>/setup-token; its console shows the token
# itself only to a terminal and otherwise names the file.
TOKEN=""
if [ -f "$DATA/setup-token" ]; then
  TOKEN=$(tr -d ' \r\n' < "$DATA/setup-token")
fi
if [ -z "$TOKEN" ]; then
  TOKEN=$(sed -n 's/^Setup token: *\([^ ]*\).*$/\1/p' "$OUTLOG" | grep -v '^in$' | head -n 1)
fi
[ -n "$TOKEN" ] || die "no setup token in the token file or on the server console"
sample ready
note "ready after $READY_AFTER s; RSS $LAST_RSS MiB, HWM $LAST_HWM MiB, anon $LAST_ANON MiB, file $LAST_FILE MiB"

# ---- setup and login ----------------------------------------------------------------------
export TENKO_CREDENTIALS="$CRED"
for try in 1 2 3 4 5; do
  out=$(printf '%s\n' "$PIN" | TENKO_SETUP_TOKEN="$TOKEN" "$BINARY" setup --url "$URL" --ca-file "$CA" \
        --admin admin --host-name localhost --password-stdin 2>&1)
  rc=$?
  [ "$rc" -eq 0 ] && break
  if echo "$out" | grep -qiE 'trivial|policy|password'; then PIN=$(new_pin); continue; fi
  break
done
[ "$rc" -eq 0 ] || die "tenko setup failed (status $rc): $(echo "$out" | sed "s/$TOKEN/<token>/g")"
note "setup complete"
out=$(printf '%s\n' "$PIN" | "$BINARY" login --url "$URL" --ca-file "$CA" --user admin --password-stdin 2>&1)
rc=$?
[ "$rc" -eq 0 ] || die "tenko login failed (status $rc): $out"
note "login ok"
sample setup

# ---- data set -----------------------------------------------------------------------------
# One /8 and four /16 supernets, the rest /24 networks spread over the /16s.
CIDRS=("10.0.0.0/8 supernet")
for a in 1 2 3 4; do CIDRS+=("10.$a.0.0/16 supernet"); done
n=0
while [ "${#CIDRS[@]}" -lt "$PREFIXES" ]; do
  a=$((1 + n % 4)); b=$((n / 4))
  CIDRS+=("10.$a.$b.0/24 network")
  n=$((n + 1))
done

LOAD_START=$(date +%s.%N)
failures=0
i=0
for entry in "${CIDRS[@]}"; do
  i=$((i + 1))
  set -- $entry
  out=$("$BINARY" prefix create "$1" --role "$2" 2>&1) || {
    sleep 1
    out=$("$BINARY" prefix create "$1" --role "$2" 2>&1)
  } || { failures=$((failures + 1)); say "prefix $1 failed: $out"; }
  if [ $((i % 10)) -eq 0 ] || [ "$i" -eq "${#CIDRS[@]}" ]; then sample load; fi
done
LOAD_SECS=$(awk -v a="$(date +%s.%N)" -v b="$LOAD_START" 'BEGIN { printf "%.1f", a - b }')
listed=$("$BINARY" prefix list --all --json 2>/dev/null | grep -o '"cidr"' | wc -l)
sample load-end
note "created $((${#CIDRS[@]} - failures)) of ${#CIDRS[@]} prefixes in $LOAD_SECS s ($failures failures); server lists $listed"
note "peak during start-up and data creation: VmHWM $LAST_HWM MiB (now RSS $LAST_RSS MiB, anon $LAST_ANON MiB, file $LAST_FILE MiB)"
LOAD_HWM=$LAST_HWM

# ---- idle ---------------------------------------------------------------------------------
note "idle phase: $IDLE_SECS s, one sample every $INTERVAL s"
IDLE_START=$(date +%s.%N)
COUNT=$((IDLE_SECS / INTERVAL))
IDLE_FILE="$WORKDIR/idle.txt"
: > "$IDLE_FILE"
for k in $(seq 0 "$COUNT"); do
  due=$((k * INTERVAL))
  wait_s=$(awk -v a="$(date +%s.%N)" -v b="$IDLE_START" -v d="$due" 'BEGIN { w = d - (a - b); if (w < 0) w = 0; printf "%.3f", w }')
  sleep "$wait_s"
  kill -0 "$SERVER_PID" 2>/dev/null || die "the server exited during the idle phase"
  sample idle
  echo "$LAST_RSS" >> "$IDLE_FILE"
  say "idle $(printf '%4s' "$due") s: RSS $LAST_RSS MiB, HWM $LAST_HWM MiB, anon $LAST_ANON MiB, file $LAST_FILE MiB, threads $LAST_THREADS"
done
FINAL_RSS=$LAST_RSS
sample idle-end
END_HWM=$LAST_HWM

STATS=$(sort -n "$IDLE_FILE" | awk '{ v[NR] = $1 } END {
  m = (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
  printf "min %.2f median %.2f max %.2f", v[1], m, v[NR] }')
MAX_RSS=$(sort -n "$IDLE_FILE" | tail -n 1)
note "idle VmRSS MiB: $STATS final $FINAL_RSS"
note "peak at the end of the run: VmHWM $END_HWM MiB; start-up and data creation peak: VmHWM $LOAD_HWM MiB"
# OPS-15 says 100 MB; read as 100,000,000 bytes (95.37 MiB), the stricter reading.
if awk -v m="$MAX_RSS" 'BEGIN { exit !(m * 1048576 < 100000000) }'; then VERDICT=PASS; else VERDICT=FAIL; fi
note "verdict against 100 MB = 100,000,000 bytes = 95.37 MiB (largest idle VmRSS $MAX_RSS MiB = $(awk -v m="$MAX_RSS" 'BEGIN { printf "%.1f", m * 1.048576 }') MB): $VERDICT"

# ---- stop ---------------------------------------------------------------------------------
STOP_AT=$(date +%s.%N)
kill -TERM "$SERVER_PID"
wait "$SERVER_PID"
EXIT_CODE=$?
SERVER_PID=0
note "graceful stop (SIGTERM): exit status $EXIT_CODE after $(awk -v a="$(date +%s.%N)" -v b="$STOP_AT" 'BEGIN { printf "%.1f", a - b }') s"
exit 0
