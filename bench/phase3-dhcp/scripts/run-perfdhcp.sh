#!/usr/bin/env bash
# M26 to M28 with ISC's perfdhcp (Kea), on loopback or from a second host (WP7.6).
#
#   M26  4-way exchanges per second (DISCOVER, OFFER, REQUEST, ACK), every lease committed
#        before the ACK: a ladder of offered rates per worker count; the ceiling is the
#        highest rate answered with at most 0.1 percent drops
#   M27  renewals per second (REQUEST and ACK on leases perfdhcp holds): a ladder of
#        renewal rates (perfdhcp -f), each beside new 4-way exchanges at the same rate
#        (perfdhcp renews only leases it got in the same run, at most at -r)
#   M28  latency at 1,000 and 5,000 exchanges per second: the 50th and 99th percentile of
#        DISCOVER to OFFER and of REQUEST to ACK from perfdhcp's packet timestamps (-x t),
#        the 99th percentile from DISCOVER to ACK from the engine's own load client
#        (--client), and the server's commit time (the example prints it; tenko serves
#        tenko_dhcp_commit_duration_seconds)
#
# With --client, the engine's own load client (the example's `load`) adds closed-loop rows:
# the 4-way ceiling per worker count (M26) and pure renewals after a fill (M27). perfdhcp
# paces its packets and on a small host is the first to saturate; the closed loop shows
# what the server answers when the client is not the limit.
#
# Every rung runs --runs times (default 2) against a fresh server and the better run is
# the figure (the higher achieved rate, then the fewer drops), as in Phase 2. perfdhcp
# sends as a relay agent: its address is giaddr and option 118 (198.18.0.0) selects the
# scope, 198.18.0.0/15 (RFC 2544's benchmarking range, about 131,000 pool addresses), so
# any address of the load host works. The simulated clients are the same in every run
# (-R with a fixed seed, -s 1).
#
# The server (--kind):
#   tenko    the binary with the roles controller and dhcp, its own data directory under
#            ~/<remote-dir> on the node, the API in plain HTTP on --api-port (the Lab
#            profile), the scope created through the API by node-setup.sh; the leases are
#            committed to the store before the ACK. The figures of M26 to M28.
#   example  crates/tenko-dhcp/examples/dhcp_server.rs (`serve`) with --store queue or mem:
#            the engine without the store, for the comparison with WP7.3's loopback rows.
#
# Where (--node and --load, each an ssh target or `local`):
#   loopback  --node and --load the same host (or both `local`), addresses 127.0.0.1: an
#             upper bound, labelled so
#   two-host  --node on the node VM, --load on the load VM, --node-addr the node's address
#             on the link; tune-udp.sh (bench/phase2-dns/scripts) raises the load host's UDP
#             sysctls for the run and restores them, the node's are recorded, not changed
#
# Linux runs measure the static musl binary, the one that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# (and the example with -p tenko-dhcp --example dhcp_server for the same target). A
# dynamically linked binary is refused (lib.sh, check_linkage; --allow-dynamic overrides
# and marks the run not publishable). Every figure is a single-node figure: one server
# process on the node.
#
# Usage:
#   run-perfdhcp.sh --kind tenko|example --binary PATH [--client PATH]
#                   [--node local|USER@HOST] [--load local|USER@HOST] [--node-addr ADDR]
#                   [--load-addr ADDR] [--phases "m26 m27 m28"] [--workers "1 2 4"]
#                   [--rates "1000 2000 5000 7500 10000 15000 20000 40000"]
#                   [--renew-rates "1000 2000 5000 10000"] [--latency-rates "1000 5000"]
#                   [--clients 100000] [--period 20] [--runs 2] [--store queue|mem]
#                   [--port 6767] [--relay-port 6868] [--api-port 18443]
#                   [--remote-dir dhcp] [--sudo-perfdhcp] [--tune] [--out DIR]
#                   [--allow-dynamic]
# The raw output (every perfdhcp report, the server logs, the meta file with the machine,
# the kernel, the versions and the sysctls) goes to --out (default
# bench/phase3-dhcp/results/raw/perfdhcp-<kind>-<stamp>/); summary.tsv has one line per run
# and report.md the tables for the results file (perfdhcp-report.py, which also runs alone
# on a finished raw directory).
set -u
export LC_ALL=C

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The Phase 2 helpers: say, die, note, machine_line, check_linkage.
# shellcheck source=bench/phase2-dns/scripts/lib.sh
. "$SCRIPTS/../../phase2-dns/scripts/lib.sh"
TUNE="$SCRIPTS/../../phase2-dns/scripts/tune-udp.sh"

KIND=""; BINARY=""; CLIENT=""; NODE=local; LOAD=local; NODE_ADDR=127.0.0.1; LOAD_ADDR=""
PHASES="m26 m27 m28"; WORKERS="1 2 4"; RATES="1000 2000 5000 7500 10000 15000 20000 40000"
RENEW_RATES="1000 2000 5000 10000"; LATENCY_RATES="1000 5000"; CLIENTS=100000; PERIOD=20
RUNS=2; STORE=queue; PORT=6767; RELAY_PORT=6868; API_PORT=18443; REMOTE_DIR=dhcp
SUDO_PERFDHCP=0; TUNE_LOAD=0; OUT=""; ALLOW_DYNAMIC=0

while [ $# -gt 0 ]; do
  case "$1" in
    --kind) KIND="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --client) CLIENT="$2"; shift 2 ;;
    --node) NODE="$2"; shift 2 ;;
    --load) LOAD="$2"; shift 2 ;;
    --node-addr) NODE_ADDR="$2"; shift 2 ;;
    --load-addr) LOAD_ADDR="$2"; shift 2 ;;
    --phases) PHASES="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --rates) RATES="$2"; shift 2 ;;
    --renew-rates) RENEW_RATES="$2"; shift 2 ;;
    --latency-rates) LATENCY_RATES="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --period) PERIOD="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --store) STORE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --relay-port) RELAY_PORT="$2"; shift 2 ;;
    --api-port) API_PORT="$2"; shift 2 ;;
    --remote-dir) REMOTE_DIR="$2"; shift 2 ;;
    --sudo-perfdhcp) SUDO_PERFDHCP=1; shift ;;
    --tune) TUNE_LOAD=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --allow-dynamic) ALLOW_DYNAMIC=1; shift ;;
    -h | --help) sed -n '2,62p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
case "$KIND" in tenko | example) ;; *) die "--kind must be tenko or example" ;; esac
[ -n "$BINARY" ] && [ -f "$BINARY" ] || die "--binary must name the server binary"
[ -n "$LOAD_ADDR" ] || LOAD_ADDR="$NODE_ADDR"
[ -n "$OUT" ] || OUT="$SCRIPTS/../results/raw/perfdhcp-$KIND-$STAMP"
mkdir -p "$OUT"
META="$OUT/meta.txt"
SUMMARY="$OUT/summary.tsv"
: >"$META"
printf 'phase\tworkers\trate\trun\tachieved\tdo_sent\tdo_drops\tra_sent\tra_drops\tdo_avg_ms\tra_avg_ms\trenew_rate\trenew_drops\tdo_p50_ms\tdo_p99_ms\tra_p50_ms\tra_p99_ms\n' >"$SUMMARY"
check_linkage "$BINARY" "$ALLOW_DYNAMIC"
[ -z "$CLIENT" ] || check_linkage "$CLIENT" "$ALLOW_DYNAMIC"

# on <host> <command>: runs a shell command on the node or the load host.
on() {
  local host="$1"
  shift
  if [ "$host" = local ]; then bash -c "$*"; else ssh -o BatchMode=yes "$host" "$*"; fi
}
put() {
  local host="$1" from="$2" to="$3"
  if [ "$host" = local ]; then
    mkdir -p "$HOME/$REMOTE_DIR/bin" && cp "$from" "$HOME/$REMOTE_DIR/$to"
  else
    # A new name and a rename: a server still running from the old file keeps it.
    on "$host" "mkdir -p ~/$REMOTE_DIR/bin" && scp -q "$from" "$host:$REMOTE_DIR/$to.new" &&
      on "$host" "mv -f ~/$REMOTE_DIR/$to.new ~/$REMOTE_DIR/$to"
  fi
}
SUDO=""
[ "$SUDO_PERFDHCP" = 1 ] && SUDO="sudo"
LOOPBACK=0
[ "$NODE_ADDR" = 127.0.0.1 ] && LOOPBACK=1

# ---------------------------------------------------------------------------------------
# The record

note "# run-perfdhcp.sh $STAMP: kind $KIND, node $NODE ($NODE_ADDR), load $LOAD ($LOAD_ADDR)"
[ "$LOOPBACK" = 1 ] && note "loopback: an upper bound (server and perfdhcp on one host)"
note "node $(on "$NODE" "$(declare -f machine_line); machine_line")"
[ "$LOAD" = "$NODE" ] || note "load $(on "$LOAD" "$(declare -f machine_line); machine_line")"
note "perfdhcp: $(on "$LOAD" 'perfdhcp -v 2>&1 | head -1')"
note "binary: $(sha256sum "$BINARY" | cut -c1-16) $(basename "$BINARY")"
note "node sysctls:"
on "$NODE" "bash -s show" <"$TUNE" | sed 's/^/  /' | tee -a "$META"
note "settings: workers '$WORKERS', rates '$RATES', renew rates '$RENEW_RATES', latency rates '$LATENCY_RATES', clients $CLIENTS, period $PERIOD s, runs $RUNS, store $STORE (example)"

R="\$HOME/$REMOTE_DIR"
stop_server() {
  # The example prints its counters when it exits by itself, 3 s after the last packet.
  # A tenko instance is stopped at once (its metrics are read first).
  local wait=8
  [ "$KIND" = example ] || wait=0
  on "$NODE" "if [ -f $R/server.pid ]; then p=\$(cat $R/server.pid); for i in \$(seq 1 $wait); do kill -0 \$p 2>/dev/null || break; sleep 1; done; kill \$p 2>/dev/null; sleep 1; kill -9 \$p 2>/dev/null; rm -f $R/server.pid; fi" || true
}
# A server left over from an interrupted run goes first.
stop_server
put "$NODE" "$BINARY" "bin/server"
put "$NODE" "$SCRIPTS/node-setup.sh" "bin/node-setup.sh"
[ -z "$CLIENT" ] || put "$LOAD" "$CLIENT" "bin/client"

TUNED=0
restore() {
  stop_server
  if [ "$TUNED" = 1 ]; then
    note "load sysctls restored:"
    on "$LOAD" "bash -s restore" <"$TUNE" | sed 's/^/  /' | tee -a "$META"
  fi
}
trap restore EXIT
if [ "$TUNE_LOAD" = 1 ] && [ "$LOAD" != "$NODE" ]; then
  note "load sysctls raised for the run:"
  on "$LOAD" "bash -s apply" <"$TUNE" | sed 's/^/  /' | tee -a "$META"
  TUNED=1
fi

# ---------------------------------------------------------------------------------------
# The server

# start_server <workers> <log name>: a fresh server (a new data directory for tenko).
start_server() {
  local workers="$1" log="$2"
  stop_server
  case "$KIND" in
    example)
      on "$NODE" "cd $R; nohup bin/server serve --listen $NODE_ADDR:$PORT --relay-port $RELAY_PORT --workers $workers --store $STORE --seconds 86400 --idle-exit 3 > $log 2>&1 < /dev/null & echo \$! > $R/server.pid"
      sleep 1
      ;;
    tenko)
      on "$NODE" "bash $R/bin/node-setup.sh start $R $NODE_ADDR $PORT $RELAY_PORT $API_PORT $workers $log" ||
        die "the node did not start (see $log on the node)"
      ;;
  esac
}

# fetch_server_log <log name>: the node's server log into the raw directory (the example
# prints its counters and histograms when it stops).
fetch_server_log() {
  if [ "$KIND" = tenko ]; then
    on "$NODE" "bash $R/bin/node-setup.sh metrics $R $API_PORT $1.metrics" || true
    on "$NODE" "cat $R/$1.metrics" >"$OUT/$1.metrics" 2>/dev/null || true
  fi
  stop_server
  on "$NODE" "cat $R/$1" >"$OUT/$1" 2>/dev/null || true
}

# ---------------------------------------------------------------------------------------
# perfdhcp

# perf <file> <arguments...>: one perfdhcp run from the load host; its report into <file>.
perf() {
  local file="$1"
  shift
  on "$LOAD" "$SUDO perfdhcp -4 -l ${LOAD_ADDR} -L $RELAY_PORT -N $PORT -o 118,c6120000 -R $CLIENTS -s 1 $* $NODE_ADDR" >"$file" 2>&1
  return 0
}

# parse <file>: the fields of summary.tsv after the rate (achieved ... ra_p99_ms).
parse() {
  python3 - "$1" "$PERIOD" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
period = float(sys.argv[2])
def block(name):
    m = re.search(r"Statistics for: " + re.escape(name) + r"\*+\s+sent packets: (\d+)\s+received packets: (\d+)\s+drops: (\d+).*?avg delay: ([\d.]+) ms", text, re.S)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), float(m.group(4))) if m else (0, 0, 0, 0.0)
def stamps(name):
    m = re.search(r"Timestamps for packets: " + re.escape(name) + r"\*+\n(.*?)(?:\n\*\*\*|\Z)", text, re.S)
    if not m:
        return []
    out = []
    for s, r in re.findall(r"sent / received: ([\d.]+) / ([\d.]+)", m.group(1)):
        out.append((float(r) - float(s)) * 1000)
    return sorted(out)
def pct(v, q):
    if not v:
        return "-"
    return "%.3f" % v[min(len(v) - 1, max(0, int(round(q * len(v) + 0.5)) - 1))]
rate = re.search(r"Rate: ([\d.]+) 4-way", text)
do, ra, rn = block("DISCOVER-OFFER"), block("REQUEST-ACK"), block("REQUEST-ACK (renewal)")
dos, ras = stamps("DISCOVER-OFFER"), stamps("REQUEST-ACK")
fields = [
    "%.0f" % float(rate.group(1)) if rate else "0",
    do[0], do[2], ra[0], ra[2], "%.3f" % do[3], "%.3f" % ra[3],
    "%.0f" % (rn[1] / period) if rn[0] else "-", rn[2] if rn[0] else "-",
    pct(dos, 0.5), pct(dos, 0.99), pct(ras, 0.5), pct(ras, 0.99),
]
print("\t".join(str(f) for f in fields))
PY
}

# record <phase> <workers> <rate> <run> <file>
record() {
  local line
  line="$(parse "$5")"
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$line" >>"$SUMMARY"
  say "$1 workers $2 rate $3 run $4: $(printf '%s' "$line" | cut -f1,3,5 | tr '\t' ' ') (achieved, drops DO, drops RA)"
}

# The drop ratio of the better run of a rung, in percent.
rung_drops() {
  awk -F'\t' -v p="$1" -v w="$2" -v r="$3" '
    $1 == p && $2 == w && $3 == r { d = ($7 + 0) + ($9 + 0); s = ($6 + 0) + ($8 + 0); x = (s ? 100 * d / s : 100); if (best == "" || x < best) best = x }
    END { printf "%.3f", (best == "" ? 100 : best) }' "$SUMMARY"
}

# ---------------------------------------------------------------------------------------
# The phases

m26() {
  local w rate run file
  for w in $WORKERS; do
    for rate in $RATES; do
      for run in $(seq 1 "$RUNS"); do
        file="$OUT/m26-w$w-r$rate-$run.txt"
        start_server "$w" "server-m26-w$w-r$rate-$run.log"
        perf "$file" "-r $rate -p $PERIOD"
        fetch_server_log "server-m26-w$w-r$rate-$run.log"
        record m26 "$w" "$rate" "$run" "$file"
      done
      # Past the ceiling: the next rungs only lose more.
      if awk -v d="$(rung_drops m26 "$w" "$rate")" 'BEGIN { exit !(d > 1) }'; then
        note "m26 workers $w: $rate per second lost more than 1 percent; the ladder stops"
        break
      fi
    done
    own m26c "$w" "--mode dora --clients $CLIENTS --window 64 --seconds $((PERIOD * 3))" '^dora'
  done
}

# own <name> <workers> <load arguments> <line>: the own client, closed loop, --runs times.
own() {
  local name="$1" w="$2" args="$3" line="$4" run
  [ -n "$CLIENT" ] || return 0
  for run in $(seq 1 "$RUNS"); do
    start_server "$w" "server-$name-w$w-$run.log"
    on "$LOAD" "$R/bin/client load --server $NODE_ADDR:$PORT --bind ${LOAD_ADDR}:$RELAY_PORT $args" \
      >"$OUT/$name-w$w-$run.txt" 2>&1
    fetch_server_log "server-$name-w$w-$run.log"
    say "$name workers $w run $run: $(grep "$line" "$OUT/$name-w$w-$run.txt")"
  done
}

m27() {
  local w rate run file
  w="${WORKERS##* }"
  for rate in $RENEW_RATES; do
    for run in $(seq 1 "$RUNS"); do
      file="$OUT/m27-w$w-f$rate-$run.txt"
      start_server "$w" "server-m27-w$w-f$rate-$run.log"
      # New 4-way exchanges and renewals of the leases held, both at the rung's rate.
      perf "$file" "-r $rate -f $rate -p $PERIOD"
      fetch_server_log "server-m27-w$w-f$rate-$run.log"
      record m27 "$w" "$rate" "$run" "$file"
    done
  done
  own m27c "$w" "--mode renew --clients $CLIENTS --window 64 --seconds $PERIOD" '^renew'
}

m28() {
  local w rate run file
  w="${WORKERS##* }"
  for rate in $LATENCY_RATES; do
    for run in $(seq 1 "$RUNS"); do
      file="$OUT/m28-w$w-r$rate-$run.txt"
      start_server "$w" "server-m28-w$w-r$rate-$run.log"
      perf "$file" "-r $rate -p $PERIOD -x t"
      fetch_server_log "server-m28-w$w-r$rate-$run.log"
      record m28 "$w" "$rate" "$run" "$file"
      # Only the percentiles are kept; the timestamps are large.
      grep -v '^sent / received' "$file" >"$file.tmp" && mv "$file.tmp" "$file"
      if [ -n "$CLIENT" ]; then
        # DISCOVER to ACK from the engine's own load client (a relay with option 118).
        start_server "$w" "server-m28c-w$w-r$rate-$run.log"
        on "$LOAD" "$R/bin/client load --server $NODE_ADDR:$PORT --bind ${LOAD_ADDR}:$RELAY_PORT --mode dora --clients $((rate * PERIOD)) --rate $rate --seconds $PERIOD" \
          >"$OUT/m28c-w$w-r$rate-$run.txt" 2>&1
        fetch_server_log "server-m28c-w$w-r$rate-$run.log"
        say "m28 own client, rate $rate run $run: $(grep '^dora' "$OUT/m28c-w$w-r$rate-$run.txt")"
      fi
    done
  done
}

report() {
  python3 "$SCRIPTS/perfdhcp-report.py" "$SUMMARY" "$OUT" >"$OUT/report.md"
  cat "$OUT/report.md"
}

for phase in $PHASES; do
  case "$phase" in
    m26 | m27 | m28) note "== $phase"; "$phase" ;;
    *) die "unknown phase $phase" ;;
  esac
done
report
say "raw output in $OUT"
