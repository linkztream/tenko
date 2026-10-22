#!/usr/bin/env bash
# M17 (one node over a real link), M22 (the metrics cost on the query path over that link)
# and M23 (idle RSS with every role, the home zones and a full cache), driven from a third
# host that reaches the server host and the load host by ssh without a password.
#
# Linux runs use the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# The script refuses a --server-binary that is not static (lib.sh, check_linkage) and copies
# it to the server host. Every figure is a single-node figure (plan section 2.10): one Tenko
# process on the server host ("node"), the load generators on another host ("load"), and
# for the workstation run on the host that runs this script.
#
# The node runs its own instance as the ssh user from ~/<remote-dir> (default ~/m17): its
# own data directory, the API on --api-port on loopback, the dns role on --node-addr with
# high ports for UDP and TCP, DoT and DoH. It never touches a Tenko service installed on the
# node (port 53, /var/lib/tenko, systemctl): the instance is started and stopped by the pid
# it wrote. The load host gets the query file and the procedure scripts in the same
# directory; tune-udp.sh raises its UDP sysctls for the run and restores them at the end.
#
# Phases (--phases, in this order by default):
#   prepare      copy the binary, the zone and the scripts; a new data directory; first-run
#                setup through the CLI; the zone created and imported; the answer checked
#   dnsperf      for each --workers count: the node restarted with that many workers
#                ([dns] workers, [runtime] workers at least 2 for TCP), then dnsperf over
#                UDP and over TCP, --runs runs each, with the node's CPU seconds and RSS
#                (server-cpu.sh) before and after every run and the load host's CPU
#   tls          at the last --workers count: the internal CA root fetched and the DoT and
#                DoH certificates checked against it, then dnsperf over DoT and h2load
#                (nghttp2-client) over DoH, at --flame-rate and at their maximum
#   flame        at the last --workers count: flamethrower over UDP, TCP, DoT and DoH, at
#                --flame-rate and at its maximum (generators 50, batch 20), on the first
#                100,000 lines of the query file (run-flamethrower.sh says why)
#   harness      the phase2-dns load generator from the load host at the last --workers
#                count, UDP and TCP, --runs runs each (the tool of M16, for the comparison)
#   workstation  dnsperf and the harness from the host that runs this script (UDP)
#   metrics      M22: the engine's example server (--example, built for musl like the
#                binary) with --metrics on and off, --pairs pairs, UDP at --metrics-rate
#                (a fixed rate below saturation, so that the CPU seconds per query
#                compare): by default both servers at once with half the last --workers
#                count each (--metrics-mode together), so that the hypervisor's noise
#                hits both alike; `tenko serve` has no metrics switch (docs/dns.md 12.7)
#                (the ports swap every pair, which server starts first every two pairs, so
#                that neither the port nor the start order follows the metrics; with
#                --metrics-control both servers run with the metrics off, an A/A run
#                whose cost is the design's own bias)
#   m23          M23: the instance stopped; an upstream (the example server) on the load
#                host; bench/phase1-server/m9-idle-rss.sh on the node with the roles
#                controller,probe,dns, ten home zones and the cache filled to its bound
#                through a hook, ten minutes idle
#   stop         the instance and every example server stopped, the sysctls restored
#   report       the tables of the results file from the collected raw output
#
# Usage:
#   run-m17-remote.sh --node USER@HOST --node-addr ADDR --load USER@HOST --load-addr ADDR
#                     --server-binary PATH --harness PATH --data DIR [options]
# Options:
#   --node USER@HOST     ssh target of the server host (required)
#   --node-addr ADDR     the server host's address on the link (required)
#   --load USER@HOST     ssh target of the load host (required)
#   --load-addr ADDR     the load host's address on the link (required for m23)
#   --server-binary P    the static musl tenko binary on this host (required for prepare
#                        and m23)
#   --harness P          the phase2-dns binary (static musl), copied to both hosts
#   --example P          the engine's example server `authoritative` (metrics, m23)
#   --data DIR           a zonegen --records 100000 directory (example.test.zone,
#                        queries.txt)
#   --phases LIST        the phases to run (default: all but report, then report)
#   --workers LIST       the node's worker counts (default "1 2 4"; the last is full)
#   --runs N             runs per configuration (default 2)
#   --pairs N            metrics on and off pairs of M22 (default 3)
#   --duration SECONDS   length of a run (default 30)
#   --threads N          dnsperf -T (default 8)
#   --clients N          dnsperf -c (default 64)
#   --outstanding N      dnsperf -q over UDP (default 1024; more loses datagrams at the
#                        server's socket buffers without more answers)
#   --tcp-outstanding N  dnsperf -q over TCP and DoT (default 4096)
#   --flame-rate QPS     the fixed rate of the tls and flame runs (default 10000)
#   --metrics-rate QPS   the total rate of the M22 runs (default 200000; 0 = saturation)
#   --metrics-mode M     together (default: an on and an off server at once, half the
#                        workers and half the rate each) or alternate (one server, on and
#                        off one after the other)
#   --metrics-control    M22's A/A control: the server on the "on" side runs with the
#                        metrics off too (together mode only)
#   --api-port N         the instance's API on 127.0.0.1 (default 18443)
#   --dns-port N         UDP and TCP (default 15353); DoT and DoH on --dot-port (15853)
#                        and --doh-port (15443); M23's upstream on the load host on
#                        --upstream-port (15354)
#   --remote-dir DIR     below the ssh user's home on both hosts (default m17)
#   --out DIR            local output (default results/raw/m17-<stamp>)
#   --idle-secs N        M23's idle phase (default 600)
#   --m23-prefixes N     the IPAM prefixes of the M9 data set (default 200, as in M9)
#   --m23-no-home        M23 without the hooks: no home zones, no cache fill (the M9 run
#                        of Phase 1 with the dns role, for the comparison)
set -u
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
REPO="$(cd "$ROOT/../.." && pwd)"

NODE=""; NODE_ADDR=""; LOAD=""; LOAD_ADDR=""; SERVER_BINARY=""; HARNESS=""; EXAMPLE=""
DATA=""; PHASES="prepare dnsperf tls flame harness workstation metrics m23 stop report"
WORKERS="1 2 4"; RUNS=2; PAIRS=3; DURATION=30; THREADS=8; CLIENTS=64; OUTSTANDING=1024; TCP_OUTSTANDING=4096
FLAME_RATE=10000; METRICS_RATE=200000; METRICS_MODE=together; API_PORT=18443; DNS_PORT=15353; DOT_PORT=15853; DOH_PORT=15443
UPSTREAM_PORT=15354; REMOTE_DIR=m17; OUT=""; IDLE_SECS=600; M23_PREFIXES=200; M23_HOME=1; METRICS_CONTROL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --node) NODE="$2"; shift 2 ;;
    --node-addr) NODE_ADDR="$2"; shift 2 ;;
    --load) LOAD="$2"; shift 2 ;;
    --load-addr) LOAD_ADDR="$2"; shift 2 ;;
    --server-binary) SERVER_BINARY="$2"; shift 2 ;;
    --harness) HARNESS="$2"; shift 2 ;;
    --example) EXAMPLE="$2"; shift 2 ;;
    --data) DATA="$2"; shift 2 ;;
    --phases) PHASES="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --pairs) PAIRS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --outstanding) OUTSTANDING="$2"; shift 2 ;;
    --tcp-outstanding) TCP_OUTSTANDING="$2"; shift 2 ;;
    --flame-rate) FLAME_RATE="$2"; shift 2 ;;
    --metrics-rate) METRICS_RATE="$2"; shift 2 ;;
    --metrics-mode) METRICS_MODE="$2"; shift 2 ;;
    --metrics-control) METRICS_CONTROL=1; shift ;;
    --api-port) API_PORT="$2"; shift 2 ;;
    --dns-port) DNS_PORT="$2"; shift 2 ;;
    --dot-port) DOT_PORT="$2"; shift 2 ;;
    --doh-port) DOH_PORT="$2"; shift 2 ;;
    --upstream-port) UPSTREAM_PORT="$2"; shift 2 ;;
    --remote-dir) REMOTE_DIR="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --idle-secs) IDLE_SECS="$2"; shift 2 ;;
    --m23-prefixes) M23_PREFIXES="$2"; shift 2 ;;
    --m23-no-home) M23_HOME=0; shift ;;
    -h|--help) sed -n '2,87p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$NODE" ] && [ -n "$NODE_ADDR" ] && [ -n "$LOAD" ] || die "--node, --node-addr and --load are required"
[ -n "$OUT" ] || OUT="$ROOT/results/raw/m17-$STAMP"
mkdir -p "$OUT"
META="$OUT/meta.txt"
touch "$META"
FULL="${WORKERS##* }"
RD="$REMOTE_DIR"   # relative to the remote home: ssh starts there
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15)
SCP=(scp -q -o BatchMode=yes -o ConnectTimeout=10)
on_node() { "${SSH[@]}" "$NODE" "$@"; }
on_load() { "${SSH[@]}" "$LOAD" "$@"; }
has_phase() { case " $PHASES " in *" $1 "*) return 0 ;; esac; return 1; }
now() { date +%s.%N; }
TUNED=0

# ---- the node's helper ----------------------------------------------------------------
# Written to ~/<remote-dir>/node.sh on the server host. It knows only its own directory.
node_helper() {
  cat <<'NODE_SH'
#!/usr/bin/env bash
# The server host's half of run-m17-remote.sh: one Tenko instance in this directory.
set -u
RD="$(cd "$(dirname "$0")" && pwd)"
BIN="$RD/tenko"; CFG="$RD/tenko.toml"; DATA="$RD/data"; PIDF="$RD/tenko.pid"
CA="$DATA/tls/ca-root.pem"
export TENKO_CREDENTIALS="$RD/credentials.json"
alive() { [ -s "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }
stop_pidfile() {
  local f="$1" pid n
  alive "$f" || { rm -f "$f"; return 0; }
  pid=$(cat "$f")
  kill -TERM "$pid"
  for n in $(seq 1 150); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
  kill -0 "$pid" 2>/dev/null && kill -KILL "$pid"
  rm -f "$f"
}
cmd="$1"; shift
case "$cmd" in
  config)
    W="$1"; ADDR="$2"; API="$3"; DNS="$4"; DOT="$5"; DOH="$6"
    RT="$W"; [ "$RT" -ge 2 ] || RT=2
    cat > "$CFG" <<TOML
data_dir = "$DATA"
roles = "controller,dns"
modules = ["ipam", "dns"]

[server]
listen = ["127.0.0.1:$API"]

[runtime]
workers = $RT

[tls]
mode = "internal_ca"
addresses = ["$ADDR"]

[kek]
provider = "file"
path = "$RD/kek.key"

[hibp]
online = false

[updates]
air_gapped = true

[cluster]
listen = []

[dns]
listen = ["$ADDR:$DNS"]
workers = $W

[dns.tcp]
max_connections = 20000
per_client = 1000

[dns.limits]
rrl = false

[dns.tls]
dot = true
doh = true
dot_listen = ["$ADDR:$DOT"]
doh_listen = ["$ADDR:$DOH"]
max_connections = 20000
per_client = 1000
TOML
    ;;
  start)
    API="$1"
    alive "$PIDF" && { echo "already running: pid $(cat "$PIDF")"; exit 1; }
    setsid nohup "$BIN" serve --config "$CFG" >> "$RD/server.log" 2>&1 < /dev/null &
    echo $! > "$PIDF"
    for _ in $(seq 1 600); do
      alive "$PIDF" || { echo "the server exited at start"; tail -n 20 "$RD/server.log"; exit 1; }
      if [ -f "$CA" ] && "$BIN" health --url "https://localhost:$API" --ca-file "$CA" > /dev/null 2>&1; then
        echo "pid $(cat "$PIDF")"; exit 0
      fi
      sleep 0.2
    done
    echo "the API did not answer within 120 s"; exit 1
    ;;
  stop) stop_pidfile "$PIDF"; for f in "$RD"/example*.pid; do [ -e "$f" ] && stop_pidfile "$f"; done; true ;;
  setup)
    API="$1"; URL="https://localhost:$API"
    TOKEN=$(head -n 1 "$DATA/setup-token")
    rc=1
    for _ in 1 2 3 4 5; do
      PIN=$(shuf -i 0-9 -n 8 | tr -d '\n')
      printf '%s\n' "$PIN" | TENKO_SETUP_TOKEN="$TOKEN" "$BIN" setup --url "$URL" --ca-file "$CA" \
        --admin bench --host-name localhost --password-stdin > "$RD/setup.out" 2>&1 && { rc=0; break; }
      grep -qiE 'trivial|policy|password' "$RD/setup.out" || break
    done
    [ "$rc" -eq 0 ] || { sed "s/$TOKEN/<token>/g" "$RD/setup.out"; exit 1; }
    printf '%s\n' "$PIN" | "$BIN" login --url "$URL" --ca-file "$CA" --user bench --password-stdin > /dev/null || exit 1
    "$BIN" dns zone create example.test --kind primary --ns ns1.example.test. --mname ns1.example.test. \
      --rname hostmaster@example.test --serial counter > /dev/null || exit 1
    start=$(date +%s.%N)
    "$BIN" dns import example.test "$RD/example.test.zone" --replace --wait-secs 600 > "$RD/import.out" || exit 1
    echo "import $(awk -v a="$(date +%s.%N)" -v b="$start" 'BEGIN { printf "%.1f", a - b }') s"
    ;;
  wait-dns)
    ADDR="$1"; PORT="$2"
    for _ in $(seq 1 300); do
      a=$(dig @"$ADDR" -p "$PORT" host-99999.example.test A +time=1 +tries=1 +short 2>/dev/null | grep -E '^[0-9.]+$' | head -n 1)
      [ -n "$a" ] && { echo "answers: host-99999.example.test A $a"; exit 0; }
      sleep 0.5
    done
    echo "no answer"; exit 1
    ;;
  cpu)
    # tenko, example, or example-NAME for a named example server.
    f="$PIDF"; case "${1:-tenko}" in example*) f="$RD/$1.pid" ;; esac
    alive "$f" || { echo "not running"; exit 1; }
    "$RD/server-cpu.sh" "$(cat "$f")"
    ;;
  example-start)
    W="$1"; LISTEN="$2"; METRICS="$3"; NAME="example${4:+-$4}"
    alive "$RD/$NAME.pid" && { echo "already running"; exit 1; }
    : > "$RD/$NAME.log"
    setsid nohup "$RD/authoritative" --listen "$LISTEN" --workers "$W" --metrics "$METRICS" \
      --mode reuseport --pid-file "$RD/$NAME.pid" >> "$RD/$NAME.log" 2>&1 < /dev/null &
    for _ in $(seq 1 300); do
      grep -q '^ready ' "$RD/$NAME.log" && { grep '^ready ' "$RD/$NAME.log"; exit 0; }
      sleep 0.2
    done
    echo "the example server did not start"; cat "$RD/$NAME.log"; exit 1
    ;;
  example-stop) for f in "$RD"/example*.pid; do [ -e "$f" ] && stop_pidfile "$f"; done; true ;;
  facts)
    echo "host: $(nproc) vCPU, $(awk '/MemTotal/ { printf "%.1f", $2 / 1048576 }' /proc/meminfo) GiB, $(awk -F: '/model name/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo), kernel $(uname -r), $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "binary: $("$BIN" --version), $(file -b "$BIN" | cut -d, -f1-4 | tr -s ' ')"
    for k in net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog; do echo "$k = $(sysctl -n "$k")"; done
    echo "mtu: $(ip -o link | awk '$2 != "lo:" { for (i = 1; i < NF; i++) if ($i == "mtu") { print $(i + 1); exit } }')"
    ;;
  *) echo "unknown command $cmd"; exit 2 ;;
esac
NODE_SH
}

# ---- steps ------------------------------------------------------------------------------
STEPS="$OUT/steps.tsv"
[ -s "$STEPS" ] || printf 'label\ttool\tkind\ttransport\tworkers\trun\trate\tmetrics\tcpu0\tcpu1\trss0\trss1\tload_busy\tload_secs\n' > "$STEPS"

# The busy and total ticks of the load host's CPUs: "busy total".
stat_line() { awk '$1 == "cpu" { idle = $5 + $6; t = 0; for (i = 2; i <= 9; i++) t += $i; print t - idle, t; exit }' /proc/stat; }
load_stat() { on_load "awk '\$1 == \"cpu\" { idle = \$5 + \$6; t = 0; for (i = 2; i <= 9; i++) t += \$i; print t - idle, t; exit }' /proc/stat"; }

# Records a step: label tool kind transport workers run rate metrics, the CPU readings of
# the server and the load host around the command given after "--".
# Usage: measure LABEL TOOL KIND TRANSPORT WORKERS RUN RATE METRICS WHERE -- COMMAND...
measure() {
  local label="$1" tool="$2" kind="$3" transport="$4" workers="$5" run="$6" rate="$7" metrics="$8" where="$9"
  shift 10
  local c0 c1 s0 s1 t0 t1 busy secs
  c0=$(on_node "bash $RD/node.sh cpu $kind") || die "the $kind server is not running"
  if [ "$where" = local ]; then s0=$(stat_line); else s0=$(load_stat); fi
  t0=$(now)
  "$@" > "$OUT/$label.log" 2>&1 || note "step $label: the command failed (see $label.log)"
  t1=$(now)
  if [ "$where" = local ]; then s1=$(stat_line); else s1=$(load_stat); fi
  c1=$(on_node "bash $RD/node.sh cpu $kind") || die "the $kind server stopped during $label"
  busy=$(awk -v a="$s0" -v b="$s1" -v hz="$(getconf CLK_TCK)" -v t="$(awk -v x="$t1" -v y="$t0" 'BEGIN { print x - y }')" \
    'BEGIN { split(a, p, " "); split(b, q, " "); printf "%.2f", (q[1] - p[1]) / hz / t }')
  secs=$(awk -v x="$t1" -v y="$t0" 'BEGIN { printf "%.1f", x - y }')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$tool" "$kind" "$transport" \
    "$workers" "$run" "$rate" "$metrics" "$(echo "$c0" | awk '{ print $2 }')" "$(echo "$c1" | awk '{ print $2 }')" \
    "$(echo "$c0" | awk '{ print $3 }')" "$(echo "$c1" | awk '{ print $3 }')" "$busy" "$secs" >> "$STEPS"
  say "step $label: server cpu $(echo "$c0" | awk '{ print $2 }') -> $(echo "$c1" | awk '{ print $2 }') s, load busy $busy cores"
}

fetch() { "${SCP[@]}" -r "$LOAD:$RD/raw/$1" "$OUT/" 2>/dev/null || note "could not fetch $1 from the load host"; }

dnsperf_step() { # LABEL TRANSPORT WORKERS RUN KIND METRICS [RATE]
  local label="$1" rate="${7:-0}" port="$DNS_PORT" q="$OUTSTANDING"
  [ "$2" = udp ] || q="$TCP_OUTSTANDING"
  [ "$2" = dot ] && port="$DOT_PORT"
  measure "$label" dnsperf "$5" "$2" "$3" "$4" "$rate" "$6" load -- on_load "bash $RD/scripts/run-dnsperf.sh --server $NODE_ADDR --port $port --names $RD/queries.txt --transport $2 --rates $rate --duration $DURATION --threads $THREADS --clients $CLIENTS --outstanding $q --extra '-O latency-histogram' --out-dir $RD/raw/$label"
  fetch "$label"
}

# DoH: h2load (nghttp2) over HTTP/2 with GET requests for the first 10,000 names of the
# query file, one URI each, round robin (`-i`); dnsperf 2.14 and flamethrower 0.12 stall on
# this listener with more than two requests in flight per connection (DoH notes in
# run-flamethrower.sh), h2load does not.
h2load_step() { # LABEL RATE
  local label="$1" rate="$2" args
  if [ "$rate" = 0 ]; then args="-c 64 -m 32"; else args="-c 10 -m 4 --rps $((rate / 10))"; fi
  measure "$label" h2load tenko doh "$FULL" 1 "$rate" on load -- on_load "mkdir -p $RD/raw/$label && h2load $args -D $DURATION -i $RD/doh-uris.txt -H 'accept: application/dns-message' > $RD/raw/$label/h2load.txt 2>&1"
  fetch "$label"
}

# Runs a command of the node's helper, notes its output and stops the run when it fails.
node_do() {
  local out rc
  out=$(on_node "bash $RD/node.sh $*" 2>&1)
  rc=$?
  [ -z "$out" ] || printf '%s\n' "$out" | while IFS= read -r l; do note "node: $l"; done
  [ "$rc" -eq 0 ] || die "node.sh $1 failed (status $rc)"
}

node_restart() { # WORKERS
  node_do stop
  node_do config "$1" "$NODE_ADDR" "$API_PORT" "$DNS_PORT" "$DOT_PORT" "$DOH_PORT"
  node_do start "$API_PORT"
  node_do wait-dns "$NODE_ADDR" "$DNS_PORT"
  note "node: $1 workers"
}

tune() {
  [ "$TUNED" = 1 ] && return 0
  on_load "bash $RD/scripts/tune-udp.sh apply" | while IFS= read -r l; do note "load sysctl: $l"; done
  TUNED=1
}
untune() {
  on_load "bash $RD/scripts/tune-udp.sh restore" | while IFS= read -r l; do note "load sysctl: $l"; done
  TUNED=0
}
cleanup() {
  local status=$?
  [ "$TUNED" = 1 ] && untune
  exit "$status"
}
trap cleanup EXIT

note "run-m17-remote: phases=[$PHASES] workers=[$WORKERS] runs=$RUNS duration=${DURATION}s dnsperf -T $THREADS -c $CLIENTS -q $OUTSTANDING"
note "control host: $(machine_line)"

# The scripts on both hosts are those of this checkout, at every start.
sync_scripts() {
  on_node "mkdir -p $RD" && on_load "mkdir -p $RD/scripts $RD/raw" || die "cannot reach the hosts"
  node_helper | on_node "cat > $RD/node.sh"
  "${SCP[@]}" "$HERE/server-cpu.sh" "$NODE:$RD/"
  "${SCP[@]}" "$HERE/lib.sh" "$HERE/run-dnsperf.sh" "$HERE/run-flamethrower.sh" "$HERE/tune-udp.sh" "$LOAD:$RD/scripts/"
}
has_phase prepare || sync_scripts

# ---- prepare ----------------------------------------------------------------------------
if has_phase prepare; then
  [ -n "$SERVER_BINARY" ] || die "--server-binary is required for prepare"
  check_linkage "$SERVER_BINARY" 0
  [ -f "$DATA/example.test.zone" ] && [ -f "$DATA/queries.txt" ] || die "--data needs example.test.zone and queries.txt (zonegen --records 100000)"
  on_node "bash $RD/node.sh stop" 2>/dev/null || true
  on_node "mkdir -p $RD && rm -rf $RD/data $RD/credentials.json $RD/kek.key $RD/server.log"
  sync_scripts
  "${SCP[@]}" "$SERVER_BINARY" "$NODE:$RD/tenko"
  "${SCP[@]}" "$DATA/example.test.zone" "$NODE:$RD/"
  "${SCP[@]}" "$DATA/queries.txt" "$LOAD:$RD/"
  [ -z "$HARNESS" ] || "${SCP[@]}" "$HARNESS" "$LOAD:$RD/phase2-dns"
  node_do facts
  on_load "nproc; awk -F: '/model name/ { sub(/^ /, \"\", \$2); print \$2; exit }' /proc/cpuinfo; uname -r; dnsperf -h 2>&1 | grep -m1 Version; flame --version 2>&1 | head -n 1" |
    paste -sd';' | while IFS= read -r l; do note "load host: $l"; done
  note "link: $(on_load "ping -c 20 -i 0.2 -q $NODE_ADDR" | tail -n 1)"
  node_do config "$FULL" "$NODE_ADDR" "$API_PORT" "$DNS_PORT" "$DOT_PORT" "$DOH_PORT"
  node_do start "$API_PORT"
  node_do setup "$API_PORT"
  node_do wait-dns "$NODE_ADDR" "$DNS_PORT"
fi

# ---- dnsperf ----------------------------------------------------------------------------
if has_phase dnsperf; then
  tune
  for w in $WORKERS; do
    node_restart "$w"
    for t in udp tcp; do
      for r in $(seq 1 "$RUNS"); do
        dnsperf_step "dnsperf-$t-w$w-r$r" "$t" "$w" "$r" tenko on
      done
    done
  done
fi

# ---- tls --------------------------------------------------------------------------------
# DoT with dnsperf and DoH with h2load, at --flame-rate and at their maximum.
if has_phase tls; then
  tune
  node_restart "$FULL"
  on_load "command -v h2load > /dev/null" || die "h2load (package nghttp2-client) is not installed on the load host"
  on_node "cat $RD/data/tls/ca-root.pem" > "$OUT/ca-root.pem"
  "${SCP[@]}" "$OUT/ca-root.pem" "$LOAD:$RD/ca-root.pem"
  note "internal CA root: $(openssl x509 -in "$OUT/ca-root.pem" -noout -subject -fingerprint -sha256 2>/dev/null | paste -sd' ')"
  note "DoT certificate check: $(on_load "openssl s_client -connect $NODE_ADDR:$DOT_PORT -CAfile $RD/ca-root.pem -verify_return_error < /dev/null 2>&1 | grep -m1 'Verify return code'")"
  note "DoH certificate check: $(on_load "curl -s -o /dev/null -w '%{http_code} %{http_version} ssl_verify=%{ssl_verify_result}' --cacert $RD/ca-root.pem -H 'accept: application/dns-message' 'https://$NODE_ADDR:$DOH_PORT/dns-query?dns=AAABAAABAAAAAAAACmhvc3QtOTk5OTkHZXhhbXBsZQR0ZXN0AAABAAE'")"
  # GET URIs: the DNS message of each name in base64url without padding (RFC 8484).
  on_load "head -n 10000 $RD/queries.txt | python3 -c '
import base64, struct, sys
for i, line in enumerate(sys.stdin):
    name = line.split()[0].rstrip(\".\")
    q = struct.pack(\">HHHHHH\", 0, 0x0000, 1, 0, 0, 0)
    q += b\"\".join(bytes([len(l)]) + l.encode() for l in name.split(\".\")) + b\"\\0\" + struct.pack(\">HH\", 1, 1)
    print(\"https://$NODE_ADDR:$DOH_PORT/dns-query?dns=\" + base64.urlsafe_b64encode(q).decode().rstrip(\"=\"))
' > $RD/doh-uris.txt && wc -l < $RD/doh-uris.txt" | while IFS= read -r l; do note "DoH URIs: $l"; done
  for rate in "$FLAME_RATE" 0; do
    for r in $(seq 1 "$RUNS"); do
      dnsperf_step "dnsperf-dot-w$FULL-rate$rate-r$r" dot "$FULL" "$r" tenko on "$rate"
      h2load_step "h2load-doh-w$FULL-rate$rate-r$r" "$rate"
    done
  done
fi

# ---- flame ------------------------------------------------------------------------------
if has_phase flame; then
  tune
  node_restart "$FULL"
  on_load "head -n 100000 $RD/queries.txt > $RD/queries-100k.txt"
  for p in udp tcp dot doh; do
    case "$p" in dot) port=$DOT_PORT ;; doh) port=$DOH_PORT ;; *) port=$DNS_PORT ;; esac
    for rate in "$FLAME_RATE" 0; do
      label="flame-$p-rate$rate"
      gen=""; [ "$rate" = 0 ] && gen="--generators 50 --batch 20"
      measure "$label" flame tenko "$p" "$FULL" 1 "$rate" on load -- on_load "bash $RD/scripts/run-flamethrower.sh --server $NODE_ADDR --port $port --names $RD/queries-100k.txt --protocol $p --rates $rate --duration $DURATION $gen --out-dir $RD/raw/$label"
      fetch "$label"
    done
  done
fi

# ---- harness ----------------------------------------------------------------------------
if has_phase harness; then
  [ -n "$HARNESS" ] || die "--harness is required for the harness phase"
  tune
  node_restart "$FULL"
  for t in udp tcp; do
    for r in $(seq 1 "$RUNS"); do
      label="harness-$t-w$FULL-r$r"
      measure "$label" harness tenko "$t" "$FULL" "$r" 0 on load -- on_load "mkdir -p $RD/raw/$label && $RD/phase2-dns load --target $NODE_ADDR:$DNS_PORT --names $RD/queries.txt --transport $t --clients 32 --inflight 64 --duration ${DURATION}s --warmup 0s --require-aa --workers $FULL --label m17-link --json $RD/raw/$label/run.jsonl"
      fetch "$label"
    done
  done
fi

# ---- workstation ------------------------------------------------------------------------
if has_phase workstation; then
  command -v dnsperf > /dev/null 2>&1 || die "dnsperf is not on this host's PATH"
  node_restart "$FULL"
  for r in $(seq 1 "$RUNS"); do
    label="workstation-dnsperf-udp-w$FULL-r$r"
    measure "$label" dnsperf tenko udp "$FULL" "$r" 0 on local -- bash "$HERE/run-dnsperf.sh" --server "$NODE_ADDR" --port "$DNS_PORT" --names "$DATA/queries.txt" --transport udp --duration "$DURATION" --threads "$THREADS" --clients "$CLIENTS" --outstanding "$OUTSTANDING" --extra "-O latency-histogram" --out-dir "$OUT/$label"
    if [ -n "$HARNESS" ]; then
      label="workstation-harness-udp-w$FULL-r$r"
      mkdir -p "$OUT/$label"
      measure "$label" harness tenko udp "$FULL" "$r" 0 on local -- "$HARNESS" load --target "$NODE_ADDR:$DNS_PORT" --names "$DATA/queries.txt" --transport udp --clients 32 --inflight 64 --duration "${DURATION}s" --warmup 0s --require-aa --workers "$FULL" --label m17-workstation --json "$OUT/$label/run.jsonl"
    fi
  done
fi

# ---- metrics (M22) ----------------------------------------------------------------------
if has_phase metrics; then
  [ -n "$EXAMPLE" ] || die "--example is required for the metrics phase"
  check_linkage "$EXAMPLE" 0
  tune
  on_node "bash $RD/node.sh stop"
  "${SCP[@]}" "$EXAMPLE" "$NODE:$RD/authoritative"
  if [ "$METRICS_MODE" = alternate ]; then
    for i in $(seq 1 "$PAIRS"); do
      for m in on off; do
        node_do example-start "$FULL" "$NODE_ADDR:$DNS_PORT" "$m"
        dnsperf_step "metrics-$m-udp-w$FULL-rate$METRICS_RATE-p$i" udp "$FULL" "$i" example "$m" "$METRICS_RATE"
        node_do example-stop
      done
    done
  else
    # Together: two example servers at once, one with the metrics on and one with them off,
    # each with half the workers and half the rate, loaded by two dnsperf processes in the
    # same window, so that whatever else the hypervisor does at that moment costs both the
    # same. The ports swap from pair to pair and the start order every two pairs, so that
    # neither follows the metrics (WP6.5 started the server with the metrics on first in
    # every pair). With --metrics-control the "on" side runs with the metrics off too: the
    # cost such a run reports is the design's own bias.
    half=$((FULL / 2)); [ "$half" -ge 1 ] || half=1
    rate=$((METRICS_RATE / 2)); threads=$((THREADS / 2)); [ "$threads" -ge 1 ] || threads=1
    m_on=on; kind=together
    [ "$METRICS_CONTROL" = 1 ] && { m_on=off; kind=control; }
    for i in $(seq 1 "$PAIRS"); do
      if [ $((i % 2)) = 1 ]; then p_on=$DNS_PORT; p_off=$((DNS_PORT + 10)); else p_on=$((DNS_PORT + 10)); p_off=$DNS_PORT; fi
      if [ $(((i - 1) / 2 % 2)) = 0 ]; then
        node_do example-start "$half" "$NODE_ADDR:$p_on" "$m_on" on
        node_do example-start "$half" "$NODE_ADDR:$p_off" off off
      else
        node_do example-start "$half" "$NODE_ADDR:$p_off" off off
        node_do example-start "$half" "$NODE_ADDR:$p_on" "$m_on" on
      fi
      l_on="metrics-$kind-on-w$half-rate$rate-p$i"; l_off="metrics-$kind-off-w$half-rate$rate-p$i"
      a0=$(on_node "bash $RD/node.sh cpu example-on"); b0=$(on_node "bash $RD/node.sh cpu example-off"); s0=$(load_stat); t0=$(now)
      on_load "for x in 'on $p_on $l_on' 'off $p_off $l_off'; do set -- \$x; bash $RD/scripts/run-dnsperf.sh --server $NODE_ADDR --port \$2 --names $RD/queries.txt --transport udp --rates $rate --duration $DURATION --threads $threads --clients $((CLIENTS / 2)) --outstanding $((OUTSTANDING / 2)) --extra '-O latency-histogram' --out-dir $RD/raw/\$3 > /dev/null 2>&1 & done; wait"
      t1=$(now); s1=$(load_stat); a1=$(on_node "bash $RD/node.sh cpu example-on"); b1=$(on_node "bash $RD/node.sh cpu example-off")
      busy=$(awk -v a="$s0" -v b="$s1" -v hz="$(getconf CLK_TCK)" -v t="$(awk -v x="$t1" -v y="$t0" 'BEGIN { print x - y }')" \
        'BEGIN { split(a, p, " "); split(b, q, " "); printf "%.2f", (q[1] - p[1]) / hz / t }')
      secs=$(awk -v x="$t1" -v y="$t0" 'BEGIN { printf "%.1f", x - y }')
      for row in "$l_on example-on on $a0|$a1" "$l_off example-off off $b0|$b1"; do
        set -- ${row%%|*}; label=$1; kind=$2; m=$3; c0="$4 $5 $6"; c1="${row##*|}"
        printf '%s\tdnsperf\t%s\tudp\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$kind" "$half" "$i" "$rate" "$m" \
          "$(echo "$c0" | awk '{ print $2 }')" "$(echo "$c1" | awk '{ print $2 }')" \
          "$(echo "$c0" | awk '{ print $3 }')" "$(echo "$c1" | awk '{ print $3 }')" "$busy" "$secs" >> "$STEPS"
        fetch "$label"
      done
      say "pair $i: on $(echo "$a0 $a1" | awk '{ printf "%.2f", $5 - $2 }') s, off $(echo "$b0 $b1" | awk '{ printf "%.2f", $5 - $2 }') s of server CPU; load busy $busy cores"
      node_do example-stop
    done
  fi
fi

# ---- m23 --------------------------------------------------------------------------------
# The hooks run on the server host inside m9-idle-rss.sh (bench/phase1-server): before the
# idle phase they create the ten home zones and fill the cache, after it they read the
# cache once more.
m23_before() {
  cat <<'HOOK'
#!/usr/bin/env bash
# M23 before the idle phase: ten small home zones (five forward zones, three IPv4 and two
# IPv6 reverse zones, about 600 RRsets), then the cache filled to its bound through the
# forwarder at about 1,000 queries per second.
set -eu
B="$M9_BINARY"; DIR="$(dirname "$0")"; Z="$DIR/zones"; mkdir -p "$Z"
header() { printf '$ORIGIN %s.\n$TTL 3600\n@ IN SOA ns1.lan.example.test. hostmaster.lan.example.test. 1 3600 900 604800 300\n@ IN NS ns1.lan.example.test.\n' "$1"; }
{ header lan.example.test; echo "ns1 IN A 192.0.2.53"; echo "ns1 IN AAAA 2001:db8::53"
  for i in $(seq 1 60); do echo "pc-$i IN A 192.0.2.$((i + 10))"; echo "pc-$i IN AAAA 2001:db8::$(printf '%x' $((i + 16)))"; done
  echo "www IN CNAME pc-1"; echo "@ IN MX 10 mail"; echo "mail IN A 192.0.2.25"
  echo '@ IN TXT "v=spf1 mx -all"'; echo "_ldap._tcp IN SRV 0 100 389 pc-2"; } > "$Z/lan.example.test.zone"
{ header iot.example.test; for i in $(seq 1 40); do echo "sensor-$i IN A 198.51.100.$((i + 10))"; done; } > "$Z/iot.example.test.zone"
{ header dmz.example.test; for i in $(seq 1 10); do echo "srv-$i IN A 203.0.113.$((i + 10))"; echo "srv-$i IN AAAA 2001:db8:0:1::$i"; done; } > "$Z/dmz.example.test.zone"
{ header guest.example.test; for i in $(seq 1 5); do echo "guest-$i IN A 198.51.100.$((i + 200))"; done; } > "$Z/guest.example.test.zone"
{ header lab.example.test; for i in $(seq 1 20); do echo "vm-$i IN A 203.0.113.$((i + 100))"; done; } > "$Z/lab.example.test.zone"
{ header 2.0.192.in-addr.arpa; for i in $(seq 1 60); do echo "$((i + 10)) IN PTR pc-$i.lan.example.test."; done; } > "$Z/2.0.192.in-addr.arpa.zone"
{ header 100.51.198.in-addr.arpa; for i in $(seq 1 40); do echo "$((i + 10)) IN PTR sensor-$i.iot.example.test."; done
  for i in $(seq 1 5); do echo "$((i + 200)) IN PTR guest-$i.guest.example.test."; done; } > "$Z/100.51.198.in-addr.arpa.zone"
{ header 113.0.203.in-addr.arpa; for i in $(seq 1 10); do echo "$((i + 10)) IN PTR srv-$i.dmz.example.test."; done
  for i in $(seq 1 20); do echo "$((i + 100)) IN PTR vm-$i.lab.example.test."; done; } > "$Z/113.0.203.in-addr.arpa.zone"
nib() { printf '%032x' "$1" | rev | sed 's/./&./g; s/\.$//'; }
{ header 0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa; for i in $(seq 1 60); do echo "$(nib $((i + 16)) | cut -d. -f1-24) IN PTR pc-$i.lan.example.test."; done; } > "$Z/0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.zone"
{ header 1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa; for i in $(seq 1 10); do echo "$(nib "$i" | cut -d. -f1-16).0.0.0.0.0.0.0.0 IN PTR srv-$i.dmz.example.test."; done; } > "$Z/1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.zone"
# The API's rate limit answers 429 right after the M9 data set; retry like a client would.
try() { local n; for n in $(seq 1 30); do "$@" > /dev/null 2>&1 && return 0; sleep 2; done; "$@"; }
rrsets=0
for f in "$Z"/*.zone; do
  zone=$(basename "$f" .zone)
  try "$B" dns zone create "$zone" --kind primary --ns ns1.lan.example.test. --mname ns1.lan.example.test. \
    --rname hostmaster@lan.example.test --serial counter
  try "$B" dns import "$zone" "$f" --replace --wait-secs 600
  rrsets=$((rrsets + $(grep -c ' IN ' "$f")))
done
echo "home zones: 10 imported, about $rrsets records"
sleep 20
for _ in $(seq 1 30); do zones=$("$B" dns zone list --json 2>/dev/null) && break; sleep 2; done
printf '%s' "$zones" | python3 -c '
import json, sys
items = json.load(sys.stdin)["items"]
print("zones on the node 20 s later: %d with %d RRsets (the networks of the M9 data set get reverse zones once a forward zone exists, P2-Q11)" % (len(items), sum(int(z.get("rrsets") or 0) for z in items)))'
seq 0 19999 | awk '{ print "host-" $1 ".example.test A" }' > "$DIR/fill.txt"
"$DIR/phase2-dns" load --target "$M9_DNS" --names "$DIR/fill.txt" --rd --qps 1000 --clients 2 --inflight 16 \
  --duration 40s --warmup 0s --timeout 2s | grep -E '^(sent|received|answers|timeouts|errors)' | paste -sd' '
bash "$DIR/m23-count.sh"
HOOK
}
m23_count() {
  cat <<'HOOK'
#!/usr/bin/env bash
# Counts the entries of node 1's cache by paging through `tenko dns cache list --json`.
set -u
B="$M9_BINARY"; n=0; stale=0; cursor=""
for _ in $(seq 1 100); do
  if [ -n "$cursor" ]; then set -- --cursor "$cursor"; else set --; fi
  page=""
  for _ in $(seq 1 30); do page=$("$B" dns cache list 1 --limit 1000 --json "$@" 2>/dev/null) && break; page=""; sleep 2; done
  [ -n "$page" ] || { echo "tenko dns cache list failed"; exit 1; }
  read -r rows st cursor < <(printf '%s' "$page" | python3 -c '
import json, sys
p = json.load(sys.stdin)
items = p.get("items", [])
print(len(items), sum(1 for i in items if i.get("stale")), p.get("next_cursor") or "")')
  n=$((n + rows)); stale=$((stale + st))
  [ -n "$cursor" ] || break
done
echo "cache entries (tenko dns cache list): $n, of them stale: $stale"
HOOK
}
if has_phase m23; then
  [ -n "$SERVER_BINARY" ] && [ -n "$EXAMPLE" ] && [ -n "$HARNESS" ] && [ -n "$LOAD_ADDR" ] || die "m23 needs --server-binary, --example, --harness and --load-addr"
  on_node "bash $RD/node.sh stop"
  on_node "mkdir -p $RD/m23 && rm -rf $RD/m23/work"
  "${SCP[@]}" "$SERVER_BINARY" "$NODE:$RD/tenko"
  "${SCP[@]}" "$HARNESS" "$NODE:$RD/m23/phase2-dns"
  "${SCP[@]}" "$REPO/bench/phase1-server/m9-idle-rss.sh" "$NODE:$RD/m23/"
  m23_before | on_node "cat > $RD/m23/m23-before.sh"
  m23_count | on_node "cat > $RD/m23/m23-count.sh"
  "${SCP[@]}" "$EXAMPLE" "$LOAD:$RD/authoritative"
  on_load "[ -s $RD/example.pid ] && kill -INT \$(cat $RD/example.pid) 2>/dev/null; sleep 1; : > $RD/example.log; setsid nohup $RD/authoritative --listen $LOAD_ADDR:$UPSTREAM_PORT --workers 2 --pid-file $RD/example.pid >> $RD/example.log 2>&1 < /dev/null & sleep 3; grep '^ready ' $RD/example.log" |
    while IFS= read -r l; do note "upstream on the load host: $l"; done
  hooks="--before-idle \$HOME/$RD/m23/m23-before.sh --after-idle \$HOME/$RD/m23/m23-count.sh"
  [ "$M23_HOME" = 1 ] || hooks=""
  note "m23: prefixes $M23_PREFIXES, home zones and cache fill: $([ "$M23_HOME" = 1 ] && echo yes || echo no)"
  on_node "cd $RD/m23 && bash m9-idle-rss.sh --binary \$HOME/$RD/tenko --roles controller,probe,dns --kek file --prefixes $M23_PREFIXES --dns-forwarder $LOAD_ADDR:$UPSTREAM_PORT $hooks --idle-secs $IDLE_SECS --workdir \$HOME/$RD/m23/work --outdir \$HOME/$RD/m23/raw" > "$OUT/m23.log" 2>&1 ||
    note "m9-idle-rss.sh failed on the node (see m23.log)"
  "${SCP[@]}" -r "$NODE:$RD/m23/raw" "$OUT/m23-raw" || note "could not fetch the M23 raw output"
  on_load "[ -s $RD/example.pid ] && kill -INT \$(cat $RD/example.pid); rm -f $RD/example.pid"
fi

# ---- stop -------------------------------------------------------------------------------
if has_phase stop; then
  on_node "bash $RD/node.sh stop" || true
  on_load "[ -s $RD/example.pid ] && kill -INT \$(cat $RD/example.pid); rm -f $RD/example.pid" || true
  untune
  note "node: instance stopped; $(on_node "ss -lntu | grep -cE ':($DNS_PORT|$DOT_PORT|$DOH_PORT|$API_PORT) '" ) sockets left on the instance's ports"
fi

# ---- report -----------------------------------------------------------------------------
# One row per step: the tool's figures joined with the CPU readings.
if has_phase report; then
  {
    printf 'label\ttool\ttransport\tworkers\tmetrics\trate\tqps\tcompleted\tlost\tmean_us\tp50_us\tp99_us\tp999_us\tserver_cpu_s\tserver_cores\tqps_per_core\trss_before\trss_after\tload_cores\n'
    tail -n +2 "$STEPS" | while IFS=$'\t' read -r label tool kind transport workers run rate metrics cpu0 cpu1 rss0 rss1 busy secs; do
      qps=""; done_=""; lost=""; mean=""; p50=""; p99=""; p999=""; dur=""
      case "$tool" in
        dnsperf)
          if [ -f "$OUT/$label/summary.tsv" ]; then
            IFS=$'\t' read -r _ _ done_ lost qps mean _ _ _ _ p50 p99 p999 dur < <(tail -n 1 "$OUT/$label/summary.tsv")
            mean=$(awk -v s="$mean" 'BEGIN { if (s != "") printf "%.0f", s * 1e6 }')
          fi ;;
        harness)
          if [ -f "$OUT/$label/run.jsonl" ]; then
            read -r qps done_ lost mean p50 p99 p999 dur < <(tail -n 1 "$OUT/$label/run.jsonl" | tr ',{}' '\n\n\n' |
              awk -F: '{ gsub(/"/, "", $1); v[$1] = $2 } END { print v["qps"], v["received"], v["timeouts"], v["mean"], v["p50"], v["p99"], v["p999"], v["measured_seconds"] }')
          fi ;;
        flame)
          if [ -f "$OUT/$label/summary.tsv" ]; then
            IFS=$'\t' read -r _ _ done_ lost qps mean _ < <(tail -n 1 "$OUT/$label/summary.tsv")
            mean=$(awk -v s="$mean" 'BEGIN { if (s != "") printf "%.0f", s * 1e3 }')
            dur="$DURATION"
          fi ;;
        h2load)
          if [ -f "$OUT/$label/h2load.txt" ]; then
            read -r qps done_ lost mean dur < <(awk '
              function us(v) { if (v ~ /us$/) return v + 0; if (v ~ /ms$/) return v * 1e3; if (v ~ /s$/) return v * 1e6; return v }
              /^finished in/ { d = $3 + 0; r = $4 + 0 }
              /^requests:/ { ok = $8; bad = $10 + $12 + $14 }
              /^time for request:/ { m = us($6) }
              END { printf "%.0f %s %s %.0f %s\n", r, ok, bad, m, d }' "$OUT/$label/h2load.txt")
          fi ;;
      esac
      cpu=$(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN { if (a == "" || b == "") print ""; else printf "%.2f", b - a }')
      cores=$(awk -v c="$cpu" -v d="${dur:-$DURATION}" 'BEGIN { if (c == "" || d == "" || d == 0) print ""; else printf "%.2f", c / d }')
      per_core=$(awk -v n="$done_" -v c="$cpu" 'BEGIN { if (n == "" || c == "" || c == 0) print ""; else printf "%.0f", n / c }')
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$tool" "$transport" "$workers" "$metrics" "$rate" \
        "$qps" "$done_" "$lost" "$mean" "$p50" "$p99" "$p999" "$cpu" "$cores" "$per_core" "$rss0" "$rss1" "$busy"
    done
  } > "$OUT/report.tsv"
  column -t -s $'\t' "$OUT/report.tsv" 2>/dev/null || cat "$OUT/report.tsv"
  # M22: the metrics cost from the pairs, as CPU seconds per query with the metrics on over
  # those with them off, per pair and over all pairs (mean, standard error of the mean).
  awk -F'\t' '
    $1 ~ /^metrics-/ && $8 > 0 && $14 > 0 {
      p = $1; sub(/^.*-p/, "", p); cpq = $14 / $8
      if ($5 == "on") { on[p] = cpq; onq += $8; onc += $14; p99on[++n1] = $12 } else { off[p] = cpq; offq += $8; offc += $14; p99off[++n2] = $12 }
    }
    function median(a, n,   i, j, t) {
      for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (a[j] + 0 < a[i] + 0) { t = a[i]; a[i] = a[j]; a[j] = t }
      return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
    }
    END {
      k = 0
      for (p in on) if (p in off) { k++; r[k] = on[p] / off[p] - 1; s += r[k]; printf "M22 pair %s: cost %+.2f%%\n", p, 100 * r[k] }
      if (k == 0) exit
      m = s / k; for (i = 1; i <= k; i++) v += (r[i] - m) ^ 2
      se = (k > 1) ? sqrt(v / (k - 1) / k) : 0
      printf "M22 %d pairs: cost per query %+.2f%% (mean of the pairs, standard error %.2f points); over all queries %+.2f%%\n", k, 100 * m, 100 * se, 100 * ((onc / onq) / (offc / offq) - 1)
      printf "M22 QPS per server core: on %.0f, off %.0f; p99 median: on %s us, off %s us\n", onq / onc, offq / offc, median(p99on, n1), median(p99off, n2)
    }' "$OUT/report.tsv" | tee "$OUT/m22-summary.txt"
fi
say "output: $OUT"
