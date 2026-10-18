#!/usr/bin/env bash
# M19 (IXFR delta and NOTIFY latency, docs/plans/phase-2-plan.md section 6): a 100-record
# change on a 100,000-record zone reaches BIND within 5 s, and the transfer carries only
# the change.
#
# The measurement runs on the compose DNS lab (deploy/compose/lab-dns) with the Tenko image
# of the release, which holds the static musl binary that ships (deploy/Dockerfile), and
# BIND 9 as the secondary of a Tenko zone:
#
# 1. Lab. The lab smoke runs its transfer round with KEEP=1 (TSIG key, access list, setup
#    through the API) and leaves the lab running; the smoke's checks must pass.
# 2. Zone. big.example.test is created on Tenko as a primary zone that the key's access list
#    may transfer and that notifies BIND, and --records A records are imported from a zone
#    file through the API (the import job). BIND's secondary zone of the same name
#    (transfer.conf) takes the zone by AXFR; the script waits until BIND serves Tenko's
#    serial, and notes the size of that AXFR.
# 3. Rounds. --rounds times, one batch of --changes records is written through the API
#    (each a new address for an existing name). From the moment the API answered (the
#    change set committed) the script asks BIND every 20 ms for the last name of the batch
#    until it has the new address: the change-to-BIND latency. BIND's log gives the moment
#    the NOTIFY arrived (the NOTIFY latency, from the same start) and the size of the
#    transfer (messages, records, bytes): the delta carries 2 x --changes records and
#    four SOA records.
# 4. The results go to results/raw/m19-<stamp>.log (the figures) and are printed as the
#    table of the results file; the lab is torn down.
#
# Every figure is a single-node figure (plan section 2.10). The lab runs on one Docker host:
# Tenko, BIND and the client are containers on one bridge network, so the latencies are an
# upper bound of what the same software does over a real link minus that link's delay;
# they are labelled loopback figures.
#
# Run as root (Docker) on the Docker host, from the repository root:
#   IMAGE=tenko:lab bash bench/phase2-dns/scripts/run-m19-xfr.sh [--records N] [--changes N] [--rounds N]
# IMAGE names an existing image; without it the smoke builds tenko:lab first.
set -euo pipefail
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
REPO="$(cd "$ROOT/../.." && pwd)"
LAB="$REPO/deploy/compose/lab-dns"

RECORDS=100000; CHANGES=100; ROUNDS=5
while [ $# -gt 0 ]; do
  case "$1" in
    --records) RECORDS="$2"; shift 2 ;;
    --changes) CHANGES="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
mkdir -p "$ROOT/results/raw"
OUT="$ROOT/results/raw/m19-$STAMP.log"
META="$OUT"
: >"$OUT"

note "M19 run $STAMP: $RECORDS records, $CHANGES changes per round, $ROUNDS rounds"
note "$(machine_line)"
note "image: ${IMAGE:-tenko:lab (built by the smoke)}"

say "the lab: the smoke's transfer round with KEEP=1"
smoke_log="$ROOT/results/raw/m19-$STAMP-smoke.log"
if ! KEEP=1 ROUNDS=xfr bash "$LAB/smoke.sh" >"$smoke_log" 2>&1; then
  grep -E "^(PASS|FAIL)|smoke:" "$smoke_log" >&2 || true
  die "the lab smoke failed; see $smoke_log"
fi
LAB_DIR="$(sed -n 's/^    LAB_DIR=\([^ ]*\) .*/\1/p' "$smoke_log" | head -n 1)"
[ -n "$LAB_DIR" ] && [ -f "$LAB_DIR/session.env" ] || die "no kept lab in $smoke_log"
export LAB_DIR
# shellcheck disable=SC1091
. "$LAB_DIR/session.env"
compose() { docker compose -f "$LAB/compose.yml" "$@"; }
teardown() {
  compose logs --no-color --timestamps bind tenko >"$ROOT/results/raw/m19-$STAMP-services.log" 2>&1 || true
  compose down --volumes --timeout 10 >/dev/null 2>&1 || true
  rm -rf "$LAB_DIR"
}
trap teardown EXIT

work="$LAB_DIR"
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -o "$work/m19.out" -w '%{http_code}' -X "$method" -H "Origin: $api_base"
    -H "Cookie: $cookie" -H "Idempotency-Key: $(cat /proc/sys/kernel/random/uuid)")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" --data-binary "@$body")
  fi
  status="$(curl "${args[@]}" "$api_base/api/v1$path")"
  case "$status" in 2*) return 0 ;; *) echo "API $method $path: $status $(head -c 400 "$work/m19.out")" >&2; return 1 ;; esac
}
field() { python3 -c "import json; d=json.load(open('$work/m19.out')); print($1)"; }
bind_serial() { compose exec -T client dig @203.0.113.2 +time=1 +tries=1 +short big.example.test SOA | awk '{print $3}'; }
bind_address() { compose exec -T client dig @203.0.113.2 +time=1 +tries=1 +short "$1" A; }
now_ms() { date +%s%3N; }

say "the zone: big.example.test with $RECORDS records"
cat >"$work/zone.json" <<JSON
{"name": "big.example.test", "kind": "primary", "serial": "counter",
 "soa": {"mname": "ns.example.test", "rname": "hostmaster.example.test", "refresh": 3600, "retry": 600, "expire": 86400, "minimum": 60, "ttl": 60},
 "name_servers": ["ns.example.test"],
 "transfer": {"allow": ["$acl"], "notify": [{"address": "203.0.113.2", "port": 53, "key": "$xfr_key"}], "require_tsig": true}}
JSON
api POST /dns/zones "$work/zone.json" || die "the zone could not be created"
zone_id="$(field "d['id']")"
python3 - "$RECORDS" "$work/import.json" <<'PY'
import json, sys
count, path = int(sys.argv[1]), sys.argv[2]
lines = ["$ORIGIN big.example.test.", "$TTL 60"]
for i in range(count):
    lines.append(f"h{i} IN A 198.51.100.{i % 250 + 1}")
json.dump({"zone_file": "\n".join(lines) + "\n", "replace": False}, open(path, "w"))
PY
began="$(now_ms)"
api POST "/dns/zones/$zone_id/records/import" "$work/import.json" || die "the import could not start"
job="$(field "d['job_id']")"
while true; do
  api GET "/jobs/$job" "" || die "the import job cannot be read"
  state="$(field "d['job']['state']")"
  case "$state" in
    succeeded) break ;;
    failed|rolled_back) die "the import job ended $state: $(head -c 400 "$work/m19.out")" ;;
  esac
  sleep 1
done
note "import of $RECORDS records: $(( $(now_ms) - began )) ms"
api GET "/dns/zones/$zone_id" "" || die "the zone cannot be read"
serial="$(field "d['soa_serial']")"
began="$(now_ms)"
until [ "$(bind_serial)" = "$serial" ]; do
  [ $(( $(now_ms) - began )) -lt 300000 ] || die "BIND did not take serial $serial within 300 s"
  sleep 0.5
done
axfr="$(compose logs --no-color --no-log-prefix bind 2>&1 | grep "transfer of 'big.example.test/IN'.*Transfer completed" | tail -n 1 | sed 's/.*Transfer completed: //')"
note "initial transfer to BIND (serial $serial): $axfr"

printf '| Round | Change to BIND answer (ms) | NOTIFY at BIND (ms) | Transfer to BIND | Delta only |\n|---|---|---|---|---|\n' >>"$OUT"
latencies=()
failed=0
for round in $(seq 1 "$ROUNDS"); do
  python3 - "$CHANGES" "$round" "$work/batch.json" <<'PY'
import json, sys
count, round_, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
changes = [{"op": "set", "name": f"h{i}.big.example.test", "type": "A", "ttl": 60,
            "records": [{"type": "A", "address": f"203.0.113.{(round_ * 7 + i) % 250 + 1}"}]}
           for i in range(count)]
json.dump({"changes": changes}, open(path, "w"))
PY
  last="h$((CHANGES - 1)).big.example.test"
  want="203.0.113.$(( (round * 7 + CHANGES - 1) % 250 + 1 ))"
  since="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  api POST "/dns/zones/$zone_id/records/batch" "$work/batch.json" || die "round $round: the batch was refused"
  committed="$(now_ms)"
  until [ "$(bind_address "$last")" = "$want" ]; do
    [ $(( $(now_ms) - committed )) -lt 30000 ] || die "round $round: BIND did not answer the change within 30 s"
    sleep 0.02
  done
  latency=$(( $(now_ms) - committed ))
  latencies+=("$latency")
  sleep 0.5
  logs="$(compose logs --no-color --timestamps --since "$since" bind 2>&1)"
  notify_at="$(grep "received notify for zone 'big.example.test'" <<<"$logs" | head -n 1 | awk '{print $3}')"
  notify_ms="-"
  if [ -n "$notify_at" ]; then
    notify_ms=$(( $(date -d "$notify_at" +%s%3N) - committed ))
  fi
  transfer="$(grep "transfer of 'big.example.test/IN'.*Transfer completed" <<<"$logs" | tail -n 1 | sed 's/.*Transfer completed: //; s/ (serial.*//')"
  records="$(sed -n 's/^[0-9]* messages, \([0-9]*\) records.*/\1/p' <<<"$transfer")"
  delta="no"
  if [ "${records:-0}" -eq $(( 2 * CHANGES + 4 )) ]; then delta="yes"; fi
  if [ "$latency" -gt 5000 ] || [ "$delta" = no ]; then failed=1; fi
  printf '| %s | %s | %s | %s | %s |\n' "$round" "$latency" "$notify_ms" "$transfer" "$delta" >>"$OUT"
  say "round $round: $latency ms, NOTIFY at $notify_ms ms, $transfer, delta only: $delta"
done
sorted="$(printf '%s\n' "${latencies[@]}" | sort -n | tr '\n' ' ')"
note "change-to-BIND latencies (ms, sorted): $sorted"
if [ "$failed" = 0 ]; then
  note "M19 PASS: every change reached BIND within 5 s by IXFR with the delta only"
else
  note "M19 FAIL: a change took longer than 5 s or did not come as the delta only"
fi
cat "$OUT"
