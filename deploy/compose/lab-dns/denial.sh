# shellcheck shell=bash
# The rows of E35 in the round `recursion` (WP10.3, dns-recursion-plan.md sections 2.2 and
# 2.6): QNAME minimisation on the wire (RFC 9156) and the denial cache (RFC 8198, RFC 8020).
# smoke.sh sources this file; recursion.sh runs `denial_rows` with the node's default
# settings (relaxed minimisation, the denial cache on) and `denial_mode_rows` at the end of
# the round, which restarts the node with `qname_minimisation = "strict"` and
# `aggressive_nsec = false`, then with `qname_minimisation = "off"`. With M42=1 the round
# also runs the measurement M42 (`denial_m42`; bench/phase2-dns/scripts/run-m42-denial.sh).
#
# Witnesses: the authority's query log (GET /nodes/{id}/dns/log on the lab root's node:
# every query that reached the zones of the lab), the lines `asked NAME TYPE` of the quirk
# responder `quirk-ent` (a server that answers NXDOMAIN for its empty non-terminals, the
# kind RFC 9156 falls back for), delv for the synthesised answers, and dig's RCODE and AD.

ent_zone=ent.quirk.example.test
m42=()

# auth_asked <name>: the queries for exactly that name (any type) in the authority's log.
auth_asked() {
  sleep 1
  on authority
  [[ -n "$auth_node_id" ]] || auth_node_id="$(api GET /system/status >/dev/null && field "d['node']['id']" <"$work/api.out")"
  api GET "/nodes/$auth_node_id/dns/log?qname=$1&limit=1000" >/dev/null || {
    echo -1
    return
  }
  python3 -c "
import json, sys
name = '$1'.rstrip('.').lower()
items = json.load(open('$work/api.out'))['items']
print(sum(1 for item in items if item['qname'].rstrip('.').lower() == name))"
}

# auth_asked_a <name>: the type-A queries for exactly that name in the authority's log (only
# minimisation asks a zone's apex for A here; the validator asks DS and DNSKEY).
auth_asked_a() {
  sleep 1
  on authority
  [[ -n "$auth_node_id" ]] || auth_node_id="$(api GET /system/status >/dev/null && field "d['node']['id']" <"$work/api.out")"
  api GET "/nodes/$auth_node_id/dns/log?qname=$1&limit=1000" >/dev/null || {
    echo -1
    return
  }
  python3 -c "
import json
name = '$1'.rstrip('.').lower()
items = json.load(open('$work/api.out'))['items']
print(sum(1 for item in items if item['qname'].rstrip('.').lower() == name and str(item['type']) == 'A'))"
}

# auth_since <from> <suffix>: the queries for names at or below the suffix the authority's
# log holds since the time <from> (RFC 3339), every page read.
auth_since() {
  sleep 1
  on authority
  [[ -n "$auth_node_id" ]] || auth_node_id="$(api GET /system/status >/dev/null && field "d['node']['id']" <"$work/api.out")"
  python3 - "$api_base" "$cookie" "$auth_node_id" "$1" "$2" <<'PY'
import json, sys, urllib.parse, urllib.request
base, cookie, node, since, suffix = sys.argv[1:6]
count, cursor = 0, None
while True:
    query = {"qname": suffix, "from": since, "limit": "1000"}
    if cursor:
        query["cursor"] = cursor
    request = urllib.request.Request(
        f"{base}/api/v1/nodes/{node}/dns/log?{urllib.parse.urlencode(query)}",
        headers={"Cookie": cookie, "Origin": base},
    )
    page = json.load(urllib.request.urlopen(request, timeout=30))
    count += len(page["items"])
    cursor = page.get("next_cursor")
    if not cursor:
        break
print(count)
PY
}

# ent_asked: the names quirk-ent was asked, one per line, oldest first.
ent_asked() { compose logs --no-log-prefix quirk-ent 2>/dev/null | sed -n 's/^asked \([^ ]*\) .*/\1/p'; }

# rcode_ad <name> <type>: the RCODE and, when set, `ad`, as the node answers with DO.
rcode_ad() {
  local out
  out="$(dig_node "$1" "$2" +dnssec)"
  printf '%s%s\n' "$(rcode_of <<<"$out")" "$(grep -q '^;; flags:.* ad[ ;]' <<<"$out" && echo ' ad')"
}

# synthesised <first> <type> <second> <type> <want>: asks <first> (the authority answers
# and the node keeps the proof), then <second>, which must answer <want> (the RCODE and ad,
# as rcode_ad prints them) with no query for it at the authority.
synthesised() {
  local first="$1" first_type="$2" second="$3" type="$4" want="$5" before after got
  rcode_ad "$first" "$first_type" >/dev/null
  before="$(auth_asked "$second")"
  got="$(rcode_ad "$second" "$type")"
  after="$(auth_asked "$second")"
  echo "$second $type: $got, the authority asked $((after - before)) time(s)"
  [[ "$after" == "$before" ]] || node_lines "$first" "$second"
  [[ "$got" == "$want" && "$before" -ge 0 && "$after" == "$before" ]]
}

# node_lines <name>...: the node's query log lines of the names (how each was resolved and
# its validation state), for a row that failed.
node_lines() {
  local name
  for name in "$@"; do
    on tenko
    api GET "/nodes/$node_id/dns/log?qname=$name&limit=20" >/dev/null &&
      python3 -c "
import json
for i in json.load(open('$work/api.out'))['items']:
    print('node log:', i['qname'], i['type'], i['rcode'], i.get('resolution'), i.get('validation'), i.get('subqueries', 0))"
  done
}

# not_synthesised <first> <second> <type>: as synthesised, but the second name must reach
# the authority (the denial cache off).
not_synthesised() {
  local before after
  rcode_ad "$1" "$3" >/dev/null
  before="$(auth_asked "$2")"
  rcode_ad "$2" "$3" >/dev/null
  after="$(auth_asked "$2")"
  echo "$2: the authority asked $((after - before)) time(s)"
  ((after > before))
}

# minimised <name> <minimised|full>: with the node's caches flushed, asks the name (three
# labels below the TLD, www.nsec3.example.test). The lab's authority serves the root, the TLD
# and the zones under it from one address and answers from the deepest zone it holds, so
# the walk never leaves the root's cut: minimised, the root's servers are asked
# `example.test` and `nsec3.example.test` (type A, which only minimisation asks of those
# names) before the full name, and the full name once; full (QNAME minimisation off), the
# full name and none of the shorter questions.
minimised() {
  local name="$1" mode="$2" full_before full_after tld_before tld_after zone_before zone_after
  on tenko
  if [[ "$mode" == minimised ]]; then
    api POST "/nodes/$node_id/dns/cache/flush" >/dev/null &&
      api POST "/nodes/$node_id/dns/infra/flush" >/dev/null || return 1
  fi
  full_before="$(auth_asked "$name")"
  tld_before="$(auth_asked_a example.test)"
  zone_before="$(auth_asked_a "${name#*.}")"
  [[ "$(rcode_of <<<"$(dig_node "$name" A)")" == NOERROR ]] || return 1
  full_after="$(auth_asked "$name")"
  tld_after="$(auth_asked_a example.test)"
  zone_after="$(auth_asked_a "${name#*.}")"
  echo "$name asked $((full_after - full_before)) time(s); example.test A $((tld_after - tld_before)) time(s), ${name#*.} A $((zone_after - zone_before)) time(s)"
  if [[ "$mode" == minimised ]]; then
    ((full_after - full_before == 1 && tld_after > tld_before && zone_after > zone_before))
  else
    ((full_after > full_before && tld_after == tld_before && zone_after == zone_before))
  fi
}

# ent_case <mode>: www.a.b.ent.quirk.example.test against the server that denies its
# empty non-terminals, and what quirk-ent was asked: relaxed falls back to the full name
# and remembers it for the zone, strict takes the NXDOMAIN, off asks the full name only.
ent_case() {
  local mode="$1" before asked out rcode
  before="$(ent_asked | wc -l)"
  out="$(dig_node "www.a.b.$ent_zone" A)"
  rcode="$(rcode_of <<<"$out")"
  asked="$(ent_asked | tail -n +"$((before + 1))" | tr '\n' ' ')"
  echo "$mode: $rcode; quirk-ent was asked: $asked"
  case "$mode" in
    relaxed)
      [[ "$rcode" == NOERROR && "$asked" == "b.$ent_zone www.a.b.$ent_zone " ]] || return 1
      # Remembered: the next name of the zone goes out whole at once.
      before="$(ent_asked | wc -l)"
      dig_node "www.c.$ent_zone" A >/dev/null
      asked="$(ent_asked | tail -n +"$((before + 1))" | tr '\n' ' ')"
      echo "then quirk-ent was asked: $asked"
      [[ "$asked" == "www.c.$ent_zone " ]]
      ;;
    strict) [[ "$rcode" == NXDOMAIN && "$asked" == "b.$ent_zone " ]] ;;
    off) [[ "$rcode" == NOERROR && "$asked" == "www.a.b.$ent_zone " ]] ;;
  esac
}

# delv_secure <name> <type>: delv validates the node's (synthesised) answer, and the
# authority was not asked for the name meanwhile.
delv_secure() {
  local before after verdict
  before="$(auth_asked "$1")"
  verdict="$(delv_verdict "$tenko_ip" "$dns_port" "$1" "$2")"
  after="$(auth_asked "$1")"
  echo "delv: $verdict; the authority asked $((after - before)) time(s)"
  [[ "$verdict" == secure && "$after" == "$before" ]]
}

# denial_rows: the rows with the node's default settings.
denial_rows() {
  printf '\n==> E35: QNAME minimisation and the denial cache\n'
  row den.qmin "www.nsec3.example.test: example.test and nsec3.example.test asked first, the full name once" \
    minimised www.nsec3.example.test minimised
  row den.qmin.fallback "relaxed: the NXDOMAIN of an empty non-terminal asked again whole, remembered" \
    ent_case relaxed
  row den.nsec "after nothing.example.test, nope.example.test is NXDOMAIN from the NSEC, no query" \
    synthesised nothing.example.test A nope.example.test A "NXDOMAIN ad"
  row den.nsec.nodata "after api.example.test AAAA, MX is NODATA from the NSEC, no query" \
    synthesised api.example.test AAAA api.example.test MX "NOERROR ad"
  row den.nsec3 "after a.nsec3.example.test, b.nsec3.example.test is NXDOMAIN from the NSEC3, no query" \
    synthesised a.nsec3.example.test A b.nsec3.example.test A "NXDOMAIN ad"
  row den.nsec3.nodata "after www.nsec3.example.test AAAA, TXT is NODATA from the NSEC3, no query" \
    synthesised www.nsec3.example.test AAAA www.nsec3.example.test TXT "NOERROR ad"
  row den.wildcard "after one.wild.example.test, two.wild.example.test from the wildcard, no query" \
    synthesised one.wild.example.test A two.wild.example.test A "NOERROR ad"
  row den.rfc8020 "after gone.insecure.example.test, x.gone.insecure.example.test is NXDOMAIN, no query" \
    synthesised gone.insecure.example.test A x.gone.insecure.example.test A NXDOMAIN
  row den.delv.nxdomain "delv validates the synthesised NXDOMAIN of nope.example.test" \
    delv_secure nope.example.test A
  row den.delv.nodata "delv validates the synthesised NODATA of api.example.test MX" \
    delv_secure api.example.test MX
}

# restart_node <extra [dns.recursion] lines>: the node under test with other settings, its
# data (the lab anchor) kept and its caches empty.
restart_node() {
  recursion_extra="$1"
  write_recursion_config
  compose up -d --no-build --force-recreate tenko >/dev/null
  retry "$wait_secs" "tenko to become healthy" healthy tenko
  retry 60 "the node to resolve again" \
    bash -c "[[ \"\$(docker compose -f '$compose_file' exec -T client dig @$tenko_ip -p $dns_port +short +time=5 +tries=1 www.example.test)\" == 192.0.2.10 ]]"
}

# denial_mode_rows: the rows of the other settings; the node runs the defaults again after.
denial_mode_rows() {
  printf '\n==> E35: strict and off, and the denial cache off\n'
  restart_node $'qname_minimisation = "strict"\naggressive_nsec = false'
  row den.strict "strict: the NXDOMAIN of the empty non-terminal stands, no fallback" ent_case strict
  row den.off.aggressive "aggressive_nsec = false: nope.example.test reaches the authority" \
    not_synthesised nothing.example.test nope2.example.test A
  restart_node 'qname_minimisation = "off"'
  row den.off "off: www.nsec3.example.test asked whole, no shorter question" \
    minimised www.nsec3.example.test full
  row den.off.ent "off: quirk-ent asked the full name only" ent_case off
  [[ "${M42:-0}" == 1 ]] && denial_m42
  restart_node ""
}

# m42_run <label> <suffix> <first>: 1,000 random names under one covered range, asked of the
# node after <first> (an NXDOMAIN whose proof covers the range); prints the queries the
# authority saw for names below <suffix> during the run.
m42_run() {
  local label="$1" suffix="$2" first="$3" since count names
  dig_node "$first" A >/dev/null
  names="$(python3 -c "
import random
for _ in range(1000):
    print('m' + ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(12)) + '.$suffix A')")"
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sleep 1
  compose exec -T client dig "@$tenko_ip" -p "$dns_port" +time=5 +tries=1 +noall -f /dev/stdin <<<"$names" >/dev/null 2>&1 || true
  count="$(auth_since "$since" "$suffix")"
  m42+=("$(printf '%-34s %5s authority queries per 1,000 names' "$label" "$count")")
}

# denial_m42: M42 under each setting (the node restarted for each).
denial_m42() {
  local mode aggressive
  printf '\n==> M42: authority queries per 1,000 random names under a covered range\n'
  for aggressive in true false; do
    for mode in relaxed strict off; do
      restart_node "qname_minimisation = \"$mode\""$'\n'"aggressive_nsec = $aggressive"
      m42_run "nsec  $mode denial=$aggressive" example.test nothing.example.test
      m42_run "nsec3 $mode denial=$aggressive" nsec3.example.test a.nsec3.example.test
    done
  done
  printf '%s\n' "${m42[@]}"
  summary+=("${m42[@]}")
}
