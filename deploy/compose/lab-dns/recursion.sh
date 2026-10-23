# shellcheck shell=bash
# The round `recursion` of the DNS lab (WP10.1, dns-recursion-plan.md section 2.12): the
# node under test resolves iteratively from the lab's own root, served by a second Tenko
# node (`authority`), with the quirk responders beside it. smoke.sh sources this file and
# runs `recursion` for ROUNDS=recursion; README.md lists the rows.
#
# The zones are signed (NSEC, NSEC3 where said) and their DS records published in the
# parents; the round checks resolution first: E36 (priming, the work budget and the failure
# cases) and E41 (the RPZ triggers NSDNAME and NSIP on the delegation the resolver
# followed), then the validation rows of E33 (validation.sh, WP10.2: every state with delv
# agreeing, the KeyTrap zone, the forwarded answers). E35's rows come with WP10.3; E34's
# roll is the round rfc5011 (validation.sh).
#
# Witnesses: the node's own counters (GET /nodes/{id}/dns/recursion: the queries sent to
# authorities before and after each case, M40), the answers as dig prints them (RCODE and
# the extended error), and the authority's query log (GET /nodes/{id}/dns/log on the
# authority) for the queries that reached the lab root.

authority_ip=203.0.113.10
here_recursion="$here/recursion"
auth_cookie=""
node_cookie=""
node_id=""
auth_node_id=""
# The zones of the authority in creation order: name, file, signing.
recursion_zones=(
  ".|root.zone|nsec"
  "test|test.zone|nsec"
  "example.test|example.test.zone|nsec"
  "nsec3.example.test|nsec3.example.test.zone|nsec3"
  "wild.example.test|wild.example.test.zone|nsec"
  "dname.example.test|dname.example.test.zone|nsec"
  "cname.example.test|cname.example.test.zone|nsec"
  "big.example.test|big.example.test.zone|nsec"
  "insecure.example.test|insecure.example.test.zone|off"
  "bogus.example.test|bogus.example.test.zone|nsec"
)

# on <authority|tenko>: points api() at that node's API and session.
on() {
  case "$1" in
    authority)
      api_base="http://$authority_ip:8443"
      cookie="$auth_cookie"
      ;;
    tenko)
      api_base="http://$tenko_ip:8443"
      cookie="$node_cookie"
      ;;
  esac
}

# setup_node <service> <ip> <host name>: the first-run setup of a node under the Lab
# profile; prints the session cookie.
setup_node() {
  local token password body
  token="$(compose exec -T "$1" /usr/local/bin/tenko setup token --data-dir /var/lib/tenko | tr -d '\r\n')"
  [[ -n "$token" ]] || fail "recursion: no setup token on $1"
  password="$(od -An -N4 -tu4 /dev/urandom | tr -dc '0-9')"
  body="{\"setup_token\": \"$token\", \"profile\": \"lab\", \"admin\": {\"name\": \"labadmin\", \"display_name\": \"Lab Admin\", \"password\": \"$password\"}, \"host_name\": \"$3\", \"language\": \"en\"}"
  curl -sS -D - -o "$work/api.out" -H "Origin: http://$2:8443" -H "Content-Type: application/json" \
    --data "$body" "http://$2:8443/api/v1/setup" | tr -d '\r' |
    sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1
}

# The configuration of the authority node: the Lab profile, DNS on 53, no recursion of its
# own (a name outside its zones is REFUSED), the query log on as the witness.
write_authority_config() {
  mkdir -p "$work/authority"
  cat >"$work/authority/authority.toml" <<TOML
# The lab root's authority node (written by smoke.sh, round recursion).
roles = "controller,dns"
modules = ["ipam", "dns"]

[profile]
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["0.0.0.0:8443"]

[dns]
listen = ["0.0.0.0:53"]

[dns.recursion]
enabled = false

[dns.log]
enabled = true
pseudonymise = false
TOML
  chmod 0755 "$work/authority"
  chmod 0444 "$work/authority/authority.toml"
}

# The configuration of the node under test: recursion from the lab root, no forwarder.
write_recursion_config() {
  rm -f "$work/tenko.toml"
  cat >"$work/tenko.toml" <<TOML
# The configuration of the round "recursion" (written by smoke.sh). Validation is on (the
# default); the lab root's DS replaces the shipped root anchor once the node is up (WP10.2).
roles = "controller,dns"
modules = ["ipam", "dns"]

[profile]
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["0.0.0.0:8443"]

[dns]
listen = ["0.0.0.0:$dns_port"]

[dns.recursion]
hints = "/lab/root.hints"
# The lab's names are under the special-use TLD test (RFC 6761).
local_zones_except = ["test"]
timeout_ms = 1000

[dns.cache]
prefetch = false
TOML
  chmod 0444 "$work/tenko.toml"
}

soa_lab() {
  printf '{"mname": "a.root.test", "rname": "hostmaster.example.test", "refresh": 3600, "retry": 600, "expire": 86400, "minimum": 60, "ttl": 3600}'
}

# create_zone <name> <nsec|nsec3|off>: a primary zone on the authority, signed online as
# asked; prints its id.
create_zone() {
  local dnssec=""
  case "$2" in
    nsec) dnssec=', "dnssec": {"mode": "online", "denial": {"kind": "nsec"}}' ;;
    nsec3) dnssec=', "dnssec": {"mode": "online", "denial": {"kind": "nsec3", "iterations": 0}}' ;;
  esac
  api POST /dns/zones "{\"name\": \"$1\", \"kind\": \"primary\", \"serial\": \"counter\", \"soa\": $(soa_lab), \"name_servers\": [\"a.root.test\"]$dnssec}" >/dev/null ||
    fail "recursion: zone $1 could not be created on the authority ($api_status: $(cat "$work/api.out"))"
  field "d['id']" <"$work/api.out"
}

# import_zone <id> <file>: merges the records of a zone file into the zone.
import_zone() {
  local body
  body="$(python3 -c 'import json,sys; print(json.dumps({"zone_file": open(sys.argv[1]).read(), "replace": False}))' "$2")"
  api POST "/dns/zones/$1/records/import" "$body" >/dev/null ||
    fail "recursion: $2 could not be imported ($api_status: $(cat "$work/api.out"))"
}

# publish_ds <child id> <parent id> <child name> [wrong]: the DS records of a signed child
# in its parent; with `wrong`, a DS whose digest matches no key (bogus.example.test).
publish_ds() {
  local records
  api GET "/dns/zones/$1/dnssec" >/dev/null || return 1
  records="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
ds = d.get("ds") or []
if not ds:
    sys.exit(1)
if sys.argv[2] == "wrong":
    for record in ds:
        digest = record["digest"]
        record["digest"] = ("0" if digest[0] != "0" else "1") + digest[1:]
print(json.dumps(ds))' "$work/api.out" "${4:-right}")" || return 1
  api POST "/dns/zones/$2/records/batch" "{\"changes\": [{\"op\": \"set\", \"name\": \"$3\", \"type\": \"DS\", \"ttl\": 3600, \"records\": $records}]}" >/dev/null
}

# dig_node <name> [type] [options...]: one query to the node under test, full output.
dig_node() {
  local name="$1" type="${2:-A}"
  shift 2 || shift $#
  dig_client "@$tenko_ip" -p "$dns_port" +time=12 +tries=1 +noall +comments +answer +authority "$@" "$name" "$type"
}
ede_of() { sed -n 's/.*EDE: \([0-9]*\).*/\1/p' | head -n 1; }

# The node's recursion status into $work/recursion.json.
node_status() { on tenko && api GET "/nodes/$node_id/dns/recursion" >"$work/recursion.json"; }
# counter <name>: a counter of the node's recursion status.
counter() {
  node_status >/dev/null || { echo 0; return; }
  python3 -c "import json; print(json.load(open('$work/recursion.json'))['counters']['$1'])"
}

# case_row <row> <what> <name> <type> <rcode> <ede or -> [answer]: resolves the name, checks
# the RCODE (and the extended error, and the first answer's data when given), prints the
# queries sent and the time, and asks again to see the failure cache answer without a query.
case_row() {
  local row_name="$1" what="$2" name="$3" type="$4" rcode="$5" ede="$6" want="${7:-}"
  local before after out took got_rcode got_ede data second
  before="$(counter subqueries)"
  local began
  began="$(date +%s%3N)"
  out="$(dig_node "$name" "$type" 2>&1)" || true
  took=$(($(date +%s%3N) - began))
  after="$(counter subqueries)"
  got_rcode="$(rcode_of <<<"$out")"
  got_ede="$(ede_of <<<"$out")"
  data="$(awk -v type="$type" '!/^;/ && $4 == type { print $5; exit }' <<<"$out")"
  local sent=$((after - before))
  local ok_case=1
  [[ "$got_rcode" == "$rcode" ]] || ok_case=0
  [[ "$ede" == - || "$got_ede" == "$ede" ]] || ok_case=0
  [[ -z "$want" || "$data" == "$want" ]] || ok_case=0
  ((sent <= 32 && took <= 10500)) || ok_case=0
  if [[ "$rcode" == SERVFAIL ]]; then
    local again_before again_after
    again_before="$(counter subqueries)"
    second="$(dig_node "$name" "$type" 2>&1)" || true
    again_after="$(counter subqueries)"
    [[ "$(rcode_of <<<"$second")" == SERVFAIL && $((again_after - again_before)) == 0 ]] || ok_case=0
    what="$what; the second ask sent nothing (RFC 9520)"
  fi
  m40+=("$(printf '%-24s %2s queries %5s ms  %s %s' "$row_name" "$sent" "$took" "$got_rcode" "${got_ede:+EDE $got_ede}")")
  row "$row_name" "$what ($got_rcode${got_ede:+ EDE $got_ede}, $sent queries, $took ms)" test "$ok_case" == 1 ||
    printf '%s\n' "$out" >&2
}

priming_ok() {
  node_status >/dev/null &&
    python3 -c "
import json, sys
d = json.load(open('$work/recursion.json'))
p = d.get('last_priming') or {}
ok = d['enabled'] and d['hints_source'] == '/lab/root.hints' and p.get('outcome') == 'ok' and p.get('duration_ms', 1e9) < 100
print('priming', p, 'root', d.get('root_servers'))
sys.exit(0 if ok else 1)"
}
primed_again() {
  local before
  before="$(counter primings_ok)"
  on tenko && api POST "/nodes/$node_id/dns/recursion/prime" >/dev/null || return 1
  within 10 test_counter_above primings_ok "$before"
}
test_counter_above() { (($(counter "$1") > $2)); }

infra_has_edns_off() {
  on tenko && api GET "/nodes/$node_id/dns/infra?suffix=quirk.example.test&limit=100" >/dev/null &&
    python3 -c "
import json, sys
d = json.load(open('$work/api.out'))
found = [a for c in d['items'] for s in c['servers'] for a in s['addresses'] if a['address'] == '$1']
print(found)
sys.exit(0 if found and found[0].get('$2') == $3 else 1)"
}
unwanted_counted() { (($(counter unwanted) > 0)); }
local_answer() {
  local before after out
  before="$(counter subqueries)"
  out="$(dig_node printer.local A)"
  after="$(counter subqueries)"
  [[ "$(rcode_of <<<"$out")" == NXDOMAIN && "$after" == "$before" ]]
}

# The RPZ zone of E41 on the node under test, with one NSDNAME and one NSIP trigger.
rpz_setup() {
  local id
  on tenko
  api POST /dns/zones "{\"name\": \"rpz.lab.test\", \"kind\": \"rpz\", \"serial\": \"counter\", \"soa\": $(soa_lab), \"name_servers\": [\"a.root.test\"]}" >/dev/null ||
    fail "recursion: the RPZ zone could not be created ($api_status: $(cat "$work/api.out"))"
  id="$(field "d['id']" <"$work/api.out")"
  api POST "/dns/zones/$id/records/batch" '{"changes": [
    {"op": "set", "name": "ns.case.quirk.example.test.rpz-nsdname.rpz.lab.test", "type": "CNAME", "ttl": 60, "records": [{"type": "CNAME", "target": "."}]},
    {"op": "set", "name": "32.14.113.0.203.rpz-nsip.rpz.lab.test", "type": "CNAME", "ttl": 60, "records": [{"type": "CNAME", "target": "."}]}
  ]}' >/dev/null || fail "recursion: the RPZ triggers could not be written ($api_status: $(cat "$work/api.out"))"
}
blocked_by() {
  local out
  out="$(dig_node "$1" A)"
  [[ "$(rcode_of <<<"$out")" == NXDOMAIN && "$(ede_of <<<"$out")" == 15 ]]
}
not_blocked() { [[ "$(rcode_of <<<"$(dig_node "$1" A)")" == NOERROR ]]; }

authority_saw() {
  on authority
  [[ -n "$auth_node_id" ]] || auth_node_id="$(api GET /system/status >/dev/null && field "d['node']['id']" <"$work/api.out")"
  api GET "/nodes/$auth_node_id/dns/log?name=$1&limit=100" >/dev/null &&
    python3 -c "import json,sys; d=json.load(open('$work/api.out')); n=len(d['items']); print(n, 'queries'); sys.exit(0 if n > 0 else 1)"
}

recursion() {
  local name file signing id parent
  declare -A zone_ids=()
  m40=()
  step "round recursion: iterative resolution from the lab root, then validation (E33)"
  if [[ -z "${QUIRK_IMAGE:-}" ]]; then
    export QUIRK_IMAGE=tenko-quirk:lab
    docker build -f "$here/quirk.Dockerfile" -t "$QUIRK_IMAGE" "$repo"
  fi
  write_authority_config
  compose --profile recursion up -d --no-build authority quirk-noedns quirk-case quirk-tc \
    quirk-slow quirk-spoof quirk-oob quirk-sub quirk-strip client bind bind-resolver delv
  retry "$wait_secs" "the authority to become healthy" healthy authority
  auth_cookie="$(setup_node authority "$authority_ip" a.root.test)"
  [[ -n "$auth_cookie" ]] || fail "recursion: the authority's setup did not sign in: $(cat "$work/api.out")"
  on authority
  for entry in "${recursion_zones[@]}"; do
    IFS='|' read -r name file signing <<<"$entry"
    id="$(create_zone "$name" "$signing")"
    zone_ids[$name]="$id"
    import_zone "$id" "$here_recursion/zones/$file"
  done
  retry 120 "the authority to answer www.example.test" \
    bash -c "[[ \"\$(docker compose -f '$compose_file' exec -T client dig @$authority_ip +short +time=2 +tries=1 www.example.test)\" == 192.0.2.10 ]]"
  # The DS records in the parents, once the children are signed: the root's child test,
  # test's child example.test and example.test's signed children; bogus.example.test gets
  # a DS that matches no key.
  for entry in "${recursion_zones[@]}"; do
    IFS='|' read -r name file signing <<<"$entry"
    [[ "$name" == . || "$signing" == off ]] && continue
    case "$name" in
      test) parent=. ;;
      example.test) parent=test ;;
      *) parent=example.test ;;
    esac
    if [[ "$name" == bogus.example.test ]]; then
      retry 60 "the DS of $name" publish_ds "${zone_ids[$name]}" "${zone_ids[$parent]}" "$name" wrong
    else
      retry 60 "the DS of $name" publish_ds "${zone_ids[$name]}" "${zone_ids[$parent]}" "$name"
    fi
  done
  ok "recursion: lab root" "the authority serves . test example.test and ${#recursion_zones[@]} zones, signed"
  # WP10.2: the zones BIND signs with its own keys, delegated from example.test.
  bind_zones_setup

  write_recursion_config
  compose up -d --no-build --force-recreate tenko
  retry "$wait_secs" "tenko to become healthy" healthy tenko
  node_cookie="$(setup_node tenko "$tenko_ip" tenko.example.test)"
  [[ -n "$node_cookie" ]] || fail "recursion: the node's setup did not sign in: $(cat "$work/api.out")"
  on tenko
  node_id="$(api GET /system/status >/dev/null && field "d['node']['id']" <"$work/api.out")"
  [[ -n "$node_id" ]] || fail "recursion: no node id"
  # WP10.2: the lab root's DS as the node's trust anchor and delv's.
  anchor_setup

  row rec.prime.file "primed from the hints file at start, under 100 ms (M41)" within 30 priming_ok
  node_status >/dev/null || true
  local priming_ms
  priming_ms="$(python3 -c "import json; print((json.load(open('$work/recursion.json')).get('last_priming') or {}).get('duration_ms', '?'))" 2>/dev/null || echo '?')"
  m40+=("$(printf '%-24s %s ms (M41)' "priming at start" "$priming_ms")")
  row rec.prime.again "POST .../recursion/prime primes again" primed_again
  case_row rec.resolve "www.example.test from a cold cache" www.example.test A NOERROR - 192.0.2.10
  case_row rec.wildcard "a name under a wildcard" any.wild.example.test A NOERROR - 192.0.2.20
  case_row rec.dname "a name under a DNAME (RFC 6672)" www.old.dname.example.test A NOERROR - 192.0.2.31
  case_row rec.chain "a CNAME chain of one" short.cname.example.test A NOERROR - 192.0.2.32
  case_row rec.nxdomain "NXDOMAIN" nothing.example.test A NXDOMAIN -
  case_row rec.big "an answer above 1,232 octets, over TCP" big.example.test AAAA NOERROR - 2001:db8::1
  case_row rec.lame "a lame delegation (NS at BIND, which serves the parent)" www.lame.example.test A SERVFAIL 22
  case_row rec.nsloop "name servers pointing at each other without glue" www.loop.example.test A SERVFAIL 22
  case_row rec.cname.loop "a CNAME loop" loop1.cname.example.test A SERVFAIL 22
  case_row rec.cname.ten "a CNAME chain of ten, over the eight restarts" c1.cname.example.test A SERVFAIL 22
  case_row rec.unreachable "a TLD whose server does not answer" www.unreachable A SERVFAIL 22
  case_row rec.0x20 "a server that breaks 0x20" www.case.quirk.example.test A NOERROR - 192.0.2.7
  case_row rec.formerr "a server that answers FORMERR to EDNS" www.noedns.quirk.example.test A NOERROR - 192.0.2.7
  row rec.formerr.marked "the server is marked EDNS-less in the infrastructure cache" infra_has_edns_off 203.0.113.11 edns False
  case_row rec.tc "a server that truncates everything" www.tc.quirk.example.test A NOERROR - 192.0.2.7
  case_row rec.oob "a referral with out-of-bailiwick glue (ignored)" www.sub.oob.quirk.example.test A NOERROR - 192.0.2.7
  case_row rec.slow "a server that answers after 2.5 s, past the attempt's timeout" www.slow.quirk.example.test A SERVFAIL 22
  case_row rec.spoof "a server that answers from the wrong source port" www.spoof.quirk.example.test A SERVFAIL 22
  row rec.unwanted "the answers from the wrong source are counted as unwanted" unwanted_counted
  row rec.local "a locally served name (printer.local) is NXDOMAIN without a query" local_answer
  row rec.witness "the lab root's query log saw the node's queries" authority_saw www.example.test

  # E41: NSDNAME and NSIP on the delegation the resolver followed.
  rpz_setup
  row rec.rpz.nsdname "NSDNAME ns.case.quirk.example.test blocks a name of its zone" within 30 blocked_by other.case.quirk.example.test
  row rec.rpz.nsip "NSIP 203.0.113.14/32 blocks a name of the zone it serves" within 30 blocked_by other.tc.quirk.example.test
  row rec.rpz.pass "a name whose delegation no trigger names still resolves" not_blocked www.wild.example.test

  # WP10.2: the validation rows (E33).
  validation_rows

  printf '\n==> M40: the queries sent per case\n'
  printf '%s\n' "${m40[@]}"
  summary+=("${m40[@]}")
  ((rows_failed == 0)) || fail "recursion: $rows_failed row(s) failed"
}
