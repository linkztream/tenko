# shellcheck shell=bash
# shellcheck disable=SC2154
# The round dhcp6 of the DHCP lab (WP9.1, docs/dhcp.md section 19): the DHCPv6 server of
# one Tenko node behind a gateway that relays two dual-stack client links to it, with real
# clients (ISC dhclient -6, systemd-networkd) and a relay agent written against RFC 8415
# (scripts/relay-test6.py). smoke.sh sources this file and runs `dhcp6_round` for
# ROUNDS=dhcp6; README.md lists the rows. The round brings its own compose project
# (compose.dhcp6.yml, tenkodhcp6lab) and its own networks, sets the node up itself and
# tears down what it started.
#
# Witnesses: the clients' own results (dhclient's script writes /run/lab/events6, networkd
# writes /run/systemd/netif), the node's metrics (tenko_dhcp_packets_total{family="v6"}),
# the IPAM observations of the leases (GET /observations) and the records DDNS wrote
# (GET /dns/zones/{id}/records).

v6_project=tenkodhcp6lab
v6_compose_file="$here/compose.dhcp6.yml"
v6_node4=192.0.2.10
v6_node6=2001:db8:100::10
v6_tester4=192.0.2.20
v6_tester6=2001:db8:100::20
v6_links=(lan6 iot6)
declare -A v6_prefix4=([lan6]=192.0.2.64/26 [iot6]=192.0.2.128/26)
declare -A v6_prefix6=([lan6]=2001:db8:101::/64 [iot6]=2001:db8:102::/64)
declare -A v6_gateway4=([lan6]=192.0.2.66 [iot6]=192.0.2.130)
declare -A v6_pool4_first=([lan6]=192.0.2.94 [iot6]=192.0.2.158)
declare -A v6_pool4_last=([lan6]=192.0.2.123 [iot6]=192.0.2.187)
declare -A v6_pool6_first=([lan6]=2001:db8:101::1000 [iot6]=2001:db8:102::1000)
declare -A v6_pool6_last=([lan6]=2001:db8:101::1fff [iot6]=2001:db8:102::1fff)
declare -A v6_scope6=()
# The MAC address of client-dhclient6 (client-networkd has :62, client-iot6 :63), and the
# relay-test6 client of the correlation row.
v6_mac_dhclient=00:00:5e:00:53:61
v6_mac_rfc6939=00:00:5e:00:53:6f
# Two DUID-ENs (type 2, the documentation enterprise number 32473 = 0x7ed9 of RFC 5612, an
# identifier): the correlation row's client has no link-layer address in its DUID, so the
# MAC address comes from the relay's option 79 alone; the second is the DDNS row's client.
v6_duid_en=000200007ed90011223344556677
v6_duid_en_fqdn=000200007ed9aabbccddeeff
# The options every client gets (the server's option set).
v6_dns=2001:db8:100::53
v6_ntp=2001:db8:100::123
v6_domain=lab6.example.test
# The reservation row: the DUID-LL of client-dhclient6 gets this address, outside the pool.
v6_reserved_ip=2001:db8:101::80
# The lease times of lan6: valid 120 s, preferred 60 s, so that T1 comes after 30 s.
v6_valid_secs=120
v6_preferred_secs=60
v6_started=0
v6_work=""
declare -A v6_ip=()

c6() { docker compose -p "$v6_project" -f "$v6_compose_file" --profile networkd "$@"; }
v6_healthy() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(c6 ps -q tenko)")" == healthy ]]; }
# Both relay agents of the gateway run.
v6_relays_up() {
  [[ "$(c6 exec -T relay sh -c 'cat /proc/[0-9]*/comm | grep -c dhcrelay')" -ge 2 ]]
}

# v6_lab_setup: the first-run setup through the API under the Lab profile.
v6_lab_setup() {
  local token password setup
  token="$(c6 exec -T tenko /usr/local/bin/tenko setup token --data-dir /var/lib/tenko | tr -d '\r\n')"
  [[ -n "$token" ]] || fail "dhcp6: no setup token"
  # The Lab profile's password policy is a PIN of digits.
  password="$(od -An -N4 -tu4 /dev/urandom | tr -dc '0-9')"
  setup="{\"setup_token\": \"$token\", \"profile\": \"lab\", \"admin\": {\"name\": \"labadmin\", \"display_name\": \"Lab Admin\", \"password\": \"$password\"}, \"host_name\": \"tenko.example.test\", \"language\": \"en\"}"
  cookie="$(curl -sS -D - -o "$work/api.out" -H "Origin: $api_base" -H "Content-Type: application/json" \
    --data "$setup" "$api_base/api/v1/setup" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(tenko_session=[^;]*\).*/\1/p' | head -n 1)"
  [[ -n "$cookie" ]] || fail "dhcp6: the setup did not sign in: $(cat "$work/api.out")"
  ok "setup6" "Tenko is set up under the Lab profile"
}

# v6_configure: the server's options (DHCPv4 6, 15, 42 and DHCPv6 23, 24, 56), and per link
# an IPv4 and an IPv6 prefix with a dhcp_pool range and a scope each.
v6_configure() {
  local net id
  must "the server's options" api PUT /dhcp/option-sets/server \
    "{\"values\": [
      {\"code\": 6, \"typed\": {\"ipv4\": {\"values\": [\"192.0.2.53\"]}}},
      {\"code\": 42, \"typed\": {\"ipv4\": {\"values\": [\"192.0.2.123\"]}}},
      {\"code\": 15, \"typed\": {\"text\": \"example.test\"}},
      {\"space\": \"dhcp6\", \"code\": 23, \"typed\": {\"ipv6\": {\"values\": [\"$v6_dns\"]}}},
      {\"space\": \"dhcp6\", \"code\": 24, \"typed\": {\"names\": [\"$v6_domain\"]}},
      {\"space\": \"dhcp6\", \"code\": 56, \"typed\": {\"ipv6\": {\"values\": [\"$v6_ntp\"]}}}]}"
  for net in "${v6_links[@]}"; do
    must "the IPv4 prefix of $net" api POST /prefixes "{\"cidr\": \"${v6_prefix4[$net]}\", \"description\": \"lab link $net, IPv4\"}"
    id="$(field "d['item']['id']" <"$work/api.out")"
    must "the IPv4 pool of $net" api POST "/prefixes/$id/ranges" \
      "{\"first\": \"${v6_pool4_first[$net]}\", \"last\": \"${v6_pool4_last[$net]}\", \"role\": \"dhcp_pool\"}"
    must "the IPv4 scope of $net" api POST /dhcp/scopes \
      "{\"prefix\": \"$id\", \"lease\": {\"default_secs\": 300, \"min_secs\": 300, \"max_secs\": 600}}"
    must "option 3 of $net" api PUT "/dhcp/option-sets/scope:$id" \
      "{\"values\": [{\"code\": 3, \"typed\": {\"ipv4\": {\"values\": [\"${v6_gateway4[$net]}\"]}}}]}"
    must "the IPv6 prefix of $net" api POST /prefixes "{\"cidr\": \"${v6_prefix6[$net]}\", \"description\": \"lab link $net, IPv6\"}"
    id="$(field "d['item']['id']" <"$work/api.out")"
    v6_scope6[$net]="$id"
    must "the IPv6 pool of $net" api POST "/prefixes/$id/ranges" \
      "{\"first\": \"${v6_pool6_first[$net]}\", \"last\": \"${v6_pool6_last[$net]}\", \"role\": \"dhcp_pool\"}"
  done
  # lan6: valid 120 s and preferred 60 s, so that T1 comes after 30 s. iot6: the relay's
  # Interface-Id selects the scope.
  must "the IPv6 scope of lan6" api POST /dhcp/scopes \
    "{\"prefix\": \"${v6_scope6[lan6]}\", \"lease\": {\"default_secs\": $v6_valid_secs, \"min_secs\": $v6_valid_secs, \"max_secs\": $v6_valid_secs}, \"v6\": {\"preferred_secs\": $v6_preferred_secs, \"rapid_commit\": true}}"
  must "the IPv6 scope of iot6" api POST /dhcp/scopes \
    "{\"prefix\": \"${v6_scope6[iot6]}\", \"lease\": {\"default_secs\": 3600, \"min_secs\": 3600, \"max_secs\": 3600}, \"v6\": {\"interface_id\": \"lab-iot6\"}}"
  ok "configuration6" "two links with an IPv4 and an IPv6 prefix, a pool and a scope each, options 23, 24 and 56"
}

# ---------------------------------------------------------------------------------------
# Metrics, clients and the relay agent

# v6_packets <type> <outcome>: tenko_dhcp_packets_total{family="v6"} from the node's metrics
# (0 while the series does not exist).
v6_packets() {
  local text
  text="$(curl -sS -H "Cookie: $cookie" "$api_base/api/v1/metrics")" || return 1
  awk -v t="$1" -v o="$2" '
    index($0, "tenko_dhcp_packets_total{") == 1 && index($0, "family=\"v6\"") &&
    index($0, "type=\"" t "\"") && index($0, "outcome=\"" o "\"") { n += $NF }
    END { print n + 0 }' <<<"$text"
}

# v6_dhclient <service> [<dhclient options>]: dhclient -6 with a DUID-LL in a client; -1
# tries once (the timeout of dhclient6.conf) and goes to the background with the lease.
v6_dhclient() {
  local service="$1"
  shift
  c6 exec -T "$service" dhclient -6 -D LL -v -cf /lab/dhclient6.conf -sf /lab/client6-script.sh \
    -lf /run/lab/dhclient6.leases -pf /run/lab/dhclient6.pid "$@" eth0
}
v6_events() { c6 exec -T "$1" sh -c 'cat /run/lab/events6 2>/dev/null' | tr -d '\r'; }
v6_last() { v6_events "$1" | tail -n 1; }
# v6_fresh <service>: the client releases its lease and forgets it.
v6_fresh() {
  v6_dhclient "$1" -r >/dev/null 2>&1 || true
  c6 exec -T "$1" rm -f /run/lab/dhclient6.leases
}

# v6_in_pool <address> <first> <last>
v6_in_pool() {
  python3 - "$1" "$2" "$3" <<'PY'
import ipaddress, sys
a, f, l = (ipaddress.IPv6Address(x) for x in sys.argv[1:])
sys.exit(0 if f <= a <= l else 1)
PY
}

# t6 <relay-test6.py arguments>: the relay agent on servers6 sends to the node.
t6() {
  c6 exec -T tester python3 /lab/relay-test6.py --server "$v6_node6" --bind "$v6_tester6" "$@"
}
# t4 <relay-test.py arguments>: the DHCPv4 relay agent of the other rounds.
t4() {
  c6 exec -T tester python3 /lab/relay-test.py --server "$v6_node4" --giaddr "$v6_tester4" "$@"
}

# v6_duid_ll <mac>: the DUID-LL (type 3, hardware type 1) dhclient -D LL builds, in hex.
v6_duid_ll() { printf '00030001%s' "$(tr -d ':' <<<"$1" | tr 'A-F' 'a-f')"; }

# ---------------------------------------------------------------------------------------
# The rows

# v6_lease_ok <service> <link>: dhclient -6 got an address of the link's pool.
v6_lease_ok() {
  local service="$1" net="$2" line ip
  v6_dhclient "$service" -1 >/dev/null 2>&1 || return 1
  line="$(v6_last "$service")"
  printf '%s: %s\n' "$service" "$line" >&2
  [[ "$line" == BOUND6* || "$line" == REBOOT6* ]] || return 1
  ip="$(event_field ip6 <<<"$line")"
  v6_ip[$service]="$ip"
  v6_in_pool "$ip" "${v6_pool6_first[$net]}" "${v6_pool6_last[$net]}"
}
# v6_options_ok <service>: options 23, 24 and 56 of its lease (the script of dhclient decodes
# option 56 into addresses of eight groups).
v6_options_ok() {
  local line search ntp
  line="$(v6_last "$1")"
  search="$(event_field search <<<"$line" | tr -d '"')"
  ntp="$(event_field ntp <<<"$line")"
  [[ "$(event_field dns <<<"$line")" == "$v6_dns" ]] && [[ "${search%.}" == "$v6_domain" ]] &&
    python3 -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) == ipaddress.ip_address(sys.argv[2]) else 1)' \
      "${ntp%%,*}" "$v6_ntp"
}
v6_lease_options_ok() { v6_lease_ok "$1" "$2" && v6_options_ok "$1"; }

# The networkd client: an address of the lan6 pool on eth0, and the DNS and NTP servers in
# the link's state file.
v6_networkd_address() {
  c6 exec -T client-networkd ip -6 -o addr show dev eth0 scope global | tr -d '\r' |
    awk '{ split($4, p, "/"); print p[1]; exit }'
}
v6_networkd_state() {
  c6 exec -T client-networkd sh -c 'cat /run/systemd/netif/links/* 2>/dev/null' | tr -d '\r'
}
v6_networkd_has_address() {
  local ip
  ip="$(v6_networkd_address)"
  [[ -n "$ip" ]] && v6_in_pool "$ip" "${v6_pool6_first[lan6]}" "${v6_pool6_last[lan6]}"
}
# networkd writes the link's state file a moment after the address.
v6_networkd_state_ok() {
  local state
  state="$(v6_networkd_state)"
  grep -q "^DNS=.*$v6_dns" <<<"$state" && grep -q "^NTP=.*$v6_ntp" <<<"$state"
}
v6_networkd_ok() {
  within 40 v6_networkd_has_address || return 1
  within 20 v6_networkd_state_ok
  printf 'networkd: %s\n%s\n' "$(v6_networkd_address)" "$(v6_networkd_state)" >&2
  v6_networkd_state_ok
}
# The counters before networkd starts: its SOLICIT carries Rapid Commit, so the node
# counts a SOLICIT answered and no REQUEST at all.
v6_networkd_start() {
  v6_solicit0="$(v6_packets solicit answered)"
  v6_request0="$(v6_packets request answered)"
  c6 up -d client-networkd >/dev/null 2>&1
}
v6_rapid_commit_ok() {
  local solicit1 request1 out
  solicit1="$(v6_packets solicit answered)"
  request1="$(v6_packets request answered)"
  printf 'solicit answered %s -> %s, request answered %s -> %s\n' \
    "$v6_solicit0" "$solicit1" "$v6_request0" "$request1" >&2
  ((solicit1 > v6_solicit0)) && ((request1 == v6_request0)) || return 1
  out="$(t6 --link 2001:db8:101::1 --rapid-commit --expect "${v6_prefix6[lan6]}")" || {
    printf '%s\n' "$out" >&2
    return 1
  }
  printf '%s\n' "$out" >&2
  grep -q '^reply .*depth=1' <<<"$out"
}

# v6_renewed <service>: a RENEW6 event with the address of the first binding.
v6_renewed() { v6_events "$1" | grep -q "^RENEW6 ip6=${v6_ip[$1]} "; }

v6_interface_id_ok() {
  local out
  # The outer relay's link address is on servers6, which has no scope: only the
  # Interface-Id of the inner (lightweight) relay selects the iot6 scope.
  out="$(t6 --two-deep --interface-id lab-iot6 --link "$v6_tester6" --expect "${v6_prefix6[iot6]}")" || {
    printf '%s\n' "$out" >&2
    return 1
  }
  printf '%s\n' "$out" >&2
  grep -q '^advertise .*depth=2 iid=ok' <<<"$out" && grep -q '^reply .*depth=2 iid=ok' <<<"$out"
}

v6_reserved_ok() {
  v6_dhclient client-dhclient6 -1 >/dev/null 2>&1 || return 1
  [[ "$(v6_last client-dhclient6 | event_field ip6)" == "$v6_reserved_ip" ]]
}

# v6_observed <mac> <address>...: the observations of the MAC list every address, each from
# a source dhcp:<node> (the facts of the DHCPv4 and the DHCPv6 lease).
v6_observed() {
  local mac="$1"
  shift
  api GET "/observations?mac=$mac&type=address&limit=200" >/dev/null || return 1
  python3 - "$work/api.out" "$@" <<'PY'
import ipaddress, json, sys
d = json.load(open(sys.argv[1]))
want = {ipaddress.ip_address(a) for a in sys.argv[2:]}
got = {}
for fact in d["items"]:
    observed = fact["observed"]
    if observed.get("type") != "address":
        continue
    got[ipaddress.ip_address(observed["data"]["ip"])] = fact["source_key"]
print({str(a): s for a, s in got.items()}, file=sys.stderr)
sys.exit(0 if all(got.get(a, "").startswith("dhcp:") for a in want) else 1)
PY
}

v6_correlation_duid_ok() {
  local ip4 ip6 line
  c6 exec -T client-dhclient6 dhclient -4 -v -cf /lab/dhclient.conf -sf /lab/client-script.sh \
    -lf /run/lab/dhclient.leases -pf /run/lab/dhclient.pid -1 eth0 >/dev/null 2>&1 || return 1
  line="$(c6 exec -T client-dhclient6 sh -c 'tail -n 1 /run/lab/events 2>/dev/null' | tr -d '\r')"
  printf 'dhclient -4: %s\n' "$line" >&2
  ip4="$(event_field ip <<<"$line")"
  ip6="$(v6_last client-dhclient6 | event_field ip6)"
  [[ -n "$ip4" && -n "$ip6" ]] && within 15 v6_observed "$v6_mac_dhclient" "$ip4" "$ip6"
}

v6_correlation_rfc6939_ok() {
  local out4 out6 ip4 ip6
  out6="$(t6 --link 2001:db8:101::1 --mac "$v6_mac_rfc6939" --duid "$v6_duid_en" --expect "${v6_prefix6[lan6]}")" || {
    printf '%s\n' "$out6" >&2
    return 1
  }
  out4="$(t4 --mac "$v6_mac_rfc6939" --link 192.0.2.64 --expect "${v6_prefix4[lan6]}")" || {
    printf '%s\n' "$out4" >&2
    return 1
  }
  printf '%s\n%s\n' "$out6" "$out4" >&2
  ip6="$(sed -n 's/^address //p' <<<"$out6")"
  ip4="$(sed -n 's/^ack \([0-9.]*\) .*/\1/p' <<<"$out4")"
  [[ -n "$ip4" && -n "$ip6" ]] && within 15 v6_observed "$v6_mac_rfc6939" "$ip4" "$ip6"
}

# The DDNS rows: a forward zone and the reverse zone of the lan6 prefix, DDNS on for the
# lan6 scope with the forward zone named.
v6_zone_create() {
  must "the zone $1" api POST /dns/zones \
    "{\"name\": \"$1\", \"kind\": \"primary\", \"serial\": \"counter\", \"soa\": {\"mname\": \"ns.example.test\", \"rname\": \"hostmaster.example.test\", \"refresh\": 60, \"retry\": 10, \"expire\": 3600, \"minimum\": 5, \"ttl\": 60}, \"name_servers\": [\"ns.example.test\"]}"
  field "d['id']" <"$work/api.out"
}
# v6_zone_has <zone id> <name> <type> [<address or target>]: an RRset of origin dhcp. The
# API shows a DHCID record as the unknown type TYPE49 with its data in hex; the DHCID type
# asks for identifier type 2 (the DUID, RFC 4701 section 3.3) and digest type 1 (SHA-256),
# the octets 00 02 01.
v6_zone_has() {
  api GET "/dns/zones/$1/records?limit=1000" >/dev/null || return 1
  python3 - "$work/api.out" "$2" "$3" "${4:-}" <<'PY'
import ipaddress, json, sys
d = json.load(open(sys.argv[1]))
name, rtype, want = sys.argv[2:5]
dhcid = rtype == "DHCID"
if dhcid:
    rtype = "TYPE49"
for rrset in d["items"]:
    if rrset["name"].rstrip(".") != name or rrset["type"] != rtype or rrset["origin"] != "dhcp":
        continue
    for record in rrset["records"]:
        if dhcid:
            if record.get("data", "").startswith("000201"):
                sys.exit(0)
        elif "address" in record and ipaddress.ip_address(record["address"]) == ipaddress.ip_address(want):
            sys.exit(0)
        elif "target" in record and record["target"].rstrip(".") == want:
            sys.exit(0)
sys.exit(1)
PY
}
v6_zone_lacks() { ! v6_zone_has "$@" 2>/dev/null; }
# v6_zone_dump <zone id>: the RRsets of a zone, for the log of a failed row.
v6_zone_dump() {
  api GET "/dns/zones/$1/records?limit=1000" >/dev/null || return 0
  python3 - "$work/api.out" <<'PY' >&2
import json, sys
for rrset in json.load(open(sys.argv[1]))["items"]:
    print(rrset["origin"], rrset["name"], rrset["type"], json.dumps(rrset["records"]))
PY
}

v6_fqdn_ok() {
  local out ip6
  out="$(t6 --fqdn host6 --link 2001:db8:101::1 --duid "$v6_duid_en_fqdn" --expect "${v6_prefix6[lan6]}")" || {
    printf '%s\n' "$out" >&2
    return 1
  }
  printf '%s\n' "$out" >&2
  ip6="$(sed -n 's/^address //p' <<<"$out")"
  v6_fqdn_ip="$ip6"
  v6_reverse="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_address(sys.argv[1]).reverse_pointer)' "$ip6")"
  within 15 v6_zone_has "$v6_zone_fwd" host6.example.test AAAA "$ip6" &&
    within 15 v6_zone_has "$v6_zone_fwd" host6.example.test DHCID &&
    within 15 v6_zone_has "$v6_zone_rev" "$v6_reverse" PTR host6.example.test && return 0
  printf 'the forward zone:\n' >&2
  v6_zone_dump "$v6_zone_fwd"
  printf 'the reverse zone:\n' >&2
  v6_zone_dump "$v6_zone_rev"
  return 1
}

v6_release_after() {
  local after
  after="$(v6_packets release answered)"
  printf 'release answered %s -> %s\n' "$1" "$after" >&2
  ((after > $1))
}
v6_release_counted() {
  local before
  before="$(v6_packets release answered)"
  v6_dhclient client-dhclient6 -r >/dev/null 2>&1 || true
  within 10 v6_release_after "$before"
}
v6_fqdn_released_ok() {
  local out
  out="$(t6 --fqdn host6 --link 2001:db8:101::1 --duid "$v6_duid_en_fqdn" --expect "${v6_prefix6[lan6]}" --release)" || {
    printf '%s\n' "$out" >&2
    return 1
  }
  printf '%s\n' "$out" >&2
  grep -q "^release $v6_fqdn_ip status=0" <<<"$out" &&
    within 15 v6_zone_lacks "$v6_zone_fwd" host6.example.test AAAA &&
    within 15 v6_zone_lacks "$v6_zone_rev" "$v6_reverse" PTR
}

v6_rows() {
  local host iface
  step "dhcp6: leases through the relay"
  row "v6.lease.dhclient" "dhclient -6 on lan6 gets an address of ${v6_pool6_first[lan6]}-${v6_pool6_last[lan6]} through dhcrelay, with options 23, 24 and 56" \
    v6_lease_options_ok client-dhclient6 lan6
  row "v6.lease.iot" "dhclient -6 on iot6 gets an address of the iot6 pool: the relay's link address selects the scope" \
    v6_lease_ok client-iot6 iot6

  step "dhcp6: systemd-networkd (Rapid Commit)"
  v6_networkd_start
  row "v6.lease.networkd" "systemd-networkd on lan6 gets an address of the pool, with the DNS server $v6_dns and the NTP server $v6_ntp (option 56)" \
    v6_networkd_ok
  row "v6.rapid-commit" "networkd's SOLICIT is answered with a committed REPLY (no REQUEST), and so is relay-test6 --rapid-commit" \
    v6_rapid_commit_ok

  step "dhcp6: renewal, Interface-Id, reservation"
  row "v6.renew" "dhclient renews at T1 (preferred ${v6_preferred_secs} s, T1 half of it) and keeps its address" \
    within 90 v6_renewed client-dhclient6
  row "v6.interface-id" "relay-test6 two deep (outer link address on servers6, Interface-Id lab-iot6) gets an iot6 address, the Interface-Id echoed" \
    v6_interface_id_ok

  must "the reserved host" api POST /hosts \
    "{\"name\": \"lab6-reserved\", \"mode\": \"reserved\", \"interfaces\": [{\"name\": \"eth0\", \"duid\": \"$(v6_duid_ll "$v6_mac_dhclient")\"}]}"
  host="$(field "d['item']['id']" <"$work/api.out")"
  must "the reserved host's interface" api GET "/hosts/$host/interfaces"
  iface="$(field "d['items'][0]['id']" <"$work/api.out")"
  must "the reserved address" api POST /addresses "{\"ip\": \"$v6_reserved_ip\", \"interface\": \"$iface\"}"
  v6_fresh client-dhclient6
  row "v6.reservation" "a reservation by DUID wins: after a release dhclient -6 gets $v6_reserved_ip" \
    within 30 v6_reserved_ok
  v6_ip[client-dhclient6]="$v6_reserved_ip"

  step "dhcp6: correlation with the DHCPv4 lease of the same device"
  row "v6.correlation.duid" "client-dhclient6's DHCPv4 and DHCPv6 leases are both IPAM facts of its MAC address (its DUID-LL carries it)" \
    v6_correlation_duid_ok
  row "v6.correlation.rfc6939" "relay-test6 --mac $v6_mac_rfc6939 (DUID-EN) and relay-test the same MAC: both addresses are IPAM facts of the MAC" \
    v6_correlation_rfc6939_ok

  step "dhcp6: DDNS for a client with option 39"
  v6_zone_fwd="$(v6_zone_create example.test)"
  v6_zone_rev="$(v6_zone_create 0.0.0.0.1.0.1.0.8.b.d.0.1.0.0.2.ip6.arpa)"
  must "DDNS on the lan6 scope" api PATCH "/dhcp/scopes/${v6_scope6[lan6]}" \
    "{\"ddns\": {\"enabled\": true, \"forward_zone\": \"$v6_zone_fwd\", \"reverse\": true}}"
  row "v6.fqdn" "option 39 host6: host6.example.test AAAA, DHCID and the PTR in ip6.arpa, all of origin dhcp" \
    v6_fqdn_ok

  step "dhcp6: release"
  row "v6.release" "dhclient -6 -r on lan6: the node counts a RELEASE answered; relay-test6 --release removes the AAAA and the PTR of host6" \
    v6_release_all
}
v6_release_all() { v6_release_counted && v6_fqdn_released_ok; }

# ---------------------------------------------------------------------------------------
# The round

v6_logs() {
  local service
  printf '\n==> FAILED: logs of the round dhcp6\n' >&2
  for service in relay netns tenko tester client-dhclient6 client-networkd client-iot6; do
    printf '\n--- %s ---\n' "$service" >&2
    c6 logs --no-color --tail 200 "$service" >&2 2>&1
  done
  for service in client-dhclient6 client-iot6 client-networkd; do
    printf '\n--- %s: /run/lab ---\n' "$service" >&2
    c6 exec -T "$service" sh -c 'tail -n 20 /run/lab/events6 /run/lab/events 2>&1; ls /run/lab /run/systemd/netif/links 2>&1' >&2 2>&1
  done
  docker ps -a --filter "label=com.docker.compose.project=$v6_project" >&2 2>&1
}

v6_keep_hint() {
  printf '\n==> KEEP=1: the round dhcp6 keeps running; for example\n'
  printf '    LAB_DIR=%s docker compose -p %s -f %s --profile networkd exec client-dhclient6 dhclient -6 -D LL -v -1 -cf /lab/dhclient6.conf -sf /lab/client6-script.sh eth0\n' \
    "$v6_work" "$v6_project" "$v6_compose_file"
  printf 'tear it down with: LAB_DIR=%s docker compose -p %s -f %s --profile networkd down --volumes\n' \
    "$v6_work" "$v6_project" "$v6_compose_file"
}

v6_teardown() {
  ((v6_started)) || return 0
  c6 down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1
  v6_started=0
  if [[ -n "$v6_work" ]]; then
    rm -rf "$v6_work"
    v6_work=""
  fi
}

dhcp6_round() {
  step "the round dhcp6: DHCPv6 through dhcrelay to one node"
  if ((build_networkd)); then
    step "build the networkd image $NETWORKD_IMAGE"
    docker build -f "$here/networkd.Dockerfile" -t "$NETWORKD_IMAGE" "$here"
  fi
  docker image inspect "$NETWORKD_IMAGE" >/dev/null 2>&1 || fail "image $NETWORKD_IMAGE not found"
  ok "networkd" "$NETWORKD_IMAGE (systemd-networkd as a DHCPv6 client)"
  if ((build_tenko)); then
    step "build $TENKO_IMAGE from deploy/Dockerfile (the static musl binary)"
    docker build -f "$repo/deploy/Dockerfile" -t "$TENKO_IMAGE" "$repo"
  else
    docker image inspect "$TENKO_IMAGE" >/dev/null 2>&1 || fail "image $TENKO_IMAGE not found"
  fi
  ok "image" "$TENKO_IMAGE"

  v6_work="$(mktemp -d)"
  work="$v6_work"
  export LAB_DIR="$work"
  mkdir -p "$work/secrets"
  head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/kek"
  chmod 0444 "$work/secrets/kek"
  cat >"$work/tenko.toml" <<TOML
# The node of the round dhcp6 (written by smoke.sh).
roles = "controller,dhcp"
# DDNS needs the DNS module next to the DHCP module (the node serves no DNS here).
modules = ["ipam", "dns", "dhcp"]

[profile]
# The Lab profile: plain HTTP is allowed.
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["0.0.0.0:8443"]

[dhcp]
# Relay mode on both addresses of the node: the relay sends DHCPv4 to port 67 and DHCPv6
# to port 547.
listen = [{ address = "$v6_node4", mode = "relay" }, { address = "$v6_node6", mode = "relay" }]
workers = 2
TOML
  chmod 0444 "$work/tenko.toml"
  chmod 0755 "$work"
  api_base="http://$v6_node4:8443"
  cookie=""
  c6 config --quiet
  # A lab left over from an interrupted run goes first.
  c6 down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true

  step "start the gateway, the node and the clients"
  v6_started=1
  c6 up -d relay netns tenko client-dhclient6 client-iot6 tester
  retry "$wait_secs" "tenko to become healthy" v6_healthy
  v6_lab_setup
  v6_configure
  # The gateway starts dhcrelay -4 and dhcrelay -6.
  retry 60 "dhcrelay -4 and -6 to start" v6_relays_up
  ok "lab6" "gateway, node, two dhclient clients and the tester are up (networkd starts with its row)"

  v6_rows

  # A failed row prints the logs before the lab goes.
  ((rows_failed == 0)) || v6_logs
  if [[ "$keep" == 1 ]]; then
    v6_keep_hint
    v6_started=0
    v6_work=""
  else
    step "tear down the round dhcp6"
    v6_teardown
  fi
  work=""
  cookie=""
  api_base="http://$node_ip:8443"
}
