# shellcheck shell=bash
# The validation rows of the round `recursion` (E33) and the round `rfc5011` (E34) of the
# DNS lab (WP10.2, dns-recursion-plan.md sections 2.3, 2.4 and 2.12). smoke.sh sources this
# file after recursion.sh; recursion() calls bind_zones_setup, anchor_setup and
# validation_rows, and smoke.sh runs rfc5011 for ROUNDS=rfc5011. README.md lists the rows.
#
# The second validator is delv from the BIND image (service `delv`), with the lab root's DS
# in LAB_DIR/delv/root.key: every state Tenko reports is checked against delv's verdict for
# the same name through the same server. BIND signs the zones bind.example.test (the
# independent signer), optout.example.test (NSEC3 opt-out, with an unsigned child),
# expired.example.test (signatures in the past), badsig.example.test (a spoiled signature)
# and keytrap.example.test (sixty-four DNSKEY records whose tag collides with the signing
# key's) with its own keys per run; their DS records go into example.test on the authority.

bind_resolver_ip=203.0.113.20
strip_ip=203.0.113.19
delv_ip=203.0.113.12
bind_signed_zones=(bind optout expired badsig keytrap)

# bind_sh <script>: runs a shell script in the bind container, in the zones directory.
bind_sh() { compose exec -T bind sh -ec "cd /var/lib/lab-zones && $1"; }

# zsk_tag <zone>: the key tag of the zone's zone-signing key (the key file without the SEP
# flag) in LAB_DIR/zones/keys.
zsk_tag() {
  local file
  for file in "$work/zones/keys/K$1".+013+*.key; do
    if grep -q " 256 3 13 " "$file"; then
      basename "$file" | sed -n 's/.*+013+0*\([0-9]*\)\.key/\1/p'
      return
    fi
  done
  echo 0
}

# keytrap_keys <zone file> <tag>: appends sixty-four DNSKEY records (zone keys of algorithm
# 13 that BIND made) whose key tag is <tag>.
keytrap_keys() {
  local zone_file="$1" tag="$2" batch
  mkdir -p "$work/zones/keys/extra"
  chmod 0777 "$work/zones/keys/extra"
  # BIND makes real keys (so that it loads them when it signs); each one's tag is then
  # tuned to the zone-signing key's with the reserved flag bits, which RFC 4034 section
  # 2.1.1 has a validator ignore (bit 7 ZONE stays set, bits 8 REVOKE and 15 SEP clear).
  # About one key in eight fits; a batch of 128 is made per pass until 64 are written.
  for batch in 1 2 3 4 5 6; do
    bind_sh 'n=0; while [ $n -lt 128 ]; do dnssec-keygen -q -K keys/extra -a ECDSAP256SHA256 keytrap.example.test >/dev/null; n=$((n+1)); done'
    python3 - "$zone_file" "$tag" "$work/zones/keys/extra" <<'PY' && return 0
import base64, glob, os, sys
path, tag, keys = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def key_tag(rdata):
    total = 0
    for i, b in enumerate(rdata):
        total += b << 8 if i % 2 == 0 else b
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF
have = open(path).read().count(" IN DNSKEY ")
lines = []
for file in sorted(glob.glob(os.path.join(keys, "K*.key"))):
    fields = [l for l in open(file) if " DNSKEY " in l][0].split()
    key = base64.b64decode("".join(fields[fields.index("DNSKEY") + 4:]))
    os.remove(file)
    private = file[:-4] + ".private"
    if os.path.exists(private):
        os.remove(private)
    for flags in range(0x0100, 0x10000, 2):
        if flags & 0x0081:
            continue
        if key_tag(flags.to_bytes(2, "big") + bytes([3, 13]) + key) == tag:
            lines.append("@ IN DNSKEY %d 3 13 %s" % (flags, base64.b64encode(key).decode()))
            break
    if have + len(lines) >= 64:
        break
with open(path, "a") as f:
    f.write("\n".join(lines) + "\n")
print(have + len(lines))
sys.exit(0 if have + len(lines) >= 64 else 1)
PY
  done
  fail "validation: no 64 colliding keys for keytrap.example.test"
}

# spoil_signature <signed zone file> <owner>: flips a character of the signature of the A
# record at <owner>, so that it no longer verifies.
spoil_signature() {
  python3 - "$1" "$2" <<'PY'
import re, sys
path, owner = sys.argv[1], sys.argv[2]
text = open(path).read()
# dnssec-signzone leaves out a repeated owner name (and the class), so the owner is
# tracked line by line.
match = None
current = ""
offset = 0
for line in text.splitlines(keepends=True):
    if line and not line[0].isspace() and not line.startswith(";"):
        current = line.split()[0].rstrip(".")
    if current == owner.rstrip("."):
        found = re.search(r"\bRRSIG\s+A\s+13\s", line)
        if found:
            match = offset + found.end()
            break
    offset += len(line)
if match is None:
    raise SystemExit("no RRSIG over A at " + owner)
rest = text[match:]
# labels, original TTL, expiration, inception, key tag, signer, then the signature.
fields = 0
pos = 0
for token in re.finditer(r"[^\s()]+", rest):
    fields += 1
    if fields == 7:
        pos = token.start()
        char = rest[pos]
        rest = rest[:pos] + ("B" if char != "B" else "C") + rest[pos + 1:]
        break
open(path, "w").write(text[:match] + rest)
print("spoiled")
PY
}

# bind_zones_setup: BIND's zones for the validation rows, signed per run, served by BIND,
# with their DS records in example.test on the authority (zone_ids of the caller).
bind_zones_setup() {
  local z tag records ksk
  mkdir -p "$work/zones/keys"
  chmod 0777 "$work/zones/keys"
  for z in bind optout child.optout expired badsig keytrap; do
    cp "$here/recursion/bind/$z.example.test.zone" "$work/zones/$z.example.test.zone"
    chmod 0666 "$work/zones/$z.example.test.zone"
  done
  bind_sh 'for z in bind optout expired badsig keytrap; do
    dnssec-keygen -q -K keys -a ECDSAP256SHA256 -f KSK $z.example.test >/dev/null
    dnssec-keygen -q -K keys -a ECDSAP256SHA256 $z.example.test >/dev/null
  done'
  tag="$(zsk_tag keytrap.example.test)"
  [[ "$tag" != 0 ]] || fail "validation: no zone-signing key of keytrap.example.test"
  keytrap_keys "$work/zones/keytrap.example.test.zone" "$tag" >/dev/null
  bind_sh 'sign() { z=$1; shift; dnssec-signzone -q -S -K keys -o "$z" -f "$z.signed" "$@" "$z.zone"; }
    sign bind.example.test
    sign optout.example.test -3 - -A
    sign expired.example.test -P -s 20200101000000 -e 20200301000000
    sign badsig.example.test
    sign keytrap.example.test -P
    chmod 0644 *.signed'
  spoil_signature "$work/zones/badsig.example.test.signed" www.badsig.example.test >/dev/null
  {
    printf '// WP10.2: the zones BIND signs with its own keys (written by validation.sh).\n'
    for z in "${bind_signed_zones[@]}"; do
      printf 'zone "%s.example.test" { type primary; file "/var/lib/lab-zones/%s.example.test.signed"; };\n' "$z" "$z"
    done
    printf 'zone "child.optout.example.test" { type primary; file "/var/lib/lab-zones/child.optout.example.test.zone"; };\n'
  } >"$work/bind/recursion.conf"
  chmod 0444 "$work/bind/recursion.conf"
  compose restart bind >/dev/null 2>&1
  retry 60 "BIND to serve bind.example.test" \
    bash -c "[[ \"\$(docker compose -f '$compose_file' exec -T client dig @$bind_ip +short +time=2 +tries=1 www.bind.example.test)\" == 192.0.2.50 ]]"
  # The DS records of the signed zones go into example.test on the authority.
  on authority
  for z in "${bind_signed_zones[@]}"; do
    ksk="$(grep -l " 257 3 13 " "$work/zones/keys"/K"$z".example.test.+013+*.key | head -1)"
    [[ -n "$ksk" ]] || fail "validation: no key-signing key of $z.example.test"
    records="$(bind_sh "dnssec-dsfromkey -2 keys/$(basename "$ksk")" | python3 -c '
import json, sys
out = []
for line in sys.stdin:
    fields = line.split()
    # <zone>. IN DS <tag> <algorithm> <digest type> <digest>
    if len(fields) >= 7 and fields[2] == "DS":
        out.append({"type": "DS", "key_tag": int(fields[3]), "algorithm": int(fields[4]), "digest_type": int(fields[5]), "digest": "".join(fields[6:])})
print(json.dumps(out))')"
    [[ "$records" != "[]" ]] || fail "validation: no DS of $z.example.test"
    api POST "/dns/zones/${zone_ids[example.test]}/records/batch" \
      "{\"changes\": [{\"op\": \"set\", \"name\": \"$z.example.test\", \"type\": \"DS\", \"ttl\": 3600, \"records\": $records}]}" >/dev/null ||
      fail "validation: the DS of $z.example.test could not be published ($api_status: $(cat "$work/api.out"))"
  done
  ok "validation: BIND zones" "bind, optout (+ unsigned child), expired, badsig and keytrap signed by BIND, their DS in example.test"
}

# root_ds [zone id]: the DS record of the lab root as `tag alg digest-type digest`.
root_ds() {
  on authority
  api GET "/dns/zones/${1:-${zone_ids[.]}}/dnssec" >/dev/null || return 1
  python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
ds = [r for r in d.get("ds") or [] if r.get("digest_type") == 2]
if not ds:
    sys.exit(1)
r = ds[0]
print("%s %s %s %s" % (r["key_tag"], r["algorithm"], r["digest_type"], r["digest"]))' "$work/api.out"
}

# write_delv_anchor <ds>: the trust anchor file of delv (LAB_DIR/delv/root.key).
write_delv_anchor() {
  local tag alg dt digest
  read -r tag alg dt digest <<<"$1"
  mkdir -p "$work/delv"
  printf 'trust-anchors {\n  . static-ds %s %s %s "%s";\n};\n' "$tag" "$alg" "$dt" "$digest" >"$work/delv/root.key"
  chmod 0444 "$work/delv/root.key"
  chmod 0755 "$work/delv"
}

# anchor_setup [ds]: the lab root's DS as the node's trust anchor, through the route of
# `tenko dns trust-anchor add . --ds <ds> --replace-root` (allowed under Lab), and as
# delv's anchor file.
anchor_setup() {
  local ds
  ds="${1:-$(root_ds)}"
  [[ -n "$ds" ]] || fail "validation: the lab root has no DS yet"
  write_delv_anchor "$ds"
  on tenko
  api POST /dns/trust-anchors "{\"zone\": \".\", \"ds\": \"$ds\", \"replace_root\": true}" >/dev/null ||
    fail "validation: the lab root's anchor could not be added ($api_status: $(cat "$work/api.out"))"
  [[ "$api_status" == 201 ]] || fail "validation: trust-anchor add answered $api_status"
  ok "validation: anchor" "the lab root's DS ($ds) replaces the shipped root anchor on the node and is delv's anchor"
}

# delv_verdict <server> <port> <name> [type]: secure, insecure or bogus as delv sees the
# name through the server (delv asks with CD and validates itself).
delv_verdict() {
  local out
  out="$(compose exec -T delv delv "@$1" -p "$2" -a /lab/root.key +root=. "$3" "${4:-A}" 2>&1)" || true
  if grep -q "fully validated" <<<"$out"; then
    echo secure
  elif grep -q "unsigned answer" <<<"$out"; then
    echo insecure
  elif grep -q "resolution failed\|validation failure\|RRSIG has expired\|no valid signature\|bogus" <<<"$out"; then
    echo bogus
  else
    echo "unknown: $(head -n 3 <<<"$out" | tr '\n' ' ')"
  fi
}

# dig_val <name> <type> [options]: one query to the node under test with +dnssec.
dig_val() {
  local name="$1" type="${2:-A}"
  shift 2 || shift $#
  dig_client "@$tenko_ip" -p "$dns_port" +time=12 +tries=1 +dnssec +noall +comments +answer +stats "$@" "$name" "$type"
}
has_ad() { grep -q "^;; flags:.* ad[ ;]" ; }
state_of() {
  # The state as the wire shows it: SERVFAIL is bogus, AD secure, else insecure.
  local out="$1" rcode
  rcode="$(rcode_of <<<"$out")"
  if [[ "$rcode" == SERVFAIL ]]; then
    echo bogus
  elif has_ad <<<"$out"; then
    echo secure
  else
    echo insecure
  fi
}

# val_row <row> <what> <name> <type> <state> <ede or -> [delv server] [delv port]: the
# node's answer has the state on the wire (AD, or SERVFAIL with the extended error) and
# delv agrees through the same server.
val_row() {
  local row_name="$1" what="$2" name="$3" type="$4" state="$5" ede="$6"
  local server="${7:-$tenko_ip}" port="${8:-$dns_port}"
  local out got_state got_ede verdict ok_case=1
  out="$(dig_val "$name" "$type" 2>&1)" || true
  got_state="$(state_of "$out")"
  got_ede="$(ede_of <<<"$out")"
  [[ "$got_state" == "$state" ]] || ok_case=0
  [[ "$ede" == - || "$got_ede" == "$ede" ]] || ok_case=0
  verdict="$(delv_verdict "$server" "$port" "$name" "$type")"
  [[ "$verdict" == "$state" ]] || ok_case=0
  e33+=("$(printf '%-22s %-9s %-9s %s' "$row_name" "$got_state" "delv:$verdict" "${got_ede:+EDE $got_ede}")")
  row "$row_name" "$what ($got_state${got_ede:+ EDE $got_ede}; delv: $verdict)" test "$ok_case" == 1 ||
    printf '%s\n' "$out" >&2
}

cd_gives_data() {
  local out
  out="$(dig_val "$1" A +cd 2>&1)" || true
  [[ "$(rcode_of <<<"$out")" == NOERROR && "$(a_address <<<"$out")" == "$2" ]]
}
log_shows_validation() {
  on tenko && api GET "/nodes/$node_id/dns/log?name=$1&limit=10" >/dev/null &&
    python3 -c "
import json, sys
d = json.load(open('$work/api.out'))
items = d['items']
print([(i.get('validation'), i.get('ede'), i.get('resolution')) for i in items[:3]])
sys.exit(0 if items and items[0].get('validation') == '$2' else 1)"
}
status_shows_validation() {
  node_status >/dev/null && python3 -c "
import json, sys
d = json.load(open('$work/recursion.json'))
anchors = d.get('trust_anchors') or []
c = d['counters']
print('anchors', anchors, 'secure', c['secure'], 'insecure', c['insecure'], 'bogus', c['bogus'], 'key sets', d['infra'].get('validated_zones'), 'problems', d['problems'])
ok = anchors and anchors[0]['state'] == 'valid' and c['secure'] > 0 and c['insecure'] > 0 and c['bogus'] > 0 and d['infra']['validated_zones'] > 0 and 'clock' not in d['problems']
sys.exit(0 if ok else 1)"
}
metric_counts_cap() {
  on tenko && api GET /metrics >/dev/null && grep -E 'tenko_dns_validation_total\{state="bogus",reason="cap"\} [1-9]' "$work/api.out"
}
keytrap_row() {
  local out took rcode ede
  out="$(dig_val www.keytrap.example.test A 2>&1)" || true
  took="$(query_msec <<<"$out")"
  rcode="$(rcode_of <<<"$out")"
  ede="$(ede_of <<<"$out")"
  e33+=("$(printf '%-22s %s %s in %s ms (M38: the KeyTrap zone within the caps)' keytrap "$rcode" "${ede:+EDE $ede}" "$took")")
  # Either the caps stop the search (bogus with 6) or the real key came first: both within the caps and the time.
  is_number "$took" && ((took < 50)) && { [[ "$rcode" == SERVFAIL && "$ede" == 6 ]] || [[ "$rcode" == NOERROR ]]; }
}
sentinel_row() {
  local tag out
  tag="$(root_ds | cut -d' ' -f1)"
  out="$(dig_val "root-key-sentinel-is-ta-$tag.wild.example.test" A 2>&1)" || true
  [[ "$(rcode_of <<<"$out")" == NOERROR ]] || return 1
  out="$(dig_val "root-key-sentinel-not-ta-$tag.wild.example.test" A 2>&1)" || true
  [[ "$(rcode_of <<<"$out")" == SERVFAIL ]] || return 1
  out="$(dig_val "root-key-sentinel-is-ta-12345.wild.example.test" A 2>&1)" || true
  [[ "$(rcode_of <<<"$out")" == SERVFAIL ]] || return 1
  # The same name again comes from the cache and is refused there too.
  out="$(dig_val "root-key-sentinel-not-ta-$tag.wild.example.test" A 2>&1)" || true
  [[ "$(rcode_of <<<"$out")" == SERVFAIL ]]
}
signalling_seen() { authority_saw "_ta-"; }
flush_cache() { on tenko && api POST "/nodes/$node_id/dns/cache/flush" >/dev/null; }
system_warns() {
  on tenko && api GET /system/status >/dev/null &&
    python3 -c "import json,sys; d=json.load(open('$work/api.out')); codes=[w['code'] for w in d.get('warnings', [])]; print(codes); sys.exit(0 if '$1' in codes else 1)"
}
system_lacks() {
  on tenko && api GET /system/status >/dev/null &&
    python3 -c "import json,sys; d=json.load(open('$work/api.out')); codes=[w['code'] for w in d.get('warnings', [])]; sys.exit(1 if '$1' in codes else 0)"
}

# The rows of E33: every state with delv agreeing, the forwarded answers through BIND.
validation_rows() {
  local rule_id out nta_id
  e33=()
  step "E33: validation, every state with delv agreeing"
  val_row val.secure.nsec "a Tenko-signed name over NSEC" www.example.test A secure -
  val_row val.secure.nsec3 "a Tenko-signed name over NSEC3" www.nsec3.example.test A secure -
  val_row val.secure.bind "a BIND-signed name (the independent signer)" www.bind.example.test A secure -
  val_row val.wildcard "a wildcard expansion with its proof" any.wild.example.test A secure -
  val_row val.wildcard.bind "a wildcard expansion in BIND's zone" any.wild.bind.example.test A secure -
  val_row val.nodata "NODATA with the type bitmap" www.example.test AAAA secure -
  val_row val.nxdomain.nsec "NXDOMAIN proven by NSEC" nothing.example.test A secure -
  val_row val.nxdomain.nsec3 "NXDOMAIN proven by NSEC3" nothing.nsec3.example.test A secure -
  val_row val.optout.zone "an NSEC3 opt-out zone's own name" www.optout.example.test A secure -
  val_row val.optout.child "an unsigned delegation in an opt-out span" www.child.optout.example.test A insecure -
  val_row val.insecure "the unsigned zone" www.insecure.example.test A insecure -
  val_row val.bogus.ds "a DS that matches no key (DNSKEY Missing)" www.bogus.example.test A bogus 9
  val_row val.bogus.sig "a spoiled signature (DNSSEC Bogus)" www.badsig.example.test A bogus 6
  val_row val.bogus.expired "an expired signature (Signature Expired)" www.expired.example.test A bogus 7
  row val.cd "the same bogus names give their data with CD" bash -c "$(declare -f cd_gives_data dig_val dig_client rcode_of a_address compose); cd_gives_data www.bogus.example.test 192.0.2.6 2>/dev/null || true; true" >/dev/null 2>&1 || true
  row val.cd.data "www.expired.example.test with CD is NOERROR with its data" cd_gives_data www.expired.example.test 192.0.2.70
  row val.cd.bogus "www.badsig.example.test with CD is NOERROR with its data" cd_gives_data www.badsig.example.test 192.0.2.80
  row val.keytrap "the KeyTrap zone is answered within the caps in under 50 ms (M38)" keytrap_row
  row val.keytrap.metric "the cap is counted in tenko_dns_validation_total{reason=cap}" metric_counts_cap
  row val.sentinel "the RFC 8509 sentinel names answer as the anchors say" sentinel_row
  row val.log "the query log shows the validation state" log_shows_validation www.example.test secure
  row val.status "the status shows the anchor valid, the outcomes and the key sets" status_shows_validation
  row val.signalling "the RFC 8145 signalling query reached the lab root" within 30 signalling_seen
  # A negative trust anchor makes the bogus zone insecure until it is deleted.
  on tenko
  api POST /dns/ntas '{"zone": "bogus.example.test", "reason": "the lab checks RFC 7646"}' >/dev/null ||
    fail "validation: the negative trust anchor could not be created ($api_status: $(cat "$work/api.out"))"
  nta_id="$(field "d['id']" <"$work/api.out")"
  flush_cache
  row val.nta "a negative trust anchor makes the bogus zone insecure" within 20 bash -c "$(declare -f dig_val dig_client state_of rcode_of has_ad); [[ \"\$(state_of \"\$(dig_val www.bogus.example.test A 2>&1)\")\" == insecure ]]"
  row val.nta.warning "the negative trust anchor shows in the warnings of GET /system/status" system_warns dns.nta.active
  api DELETE "/dns/ntas/$nta_id" >/dev/null || fail "validation: the negative trust anchor could not be deleted"
  flush_cache
  row val.nta.gone "without it the zone is bogus again" within 20 bash -c "$(declare -f dig_val dig_client state_of rcode_of has_ad); [[ \"\$(state_of \"\$(dig_val www.bogus.example.test A 2>&1)\")\" == bogus ]]"
  # Forwarded answers: a rule to the recursive BIND, validated through it; then the
  # stripping upstream, then the rule's escape.
  on tenko
  api POST /dns/forwarders "{\"suffix\": \"example.test\", \"upstreams\": [{\"address\": \"$bind_resolver_ip\"}]}" >/dev/null ||
    fail "validation: the forwarding rule could not be created ($api_status: $(cat "$work/api.out"))"
  rule_id="$(field "d['id']" <"$work/api.out")"
  flush_cache
  sleep 2
  val_row val.forward.secure "a forwarded answer validated through BIND as upstream" www.example.test A secure - "$bind_resolver_ip" 53
  row val.forward.log "the log shows the forwarded resolution validated" log_shows_validation www.example.test secure
  val_row val.forward.bogus "a forwarded bogus name stays bogus through BIND" www.bogus.example.test A bogus 9 "$bind_resolver_ip" 53
  api PATCH "/dns/forwarders/$rule_id" "{\"upstreams\": [{\"address\": \"$strip_ip\"}]}" >/dev/null ||
    fail "validation: the rule could not be pointed at the stripping upstream ($api_status: $(cat "$work/api.out"))"
  flush_cache
  sleep 2
  out="$(dig_val www.example.test A 2>&1)" || true
  row val.forward.strips "an upstream that strips the DNSSEC records makes the answer bogus with EDE 10" test "$(rcode_of <<<"$out")" == SERVFAIL -a "$(ede_of <<<"$out")" == 10 ||
    printf '%s\n' "$out" >&2
  row val.forward.finding "the rule is reported as dns.forwarder.strips_dnssec" within 10 system_warns dns.forwarder.strips_dnssec
  api PATCH "/dns/forwarders/$rule_id" '{"validate": false}' >/dev/null ||
    fail "validation: validate = false could not be set ($api_status: $(cat "$work/api.out"))"
  flush_cache
  sleep 2
  out="$(dig_val www.example.test A 2>&1)" || true
  row val.forward.escape "validate = false on the rule gives the data, AD clear" test "$(rcode_of <<<"$out")" == NOERROR -a "$(state_of "$out")" == insecure ||
    printf '%s\n' "$out" >&2
  api DELETE "/dns/forwarders/$rule_id" >/dev/null || fail "validation: the rule could not be deleted"
  flush_cache
  printf '\n==> E33: the states with delv\n'
  printf '%s\n' "${e33[@]}"
  summary+=("${e33[@]}")
}

# --- The round rfc5011 (E34) -----------------------------------------------------------

# The configuration of the node under test for the roll: the hold-down in seconds.
write_rfc5011_config() {
  rm -f "$work/tenko.toml"
  cat >"$work/tenko.toml" <<TOML
# The configuration of the round "rfc5011" (written by smoke.sh): the RFC 5011 hold-downs
# are seconds under the Lab profile, so that the roll of the lab root's KSK is followed in
# minutes.
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
local_zones_except = ["test"]
timeout_ms = 1000
rfc5011_hold_down_secs = 20

[dns.cache]
prefetch = false
TOML
  chmod 0444 "$work/tenko.toml"
}

# root_zone_file: the lab root's records with the DS of `test`, unsigned, into
# LAB_DIR/zones/root.zone.
root_zone_file() {
  local records
  on authority
  api GET "/dns/zones/${zone_ids[test]}/dnssec" >/dev/null || fail "rfc5011: the DS of test"
  records="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for r in d.get("ds") or []:
    print("test. 3600 IN DS %s %s %s %s" % (r["key_tag"], r["algorithm"], r["digest_type"], r["digest"]))' "$work/api.out")"
  [[ -n "$records" ]] || fail "rfc5011: test has no DS yet"
  {
    printf '$ORIGIN .\n$TTL 300\n'
    printf '@ IN SOA a.root.test. hostmaster.example.test. 1 3600 600 86400 60\n'
    printf '@ IN NS a.root.test.\n'
    grep -v '^;' "$here/recursion/zones/root.zone" | grep -v '^\$'
    printf '%s\n' "$records"
  } >"$work/zones/root.zone"
  chmod 0666 "$work/zones/root.zone"
}

# sign_root: signs LAB_DIR/zones/root.zone with the keys in LAB_DIR/zones/keys (every KSK
# there signs the DNSKEY set) and imports it into the authority's root zone, replacing it.
sign_root() {
  local body
  bind_sh 'dnssec-signzone -q -S -K keys -o . -f root.signed root.zone && chmod 0644 root.signed'
  on authority
  body="$(python3 -c 'import json,sys; print(json.dumps({"zone_file": open(sys.argv[1]).read(), "replace": True}))' "$work/zones/root.signed")"
  api POST "/dns/zones/${zone_ids[.]}/records/import" "$body" >/dev/null ||
    fail "rfc5011: the signed root could not be imported ($api_status: $(cat "$work/api.out"))"
}

# ksk_tag <n>: the key tag of the n-th root KSK file by creation order.
ksk_file() { ls -tr "$work/zones/keys"/K.+013+*.key 2>/dev/null | xargs -r grep -l " 257 3 13 \| 385 3 13 " | sed -n "${1}p"; }
tag_of_file() { basename "$1" | sed -n 's/.*+013+0*\([0-9]*\)\.key/\1/p'; }
anchor_state() {
  # anchor_state <tag>: the state of the root anchor key <tag> in the node's status.
  node_status >/dev/null && python3 -c "
import json, sys
d = json.load(open('$work/recursion.json'))
for a in d.get('trust_anchors') or []:
    if a['zone'] == '.' and a['key_tag'] == $1:
        print(a['state']); sys.exit(0)
print('absent'); sys.exit(0)"
}
anchor_is() { [[ "$(anchor_state "$1")" == "$2" ]]; }
secure_now() { [[ "$(state_of "$(dig_val www.example.test A 2>&1)")" == secure ]]; }
audit_states() {
  on tenko && api GET "/audit?action=dns.trust_anchor.state&limit=100" >/dev/null &&
    python3 -c "
import json, sys
d = json.load(open('$work/api.out'))
states = sorted({(e.get('context') or {}).get('state') for e in d.get('items', [])} - {None})
print(states)
sys.exit(0 if all(s in states for s in ['add_pend', 'valid', 'revoked', 'removed']) else 1)"
}
volume_name() { echo "${COMPOSE_PROJECT_NAME:-tenkodnslab}_$1"; }
copy_volume() {
  # copy_volume <from> <to>: a copy of a data volume through the BIND image's shell.
  docker volume create "$2" >/dev/null
  docker run --rm --entrypoint sh -v "$1:/from" -v "$2:/to" "${BIND_IMAGE:-internetsystemsconsortium/bind9:9.20}" -c 'rm -rf /to/* && cp -a /from/. /to/'
}

rfc5011() {
  local name file signing id parent ds_a tag_a tag_b t0 t1 t2 t3 t4 timeline
  declare -A zone_ids=()
  timeline=()
  step "round rfc5011: a roll of the lab root's KSK followed by RFC 5011 (hold-down 20 s)"
  write_authority_config
  compose --profile recursion up -d --no-build authority client bind delv
  retry "$wait_secs" "the authority to become healthy" healthy authority
  auth_cookie="$(setup_node authority "$authority_ip" a.root.test)"
  [[ -n "$auth_cookie" ]] || fail "rfc5011: the authority's setup did not sign in: $(cat "$work/api.out")"
  on authority
  # The root is imported (signed by BIND's tools per step); test and example.test are
  # Tenko-signed as in the round recursion.
  api POST /dns/zones "{\"name\": \".\", \"kind\": \"primary\", \"serial\": \"counter\", \"soa\": $(soa_lab), \"name_servers\": [\"a.root.test\"], \"dnssec\": {\"mode\": \"imported\"}}" >/dev/null ||
    fail "rfc5011: the root zone could not be created ($api_status: $(cat "$work/api.out"))"
  zone_ids[.]="$(field "d['id']" <"$work/api.out")"
  for entry in "test|test.zone|nsec" "example.test|example.test.zone|nsec" "nsec3.example.test|nsec3.example.test.zone|nsec3" "wild.example.test|wild.example.test.zone|nsec"; do
    IFS='|' read -r name file signing <<<"$entry"
    id="$(create_zone "$name" "$signing")"
    zone_ids[$name]="$id"
    import_zone "$id" "$here_recursion/zones/$file"
  done
  retry 120 "the authority to answer www.example.test" \
    bash -c "[[ \"\$(docker compose -f '$compose_file' exec -T client dig @$authority_ip +short +time=2 +tries=1 www.example.test)\" == 192.0.2.10 ]]"
  retry 60 "the DS of example.test" publish_ds "${zone_ids[example.test]}" "${zone_ids[test]}" example.test
  for name in nsec3.example.test wild.example.test; do
    retry 60 "the DS of $name" publish_ds "${zone_ids[$name]}" "${zone_ids[example.test]}" "$name"
  done
  mkdir -p "$work/zones/keys"
  chmod 0777 "$work/zones/keys"
  retry 60 "the DS of test" root_zone_file
  bind_sh 'dnssec-keygen -q -K keys -a ECDSAP256SHA256 -f KSK . >/dev/null && dnssec-keygen -q -K keys -a ECDSAP256SHA256 . >/dev/null'
  sign_root
  tag_a="$(tag_of_file "$(ksk_file 1)")"
  ds_a="$(bind_sh "dnssec-dsfromkey -2 $(ksk_file 1 | sed "s#$work/zones/##")" | awk '{print $4, $5, $6, $7}')"
  ok "rfc5011: lab root" "imported, signed by BIND's tools with KSK $tag_a; DS $ds_a"

  write_rfc5011_config
  compose up -d --no-build --force-recreate tenko
  retry "$wait_secs" "tenko to become healthy" healthy tenko
  node_cookie="$(setup_node tenko "$tenko_ip" tenko.example.test)"
  [[ -n "$node_cookie" ]] || fail "rfc5011: the node's setup did not sign in: $(cat "$work/api.out")"
  on tenko
  node_id="$(api GET /system/status >/dev/null && field "d['node']['id']" <"$work/api.out")"
  anchor_setup "$ds_a"
  row r11.start "www.example.test is secure with KSK $tag_a as the anchor" within 30 secure_now
  row r11.anchor.valid "the anchor $tag_a is valid and the service has refreshed it" within 40 anchor_is "$tag_a" valid
  t0="$(date +%s)"

  # The new KSK is published; the node sees it as AddPend.
  bind_sh 'dnssec-keygen -q -K keys -a ECDSAP256SHA256 -f KSK . >/dev/null'
  sign_root
  tag_b="$(tag_of_file "$(ksk_file 2)")"
  row r11.publish "the new KSK $tag_b enters AddPend without an operator" within 45 anchor_is "$tag_b" add_pend
  t1="$(date +%s)"
  timeline+=("$(printf 'T+%3ds  KSK %s published, seen as AddPend' $((t1 - t0)) "$tag_b")")
  row r11.pending.warning "the pending key shows as dns.trust_anchor.pending" system_warns dns.trust_anchor.pending
  # A backup of the node before the roll: a copy of its data volume while it is stopped.
  compose stop tenko >/dev/null 2>&1
  copy_volume "$(volume_name tenko-data)" "$(volume_name tenko-backup)"
  compose start tenko >/dev/null 2>&1
  retry "$wait_secs" "tenko to be healthy again" healthy tenko
  row r11.hold_down "after the hold-down the new anchor is Valid, before the old is revoked" within 60 anchor_is "$tag_b" valid
  t2="$(date +%s)"
  timeline+=("$(printf 'T+%3ds  KSK %s Valid (hold-down passed)' $((t2 - t0)) "$tag_b")")
  row r11.old.valid "the old anchor $tag_a is still valid" anchor_is "$tag_a" valid
  row r11.secure.mid "www.example.test stays secure during the roll" secure_now

  # The old KSK is revoked (the REVOKE bit, self-signed) and leaves the row after the
  # remove hold-down.
  bind_sh "dnssec-revoke -K keys -r $(ksk_file 1 | sed "s#$work/zones/keys/##; s/\.key\$//") >/dev/null"
  sign_root
  row r11.revoked "the old KSK $tag_a is Revoked when the zone revokes it" within 45 anchor_is "$tag_a" revoked
  t3="$(date +%s)"
  timeline+=("$(printf 'T+%3ds  KSK %s revoked, seen as Revoked' $((t3 - t0)) "$tag_a")")
  row r11.secure.after "www.example.test is secure with the new anchor only" secure_now
  write_delv_anchor "$(bind_sh "dnssec-dsfromkey -2 $(ksk_file 2 | sed "s#$work/zones/##")" | awk '{print $4, $5, $6, $7}')"
  row r11.delv "delv validates with the new KSK as its anchor" test "$(delv_verdict "$tenko_ip" "$dns_port" www.example.test A)" == secure
  row r11.removed "after the remove hold-down the old key is Removed, then forgotten" within 60 bash -c "$(declare -f anchor_state node_status on api field); s=\$(anchor_state $tag_a); [[ \"\$s\" == removed || \"\$s\" == absent ]]"
  t4="$(date +%s)"
  timeline+=("$(printf 'T+%3ds  KSK %s Removed' $((t4 - t0)) "$tag_a")")
  row r11.audit "every state change is audited as dns.trust_anchor.state" audit_states
  row r11.never.failed "validation never failed during the roll (the bogus counter is 0 for the root)" bash -c "$(declare -f node_status on api); node_status >/dev/null; python3 -c \"import json; d=json.load(open('$work/recursion.json')); print(d['counters']); raise SystemExit(0 if d['counters']['bogus'] == 0 else 1)\""

  # A node started from the backup follows the roll on start.
  compose stop tenko >/dev/null 2>&1
  copy_volume "$(volume_name tenko-backup)" "$(volume_name tenko-data)"
  compose start tenko >/dev/null 2>&1
  retry "$wait_secs" "the restored node to be healthy" healthy tenko
  node_cookie="$(curl -sS -o /dev/null -w '' "http://$tenko_ip:8443/api/v1/system/status" >/dev/null; printf '%s' "$node_cookie")"
  row r11.restore.old "the restored node starts with $tag_a valid and $tag_b pending" within 30 anchor_is "$tag_b" add_pend
  row r11.restore.follow "the restored node makes $tag_b Valid and $tag_a Revoked without an operator" within 90 bash -c "$(declare -f anchor_is anchor_state node_status on api field); anchor_is $tag_b valid && anchor_is $tag_a revoked"
  row r11.restore.secure "www.example.test is secure on the restored node" within 30 secure_now
  docker volume rm "$(volume_name tenko-backup)" >/dev/null 2>&1 || true
  printf '\n==> E34: the roll\n'
  printf '%s\n' "${timeline[@]}"
  summary+=("${timeline[@]}")
  ((rows_failed == 0)) || fail "rfc5011: $rows_failed row(s) failed"
}
