#!/usr/bin/env bash
# W4, second part: the zones on Tenko by the Windows-dialect import, and the secure-only
# policy (README.md section W4), on ns1 as root.
#
# Expects: the three zone exports of W2 in /root/lab/in/<zone>.dns and dc1's sids.json in
# /root/lab/in/sids.json (the job copies them from dc1); the Kerberos account adopted (W3).
# Leaves: the zones corp.example.test, _msdcs.corp.example.test and 2.0.192.in-addr.arpa
# as primaries imported in the Windows dialect with the claimable names approved, ns1 as
# their name server and SOA mname, the access list ad-corp and each zone's secure-only
# policy (ownership windows, owner hold 14 days, the privileged SIDs, DnsUpdateProxy).
# Keeps: w4-import.txt (the dry-run reports and the two record lists), dry-run-<zone>.json,
# zone-<zone>.json (each zone's settings after the policy: they replace the runbook's
# screenshot of the settings page), owners-<zone>.json.
# Checks, in place of a person reading the lists: every claimable RRset of every zone is
# claimed by one of the lab's computers (DC1$, DC2$, SRV1$, PC1$) and the list is whole;
# srv1.corp.example.test is claimable by SRV1$; the import then approves exactly that list.
# After the import: `record list --origin ad` names srv1, `--origin manual` names printer1,
# and no zone has an owner yet.
# Departs from the runbook: jq is not on a stock Ubuntu server, so python3 reads the JSON;
# the access list and the zones' policy go through the API with the administrator's token
# (the command line has no flag for a Kerberos entry or the zone's Kerberos settings).

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
zones=(corp.example.test _msdcs.corp.example.test 2.0.192.in-addr.arpa)
for zone in "${zones[@]}"; do need_file "$LAB/in/$zone.dns" "the job copies the W2 export from dc1"; done
need_file "$LAB/in/sids.json" "the job copies sids.json of W4's dc1 part"
assert_clock
out="$STEP_DIR/w4-import.txt"
cd "$LAB/in"

say "the zones"
for zone in "${zones[@]}"; do
  tenko dns zone create "$zone" --kind primary --ns ns1.corp.example.test \
    --mname ns1.corp.example.test --rname hostmaster.corp.example.test --serial date_counter
done

say "the dry runs"
for zone in "${zones[@]}"; do
  printf '== tenko dns import %s --windows --dry-run\n' "$zone" >>"$out"
  tenko dns import "$zone" "$zone.dns" --windows --dry-run >>"$out"
  tenko dns import "$zone" "$zone.dns" --windows --dry-run --json >"$STEP_DIR/dry-run-$zone.json"
  python3 - "$STEP_DIR/dry-run-$zone.json" <<'EOF' || fail "the claimable list of $zone holds a name the lab does not expect (dry-run-$zone.json)"
import json, sys
report = json.load(open(sys.argv[1]))
names = report.get("claimable_names") or []
strange = [n for n in names if n["claimant"].upper() not in ("DC1$", "DC2$", "SRV1$", "PC1$")]
print("claimable:", [(n["name"], n["rtype"], n["claimant"]) for n in names])
sys.exit(1 if strange or report.get("claimable_next") else 0)
EOF
done
py 'str(any(n["name"].rstrip(".") == "srv1.corp.example.test" and n["claimant"].upper() == "SRV1$" for n in v["claimable_names"]))' \
  <"$STEP_DIR/dry-run-corp.example.test.json" | grep -qx True ||
  fail "srv1.corp.example.test is not claimable by SRV1\$ (dry-run-corp.example.test.json)"

say "the imports"
for zone in "${zones[@]}"; do
  digest="$(py 'v["claimable_digest"]' <"$STEP_DIR/dry-run-$zone.json")"
  printf '== tenko dns import %s --windows --approve-claimable %s\n' "$zone" "$digest" >>"$out"
  tenko dns import "$zone" "$zone.dns" --windows --approve-claimable "$digest" >>"$out"
done
tenko dns record replace corp.example.test ns1 A 192.0.2.53
tenko dns record replace corp.example.test _msdcs NS ns1.corp.example.test.
tenko dns record replace corp.example.test @ NS ns1.corp.example.test.
tenko dns record replace _msdcs.corp.example.test @ NS ns1.corp.example.test.
tenko dns record replace 2.0.192.in-addr.arpa @ NS ns1.corp.example.test.
for zone in "${zones[@]}"; do
  tenko dns zone update "$zone" --mname ns1.corp.example.test --rname hostmaster.corp.example.test
done
for origin in ad manual; do
  printf '== tenko dns record list corp.example.test --origin %s\n' "$origin" >>"$out"
  tenko dns record list corp.example.test --origin "$origin" | tee "$STEP_DIR/records-$origin.txt" >>"$out"
done
grep -qw srv1 "$STEP_DIR/records-ad.txt" || fail "record list --origin ad does not name srv1"
grep -qw printer1 "$STEP_DIR/records-manual.txt" || fail "record list --origin manual does not name printer1"

say "the secure-only policy"
acl="$(api admin POST /dns/acls <(printf '{"name":"ad-corp","entries":[{"kind":"kerberos","realm":"CORP.EXAMPLE.TEST"}]}') | py 'v["id"]')"
for zone in "${zones[@]}"; do
  id="$(zone_id "$zone")"
  api admin PATCH "/dns/zones/$id" <(python3 - "$acl" "$LAB/in/sids.json" <<'EOF'
import json, sys
acl, sids = sys.argv[1], json.load(open(sys.argv[2], encoding="utf-8-sig"))
d = sids["domain"]
print(json.dumps({"update": {"allowed": [acl], "require_tsig": True, "may_replace_ipam": False,
  "kerberos": {"realms": ["CORP.EXAMPLE.TEST"], "ownership": "windows", "owner_hold_days": 14,
    "privileged": [d + "-512", d + "-516", d + "-519", sids["dnsadmins"]],
    "update_proxy": sids["dnsupdateproxy"]}}}))
EOF
  ) >/dev/null
  zone_json "$zone" >"$STEP_DIR/zone-$zone.json"
  owners "$zone" "$STEP_DIR/owners-$zone.json"
  [[ "$(py 'str(len(v["items"]))' <"$STEP_DIR/owners-$zone.json")" == 0 ]] || fail "$zone has owners before any secure update"
done

step "three zones imported in the Windows dialect with the approved claimable names; the secure-only policy is set"
