#!/usr/bin/env bash
# W3, second part: Tenko adopts the pre-staged account (README.md section W3, item 3), on ns1
# as root.
#
# Expects: TENKO-DNS$ created by the block of section 4.1 on dc1; the secrets
# tenko_admin_password and kerberos_onetime_password (the same value the dc1 part used);
# ns1 synchronized to dc1's clock.
# Leaves: the account adopted: Tenko changed its password and keeps its AES keys.
# Keeps: adopt.json (the adoption's answer: no password or key is ever in it), w3-status.txt
# and kerberos-status.json (`tenko dns kerberos status`, the second for the dc1 part's
# comparison), timesync.txt.
# Checks: the account is TENKO-DNS$ of CORP.EXAMPLE.TEST with one current key version and
# no finding.
# Departs from the runbook: the runbook's `tenko dns kerberos adopt` sends the request with
# the API token of `tenko login`, and the route takes an interactive session only (the
# account is key material; a token is refused with 403). The script sends the same request,
# with the same values, from an interactive session of the administrator, as the wizard of
# the web UI does. The one-time password goes from its file into the request body through a
# pipe.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
secret kerberos_onetime_password >/dev/null
assert_clock
timedatectl timesync-status >"$STEP_DIR/timesync.txt" 2>&1 || true

say "the adoption"
session_login
api session POST /dns/kerberos/adopt <(python3 -c 'import json,sys
print(json.dumps({"realm": "CORP.EXAMPLE.TEST", "name": "TENKO-DNS$",
  "password": open(sys.argv[1]).read().rstrip("\n"),
  "spns": ["DNS/ns1.corp.example.test"], "kdcs": ["192.0.2.5"]}))' "$(secret kerberos_onetime_password)") >"$STEP_DIR/adopt.json"

say "the status"
tenko dns kerberos status >"$STEP_DIR/w3-status.txt"
tenko dns kerberos status --json >"$STEP_DIR/kerberos-status.json"
check="$(py '"%s %s %d %d" % (v["account"]["name"], v["account"]["realm"],
  len([x for x in v["account"]["versions"] if x["state"] == "current"]), len(v.get("findings") or []))' \
  <"$STEP_DIR/kerberos-status.json")"
[[ "$check" == 'TENKO-DNS$ CORP.EXAMPLE.TEST 1 0' ]] ||
  fail "the status is '$check', not 'TENKO-DNS\$ CORP.EXAMPLE.TEST 1 0' (account, realm, current versions, findings)"

step "Tenko adopted TENKO-DNS\$@CORP.EXAMPLE.TEST with no finding"
