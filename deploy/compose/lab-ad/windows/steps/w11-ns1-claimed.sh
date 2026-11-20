#!/usr/bin/env bash
# W11 on ns1: srv1 claimed its imported names (README.md section W11), as root. Runs right
# after srv1's W11 entry, before W6.
#
# Expects: srv1 registered twice with Tenko.
# Leaves: nothing changed.
# Keeps: w11.txt (the two record lists, as JSON), owners-corp.example.test.json,
# owners-2.0.192.in-addr.arpa.json, audit-apply.json (the last 15 minutes).
# Checks: srv1.corp.example.test and 20.2.0.192.in-addr.arpa are owned by SRV1$, claimed.
# Whether the second registration wrote nothing is read from audit-apply.json by a person.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
assert_clock
{
  echo "== the RRsets of corp.example.test named srv1"
  records corp.example.test srv1
  echo "== the RRsets of 2.0.192.in-addr.arpa named 20"
  records 2.0.192.in-addr.arpa 20
} >"$STEP_DIR/w11.txt"
audit dns.update.apply "$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ)" "$STEP_DIR/audit-apply.json"
owners corp.example.test "$STEP_DIR/owners-corp.example.test.json"
owners 2.0.192.in-addr.arpa "$STEP_DIR/owners-2.0.192.in-addr.arpa.json"
owned_by "$STEP_DIR/owners-corp.example.test.json" srv1.corp.example.test 'SRV1$' claimed
owned_by "$STEP_DIR/owners-2.0.192.in-addr.arpa.json" 20.2.0.192.in-addr.arpa 'SRV1$' claimed

step "srv1.corp.example.test and 20.2.0.192.in-addr.arpa are claimed by SRV1\$"
