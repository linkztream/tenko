#!/usr/bin/env bash
# W12 on ns1: pc1's update of srv1's PTR name was refused (README.md section W12), as root.
#
# Expects: pc1's attempt with 192.0.2.20 (the pc1 entry of W12).
# Leaves: nothing changed.
# Keeps: w12.txt (the RRsets named 20, as JSON), audit-refuse.json (the last 15 minutes).
# Checks: a dns.update.refuse record names SRV1$, the owner; the PTR record of
# 20.2.0.192.in-addr.arpa still points at srv1.corp.example.test.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
assert_clock
records 2.0.192.in-addr.arpa 20 >"$STEP_DIR/w12.txt"
py 'str(any(s["name"].rstrip(".") == "20.2.0.192.in-addr.arpa" and r.get("target", "").rstrip(".") == "srv1.corp.example.test"
  for s in v["items"] if s["type"] == "PTR" for r in s["records"]))' <"$STEP_DIR/w12.txt" | grep -qx True ||
  fail "20.2.0.192.in-addr.arpa no longer points at srv1 (w12.txt)"
audit dns.update.refuse "$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ)" "$STEP_DIR/audit-refuse.json"
(($(mentions "$STEP_DIR/audit-refuse.json" 'SRV1$') > 0)) || fail "no dns.update.refuse names the owner SRV1\$ (audit-refuse.json)"

step "pc1's update of 20.2.0.192.in-addr.arpa was refused for SRV1\$; the PTR record is unchanged"
