#!/usr/bin/env bash
# W13 on ns1, last: nothing refused after the restart (README.md section W13), as root.
#
# Expects: the W13 restart entry's started.txt in its step directory on this machine; dc1
# and pc1 registered again after the restart.
# Leaves: nothing changed.
# Keeps: w13.txt, audit-refuse.json, audit-apply.json (since the restart).
# Checks: no dns.update.refuse since the restart (the owners live in the store, not in the
# contexts). The applied updates are only counted: a registration of unchanged records
# writes nothing. BADKEY and the new TKEY are read from the captures by a person.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
assert_clock
restart=("$LAB"/*-w13-ns1-restart)
[[ ${#restart[@]} == 1 && -s "${restart[0]}/started.txt" ]] || fail "the W13 restart entry's directory is missing"
since="$(<"${restart[0]}/started.txt")"
audit dns.update.refuse "$since" "$STEP_DIR/audit-refuse.json"
audit dns.update.apply "$since" "$STEP_DIR/audit-apply.json"
printf 'since %s: dns.update.refuse %s, dns.update.apply %s\n' "$since" \
  "$(audit_count "$STEP_DIR/audit-refuse.json")" "$(audit_count "$STEP_DIR/audit-apply.json")" >"$STEP_DIR/w13.txt"
(($(signed_refusals "$STEP_DIR/audit-refuse.json") == 0)) || fail "signed updates were refused after the restart (audit-refuse.json)"

step "no signed update was refused after the node's restart"
