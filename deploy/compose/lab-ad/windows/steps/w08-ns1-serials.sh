#!/usr/bin/env bash
# W8 on ns1, before and after the hour on dc1 (README.md section W8), as root. One script for
# two entries: an id ending in "-before" keeps the zones' serials; one ending in "-after"
# compares them with the "-before" entry's and reads the audit since it began.
#
# Expects ("-after"): the "-before" entry's zones.txt and started.txt in its step directory
# on this machine.
# Leaves: nothing changed.
# Keeps: zones.txt (`tenko dns zone list`: name, kind, serial, RRsets), started.txt
# ("-before"); w8.txt and audit-apply.json ("-after").
# Checks ("-after"): the serials did not move and no dns.update.apply was written since the
# "-before" entry: a pure refresh writes nothing. That every update was answered NOERROR is
# read from dc1's capture by a person.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
assert_clock
tenko_read dns zone list >"$STEP_DIR/zones.txt"

case "$ID" in
  *-before)
    printf '%s\n' "$STARTED" >"$STEP_DIR/started.txt"
    step "the zones' serials before the hour are kept"
    ;;
  *-after)
    before=("$LAB"/*-w08-ns1-before)
    [[ ${#before[@]} == 1 && -s "${before[0]}/started.txt" ]] || fail "the W8 \"-before\" entry's directory is missing"
    audit dns.update.apply "$(<"${before[0]}/started.txt")" "$STEP_DIR/audit-apply.json"
    {
      echo "== before (${before[0]##*/})"
      cat "${before[0]}/zones.txt"
      echo "== after"
      cat "$STEP_DIR/zones.txt"
      echo "== dns.update.apply since $(<"${before[0]}/started.txt"): $(audit_count "$STEP_DIR/audit-apply.json")"
    } >"$STEP_DIR/w8.txt"
    cmp -s "${before[0]}/zones.txt" "$STEP_DIR/zones.txt" || fail "the zones' serials moved during the hour (w8.txt)"
    (($(audit_count "$STEP_DIR/audit-apply.json") == 0)) || fail "dns.update.apply records were written during the hour (audit-apply.json)"
    step "the hour's refresh moved no serial and wrote nothing"
    ;;
  *) fail "the entry id must end in -before or -after" ;;
esac
