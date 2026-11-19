#!/usr/bin/env bash
# W5 and W7 on ns1: what Tenko saw of a controller's registration (README.md sections W5 and
# W7), as root. One script for both entries: the controller is the last word of the entry's
# id (dc1 or dc2).
#
# Expects: the controller's entry before it registered with Tenko.
# Leaves: nothing changed.
# Keeps: audit-apply.json, audit-refuse.json, audit-gss-refuse.json (the audit records of the
# last 30 minutes), owners-corp.example.test.json, owners-_msdcs.corp.example.test.json,
# metrics.txt (tenko_dns_tkey_total and tenko_dns_updates_total).
# Checks: dns.update.apply records with the controller's principal and the decision
# privileged; no dns.update.refuse and no dns.gss.refuse; <dc>.corp.example.test owned by
# <DC>$ (created); no locator name owned (nothing in _msdcs, no owned name that starts
# with an underscore).
# Departs from the runbook: the metrics come from GET /api/v1/metrics with the lab reader's
# token (scope metrics): the loopback listener the runbook reads is off unless `[metrics]
# listen` is set, and the lab does not change the node's configuration for it.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
dc="${ID##*-}"
[[ "$dc" == dc1 || "$dc" == dc2 ]] || fail "the entry id must end in -dc1 or -dc2"
DC="${dc^^}"
assert_clock
since="$(date -u -d '-30 min' +%Y-%m-%dT%H:%M:%SZ)"

say "the audit"
audit dns.update.apply "$since" "$STEP_DIR/audit-apply.json"
audit dns.update.refuse "$since" "$STEP_DIR/audit-refuse.json"
audit dns.gss.refuse "$since" "$STEP_DIR/audit-gss-refuse.json"
(($(mentions "$STEP_DIR/audit-apply.json" "$DC\$@CORP.EXAMPLE.TEST" privileged) > 0)) ||
  fail "no dns.update.apply by $DC\$@CORP.EXAMPLE.TEST with the decision privileged (audit-apply.json)"
(($(audit_count "$STEP_DIR/audit-refuse.json") == 0)) || fail "updates were refused (audit-refuse.json)"
(($(audit_count "$STEP_DIR/audit-gss-refuse.json") == 0)) || fail "GSS negotiations were refused (audit-gss-refuse.json)"

say "the owners"
owners corp.example.test "$STEP_DIR/owners-corp.example.test.json"
owners _msdcs.corp.example.test "$STEP_DIR/owners-_msdcs.corp.example.test.json"
owned_by "$STEP_DIR/owners-corp.example.test.json" "$dc.corp.example.test" "$DC\$" created
[[ "$(py 'str(len(v["items"]))' <"$STEP_DIR/owners-_msdcs.corp.example.test.json")" == 0 ]] ||
  fail "a name of _msdcs has an owner (owners-_msdcs.corp.example.test.json)"
[[ "$(py 'str(len([i for i in v["items"] if i["name"].startswith("_")]))' <"$STEP_DIR/owners-corp.example.test.json")" == 0 ]] ||
  fail "a locator name of corp.example.test has an owner (owners-corp.example.test.json)"

say "the counters"
api reader GET /metrics | grep -E 'tenko_dns_(tkey|updates)_total' >"$STEP_DIR/metrics.txt" ||
  fail "the metrics hold no tenko_dns_tkey_total or tenko_dns_updates_total"

step "$dc registered with GSS-TSIG as $DC\$, privileged; it owns $dc.corp.example.test; nothing refused"
