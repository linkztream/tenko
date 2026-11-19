#!/usr/bin/env bash
# W9 on ns1: the profile moves to Hardened (README.md section W9), as root.
#
# Expects: the GPO entry on dc1 before it; the secret tenko_admin_password and the TOTP seed
# W0 wrote.
# Leaves: an audit export file sink `lab-file` (lab-audit.jsonl in the node's export
# directory) and the profile Hardened. Hardened refuses the switch while no sink that
# confirms delivery is enabled (TGL-21), so the sink comes first. What Hardened changes for
# the later steps: an administrator then signs in with a passkey only (TGL-03), so neither
# the administrator's token nor a TOTP session acts any more; the later ns1 entries read
# with the lab reader's service-account token, which W0 created for this, and change nothing
# but the service itself (W13). Updates: unsigned ones are refused everywhere and ownership is
# on in every zone with Kerberos settings, which the zones of W4 have already.
# Keeps: audit-export.json, security.json (the settings after the change), zones.txt.
# Checks: the profile reads hardened; the lab reader's token still lists the zones.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
assert_clock

say "the audit export sink"
session_login
api session PUT /settings/audit-export \
  <(printf '{"sinks":[{"name":"lab-file","enabled":true,"format":"json","target":{"kind":"file","file":"lab-audit.jsonl"}}]}') \
  >"$STEP_DIR/audit-export.json"

say "the profile"
api session PATCH /settings/security <(printf '{"profile":"hardened"}') >"$STEP_DIR/security.json"
[[ "$(py '(v.get("settings") or v)["profile"]' <"$STEP_DIR/security.json")" == hardened ]] ||
  fail "the profile is not hardened after the change (security.json)"

say "the lab reader under Hardened"
tenko_read dns zone list >"$STEP_DIR/zones.txt" || fail "the lab reader's token no longer reads under Hardened"

step "the profile is Hardened, with an audit export file sink; the lab reader still reads"
