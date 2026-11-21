#!/usr/bin/env bash
# W9 on ns1: the profile moves to Hardened (README.md section W9), as root.
#
# Expects: the GPO entry on dc1 before it; the secret tenko_admin_password and the TOTP seed
# W0 wrote; the lab reader's certificate and bound token of W0.
# Leaves: an audit export file sink `lab-file` (lab-audit.jsonl in the node's export
# directory), a service account `lab-unbound` without tokens, and the profile Hardened.
# Hardened refuses the switch while no sink that confirms delivery is enabled (TGL-21), so the
# sink comes first. What Hardened changes for the later steps: an administrator then signs in
# with a passkey only (TGL-03), so neither the administrator's token nor a TOTP session acts
# any more; and it requires certificate-bound service-account tokens (TGL-47), so the switch
# removes every unbound one (docs/integrations.md section 9). The later ns1 entries read as
# the lab reader, whose token W0 bound to its certificate, and change nothing but the service
# itself (W13). Updates: unsigned ones are refused everywhere and ownership is on in every
# zone with Kerberos settings, which the zones of W4 have already.
# Keeps: audit-export.json, security-dry-run.json (what the switch would remove),
# security.json (the settings after the change, with what it removed), unbound-before.json and
# unbound-after.json (the throwaway token's answers), audit-revoke.json (auth.token.revoke
# since the step began), zones.txt.
# Checks: one throwaway unbound token of `lab-unbound`, made for this check, reads before the
# switch; the dry run names exactly that token (one token of lab-unbound, none of lab-reader);
# the switch removes the same, audited as auth.token.revoke with the throwaway token's id;
# the profile reads hardened; the lab reader still reads through its certificate; the
# throwaway token answers 401 auth.unauthenticated.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
assert_clock

# unbound_read <file>: the status of a zone list with the throwaway token on the API listener;
# the answer goes to the file.
unbound_read() {
  printf 'header = "Authorization: Bearer %s"\n' "$(<"$(secret tenko_unbound_token)")" |
    curl -sS --max-time 10 --cacert "$CA" -K - -o "$1" -w '%{http_code}' "$TENKO_URL/api/v1/dns/zones"
}

say "the audit export sink"
session_login
api session PUT /settings/audit-export \
  <(printf '{"sinks":[{"name":"lab-file","enabled":true,"format":"json","target":{"kind":"file","file":"lab-audit.jsonl"}}]}') \
  >"$STEP_DIR/audit-export.json"

say "a throwaway unbound service-account token"
account="$(api session POST /access/service-accounts \
  <(printf '{"name":"lab-unbound","display_name":"Lab unbound token","roles":["viewer"]}') | py 'v["id"]')"
api session POST "/access/service-accounts/$account/tokens" \
  <(printf '{"name":"lab-unbound","expires_in_days":1,"grants":[{"role":"viewer"}]}') >"$SECRETS/tenko_unbound.json"
py 'v["token"]' <"$SECRETS/tenko_unbound.json" >"$SECRETS/tenko_unbound_token"
token_id="$(py 'v["info"]["id"]' <"$SECRETS/tenko_unbound.json")"
rm -f "$SECRETS/tenko_unbound.json"
[[ "$(unbound_read "$STEP_DIR/unbound-before.json")" == 200 ]] ||
  fail "the throwaway token does not read under Standard (unbound-before.json)"

say "the dry run of the switch"
api session PATCH '/settings/security?dry_run=true' <(printf '{"profile":"hardened"}') >"$STEP_DIR/security-dry-run.json"
removes='str((v["unbound_tokens_removed"]["count"], [(a["name"], a["tokens"]) for a in v["unbound_tokens_removed"]["accounts"]]))'
would="$(py "$removes" <"$STEP_DIR/security-dry-run.json")"
[[ "$would" == "(1, [('lab-unbound', 1)])" ]] ||
  fail "the dry run would remove $would, not the one throwaway token of lab-unbound (security-dry-run.json)"

say "the profile"
api session PATCH /settings/security <(printf '{"profile":"hardened"}') >"$STEP_DIR/security.json"
[[ "$(py '(v.get("settings") or v)["profile"]' <"$STEP_DIR/security.json")" == hardened ]] ||
  fail "the profile is not hardened after the change (security.json)"
[[ "$(py "$removes" <"$STEP_DIR/security.json")" == "$would" ]] ||
  fail "the switch removed other tokens than its dry run named (security.json)"

say "the tokens under Hardened"
zone_table >"$STEP_DIR/zones.txt" || fail "the lab reader no longer reads through its certificate under Hardened"
audit auth.token.revoke "$STARTED" "$STEP_DIR/audit-revoke.json"
(($(mentions "$STEP_DIR/audit-revoke.json" "$token_id") == 1)) ||
  fail "no single auth.token.revoke names the throwaway token $token_id (audit-revoke.json)"
status="$(unbound_read "$STEP_DIR/unbound-after.json")"
[[ "$status" == 401 && "$(py 'v["code"]' <"$STEP_DIR/unbound-after.json")" == auth.unauthenticated ]] ||
  fail "the removed unbound token answered $status, not 401 auth.unauthenticated (unbound-after.json)"

step "the profile is Hardened, with an audit export file sink; the switch removed the one unbound token, which answers 401; the lab reader still reads through its certificate"
