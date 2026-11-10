#!/usr/bin/env bash
# The round `account` of the Active Directory lab (identity plan sections 3.1, 3.10 and 3.19,
# WP13.3, E45): Tenko's Kerberos service account against a Samba AD domain controller.
#
# One PASS or FAIL line per row, then a summary:
#   adopt.taken          the pre-staged TENKO-DNS$ is adopted with its one-time password; the
#                        version Tenko holds is the controller's msDS-KeyVersionNumber
#   adopt.otp_gone       the one-time password no longer gets a ticket
#   adopt.no_secret      no answer of the API carried the one-time password
#   finding.spn_missing  an SPN no account holds is dns.gss.spn_missing, naming it
#   check.pass           the SPN added on the controller, the self-test passes
#   client.kvno          a user's service ticket for the SPN names the version Tenko holds
#   rotate.moves         a forced rotation (the job) moves the version on Tenko and on the
#                        controller; the version before stays as previous, so a ticket issued
#                        before the rotation (alice's, still in her cache) is under a key
#                        Tenko holds
#   restart.recovered    the controller drops the change-password answers, Tenko is killed
#                        after the controller took the new password and before Tenko
#                        committed it; after the restart the pending version is committed
#   finding.weak_etype   msDS-SupportedEncryptionTypes set to RC4 only is dns.gss.weak_etype
#   finding.spn_duplicate the SPN put on a second account as well is dns.gss.spn_duplicate;
#                        SKIP when the controller refuses the duplicate at the write
#   finding.clock_skew   the controller's clock 120 s ahead is dns.gss.clock_skew
#   finding.self_test    the account disabled is dns.gss.self_test_failed, reason disabled
#   import.works         a keytab written with ktutil as ktpass writes it imports and the
#                        self-test passes
#   finding.kvno_unknown a keytab with a key version the KDC does not issue is
#                        dns.gss.kvno_unknown
#
# Needs bash and Docker with the compose plugin. From the repository root:
#   bash deploy/compose/lab-ad/account/round.sh                 # builds tenko:lab first
#   TENKO_IMAGE=tenko:lab bash deploy/compose/lab-ad/account/round.sh
#   KEEP=1 ...                                                  # leave the lab running
#
# Everything runs inside the lab network 198.51.100.0/24 (documentation addresses); nothing
# is published on the host, and the API is reached from the client container, so the round
# also runs where the host cannot reach a bridge network (Docker Desktop). Every secret (the
# controller's administrator password, alice's, the one-time password, Tenko's PIN and its
# key-encryption key) is generated per run into the work directory and removed with it; none
# is printed. The acceptance of tickets by the TKEY handler is the round `gss` (WP13.2): this
# round proves that the keys Tenko holds are the ones the controller issues tickets under.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab="$(cd "$here/.." && pwd)"
repo="$(cd "$lab/../../.." && pwd)"
keep="${KEEP:-0}"
wait_secs="${WAIT_SECS:-300}"
project="${COMPOSE_PROJECT_NAME:-tenkoadaccount}"
realm=LAB.EXAMPLE.TEST
salt="${realm}hosttenko-dns.lab.example.test"
spn1=DNS/ns1.lab.example.test
spn2=DNS/ns2.lab.example.test

export SAMBA_IMAGE="${SAMBA_IMAGE:-tenko-lab-account-samba:local}"
export CLIENT_IMAGE="${CLIENT_IMAGE:-tenko-lab-account-client:local}"
export TENKO_IMAGE="${TENKO_IMAGE:-tenko:lab}"

summary=()
rows_failed=0
step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'account: %s\n' "$*" >&2; exit 1; }
row() {
  local name="$1" what="$2" line
  shift 2
  if "$@"; then
    line="$(printf 'PASS %-22s %s' "$name" "$what")"
  else
    line="$(printf 'FAIL %-22s %s' "$name" "$what")"
    rows_failed=$((rows_failed + 1))
  fi
  summary+=("$line")
  printf '%s\n' "$line"
}
retry() {
  local limit="$1" what="$2" waited=0
  shift 2
  until "$@" >/dev/null 2>&1; do
    ((waited >= limit)) && fail "timed out after ${limit}s waiting for: $what"
    sleep 2
    waited=$((waited + 2))
  done
}

work="$(mktemp -d)"
# Docker Desktop on Windows takes Windows paths for the compose files and the bind mounts.
if command -v cygpath >/dev/null 2>&1; then
  export LAB_DIR="$(cygpath -m "$work")"
  lab_files="$(cygpath -m "$lab")"
else
  export LAB_DIR="$work"
  lab_files="$lab"
fi
compose() { MSYS_NO_PATHCONV=1 docker compose -p "$project" -f "$lab_files/compose.yml" -f "$lab_files/account.override.yml" "$@"; }
in_samba() { compose exec -T samba "$@"; }
in_client() { compose exec -T client "$@"; }

teardown() {
  local status=$?
  if ((status != 0 || rows_failed > 0)); then
    compose logs --no-color --tail 200 >&2 || true
  fi
  if [[ "$keep" == 1 ]]; then
    printf 'account: the lab is kept (project %s, LAB_DIR %s)\n' "$project" "$LAB_DIR"
  else
    compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
    rm -rf "$work"
  fi
  printf '\n%s\n' "${summary[@]}"
  exit "$status"
}
trap teardown EXIT

# ---------------------------------------------------------------------------------------
step "images and secrets"
if ! docker image inspect "$TENKO_IMAGE" >/dev/null 2>&1; then
  docker build -f "$repo/deploy/Dockerfile" -t "$TENKO_IMAGE" "$repo"
fi
docker build -q -f "$here/samba.Dockerfile" -t "$SAMBA_IMAGE" "$here" >/dev/null
docker build -q -f "$here/client.Dockerfile" -t "$CLIENT_IMAGE" "$here" >/dev/null
mkdir -p "$work/secrets" "$work/tls" "$work/out"
umask 077
secret() { head -c 18 /dev/urandom | od -An -v -tx1 | tr -d ' \n'; }
printf 'Adm1n-%s' "$(secret)" >"$work/secrets/admin"
printf 'Al1ce-%s' "$(secret)" >"$work/secrets/alice"
printf 'Otp-%s' "$(secret)" >"$work/secrets/otp"
printf 'Pass-%s' "$(secret)" >"$work/secrets/reset"
od -An -N4 -tu4 /dev/urandom | tr -dc '0-9' >"$work/secrets/tenko"
head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$work/secrets/kek"
chmod 0444 "$work/secrets/"*
umask 022
cat >"$work/tenko.toml" <<'EOF'
# The node of the round `account` (written by account/round.sh).
roles = "controller,dns"
modules = ["dns"]

[profile]
name = "lab"

[tls]
mode = "plain"

[server]
listen = ["0.0.0.0:8443"]

[dns]
listen = ["0.0.0.0:53"]
EOF

step "the controller, the client and the node"
compose up -d samba client
retry 300 "the controller to provision" test -f "$work/out/READY"
retry 120 "the KDC to listen" in_samba bash -c 'echo > /dev/tcp/198.51.100.2/88'
in_client bash -c 'printf "[libdefaults]\n default_realm = LAB.EXAMPLE.TEST\n dns_lookup_kdc = false\n[realms]\n LAB.EXAMPLE.TEST = {\n  kdc = 198.51.100.2\n  admin_server = 198.51.100.2\n }\n" > /etc/krb5.conf'
compose up -d tenko
healthy() { [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q tenko)")" == healthy ]]; }
retry "$wait_secs" "tenko to become healthy" healthy

# api <METHOD> <path> [body]: sets $api_status and $api_body (the body never echoes a secret).
api() {
  local out
  out="$(printf '%s' "${3:-}" | in_client bash /lab/account/api.sh "$1" "$2")" || true
  api_status="${out##*$'\n'}"
  api_body="${out%$'\n'*}"
  [[ "$api_status" == 2* ]]
}
jqb() { printf '%s' "$api_body" | in_client jq -r "$1"; }
kvno_on_dc() {
  in_samba ldbsearch -H /var/lib/samba/private/sam.ldb '(sAMAccountName=TENKO-DNS$)' msDS-KeyVersionNumber |
    sed -n 's/^msDS-KeyVersionNumber: //p' | tr -d '\r'
}
# A problem answer has no findings: an empty list, which the rows below never take for a
# clean self-test on its own (they require a 2xx answer as well).
codes() { jqb '[(.findings // [])[].code] | join(",")'; }
details() { jqb '[(.findings // [])[] | .code + ": " + .detail] | join("; ")'; }
has_code() { [[ ",$(codes)," == *",$1,"* ]]; }
no_findings() { [[ -z "$(codes)" ]]; }
# The self-test answered (2xx) and found nothing.
spn_listed() { in_samba samba-tool spn list 'TENKO-DNS$' | grep -qiF "$spn2"; }
clean_check() { [[ "$api_status" == 2* ]] && no_findings; }
otp_refused() { ! in_client bash -c "kinit 'TENKO-DNS\$@$realm' < /lab/secrets/otp >/dev/null 2>&1"; }
no_otp() { ! grep -qF -f "$work/secrets/otp" <<<"$answers"; }
check() { api POST /dns/kerberos/check '' || [[ "$api_status" == 503 ]]; }

token="$(compose exec -T tenko /usr/local/bin/tenko setup token --data-dir /var/lib/tenko | tr -d '\r\n')"
[[ -n "$token" ]] || fail "no setup token"
out="$(printf '{"setup_token": "%s", "profile": "lab", "admin": {"name": "labadmin", "display_name": "Lab Admin"}, "host_name": "ns1.lab.example.test", "language": "en"}' "$token" |
  in_client bash /lab/account/api.sh setup)"
[[ "${out##*$'\n'}" == 2* && -s "$work/out/cookie" ]] || fail "the setup did not sign in"

# ---------------------------------------------------------------------------------------
step "adopt"
answers=""
api POST /dns/kerberos/adopt "{\"realm\": \"lab.example.test\", \"name\": \"TENKO-DNS\$\", \"password\": \"@OTP@\", \"spns\": [\"$spn1\", \"$spn2\"], \"kdcs\": [\"198.51.100.2\"]}" ||
  fail "the adopt failed ($api_status): $api_body"
answers+="$api_body"
held="$(jqb '[.account.versions[] | select(.state == "current") | .kvno][0]')"
row adopt.taken "TENKO-DNS\$ adopted; Tenko holds version $held, the controller issues $(kvno_on_dc)" \
  test "$held" == "$(kvno_on_dc)"
row adopt.otp_gone "the one-time password gets no ticket any more" otp_refused
row finding.spn_missing "the SPN no account holds is dns.gss.spn_missing" \
  test "$(jqb '[.findings[] | select(.code == "dns.gss.spn_missing") | .params.spn] | join(",")')" == "$spn2"

in_samba samba-tool spn add "$spn2" 'TENKO-DNS$' >/dev/null
# The SPN is on the account before the self-test asks the KDC for it.
retry 30 "the controller to list $spn2" spn_listed
check
answers+="$api_body"
row check.pass "with the SPN added the self-test passes (HTTP $api_status; findings: $(details))" clean_check

in_client bash -c "kinit alice@$realm < /lab/secrets/alice >/dev/null && kvno $spn1@$realm" >"$work/out/kvno1" 2>&1 || true
row client.kvno "alice's ticket for $spn1 names version $held" grep -q "kvno = $held\$" "$work/out/kvno1"

# ---------------------------------------------------------------------------------------
step "rotation"
api POST /dns/kerberos/rotate '' || fail "the rotation did not start ($api_status): $api_body"
rotated() {
  api GET /dns/kerberos && [[ "$(jqb '[.account.versions[] | select(.state == "current") | .kvno][0]')" == "$((held + 1))" ]]
}
retry 90 "the rotation to commit" rotated
previous="$(jqb '[.account.versions[] | select(.state == "previous") | .kvno][0]')"
row rotate.moves "the version moved to $((held + 1)) on Tenko and on the controller ($(kvno_on_dc)); $previous kept as previous" \
  test "$(kvno_on_dc)" == "$((held + 1))" -a "$previous" == "$held"
in_client bash -c "klist -e" >"$work/out/klist" 2>&1 || true
row rotate.old_ticket "alice's ticket from before the rotation is still in her cache, under a version Tenko holds" \
  grep -q "$spn1@$realm" "$work/out/klist"
held=$((held + 1))

# ---------------------------------------------------------------------------------------
step "restart between the change and the commit"
# The answers of the change-password service are dropped (the TCP handshake passes, the
# segments with the answer do not; the request goes over TCP, since a ticket with a PAC is
# larger than the UDP limit), so the controller takes the new password and Tenko never
# hears it. As soon as the controller has it, the KDC's answers are dropped too, so that
# Tenko cannot learn it from a ticket either, and Tenko is killed: a restart between the
# change and the commit.
drop() { # drop <A|D> <port>
  in_samba bash -c "iptables -$1 OUTPUT -p udp --sport $2 -j DROP && iptables -$1 OUTPUT -p tcp --sport $2 -m length --length 100:65535 -j DROP"
}
drop A 464
api POST /dns/kerberos/rotate '' || fail "the second rotation did not start ($api_status)"
changed() { [[ "$(kvno_on_dc)" == "$((held + 1))" ]]; }
waited=0
until changed; do
  ((waited >= 300)) && fail "the controller did not take the new password"
  sleep 0.2
  waited=$((waited + 1))
done
drop A 88
sleep 1
api GET /dns/kerberos || true
pending_seen="$(jqb '[.account.versions[] | select(.state == "pending")] | length')"
compose kill tenko >/dev/null
api_down_state="killed after the controller moved to $((held + 1)) ($pending_seen version pending)"
drop D 464
drop D 88
compose up -d tenko >/dev/null
retry "$wait_secs" "tenko to become healthy again" healthy
recovered() {
  api GET /dns/kerberos &&
    [[ "$(jqb '[.account.versions[] | select(.state == "pending")] | length')" == 0 ]] &&
    [[ "$(jqb '[.account.versions[] | select(.state == "current") | .kvno][0]')" == "$((held + 1))" ]]
}
# The leader finishes a pending change when it takes office; the self-test does it too.
finished() { recovered || { check && recovered; }; }
retry 60 "the pending change to be finished" finished
row restart.recovered "Tenko $api_down_state; after the restart it holds $((held + 1)) as current" recovered
held=$((held + 1))

# ---------------------------------------------------------------------------------------
step "findings"
ldb_replace() { printf 'dn: CN=%s,CN=Computers,DC=lab,DC=example,DC=test\nchangetype: modify\nreplace: %s\n%s: %s\n' "$1" "$2" "$2" "$3" | in_samba ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null; }
ldb_replace TENKO-DNS msDS-SupportedEncryptionTypes 4
check
row finding.weak_etype "RC4 only is dns.gss.weak_etype ($(codes))" has_code dns.gss.weak_etype
ldb_replace TENKO-DNS msDS-SupportedEncryptionTypes 24

# A duplicate: the SPN on a second computer account, or the same host through that
# account's HOST/ SPN (Active Directory maps DNS/ to HOST/). Samba, like Windows since 2012
# R2, refuses both at the write, so its KDC never holds one; the row then says so and is
# left to the owner's Windows lab, where an older or a replicated duplicate can exist.
in_samba samba-tool computer create OTHER >/dev/null
duplicate() { # duplicate <spn>
  printf 'dn: CN=OTHER,CN=Computers,DC=lab,DC=example,DC=test\nchangetype: modify\nadd: servicePrincipalName\nservicePrincipalName: %s\n' "$1" |
    in_samba ldbmodify -H /var/lib/samba/private/sam.ldb --controls=relax:0 >"$work/out/duplicate.log" 2>&1
}
if duplicate "$spn2" || duplicate "HOST/${spn2#*/}"; then
  check
  row finding.spn_duplicate "the SPN on a second account is dns.gss.spn_duplicate ($(codes))" has_code dns.gss.spn_duplicate
else
  refusal="$(grep -m1 -iE 'error|fail|refus|constraint' "$work/out/duplicate.log" | tr -d '\r' | cut -c1-120)"
  line="$(printf 'SKIP %-22s %s' finding.spn_duplicate "the controller refuses a duplicate SPN at the write: $refusal")"
  summary+=("$line")
  printf '%s\n' "$line"
fi
in_samba samba-tool computer delete OTHER >/dev/null 2>&1 || true

printf '120' >"$work/out/skew"
rm -f "$work/out/READY"
compose restart samba >/dev/null
retry 120 "the KDC to listen again" in_samba bash -c 'echo > /dev/tcp/198.51.100.2/88'
check
row finding.clock_skew "the controller 120 s ahead is dns.gss.clock_skew ($(jqb '[.findings[] | select(.code == "dns.gss.clock_skew") | .params.skew_secs][0]') s)" \
  has_code dns.gss.clock_skew
rm -f "$work/out/skew"
compose restart samba >/dev/null
retry 120 "the KDC to listen again" in_samba bash -c 'echo > /dev/tcp/198.51.100.2/88'

in_samba samba-tool user disable 'TENKO-DNS$' >/dev/null
check
row finding.self_test "the account disabled is dns.gss.self_test_failed, reason $(jqb '[.findings[].params.reason][0]')" \
  test "$(jqb '[.findings[] | select(.code == "dns.gss.self_test_failed") | .params.reason][0]')" == disabled
in_samba samba-tool user enable 'TENKO-DNS$' >/dev/null

# ---------------------------------------------------------------------------------------
step "keytab import"
api DELETE /dns/kerberos '' || fail "the delete failed ($api_status)"
in_samba bash -c "samba-tool user setpassword 'TENKO-DNS\$' --newpassword=\"\$(cat /lab/secrets/reset)\" >/dev/null"
version="$(kvno_on_dc)"
keytab() { # keytab <kvno>: a keytab as ktpass writes it (the account and the SPN, AES-256 and AES-128)
  # The password reaches ktutil on standard input, never in an argument list.
  in_client bash -c "rm -f /tmp/tenko.keytab; for p in 'TENKO-DNS\$@$realm' '$spn1@$realm'; do for e in aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96; do
    { printf 'addent -password -p %s -k %s -e %s -s %s\n' \"\$p\" $1 \"\$e\" '$salt'; cat /lab/secrets/reset; printf '\nwkt /tmp/tenko.keytab\nq\n'; } | ktutil >/dev/null; done; done;
    base64 -w0 /tmp/tenko.keytab | tr '+/' '-_' | tr -d '='"
}
api POST /dns/kerberos/import "{\"realm\": \"$realm\", \"keytab\": \"$(keytab "$version")\", \"spns\": [\"$spn1\", \"$spn2\"], \"kdcs\": [\"198.51.100.2\"]}" ||
  fail "the import failed ($api_status): $api_body"
row import.works "the ktpass-style keytab of version $version imports and the self-test passes ($(details))" clean_check
api DELETE /dns/kerberos '' || fail "the delete failed ($api_status)"
api POST /dns/kerberos/import "{\"realm\": \"$realm\", \"keytab\": \"$(keytab "$((version + 5))")\", \"spns\": [\"$spn1\"], \"kdcs\": [\"198.51.100.2\"]}" ||
  fail "the second import failed ($api_status): $api_body"
row finding.kvno_unknown "a keytab of version $((version + 5)) is dns.gss.kvno_unknown ($(codes))" \
  has_code dns.gss.kvno_unknown

answers+="$api_body"
row adopt.no_secret "no answer carried the one-time password" no_otp

((rows_failed == 0)) || fail "$rows_failed rows failed"
