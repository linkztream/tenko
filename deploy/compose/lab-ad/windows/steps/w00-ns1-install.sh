#!/usr/bin/env bash
# W0, the Tenko node (README.md section W0), on ns1 as root.
#
# Expects: a plain Ubuntu 24.04 server with the address 192.0.2.53; the release media under
# /root/lab/media/ as the job copies them (tenko, the release's single Linux binary under a
# fixed name; install.sh; SHA256SUMS); the secret tenko_admin_password.
# Leaves: Tenko installed by its installer (roles controller,dns, module dns, profile
# Standard, host name ns1.corp.example.test, forwarders none, administrator admin);
# systemd-timesyncd following dc1 (192.0.2.5), as the runbook's names section asks; root's
# copy of the CA root in /root/lab/ca-root.pem; and the unattended access of the later steps:
#   - the administrator's second factor. Standard requires one for administrators (TGL-02),
#     and the routes the later steps need refuse a password-only session. This step enrolls
#     TOTP through the API as a person would in the UI and keeps the seed and the recovery
#     codes in /root/lab/secrets/ (tenko_admin_totp, tenko_admin_recovery_codes);
#   - root's API token from `tenko login` (/root/lab/secrets/tenko-credentials.json);
#   - a service account `lab-reader` with the viewer role and a token with the scopes
#     `metrics` and `audit:read` (/root/lab/secrets/tenko_reader_token): the reads of the
#     later steps, which keep working after W9 moves the profile to Hardened, where an
#     administrator signs in with a passkey only.
# Keeps: w0-node.txt (version, diagnostics, dig), install.txt (the installer's output, the
# setup token line removed), release-name.txt (the release file name the binary's hash has in
# SHA256SUMS), ca-root.pem and ca-root-sha256.txt.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }

say "the release media against SHA256SUMS"
for f in tenko install.sh SHA256SUMS; do need_file "$MEDIA/$f" "the job copies the release media in"; done
command -v python3 >/dev/null || fail "python3 is missing (stock Ubuntu Server has it)"
command -v dig >/dev/null || fail "dig is missing (bind9-dnsutils, stock on Ubuntu Server)"
hash="$(sha256sum "$MEDIA/tenko" | cut -d' ' -f1)"
mapfile -t names < <(awk -v h="$hash" '{ n = $2; sub(/^\*/, "", n) } $1 == h && n ~ /-linux-x86_64$/ { print n }' "$MEDIA/SHA256SUMS")
((${#names[@]} == 1)) || fail "SHA256SUMS has ${#names[@]} lines with the binary's hash and a -linux-x86_64 name, not one"
printf '%s\n' "${names[0]}" >"$STEP_DIR/release-name.txt"
version="${names[0]#tenko-}"
version="${version%-linux-x86_64}"
hash="$(sha256sum "$MEDIA/install.sh" | cut -d' ' -f1)"
awk -v h="$hash" '{ n = $2; sub(/^\*/, "", n) } $1 == h && n == "install.sh" { found = 1 } END { exit !found }' "$MEDIA/SHA256SUMS" ||
  fail "install.sh does not match its line in SHA256SUMS"
chown root:root "$MEDIA"/*
chmod 700 "$MEDIA/tenko"

say "dc1 as the time source"
systemctl cat systemd-timesyncd >/dev/null 2>&1 || fail "systemd-timesyncd is not installed"
# The helper's umask is 077 and the time service does not run as root: without 755 it cannot
# read the directory and ignores the file.
install -d -m 755 /etc/systemd/timesyncd.conf.d
# dc1 keeps time from its own clock and says so with a root dispersion of about ten seconds,
# above the service's default limit of five; and it serves time only from W1 on, so the first
# tries fail and the service must not back off for half an hour.
printf '[Time]\nNTP=192.0.2.5\nFallbackNTP=\nRootDistanceMaxSec=30\nPollIntervalMaxSec=64\n' >/etc/systemd/timesyncd.conf.d/lab-dc1.conf
chmod 644 /etc/systemd/timesyncd.conf.d/lab-dc1.conf
timedatectl set-ntp true
systemctl restart systemd-timesyncd
timedatectl show-timesync --property=SystemNTPServers --value | grep -qx '192.0.2.5' ||
  fail "systemd-timesyncd did not take dc1 as its server (timedatectl show-timesync)"

say "the installer"
rc=0
bash "$MEDIA/install.sh" --yes --binary "$MEDIA/tenko" --roles controller,dns --modules dns \
  --profile standard --host-name ns1.corp.example.test --forwarders none --admin admin \
  --password-stdin <"$(secret tenko_admin_password)" 2>&1 |
  sed -E 's/(Setup token:).*/\1 (removed)/' >"$STEP_DIR/install.txt" || rc=$?
((rc == 0)) || fail "install.sh exited with status $rc (install.txt)"

say "root's copy of the CA root"
# As the installer does it: the service account reads its own file, root keeps the PEM.
setsid -w runuser -u tenko -- cat /var/lib/tenko/tls/ca-root.pem </dev/null 2>/dev/null |
  tr -cd '\n[:print:]' >"$CA"
grep -qx -- '-----BEGIN CERTIFICATE-----' "$CA" || fail "the node's CA root could not be read"
cp "$CA" "$STEP_DIR/ca-root.pem"
openssl x509 -in "$CA" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f' >"$STEP_DIR/ca-root-sha256.txt"
for ((i = 0; i < 60; i++)); do curl -fsS --cacert "$CA" "$TENKO_URL/api/v1/health/ready" >/dev/null && break; sleep 5; done
curl -fsS --cacert "$CA" "$TENKO_URL/api/v1/health/ready" >/dev/null || fail "the API is not ready after five minutes"

say "the administrator's second factor"
rm -f "$LAB/totp-last-step"
session_login
answer="$(api session POST /auth/totp/enroll/start)"
[[ "$(py '"%s/%s/%s" % (v["params"]["algorithm"], v["params"]["digits"], v["params"]["period"])' <<<"$answer")" == sha1/6/30 ]] ||
  fail "the TOTP parameters are not HMAC-SHA1, six digits, 30 s, which this lab's code generator computes"
py 'v["secret"]' <<<"$answer" >"$SECRETS/tenko_admin_totp"
enrollment="$(py 'v["enrollment_id"]' <<<"$answer")"
[[ "$enrollment" =~ ^[A-Za-z0-9_-]+$ ]] || fail "the enrollment answered an unexpected id"
answer="$(api session POST /auth/totp/enroll/finish <(printf '{"enrollment_id":"%s","code":"%s"}' "$enrollment" "$(totp_code)"))"
py 'v.get("recovery_codes") or []' <<<"$answer" >"$SECRETS/tenko_admin_recovery_codes"
unset answer
session_login

say "the lab reader"
account="$(api session POST /access/service-accounts \
  <(printf '{"name":"lab-reader","display_name":"Lab reader","roles":["viewer"]}') | py 'v["id"]')"
api session POST "/access/service-accounts/$account/tokens" \
  <(printf '{"name":"lab-reader","expires_in_days":30,"grants":[{"role":"viewer"}],"scopes":["metrics","audit:read"]}') |
  py 'v["token"]' >"$SECRETS/tenko_reader_token"

say "the administrator's token for the command line"
# The code is ready before the login starts: a login of 0.0.12-rc.4 that waits for it longer
# than the server keeps the idle connection (30 s) sends it over the closed connection.
code="$(totp_code)"
password_file="$(secret tenko_admin_password)"
{ head -n 1 "$password_file"; printf '%s\n' "$code"; } |
  tenko login --user admin --password-stdin --token-name lab-ns1-root
unset code

say "the node"
{
  tenko --version
  tenko system diagnostics
  dig +time=2 +tries=3 @192.0.2.53 ns1.corp.example.test A
} >"$STEP_DIR/w0-node.txt" 2>&1 || fail "a command of W0 failed (w0-node.txt)"
grep -q -- "$version" "$STEP_DIR/w0-node.txt" || fail "tenko --version does not name $version"
grep -qi standard "$STEP_DIR/w0-node.txt" || fail "the diagnostics do not name the profile standard"
grep -q 'status: \(NOERROR\|NXDOMAIN\|REFUSED\)' "$STEP_DIR/w0-node.txt" || fail "dig got no answer from 192.0.2.53"
tenko_read dns zone list >/dev/null || fail "the lab reader's token cannot list the zones"

step "Tenko $version installed with profile standard, roles controller,dns; the DNS role answers"
