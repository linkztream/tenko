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
#   - a service account `lab-reader` with the viewer role, enrolled as an integration by
#     docs/integrations.md section 5.1 (label ns1): its key and certificate in
#     /root/lab/secrets/tenko_reader_client.pem, the root of the integration listener in
#     tenko_reader_ca.pem, and a token bound to the certificate with the scopes `metrics` and
#     `audit:read` in tenko_reader_token. These are the reads of the later steps, on the
#     integration listener (port 8445 by default, open while a certificate is valid). They
#     keep working after W9 moves the profile to Hardened, where an administrator signs in
#     with a passkey only and every unbound service-account token is removed. The
#     certificate lasts 30 days (Standard; Hardened's 7 days apply at its next renewal), as
#     long as the token: a run of hours needs no renewal.
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
for ((i = 0; i < 60; i++)); do curl -fsS --max-time 10 --cacert "$CA" "$TENKO_URL/api/v1/health/ready" >/dev/null && break; sleep 5; done
curl -fsS --max-time 10 --cacert "$CA" "$TENKO_URL/api/v1/health/ready" >/dev/null || fail "the API is not ready after five minutes"

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

say "the lab reader's enrollment"
account="$(api session POST /access/service-accounts \
  <(printf '{"name":"lab-reader","display_name":"Lab reader","roles":["viewer"]}') | py 'v["id"]')"
# The code is a credential: from the answer to a root-only file, never to the log.
api session POST /integrations/enrollments <(printf '{"account":"%s","lifetime_secs":600}' "$account") |
  py 'v["code"]' >"$SECRETS/reader-enroll.code"
IFS=. read -r prefix code_id code_account code_secret fingerprint <"$SECRETS/reader-enroll.code"
[[ "$prefix" == tnki && "$code_account" == "$account" ]] || fail "the enrollment answered no code for lab-reader"
cd "$SECRETS"
curl -fsS --cacert "$CA" "$TENKO_URL/api/v1/integrations/ca" -o tenko_reader_ca.pem
[[ "$(openssl x509 -in tenko_reader_ca.pem -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')" == "$fingerprint" ]] ||
  fail "the root of the integration listener does not match the enrollment code"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out reader.key
openssl req -new -key reader.key -subj /CN=tenko-integration -outform DER -out reader.csr
openssl req -in reader.csr -inform DER -noout -pubkey | openssl pkey -pubin -outform DER -out reader.spki
# The secret reaches Python on standard input, never as an argument.
proof="$(printf '%s\n' "$code_secret" | python3 -c 'import hashlib,hmac,sys
key=bytes.fromhex(sys.stdin.readline().strip())
head=("tenko-integration-enroll-v1\n%s\n%s\n%s\n" % tuple(sys.argv[1:4])).encode()
print(hmac.new(key, head + open(sys.argv[4], "rb").read(), hashlib.sha256).hexdigest())' "$code_id" "$account" ns1 reader.spki)"
unset code_secret
status="$(printf 'header = "Content-Type: application/pkcs10"\nheader = "Tenko-Enrollment-Code: %s"\nheader = "Tenko-Enrollment-Proof: %s"\n' "$code_id" "$proof" |
  curl -sS --cacert tenko_reader_ca.pem -K - --data-binary @reader.csr -o reader.crt -w '%{http_code}' \
    "$TENKO_URL/api/v1/integrations/enroll?label=ns1")"
[[ "$status" == 201 ]] || fail "the enrollment was refused ($status): $(cat reader.crt)"
cat reader.key reader.crt >tenko_reader_client.pem
rm -f reader.key reader.csr reader.spki reader.crt reader-enroll.code
cd - >/dev/null

say "the lab reader's bound token"
lineage="$(api session GET "/integrations/certificates?account=$account" | py 'v["items"][0]["lineage"]')"
api session POST "/access/service-accounts/$account/tokens" \
  <(printf '{"name":"lab-reader","expires_in_days":30,"grants":[{"role":"viewer"}],"scopes":["metrics","audit:read"],"lineage":"%s"}' "$lineage") |
  py 'v["token"]' >"$SECRETS/tenko_reader_token"
[[ "$(<"$SECRETS/tenko_reader_token")" == tnkb_* ]] || fail "the lab reader's token is not bound to its certificate"

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
zone_table >/dev/null || fail "the lab reader cannot list the zones through the integration listener"

step "Tenko $version installed with profile standard, roles controller,dns; the DNS role answers; the lab reader reads with its certificate and bound token"
