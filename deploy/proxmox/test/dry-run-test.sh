#!/usr/bin/env bash
# The host flow of ct/tenko-ci-runner.sh under TENKO_DRY_RUN=1 var_unattended=yes: no
# Proxmox, no container, no network. pve() in lib/host.sh prints every pct, pveam, pvesm
# and pvesh command and answers the queries; this checks the printed commands, that the
# registration token and the root password appear nowhere in the output (only the size of
# what went to standard input), the by-hand registration lines without a token, the
# refusal of an invalid setting, and that the runner script refuses the one-command form.
# Then the flows of ct/tenko.sh, and its one-command form from the files release-files.sh
# writes, served by a loopback HTTP server: every file fetched https-only and without a
# token, a file that differs from its pin refused before anything runs, and the
# repository's copy (no pins) refusing to fetch.
#
# Usage:  bash deploy/proxmox/test/dry-run-test.sh     (bash, python3 and curl)
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
ct="${root}/ct/tenko-ci-runner.sh"
token="dummy-registration-token-5f3a9c"
password="root-password-7d21"
sha="af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32"
work="$(mktemp -d)"
server_pid=""
trap '[[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null; rm -rf "$work"' EXIT

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() {
  printf 'FAIL  %s\n' "$*"
  failures=$((failures + 1))
}
# has <output> <fixed string> <what>
has() { if grep -qF -- "$2" <<<"$1"; then pass "$3"; else fail "$3 (missing: $2)"; fi; }
lacks() { if grep -qF -- "$2" <<<"$1"; then fail "$3"; else pass "$3"; fi; }

# dry <env assignment>...: the ct/ script in a dry run, unattended, with a fixed release.
dry() {
  env -u RUNNER_TOKEN -u GITHUB_TOKEN TENKO_DRY_RUN=1 var_unattended=yes NO_COLOR=1 \
    var_runner_version=2.338.0 var_runner_sha256="$sha" TENKO_LOG="${work}/host.log" "$@" \
    bash "$ct" </dev/null 2>&1
}

echo "== 1. defaults, with a registration token"
rc=0
out="$(dry RUNNER_TOKEN="$token")" || rc=$?
grep -E '^\[dry-run\]' <<<"$out" | sed 's/^/      /'
((rc == 0)) && pass "exit 0" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
has "$out" "[dry-run] pvesh get /cluster/nextid" "next free id from pvesh"
has "$out" "[dry-run] pvesm status --content rootdir" "rootdir storages listed"
has "$out" "[dry-run] pvesm status --content vztmpl" "template storages listed"
has "$out" "[dry-run] pveam update" "pveam update"
has "$out" "[dry-run] pveam available --section system" "pveam available"
has "$out" "[dry-run] pveam download local ubuntu-24.04-standard_24.04-2_amd64.tar.zst" "newest 24.04 template downloaded"
create="$(grep -F '[dry-run] pct create ' <<<"$out")"
for opt in "pct create 100 local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst" \
  "-hostname tenko-ci-runner" "-cores 4" "-cpulimit 2" "-memory 8192" "-swap 512" "-rootfs local-lvm:120" \
  "-net0 name=eth0,bridge=vmbr0,ip=dhcp" "-unprivileged 1" "-features nesting=1,keyctl=1" \
  "-onboot 1" "-tags ci;runner" "-ostype ubuntu" "-description Tenko CI Runner"; do
  has "$create" " ${opt}" "pct create has ${opt}"
done
lacks "$create" "-password" "pct create carries no password option"
has "$out" "[dry-run] pct start 100" "pct start"
has "$out" "[dry-run] pct exec 100 -- getent hosts github.com" "waits for name resolution"
for f in common.sh container.sh tenko-ci-runner-install.sh; do
  has "$out" "/${f} /root/${f}" "pct push ${f}"
done
has "$out" "[dry-run] pct exec 100 -- env TENKO_VERBOSE=no RUNNER_VERSION=2.338.0 RUNNER_SHA256=${sha} RUNNER_LABELS=tenko-linux RUNNER_NAME=tenko-ci-runner REPO_URL=https://github.com/linkztream/tenko bash /root/tenko-ci-runner-install.sh" \
  "pct exec runs the install script with the settings"
has "$out" "(standard input: $((${#token} + 1)) bytes, not shown)" "the token went to standard input"
has "$out" "[dry-run] pct exec 100 -- rm -f /root/common.sh /root/container.sh /root/tenko-ci-runner-install.sh" "install files removed"
has "$out" "[dry-run] pct set 100 -description" "description updated"
lacks "$out" "$token" "the token appears nowhere in the output"
lacks "$(cat "${work}/host.log" 2>/dev/null)" "$token" "the token is not in the log"
has "$out" "gh variable set LINUX_RUNNER --repo linkztream/tenko --body tenko-linux" "final line: LINUX_RUNNER"
has "$out" "gh workflow enable CI --repo linkztream/tenko && gh workflow enable Release --repo linkztream/tenko" "final line: enable the workflows"
has "$out" "gh workflow run CI --repo linkztream/tenko" "final line: run CI"
has "$out" "installs the Rust toolchain, Node and Chromium" "final line: first run"
lacks "$out" "Register the runner by hand" "no by-hand registration with a token"

echo "== 2. without a token"
out="$(dry)" || fail "exit $?"
has "$out" "Register the runner by hand" "by-hand registration shown"
has "$out" "gh api -X POST repos/linkztream/tenko/actions/runners/registration-token --jq .token" "by hand: the token command"
has "$out" "cd /opt/actions-runner && sudo -u runner ./config.sh --replace --url https://github.com/linkztream/tenko --name tenko-ci-runner --labels tenko-linux --work _work" "by hand: config.sh"
has "$out" "cd /opt/actions-runner && ./svc.sh install runner && ./svc.sh start" "by hand: the service"

echo "== 3. static address, DNS, SSH key, root password"
out="$(dry var_ctid=150 var_ip=192.0.2.60/24 var_gateway=192.0.2.1 var_dns=192.0.2.53 \
  var_ssh_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyOnly test" var_password="$password")" || fail "exit $?"
create="$(grep -F '[dry-run] pct create ' <<<"$out")"
has "$create" " -net0 name=eth0,bridge=vmbr0,ip=192.0.2.60/24,gw=192.0.2.1" "static address with gateway"
has "$create" " -nameserver 192.0.2.53" "DNS server"
has "$create" " -ssh-public-keys /" "SSH key passed as a file"
has "$out" "[dry-run] pct exec 150 -- chpasswd" "root password set with chpasswd"
has "$out" "(standard input: $((${#password} + 6)) bytes, not shown)" "the password went to standard input"
lacks "$out" "$password" "the password appears nowhere in the output"

echo "== 4. an invalid setting is refused"
rc=0
out="$(dry var_ip=192.0.2.300/24)" || rc=$?
((rc == 2)) && pass "exit 2 (usage)" || fail "exit ${rc}"
has "$out" "var_ip: dhcp or a.b.c.d/nn" "names the setting"
lacks "$out" "pct create" "nothing created"

echo "== 5. one command: the runner script refuses to run outside a checkout"
mkdir -p "${work}/bin"
real_curl="$(command -v curl)"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"%s/curl-args.log"\nexec "%s" "$@"\n' "$work" "$real_curl" >"${work}/bin/curl"
chmod 0755 "${work}/bin/curl"
rc=0
out="$(env -u RUNNER_TOKEN -u GITHUB_TOKEN PATH="${work}/bin:${PATH}" TMPDIR="$work" TENKO_DRY_RUN=1 \
  var_unattended=yes NO_COLOR=1 bash -c "$(cat "$ct")" </dev/null 2>&1)" || rc=$?
((rc == 2)) && pass "exit 2" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
has "$out" "runs from a checkout only" "the message says it runs from a checkout only"
has "$out" "bash deploy/proxmox/ct/tenko-ci-runner.sh" "the message names the checkout command"
[[ ! -s "${work}/curl-args.log" ]] && pass "nothing was fetched" || fail "curl ran: $(cat "${work}/curl-args.log")"
lacks "$out" "pct create" "nothing created"

# ── ct/tenko.sh: the Tenko container ──────────────────────────────────────────────────────
tenko_ct="${root}/ct/tenko.sh"
fake_binary="${work}/tenko-0.0.1-linux-x86_64"
printf 'not a real binary\n' >"$fake_binary"
admin_password="admin-password-3e9f"
release_token="release-token-for-the-test-6a0d"
# tdry <env assignment>... -- <option>...: ct/tenko.sh in a dry run, unattended.
tdry() {
  local envs=()
  while (($#)) && [[ "$1" != -- ]]; do envs+=("$1"); shift; done
  shift
  env -u GITHUB_TOKEN -u TENKO_ADMIN_PASSWORD TENKO_DRY_RUN=1 var_unattended=yes NO_COLOR=1 \
    TENKO_LOG="${work}/tenko-host.log" "${envs[@]}" bash "$tenko_ct" "$@" </dev/null 2>&1
}

echo "== 6. ct/tenko.sh: a binary from the host, a static address, an administrator"
rc=0
out="$(tdry TENKO_ADMIN_PASSWORD="$admin_password" -- --binary "$fake_binary" --ip 192.0.2.60/24 --gw 192.0.2.1 --admin admin)" || rc=$?
grep -E '^\[dry-run\] pct (create|push|exec)' <<<"$out" | sed 's/^/      /'
((rc == 0)) && pass "exit 0" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
create="$(grep -F '[dry-run] pct create ' <<<"$out")"
for opt in "-hostname tenko" "-cores 2" "-memory 2048" "-swap 512" "-rootfs local-lvm:8" \
  "-net0 name=eth0,bridge=vmbr0,ip=192.0.2.60/24,gw=192.0.2.1" "-unprivileged 1" "-features nesting=1" \
  "-onboot 1" "-tags tenko" "-ostype ubuntu" "-description Tenko DDI"; do
  has "$create" " ${opt}" "pct create has ${opt}"
done
lacks "$create" "keyctl" "no keyctl feature"
lacks "$create" "-cpulimit" "no CPU limit"
for f in common.sh container.sh tenko-install.sh; do
  has "$out" "/${f} /root/${f}" "pct push ${f}"
done
has "$out" "/deploy/install.sh /root/install.sh" "pct push install.sh"
has "$out" "[dry-run] pct push 100 ${fake_binary} /root/tenko-binary" "pct push of the binary given on the host"
has "$out" "[dry-run] pct exec 100 -- env TENKO_VERBOSE=no TENKO_INSTALL_ROLES=controller,dns TENKO_INSTALL_MODULES=wizard TENKO_INSTALL_PROFILE=home TENKO_INSTALL_HOST_NAME=tenko TENKO_INSTALL_DNS_ADDRESS=all TENKO_INSTALL_VERSION=latest TENKO_INSTALL_LANGUAGE=en TENKO_INSTALL_KEK=auto TENKO_INSTALL_ADMIN=admin TENKO_INSTALL_BINARY=/root/tenko-binary bash /root/tenko-install.sh" \
  "pct exec runs tenko-install.sh with the answers"
has "$out" "(standard input: $((1 + ${#admin_password} + 1)) bytes, not shown)" "the password went to standard input (no token)"
has "$out" "[dry-run] pct exec 100 -- rm -f /root/common.sh /root/container.sh /root/tenko-install.sh /root/install.sh /root/tenko-binary" \
  "the pushed files are removed, the binary too"
lacks "$out" "$admin_password" "the password appears nowhere in the output"
lacks "$(cat "${work}/tenko-host.log" 2>/dev/null)" "$admin_password" "the password is not in the log"
has "$out" "Web UI:        https://192.0.2.50:8443/" "final line: the URL"
has "$out" "Administrator: admin" "final line: the administrator"
has "$out" "--update 100" "final line: the update command"

echo "== 6b. ct/tenko.sh: an administrator's password the rule refuses stops the run before the container"
for case in "481273905162|it is digits only" "Short-pw1|it is too short"; do
  bad="${case%%|*}" why="${case#*|}"
  rc=0
  out="$(tdry TENKO_ADMIN_PASSWORD="$bad" -- --binary "$fake_binary" --admin admin)" || rc=$?
  ((rc != 0)) && pass "${why}: the run fails (exit ${rc})" || fail "${why}: exit 0"
  has "$out" "TENKO_ADMIN_PASSWORD: the administrator's password is refused, ${why}" "${why}: says why"
  lacks "$out" "[dry-run] pct create" "${why}: no container is created"
  lacks "$out" "$bad" "${why}: the password appears nowhere in the output"
done

echo "== 7. ct/tenko.sh: a download in the container with a token"
out="$(tdry GITHUB_TOKEN="$release_token" var_tenko_version=0.2.0 var_forwarders=192.0.2.1,192.0.2.2 var_roles=controller --)" || fail "exit $?"
has "$out" "TENKO_INSTALL_ROLES=controller " "the roles"
has "$out" "TENKO_INSTALL_VERSION=0.2.0 " "the version"
has "$out" "TENKO_INSTALL_FORWARDERS=192.0.2.1,192.0.2.2 " "the forwarders"
lacks "$out" "TENKO_INSTALL_BINARY=" "no binary pushed"
lacks "$out" "/root/tenko-binary" "nothing pushed as the binary"
has "$out" "(standard input: $((${#release_token} + 2)) bytes, not shown)" "the token went to standard input"
lacks "$out" "$release_token" "the token appears nowhere in the output"
has "$out" "[dry-run] pct exec 100 -- bash /root/install.sh --setup-token" "the setup token is read by the installer in the container"
has "$out" "[dry-run] pct exec 100 -- rm -f /root/install.sh" "the installer pushed for the token is removed again"
lacks "$out" "runuser -u tenko" "no runuser at root's prompt"
has "$out" "Setup token:   bash deploy/proxmox/ct/tenko.sh --setup-token 100" "final line: how to read the setup token"

echo "== 7b. ct/tenko.sh --setup-token: the token of an existing container"
rc=0
out="$(tdry -- --setup-token 120)" || rc=$?
((rc == 0)) && pass "exit 0" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
has "$out" "[dry-run] pct push 120 $(dirname "$root")/install.sh /root/install.sh" "install.sh is pushed"
has "$out" "[dry-run] pct exec 120 -- bash /root/install.sh --setup-token" "the installer reads the token"
has "$out" "[dry-run] pct exec 120 -- rm -f /root/install.sh" "and is removed again"
lacks "$out" "pct create" "nothing created"
rc=0
out="$(tdry -- --setup-token abc)" || rc=$?
((rc == 2)) && pass "--setup-token needs a container ID" || fail "--setup-token abc: exit ${rc}"

echo "== 8. ct/tenko.sh: refusals"
rc=0
out="$(tdry var_roles=dns -- --binary "$fake_binary")" || rc=$?
((rc == 2)) && pass "invalid roles: exit 2" || fail "invalid roles: exit ${rc}"
has "$out" "var_roles: controller or controller,dns" "names the setting"
lacks "$out" "pct create" "nothing created"
rc=0
out="$(tdry var_dns_address=tenko.example.test -- --binary "$fake_binary")" || rc=$?
((rc == 2)) && has "$out" "var_dns_address:" "an address list with a name is refused" || fail "dns address: exit ${rc}"
rc=0
out="$(tdry -- --binary "${work}/missing")" || rc=$?
((rc == 2)) && has "$out" "var_binary: no such file on this host" "a missing binary is refused" || fail "missing binary: exit ${rc}"
rc=0
out="$(tdry -- --ip 192.0.2.60/24)" || rc=$?
((rc == 2)) && has "$out" "var_gateway: required with a static address" "--ip without --gw is refused" || fail "--ip alone: exit ${rc}"
rc=0
out="$(tdry -- --bogus x)" || rc=$?
((rc == 2)) && has "$out" "Unknown option: --bogus" "an unknown option is refused" || fail "unknown option: exit ${rc}"

echo "== 9. ct/tenko.sh --update: the installer again in an existing container"
rc=0
out="$(tdry -- --update 120 --binary "$fake_binary")" || rc=$?
((rc == 0)) && pass "exit 0" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
lacks "$out" "pct create" "nothing created"
has "$out" "[dry-run] pct push 120 ${fake_binary} /root/tenko-binary" "the binary pushed"
has "$out" "[dry-run] pct exec 120 -- env TENKO_VERBOSE=no TENKO_INSTALL_VERSION=latest TENKO_INSTALL_BINARY=/root/tenko-binary bash /root/tenko-install.sh" \
  "only the version and the binary: the container keeps its configuration"
rc=0
out="$(tdry -- --update abc)" || rc=$?
((rc == 2)) && pass "--update needs a container ID" || fail "--update abc: exit ${rc}"

echo "== 10. ct/tenko.sh in one command: the release files, each checked against its pin"
release="${work}/release"
files_out="$(bash "${root}/release-files.sh" v0.0.1 "$release" 2>&1)" && pass "release-files.sh wrote the files" ||
  fail "release-files.sh: ${files_out}"
published="${release}/tenko-proxmox.sh"
has "$(cat "$published")" "TENKO_RELEASE_TAG=v0.0.1" "the published script names its tag"
for pair in lib/common.sh:tenko-proxmox-common.sh lib/host.sh:tenko-proxmox-host.sh \
  lib/container.sh:tenko-proxmox-container.sh install/tenko-install.sh:tenko-proxmox-install.sh ../install.sh:install.sh; do
  has "$(cat "$published")" "  [${pair%%:*}]=$(sha256sum "${root}/${pair%%:*}" | cut -d' ' -f1)" "the pin of ${pair%%:*} is its SHA-256"
  cmp -s "${root}/${pair%%:*}" "${release}/${pair#*:}" && pass "${pair#*:} is ${pair%%:*}" || fail "${pair#*:} differs from ${pair%%:*}"
done
diff <(sed '/^# >>> release pins/,/^# <<< release pins/d' "${root}/ct/tenko.sh") \
  <(sed '/^# >>> release pins/,/^# <<< release pins/d' "$published") >/dev/null &&
  pass "outside the pins, tenko-proxmox.sh is ct/tenko.sh" || fail "tenko-proxmox.sh differs from ct/tenko.sh outside the pins"
# The loopback server is plain HTTP: this curl drops the two https-only options (after
# checking that the bootstrap passed them) and logs every request.
cat >"${work}/bin/curl" <<CURL
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"${work}/curl-https.log"
args=()
while ((\$#)); do
  case "\$1" in
  --proto | --proto-redir) [[ "\$2" == "=https" ]] || exit 99; shift 2 ;;
  *) args+=("\$1"); shift ;;
  esac
done
exec "${real_curl}" "\${args[@]}"
CURL
chmod 0755 "${work}/bin/curl"
cat >"${work}/serve.py" <<'EOF'
import functools, http.server, sys
directory, port_file, log = sys.argv[1:4]
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        with open(log, "a") as f:
            f.write(f"{self.path} authorization={'absent' if self.headers.get('Authorization') is None else 'present'}\n")
        super().do_GET()
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=directory))
with open(port_file, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
EOF
python3 "${work}/serve.py" "$release" "${work}/port" "${work}/requests.log" &
server_pid=$!
for _ in $(seq 50); do [[ -s "${work}/port" ]] && break; sleep 0.1; done
url="http://127.0.0.1:$(cat "${work}/port")"
# one <env assignment>... -- <option>...: the published script as bash -c runs it.
one() {
  local envs=()
  while (($#)) && [[ "$1" != -- ]]; do envs+=("$1"); shift; done
  shift
  env -u GITHUB_TOKEN -u TENKO_ADMIN_PASSWORD PATH="${work}/bin:${PATH}" TMPDIR="$work" TENKO_SCRIPTS_URL="$url" \
    TENKO_DRY_RUN=1 var_unattended=yes NO_COLOR=1 TENKO_LOG="${work}/one.log" "${envs[@]}" \
    bash -c "$(cat "$published")" bash "$@" </dev/null 2>&1
}
rc=0
out="$(one -- --binary "$fake_binary")" || rc=$?
((rc == 0)) && pass "exit 0" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
for f in tenko-proxmox-common.sh tenko-proxmox-host.sh tenko-proxmox-container.sh tenko-proxmox-install.sh install.sh; do
  grep -qx "/${f} authorization=absent" "${work}/requests.log" && pass "fetched ${f}, without a token" ||
    fail "fetch of ${f}: $(grep -F "/${f}" "${work}/requests.log")"
done
[[ "$(grep -c -- "--proto =https --proto-redir =https" "${work}/curl-https.log")" -eq 5 ]] &&
  pass "every fetch was https-only, on the request and on redirects" || fail "curl arguments: $(cat "${work}/curl-https.log")"
has "$out" "/root/tenko-install.sh" "the fetched install script was pushed"
has "$out" "/root/install.sh" "the fetched install.sh was pushed"
[[ -z "$(find "$work" -mindepth 1 -maxdepth 1 -name 'tmp.*' -type d)" ]] && pass "the temporary root was removed" ||
  fail "temporary root left behind: $(find "$work" -mindepth 1 -maxdepth 1 -name "tmp.*")"

echo "== 10b. a release file that is not the pinned one stops the run before anything is sourced"
printf '\necho TAMPERED-LIBRARY-RAN\n' >>"${release}/tenko-proxmox-host.sh"
rc=0
out="$(one -- --binary "$fake_binary")" || rc=$?
((rc == 2)) && pass "exit 2" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
has "$out" "tenko-proxmox-host.sh has the SHA-256" "the message names the file and its digest"
lacks "$out" "TAMPERED-LIBRARY-RAN" "the changed library never ran"
lacks "$out" "pct create" "nothing created"
cp "${root}/lib/host.sh" "${release}/tenko-proxmox-host.sh"

echo "== 10c. the repository's ct/tenko.sh, without pins, fetches nothing in one command"
: >"${work}/curl-https.log"
rc=0
out="$(env -u GITHUB_TOKEN PATH="${work}/bin:${PATH}" TMPDIR="$work" NO_COLOR=1 bash -c "$(cat "$tenko_ct")" </dev/null 2>&1)" || rc=$?
((rc == 2)) && pass "exit 2" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
has "$out" "carries no release pins" "the message says why"
has "$out" "releases/latest/download/tenko-proxmox.sh" "the message names the release file"
[[ ! -s "${work}/curl-https.log" ]] && pass "nothing was fetched" || fail "curl ran: $(cat "${work}/curl-https.log")"
kill "$server_pid" 2>/dev/null
server_pid=""

if ((failures > 0)); then
  echo "== dry run: ${failures} check(s) failed"
  exit 1
fi
echo "== dry run: all checks passed"
