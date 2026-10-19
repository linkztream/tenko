#!/usr/bin/env bash
# The host flow of ct/tenko-ci-runner.sh under TENKO_DRY_RUN=1 var_unattended=yes: no
# Proxmox, no container, no network. pve() in lib/host.sh prints every pct, pveam, pvesm
# and pvesh command and answers the queries; this checks the printed commands, that the
# registration token and the root password appear nowhere in the output (only the size of
# what went to standard input), the by-hand registration lines without a token, the
# refusal of an invalid setting, and the one-command bootstrap against a loopback HTTP
# server (the Authorization header arrives, the token is in no curl argument).
#
# Usage:  bash deploy/proxmox/test/dry-run-test.sh     (bash, python3 and curl)
#
# License: Copyright (c) 2026. All rights reserved. See LICENSE at the repository root.

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

echo "== 5. one command: bootstrap from a loopback server"
mkdir -p "${work}/bin"
real_curl="$(command -v curl)"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"%s/curl-args.log"\nexec "%s" "$@"\n' "$work" "$real_curl" >"${work}/bin/curl"
chmod 0755 "${work}/bin/curl"
cat >"${work}/server.py" <<'EOF'
import functools, http.server, sys
directory, port_file, auth_log, expected = sys.argv[1:5]
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        got = self.headers.get("Authorization")
        state = "absent" if got is None else ("matching" if got == "Bearer " + expected else "wrong")
        with open(auth_log, "a") as f:
            f.write(f"{self.path} authorization={state}\n")
        super().do_GET()
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=directory))
with open(port_file, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
EOF
github_token="github-token-for-the-test-91b2"
python3 "${work}/server.py" "$root" "${work}/port" "${work}/auth.log" "$github_token" &
server_pid=$!
for _ in $(seq 50); do [[ -s "${work}/port" ]] && break; sleep 0.1; done
url="http://127.0.0.1:$(cat "${work}/port")"
rc=0
out="$(env -u RUNNER_TOKEN PATH="${work}/bin:${PATH}" TMPDIR="$work" TENKO_SCRIPTS_URL="$url" \
  GITHUB_TOKEN="$github_token" TENKO_DRY_RUN=1 var_unattended=yes NO_COLOR=1 \
  var_runner_version=2.338.0 var_runner_sha256="$sha" bash -c "$(cat "$ct")" </dev/null 2>&1)" || rc=$?
((rc == 0)) && pass "exit 0" || fail "exit ${rc}: $(tail -n 5 <<<"$out")"
for f in lib/common.sh lib/host.sh lib/container.sh install/tenko-ci-runner-install.sh; do
  grep -qx "/${f} authorization=matching" "${work}/auth.log" && pass "fetched ${f} with the Authorization header" ||
    fail "fetch of ${f}: $(grep -F "/${f}" "${work}/auth.log")"
done
has "$out" "/root/tenko-ci-runner-install.sh" "the fetched install script was pushed"
if grep -qF "$github_token" "${work}/curl-args.log" || grep -qF "$github_token" <<<"$out"; then
  fail "the GitHub token appeared in a curl argument or in the output"
else
  pass "the GitHub token is in none of the $(wc -l <"${work}/curl-args.log") curl argument lists and not in the output"
fi
[[ -z "$(find "$work" -mindepth 1 -maxdepth 1 -name 'tmp.*' -type d)" ]] && pass "the temporary root was removed" ||
  fail "temporary root left behind: $(find "$work" -mindepth 1 -maxdepth 1 -name "tmp.*")"
rc=0
out="$(env -u RUNNER_TOKEN -u GITHUB_TOKEN TMPDIR="$work" TENKO_SCRIPTS_URL="${url}/missing" \
  bash -c "$(cat "$ct")" </dev/null 2>&1)" || rc=$?
((rc == 2)) && pass "a failed fetch stops with exit 2" || fail "failed fetch: exit ${rc}"
has "$out" "From a checkout on this host" "the message names the checkout way"
has "$out" "In one command, with GITHUB_TOKEN" "the message names the one-command way"

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

echo "== 7. ct/tenko.sh: a download in the container with a token"
out="$(tdry GITHUB_TOKEN="$release_token" var_tenko_version=0.2.0 var_forwarders=192.0.2.1,192.0.2.2 var_roles=controller --)" || fail "exit $?"
has "$out" "TENKO_INSTALL_ROLES=controller " "the roles"
has "$out" "TENKO_INSTALL_VERSION=0.2.0 " "the version"
has "$out" "TENKO_INSTALL_FORWARDERS=192.0.2.1,192.0.2.2 " "the forwarders"
lacks "$out" "TENKO_INSTALL_BINARY=" "no binary pushed"
lacks "$out" "/root/tenko-binary" "nothing pushed as the binary"
has "$out" "(standard input: $((${#release_token} + 2)) bytes, not shown)" "the token went to standard input"
lacks "$out" "$release_token" "the token appears nowhere in the output"
has "$out" "Setup token:   pct exec 100 -- runuser -u tenko -- tenko setup token" "final line: how to read the setup token"

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

if ((failures > 0)); then
  echo "== dry run: ${failures} check(s) failed"
  exit 1
fi
echo "== dry run: all checks passed"
