#!/usr/bin/env bash
# Runs install/tenko-install.sh in a throwaway ubuntu:24.04 Docker container, as ct/tenko.sh
# does in a Proxmox container: the two libraries, the install script, install.sh and the
# binary in /root/, the answers as arguments to env, the secrets (an empty token, no
# password) on standard input. TENKO_INSTALL_TEST=1 tells it that there is no systemd, so
# install.sh runs with --no-start. Then checks what it left behind, runs it again (nothing
# changes), and checks that a missing install.sh is refused.
#
# Usage, as root where Docker runs:
#   bash deploy/proxmox/test/tenko-container-test.sh <tenko musl binary>
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
binary="${1:?usage: tenko-container-test.sh <tenko musl binary>}"
name="tenko-container-test-$$"
failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() {
  printf 'FAIL  %s\n' "$*"
  failures=$((failures + 1))
}
check() {
  local what="$1" cmd="$2" out
  if out="$(docker exec "$name" bash -c "$cmd" 2>&1)"; then
    pass "${what}${out:+: ${out//$'\n'/ | }}"
  else
    fail "${what}${out:+: ${out//$'\n'/ | }}"
  fi
}

docker run -d --name "$name" --hostname tenko ubuntu:24.04 sleep infinity >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker cp "${root}/lib/common.sh" "${name}:/root/common.sh"
docker cp "${root}/lib/container.sh" "${name}:/root/container.sh"
docker cp "${root}/install/tenko-install.sh" "${name}:/root/tenko-install.sh"
docker cp "${root}/../install.sh" "${name}:/root/install.sh"
docker cp "$binary" "${name}:/root/tenko-binary"

# shellcheck disable=SC2054 # The commas belong to the values.
envs=(TENKO_INSTALL_TEST=1 TENKO_VERBOSE=no TENKO_INSTALL_ROLES=controller,dns TENKO_INSTALL_MODULES=ipam,dns
  TENKO_INSTALL_PROFILE=standard TENKO_INSTALL_HOST_NAME=tenko.example.test TENKO_INSTALL_DNS_ADDRESS=all
  TENKO_INSTALL_FORWARDERS=192.0.2.1,192.0.2.2 TENKO_INSTALL_VERSION=latest TENKO_INSTALL_LANGUAGE=en TENKO_INSTALL_KEK=auto
  TENKO_INSTALL_BINARY=/root/tenko-binary)

echo "== tenko-install.sh, as ct/tenko.sh runs it"
rc=0
out="$(printf '\n\n' | docker exec -i "$name" env "${envs[@]}" bash /root/tenko-install.sh 2>&1)" || rc=$?
printf '%s\n' "$out" | sed 's/^/      /'
((rc == 0)) && pass "exit 0" || fail "exit ${rc}"
check "the binary" '/usr/local/bin/tenko --version'
check "roles and modules" 'grep -E "^(roles|modules) = " /etc/tenko/tenko.toml'
check "the profile" 'grep -A2 "^\[profile\]" /etc/tenko/tenko.toml | grep -x "name = \"standard\""'
check "the host name on the certificate" 'grep -x "host_name = \"tenko.example.test\"" /etc/tenko/tenko.toml'
check "the forwarders" 'grep -x "forwarders = \[\"192.0.2.1\", \"192.0.2.2\"\]" /etc/tenko/tenko.toml'
check "the key file (no systemd here)" 'stat -c "%a %U:%G %n" /etc/tenko/kek.key'
check "tenko config check" '/usr/local/bin/tenko config check --config /etc/tenko/tenko.toml >/dev/null && echo valid'
check "no curl was installed (a binary was given)" '! command -v curl'

echo "== again: nothing changes"
out="$(printf '\n\n' | docker exec -i "$name" env "${envs[@]}" bash /root/tenko-install.sh 2>&1)" || fail "rerun exit $?"
grep -q 'nothing was changed' <<<"$out" && pass "rerun: nothing was changed" || fail "rerun changed something"

echo "== without install.sh"
docker exec "$name" mv /root/install.sh /root/install.sh.away
rc=0
out="$(docker exec -i "$name" env "${envs[@]}" bash /root/tenko-install.sh </dev/null 2>&1)" || rc=$?
((rc == 2)) && grep -q 'install.sh not found' <<<"$out" && pass "refused with exit 2" || fail "exit ${rc}: ${out}"

if ((failures > 0)); then
  echo "== Tenko container test: ${failures} check(s) failed"
  exit 1
fi
echo "== Tenko container test: all checks passed"
