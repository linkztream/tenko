#!/usr/bin/env bash
# Runs install/tenko-ci-runner-install.sh in a throwaway ubuntu:24.04 Docker container, as
# lib/host.sh does in a Proxmox container: the two libraries and the install script in
# /root/, the settings as arguments to env, no registration token. TENKO_INSTALL_TEST=1
# tells the script that there is no systemd and no Docker daemon. Then checks what it left
# behind, and that a wrong SHA-256 is refused before anything is unpacked. The runner
# version and checksum are resolved live from the GitHub API (lib/common.sh), or taken
# from test/fixtures/runner-release.json when the API does not answer.
#
# Usage, as root where Docker runs:  bash deploy/proxmox/test/container-test.sh
#
# License: Copyright (c) 2026. All rights reserved. See LICENSE at the repository root.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
# shellcheck source=../lib/common.sh
source "${root}/lib/common.sh"
name="tenko-ci-runner-test-$$"
log="${TMPDIR:-/tmp}/${name}.log"

RUNNER_VERSION="" RUNNER_SHA256=""
if tenko_resolve_runner_release 2>/dev/null; then
  echo "== runner ${RUNNER_VERSION}, SHA-256 ${RUNNER_SHA256} (live, ${TENKO_RUNNER_SOURCE})"
else
  RUNNER_VERSION="$(tenko_release_version <"${here}/fixtures/runner-release.json")"
  RUNNER_SHA256="$(tenko_release_body <"${here}/fixtures/runner-release.json" | tenko_runner_sha256 "$RUNNER_VERSION")"
  echo "== runner ${RUNNER_VERSION}, SHA-256 ${RUNNER_SHA256} (from the fixture: the API did not answer)"
fi

docker run -d --name "$name" --hostname tenko-ci-runner-test ubuntu:24.04 sleep infinity >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker cp "${root}/lib/common.sh" "${name}:/root/common.sh"
docker cp "${root}/lib/container.sh" "${name}:/root/container.sh"
docker cp "${root}/install/tenko-ci-runner-install.sh" "${name}:/root/tenko-ci-runner-install.sh"
# The image lacks the curl that a Proxmox template ships with.
docker exec "$name" sh -c 'apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends curl ca-certificates >/dev/null'

echo "== install script (log: ${log})"
if ! docker exec -i "$name" env TENKO_INSTALL_TEST=1 RUNNER_VERSION="$RUNNER_VERSION" \
  RUNNER_SHA256="$RUNNER_SHA256" RUNNER_LABELS=tenko-linux \
  bash /root/tenko-ci-runner-install.sh </dev/null 2>&1 | tee "$log"; then
  echo "FAIL  the install script exited non-zero"
  exit 1
fi

failures=0
check() {
  local what="$1" cmd="$2" out
  if out="$(docker exec "$name" bash -c "$cmd" 2>&1)"; then
    printf 'PASS  %s%s\n' "$what" "${out:+: ${out//$'\n'/ | }}"
  else
    printf 'FAIL  %s%s\n' "$what" "${out:+: ${out//$'\n'/ | }}"
    failures=$((failures + 1))
  fi
}

echo "== checks"
packages="build-essential pkg-config cmake musl-tools git curl ca-certificates gnupg jq file unzip xz-utils iproute2 openssl python3 sudo"
# shellcheck disable=SC2016 # Expanded in the container.
check "build packages installed" \
  'missing=""; n=0; for p in '"$packages"'; do n=$((n + 1)); [ "$(dpkg-query -W -f="\${db:Status-Status}" "$p" 2>/dev/null)" = installed ] || missing="$missing $p"; done; [ -z "$missing" ] || { echo "missing:$missing"; exit 1; }; echo "$n of $n"'
check "docker --version" 'docker --version'
check "docker compose version" 'docker compose version'
check "docker buildx version" 'docker buildx version'
check "Docker's deb822 repository and keyring" 'grep -h "^URIs:\|^Signed-By:" /etc/apt/sources.list.d/docker.sources && test -s /etc/apt/keyrings/docker.gpg'
check "runner account in the docker group" 'id runner && id -nG runner | tr " " "\n" | grep -qx docker'
# shellcheck disable=SC2016 # Expanded in the container.
check "sudoers file, mode 0440, valid" 'stat -c "%a %U %n" /etc/sudoers.d/90-runner && test "$(stat -c %a /etc/sudoers.d/90-runner)" = 440 && visudo -cqf /etc/sudoers.d/90-runner'
check "runner may sudo without a password" 'sudo -l -U runner | grep -F "(ALL) NOPASSWD: ALL"'
check "runner extracted, owned by runner" 'test -x /opt/actions-runner/config.sh && test -x /opt/actions-runner/run.sh && stat -c "%U %n" /opt/actions-runner/config.sh /opt/actions-runner/bin'
check "runner version" '/opt/actions-runner/bin/Runner.Listener --version'
check "not registered (no token)" 'test ! -e /opt/actions-runner/.runner && echo "no .runner file"'
check "installdependencies.sh ran (libicu installed)" 'dpkg-query -W -f="\${Package} \${db:Status-Status}\n" "libicu*" | grep " installed$"'
check "no tarball left behind" '! ls /tmp/tmp.*/actions-runner-* 2>/dev/null && echo none'
grep -q "Installed the runner ${RUNNER_VERSION} into /opt/actions-runner (SHA-256 verified)" "$log" &&
  echo "PASS  the script reports the verified install" || {
  echo "FAIL  no verified-install line"
  failures=$((failures + 1))
}
grep -q "Installed the runner's .NET dependencies" "$log" &&
  echo "PASS  installdependencies.sh finished" || {
  echo "FAIL  installdependencies.sh did not finish"
  failures=$((failures + 1))
}

echo "== a wrong SHA-256 is refused"
rc=0
out="$(docker exec -i "$name" env TENKO_INSTALL_TEST=1 RUNNER_VERSION="$RUNNER_VERSION" \
  RUNNER_SHA256=0000000000000000000000000000000000000000000000000000000000000000 \
  RUNNER_DIR=/opt/actions-runner-bad \
  bash /root/tenko-ci-runner-install.sh </dev/null 2>&1)" || rc=$?
grep -E 'SHA-256|failed' <<<"$out" | sed 's/^/      /'
if [[ "$rc" -ne 0 ]] && grep -q "does not match the expected SHA-256" <<<"$out"; then
  echo "PASS  refused with exit ${rc}"
else
  echo "FAIL  not refused (exit ${rc})"
  failures=$((failures + 1))
fi
check "nothing unpacked for the wrong checksum" 'test ! -e /opt/actions-runner-bad/config.sh && echo "no config.sh in /opt/actions-runner-bad"'

echo "== unit checks with jq (the container has it now; the host side has none)"
docker exec "$name" mkdir -p /root/proxmox
docker cp "${root}/lib" "${name}:/root/proxmox/lib"
docker cp "${root}/test" "${name}:/root/proxmox/test"
rc=0
out="$(docker exec "$name" bash /root/proxmox/test/unit-test.sh 2>&1)" || rc=$?
grep -E '\(jq\)|^FAIL|^== unit' <<<"$out" || true
((rc == 0)) || failures=$((failures + 1))

echo "== install script output (checks)"
grep -E '(ok|!!)  (dummy links|systemd|disk|runner service|Docker|Under the test)' "$log" || true

if ((failures > 0)); then
  echo "== container test: ${failures} check(s) failed"
  exit 1
fi
echo "== container test: all checks passed"
