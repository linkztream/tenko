#!/usr/bin/env bash
# Runs every check of deploy/proxmox and of deploy/install.sh: (a) bash -n and shellcheck
# over every script, (b) the host flows of ct/tenko-ci-runner.sh and ct/tenko.sh under
# TENKO_DRY_RUN=1 (dry-run-test.sh), (c) the runner's install script in a throwaway
# ubuntu:24.04 Docker container (container-test.sh), (d) the unit checks of the parsers
# against the fixtures (unit-test.sh), (e) the checks of install.sh (install-sh-test.sh: its
# parsers always; with a binary, its Docker smokes in three distributions and, with a newer
# binary, the whole life in a systemd container), (f) the Tenko install script in a
# container (tenko-container-test.sh, with a binary), (g) the compose quick start
# (quickstart-test.sh, with an image version). Written for WSL or any Linux with Docker, as
# root.
#
# Usage:  bash deploy/proxmox/test/run.sh [--no-container]
#   TENKO_TEST_BINARY=<static musl tenko>   runs the Docker smokes of (e) and (f)
#   TENKO_TEST_NEWER=<the same, a higher version>   adds the systemd container to (e)
#   TENKO_TEST_IMAGE_VERSION=<x.y.z>   runs (g) on ghcr.io/linkztream/tenko:<x.y.z>
#
# License: Copyright (c) 2026. All rights reserved. See LICENSE at the repository root.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
proxmox="$(dirname "$here")"
repo="$(cd "${proxmox}/../.." && pwd)"
cd "$repo" || exit 1
results=()

step() {
  local name="$1"
  shift
  echo
  echo "######## ${name}"
  if "$@"; then
    results+=("PASS  ${name}")
  else
    results+=("FAIL  ${name}")
  fi
}

syntax_and_shellcheck() {
  local files=(deploy/install.sh) f rc=0
  while IFS= read -r f; do files+=("$f"); done < <(find deploy/proxmox -name '*.sh' -type f | sort)
  for f in "${files[@]}"; do
    if bash -n "$f"; then echo "bash -n ok: $f"; else echo "bash -n FAIL: $f"; rc=1; fi
  done
  if docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:stable -x -P SCRIPTDIR -S warning "${files[@]}"; then
    echo "shellcheck -x -P SCRIPTDIR -S warning: clean (${#files[@]} files)"
  else
    rc=1
  fi
  return "$rc"
}

step "(a) bash -n and shellcheck" syntax_and_shellcheck
[[ -f "${here}/dry-run-test.sh" ]] && step "(b) host flows, dry run" bash "${here}/dry-run-test.sh"
[[ "${1:-}" != "--no-container" ]] && step "(c) runner install script in a container" bash "${here}/container-test.sh"
step "(d) unit checks" bash "${here}/unit-test.sh"
if [[ -n "${TENKO_TEST_BINARY:-}" && "${1:-}" != "--no-container" ]]; then
  if [[ -n "${TENKO_TEST_NEWER:-}" ]]; then
    step "(e) install.sh: parsers, three distributions, downloads, systemd" \
      bash "${here}/install-sh-test.sh" "$TENKO_TEST_BINARY" --systemd "$TENKO_TEST_NEWER"
  else
    step "(e) install.sh: parsers, three distributions, downloads" bash "${here}/install-sh-test.sh" "$TENKO_TEST_BINARY"
  fi
  step "(f) Tenko install script in a container" bash "${here}/tenko-container-test.sh" "$TENKO_TEST_BINARY"
else
  step "(e) install.sh: parsers (TENKO_TEST_BINARY runs the Docker smokes)" bash "${here}/install-sh-test.sh" --unit
fi
if [[ -n "${TENKO_TEST_IMAGE_VERSION:-}" && "${1:-}" != "--no-container" ]]; then
  step "(g) compose quick start" bash "${here}/quickstart-test.sh" "$TENKO_TEST_IMAGE_VERSION"
fi

echo
echo "######## summary"
printf '%s\n' "${results[@]}"
! printf '%s\n' "${results[@]}" | grep -q '^FAIL'
