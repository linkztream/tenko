#!/usr/bin/env bash
# Runs every check of deploy/proxmox: (a) bash -n and shellcheck over every script, (b) the
# host flow under TENKO_DRY_RUN=1 (dry-run-test.sh), (c) the install script in a throwaway
# ubuntu:24.04 Docker container (container-test.sh), (d) the unit checks of the parsers
# against the fixtures (unit-test.sh). Written for WSL or any Linux with Docker, as root.
#
# Usage:  bash deploy/proxmox/test/run.sh [--no-container]
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
  local files=() f rc=0
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
[[ -f "${here}/dry-run-test.sh" ]] && step "(b) host flow, dry run" bash "${here}/dry-run-test.sh"
[[ "${1:-}" != "--no-container" ]] && step "(c) install script in a container" bash "${here}/container-test.sh"
step "(d) unit checks" bash "${here}/unit-test.sh"

echo
echo "######## summary"
printf '%s\n' "${results[@]}"
! printf '%s\n' "${results[@]}" | grep -q '^FAIL'
