#!/usr/bin/env bash
# Unit checks of the parsing and validation functions of lib/, against the fixtures in
# test/fixtures/ (a release API response, `pveam available` and `pvesm status` listings).
# Runs anywhere with bash; no network, no Proxmox.
#
# Usage:  bash deploy/proxmox/test/unit-test.sh
#
# License: Copyright (c) 2026. All rights reserved. See LICENSE at the repository root.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
fixtures="${here}/fixtures"
if [[ -f "${root}/lib/host.sh" ]]; then
  # shellcheck source=../lib/host.sh
  source "${root}/lib/host.sh"
else
  # shellcheck source=../lib/common.sh
  source "${root}/lib/common.sh"
fi
# shellcheck source=../lib/container.sh
source "${root}/lib/container.sh"

failures=0
expect() {
  local what="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    printf 'PASS  %s: %s\n' "$what" "$got"
  else
    printf 'FAIL  %s: want "%s", got "%s"\n' "$what" "$want" "$got"
    failures=$((failures + 1))
  fi
}
accepts() {
  local fn="$1" value
  shift
  for value in "$@"; do
    if "$fn" "$value"; then
      printf 'PASS  %s accepts "%s"\n' "$fn" "$value"
    else
      printf 'FAIL  %s refuses "%s"\n' "$fn" "$value"
      failures=$((failures + 1))
    fi
  done
}
refuses() {
  local fn="$1" value
  shift
  for value in "$@"; do
    if "$fn" "$value"; then
      printf 'FAIL  %s accepts "%s"\n' "$fn" "$value"
      failures=$((failures + 1))
    else
      printf 'PASS  %s refuses "%s"\n' "$fn" "$value"
    fi
  done
}

echo "== runner release (lib/common.sh)"
sha_x64="af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32"
for mode in jq no-jq; do
  if [[ "$mode" == "jq" ]]; then
    command -v jq >/dev/null 2>&1 || {
      echo "SKIP  jq is not installed here"
      continue
    }
    unset TENKO_NO_JQ
  else
    export TENKO_NO_JQ=1
  fi
  expect "version from tag_name (${mode})" "2.338.0" "$(tenko_release_version <"${fixtures}/runner-release.json")"
  expect "SHA-256 of the linux-x64 tarball (${mode})" "$sha_x64" \
    "$(tenko_release_body <"${fixtures}/runner-release.json" | tenko_runner_sha256 2.338.0)"
  expect "no SHA-256 for a version the notes do not list (${mode})" "" \
    "$(tenko_release_body <"${fixtures}/runner-release.json" | tenko_runner_sha256 2.337.0)"
done
unset TENKO_NO_JQ
expect "a download line alone yields no checksum" "" \
  "$(printf 'curl -O -L https://example.org/actions-runner-linux-x64-2.338.0.tar.gz\n' | tenko_runner_sha256 2.338.0)"
expect "the arm64 line is not taken for x64" "" \
  "$(printf -- '- actions-runner-linux-arm64-2.338.0.tar.gz <!-- BEGIN SHA linux-arm64 -->%s<!-- END SHA linux-arm64 -->\n' "$sha_x64" | tenko_runner_sha256 2.338.0)"
# resolve <version> <sha256>: the status of tenko_resolve_runner_release for given values
# (no network: both are given, or the call fails before any request), and the source.
resolve() {
  local rc=0
  # shellcheck disable=SC2034 # Both are read by tenko_resolve_runner_release (lib/common.sh).
  RUNNER_VERSION="$1" RUNNER_SHA256="$2"
  TENKO_RUNNER_SOURCE=""
  tenko_resolve_runner_release >/dev/null 2>&1 || rc=$?
  printf '%s %s\n' "$rc" "$TENKO_RUNNER_SOURCE"
}
expect "a malformed checksum is refused" "1 given" "$(resolve 2.338.0 nothex)"
expect "a checksum without a version is refused" "1 " "$(resolve "" "$sha_x64")"
expect "a given version and checksum are taken, normalised" "0 given" "$(resolve v2.338.0 "${sha_x64^^}")"

echo "== jobs for the memory (lib/container.sh)"
gib=1048576
expect "28 cores, 8 GiB: four jobs of 2 GiB" "4" "$(tenko_jobs_for_memory 2048 $((8 * gib)) 28)"
expect "28 cores, 32 GiB: sixteen" "16" "$(tenko_jobs_for_memory 2048 $((32 * gib)) 28)"
expect "28 cores, 64 GiB: one per core" "28" "$(tenko_jobs_for_memory 2048 $((64 * gib)) 28)"
expect "4 cores, 1 GiB: never below one" "1" "$(tenko_jobs_for_memory 2048 $gib 4)"
expect "4 cores, 7.9 GiB: whole jobs only" "3" "$(tenko_jobs_for_memory 2048 $((8 * gib - 1)) 4)"
expect "a garbage core count counts as one" "1" "$(tenko_jobs_for_memory 2048 $((32 * gib)) none)"
expect "a garbage memory counts as none" "1" "$(tenko_jobs_for_memory 2048 none 8)"
echo "== the env file (lib/container.sh)"
envfile="$(mktemp)"
printf 'LANG=C.UTF-8\n' >"$envfile"
tenko_env_file_set "$envfile" CARGO_BUILD_JOBS 4
tenko_env_file_set "$envfile" CARGO_BUILD_JOBS 16
expect "the line replaced, the other kept" "LANG=C.UTF-8 CARGO_BUILD_JOBS=16" "$(tr '\n' ' ' <"$envfile" | sed 's/ $//')"
rm -f "$envfile"
tenko_env_file_set "$envfile" CARGO_BUILD_JOBS 2
expect "a missing file is created" "CARGO_BUILD_JOBS=2" "$(cat "$envfile")"
rm -f "$envfile"

if declare -F tenko_pick_template >/dev/null; then
  echo "== templates and storages (lib/host.sh)"
  expect "newest Ubuntu 24.04 standard amd64 template" "ubuntu-24.04-standard_24.04-10_amd64.tar.zst" \
    "$(tenko_pick_template ubuntu 24.04 <"${fixtures}/pveam-available.txt")"
  expect "no template for a version not listed" "" \
    "$(tenko_pick_template ubuntu 26.04 <"${fixtures}/pveam-available.txt")"
  expect "active rootdir storages" "local-lvm nvme-thin" \
    "$(tenko_parse_storages <"${fixtures}/pvesm-status-rootdir.txt" | tr '\n' ' ' | sed 's/ $//')"
  expect "active vztmpl storages" "local" \
    "$(tenko_parse_storages <"${fixtures}/pvesm-status-vztmpl.txt" | tr '\n' ' ' | sed 's/ $//')"

  echo "== address validation (lib/host.sh)"
  accepts tenko_valid_ip dhcp 192.0.2.10/24 198.51.100.1/32 203.0.113.254/16 192.0.2.1/8
  refuses tenko_valid_ip "" 192.0.2.10 192.0.2.256/24 192.0.2.10/33 192.0.2.10/0 192.0.2/24 \
    01.2.3.4/24 "192.0.2.10/24 " DHCP 2001:db8::1/64
  accepts tenko_valid_ipv4 192.0.2.1 0.0.0.0 255.255.255.255
  refuses tenko_valid_ipv4 192.0.2 192.0.2.1.5 256.1.1.1 192.0.2.01 a.b.c.d ""
  accepts tenko_valid_hostname tenko-ci-runner runner1 a
  refuses tenko_valid_hostname -runner runner- "two words" runner_1 "" \
    abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl
fi

if ((failures > 0)); then
  echo "== unit checks: ${failures} failed"
  exit 1
fi
echo "== unit checks: all passed"
