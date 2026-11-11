#!/usr/bin/env bash
# Writes the Proxmox and Linux installer files of a release into a directory: the release
# workflow runs it in the job `manifest` (.github/workflows/release.yml, step "The
# installers"), and the tests run it to serve the one-command form from a loopback server.
#
#   bash deploy/proxmox/release-files.sh v0.2.0 dist
#
# Writes, from this checkout:
#   tenko-proxmox.sh            ct/tenko.sh with its release pins filled in: the tag, and the
#                               SHA-256 of each file below that its bootstrap fetches
#   tenko-proxmox-common.sh     lib/common.sh
#   tenko-proxmox-host.sh       lib/host.sh
#   tenko-proxmox-container.sh  lib/container.sh
#   tenko-proxmox-install.sh    install/tenko-install.sh (what runs inside the container)
#   install.sh                  deploy/install.sh
# and prints their names. Nothing is fetched and nothing else is changed; a file that is
# already in the directory is replaced. The caller lists the files in SHA256SUMS.
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

set -euo pipefail

if (($# != 2)); then
  echo "usage: release-files.sh <tag vX.Y.Z[-pre]> <directory>" >&2
  exit 2
fi
tag="$1" out="$2"
if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release-files.sh: '${tag}' is not a tag vX.Y.Z or vX.Y.Z-<pre-release>" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$out"

# <path under deploy/proxmox> <release file>, the pairs of the bootstrap in ct/tenko.sh.
files=(
  "lib/common.sh tenko-proxmox-common.sh"
  "lib/host.sh tenko-proxmox-host.sh"
  "lib/container.sh tenko-proxmox-container.sh"
  "install/tenko-install.sh tenko-proxmox-install.sh"
  "../install.sh install.sh"
)

pins="$(mktemp)"
trap 'rm -f "$pins"' EXIT
{
  printf 'TENKO_RELEASE_TAG=%s\n' "$tag"
  printf 'declare -A TENKO_RELEASE_SHA256=(\n'
  for pair in "${files[@]}"; do
    src="${pair% *}" name="${pair#* }"
    install -m 0644 "${here}/${src}" "${out}/${name}"
    printf '  [%s]=%s\n' "$src" "$(sha256sum "${out}/${name}" | cut -d' ' -f1)"
  done
  printf ')\n'
} >"$pins"

# The block between the markers of ct/tenko.sh is replaced by the pins; the rest of the file
# is copied unchanged.
awk -v pins="$pins" '
  /^# >>> release pins/ { print; while ((getline line < pins) > 0) print line; skip = 1; next }
  /^# <<< release pins/ { skip = 0; found++ }
  !skip { print }
  END { if (found != 1) exit 1 }
' "${here}/ct/tenko.sh" >"${out}/tenko-proxmox.sh" ||
  { echo "release-files.sh: ct/tenko.sh has no release pins block" >&2; exit 1; }
chmod 0644 "${out}/tenko-proxmox.sh"
bash -n "${out}/tenko-proxmox.sh"
# The published script names this tag and every file it fetches.
grep -qx "TENKO_RELEASE_TAG=${tag}" "${out}/tenko-proxmox.sh"
test "$(grep -cE '^  \[[a-z./-]+\]=[0-9a-f]{64}$' "${out}/tenko-proxmox.sh")" -eq "${#files[@]}"

printf '%s\n' tenko-proxmox.sh
for pair in "${files[@]}"; do printf '%s\n' "${pair#* }"; done
