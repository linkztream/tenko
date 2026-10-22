#!/usr/bin/env bash
# Tenko DDI, container side: runs deploy/install.sh unattended with the answers that
# ../ct/tenko.sh collected on the Proxmox host. The installer does the work (the binary, the
# service account, /etc/tenko, the key-encryption key, the unit, the start, first-run
# setup); this script only maps the settings to its flags, adds curl when the binary is to
# be downloaded, and reads the secrets. ../ct/tenko.sh pushes it to /root/ with
# lib/container.sh, lib/common.sh and install.sh (and the binary, when the host was given
# one); it also runs by hand, as root, in any Debian or Ubuntu container, with install.sh
# next to it or in ../../ (a checkout). Run again, it upgrades: install.sh is idempotent.
#
# Usage (by hand, in the container, as root):
#   TENKO_INSTALL_BINARY=/root/tenko-0.2.0-linux-x86_64 bash tenko-install.sh </dev/null
#   printf '%s\n%s\n' "<github token>" "<admin password>" | TENKO_INSTALL_ADMIN=admin bash tenko-install.sh
# Settings, from the environment (ct/tenko.sh passes them as arguments to env); each one is
# the install.sh flag of the same name, and empty means the installer's default. They are
# named TENKO_INSTALL_*: a TENKO_ROLES or TENKO_KEK would be read by tenko itself as a
# configuration key.
#   TENKO_INSTALL_ROLES TENKO_INSTALL_MODULES TENKO_INSTALL_PROFILE TENKO_INSTALL_HOST_NAME
#   TENKO_INSTALL_DNS_ADDRESS TENKO_INSTALL_FORWARDERS TENKO_INSTALL_VERSION
#   TENKO_INSTALL_LANGUAGE TENKO_INSTALL_ADMIN TENKO_INSTALL_KEK
#   TENKO_INSTALL_BINARY    a binary in the container to install instead of a download
#   TENKO_INSTALL_RELEASE_URL  a release directory URL (--release-url)
# Secrets, one line each on standard input (when not set and standard input is not a
# terminal): GITHUB_TOKEN (to download while the repository is private; empty: none), then
# TENKO_ADMIN_PASSWORD (with TENKO_INSTALL_ADMIN).
#   TENKO_INSTALL_TEST=1  under the container test: no systemd, so install.sh --no-start
# Exit status: that of install.sh (0 done, 9 the node runs but setup failed; see its header).
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

TENKO_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for TENKO_LIB in "${TENKO_HERE}/container.sh" "${TENKO_HERE}/../lib/container.sh"; do
  # shellcheck source=../lib/container.sh
  [[ -f "$TENKO_LIB" ]] && source "$TENKO_LIB" && break
done
if ! declare -F tenko_container_init >/dev/null; then
  echo "tenko-install: container.sh not found next to this script or in ../lib" >&2
  exit 2
fi
tenko_container_init

installer=""
for f in "${TENKO_HERE}/install.sh" "${TENKO_HERE}/../../install.sh"; do
  if [[ -f "$f" ]]; then
    installer="$f"
    break
  fi
done
[[ -n "$installer" ]] || {
  msg_error "install.sh not found next to this script or in ../../ (deploy/ of a checkout)"
  exit 2
}

GITHUB_TOKEN="${GITHUB_TOKEN:-}"
TENKO_ADMIN_PASSWORD="${TENKO_ADMIN_PASSWORD:-}"
tenko_read_secret GITHUB_TOKEN
tenko_read_secret TENKO_ADMIN_PASSWORD
export -n GITHUB_TOKEN TENKO_ADMIN_PASSWORD

args=(--yes)
add() { [[ -n "${2:-}" ]] && args+=("$1" "$2"); return 0; }
add --roles "${TENKO_INSTALL_ROLES:-}"
add --modules "${TENKO_INSTALL_MODULES:-}"
add --profile "${TENKO_INSTALL_PROFILE:-}"
add --host-name "${TENKO_INSTALL_HOST_NAME:-}"
add --dns-address "${TENKO_INSTALL_DNS_ADDRESS:-}"
add --forwarders "${TENKO_INSTALL_FORWARDERS:-}"
add --version "${TENKO_INSTALL_VERSION:-}"
add --language "${TENKO_INSTALL_LANGUAGE:-}"
add --kek "${TENKO_INSTALL_KEK:-}"
add --binary "${TENKO_INSTALL_BINARY:-}"
add --release-url "${TENKO_INSTALL_RELEASE_URL:-}"
if [[ -n "${TENKO_INSTALL_ADMIN:-}" ]]; then
  if [[ -z "$TENKO_ADMIN_PASSWORD" ]]; then
    msg_warn "No password for ${TENKO_INSTALL_ADMIN}: setup is left to the browser"
  else
    args+=(--admin "$TENKO_INSTALL_ADMIN")
  fi
fi
if tenko_under_test; then
  args+=(--no-start)
fi

if [[ -z "${TENKO_INSTALL_BINARY:-}" ]] && ! command -v curl >/dev/null 2>&1; then
  msg_info "Installing curl, to download the release"
  tenko_apt_install curl ca-certificates
  msg_ok "Installed curl"
fi

# The secrets reach install.sh through its environment only (assignments before the
# command, in no argument list), and it drops them from the environment of what it runs.
rc=0
GITHUB_TOKEN="$GITHUB_TOKEN" TENKO_ADMIN_PASSWORD="$TENKO_ADMIN_PASSWORD" \
  bash "$installer" "${args[@]}" </dev/null || rc=$?
GITHUB_TOKEN="" TENKO_ADMIN_PASSWORD=""
exit "$rc"
