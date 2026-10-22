#!/usr/bin/env bash
# Container-side helpers of the Proxmox VE scripts in deploy/proxmox, for the install
# scripts in install/: strict mode with an error trap that names the failing line, apt
# without questions, a deb822 repository with its keyring, a download that is kept only
# when its SHA-256 matches, and reading a secret from standard input. Generic: nothing in
# here knows which application is installed. lib/host.sh pushes this file and common.sh
# to /root/ next to the install script; from a checkout they are found in lib/.
#
# Usage: source "<dir>/container.sh"   (then call tenko_container_init)
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

export DEBIAN_FRONTEND=noninteractive

# tenko_container_init: strict mode, the error trap, root and apt checks.
tenko_container_init() {
  set -Eeuo pipefail
  trap 'tenko_container_failed "$?" "$LINENO" "$BASH_COMMAND"' ERR
  if [[ "$(id -u)" != 0 ]]; then
    msg_error "Run as root"
    exit 2
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    msg_error "This install script needs a Debian or Ubuntu container (apt-get)"
    exit 2
  fi
}

tenko_container_failed() {
  trap - ERR
  msg_error "Install failed (exit $1) at line $2: $3"
  [[ "${STD:-}" == "tenko_quiet" ]] && msg_error "Output of the failed steps: ${TENKO_LOG}"
  exit "$1"
}

# tenko_under_test: true under the container test (TENKO_INSTALL_TEST=1), where there is no
# systemd and no Docker daemon.
tenko_under_test() { [[ "${TENKO_INSTALL_TEST:-0}" == "1" ]]; }

# tenko_apt_install <package>...: installs packages without recommends, refreshing the
# package lists once per run.
tenko_apt_install() {
  if [[ -z "${TENKO_APT_UPDATED:-}" ]]; then
    $STD apt-get update
    TENKO_APT_UPDATED=1
  fi
  $STD apt-get install -y --no-install-recommends "$@"
}

# tenko_deb822_repo <name> <key-url> <uri> <suite> <components>: the repository's key,
# dearmored, in /etc/apt/keyrings/<name>.gpg and the repository in
# /etc/apt/sources.list.d/<name>.sources, then fresh package lists. Needs curl and gnupg.
tenko_deb822_repo() {
  local name="$1" key_url="$2" uri="$3" suite="$4" components="$5" key
  install -d -m 0755 /etc/apt/keyrings
  key="$(mktemp)"
  curl -fsSL --retry 2 --connect-timeout 10 -o "$key" "$key_url"
  gpg --dearmor --yes -o "/etc/apt/keyrings/${name}.gpg" <"$key"
  rm -f "$key"
  chmod 0644 "/etc/apt/keyrings/${name}.gpg"
  cat >"/etc/apt/sources.list.d/${name}.sources" <<EOF
Types: deb
URIs: ${uri}
Suites: ${suite}
Components: ${components}
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/${name}.gpg
EOF
  $STD apt-get update
}

# tenko_verified_download <url> <sha256> <file>: downloads the file and keeps it only when
# its SHA-256 matches (sha256sum --check --strict). Returns non-zero, with a message and
# without the file, otherwise.
tenko_verified_download() {
  local url="$1" sum="$2" file="$3"
  if [[ ! "$sum" =~ ^[0-9a-f]{64}$ ]]; then
    msg_error "Not a SHA-256: '${sum}'"
    return 1
  fi
  if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 -o "$file" "$url"; then
    rm -f "$file"
    msg_error "Download failed: ${url}"
    return 1
  fi
  if ! printf '%s  %s\n' "$sum" "$file" | sha256sum --check --strict --quiet >/dev/null 2>&1; then
    rm -f "$file"
    msg_error "${url##*/} does not match the expected SHA-256; nothing was installed"
    return 1
  fi
}

# tenko_read_secret <name>: when the variable <name> is empty and standard input is not a
# terminal, reads one line from standard input into it. lib/host.sh sends secrets this way,
# so that they are in no argument list, environment or file.
tenko_read_secret() {
  local name="$1" value=""
  [[ -n "${!name:-}" ]] && return 0
  if [[ ! -t 0 ]]; then
    IFS= read -r value || true
  fi
  printf -v "$name" '%s' "$value"
}

# tenko_jobs_for_memory <mib-per-job> [<memory-kib>] [<cores>]: how many jobs of the given
# size run side by side in the memory: MemTotal of /proc/meminfo (which lxcfs limits to the
# container's share) divided by the size, at most one per core (nproc) and at least one.
# Linkers are the case: a build starts one per core, and the kernel kills them when they
# do not fit.
tenko_jobs_for_memory() {
  local per_job="$1" mem_kib="${2:-}" cores="${3:-}" jobs
  if [[ -z "$mem_kib" ]]; then
    mem_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || true)"
  fi
  if [[ -z "$cores" ]]; then
    cores="$(nproc 2>/dev/null || true)"
  fi
  [[ "$per_job" =~ ^[0-9]+$ && "$per_job" -gt 0 ]] || per_job=1
  [[ "$mem_kib" =~ ^[0-9]+$ ]] || mem_kib=0
  [[ "$cores" =~ ^[0-9]+$ && "$cores" -gt 0 ]] || cores=1
  jobs=$((mem_kib / 1024 / per_job))
  if ((jobs > cores)); then
    jobs="$cores"
  fi
  if ((jobs < 1)); then
    jobs=1
  fi
  echo "$jobs"
}

# tenko_env_file_set <file> <name> <value>: NAME=value in a file of such lines (the
# runner's .env), replacing the line of that name and keeping every other line; the file
# is created when missing, and an existing file keeps its owner and mode.
tenko_env_file_set() {
  local file="$1" name="$2" value="$3" tmp
  tmp="$(mktemp)"
  if [[ -f "$file" ]]; then
    grep -v "^${name}=" "$file" >"$tmp" || true
  fi
  printf '%s=%s\n' "$name" "$value" >>"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}
