#!/usr/bin/env bash
# Tenko DDI: creates an unprivileged Ubuntu 24.04 container on a Proxmox VE host and installs
# a Tenko node in it with deploy/install.sh, unattended, from the answers given here
# (install/tenko-install.sh runs it in the container). With --update <ctid> it runs the
# installer again in an existing container, which upgrades it; run inside a Tenko
# container, it does the same there. deploy/proxmox/README.md, "The Tenko container", has
# the details.
#
# Usage, as root on the Proxmox VE host:
#   bash deploy/proxmox/ct/tenko.sh --binary /root/tenko-0.2.0-linux-x86_64    # from a checkout
#   bash deploy/proxmox/ct/tenko.sh --update 120 --binary /root/tenko-0.3.0-linux-x86_64
#   bash -c "$(curl -fsSL --proto '=https' --proto-redir '=https' \
#     https://github.com/linkztream/tenko/releases/latest/download/tenko-proxmox.sh)"
# Options: --binary <file> (pushed into the container instead of a download), --update
# <ctid>, --setup-token <ctid> (print the node's setup token and nothing else), --ip
# <a.b.c.d/nn|dhcp>, --gw <a.b.c.d>, --ctid <n>, --storage <name>, --hostname <name>,
# --admin <name>, --version <x.y.z>, --yes (no dialogs), --dry-run.
# Settings: the var_* of lib/host.sh and below; GITHUB_TOKEN (the download in the container
# from a private repository or a fork); TENKO_ADMIN_PASSWORD; TENKO_SCRIPTS_URL (a mirror of
# the release files); TENKO_DRY_RUN=1.
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

# Secrets stay variables of this shell: exported, they would reach every child process.
export -n GITHUB_TOKEN TENKO_ADMIN_PASSWORD 2>/dev/null || true

# >>> release pins: empty in the repository. deploy/proxmox/release-files.sh writes the tag and
# the SHA-256 of every file the bootstrap below fetches into the copy that a release publishes
# as tenko-proxmox.sh; the one-command form runs only with them.
TENKO_RELEASE_TAG=""
declare -A TENKO_RELEASE_SHA256=()
# <<< release pins

# >>> bootstrap: the scripts root. From a checkout, deploy/proxmox itself (and install.sh in
# deploy/); in one command, the release files of TENKO_RELEASE_TAG, each checked against its
# pin before anything runs.
TENKO_CT_SCRIPT="tenko"
TENKO_INSTALL="tenko-install"
TENKO_BOOTSTRAP_TMP=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" && -r "${BASH_SOURCE[0]}" ]]; then
  # A checkout: ct/ and lib/ sit side by side in deploy/proxmox, install.sh in deploy/.
  TENKO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
else
  # One command (bash -c "$(curl ...)"), with the release file tenko-proxmox.sh: the
  # libraries, the container's install script and install.sh are files of the same release,
  # fetched from its download directory into a temporary root (removed on exit) and kept
  # only when each has the SHA-256 pinned above. They run as root on this host, so a file
  # that differs from what the release published stops the run before it is sourced.
  # tenko-proxmox.sh itself is listed in the release's SHA256SUMS and carries a provenance
  # attestation (SECURITY.md, "Verifying a release"). No token is sent: release files are
  # public.
  if [[ -z "$TENKO_RELEASE_TAG" || ${#TENKO_RELEASE_SHA256[@]} -ne 5 ]]; then
    printf '\nThis copy of ct/%s.sh carries no release pins, so it does not fetch anything.\n' "$TENKO_CT_SCRIPT" >&2
    printf 'Run it in one of two ways (deploy/proxmox/README.md):\n' >&2
    printf '  1. From a checkout on this host:\n       bash deploy/proxmox/ct/%s.sh\n' "$TENKO_CT_SCRIPT" >&2
    printf '  2. In one command, from the release file:\n' >&2
    # shellcheck disable=SC2016 # The command is printed for the owner, not run.
    printf '       bash -c "$(curl -fsSL --proto '\''=https'\'' --proto-redir '\''=https'\'' %s)"\n' \
      "https://github.com/linkztream/tenko/releases/latest/download/tenko-proxmox.sh" >&2
    exit 2
  fi
  TENKO_SCRIPTS_URL="${TENKO_SCRIPTS_URL:-https://github.com/linkztream/tenko/releases/download/${TENKO_RELEASE_TAG}}"
  TENKO_BOOTSTRAP_TMP="$(mktemp -d)" || exit 2
  trap 'rm -rf "$TENKO_BOOTSTRAP_TMP"' EXIT
  mkdir -p "${TENKO_BOOTSTRAP_TMP}/proxmox/lib" "${TENKO_BOOTSTRAP_TMP}/proxmox/install"
  # <path under deploy/proxmox>:<release file>, as release-files.sh names them.
  for tenko_file in lib/common.sh:tenko-proxmox-common.sh lib/host.sh:tenko-proxmox-host.sh \
    lib/container.sh:tenko-proxmox-container.sh "install/${TENKO_INSTALL}.sh:tenko-proxmox-install.sh" \
    ../install.sh:install.sh; do
    tenko_url="${TENKO_SCRIPTS_URL}/${tenko_file#*:}"
    tenko_dest="${TENKO_BOOTSTRAP_TMP}/proxmox/${tenko_file%%:*}"
    tenko_want="${TENKO_RELEASE_SHA256[${tenko_file%%:*}]:-}"
    # https only, on the request and on every redirect, and no file above 4 MiB.
    if ! curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 --connect-timeout 10 \
      --max-filesize 4194304 -o "$tenko_dest" "$tenko_url" || [[ ! -s "$tenko_dest" ]]; then
      printf '\nCould not fetch %s\n' "$tenko_url" >&2
      printf 'Run this script from a checkout instead: bash deploy/proxmox/ct/%s.sh\n' "$TENKO_CT_SCRIPT" >&2
      exit 2
    fi
    tenko_got="$(sha256sum "$tenko_dest" | cut -d' ' -f1)"
    if [[ -z "$tenko_want" || "$tenko_got" != "$tenko_want" ]]; then
      printf '\n%s has the SHA-256 %s, not the %s that tenko-proxmox.sh of %s pins.\n' \
        "$tenko_url" "$tenko_got" "${tenko_want:-(none)}" "$TENKO_RELEASE_TAG" >&2
      printf 'Nothing was run. Fetch tenko-proxmox.sh again, or run from a checkout of the tag.\n' >&2
      exit 2
    fi
  done
  unset tenko_file tenko_url tenko_dest tenko_want tenko_got
  TENKO_ROOT="${TENKO_BOOTSTRAP_TMP}/proxmox"
fi
# <<< bootstrap

# ── Options: shorthands for the settings below ────────────────────────────────────────────
TENKO_UPDATE_CTID="" TENKO_TOKEN_CTID=""
while (($#)); do
  case "$1" in
  --binary) var_binary="${2:-}" ;;
  --update) TENKO_UPDATE_CTID="${2:-}" ;;
  --setup-token) TENKO_TOKEN_CTID="${2:-}" ;;
  --ip) var_ip="${2:-}" ;;
  --gw) var_gateway="${2:-}" ;;
  --ctid) var_ctid="${2:-}" ;;
  --storage) var_storage="${2:-}" ;;
  --hostname) var_hostname="${2:-}" ;;
  --admin) var_admin="${2:-}" ;;
  --version) var_tenko_version="${2:-}" ;;
  --yes) var_unattended=yes; shift; continue ;;
  --dry-run) TENKO_DRY_RUN=1; shift; continue ;;
  -h | --help)
    sed -n '2,/^# License/p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null | sed 's/^# \{0,1\}//' | grep -v '^License'
    exit 0
    ;;
  *)
    printf 'Unknown option: %s (see the header of ct/tenko.sh)\n' "$1" >&2
    exit 2
    ;;
  esac
  if [[ $# -lt 2 || -z "$2" ]]; then
    printf '%s needs a value\n' "$1" >&2
    exit 2
  fi
  shift 2
done

# shellcheck source=../lib/host.sh
source "${TENKO_ROOT}/lib/host.sh"

# ── Tenko's defaults (each one overridable from the environment) ──────────────────────────
APP="Tenko DDI"
# 2 cores and 2 GiB: the node idles at about 85 MiB; zones of a few hundred thousand records,
# DNSSEC signing and imports are what use more (README).
var_cpu="${var_cpu:-2}"
var_ram="${var_ram:-2048}"
var_swap="${var_swap:-512}"
var_disk="${var_disk:-8}"
var_hostname="${var_hostname:-tenko}"
var_tags="${var_tags:-tenko}"
var_unprivileged="${var_unprivileged:-1}"
# Nesting: systemd 255 of Ubuntu 24.04 and the unit's sandbox (PrivateTmp=, ProtectSystem=,
# its own mount namespace) need it in an unprivileged container. keyctl is not needed.
var_nesting="${var_nesting:-1}"
var_keyctl="${var_keyctl:-0}"
var_roles="${var_roles:-controller,dns}"
var_modules="${var_modules:-wizard}"
var_profile="${var_profile:-home}"
var_tenko_host="${var_tenko_host:-}"
var_dns_address="${var_dns_address:-all}"
var_forwarders="${var_forwarders:-}"
var_tenko_version="${var_tenko_version:-latest}"
var_language="${var_language:-en}"
var_admin="${var_admin:-}"
var_kek="${var_kek:-auto}"
var_binary="${var_binary:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
TENKO_ADMIN_PASSWORD="${TENKO_ADMIN_PASSWORD:-}"
TENKO_PROJECT_URL="https://github.com/linkztream/tenko"
TENKO_INSTALL_SH="$(cd "${TENKO_ROOT}/.." && pwd)/install.sh"
# shellcheck disable=SC2034 # Read by push_and_run in lib/host.sh: 9 is "runs, setup failed".
TENKO_INSTALL_OK_CODES=(0 9)
TENKO_APP_SETTINGS=(var_roles var_modules var_profile var_tenko_host var_dns_address var_forwarders
  var_tenko_version var_language var_admin var_kek var_binary)
TENKO_LABEL[var_roles]="Tenko roles (controller or controller,dns)"
TENKO_LABEL[var_modules]="Modules (wizard, all, or ipam,dns,dhcp,discovery)"
TENKO_LABEL[var_profile]="Security profile (home/standard/hardened/lab)"
TENKO_LABEL[var_tenko_host]="Tenko host name (empty: the container's)"
TENKO_LABEL[var_dns_address]="DNS addresses (all, or a list)"
TENKO_LABEL[var_forwarders]="Upstream resolvers (empty: the container's)"
TENKO_LABEL[var_tenko_version]="Tenko version (latest or x.y.z)"
TENKO_LABEL[var_language]="UI language for setup (en/sv)"
TENKO_LABEL[var_admin]="Administrator (empty: setup in the browser)"
TENKO_LABEL[var_kek]="Key-encryption key (auto/sealed/file)"
TENKO_LABEL[var_binary]="Binary on this host (empty: download)"

# ── Hooks called by tenko_main (lib/host.sh) ───────────────────────────────────────────────
# prepare: keeps the token for the download in the container (tenko_main drops
# GITHUB_TOKEN after this hook), and checks a binary given here.
prepare() {
  TENKO_RELEASE_TOKEN="$GITHUB_TOKEN"
  [[ -f "${TENKO_INSTALL_SH}" ]] || die "$TENKO_E_USAGE" "install.sh not found at ${TENKO_INSTALL_SH}"
  # Without a binary and a token the download in the container works only from a public
  # repository: ask once whether the latest release answers without one.
  TENKO_RELEASES_PUBLIC=0
  if [[ -z "$var_binary" && -z "$TENKO_RELEASE_TOKEN" ]] && ! tenko_dry &&
    curl -fsSL --proto '=https' --proto-redir '=https' -o /dev/null --connect-timeout 10 \
      "${TENKO_PROJECT_URL}/releases/latest/download/SHA256SUMS" 2>/dev/null; then
    TENKO_RELEASES_PUBLIC=1
  fi
}

# tenko_admin_secret_problem <secret>: what is wrong with the first administrator's password,
# or nothing, as install.sh checks it (admin_secret_problem): at least 12 characters and not
# digits only, in every profile. Checked here so that a refused password stops the run
# before the container is created; the server stays the authority for the rest.
tenko_admin_secret_problem() {
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    printf "it is digits only: an administrator's password is never a PIN (at least 12 characters, not digits only)"
  elif ((${#1} < 12)); then
    printf "it is too short: an administrator's password has at least 12 characters"
  fi
}

validate_settings() {
  local problem
  [[ "$var_roles" == controller || "$var_roles" == controller,dns ]] ||
    echo "var_roles: controller or controller,dns, not '${var_roles}'"
  [[ "$var_modules" =~ ^(wizard|all|(ipam|dns|dhcp|discovery)(,(ipam|dns|dhcp|discovery))*)$ ]] ||
    echo "var_modules: wizard, all, or a list of ipam,dns,dhcp,discovery, not '${var_modules}'"
  [[ "$var_profile" =~ ^(home|standard|hardened|lab)$ ]] ||
    echo "var_profile: home, standard, hardened or lab, not '${var_profile}'"
  [[ -z "$var_tenko_host" ]] || tenko_valid_hostname "$var_tenko_host" ||
    echo "var_tenko_host: not a host name: '${var_tenko_host}'"
  local addresses='^[][0-9A-Fa-f.:, ]+$'
  [[ "$var_dns_address" == all || "$var_dns_address" =~ $addresses ]] ||
    echo "var_dns_address: all, or addresses separated by commas, not '${var_dns_address}'"
  [[ -z "$var_forwarders" || "$var_forwarders" == none || "$var_forwarders" =~ $addresses ]] ||
    echo "var_forwarders: addresses separated by commas, or none, not '${var_forwarders}'"
  [[ "$var_tenko_version" =~ ^(latest|v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$ ]] ||
    echo "var_tenko_version: latest or x.y.z, not '${var_tenko_version}'"
  [[ "$var_language" == en || "$var_language" == sv ]] || echo "var_language: en or sv, not '${var_language}'"
  [[ -z "$var_admin" || "$var_admin" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$ ]] ||
    echo "var_admin: a login name, not '${var_admin}'"
  if [[ -n "$var_admin" && -n "$TENKO_ADMIN_PASSWORD" ]]; then
    problem="$(tenko_admin_secret_problem "$TENKO_ADMIN_PASSWORD")"
    [[ -z "$problem" ]] || echo "TENKO_ADMIN_PASSWORD: the administrator's password is refused, ${problem}"
  fi
  [[ "$var_kek" =~ ^(auto|sealed|file)$ ]] || echo "var_kek: auto, sealed or file, not '${var_kek}'"
  [[ -z "$var_binary" || -f "$var_binary" ]] || echo "var_binary: no such file on this host: '${var_binary}'"
  [[ -n "$var_binary" || -n "${TENKO_RELEASE_TOKEN:-}" || "${TENKO_RELEASES_PUBLIC:-0}" == 1 ]] ||
    echo "var_binary: no release can be downloaded without a token: give the binary (--binary <file>) or GITHUB_TOKEN"
  return 0
}

# before_create: the files to push, and the administrator's password when an
# administrator is named.
before_create() {
  local answer problem
  tenko_setup_push
  [[ -n "$var_admin" && -z "$TENKO_ADMIN_PASSWORD" ]] || return 0
  if tenko_unattended; then
    msg_warn "No TENKO_ADMIN_PASSWORD for ${var_admin}: setup is left to the browser"
    var_admin=""
    return 0
  fi
  while true; do
    answer="$(tenko_whiptail --title "${APP}: administrator" --passwordbox \
      "Password of ${var_admin}, the first administrator: at least 12 characters, not digits only (an administrator never signs in with a PIN).\n\nEmpty: complete setup in the browser with the setup token." 14 78)" || true
    [[ -n "$answer" ]] || break
    problem="$(tenko_admin_secret_problem "$answer")"
    [[ -n "$problem" ]] || break
    tenko_whiptail --title "${APP}: administrator" --msgbox "Refused, ${problem}." 10 78 || true
  done
  TENKO_ADMIN_PASSWORD="$answer"
  [[ -n "$answer" ]] || var_admin=""
}

# tenko_setup_push: install.sh and, when given, the binary go into the container next to the
# install script.
tenko_setup_push() {
  TENKO_PUSH_FILES=("${TENKO_INSTALL_SH}|/root/install.sh")
  if [[ -n "$var_binary" ]]; then
    TENKO_PUSH_FILES+=("${var_binary}|/root/tenko-binary")
  fi
}

install_env() {
  printf '%s\n' "TENKO_INSTALL_ROLES=${var_roles}" "TENKO_INSTALL_MODULES=${var_modules}" "TENKO_INSTALL_PROFILE=${var_profile}" \
    "TENKO_INSTALL_HOST_NAME=${var_tenko_host:-$var_hostname}" "TENKO_INSTALL_DNS_ADDRESS=${var_dns_address// /}" \
    "TENKO_INSTALL_VERSION=${var_tenko_version}" "TENKO_INSTALL_LANGUAGE=${var_language}" "TENKO_INSTALL_KEK=${var_kek}"
  [[ -n "$var_forwarders" ]] && printf 'TENKO_INSTALL_FORWARDERS=%s\n' "${var_forwarders// /}"
  [[ -n "$var_admin" ]] && printf 'TENKO_INSTALL_ADMIN=%s\n' "$var_admin"
  [[ -n "$var_binary" ]] && printf 'TENKO_INSTALL_BINARY=%s\n' /root/tenko-binary
  return 0
}

# install_stdin: the secrets, one per line: the token for the download, then the password.
install_stdin() { printf '%s\n%s\n' "${TENKO_RELEASE_TOKEN:-}" "$TENKO_ADMIN_PASSWORD"; }

after_install() {
  TENKO_RELEASE_TOKEN="" TENKO_ADMIN_PASSWORD=""
  TENKO_SETUP_TOKEN="$(tenko_setup_token_of "$var_ctid")"
  [[ "${TENKO_INSTALL_RC:-0}" == 9 ]] && msg_warn "The node runs, but first-run setup failed; complete it in the browser"
  return 0
}

# tenko_setup_token_of <ctid>: the setup token of the node in the container, or nothing
# (setup is complete, or the node has not started). The installer reads it there (`bash
# install.sh --setup-token`: as the service account, in a session of its own, reduced to
# printable characters), and what comes back is kept only in the token's own shape: four
# groups of five base32 characters.
tenko_setup_token_of() {
  local token=""
  pve pct push "$1" "$TENKO_INSTALL_SH" /root/install.sh </dev/null || return 0
  token="$(pve pct exec "$1" -- bash /root/install.sh --setup-token </dev/null 2>/dev/null || true)"
  pve pct exec "$1" -- rm -f /root/install.sh </dev/null || true
  [[ "$token" =~ ^[A-Z2-7]{5}(-[A-Z2-7]{5}){3}$ ]] && printf '%s' "$token"
  return 0
}

final_lines() {
  local address="${TENKO_CT_ADDRESS:-<address>}" again="bash deploy/proxmox/ct/tenko.sh --setup-token ${var_ctid}"
  msg_bold "  Tenko DDI"
  printf '    %-14s %s\n' "Container:" "$var_ctid (pct enter ${var_ctid})" "Address:" "$address" \
    "Web UI:" "https://${address}:8443/  (https://${var_tenko_host:-$var_hostname}:8443/ once the name resolves)"
  if [[ -n "${TENKO_UPDATING:-}" && -z "${TENKO_SETUP_TOKEN:-}" ]]; then
    :
  elif [[ -n "${TENKO_SETUP_TOKEN:-}" ]]; then
    printf '    %-14s %s\n' "Setup token:" "$TENKO_SETUP_TOKEN" "" "(changes at every start; again: ${again})"
  elif [[ -n "$var_admin" ]]; then
    printf '    %-14s %s\n' "Administrator:" "$var_admin"
  else
    printf '    %-14s %s\n' "Setup token:" "${again}   (prints it; the node writes a new one at every start while setup is open)"
  fi
  printf '    %-14s %s\n' "Upgrade:" "bash deploy/proxmox/ct/tenko.sh --update ${var_ctid} [--binary <file>]" \
    "Snapshot:" "pct snapshot ${var_ctid} installed   (before every upgrade, too)"
  echo
}

# update_script: update mode inside a Tenko container: the installer again, which upgrades.
update_script() {
  local args=(--yes) rc=0
  if [[ ! -x /usr/local/bin/tenko ]]; then
    msg_error "No ${APP} installation found in this container"
    exit 233
  fi
  [[ -n "$var_binary" ]] && args+=(--binary "$var_binary")
  [[ "$var_tenko_version" != latest ]] && args+=(--version "$var_tenko_version")
  GITHUB_TOKEN="$GITHUB_TOKEN" bash "$TENKO_INSTALL_SH" "${args[@]}" || rc=$?
  exit "$rc"
}

# tenko_update_host <ctid>: from the host, the installer again in an existing container (the
# binary pushed when one is given), with the settings it was installed with: install.sh
# keeps /etc/tenko/tenko.toml, the key and the data, and upgrades the binary.
tenko_update_host() {
  set -Eeuo pipefail
  exec 3>&1
  trap 'tenko_on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
  trap tenko_on_exit EXIT
  header
  : "${var_verbose:=no}" "${var_keep_on_failure:=yes}"
  tenko_set_std
  var_ctid="$1"
  tenko_valid_int "$var_ctid" 100 999999999 || die "$TENKO_E_USAGE" "--update: a container ID, not '${var_ctid}'"
  require_pve
  if ! tenko_dry && [[ "$(pve pct status "$var_ctid" 2>/dev/null)" != "status: running" ]]; then
    die "$TENKO_E_USAGE" "Container ${var_ctid} is not running (pct start ${var_ctid})"
  fi
  [[ -z "$var_binary" || -f "$var_binary" ]] || die "$TENKO_E_USAGE" "--binary: no such file: ${var_binary}"
  TENKO_RELEASE_TOKEN="$GITHUB_TOKEN"
  unset GITHUB_TOKEN
  var_admin="" TENKO_ADMIN_PASSWORD="" TENKO_UPDATING=1
  tenko_setup_push
  # Only what an upgrade needs: the version and the binary. Everything else stays as
  # /etc/tenko/tenko.toml in the container says.
  install_env() {
    printf 'TENKO_INSTALL_VERSION=%s\n' "$var_tenko_version"
    [[ -n "$var_binary" ]] && printf 'TENKO_INSTALL_BINARY=%s\n' /root/tenko-binary
    return 0
  }
  push_and_run
  after_install
  TENKO_CT_ADDRESS="$(pve pct exec "$var_ctid" -- ip -4 -o addr show dev eth0 scope global </dev/null 2>/dev/null |
    awk '{print $4}' | head -n 1 || true)"
  TENKO_CT_ADDRESS="${TENKO_CT_ADDRESS%/*}"
  final_lines
}

# tenko_token_host <ctid>: --setup-token from the host: the setup token of the node in the
# container on standard output, alone; exit 9 with the reason when there is none.
tenko_token_host() {
  set -Eeuo pipefail
  exec 3>&1
  trap 'tenko_on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
  trap tenko_on_exit EXIT
  : "${var_verbose:=no}"
  tenko_set_std
  var_ctid="$1"
  tenko_valid_int "$var_ctid" 100 999999999 || die "$TENKO_E_USAGE" "--setup-token: a container ID, not '${var_ctid}'"
  [[ -f "${TENKO_INSTALL_SH}" ]] || die "$TENKO_E_USAGE" "install.sh not found at ${TENKO_INSTALL_SH}"
  require_pve
  if ! tenko_dry && [[ "$(pve pct status "$var_ctid" 2>/dev/null)" != "status: running" ]]; then
    die "$TENKO_E_USAGE" "Container ${var_ctid} is not running (pct start ${var_ctid})"
  fi
  local token
  token="$(tenko_setup_token_of "$var_ctid")"
  if [[ -z "$token" ]]; then
    tenko_dry && exit 0
    die "$TENKO_E_POST_INSTALL" "No setup token in container ${var_ctid}: first-run setup is complete, or the node has not started (pct exec ${var_ctid} -- journalctl -u tenko -n 20)"
  fi
  printf '%s\n' "$token"
}

if [[ -n "$TENKO_UPDATE_CTID" ]]; then
  tenko_update_host "$TENKO_UPDATE_CTID"
  exit 0
fi
if [[ -n "$TENKO_TOKEN_CTID" ]]; then
  tenko_token_host "$TENKO_TOKEN_CTID"
  exit 0
fi
tenko_main "$@"
