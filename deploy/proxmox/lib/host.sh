#!/usr/bin/env bash
# Host-side library of the Proxmox VE scripts in deploy/proxmox: everything a ct/ script
# needs to create an LXC container and set it up with its install script. The settings
# (var_*, overridable from the environment) with a whiptail default/advanced dialog, the
# template download, pct create, the wait for the network, pushing and running the install
# script, the description and the summary, an error trap that offers to destroy a
# container this run created, and update mode when the script runs inside a container.
# Generic: nothing in here knows which application is installed. Every pct, pveam, pvesm
# and pvesh call goes through pve(), which under TENKO_DRY_RUN=1 prints the command and
# answers the queries with canned values, so the whole flow runs without Proxmox.
#
# Usage: a ct/ script sets APP, TENKO_INSTALL and its var_* defaults, defines the hooks it
# needs, sources this file and calls tenko_main. deploy/proxmox/README.md, "Writing another
# ct script", lists the contract.
#
# License: Copyright (c) 2026. All rights reserved. See LICENSE at the repository root.

TENKO_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${TENKO_LIB_DIR}/common.sh"

# ── Exit codes and failure handling ────────────────────────────────────────────────────────
TENKO_E_USAGE=2 TENKO_E_NOT_PVE=3 TENKO_E_CANCELLED=4 TENKO_E_TEMPLATE=5 TENKO_E_CREATE=6
TENKO_E_NETWORK=7 TENKO_E_INSTALL=8 TENKO_E_POST_INSTALL=9
TENKO_PHASE=1             # the exit code the error trap uses for the step that is running
TENKO_CREATED_CTID=""     # set once pct create succeeded in this run
TENKO_TMP_FILES=()        # removed on exit

tenko_dry() { [[ "${TENKO_DRY_RUN:-0}" == "1" ]]; }
tenko_unattended() { [[ "${var_unattended:-no}" == "yes" ]]; }

# die <code> <message>: the message, the offer to destroy a container created in this run,
# then exit with <code>.
die() {
  local code="$1"
  shift
  trap - ERR
  msg_error "$*"
  tenko_offer_destroy
  exit "$code"
}

tenko_on_error() {
  local rc="$1" line="$2" cmd="$3"
  trap - ERR
  msg_error "Failed at line ${line} (exit ${rc}): ${cmd}"
  [[ "${STD:-}" == "tenko_quiet" ]] && msg_error "Output of the quiet steps: ${TENKO_LOG}"
  tenko_offer_destroy
  exit "$TENKO_PHASE"
}

tenko_on_exit() {
  local f
  for f in "${TENKO_TMP_FILES[@]}"; do rm -rf "$f"; done
  [[ -n "${TENKO_BOOTSTRAP_TMP:-}" ]] && rm -rf "$TENKO_BOOTSTRAP_TMP"
  return 0
}

# tenko_offer_destroy: when this run created a container and var_keep_on_failure is not
# yes, asks whether to destroy it (default yes); unattended, it is destroyed.
tenko_offer_destroy() {
  local id="${TENKO_CREATED_CTID:-}"
  [[ -n "$id" && "${var_keep_on_failure:-no}" != "yes" ]] || return 0
  if ! tenko_unattended && [[ -t 0 ]] && command -v whiptail >/dev/null 2>&1; then
    if ! whiptail --title "${APP:-Container}: failed" --yesno \
      "Container ${id} was created in this run and is incomplete.\n\nDestroy it?" 10 64; then
      msg_warn "Kept container ${id} (pct destroy ${id} removes it)"
      return 0
    fi
  fi
  msg_info "Destroying container ${id}"
  pve pct stop "$id" >/dev/null 2>&1 || true
  if pve pct destroy "$id" >/dev/null 2>&1; then
    msg_ok "Destroyed container ${id}"
  else
    msg_warn "Could not destroy container ${id}; pct destroy ${id}"
  fi
  TENKO_CREATED_CTID=""
}

# ── pve: every Proxmox command, real or dry run ────────────────────────────────────────────
# Under TENKO_DRY_RUN=1 the command is printed to the original standard output (fd 3, opened
# by tenko_main, so that quiet steps and command substitutions do not swallow it) and the
# queries get canned answers. Standard input of a dry-run pct exec is drained and only its
# size is printed, so a secret sent there is never shown.
pve() {
  if ! tenko_dry; then
    "$@"
    return
  fi
  local out="/dev/stderr" bytes
  { true >&3; } 2>/dev/null && out="/dev/fd/3"
  printf '[dry-run] %s\n' "$*" >"$out"
  case "$1 ${2:-}" in
  "pvesh get")
    [[ "${3:-}" == "/cluster/nextid" ]] && echo "${TENKO_DRY_NEXTID:-100}"
    ;;
  "pvesm status")
    printf 'Name             Type     Status           Total            Used       Available        %%\n'
    if [[ "$*" == *"--content vztmpl"* ]]; then
      printf 'local             dir     active        98497780        12345678        86152102   12.53%%\n'
    else
      printf 'local-lvm     lvmthin     active       365760512        42314752       323445760   11.57%%\n'
    fi
    ;;
  "pveam available")
    printf 'system          debian-12-standard_12.7-1_amd64.tar.zst\n'
    printf 'system          ubuntu-24.04-standard_24.04-2_amd64.tar.zst\n'
    printf 'system          ubuntu-24.04-standard_24.04-1_amd64.tar.zst\n'
    ;;
  "pveam list")
    printf 'NAME                                                         SIZE\n'
    ;;
  "pct status")
    echo "status: running"
    ;;
  "pct exec")
    if [[ ! -t 0 ]]; then
      bytes="$(wc -c | tr -d ' ')"
      [[ "$bytes" != "0" ]] && printf '[dry-run]   (standard input: %s bytes, not shown)\n' "$bytes" >"$out"
    fi
    case "$*" in
    *" ip -4 -o addr show dev eth0"*)
      echo "2: eth0    inet ${TENKO_DRY_ADDRESS:-192.0.2.50/24} brd 192.0.2.255 scope global eth0\\       valid_lft forever preferred_lft forever"
      ;;
    *" getent hosts "*) echo "203.0.113.10    github.com" ;;
    esac
    ;;
  esac
  return 0
}

# ── Checks and header ──────────────────────────────────────────────────────────────────────
require_pve() {
  if tenko_dry; then
    msg_warn "Dry run (TENKO_DRY_RUN=1): Proxmox commands are printed, not run"
    return 0
  fi
  [[ "$(id -u)" == 0 ]] || die "$TENKO_E_NOT_PVE" "Run as root on the Proxmox VE host"
  local cmd
  for cmd in pveversion pct pveam pvesm pvesh; do
    command -v "$cmd" >/dev/null 2>&1 || die "$TENKO_E_NOT_PVE" "Not a Proxmox VE host: ${cmd} is missing"
  done
  if ! tenko_unattended; then
    command -v whiptail >/dev/null 2>&1 || die "$TENKO_E_NOT_PVE" "whiptail is missing (it ships with Proxmox VE); or set var_unattended=yes"
  fi
}

header() {
  local title="  ${APP:-Container}  " rule
  rule="$(printf '%*s' "${#title}" '' | tr ' ' '=')"
  printf '\n  %s\n  %s\n  %s\n\n' "$rule" "$title" "$rule"
}

# ── Parsers and validators (unit-tested against test/fixtures/) ───────────────────────────
# tenko_pick_template <os> <version>: from a `pveam available` listing on standard input,
# the newest <os>-<version>-standard amd64 .tar.zst template.
tenko_pick_template() {
  local re="^${1}-${2//./\\.}-standard_[^ ]*_amd64\\.tar\\.zst\$"
  awk '{print $NF}' | grep -E "$re" | sort -V | tail -n 1 || true
}

# tenko_parse_storages: the active storages of a `pvesm status` listing on standard input.
tenko_parse_storages() { awk 'NR > 1 && $3 == "active" {print $1}'; }

tenko_valid_ipv4() {
  local ip="$1" octet IFS=.
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  for octet in $ip; do
    [[ "$octet" == "0" || "$octet" =~ ^[1-9][0-9]*$ ]] || return 1
    ((octet <= 255)) || return 1
  done
}

# tenko_valid_ip: "dhcp" or an IPv4 address with a prefix length from 1 to 32.
tenko_valid_ip() {
  [[ "$1" == "dhcp" ]] && return 0
  [[ "$1" =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || return 1
  local prefix="${BASH_REMATCH[2]}"
  tenko_valid_ipv4 "${BASH_REMATCH[1]}" && [[ "$prefix" =~ ^[1-9][0-9]?$ ]] && ((prefix <= 32))
}

# tenko_valid_hostname: one or more DNS labels (letters, digits, inner hyphens, 1-63 each).
tenko_valid_hostname() {
  local label IFS=.
  [[ -n "$1" && ${#1} -le 253 && "$1" != *..* && "$1" != .* && "$1" != *. ]] || return 1
  for label in $1; do
    [[ ${#label} -le 63 && "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}

tenko_valid_int() { [[ "$1" =~ ^[0-9]+$ ]] && (($1 >= $2)) && { [[ -z "${3:-}" ]] || (($1 <= $3)); }; }
tenko_valid_flag() { [[ "$1" == "0" || "$1" == "1" ]]; }
tenko_valid_yes_no() { [[ "$1" == "yes" || "$1" == "no" ]]; }
tenko_in_list() {
  local want="$1" item
  shift
  for item in "$@"; do [[ "$item" == "$want" ]] && return 0; done
  return 1
}

# ── Settings ───────────────────────────────────────────────────────────────────────────────
# The generic settings, in dialog order. A ct/ script appends its own to TENKO_APP_SETTINGS
# and labels them in TENKO_LABEL.
TENKO_SETTINGS=(var_ctid var_hostname var_storage var_template_storage var_bridge var_ip
  var_gateway var_dns var_cpu var_cpulimit var_ram var_swap var_disk var_os var_version var_unprivileged
  var_nesting var_keyctl var_fuse var_onboot var_tags var_password var_ssh_key var_verbose
  var_keep_on_failure)
declare -gA TENKO_LABEL=(
  [var_ctid]="Container ID" [var_hostname]="Host name" [var_storage]="Root disk storage"
  [var_template_storage]="Template storage" [var_bridge]="Network bridge"
  [var_ip]="IPv4 address (dhcp or a.b.c.d/nn)" [var_gateway]="Gateway (with a static address)"
  [var_dns]="DNS servers (optional)" [var_cpu]="CPU cores"
  [var_cpulimit]="CPU limit (cores of CPU time; 0: none)" [var_ram]="Memory (MiB)"
  [var_swap]="Swap (MiB)" [var_disk]="Root disk (GB)" [var_os]="OS" [var_version]="OS version"
  [var_unprivileged]="Unprivileged (1/0)" [var_nesting]="Nesting (1/0)" [var_keyctl]="Keyctl (1/0)"
  [var_fuse]="FUSE (1/0)" [var_onboot]="Start on boot (1/0)" [var_tags]="Tags (a;b)"
  [var_password]="Root password (empty: none)" [var_ssh_key]="SSH public key or file (optional)"
  [var_verbose]="Verbose output (yes/no)" [var_keep_on_failure]="Keep on failure (yes/no)"
)
TENKO_APP_SETTINGS=()
TENKO_STORAGES=() TENKO_TEMPLATE_STORAGES=() TENKO_BRIDGES=()

# tenko_slug <text>: lowercase, runs of other characters as one hyphen.
tenko_slug() { tr '[:upper:]' '[:lower:]' <<<"$1" | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'; }

tenko_list_bridges() {
  if tenko_dry; then
    echo "vmbr0"
  else
    ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//'
  fi
}

tenko_default_settings() {
  : "${var_ctid:=$(pve pvesh get /cluster/nextid)}"
  : "${var_hostname:=$(tenko_slug "${APP:-container}")}"
  mapfile -t TENKO_STORAGES < <(pve pvesm status --content rootdir | tenko_parse_storages)
  mapfile -t TENKO_TEMPLATE_STORAGES < <(pve pvesm status --content vztmpl | tenko_parse_storages)
  mapfile -t TENKO_BRIDGES < <(tenko_list_bridges)
  [[ -z "${var_storage:-}" && ${#TENKO_STORAGES[@]} -eq 1 ]] && var_storage="${TENKO_STORAGES[0]}"
  [[ -z "${var_template_storage:-}" && ${#TENKO_TEMPLATE_STORAGES[@]} -eq 1 ]] &&
    var_template_storage="${TENKO_TEMPLATE_STORAGES[0]}"
  : "${var_storage:=}" "${var_template_storage:=}"
  : "${var_bridge:=vmbr0}" "${var_ip:=dhcp}" "${var_gateway:=}" "${var_dns:=}"
  : "${var_cpu:=1}" "${var_cpulimit:=0}" "${var_ram:=1024}" "${var_swap:=512}" "${var_disk:=8}"
  : "${var_os:=ubuntu}" "${var_version:=24.04}" "${var_unprivileged:=1}" "${var_nesting:=1}"
  : "${var_keyctl:=1}" "${var_fuse:=0}" "${var_onboot:=1}" "${var_tags:=}" "${var_password:=}"
  : "${var_ssh_key:=}" "${var_verbose:=no}" "${var_keep_on_failure:=no}"
  tenko_set_std
}

# tenko_validate_settings: prints one line per invalid setting; true when there is none.
tenko_validate_settings() {
  local errors=() d
  if tenko_valid_int "$var_ctid" 100 999999999; then
    if ! tenko_dry && { compgen -G "/etc/pve/nodes/*/lxc/${var_ctid}.conf" ||
      compgen -G "/etc/pve/nodes/*/qemu-server/${var_ctid}.conf"; } >/dev/null; then
      errors+=("var_ctid: ${var_ctid} is in use")
    fi
  else
    errors+=("var_ctid: a number from 100 up, not '${var_ctid}'")
  fi
  tenko_valid_hostname "$var_hostname" || errors+=("var_hostname: not a host name: '${var_hostname}'")
  if [[ -z "$var_storage" ]]; then
    errors+=("var_storage: required; one of: ${TENKO_STORAGES[*]:-none found}")
  elif ! tenko_in_list "$var_storage" "${TENKO_STORAGES[@]}"; then
    errors+=("var_storage: '${var_storage}' is not an active storage for containers (${TENKO_STORAGES[*]:-none found})")
  fi
  if [[ -z "$var_template_storage" ]]; then
    errors+=("var_template_storage: required; one of: ${TENKO_TEMPLATE_STORAGES[*]:-none found}")
  elif ! tenko_in_list "$var_template_storage" "${TENKO_TEMPLATE_STORAGES[@]}"; then
    errors+=("var_template_storage: '${var_template_storage}' is not an active template storage (${TENKO_TEMPLATE_STORAGES[*]:-none found})")
  fi
  tenko_in_list "$var_bridge" "${TENKO_BRIDGES[@]}" ||
    errors+=("var_bridge: '${var_bridge}' is not a bridge on this host (${TENKO_BRIDGES[*]:-none found})")
  if ! tenko_valid_ip "$var_ip"; then
    errors+=("var_ip: dhcp or a.b.c.d/nn, not '${var_ip}'")
  elif [[ "$var_ip" != "dhcp" ]] && ! tenko_valid_ipv4 "$var_gateway"; then
    errors+=("var_gateway: required with a static address, an IPv4 address, not '${var_gateway}'")
  elif [[ "$var_ip" == "dhcp" && -n "$var_gateway" ]]; then
    errors+=("var_gateway: only with a static address (var_ip is dhcp)")
  fi
  for d in ${var_dns//,/ }; do
    tenko_valid_ipv4 "$d" || errors+=("var_dns: not an IPv4 address: '${d}'")
  done
  tenko_valid_int "$var_cpu" 1 512 || errors+=("var_cpu: a number of cores from 1, not '${var_cpu}'")
  if [[ "$var_cpulimit" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    # Proxmox takes a fraction of cores; the limit cannot exceed the cores of the container.
    awk -v l="$var_cpulimit" -v c="$var_cpu" 'BEGIN { exit !(l <= c) }' ||
      errors+=("var_cpulimit: at most the ${var_cpu} cores of the container, not '${var_cpulimit}'")
  else
    errors+=("var_cpulimit: cores of CPU time such as 2 or 1.5, 0 for no limit, not '${var_cpulimit}'")
  fi
  tenko_valid_int "$var_ram" 256 || errors+=("var_ram: MiB, 256 or more, not '${var_ram}'")
  tenko_valid_int "$var_swap" 0 || errors+=("var_swap: MiB, 0 or more, not '${var_swap}'")
  tenko_valid_int "$var_disk" 2 || errors+=("var_disk: GB, 2 or more, not '${var_disk}'")
  [[ "$var_os" =~ ^[a-z]+$ ]] || errors+=("var_os: a template name such as ubuntu, not '${var_os}'")
  [[ "$var_version" =~ ^[0-9]+(\.[0-9]+)?$ ]] || errors+=("var_version: such as 24.04, not '${var_version}'")
  local f
  for f in var_unprivileged var_nesting var_keyctl var_fuse var_onboot; do
    tenko_valid_flag "${!f}" || errors+=("${f}: 1 or 0, not '${!f}'")
  done
  [[ -z "$var_tags" || "$var_tags" =~ ^[A-Za-z0-9_+.-]+(\;[A-Za-z0-9_+.-]+)*$ ]] ||
    errors+=("var_tags: tags separated by ';', not '${var_tags}'")
  [[ -z "$var_password" || ${#var_password} -ge 5 ]] || errors+=("var_password: 5 characters or more")
  if [[ -n "$var_ssh_key" && ! -r "$var_ssh_key" && ! "$var_ssh_key" =~ ^(ssh-|ecdsa-|sk-) ]]; then
    errors+=("var_ssh_key: neither a readable file nor a public key")
  fi
  tenko_valid_yes_no "$var_verbose" || errors+=("var_verbose: yes or no, not '${var_verbose}'")
  tenko_valid_yes_no "$var_keep_on_failure" || errors+=("var_keep_on_failure: yes or no, not '${var_keep_on_failure}'")
  if declare -F validate_settings >/dev/null; then
    mapfile -t -O "${#errors[@]}" errors < <(validate_settings)
  fi
  ((${#errors[@]} == 0)) && return 0
  printf '%s\n' "${errors[@]}"
  return 1
}

# tenko_settings_text: every setting with its value, one per line, the password hidden.
tenko_settings_text() {
  local name value
  for name in "${TENKO_SETTINGS[@]}" "${TENKO_APP_SETTINGS[@]}"; do
    value="${!name:-}"
    [[ "$name" == "var_password" ]] && value="$([[ -n "$value" ]] && echo "(set)" || echo "(none)")"
    printf '%-36s %s\n' "${TENKO_LABEL[$name]:-$name}:" "${value:-(none)}"
  done
}

tenko_whiptail() { whiptail --backtitle "${APP:-Container} - Proxmox VE" "$@" 3>&1 1>&2 2>&3; }

# tenko_ask <name>: asks for one setting, prefilled with its value; a cancel ends the run.
tenko_ask() {
  local name="$1" label="${TENKO_LABEL[$1]:-$1}" value="${!1:-}" answer items=() s choices
  case "$name" in
  var_storage | var_template_storage | var_bridge)
    case "$name" in
    var_storage) choices="TENKO_STORAGES" ;;
    var_template_storage) choices="TENKO_TEMPLATE_STORAGES" ;;
    *) choices="TENKO_BRIDGES" ;;
    esac
    local -n list="$choices"
    if ((${#list[@]} > 1)); then
      for s in "${list[@]}"; do items+=("$s" ""); done
      answer="$(tenko_whiptail --title "$label" --default-item "$value" --menu "$label" 16 64 8 "${items[@]}")" ||
        die "$TENKO_E_CANCELLED" "Cancelled"
      printf -v "$name" '%s' "$answer"
      return 0
    fi
    ;;
  var_password)
    answer="$(tenko_whiptail --title "$label" --passwordbox "${label}\n\nEmpty: no root password (use pct enter)." 12 64)" ||
      die "$TENKO_E_CANCELLED" "Cancelled"
    printf -v "$name" '%s' "$answer"
    return 0
    ;;
  esac
  answer="$(tenko_whiptail --title "$label" --inputbox "$label" 10 64 "$value")" ||
    die "$TENKO_E_CANCELLED" "Cancelled"
  printf -v "$name" '%s' "$answer"
}

# defaults_or_advanced: shows every setting; "Create" takes them, "Advanced" asks each one
# in turn, prefilled. var_unattended=yes takes them as they are and fails on invalid ones.
defaults_or_advanced() {
  local errors name rc
  if tenko_unattended; then
    if ! errors="$(tenko_validate_settings)"; then
      printf '%s\n' "$errors" | sed 's/^/      /' >&2
      die "$TENKO_E_USAGE" "Invalid or missing settings (var_unattended=yes)"
    fi
    return 0
  fi
  while true; do
    rc=0
    tenko_whiptail --title "${APP}: settings" --yes-button "Create" --no-button "Advanced" \
      --yesno "$(tenko_settings_text)" $((${#TENKO_SETTINGS[@]} + ${#TENKO_APP_SETTINGS[@]} + 8)) 78 || rc=$?
    if ((rc == 255)); then
      die "$TENKO_E_CANCELLED" "Cancelled"
    elif ((rc == 0)); then
      if errors="$(tenko_validate_settings)"; then
        return 0
      fi
      tenko_whiptail --title "Invalid settings" --msgbox "$errors" 20 78 || true
      continue
    fi
    for name in "${TENKO_SETTINGS[@]}" "${TENKO_APP_SETTINGS[@]}"; do
      tenko_ask "$name"
    done
    tenko_set_std
    if ! errors="$(tenko_validate_settings)"; then
      tenko_whiptail --title "Invalid settings" --msgbox "$errors" 20 78 || true
    fi
  done
}

# ── The container ──────────────────────────────────────────────────────────────────────────
ensure_template() {
  TENKO_PHASE=$TENKO_E_TEMPLATE
  local name
  msg_info "Looking for the ${var_os} ${var_version} template"
  $STD pve pveam update || msg_warn "pveam update failed; using the cached template list"
  name="$(pve pveam available --section system | tenko_pick_template "$var_os" "$var_version")"
  [[ -n "$name" ]] || die "$TENKO_E_TEMPLATE" "No ${var_os}-${var_version}-standard amd64 template in pveam available"
  TENKO_TEMPLATE="${var_template_storage}:vztmpl/${name}"
  if pve pveam list "$var_template_storage" | awk '{print $1}' | grep -qxF "$TENKO_TEMPLATE"; then
    msg_ok "Template ${name} is on ${var_template_storage}"
  else
    msg_info "Downloading ${name} to ${var_template_storage}"
    $STD pve pveam download "$var_template_storage" "$name" ||
      die "$TENKO_E_TEMPLATE" "Could not download ${name}"
    msg_ok "Downloaded ${name}"
  fi
}

tenko_description() {
  printf '%s. Created %s by deploy/proxmox/ct/%s.sh from %s.%s' "$APP" "$(date -u +%Y-%m-%d)" \
    "${TENKO_CT_SCRIPT:-$(tenko_slug "$APP")}" "${TENKO_PROJECT_URL:-https://github.com/linkztream/tenko}" \
    "${TENKO_CT_ADDRESS:+ Address: ${TENKO_CT_ADDRESS}.}"
}

create_container() {
  TENKO_PHASE=$TENKO_E_CREATE
  local net="name=eth0,bridge=${var_bridge},ip=${var_ip}" features=() opts key
  [[ "$var_ip" != "dhcp" ]] && net+=",gw=${var_gateway}"
  [[ "$var_nesting" == "1" ]] && features+=("nesting=1")
  [[ "$var_keyctl" == "1" ]] && features+=("keyctl=1")
  [[ "$var_fuse" == "1" ]] && features+=("fuse=1")
  opts=(-hostname "$var_hostname" -cores "$var_cpu" -memory "$var_ram" -swap "$var_swap"
    -rootfs "${var_storage}:${var_disk}" -net0 "$net" -unprivileged "$var_unprivileged"
    -onboot "$var_onboot" -ostype "$var_os" -description "$(tenko_description)")
  # A CPU limit keeps a container that is busy for hours (a build runner) from taking the
  # whole host; 0 means none, which pct also takes as the default.
  [[ "$var_cpulimit" != "0" ]] && opts+=(-cpulimit "$var_cpulimit")
  ((${#features[@]} > 0)) && opts+=(-features "$(IFS=,; echo "${features[*]}")")
  [[ -n "$var_tags" ]] && opts+=(-tags "$var_tags")
  [[ -n "$var_dns" ]] && opts+=(-nameserver "${var_dns//,/ }")
  if [[ -n "$var_ssh_key" ]]; then
    if [[ -r "$var_ssh_key" ]]; then
      opts+=(-ssh-public-keys "$var_ssh_key")
    else
      key="$(mktemp)"
      TENKO_TMP_FILES+=("$key")
      printf '%s\n' "$var_ssh_key" >"$key"
      opts+=(-ssh-public-keys "$key")
    fi
  fi
  msg_info "Creating container ${var_ctid} (${var_hostname})"
  $STD pve pct create "$var_ctid" "$TENKO_TEMPLATE" "${opts[@]}" ||
    die "$TENKO_E_CREATE" "pct create failed for container ${var_ctid}"
  TENKO_CREATED_CTID="$var_ctid"
  msg_ok "Created container ${var_ctid} (${var_hostname})"
}

start_and_wait() {
  TENKO_PHASE=$TENKO_E_NETWORK
  local deadline addr=""
  msg_info "Starting container ${var_ctid} and waiting for its network"
  $STD pve pct start "$var_ctid" || die "$TENKO_E_NETWORK" "pct start ${var_ctid} failed"
  deadline=$((SECONDS + ${TENKO_WAIT_SECONDS:-120}))
  while ((SECONDS < deadline)); do
    addr="$(pve pct exec "$var_ctid" -- ip -4 -o addr show dev eth0 scope global </dev/null 2>/dev/null |
      awk '{print $4}' | head -n 1 || true)"
    if [[ -n "$addr" ]] && pve pct exec "$var_ctid" -- getent hosts github.com </dev/null >/dev/null 2>&1; then
      TENKO_CT_ADDRESS="${addr%/*}"
      msg_ok "Container ${var_ctid} is up at ${TENKO_CT_ADDRESS}, and resolves names"
      if [[ -n "$var_password" ]]; then
        # chpasswd reads the password on standard input: it is in no argument list.
        printf 'root:%s\n' "$var_password" | pve pct exec "$var_ctid" -- chpasswd ||
          die "$TENKO_E_NETWORK" "Could not set the root password"
      fi
      return 0
    fi
    sleep 2
  done
  die "$TENKO_E_NETWORK" "No IPv4 address on eth0 or no name resolution in container ${var_ctid} after ${TENKO_WAIT_SECONDS:-120} s"
}

# push_and_run: pushes lib/common.sh, lib/container.sh and install/<TENKO_INSTALL>.sh to
# /root/, runs the install script with the settings of the install_env hook as KEY=value
# arguments to env and the output of the install_stdin hook (the secrets) on its standard
# input, and removes the files again. An exit status outside TENKO_INSTALL_OK_CODES fails
# the run; the status is kept in TENKO_INSTALL_RC for the after_install hook.
push_and_run() {
  TENKO_PHASE=$TENKO_E_INSTALL
  local root="${TENKO_ROOT:-$(dirname "$TENKO_LIB_DIR")}" envs=() line f rc=0
  local files=("${TENKO_LIB_DIR}/common.sh" "${TENKO_LIB_DIR}/container.sh" "${root}/install/${TENKO_INSTALL}.sh")
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || die "$TENKO_E_INSTALL" "Missing ${f}"
    pve pct push "$var_ctid" "$f" "/root/${f##*/}" || die "$TENKO_E_INSTALL" "pct push of ${f##*/} failed"
  done
  envs+=("TENKO_VERBOSE=${var_verbose}")
  if declare -F install_env >/dev/null; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && envs+=("$line")
    done < <(install_env)
  fi
  msg_info "Running ${TENKO_INSTALL}.sh in container ${var_ctid}"
  if declare -F install_stdin >/dev/null; then
    install_stdin | pve pct exec "$var_ctid" -- env "${envs[@]}" bash "/root/${TENKO_INSTALL}.sh" || rc=$?
  else
    pve pct exec "$var_ctid" -- env "${envs[@]}" bash "/root/${TENKO_INSTALL}.sh" </dev/null || rc=$?
  fi
  pve pct exec "$var_ctid" -- rm -f /root/common.sh /root/container.sh "/root/${TENKO_INSTALL}.sh" </dev/null ||
    msg_warn "Could not remove the install files from /root/ in container ${var_ctid}"
  # shellcheck disable=SC2034 # Read by the after_install hook of the ct/ script.
  TENKO_INSTALL_RC="$rc"
  tenko_in_list "$rc" "${TENKO_INSTALL_OK_CODES[@]:-0}" ||
    die "$TENKO_E_INSTALL" "${TENKO_INSTALL}.sh failed in container ${var_ctid} (exit ${rc})"
  msg_ok "Ran ${TENKO_INSTALL}.sh in container ${var_ctid}"
}

set_description() {
  TENKO_PHASE=$TENKO_E_POST_INSTALL
  pve pct set "$var_ctid" -description "$(tenko_description)" ||
    msg_warn "Could not update the description of container ${var_ctid}"
}

summary() {
  echo
  msg_bold "  ${APP} is ready"
  printf '    %-12s %s\n' "Container:" "$var_ctid" "Host name:" "$var_hostname" \
    "Address:" "${TENKO_CT_ADDRESS:-unknown}" "Console:" "pct enter ${var_ctid}"
  echo
}

# tenko_in_container: true inside an LXC container (update mode).
tenko_in_container() { [[ "$(systemd-detect-virt -c 2>/dev/null || true)" == "lxc" ]]; }

tenko_hook() { if declare -F "$1" >/dev/null; then "$1"; fi; }

# tenko_main: the whole flow; a ct/ script calls it last.
tenko_main() {
  set -Eeuo pipefail
  exec 3>&1
  trap 'tenko_on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
  trap tenko_on_exit EXIT
  [[ -n "${APP:-}" && -n "${TENKO_INSTALL:-}" ]] || die "$TENKO_E_USAGE" "The ct/ script must set APP and TENKO_INSTALL"
  header
  if ! tenko_dry && tenko_in_container; then
    declare -F update_script >/dev/null || die "$TENKO_E_USAGE" "${APP}: no update for this container"
    update_script
    exit 0
  fi
  require_pve
  tenko_default_settings
  tenko_hook prepare
  # The token for raw.githubusercontent.com and the API serves the fetches up to here only.
  unset GITHUB_TOKEN
  defaults_or_advanced
  tenko_hook before_create
  ensure_template
  create_container
  start_and_wait
  push_and_run
  TENKO_PHASE=$TENKO_E_POST_INSTALL
  tenko_hook after_install
  set_description
  summary
  tenko_hook final_lines
  TENKO_CREATED_CTID=""
}
