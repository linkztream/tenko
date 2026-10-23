#!/usr/bin/env bash
# Tenko DDI installer for Linux: one command from a fresh machine to a running node, and the
# same command again to upgrade it. For Debian 12, Ubuntu 24.04 and RHEL 9 compatibles on
# x86_64 with systemd; the release binary is static, so other distributions with systemd 250
# or later work too. deploy/README.md, section "Install in one command", has the details.
#
# Usage, as root:
#   bash install.sh                                   # asks a few questions
#   bash install.sh --yes --roles controller,dns      # unattended, flags for the answers
#   bash install.sh --binary ./tenko-0.2.0-linux-x86_64   # a local binary instead of a download
#   bash install.sh --uninstall [--purge]
# Download it first and run the file (`curl -fsSLO <url>/install.sh && bash install.sh`);
# piped into bash it cannot ask questions. `bash install.sh --help` lists every option.
#
# What it does: checks the host (root, x86_64, systemd and its version, the tools, free
# ports 8443, 53 and, with the dhcp role, UDP 67), gets the binary (the GitHub release asset
# tenko-<version>-linux-x86_64, verified against the release's SHA256SUMS, or --binary),
# installs it as /usr/local/bin/tenko, creates the service account `tenko`, writes
# /etc/tenko/tenko.toml from the answers and checks it with `tenko config check`, creates
# the key-encryption key (sealed with
# systemd-creds where that works, a plain file /etc/tenko/kek.key with a warning where it
# does not), installs the unit of deploy/systemd/tenko.service (embedded below) with its
# drop-ins, starts it, waits for `tenko health`, optionally completes first-run setup, and
# prints the URL, the setup token, and where the data and the key are.
#
# Run again: a newer version is an upgrade (`tenko upgrade check` with the new binary on the
# stopped node, then the new binary as /usr/local/bin/tenko and a start, which switches the
# updates layout; docs/upgrades.md section 7.3). The data directory and the key are never
# touched. The same version changes nothing and says so; missing pieces are put back.
#
# Exit statuses:
#   0  done, or nothing to change
#   1  an unexpected failure
#   2  usage: an unknown option or an invalid value
#   3  this host is not supported: not root, not x86_64, no systemd, a tool is missing
#   4  a port that the node needs is taken by another program
#   5  the binary could not be downloaded or does not match SHA256SUMS
#   6  the configuration is invalid (tenko config check)
#   7  the service did not start or did not become ready
#   8  the upgrade was refused (tenko upgrade check), nothing was changed
#   9  first-run setup failed (the node runs; complete setup in the browser)
#  10  cancelled at a question
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

# Validators are called by name (check_or_die), and /etc/os-release is the host's.
# shellcheck disable=SC1091,SC2329
set -Eeuo pipefail
umask 077

readonly E_FAIL=1 E_USAGE=2 E_HOST=3 E_PORT=4 E_DOWNLOAD=5 E_CONFIG=6 E_START=7 E_UPGRADE=8
readonly E_SETUP=9 E_CANCEL=10

# ── Fixed paths (the unit names them) ───────────────────────────────────────────────────────
readonly BIN=/usr/local/bin/tenko
readonly ETC=/etc/tenko
readonly CONFIG=/etc/tenko/tenko.toml
readonly KEK_CRED=/etc/tenko/kek.cred
readonly KEK_FILE=/etc/tenko/kek.key
readonly STATE_FILE=/etc/tenko/installer.state
readonly UNIT=/etc/systemd/system/tenko.service
readonly DROPIN_DIR=/etc/systemd/system/tenko.service.d
readonly DROPIN_KEK=/etc/systemd/system/tenko.service.d/kek-file.conf
readonly DROPIN_DATA=/etc/systemd/system/tenko.service.d/data-dir.conf
readonly DROPIN_PROBE=/etc/systemd/system/tenko.service.d/probe.conf
readonly RESOLVED_DROPIN=/etc/systemd/resolved.conf.d/tenko.conf
readonly RESOLV_CONF=/etc/resolv.conf
readonly RESOLV_MARK='# Written by the Tenko installer (--use-self)'
readonly LOG_DIR=/var/log/tenko
readonly DEFAULT_DATA_DIR=/var/lib/tenko
readonly API_PORT_DEFAULT=8443

# ── Options ─────────────────────────────────────────────────────────────────────────────────
OPT_YES=0 OPT_DRY=0 OPT_NO_START=0 OPT_RECONFIGURE=0 OPT_UNINSTALL=0 OPT_PURGE=0
OPT_ROLES="" OPT_MODULES="" OPT_PROFILE="" OPT_HOST="" OPT_DNS_ADDRESS="" OPT_FORWARDERS=""
OPT_DATA_DIR="" OPT_VERSION="" OPT_LANGUAGE="" OPT_ADMIN="" OPT_PASSWORD_STDIN=0
OPT_BINARY="" OPT_TOKEN="" OPT_REPO="" OPT_RELEASE_URL="" OPT_KEK="" OPT_KEEP_STUB=0 OPT_USE_SELF=0
SET_ROLES=0 SET_MODULES=0 SET_FORWARDERS=0 SET_DNS_ADDRESS=0 SET_ADMIN=0

usage() {
  cat <<'EOF'
Usage: bash install.sh [options]          as root

Answers (asked when --yes is not given; the default is in brackets):
  --roles controller[,dns][,dhcp][,probe]   roles of the node [controller,dns]; the dhcp role
                                      needs [dhcp] listen in tenko.toml, see deploy/README.md,
                                      section "DHCP". The probe role probes an address before
                                      the dhcp role offers it (conflict detection) and runs the
                                      discovery scans; with it the installer puts the drop-in
                                      probe.conf (CAP_NET_RAW, for ARP and the raw scan
                                      methods; ICMP needs nothing) next to the unit, and
                                      --reconfigure --roles without it removes the drop-in
  --modules all|<list>|wizard         product modules: ipam,dns,dhcp,discovery; wizard leaves
                                      the choice to first-run setup [wizard]
  --profile home|standard|hardened|lab   security profile [home]
  --host-name <name>                  the name clients use, not an address [hostname -f]
  --dns-address all|<addr>[,<addr>]   where the dns role answers, port 53 unless given [all]
  --forwarders <addr>[,<addr>]        upstream resolvers for names outside the zones, or
                                      none [the host's resolvers, loopback excluded]
  --data-dir <path>                   the data directory, on SSD or NVMe [/var/lib/tenko]
  --version latest|<x.y.z>            the release to install [latest]
  --language en|sv                    default UI language, for --admin [en]
  --admin <name>                      complete first-run setup with this administrator; the
                                      password from --password-stdin or TENKO_ADMIN_PASSWORD.
                                      Without it, setup happens in the browser with the token
  --password-stdin                    read the administrator's password from standard input

The binary:
  --binary <file>                     install this file instead of downloading a release
  --token <token>                     GitHub token for a private repository (or GITHUB_TOKEN)
  --repo <owner/name>                 the GitHub repository [linkztream/tenko]
  --release-url <url>                 a directory URL with SHA256SUMS and the binary, instead of
                                      GitHub (a mirror)

Behaviour:
  -y, --yes                           unattended: no questions, defaults for what is not given
  --kek auto|sealed|file              the key-encryption key: sealed with systemd-creds, a plain
                                      file, or sealed where that works [auto]
  --keep-resolved-stub                never turn off systemd-resolved's stub listener on port 53
  --use-self                          with the dns role: point this host's own resolver at Tenko
                                      (127.0.0.1) once the node listens; --uninstall restores
                                      the previous resolver [asked in interactive mode, default no]
  --reconfigure                       write /etc/tenko/tenko.toml again from the answers (the old
                                      file is kept as tenko.toml.<time>.bak)
  --no-start                          everything except enabling and starting the service
  --dry-run                           print every step, change nothing
  --uninstall                         remove the service and the binary; keep data, key, config
  --purge                             with --uninstall: also the data, the key, the configuration
                                      and the service account
  -h, --help                          this text

Exit statuses: 0 done, 1 failure, 2 usage, 3 unsupported host, 4 port taken, 5 download or
checksum, 6 configuration, 7 start, 8 upgrade refused, 9 setup failed, 10 cancelled.
EOF
}

# ── Messages ────────────────────────────────────────────────────────────────────────────────
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_BLUE=$'\e[36m' C_BOLD=$'\e[1m' C_OFF=$'\e[0m'
else
  C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_BOLD="" C_OFF=""
fi
info() { printf '  %s..%s  %s\n' "$C_BLUE" "$C_OFF" "$*"; }
ok() { printf '  %sok%s  %s\n' "$C_GREEN" "$C_OFF" "$*"; }
warn() { printf '  %s!!%s  %s\n' "$C_YELLOW" "$C_OFF" "$*"; }
err() { printf '  %sxx%s  %s\n' "$C_RED" "$C_OFF" "$*" >&2; }
bold() { printf '%s%s%s\n' "$C_BOLD" "$*" "$C_OFF"; }
die() {
  local code="$1"
  shift
  err "$*"
  exit "$code"
}
have() { command -v "$1" >/dev/null 2>&1; }
# same_file <a> <b>: the same bytes (sha256sum is in coreutils; minimal images lack cmp).
same_file() { [[ "$(sha256sum <"$1")" == "$(sha256sum <"$2")" ]]; }

TMP=""
cleanup() { [[ -n "$TMP" ]] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT
trap 'err "Failed at line ${LINENO}: ${BASH_COMMAND}"; exit "$E_FAIL"' ERR

# ── Dry run: every change goes through run or put ───────────────────────────────────────────
CHANGED=0
# run <command>...: runs the command, or prints it in a dry run.
run() {
  CHANGED=$((CHANGED + 1))
  if ((OPT_DRY)); then
    printf '  [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}
# put <file> <mode> <owner:group>: writes standard input to the file through a temporary
# file in the same directory, unless the file already has exactly that content and mode.
# Returns 0 when it wrote (or would write), 1 when nothing changed.
put() {
  local file="$1" mode="$2" owner="$3" tmp
  tmp="$(mktemp "${TMP}/put.XXXXXX")"
  cat >"$tmp"
  if [[ -f "$file" ]] && same_file "$tmp" "$file" &&
    [[ "$(stat -c '%a %U:%G' "$file")" == "${mode#0} ${owner}" ]]; then
    rm -f "$tmp"
    return 1
  fi
  CHANGED=$((CHANGED + 1))
  if ((OPT_DRY)); then
    printf '  [dry-run] write %s (mode %s, %s, %s lines)\n' "$file" "$mode" "$owner" "$(wc -l <"$tmp")"
    rm -f "$tmp"
    return 0
  fi
  install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$tmp" "${file}.new"
  mv -f "${file}.new" "$file"
  rm -f "$tmp"
  return 0
}

# as_tenko <command>...: runs the command as the service account.
as_tenko() {
  if have runuser; then
    runuser -u tenko -- "$@"
  elif have setpriv; then
    setpriv --reuid=tenko --regid=tenko --init-groups -- "$@"
  else
    su -s /bin/sh tenko -c "$(printf '%q ' "$@")"
  fi
}

# ── Questions ───────────────────────────────────────────────────────────────────────────────
TTY=""
use_whiptail() { [[ -n "$TTY" ]] && have whiptail && [[ -n "${TERM:-}" && "$TERM" != "dumb" ]]; }
cancelled() { die "$E_CANCEL" "Cancelled; nothing was changed"; }

# ask <var> <question> <default>: one line of text.
ask() {
  local var="$1" q="$2" def="$3" ans=""
  if use_whiptail; then
    ans="$(whiptail --title "Tenko DDI" --inputbox "$q" 12 76 "$def" 3>&1 1>&2 2>&3 <"$TTY")" || cancelled
  else
    printf '%s\n  [%s]: ' "$q" "$def" >"$TTY"
    IFS= read -r ans <"$TTY" || cancelled
    [[ -z "$ans" ]] && ans="$def"
  fi
  printf -v "$var" '%s' "$ans"
}

# ask_menu <var> <question> <default> <choice> <text> ...: one of the choices.
ask_menu() {
  local var="$1" q="$2" def="$3" ans="" items=() i
  shift 3
  items=("$@")
  if use_whiptail; then
    ans="$(whiptail --title "Tenko DDI" --default-item "$def" --menu "$q" 18 76 8 "${items[@]}" \
      3>&1 1>&2 2>&3 <"$TTY")" || cancelled
  else
    printf '%s\n' "$q" >"$TTY"
    for ((i = 0; i < ${#items[@]}; i += 2)); do
      printf '    %-20s %s\n' "${items[i]}" "${items[i + 1]}" >"$TTY"
    done
    printf '  [%s]: ' "$def" >"$TTY"
    IFS= read -r ans <"$TTY" || cancelled
    [[ -z "$ans" ]] && ans="$def"
  fi
  printf -v "$var" '%s' "$ans"
}

# ask_yes_no <question> <default yes|no>: true for yes.
ask_yes_no() {
  local q="$1" def="$2" ans="" flags=()
  if ((OPT_YES)); then
    [[ "$def" == "yes" ]]
    return
  fi
  if use_whiptail; then
    [[ "$def" == "no" ]] && flags=(--defaultno)
    whiptail --title "Tenko DDI" "${flags[@]}" --yesno "$q" 14 76 <"$TTY" 2>/dev/null
    return
  fi
  printf '%s\n  [%s]: ' "$q" "$def" >"$TTY"
  IFS= read -r ans <"$TTY" || cancelled
  ans="${ans:-$def}"
  [[ "${ans,,}" == y || "${ans,,}" == yes ]]
}

# ask_secret <var> <question>: twice, hidden, until both agree.
ask_secret() {
  local var="$1" q="$2" a="" b=""
  while true; do
    if use_whiptail; then
      a="$(whiptail --title "Tenko DDI" --passwordbox "$q" 10 76 3>&1 1>&2 2>&3 <"$TTY")" || cancelled
      b="$(whiptail --title "Tenko DDI" --passwordbox "Again, to confirm" 10 76 3>&1 1>&2 2>&3 <"$TTY")" || cancelled
    else
      printf '%s: ' "$q" >"$TTY"
      IFS= read -rs a <"$TTY" || cancelled
      printf '\nAgain, to confirm: ' >"$TTY"
      IFS= read -rs b <"$TTY" || cancelled
      printf '\n' >"$TTY"
    fi
    if [[ -n "$a" && "$a" == "$b" ]]; then
      printf -v "$var" '%s' "$a"
      return 0
    fi
    printf 'The two entries differ or are empty; again.\n' >"$TTY"
  done
}

# ── Validation ──────────────────────────────────────────────────────────────────────────────
valid_ipv4() {
  local ip="$1" o IFS=.
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  for o in $ip; do
    [[ "$o" == 0 || "$o" =~ ^[1-9][0-9]*$ ]] && ((o <= 255)) || return 1
  done
}
valid_ipv6() { [[ "$1" =~ ^[0-9A-Fa-f:.]+$ && "$1" == *:*:* && "$1" != *:::* ]]; }
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535)); }
valid_hostname() {
  local label IFS=.
  [[ -n "$1" && ${#1} -le 253 && "$1" != *..* && "$1" != .* && "$1" != *. ]] || return 1
  valid_ipv4 "$1" && return 1
  for label in $1; do
    [[ ${#label} -le 63 && "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}
# valid_roles: controller, then any of dns, dhcp and probe in the order given, each once.
valid_roles() {
  local role list=",$1,"
  [[ "$1" =~ ^controller(,(dns|dhcp|probe)){0,3}$ ]] || return 1
  for role in dns dhcp probe; do
    [[ "${list/,${role},/,}" != *",${role},"* ]] || return 1
  done
  return 0
}
valid_modules() {
  local m IFS=,
  [[ "$1" == "wizard" || "$1" == "all" ]] && return 0
  [[ -n "$1" ]] || return 1
  for m in $1; do
    [[ "$m" == ipam || "$m" == dns || "$m" == dhcp || "$m" == discovery ]] || return 1
  done
}
valid_profile() { [[ "$1" =~ ^(home|standard|hardened|lab)$ ]]; }
valid_language() { [[ "$1" == en || "$1" == sv ]]; }
valid_version() { [[ "$1" == latest || "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; }
valid_admin() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$ ]]; }
valid_kek() { [[ "$1" =~ ^(auto|sealed|file)$ ]]; }
valid_repo() { [[ "$1" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; }
valid_data_dir() {
  [[ "$1" == /* && "$1" != / && "$1" =~ ^[A-Za-z0-9/._-]+$ && "$1" != *..* ]] || return 1
  [[ "$1" != /home/* && "$1" != /root/* && "$1" != /run/* && "$1" != /tmp/* && "$1" != /etc/* && "$1" != /usr/* ]]
}

# dns_listen <answer>: the [dns] listen entries as TOML strings, comma separated, or fails.
# "all" is every address of the host; an address without a port gets 53.
dns_listen() {
  local a host port out=() IFS=,
  if [[ "$1" == all ]]; then
    printf '"0.0.0.0:53", "[::]:53"'
    return 0
  fi
  [[ -n "$1" ]] || return 1
  for a in $1; do
    a="${a// /}"
    if [[ "$a" =~ ^\[([^]]+)\](:([0-9]+))?$ ]]; then
      host="${BASH_REMATCH[1]}" port="${BASH_REMATCH[3]:-53}"
      valid_ipv6 "$host" && valid_port "$port" || return 1
      out+=("\"[${host}]:${port}\"")
    elif valid_ipv6 "$a"; then
      out+=("\"[${a}]:53\"")
    else
      host="${a%%:*}" port=53
      [[ "$a" == *:* ]] && port="${a#*:}"
      valid_ipv4 "$host" && valid_port "$port" || return 1
      out+=("\"${host}:${port}\"")
    fi
  done
  local joined
  printf -v joined '%s, ' "${out[@]}"
  printf '%s' "${joined%, }"
}

# forwarder_list <answer>: the [dns] forwarders as TOML strings, comma separated ("none": empty).
forwarder_list() {
  local a out=() IFS=,
  [[ "$1" == none || -z "$1" ]] && return 0
  for a in $1; do
    a="${a// /}"
    if valid_ipv4 "${a%%:*}" && { [[ "$a" != *:* ]] || valid_port "${a#*:}"; }; then
      out+=("\"${a}\"")
    elif valid_ipv6 "$a"; then
      out+=("\"${a}\"")
    else
      return 1
    fi
  done
  local joined
  printf -v joined '%s, ' "${out[@]}"
  printf '%s' "${joined%, }"
}

# host_resolvers: the resolvers this host uses, loopback excluded, comma separated (the
# upstreams of systemd-resolved when it runs, else /etc/resolv.conf).
host_resolvers() {
  local file=/etc/resolv.conf
  [[ -r /run/systemd/resolve/resolv.conf ]] && file=/run/systemd/resolve/resolv.conf
  [[ -r "$file" ]] || return 0
  awk '$1 == "nameserver" && $2 !~ /^127\./ && $2 != "::1" && $2 !~ /%/ {print $2}' "$file" |
    head -n 3 | paste -sd, -
}

# primary_ipv4: the address of the interface with the default route.
primary_ipv4() {
  have ip || return 0
  ip -4 -o route get 192.0.2.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1
}

# primary_ipv6: the global address of the interface with the default IPv6 route, or nothing
# (no IPv6 route, or only a link-local address).
primary_ipv6() {
  local addr
  have ip || return 0
  addr="$(ip -6 -o route get 2001:db8::1 2>/dev/null | sed -n 's/.* src \([0-9A-Fa-f:]*\).*/\1/p' | head -n 1)"
  [[ -n "$addr" && "${addr,,}" != fe80:* && "${addr,,}" != ::1 ]] && valid_ipv6 "$addr" && printf '%s' "$addr"
  return 0
}

# ── Versions ────────────────────────────────────────────────────────────────────────────────
# version_of <binary>: the version the binary reports.
version_of() { "$1" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?' | head -n 1; }

# Anything smaller is not the Tenko binary (the release asset is several MiB).
readonly MIN_BINARY_BYTES=1048576

# check_binary <file> <name>: dies with the reason when the file cannot be the Tenko binary:
# too small (a script, an empty or partial download), not an ELF x86_64 executable, or one
# that does not run (the first two lines of what it printed are shown).
check_binary() {
  local f="$1" name="$2" size kind first out rc=0
  size="$(stat -c %s "$f")"
  if ((size == 0)); then
    die "$E_DOWNLOAD" "${name} is empty (0 bytes), not the Tenko binary"
  elif ((size < MIN_BINARY_BYTES)); then
    first="$(head -c 80 "$f" | head -n 1 | tr -cd '[:print:]')"
    die "$E_DOWNLOAD" "${name} is ${size} bytes, far too small for the Tenko binary (several MiB); it is not the binary${first:+ (it starts with: ${first})}. Pass the release file tenko-<version>-linux-x86_64"
  fi
  if have file; then
    kind="$(file -b "$f" 2>/dev/null || true)"
    if [[ "$kind" != *"ELF 64-bit LSB"* || "$kind" != *"x86-64"* ]]; then
      die "$E_DOWNLOAD" "${name} is not an ELF x86_64 executable (file says: ${kind:-nothing}); a static x86_64 Linux binary is needed"
    fi
  fi
  out="$("$f" --version 2>&1)" || rc=$?
  if ((rc != 0)); then
    die "$E_DOWNLOAD" "${name} does not run here (exit ${rc}): $(printf '%s\n' "$out" | head -n 2 | tr '\n' ' ')"
  fi
}

# version_cmp <a> <b>: prints -1, 0 or 1 (SemVer precedence: a pre-release ranks below its
# release; pre-release identifiers compare in version order).
version_cmp() {
  local a="$1" b="$2" ca cb pa="" pb="" first
  ca="${a%%-*}" cb="${b%%-*}"
  [[ "$a" == *-* ]] && pa="${a#*-}"
  [[ "$b" == *-* ]] && pb="${b#*-}"
  if [[ "$ca" != "$cb" ]]; then
    first="$(printf '%s\n%s\n' "$ca" "$cb" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)"
    [[ "$first" == "$ca" ]] && echo -1 || echo 1
    return
  fi
  if [[ "$pa" == "$pb" ]]; then echo 0; return; fi
  [[ -z "$pa" ]] && { echo 1; return; }
  [[ -z "$pb" ]] && { echo -1; return; }
  first="$(printf '%s\n%s\n' "$pa" "$pb" | sort -V | head -n 1)"
  [[ "$first" == "$pa" ]] && echo -1 || echo 1
}

# ── GitHub releases ─────────────────────────────────────────────────────────────────────────
# The token goes to curl on standard input (-H @-): it is in no argument list. curl does not
# send it on to the storage host that an asset download redirects to. TENKO_GITHUB_API
# points the calls at a test server.
GITHUB_API="${TENKO_GITHUB_API:-https://api.github.com}"
gh_api() {
  printf 'Authorization: Bearer %s\n' "$OPT_TOKEN" |
    curl -fsSL --retry 2 --connect-timeout 10 -H @- -H 'Accept: application/vnd.github+json' \
      "${GITHUB_API}/repos/${OPT_REPO}/$1"
}
gh_asset() {
  printf 'Authorization: Bearer %s\n' "$OPT_TOKEN" |
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 -H @- -H 'Accept: application/octet-stream' \
      -o "$2" "${GITHUB_API}/repos/${OPT_REPO}/releases/assets/$1"
}
fetch() { curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 -o "$2" "$1"; }

# release_tag: the tag_name of the release JSON on standard input.
release_tag() {
  if have jq; then
    jq -r '.tag_name // empty'
  else
    grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | sed -E 's/.*"([^"]*)"$/\1/'
  fi
}

# release_asset_id <name>: the id of the asset of that name in the release JSON on standard
# input. Without jq the asset API URLs and the names are read in document order: each asset
# object has its "url" (…/releases/assets/<id>) before its "name".
release_asset_id() {
  if have jq; then
    jq -r --arg n "$1" '.assets[]? | select(.name == $n) | .id' | head -n 1
    return
  fi
  grep -oE '"url"[[:space:]]*:[[:space:]]*"https://api\.github\.com/repos/[^"]+/releases/assets/[0-9]+"|"name"[[:space:]]*:[[:space:]]*"[^"]*"' |
    awk -v want="$1" '
      /^"url"/ { n = split($0, p, "/"); id = p[n]; gsub(/[^0-9]/, "", id); next }
      /^"name"/ {
        if (id != "") {
          v = $0; sub(/^"name"[[:space:]]*:[[:space:]]*"/, "", v); sub(/"$/, "", v)
          if (v == want) { print id; exit }
          id = ""
        }
      }'
}

# sums_version: the version of the Linux binary that the SHA256SUMS on standard input lists.
sums_version() {
  grep -oE '[[:space:]]\*?tenko-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?-linux-x86_64$' |
    head -n 1 | sed -E 's/^[[:space:]]\*?tenko-//; s/-linux-x86_64$//'
}

# get_binary: sets NEW_BIN (a verified executable in TMP) and NEW_VERSION.
get_binary() {
  local want="$OPT_VERSION" name sums json tag id_bin id_sums base
  if [[ -n "$OPT_BINARY" ]]; then
    [[ -f "$OPT_BINARY" ]] || die "$E_USAGE" "--binary: no such file: ${OPT_BINARY}"
    NEW_BIN="${TMP}/tenko"
    cp "$OPT_BINARY" "$NEW_BIN"
    chmod 0755 "$NEW_BIN"
    check_binary "$NEW_BIN" "$OPT_BINARY"
    NEW_VERSION="$(version_of "$NEW_BIN" || true)"
    [[ -n "$NEW_VERSION" ]] || die "$E_DOWNLOAD" "${OPT_BINARY} reports no version ($("$NEW_BIN" --version 2>&1 | head -n 2 | tr '\n' ' '))"
    if [[ "$want" != latest && "$want" != "$NEW_VERSION" ]]; then
      die "$E_USAGE" "--binary is version ${NEW_VERSION}, not the --version ${want}"
    fi
    ok "Binary ${OPT_BINARY}: version ${NEW_VERSION} (local file, not verified against SHA256SUMS)"
    return 0
  fi
  have curl || die "$E_HOST" "curl is missing; install it, or pass --binary <file>"
  sums="${TMP}/SHA256SUMS"
  if [[ -n "$OPT_RELEASE_URL" ]]; then
    base="${OPT_RELEASE_URL%/}"
    info "Reading ${base}/SHA256SUMS"
    fetch "${base}/SHA256SUMS" "$sums" || die "$E_DOWNLOAD" "Could not download ${base}/SHA256SUMS"
    [[ "$want" == latest ]] && want="$(sums_version <"$sums")"
    [[ -n "$want" ]] || die "$E_DOWNLOAD" "SHA256SUMS at ${base} lists no tenko-<version>-linux-x86_64"
    name="tenko-${want}-linux-x86_64"
    info "Downloading ${name}"
    fetch "${base}/${name}" "${TMP}/${name}" || die "$E_DOWNLOAD" "Could not download ${base}/${name}"
  elif [[ -n "$OPT_TOKEN" ]]; then
    info "Looking up the release ${want} of ${OPT_REPO} (GitHub API, with the token)"
    if [[ "$want" == latest ]]; then
      json="$(gh_api releases/latest)" || die "$E_DOWNLOAD" "No latest release of ${OPT_REPO} (or the token cannot read it)"
    else
      json="$(gh_api "releases/tags/v${want}")" || die "$E_DOWNLOAD" "No release v${want} of ${OPT_REPO} (or the token cannot read it)"
    fi
    tag="$(release_tag <<<"$json")"
    want="${tag#v}"
    valid_version "$want" || die "$E_DOWNLOAD" "The release has no usable tag: '${tag}'"
    name="tenko-${want}-linux-x86_64"
    id_sums="$(release_asset_id SHA256SUMS <<<"$json")"
    id_bin="$(release_asset_id "$name" <<<"$json")"
    [[ -n "$id_sums" && -n "$id_bin" ]] || die "$E_DOWNLOAD" "Release ${tag} has no ${name} or no SHA256SUMS"
    info "Downloading ${name}"
    gh_asset "$id_sums" "$sums" || die "$E_DOWNLOAD" "Could not download SHA256SUMS of ${tag}"
    gh_asset "$id_bin" "${TMP}/${name}" || die "$E_DOWNLOAD" "Could not download ${name}"
  else
    base="https://github.com/${OPT_REPO}/releases"
    if [[ "$want" == latest ]]; then
      info "Looking up the latest release of ${OPT_REPO}"
      fetch "${base}/latest/download/SHA256SUMS" "$sums" ||
        die "$E_DOWNLOAD" "Could not download ${base}/latest/download/SHA256SUMS. A private repository needs --token (or GITHUB_TOKEN); or pass --binary <file>"
      want="$(sums_version <"$sums")"
      [[ -n "$want" ]] || die "$E_DOWNLOAD" "The latest SHA256SUMS lists no tenko-<version>-linux-x86_64"
    fi
    name="tenko-${want}-linux-x86_64"
    info "Downloading ${name}"
    fetch "${base}/download/v${want}/SHA256SUMS" "$sums" ||
      die "$E_DOWNLOAD" "Could not download SHA256SUMS of v${want}. A private repository needs --token (or GITHUB_TOKEN); or pass --binary <file>"
    fetch "${base}/download/v${want}/${name}" "${TMP}/${name}" || die "$E_DOWNLOAD" "Could not download ${name}"
  fi
  # The binary is kept only when its SHA-256 is the one SHA256SUMS lists for its name.
  if ! (cd "$TMP" && grep -E "[[:space:]]\*?${name//./\\.}\$" SHA256SUMS | sha256sum --check --strict --quiet >/dev/null 2>&1); then
    rm -f "${TMP:?}/${name}"
    die "$E_DOWNLOAD" "${name} does not match SHA256SUMS (or is not listed there); nothing was installed"
  fi
  NEW_BIN="${TMP}/tenko"
  mv "${TMP}/${name}" "$NEW_BIN"
  chmod 0755 "$NEW_BIN"
  check_binary "$NEW_BIN" "$name"
  NEW_VERSION="$(version_of "$NEW_BIN" || true)"
  [[ "$NEW_VERSION" == "$want" ]] || die "$E_DOWNLOAD" "${name} reports version '${NEW_VERSION}', not ${want}"
  ok "Downloaded ${name}, SHA-256 verified against SHA256SUMS"
}

# ── State of this host ──────────────────────────────────────────────────────────────────────
SYSTEMD=0 SYSTEMD_VERSION=0 IN_CONTAINER=""
detect_host() {
  local arch os_id="" os_version="" pretty=""
  arch="$(uname -m)"
  [[ "$arch" == x86_64 ]] ||
    die "$E_HOST" "This is ${arch}; Tenko releases ship a binary for x86_64 Linux only (build from source for other architectures)"
  if [[ -r /etc/os-release ]]; then
    os_id="$(. /etc/os-release && echo "${ID:-}")"
    os_version="$(. /etc/os-release && echo "${VERSION_ID:-}")"
    pretty="$(. /etc/os-release && echo "${PRETTY_NAME:-}")"
  fi
  case "${os_id}:${os_version%%.*}" in
  debian:12 | ubuntu:24 | rhel:9 | rocky:9 | almalinux:9 | centos:9 | ol:9) ok "${pretty:-$os_id $os_version}" ;;
  *) warn "Written for Debian 12, Ubuntu 24.04 and RHEL 9 compatibles; this is ${pretty:-unknown}, continuing" ;;
  esac
  if [[ -d /run/systemd/system ]] && have systemctl; then
    SYSTEMD=1
    SYSTEMD_VERSION="$(systemctl --version 2>/dev/null | awk 'NR == 1 {print $2}' | grep -oE '^[0-9]+' || echo 0)"
  fi
  if have systemd-detect-virt; then
    IN_CONTAINER="$(systemd-detect-virt -c 2>/dev/null || true)"
    [[ "$IN_CONTAINER" == none ]] && IN_CONTAINER=""
  fi
  if ((SYSTEMD)); then
    if ((SYSTEMD_VERSION >= 250)); then
      ok "systemd ${SYSTEMD_VERSION}${IN_CONTAINER:+, in a container (${IN_CONTAINER})}"
    else
      warn "systemd ${SYSTEMD_VERSION} is older than 250: no encrypted credentials, so the key-encryption key is a plain file; unit options newer than this systemd are ignored with a warning"
    fi
  elif ((OPT_NO_START)); then
    warn "systemd is not running here; with --no-start the unit is installed but not started"
  elif ((!OPT_UNINSTALL)); then
    die "$E_HOST" "systemd is not running here (PID 1 is $(ps -o comm= -p 1 2>/dev/null || echo unknown)); use a host with systemd, the container image (deploy/README.md, Containers), or --no-start"
  fi
}

# Installed state, read before anything changes.
OLD_VERSION="" OLD_RUNNING="" HAVE_CONFIG=0 KEK_MODE="" ACTIVE=0
detect_installed() {
  local current
  [[ -x "$BIN" ]] && OLD_VERSION="$(version_of "$BIN" || true)"
  [[ -f "$CONFIG" ]] && HAVE_CONFIG=1
  if [[ -L "${DATA_DIR}/updates/current" ]]; then
    current="$(readlink "${DATA_DIR}/updates/current")"
    current="${current##*/}"
    valid_version "$current" && OLD_RUNNING="$current"
  fi
  # The running version is the newer of the bootstrap binary and the layout's `current`
  # (an update installed from the web UI moves only `current`).
  if [[ -n "$OLD_RUNNING" && -n "$OLD_VERSION" && "$(version_cmp "$OLD_RUNNING" "$OLD_VERSION")" == 1 ]]; then
    OLD_VERSION="$OLD_RUNNING"
  elif [[ -z "$OLD_VERSION" ]]; then
    OLD_VERSION="$OLD_RUNNING"
  fi
  if [[ -f "$KEK_CRED" ]]; then
    KEK_MODE=sealed
  elif [[ -f "$KEK_FILE" ]]; then
    KEK_MODE="file"
  elif [[ -d "${DATA_DIR}/store" ]]; then
    # An installation made by hand without the credential (its lines commented out in the
    # unit): the [kek] section of tenko.toml decides, by default with key generations in
    # <data_dir>/kek. Kept as it is.
    KEK_MODE=config
  fi
  if ((SYSTEMD)) && systemctl is-active --quiet tenko 2>/dev/null; then ACTIVE=1; fi
}

# ── Answers ─────────────────────────────────────────────────────────────────────────────────
DATA_DIR="" ROLES="" MODULES="" PROFILE="" HOST_NAME="" DNS_ADDRESS="" FORWARDERS=""
LANGUAGE="" ADMIN="" PASSWORD="" API_PORT="$API_PORT_DEFAULT" USE_SELF=0 USE_SELF_DONE=0 STUB_OFF=0

check_or_die() {
  local fn="$1" value="$2" what="$3"
  "$fn" "$value" || die "$E_USAGE" "${what}: invalid value '${value}'"
}

# answers: the defaults, the flags, and in interactive mode the questions.
answers() {
  local default_host forwarders_default
  default_host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo tenko)"
  valid_hostname "$default_host" || default_host="$(hostname 2>/dev/null || echo tenko)"
  forwarders_default="$(host_resolvers || true)"
  ROLES="${OPT_ROLES:-controller,dns}"
  MODULES="${OPT_MODULES:-wizard}"
  PROFILE="${OPT_PROFILE:-home}"
  HOST_NAME="${OPT_HOST:-$default_host}"
  # A kept configuration names the host name the closing lines show.
  if [[ -z "$OPT_HOST" && -f "$CONFIG" ]]; then
    local kept
    kept="$(sed -n 's/^host_name = "\(.*\)"$/\1/p' "$CONFIG" | head -n 1)"
    if [[ -n "$kept" ]]; then
      HOST_NAME="$kept"
    fi
  fi
  # A kept configuration names the roles the unit serves: the probe drop-in follows them, as
  # do the port checks and the closing lines.
  if ((HAVE_CONFIG && !OPT_RECONFIGURE)) && [[ -f "$CONFIG" ]]; then
    local kept_roles
    kept_roles="$(sed -n 's/^roles = "\(.*\)"$/\1/p' "$CONFIG" | head -n 1)"
    if [[ -n "$kept_roles" ]] && valid_roles "$kept_roles"; then
      ROLES="$kept_roles"
    fi
  fi
  DNS_ADDRESS="${OPT_DNS_ADDRESS:-all}"
  FORWARDERS="${OPT_FORWARDERS:-${forwarders_default:-none}}"
  LANGUAGE="${OPT_LANGUAGE:-en}"
  ADMIN="$OPT_ADMIN"

  local write_config=1
  ((HAVE_CONFIG && !OPT_RECONFIGURE)) && write_config=0

  if ((!OPT_YES && write_config)); then
    while true; do
      if ((!SET_ROLES)); then
        # WP7.5: the two choices with the dhcp role.
        ask_menu ROLES "Roles of this node" "$ROLES" \
          controller "API, web UI, store and IPAM" \
          controller,dns "The same, and DNS on port 53" \
          controller,dhcp "The same, and DHCP on UDP port 67 (no DNS)" \
          controller,dns,dhcp "The same, and DNS on port 53 and DHCP on UDP port 67"
      fi
      valid_roles "$ROLES" && break
      printf 'Not a choice: %s\n' "$ROLES" >"$TTY"
      SET_ROLES=0
    done
    # The probe role goes with any choice of the menu, so it is its own question; the
    # default follows the dhcp role, whose conflict detection needs it.
    if ((!SET_ROLES)) && [[ "$ROLES" != *probe* ]]; then
      local probe_default=no
      [[ "$ROLES" == *dhcp* ]] && probe_default=yes
      if ask_yes_no "Also run the probe role on this node?

The probe role probes an address before the dhcp role offers it (conflict detection, on by default with the dhcp role) and runs the discovery scans. It needs CAP_NET_RAW for ARP and the raw scan methods, which the installer grants with the drop-in probe.conf; ICMP works without it." "$probe_default"; then
        ROLES+=",probe"
      fi
    fi
    while true; do
      [[ -n "$OPT_MODULES" ]] || ask MODULES "Product modules: wizard (first-run setup asks), all, or a list of ipam,dns,dhcp,discovery" "$MODULES"
      valid_modules "$MODULES" && break
      printf 'Not a module list: %s\n' "$MODULES" >"$TTY"
      OPT_MODULES=""
    done
    while true; do
      [[ -n "$OPT_PROFILE" ]] || ask_menu PROFILE "Security profile (docs/SECURITY-PROFILES.md)" "$PROFILE" \
        home "One box runs all roles, sane defaults" \
        standard "A business network, the default for organisations" \
        hardened "Regulated environments, strict authentication" \
        lab "Permissive, for testing and training"
      valid_profile "$PROFILE" && break
      OPT_PROFILE=""
    done
    while true; do
      [[ -n "$OPT_HOST" ]] || ask HOST_NAME "Host name clients use for this node (the TLS name and the passkey ID; not an address)" "$HOST_NAME"
      valid_hostname "$HOST_NAME" && break
      printf 'Not a host name: %s\n' "$HOST_NAME" >"$TTY"
      OPT_HOST=""
    done
    if [[ "$ROLES" == *dns* ]]; then
      while true; do
        ((SET_DNS_ADDRESS)) || ask DNS_ADDRESS "Addresses the dns role answers on: all, or a list such as 192.0.2.53,2001:db8::53" "$DNS_ADDRESS"
        dns_listen "$DNS_ADDRESS" >/dev/null && break
        printf 'Not an address list: %s\n' "$DNS_ADDRESS" >"$TTY"
        SET_DNS_ADDRESS=0
      done
      while true; do
        ((SET_FORWARDERS)) || ask FORWARDERS "Upstream resolvers for names outside your zones (a list, or none)" "$FORWARDERS"
        forwarder_list "$FORWARDERS" >/dev/null && break
        printf 'Not a resolver list: %s\n' "$FORWARDERS" >"$TTY"
        SET_FORWARDERS=0
      done
      if ((!OPT_USE_SELF)) && dns_listen "$DNS_ADDRESS" | grep -qE '"(0\.0\.0\.0|127\.0\.0\.1):53"'; then
        ask_yes_no "Use Tenko as this host's own resolver (127.0.0.1)?

Names the host looks up then go through Tenko: your zones first, forwarders for the rest. --uninstall puts the previous resolver back. Choose no to leave the host's resolver as it is." no &&
          OPT_USE_SELF=1
      fi
    fi
    while true; do
      [[ -n "$OPT_DATA_DIR" ]] || ask DATA_DIR "Data directory (on SSD or NVMe)" "$DATA_DIR"
      valid_data_dir "$DATA_DIR" && break
      printf 'Not a usable data directory: %s\n' "$DATA_DIR" >"$TTY"
      OPT_DATA_DIR=""
    done
  fi

  check_or_die valid_roles "$ROLES" --roles
  check_or_die valid_modules "$MODULES" --modules
  check_or_die valid_profile "$PROFILE" --profile
  check_or_die valid_hostname "$HOST_NAME" --host-name
  check_or_die valid_language "$LANGUAGE" --language
  dns_listen "$DNS_ADDRESS" >/dev/null || die "$E_USAGE" "--dns-address: invalid value '${DNS_ADDRESS}'"
  forwarder_list "$FORWARDERS" >/dev/null || die "$E_USAGE" "--forwarders: invalid value '${FORWARDERS}'"
  check_or_die valid_data_dir "$DATA_DIR" --data-dir
  USE_SELF="$OPT_USE_SELF"
  ((USE_SELF)) && check_use_self "$write_config"

  if ((!write_config)) && { ((SET_ROLES || SET_MODULES || SET_FORWARDERS || SET_DNS_ADDRESS)) ||
    [[ -n "$OPT_PROFILE" || -n "$OPT_HOST" || -n "$OPT_DATA_DIR" ]]; }; then
    warn "${CONFIG} exists and is kept; the configuration flags apply with --reconfigure"
  fi
}

# check_use_self <1 when the configuration is written now>: --use-self needs the dns role,
# answering on 127.0.0.1 port 53 (a resolver address has no port). A kept configuration is
# read for both; a [dns] section without a listen line answers on every address.
check_use_self() {
  local listen
  if (($1)); then
    [[ "$ROLES" == *dns* ]] || die "$E_USAGE" "--use-self needs the dns role (--roles controller,dns)"
    listen="$(dns_listen "$DNS_ADDRESS")"
  else
    grep -qE '^roles = ".*dns' "$CONFIG" ||
      die "$E_USAGE" "--use-self needs the dns role, and ${CONFIG} does not list it (--reconfigure --roles controller,dns)"
    listen="$(awk '/^\[dns\]/ {f = 1; next} /^\[/ {f = 0} f && /^listen/' "$CONFIG")"
    [[ -n "$listen" ]] || listen='"0.0.0.0:53"'
  fi
  grep -qE '"(0\.0\.0\.0|127\.0\.0\.1):53"' <<<"$listen" ||
    die "$E_USAGE" "--use-self needs the dns role to answer on 127.0.0.1 port 53: --dns-address all, or a list with 127.0.0.1"
}

# setup_answers: first-run setup now (an administrator) or in the browser.
setup_answers() {
  ((OPT_NO_START)) && return 0
  if ((!OPT_YES)) && [[ -z "$ADMIN" ]] && ((!HAVE_CONFIG)); then
    ask ADMIN "First administrator for setup now (empty: complete setup in the browser with the setup token)" ""
  fi
  [[ -z "$ADMIN" ]] && return 0
  check_or_die valid_admin "$ADMIN" --admin
  check_or_die valid_language "$LANGUAGE" --language
  if ((!OPT_YES)) && ((!SET_ADMIN)) && [[ -z "$OPT_LANGUAGE" ]]; then
    ask_menu LANGUAGE "Default language of the web UI" "$LANGUAGE" en English sv Svenska
    check_or_die valid_language "$LANGUAGE" --language
  fi
  if [[ -z "$PASSWORD" ]]; then
    if ((OPT_YES)) || [[ -z "$TTY" ]]; then
      die "$E_USAGE" "--admin needs the password: --password-stdin or TENKO_ADMIN_PASSWORD"
    fi
    if [[ "$PROFILE" == home ]]; then
      ask_secret PASSWORD "PIN of ${ADMIN} (the Home profile signs in with a PIN: four or more digits, no simple pattern)"
    else
      ask_secret PASSWORD "Password of ${ADMIN}"
    fi
  fi
}

# ── Steps ───────────────────────────────────────────────────────────────────────────────────
step_ports() {
  local holder line
  ((ACTIVE)) && return 0
  have ss || {
    warn "ss (iproute2) is missing; the ports are not checked before the start"
    return 0
  }
  if line="$(ss -Hltnp "sport = :${API_PORT}" 2>/dev/null | head -n 1)" && [[ -n "$line" ]]; then
    holder="$(grep -oE 'users:\(\("[^"]+"' <<<"$line" | sed 's/users:(("//' || true)"
    die "$E_PORT" "Port ${API_PORT}/tcp is taken by ${holder:-another program}; stop it first"
  fi
  # WP7.5: the dhcp role binds UDP 67. Another DHCP server (dnsmasq, isc-dhcp-server, Kea)
  # on every address of the host holds the port against any address the role would use, so
  # that stops the install; one bound to a single address (a hypervisor's bridge) only
  # conflicts when [dhcp] listen names that address, so it is a warning.
  if [[ "$ROLES" == *dhcp* ]]; then
    local listen67 local67 dhcp_other=""
    listen67="$(ss -Hlnup 'sport = :67' 2>/dev/null)" || true
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      holder="$(grep -oE 'users:\(\("[^"]+"' <<<"$line" | sed 's/users:(("//' || true)"
      local67="$(awk '{for (i = 1; i <= NF; i++) if ($i ~ /:67$/) {print $i; exit}}' <<<"$line")"
      if [[ "$local67" == 0.0.0.0:67 || "$local67" == '*:67' || "$local67" == '[::]:67' ]]; then
        dhcp_other="${holder:-unknown}"
      else
        warn "${holder:-A program} holds UDP ${local67}; the dhcp role must not listen on that address"
      fi
    done <<<"$listen67"
    if [[ -n "$dhcp_other" ]]; then
      die "$E_PORT" "Port 67/udp is taken by ${dhcp_other} on every address, another DHCP server (dnsmasq, isc-dhcp-server, kea-dhcp4 or a hypervisor's DHCP service); stop and disable it first"
    fi
  fi
  [[ "$ROLES" == *dns* ]] || return 0
  local listen53 stub=0 other=""
  listen53="$(ss -Hlnup 'sport = :53' 2>/dev/null; ss -Hlntp 'sport = :53' 2>/dev/null)" || true
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    holder="$(grep -oE 'users:\(\("[^"]+"' <<<"$line" | sed 's/users:(("//' || true)"
    if [[ "$holder" == systemd-resolve* ]]; then
      stub=1
    else
      other="${holder:-unknown}"
    fi
  done <<<"$listen53"
  if [[ -n "$other" ]]; then
    die "$E_PORT" "Port 53 is taken by ${other}; stop it or narrow it to other addresses, or give the dns role other addresses with --dns-address"
  fi
  ((stub)) || return 0
  if [[ "$DNS_ADDRESS" != all ]]; then
    ok "systemd-resolved holds 127.0.0.53:53 only; the dns role answers on ${DNS_ADDRESS}"
    return 0
  fi
  if ((OPT_KEEP_STUB)); then
    die "$E_PORT" "systemd-resolved's stub listener holds port 53 and --keep-resolved-stub was given; pass --dns-address with this host's addresses"
  fi
  if ! ask_yes_no "systemd-resolved listens on 127.0.0.53:53, which the dns role on every address (0.0.0.0:53) needs.

Turn its stub listener off (DNSStubListener=no in ${RESOLVED_DROPIN}) and point /etc/resolv.conf at the upstream list, so that name resolution on this host keeps working?" yes; then
    die "$E_PORT" "Port 53 is held by systemd-resolved; run again with --dns-address <this host's addresses>, or allow the change"
  fi
  info "Turning off systemd-resolved's stub listener"
  run install -d -m 0755 /etc/systemd/resolved.conf.d
  printf '# Written by the Tenko installer: the dns role of Tenko answers on port 53.\n[Resolve]\nDNSStubListener=no\n' |
    put "$RESOLVED_DROPIN" 0644 root:root || true
  local target
  target="$(readlink /etc/resolv.conf 2>/dev/null || true)"
  if [[ "$target" == *stub-resolv.conf ]]; then
    state_set resolv_conf_link "$target"
    run ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
  fi
  state_set resolved_stub_off 1
  STUB_OFF=1
  run systemctl restart systemd-resolved
  ok "systemd-resolved no longer listens on port 53; /etc/resolv.conf lists the upstream resolvers"
}

# state_set <key> <value>: a line of the installer's state file (what to undo at --uninstall).
state_set() {
  local tmp
  ((OPT_DRY)) && return 0
  # An existing directory is not touched: the account tenko owns its group once step_dirs ran.
  [[ -d "$ETC" ]] || install -d -m 0750 -o root -g root "$ETC"
  tmp="$(mktemp "${TMP}/state.XXXXXX")"
  [[ -f "$STATE_FILE" ]] && grep -v "^${1}=" "$STATE_FILE" >"$tmp" || true
  printf '%s=%s\n' "$1" "$2" >>"$tmp"
  install -m 0600 -o root -g root "$tmp" "$STATE_FILE"
}
state_get() {
  [[ -f "$STATE_FILE" ]] || return 0
  sed -n "s/^${1}=//p" "$STATE_FILE" | tail -n 1
}

# resolved_manages: systemd-resolved runs and /etc/resolv.conf is one of its files, so the
# host's lookups follow resolved's settings.
resolved_manages() {
  local target
  ((SYSTEMD)) && systemctl is-active --quiet systemd-resolved 2>/dev/null || return 1
  target="$(readlink -f "$RESOLV_CONF" 2>/dev/null || true)"
  [[ "$target" == /run/systemd/resolve/* || "$target" == /usr/lib/systemd/resolv.conf ]]
}

# node_listens_dns: something accepts a TCP connection on 127.0.0.1:53. A query would prove
# more, but the node forwards every name it does not serve and answers only when an upstream
# does, so the listener is what can be checked at once.
node_listens_dns() {
  have timeout || return 0
  for _ in 1 2 3 4 5; do
    timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/53' 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

# resolved_dropin: the drop-in of systemd-resolved: the stub listener off where the installer
# turned it off, and Tenko as the DNS server for every name (the routing domain ~.).
resolved_dropin() {
  printf '# Written by the Tenko installer.\n[Resolve]\n'
  if ((STUB_OFF)) || [[ "$(state_get resolved_stub_off)" == 1 ]]; then
    printf '# The dns role of Tenko answers on port 53.\nDNSStubListener=no\n'
  fi
  if (($1)); then
    printf '# --use-self: this host resolves through Tenko (127.0.0.1); a name that Tenko does not\n# serve goes to its forwarders. `install.sh --uninstall` removes this.\nDNS=127.0.0.1\nDomains=~.\n'
  fi
}

# write_resolv_conf: standard input becomes /etc/resolv.conf, written in place (it can be a
# bind mount in a container, which a rename cannot replace); a symbolic link is removed first.
write_resolv_conf() {
  local tmp
  tmp="$(mktemp "${TMP}/resolv.XXXXXX")"
  cat >"$tmp"
  CHANGED=$((CHANGED + 1))
  if ((OPT_DRY)); then
    printf '  [dry-run] write %s (mode 0644, root:root, %s lines)\n' "$RESOLV_CONF" "$(wc -l <"$tmp")"
    rm -f "$tmp"
    return 0
  fi
  [[ -L "$RESOLV_CONF" ]] && rm -f "$RESOLV_CONF"
  cat "$tmp" >"$RESOLV_CONF"
  chmod 0644 "$RESOLV_CONF"
  rm -f "$tmp"
}

# step_use_self: with --use-self, the host's resolver becomes 127.0.0.1, after the node listens.
# systemd-resolved: DNS= in the installer's drop-in. Otherwise /etc/resolv.conf, whose
# previous state is kept for --uninstall. Both are recorded in the installer's state file.
step_use_self() {
  ((USE_SELF)) || return 0
  if ((OPT_NO_START)); then
    warn "--use-self: the node is not started (--no-start), so the host's resolver is not changed; run the installer again with --use-self once it runs"
    return 0
  fi
  if ((!OPT_DRY)) && ! node_listens_dns; then
    warn "--use-self: nothing listens on 127.0.0.1:53, so the host's resolver is not changed (see journalctl -u tenko)"
    return 0
  fi
  if resolved_manages; then
    [[ -d /etc/systemd/resolved.conf.d ]] || run install -d -m 0755 /etc/systemd/resolved.conf.d
    if resolved_dropin 1 | put "$RESOLVED_DROPIN" 0644 root:root; then
      info "Pointing the host at Tenko through systemd-resolved (DNS=127.0.0.1)"
      state_set use_self resolved
      run systemctl restart systemd-resolved
    fi
    ok "The host resolves through Tenko: DNS=127.0.0.1 in ${RESOLVED_DROPIN}"
  elif grep -qF "$RESOLV_MARK" "$RESOLV_CONF" 2>/dev/null; then
    ok "${RESOLV_CONF} points at Tenko already"
  else
    local link="" kept
    kept="$(grep -E '^(search|domain|options)[[:space:]]' "$RESOLV_CONF" 2>/dev/null || true)"
    if [[ -L "$RESOLV_CONF" ]]; then
      link="$(readlink "$RESOLV_CONF")"
      state_set use_self_resolv_link "$link"
    elif [[ -f "$RESOLV_CONF" ]]; then
      [[ -d "$ETC" ]] || run install -d -m 0750 -o root -g root "$ETC"
      run cp -p "$RESOLV_CONF" "${ETC}/resolv.conf.before"
      state_set use_self_resolv_backup "${ETC}/resolv.conf.before"
    fi
    state_set use_self resolv_conf
    info "Pointing ${RESOLV_CONF} at Tenko"
    {
      printf '%s: this host resolves through Tenko; install.sh --uninstall restores the previous file.\nnameserver 127.0.0.1\n' "$RESOLV_MARK"
      [[ -z "$kept" ]] || printf '%s\n' "$kept"
    } | write_resolv_conf
    ok "The host resolves through Tenko: ${RESOLV_CONF} lists 127.0.0.1 only"
  fi
  USE_SELF_DONE=1
  [[ "$FORWARDERS" == none ]] &&
    warn "The dns role has no forwarders, so the host resolves your zones and nothing else; add upstream resolvers to [dns] forwarders in ${CONFIG}"
  return 0
}

# restore_host_resolver: undoes step_use_self (before the service stops, so that the host
# never points at a node that is gone).
restore_host_resolver() {
  local mode link backup
  mode="$(state_get use_self)"
  [[ -n "$mode" ]] || return 0
  case "$mode" in
  resolved)
    if [[ "$(state_get resolved_stub_off)" == 1 ]]; then
      STUB_OFF=1
      resolved_dropin 0 | put "$RESOLVED_DROPIN" 0644 root:root || true
    else
      run rm -f "$RESOLVED_DROPIN"
    fi
    ((SYSTEMD)) && run systemctl restart systemd-resolved
    ;;
  resolv_conf)
    if grep -qF "$RESOLV_MARK" "$RESOLV_CONF" 2>/dev/null; then
      link="$(state_get use_self_resolv_link)"
      backup="$(state_get use_self_resolv_backup)"
      if [[ -n "$link" ]]; then
        run ln -sfn "$link" "$RESOLV_CONF"
      elif [[ -n "$backup" && -f "$backup" ]]; then
        write_resolv_conf <"$backup"
        run rm -f "$backup"
      fi
    else
      warn "${RESOLV_CONF} was changed since --use-self; left as it is"
    fi
    ;;
  esac
  ok "The host's resolver is back as it was before --use-self"
}

step_account() {
  if id -u tenko >/dev/null 2>&1; then
    ok "Service account tenko exists"
    return 0
  fi
  have useradd || die "$E_HOST" "useradd is missing (the passwd or shadow-utils package)"
  local nologin=/usr/sbin/nologin
  [[ -x "$nologin" ]] || nologin=/sbin/nologin
  run useradd --system --home-dir "$DATA_DIR" --no-create-home --shell "$nologin" tenko
  ok "Created the service account tenko"
}

step_dirs() {
  if [[ ! -d "$ETC" ]] || [[ "$(stat -c '%a %U:%G' "$ETC")" != "750 root:tenko" ]]; then
    run install -d -m 0750 -o root -g tenko "$ETC"
  fi
  if [[ ! -d "$DATA_DIR" ]]; then
    run install -d -m 0700 -o tenko -g tenko "$DATA_DIR"
    ok "Created the data directory ${DATA_DIR}"
  fi
  [[ -d "$LOG_DIR" ]] || run install -d -m 0750 -o tenko -g tenko "$LOG_DIR"
}

step_binary() {
  if [[ -z "$OLD_VERSION" ]]; then
    run install -m 0755 -o root -g root "$NEW_BIN" "$BIN"
    ok "Installed ${BIN} (${NEW_VERSION})"
    return 0
  fi
  case "$(version_cmp "$NEW_VERSION" "$OLD_VERSION")" in
  0)
    if [[ -x "$BIN" ]] && same_file "$NEW_BIN" "$BIN"; then
      ok "Tenko ${NEW_VERSION} is installed already"
    elif [[ -x "$BIN" && "$(version_of "$BIN")" == "$NEW_VERSION" ]]; then
      ok "Tenko ${NEW_VERSION} is installed already (another build of the same version; kept)"
    else
      run install -m 0755 -o root -g root "$NEW_BIN" "$BIN"
      ok "Installed ${BIN} (${NEW_VERSION}) again"
    fi
    ;;
  1) step_upgrade ;;
  *)
    ok "Tenko ${OLD_VERSION} is installed, newer than ${NEW_VERSION}; the binary is kept (a downgrade is a rollback: docs/upgrades.md, section 7.6)"
    ;;
  esac
}

UPGRADED=0
step_upgrade() {
  local rc=0 was_active="$ACTIVE"
  info "Upgrading ${OLD_VERSION} to ${NEW_VERSION}"
  if ((was_active)); then
    run systemctl stop tenko
  fi
  if [[ -d "${DATA_DIR}/store" ]]; then
    info "Checking the data directory with ${NEW_VERSION} (tenko upgrade check, a dry run on a copy)"
    if ((OPT_DRY)); then
      printf '  [dry-run] %s upgrade check --config %s --data-dir %s (as tenko)\n' "$NEW_BIN" "$CONFIG" "$DATA_DIR"
    else
      install -m 0755 "$NEW_BIN" "${TMP}/tenko-check"
      chmod 0711 "$TMP"
      as_tenko "${TMP}/tenko-check" upgrade check --config "$CONFIG" --data-dir "$DATA_DIR" || rc=$?
      if ((rc != 0 && rc != 10)); then
        ((was_active)) && systemctl start tenko || true
        die "$E_UPGRADE" "tenko upgrade check refused the data directory (exit ${rc}); ${OLD_VERSION} keeps running and nothing was changed. See docs/upgrades.md, section 5.3"
      fi
      if ((rc == 10)); then
        ok "The data directory needs a migration, and its dry run passed"
      else
        ok "The data directory needs no migration"
      fi
    fi
  fi
  run install -m 0755 -o root -g root "$NEW_BIN" "$BIN"
  UPGRADED=1
  ok "Installed ${BIN} (${NEW_VERSION}); the next start switches the updates layout to it"
}

kek_file_section() {
  printf '\n[kek]\n'
  printf '# A plain key file: systemd-creds could not seal the key on this host (the installer\n'
  printf '# said why). It lives outside the data directory, so a backup of the data does not\n'
  printf '# carry it. deploy/README.md, "Install in one command", says how to seal it later.\n'
  printf 'provider = "file"\npath = "%s"\n' "$KEK_FILE"
}

# config_add_kek_file: a kept configuration without a [kek] section gets the section of a
# new plain key file.
config_add_kek_file() {
  if grep -q '^[[:space:]]*\[kek\]' "$CONFIG" 2>/dev/null; then
    die "$E_CONFIG" "${CONFIG} has a [kek] section; set provider = \"file\" and path = \"${KEK_FILE}\" in it, or run with --reconfigure"
  fi
  if ((OPT_DRY)); then
    printf '  [dry-run] add [kek] provider = "file", path = "%s" to %s\n' "$KEK_FILE" "$CONFIG"
    return 0
  fi
  { cat "$CONFIG"; kek_file_section; } | put "$CONFIG" 0640 root:tenko || true
  ok "Added the [kek] section of the key file to ${CONFIG}"
  WROTE_CONFIG=1
}

step_config() {
  local modules_line listen forwarders tls_addresses ip ip6 api_listen api_note kek_section=""
  if ((HAVE_CONFIG && !OPT_RECONFIGURE)); then
    ok "Keeping ${CONFIG} (--reconfigure writes it again from the answers)"
    if ((FRESH_KEY)) && [[ "$KEK_MODE" == file ]]; then
      config_add_kek_file
    fi
    return 0
  fi
  case "$MODULES" in
  wizard) modules_line='# modules = ["ipam", "dns", "dhcp", "discovery"]   # not set: first-run setup asks' ;;
  all) modules_line='modules = ["all"]' ;;
  *) modules_line="modules = [\"${MODULES//,/\", \"}\"]" ;;
  esac
  ip="$(primary_ipv4 || true)"
  tls_addresses='"127.0.0.1"'
  [[ -n "$ip" ]] && tls_addresses+=", \"${ip}\""
  ip6="$(primary_ipv6 || true)"
  [[ -n "$ip6" ]] && tls_addresses+=", \"${ip6}\""
  # IPv4 and IPv6 as the dns role does; a kernel without IPv6 has no [::] to bind.
  api_listen="\"0.0.0.0:${API_PORT}\""
  api_note=" (IPv4 only: this kernel has no IPv6)"
  if [[ -e /proc/net/if_inet6 ]]; then
    api_listen+=", \"[::]:${API_PORT}\""
    api_note=" on IPv4 and IPv6, as the dns role below"
  fi
  if [[ "$KEK_TARGET" == file ]]; then
    kek_section="$(kek_file_section)
"
  fi
  local body
  body="# Tenko DDI node configuration, written by install.sh on $(date -u +%Y-%m-%d).
# Every key with its default and its environment name: tenko.example.toml (deploy/ in the
# repository). Check the file with: tenko config check --config ${CONFIG}
# The key-encryption key is set by the unit (a systemd credential) or in [kek] below.

data_dir = \"${DATA_DIR}\"
roles = \"${ROLES}\"
${modules_line}

[profile]
# The security profile until first-run setup stores the one chosen there.
name = \"${PROFILE}\"

[server]
# The API and the web UI${api_note}
listen = [${api_listen}]

[tls]
# Tenko's internal CA issues the server certificate. Install ${DATA_DIR}/tls/ca-root.pem
# on admin clients. The names below are on the certificate until setup stores a host name.
mode = \"internal_ca\"
host_name = \"${HOST_NAME}\"
alt_names = [\"localhost\"]
addresses = [${tls_addresses}]
${kek_section}"
  if [[ "$ROLES" == *dns* ]]; then
    listen="$(dns_listen "$DNS_ADDRESS")"
    forwarders="$(forwarder_list "$FORWARDERS")"
    body+="
[dns]
# Where the dns role answers (UDP and TCP). Port 53 needs the unit's CAP_NET_BIND_SERVICE.
listen = [${listen}]
# Upstream resolvers for names outside the zones; empty: such names are refused.
forwarders = [${forwarders}]
"
  fi
  # WP7.5: the dhcp role serves nothing until [dhcp] listen names an address.
  if [[ "$ROLES" == *dhcp* ]]; then
    body+="
[dhcp]
# Where the dhcp role listens (UDP 67): the node's own unicast address for a gateway that
# relays to it (relay mode), or an interface for the broadcasts of clients on its link
# (direct mode, which needs the drop-in deploy/systemd/dhcp-direct.conf). Set it, then
# restart the service. Every key: tenko.example.toml.
# listen = [{ address = \"192.0.2.10\", mode = \"relay\" }]
# listen = [{ address = \"192.0.2.10\", mode = \"direct\", interface = \"eth0\" }]
"
  fi
  if ((HAVE_CONFIG)) && ((!OPT_DRY)); then
    local backup
    backup="${CONFIG}.$(date -u +%Y%m%dT%H%M%SZ).bak"
    cp -p "$CONFIG" "$backup"
    ok "Kept the previous configuration as ${backup}"
  fi
  printf '%s' "$body" | put "$CONFIG" 0640 root:tenko || true
  ok "Wrote ${CONFIG}"
  WROTE_CONFIG=1
}

step_config_check() {
  local out rc=0
  if ((OPT_DRY)); then
    printf '  [dry-run] %s config check --config %s\n' "$BIN" "$CONFIG"
    return 0
  fi
  # A clean environment: TENKO_* variables of this shell would be checked too, and the
  # service does not see them.
  out="$(env -i PATH="$PATH" "$BIN" config check --config "$CONFIG" 2>&1 >/dev/null)" || rc=$?
  if ((rc != 0)); then
    printf '%s\n' "$out" | sed 's/^/      /' >&2
    die "$E_CONFIG" "tenko config check refused ${CONFIG} (exit ${rc})"
  fi
  ok "tenko config check: ${CONFIG} is valid"
}

# The key-encryption key. KEK_TARGET is what a new key becomes; an existing key is never
# touched (KEK_MODE).
KEK_TARGET="" KEK_REASON="" NEW_KEY=""
plan_kek() {
  if [[ -n "$KEK_MODE" ]]; then
    KEK_TARGET="$KEK_MODE"
    [[ -n "$OPT_KEK" && "$OPT_KEK" != auto && "$OPT_KEK" != "$KEK_MODE" ]] &&
      warn "--kek ${OPT_KEK} is ignored: the existing key (${KEK_MODE}) is never replaced; deploy/README.md says how to seal a plain key"
    return 0
  fi
  KEK_TARGET="${OPT_KEK:-auto}"
  if [[ "$KEK_TARGET" == file ]]; then
    KEK_REASON="--kek file was given"
    return 0
  fi
  local why=""
  if ((!SYSTEMD)); then
    why="systemd is not running here, and only its service manager hands a sealed key to the service"
  elif ((SYSTEMD && SYSTEMD_VERSION < 250)); then
    why="systemd ${SYSTEMD_VERSION} has no encrypted credentials (250 or later needed)"
  elif ! have systemd-creds; then
    why="systemd-creds is not installed"
  fi
  if [[ -n "$why" ]]; then
    [[ "$KEK_TARGET" == sealed ]] && die "$E_HOST" "--kek sealed: ${why}"
    KEK_TARGET="file" KEK_REASON="$why"
    return 0
  fi
  if ((OPT_DRY)); then
    KEK_TARGET=sealed
    return 0
  fi
  # Try it: encrypt a key and decrypt it again. In an unprivileged container (no host key,
  # no TPM2) this is where sealing fails.
  local key="" out back=""
  key="$(new_key)"
  out="${TMP}/kek.cred"
  if printf '%s' "$key" | systemd-creds encrypt --name=tenko_kek - "$out" >"${TMP}/creds.log" 2>&1 &&
    back="$(systemd-creds decrypt --name=tenko_kek "$out" - 2>>"${TMP}/creds.log")" &&
    [[ "$back" == "$key" ]]; then
    KEK_TARGET=sealed
    NEW_KEY="$key"
  else
    why="$(tail -n 1 "${TMP}/creds.log" 2>/dev/null)"
    [[ "$KEK_TARGET" == sealed ]] && die "$E_HOST" "--kek sealed: systemd-creds cannot seal a key here: ${why:-no message}"
    KEK_TARGET="file" KEK_REASON="systemd-creds cannot seal a key here${IN_CONTAINER:+ (a ${IN_CONTAINER} container)}: ${why:-no message}"
    NEW_KEY="$key"
  fi
  rm -f "$out"
}

# credential_delivered <file> [<user>]: true when the service manager hands the sealed key to a
# service as the unit does (LoadCredentialEncrypted=, as the tenko account, in a sandbox),
# checked with a transient unit that prints the SHA-256 of what it received. In some
# containers systemd-creds seals and the credential still never reaches the service.
credential_delivered() {
  local want got
  want="$(printf '%s' "$NEW_KEY" | sha256sum | cut -d' ' -f1)"
  # shellcheck disable=SC2016 # Expanded by the transient unit's shell.
  got="$(systemd-run --quiet --wait --pipe --collect -p "User=${2:-tenko}" -p PrivateDevices=yes \
    -p ProtectSystem=strict -p "LoadCredentialEncrypted=tenko_kek:$1" \
    /bin/sh -c 'sha256sum <"$CREDENTIALS_DIRECTORY/tenko_kek"' </dev/null 2>"${TMP}/deliver.log" |
    cut -d' ' -f1)" || true
  [[ -n "$got" && "$got" == "$want" ]]
}

new_key() {
  if have openssl; then
    openssl rand -hex 32
  else
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

step_kek() {
  case "$KEK_MODE" in
  sealed)
    ok "Keeping the sealed key-encryption key ${KEK_CRED}"
    return 0
    ;;
  file)
    ok "Keeping the key-encryption key file ${KEK_FILE}"
    return 0
    ;;
  config)
    warn "No key in ${ETC}: the [kek] section of ${CONFIG} decides (by default key generations in ${DATA_DIR}/kek, as installed by hand). Kept as it is"
    return 0
    ;;
  esac
  if ((OPT_DRY)); then
    printf '  [dry-run] create the key-encryption key: %s\n' "$([[ "$KEK_TARGET" == sealed ]] && echo "$KEK_CRED (systemd-creds encrypt --name=tenko_kek)" || echo "$KEK_FILE (plain file)")"
    CHANGED=$((CHANGED + 1))
    return 0
  fi
  [[ -n "$NEW_KEY" ]] || NEW_KEY="$(new_key)"
  [[ "$NEW_KEY" =~ ^[0-9a-f]{64}$ ]] || die "$E_FAIL" "Could not create a key-encryption key"
  if [[ "$KEK_TARGET" == sealed ]]; then
    printf '%s' "$NEW_KEY" | systemd-creds encrypt --name=tenko_kek - "${KEK_CRED}.new" >/dev/null 2>&1 ||
      die "$E_FAIL" "systemd-creds encrypt failed"
    chmod 0600 "${KEK_CRED}.new"
    if credential_delivered "${KEK_CRED}.new"; then
      mv -f "${KEK_CRED}.new" "$KEK_CRED"
      CHANGED=$((CHANGED + 1))
      ok "Created the key-encryption key, sealed with systemd-creds: ${KEK_CRED}"
    else
      rm -f "${KEK_CRED}.new"
      [[ "$OPT_KEK" == sealed ]] && die "$E_HOST" "--kek sealed: the service manager does not hand encrypted credentials to services here"
      KEK_TARGET="file"
      KEK_REASON="the service manager does not hand encrypted credentials to services here${IN_CONTAINER:+ (a ${IN_CONTAINER} container)}, although systemd-creds can seal"
    fi
  fi
  if [[ "$KEK_TARGET" == file ]]; then
    printf '%s\n' "$NEW_KEY" | put "$KEK_FILE" 0640 root:tenko || true
    warn "The key-encryption key is a plain file, ${KEK_FILE}, because ${KEK_REASON}."
    warn "Anyone who can read it (root, the tenko account) can decrypt the vault; it is kept out of ${DATA_DIR}, so a backup of the data does not carry it."
    warn "To seal it later on a host where systemd-creds works: deploy/README.md, \"Install in one command\", \"Seal a plain key later\"."
  fi
  KEK_MODE="$KEK_TARGET"
  NEW_KEY=""
}

# The unit of deploy/systemd/tenko.service, unchanged. `install.sh --print-unit` prints it;
# the test compares it with the file.
unit_text() {
  cat <<'TENKO_UNIT_END'
# Hardened systemd unit for Tenko DDI: the controller role (REST API, web UI, replicated
# store, IPAM) and, when tenko.toml lists them, the dns role (port 53) and the dhcp role
# (UDP port 67) in the same process. The dhcp role in relay mode needs nothing beyond this
# unit; its direct mode needs the drop-in deploy/systemd/dhcp-direct.conf (see the end of
# this file).
#
# Needs systemd 250 or later (LoadCredentialEncrypted= and the %d specifier): Debian 12,
# Ubuntu 24.04, RHEL 9 and newer.
#
# Install (as root; the full walk-through is in deploy/README.md):
#   1. Place the binary at /usr/local/bin/tenko.
#   2. Create the service account first:
#        useradd --system --home-dir /var/lib/tenko --no-create-home \
#                --shell /usr/sbin/nologin tenko
#   3. Create /etc/tenko, readable by the service account but not writable by it, and put
#      the configuration (deploy/tenko.example.toml) in it:
#        install -d -m 0750 -o root -g tenko /etc/tenko
#        install -m 0640 -o root -g tenko deploy/tenko.example.toml /etc/tenko/tenko.toml
#        tenko config check --config /etc/tenko/tenko.toml
#   4. Create the key-encryption key as an encrypted credential, once (see the section
#      "Key-encryption key" below; keep an offline copy of the key, see deploy/README.md):
#        openssl rand -hex 32 | systemd-creds encrypt --name=tenko_kek - /etc/tenko/kek.cred
#        chmod 0600 /etc/tenko/kek.cred
#   5. Install this file as /etc/systemd/system/tenko.service, then run:
#        systemctl daemon-reload && systemctl enable --now tenko
#   6. While first-run setup is open the server keeps a one-time setup token in
#      /var/lib/tenko/setup-token (never in the journal); print it with
#        sudo -u tenko tenko setup token --config /etc/tenko/tenko.toml
#      and complete setup in the web UI or with `tenko setup`.
#
# If the unit fails at once with status 243/CREDENTIALS, /etc/tenko/kek.cred is missing or
# was created with another --name. Exit statuses 2, 3 and 4 of `tenko serve` (usage,
# invalid configuration or a data directory of a newer format, a start step failed) are not
# retried; see `journalctl -u tenko`. Exit status 12 asks for a restart (an update installed
# from the web UI, a changed module set, a switch back to the previous version) and is
# always restarted.
#
# Versions (OPS-24, docs/upgrades.md): the service runs /var/lib/tenko/updates/current/tenko,
# the version that the link `current` points at. ExecStartPre= copies /usr/local/bin/tenko
# into /var/lib/tenko/updates/<version>/ when it is missing, and moves `current` to it when
# it is newer than the running version (an administrator upgraded the binary by hand), so
# that an update installed from the web UI is a switch of the link and a restart. To keep
# the old layout without updates from the UI, use instead:
#   ExecStart=/usr/local/bin/tenko serve --config /etc/tenko/tenko.toml
# and delete the ExecStartPre= line; the UI then shows update notices only.

[Unit]
Description=Tenko DDI (DNS, DHCP and IPAM): controller
After=network-online.target
Wants=network-online.target
# Give up after five failed starts within five minutes instead of looping.
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
# `tenko serve` sends READY=1 once the API listens and STOPPING=1 when it shuts down, from
# its main process (NOTIFY_SOCKET).
Type=notify
NotifyAccess=main
# The configuration file names the node's settings; --roles defaults to the file's value
# ("controller"). A controller node runs the dns, dhcp and probe roles in its process when
# they are listed (roles = "controller,dns,dhcp"); a role list without `controller` exits
# with status 2 when it names dns or dhcp. The binary is the version that `current` points
# at; ExecStartPre= sets the layout up (see the top).
ExecStartPre=/usr/local/bin/tenko upgrade layout --config /etc/tenko/tenko.toml
ExecStart=/var/lib/tenko/updates/current/tenko serve --config /etc/tenko/tenko.toml
# The data directory is the state directory below; the unit pins it so that a data_dir in
# tenko.toml cannot point at a path the sandbox makes read-only.
Environment=TENKO_DATA_DIR=/var/lib/tenko

Restart=on-failure
RestartSec=5s
# 12: stopped to be restarted (an installed update, a module change, a switch back).
# Status 12 is a deliberate stop, so it counts as a success: the journal does not log
# "Failed with result 'exit-code'" before the restart that RestartForceExitStatus= makes.
SuccessExitStatus=12
RestartForceExitStatus=12
# Tells tenko that this unit restarts it after status 12, so that it may install updates
# from the web UI and apply a module change by restarting itself. tenko does not infer this
# from the variables systemd passes to every process (INVOCATION_ID, NOTIFY_SOCKET).
Environment=TENKO_SUPERVISED=1
# 2 usage, 3 invalid configuration or a newer data format, 4 a start step failed (key,
# store, port, ...): the same start would fail again, so do not loop. 1 (unexpected
# failure) is retried.
RestartPreventExitStatus=2 3 4
# Starting opens the store and runs the fsync probe; the server reports readiness (READY=1)
# when it is done. When the data directory is of an older format, the start migrates it
# first (docs/upgrades.md, section 7) and sends EXTEND_TIMEOUT_USEC to systemd while the
# migration runs, so a long migration does not hit this timeout; the timeout applies again
# to the rest of the start. A start that makes no progress still fails after this time.
TimeoutStartSec=120s
# A stop lets open requests finish (server.shutdown_grace_secs, 10 s), stops the job runner
# (up to 15 s) and makes the store durable.
TimeoutStopSec=30s

# Identity
User=tenko
Group=tenko
# The API listens on 8443 (above 1024) and nothing opens raw sockets. The one capability is
# CAP_NET_BIND_SERVICE, for the dns role on port 53 ([dns] listen) and the dhcp role on UDP
# port 67 ([dhcp] listen; 547 joins it with DHCPv6, which is not served yet); a node with
# neither role does not use it, and removing both lines' value takes it away again.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

# Key-encryption key (KEK) of the vault
# The vault needs a 256-bit KEK at every start. This unit passes it as a systemd credential
# and tells tenko to read it with the `systemd_credential` provider (the environment beats
# tenko.toml). Why not the default provider ("platform", which runs `systemd-creds encrypt`
# itself as the tenko user)?
#   * The host key /var/lib/systemd/credential.secret is readable by root only, so the
#     unprivileged tenko account can seal only with a TPM2 it may open (/dev/tpmrm0, which
#     PrivateDevices= hides) or, from systemd 256, with `systemd-creds --user`. Where
#     sealing fails, the platform provider falls back to a plain 0600 file in
#     <data dir>/kek and warns at every start: the key then sits next to the data it
#     protects, and in the same backups.
#   * LoadCredentialEncrypted= is decrypted by the service manager (root; host key and/or
#     TPM2) and handed to the service as a read-only file in a RAM-backed directory that
#     only the service account (and root) can read ($CREDENTIALS_DIRECTORY, %d). At rest
#     the key is /etc/tenko/kek.cred, sealed to this host.
# The `systemd_credential` provider reads that file. The credential holds the key as 32 raw
# bytes, 64 hexadecimal digits or base64, so `openssl rand -hex 32` (install step 4) is
# right. The server logs "loaded the key-encryption key from a systemd credential" at every
# start and reports the protection "systemd-creds (host key)"; it does not warn about a plain
# file. Later key generations (a rotation) are wrapped under the credential in
# <data dir>/kek and have the same protection.
# The credential name (tenko_kek) must match the --name used when encrypting and
# `kek.credential` in tenko.toml (default tenko_kek).
# To rotate the root key, add a second credential (for example tenko_kek_old) with another
# LoadCredentialEncrypted= line and list its name under `retired` in the [kek] section of
# tenko.toml (see tenko.example.toml).
LoadCredentialEncrypted=tenko_kek:/etc/tenko/kek.cred
Environment=TENKO_KEK__PROVIDER=systemd_credential
Environment=TENKO_KEK__CREDENTIAL=tenko_kek
# Alternative on a host where the tenko account may use a TPM2 (untested here): drop the
# three lines above, add SupplementaryGroups=tss, PrivateDevices=no, DevicePolicy=closed and
# DeviceAllow=/dev/tpmrm0 rw, and set TENKO_KEK__PROVIDER=systemd_creds with
# TENKO_KEK__WITH_KEY=tpm2. The service then spawns systemd-creds (allowed by the system
# call filter below). A credential encrypted with a TPM2 can also stay with the provider
# above if you declare it: TENKO_KEK__WITH_KEY=tpm2 (tenko cannot see how it was sealed).

# Filesystem
# /var/lib/tenko holds kek/ (later key generations; the root key is the credential), store/ (redb files, fsynced
# on every commit), tls/ca-root.pem and logs/. Mode 0700: the service account only.
# Put it on SSD or NVMe (OPS-19); the server logs the fsync median at start and warns
# above 10 ms.
StateDirectory=tenko
StateDirectoryMode=0700
# /var/log/tenko, created and owned by the service account, the only place besides the state
# directory that the service may write. It is for `log.file = "/var/log/tenko/tenko.log"` in
# tenko.toml (the journal gets the log either way). The server rotates that file itself by
# size: [log] max_file_mb (default 64) is the size at which tenko.log moves to tenko.log.1,
# and keep_files (default 5) is how many rotated files stay (tenko.log.1 to tenko.log.5;
# the oldest is deleted). Nothing else (logrotate) needs to run.
LogsDirectory=tenko
LogsDirectoryMode=0750
UMask=0077
# /etc and the rest of the system are read-only for the service. Imported TLS certificates
# (tls.mode = "imported") are read from /etc/tenko/tls, readable by group tenko.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes

# Kernel and process isolation
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RemoveIPC=yes
# No core dumps: process memory holds the unsealed KEK and data keys.
LimitCORE=0

# Network
# TCP and UDP listeners (AF_INET, AF_INET6: the API, the dns role, the dhcp role in relay
# mode, the forwarder's upstream queries) and the sd_notify socket (AF_UNIX).
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# System calls
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# A call outside the filter fails with EPERM instead of killing the service.
SystemCallErrorNumber=EPERM

# Limits
# One descriptor per open connection (server.max_connections, default 20000, and the dns
# role's TCP connections, [dns.tcp] max_connections, default 1000) plus the store files,
# the dns role's UDP sockets (one per worker and listen address on Linux) and the
# forwarder's upstream sockets.
LimitNOFILE=65536

# The probe role: deploy/systemd/probe.conf is a drop-in for `--roles controller,probe`
# (CAP_NET_RAW and the address families the scan methods need). Install it as
# /etc/systemd/system/tenko.service.d/probe.conf; see its header.
#
# The dhcp role: it runs in this process when tenko.toml lists it (roles =
# "controller,dhcp"). In relay mode (the gateway relays to the node's unicast address,
# [dhcp] listen with mode = "relay") it binds UDP 67 and needs nothing but the
# CAP_NET_BIND_SERVICE above. Direct mode (the node hears the broadcasts of clients on its
# link) binds the interface with SO_BINDTODEVICE and answers a client without an address
# through an AF_PACKET socket, which needs CAP_NET_RAW, AF_PACKET and AF_NETLINK:
# deploy/systemd/dhcp-direct.conf is the drop-in for that. Install it as
# /etc/systemd/system/tenko.service.d/dhcp-direct.conf; see its header.

[Install]
WantedBy=multi-user.target
TENKO_UNIT_END
}

# The drop-in of deploy/systemd/probe.conf, unchanged: CAP_NET_RAW and the address families
# of the raw scan methods, for the probe role (deploy/systemd/smoke.sh compares the
# installed file with the one in the repository).
probe_dropin_text() {
  cat <<'TENKO_PROBE_END'
# Drop-in for the probe role of Tenko DDI: lets the unit run `tenko serve --roles
# controller,probe` (or roles = "controller,probe" in tenko.toml).
#
# Install (as root):
#   install -d /etc/systemd/system/tenko.service.d
#   install -m 0644 deploy/systemd/probe.conf /etc/systemd/system/tenko.service.d/probe.conf
#   systemctl daemon-reload && systemctl restart tenko
# Without systemd, `setcap cap_net_raw+ep` on the binary does the same for the capability
# (repeat it after every update, because a replaced file loses it).
# To remove it: delete the file, then `systemctl daemon-reload && systemctl restart tenko`.
#
# What it opens up, compared with the base unit (whose only capability is
# CAP_NET_BIND_SERVICE, for the dns role on port 53, which stays):
#   * CAP_NET_RAW, in the bounding set and as an ambient capability, so the unprivileged
#     account `tenko` may open raw sockets. The scan methods that need them (arp_sweep,
#     tcp_syn, os_fingerprint, lldp and dhcp_snoop; docs/scanning.md, section 9) run with
#     it (WP3.14) and answer `unsupported` without it, so `tenko node scan status` reports
#     "raw sockets: yes" once it is granted. The probe role works without it; grant it to
#     use those methods.
#   * AF_NETLINK: the `nd` method reads the IPv6 neighbor table with the `ip` command, which
#     talks to the kernel over netlink, and the scanner lists interfaces.
#   * AF_PACKET: layer-2 sockets for the raw methods above.
# Everything else in the base unit stays: no new privileges, the system call filter, a
# read-only system, and the state directory as the only writable place besides the log
# directory.
#
# Listing only what is new is not enough for these three settings: the base unit sets the
# first two to empty and gives the third a shorter list, so each is reset below and given
# its full value.
#
# The ICMP echo of the scan method `icmp` uses an unprivileged datagram socket when
# net.ipv4.ping_group_range admits the group `tenko`, and the `ping` command otherwise; it
# needs no capability.

[Service]
AmbientCapabilities=
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
TENKO_PROBE_END
}

step_unit() {
  local changed=0
  [[ -d /etc/systemd/system ]] || run install -d -m 0755 /etc/systemd/system
  unit_text | put "$UNIT" 0644 root:root && changed=1
  if [[ "$KEK_MODE" == file || "$KEK_MODE" == config ]]; then
    [[ -d "$DROPIN_DIR" ]] || run install -d -m 0755 "$DROPIN_DIR"
    # A drop-in instead of an edited unit: the shipped unit stays as released (a rerun
    # replaces it), and the empty LoadCredentialEncrypted= resets the credential list.
    {
      echo "# Written by the Tenko installer. The key-encryption key is not a systemd credential"
      echo "# on this host: no LoadCredentialEncrypted= (an empty assignment resets the list),"
      echo "# and tenko.toml's [kek] section decides the provider."
      echo "[Service]"
      echo "LoadCredentialEncrypted="
      echo "UnsetEnvironment=TENKO_KEK__PROVIDER TENKO_KEK__CREDENTIAL"
    } | put "$DROPIN_KEK" 0644 root:root && changed=1
  elif [[ -f "$DROPIN_KEK" ]]; then
    run rm -f "$DROPIN_KEK"
    changed=1
  fi
  if [[ "$DATA_DIR" != "$DEFAULT_DATA_DIR" ]]; then
    [[ -d "$DROPIN_DIR" ]] || run install -d -m 0755 "$DROPIN_DIR"
    {
      echo "# Written by the Tenko installer: the data directory is ${DATA_DIR}."
      echo "[Service]"
      echo "Environment=TENKO_DATA_DIR=${DATA_DIR}"
      echo "ReadWritePaths=${DATA_DIR}"
      echo "ExecStart="
      echo "ExecStart=${DATA_DIR}/updates/current/tenko serve --config ${CONFIG}"
    } | put "$DROPIN_DATA" 0644 root:root && changed=1
  elif [[ -f "$DROPIN_DATA" ]]; then
    run rm -f "$DROPIN_DATA"
    changed=1
  fi
  # The probe role: its drop-in comes with the role and goes with it (--reconfigure --roles
  # without probe), the way dhcp-direct.conf is left to the operator because it needs an
  # interface the installer does not ask for.
  if [[ "$ROLES" == *probe* ]]; then
    [[ -d "$DROPIN_DIR" ]] || run install -d -m 0755 "$DROPIN_DIR"
    probe_dropin_text | put "$DROPIN_PROBE" 0644 root:root && changed=1
  elif [[ -f "$DROPIN_PROBE" ]]; then
    run rm -f "$DROPIN_PROBE"
    changed=1
  fi
  if ((changed)); then
    if [[ -f "$DROPIN_KEK" || -f "$DROPIN_DATA" || -f "$DROPIN_PROBE" ]]; then
      ok "Installed the unit ${UNIT} with drop-ins in ${DROPIN_DIR}"
    else
      ok "Installed the unit ${UNIT}"
    fi
    UNIT_CHANGED=1
  else
    ok "The unit is current"
  fi
}

step_start() {
  if ((OPT_NO_START)); then
    ok "Not started (--no-start). Start it with: systemctl enable --now tenko"
    return 0
  fi
  ((UNIT_CHANGED)) && run systemctl daemon-reload
  if ! systemctl is-enabled --quiet tenko 2>/dev/null; then
    run systemctl enable tenko
  fi
  if ((ACTIVE)) && ((!UPGRADED)) && ((UNIT_CHANGED || WROTE_CONFIG)); then
    info "Restarting tenko for the changed unit or configuration"
    run systemctl restart tenko
  elif ! systemctl is-active --quiet tenko 2>/dev/null || ((UPGRADED)); then
    info "Starting tenko"
    run systemctl reset-failed tenko 2>/dev/null || true
    run systemctl start --no-block tenko
  fi
  ((OPT_DRY)) && return 0
  wait_ready
}

wait_ready() {
  local deadline=$((SECONDS + ${TENKO_READY_SECONDS:-180})) ca="${DATA_DIR}/tls/ca-root.pem" state status
  info "Waiting for the node to become ready (tenko health)"
  while ((SECONDS < deadline)); do
    state="$(systemctl show -p ActiveState --value tenko 2>/dev/null || true)"
    if [[ "$state" == failed ]]; then
      status="$(systemctl show -p ExecMainStatus --value tenko 2>/dev/null || true)"
      start_failed "$status"
      return 0
    fi
    if [[ "$state" == active && -f "$ca" ]] &&
      "$BIN" health --url "https://localhost:${API_PORT}" --ca-file "$ca" >/dev/null 2>&1; then
      ok "The node is ready: $("$BIN" health --live --url "https://localhost:${API_PORT}" --ca-file "$ca" 2>/dev/null | head -n 1)"
      return 0
    fi
    sleep 2
  done
  journalctl -u tenko -n 30 --no-pager 2>/dev/null | sed 's/^/      /' >&2 || true
  die "$E_START" "The node did not become ready in ${TENKO_READY_SECONDS:-180} s; see journalctl -u tenko"
}

# start_failed <status>: a fresh sealed key that never reaches the server (status 243,
# CREDENTIALS, or the kek start step failing with status 4) becomes a plain file once: the
# server stopped at its first step and encrypted nothing. Anything else stops with the journal.
RETRIED_KEK=0
start_failed() {
  local status="$1" invocation kek_failed=0
  invocation="$(systemctl show -p InvocationID --value tenko 2>/dev/null || true)"
  if [[ "$status" == 4 && -n "$invocation" ]] &&
    journalctl --no-pager -q "_SYSTEMD_INVOCATION_ID=${invocation}" 2>/dev/null | grep -q 'vault.kek.unavailable'; then
    kek_failed=1
  fi
  if [[ "$status" == 243 || "$kek_failed" == 1 ]] && [[ "$KEK_MODE" == sealed && "$FRESH_KEY" == 1 && "$RETRIED_KEK" == 0 ]]; then
    RETRIED_KEK=1
    warn "The server did not receive the sealed key (status ${status}); it stopped at its first step, so the key becomes a plain file instead"
    local key
    key="$(systemd-creds decrypt --name=tenko_kek "$KEK_CRED" - 2>/dev/null || true)"
    [[ "$key" =~ ^[0-9a-f]{64}$ ]] || key="$(new_key)"
    KEK_MODE="" KEK_TARGET="file" KEK_REASON="the server did not receive the sealed credential here (status ${status})" NEW_KEY="$key"
    rm -f "$KEK_CRED"
    step_kek
    config_add_kek_file
    step_config_check
    step_unit
    systemctl daemon-reload
    systemctl reset-failed tenko || true
    systemctl start --no-block tenko
    wait_ready
    return 0
  fi
  journalctl -u tenko -n 30 --no-pager 2>/dev/null | sed 's/^/      /' >&2 || true
  if [[ "$status" == 226 || "$status" == 218 ]] && [[ -n "$IN_CONTAINER" ]]; then
    err "The unit's sandbox needs privileges this container lacks (status ${status}); deploy/README.md, LXC, has the drop-in that relaxes only the failing options"
  fi
  die "$E_START" "tenko failed to start (status ${status:-unknown}); see journalctl -u tenko"
}

SETUP_TOKEN="" SETUP_DONE=0
step_setup() {
  ((OPT_NO_START || OPT_DRY)) && return 0
  [[ -f "${DATA_DIR}/setup-token" ]] || return 0
  SETUP_TOKEN="$(as_tenko "$BIN" setup token --config "$CONFIG" --data-dir "$DATA_DIR" 2>/dev/null || true)"
  [[ -n "$ADMIN" ]] || return 0
  info "Completing first-run setup with the administrator ${ADMIN}"
  local rc=0
  printf '%s\n' "$PASSWORD" | TENKO_SETUP_TOKEN="$SETUP_TOKEN" "$BIN" setup \
    --url "https://localhost:${API_PORT}" --ca-file "${DATA_DIR}/tls/ca-root.pem" \
    --admin "$ADMIN" --host-name "$HOST_NAME" --profile "$PROFILE" --language "$LANGUAGE" \
    --password-stdin >"${TMP}/setup.log" 2>&1 || rc=$?
  PASSWORD=""
  if ((rc != 0)); then
    sed 's/^/      /' "${TMP}/setup.log" >&2
    SETUP_FAILED="$rc"
    err "tenko setup failed (exit ${rc}); the node runs, complete setup in the browser with the token below"
    return 0
  fi
  SETUP_DONE=1 SETUP_TOKEN=""
  ok "First-run setup is complete: ${ADMIN} is the administrator, profile ${PROFILE}"
}

summary() {
  local ip url fp="" SHOWN_VERSION="$NEW_VERSION"
  # A newer version that runs already (an older binary was given) is the one to name.
  if [[ -n "$OLD_VERSION" && "$(version_cmp "$OLD_VERSION" "$NEW_VERSION")" == 1 ]]; then
    SHOWN_VERSION="$OLD_VERSION"
  fi
  ip="$(primary_ipv4 || true)"
  url="https://${HOST_NAME}:${API_PORT}/"
  echo
  if ((CHANGED == 0)); then
    bold "  Tenko ${SHOWN_VERSION} is installed and up to date; nothing was changed"
  elif ((OPT_DRY)); then
    bold "  Dry run: the steps above were printed, nothing was changed"
    return 0
  else
    bold "  Tenko ${SHOWN_VERSION} is installed"
  fi
  if [[ -f "${DATA_DIR}/tls/ca-root.pem" ]] && have openssl; then
    fp="$(openssl x509 -in "${DATA_DIR}/tls/ca-root.pem" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')"
  fi
  printf '    %-14s %s\n' "Web UI:" "$url"
  [[ -n "$ip" ]] && printf '    %-14s %s\n' "" "https://${ip}:${API_PORT}/"
  [[ -n "$fp" ]] && printf '    %-14s %s\n' "CA root:" "${DATA_DIR}/tls/ca-root.pem (SHA-256 ${fp})"
  if ((SETUP_DONE)); then
    printf '    %-14s %s\n' "Administrator:" "$ADMIN (sign in at the URL)"
  elif [[ -n "$SETUP_TOKEN" ]]; then
    # round2: the token is shown once here; say so and where it comes from again.
    printf '    %-14s %s\n' "Setup token:" "$SETUP_TOKEN" "" "(a one-time token, valid while setup is open; it changes at every start)" \
      "" "(print it again: runuser -u tenko -- tenko setup token --config ${CONFIG})"
  elif ((OPT_NO_START)); then
    printf '    %-14s %s\n' "Setup:" "after the first start: runuser -u tenko -- tenko setup token --config ${CONFIG}"
  fi
  printf '    %-14s %s\n' "Next:" "docs/QUICKSTART.md in the repository: the roles, a first network, the firewall ports."
  printf '    %-14s %s\n' "Data:" "$DATA_DIR" "Configuration:" "$CONFIG"
  ((USE_SELF_DONE)) && printf '    %-14s %s\n' "Host resolver:" "127.0.0.1 (Tenko; --uninstall restores the previous one)"
  # WP7.5: the dhcp role needs an address to listen on, and direct mode a drop-in.
  if [[ "$ROLES" == *dhcp* ]]; then
    printf '    %-14s %s\n' "DHCP:" "set [dhcp] listen in ${CONFIG} (relay mode: the node's address, the gateway relays to it;" \
      "" "direct mode: an interface, and install deploy/systemd/dhcp-direct.conf as" \
      "" "/etc/systemd/system/tenko.service.d/dhcp-direct.conf); then restart the service." \
      "" "UDP 67 must be open on the host's firewall; 547 (DHCPv6) is not served yet."
    if [[ "$ROLES" != *probe* ]]; then
      printf '    %-14s %s\n' "" "Conflict detection (docs/dhcp.md, section 14.5) is off without the probe role:" \
        "" "add probe to roles in ${CONFIG} and run this script again, which installs its drop-in."
    fi
  fi
  if [[ "$ROLES" == *probe* ]]; then
    printf '    %-14s %s\n' "Probe:" "${DROPIN_PROBE} grants CAP_NET_RAW (ARP for the dhcp role's conflict" \
      "" "detection, the raw scan methods); --reconfigure --roles without probe removes it."
  fi
  case "$KEK_MODE" in
  sealed)
    printf '    %-14s %s\n' "Key:" "${KEK_CRED} (sealed with systemd-creds to this host)"
    printf '    %-14s %s\n' "Back it up:" "systemd-creds decrypt --name=tenko_kek ${KEK_CRED} -   (keep the output offline)"
    ;;
  file)
    printf '    %-14s %s\n' "Key:" "${KEK_FILE} (a plain file, not sealed)"
    printf '    %-14s %s\n' "Back it up:" "cat ${KEK_FILE}   (keep the output offline)"
    ;;
  config) printf '    %-14s %s\n' "Key:" "as [kek] of ${CONFIG} says (default ${DATA_DIR}/kek, inside the data directory)" ;;
  esac
  printf '    %-14s %s\n' "" "A backup needs the data directory and the key, kept in different places;" \
    "" "a store restored without its key cannot open its secrets."
  printf '    %-14s %s\n' "Logs:" "journalctl -u tenko" "Upgrade:" "run this script again" \
    "Remove:" "bash install.sh --uninstall   (keeps the data and the key; --purge removes them)"
  echo
}

# ── Uninstall ───────────────────────────────────────────────────────────────────────────────
uninstall() {
  local link
  [[ -f "$UNIT" || -x "$BIN" ]] || ((OPT_PURGE)) || {
    ok "Tenko is not installed; nothing to remove"
    return 0
  }
  if ((OPT_PURGE)) && ((!OPT_YES)); then
    local answer=""
    [[ -n "$TTY" ]] || die "$E_USAGE" "--purge without --yes needs a terminal to confirm"
    printf 'This deletes %s, %s (the key and the configuration), %s and the account tenko.\nType purge to go on: ' \
      "$DATA_DIR" "$ETC" "$LOG_DIR" >"$TTY"
    IFS= read -r answer <"$TTY" || cancelled
    [[ "$answer" == purge ]] || cancelled
  fi
  restore_host_resolver
  if ((SYSTEMD)) && [[ -f "$UNIT" ]]; then
    systemctl is-active --quiet tenko 2>/dev/null && run systemctl stop tenko
    systemctl is-enabled --quiet tenko 2>/dev/null && run systemctl disable tenko
  fi
  [[ -f "$DROPIN_KEK" ]] && run rm -f "$DROPIN_KEK"
  [[ -f "$DROPIN_DATA" ]] && run rm -f "$DROPIN_DATA"
  [[ -f "$DROPIN_PROBE" ]] && run rm -f "$DROPIN_PROBE"
  [[ -d "$DROPIN_DIR" ]] && [[ -z "$(ls -A "$DROPIN_DIR")" ]] && run rmdir "$DROPIN_DIR"
  [[ -f "$UNIT" ]] && run rm -f "$UNIT"
  ((SYSTEMD)) && run systemctl daemon-reload
  [[ -e "$BIN" ]] && run rm -f "$BIN"
  ok "Removed the service and ${BIN}"
  # round2: updates/ holds binaries (one per version, plus the links current and previous), not
  # data; the next install's `tenko upgrade layout` recreates it from the installed binary.
  if [[ -d "${DATA_DIR}/updates" ]] && ((!OPT_PURGE)); then
    run rm -rf "${DATA_DIR}/updates"
    ok "Removed ${DATA_DIR}/updates (the binaries of the installed versions; a reinstall starts the layout afresh, so going back to the previous version is not possible after an uninstall)"
  fi
  if [[ "$(state_get resolved_stub_off)" == 1 ]]; then
    run rm -f "$RESOLVED_DROPIN"
    link="$(state_get resolv_conf_link)"
    [[ -n "$link" ]] && run ln -sfn "$link" /etc/resolv.conf
    ((SYSTEMD)) && run systemctl restart systemd-resolved
    ok "systemd-resolved listens on 127.0.0.53 again"
  fi
  if ((OPT_PURGE)); then
    [[ -d "$DATA_DIR" ]] && run rm -rf "$DATA_DIR"
    [[ -d "$ETC" ]] && run rm -rf "$ETC"
    [[ -d "$LOG_DIR" ]] && run rm -rf "$LOG_DIR"
    id -u tenko >/dev/null 2>&1 && run userdel tenko
    ok "Purged ${DATA_DIR}, ${ETC}, ${LOG_DIR} and the account tenko"
  else
    [[ -f "$STATE_FILE" ]] && run rm -f "$STATE_FILE"
    ok "Kept ${DATA_DIR}, ${ETC} (configuration and key) and the account tenko; --purge removes them"
  fi
}

# ── Arguments ───────────────────────────────────────────────────────────────────────────────
need() { [[ $# -ge 2 && -n "$2" ]] || die "$E_USAGE" "$1 needs a value"; }
parse_args() {
  while (($#)); do
    case "$1" in
    -y | --yes) OPT_YES=1 ;;
    --dry-run) OPT_DRY=1 ;;
    --no-start) OPT_NO_START=1 ;;
    --reconfigure) OPT_RECONFIGURE=1 ;;
    --uninstall) OPT_UNINSTALL=1 ;;
    --purge) OPT_PURGE=1 ;;
    --password-stdin) OPT_PASSWORD_STDIN=1 ;;
    --keep-resolved-stub) OPT_KEEP_STUB=1 ;;
    --print-unit)
      unit_text
      exit 0
      ;;
    --use-self) OPT_USE_SELF=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    --roles) need "$@"; OPT_ROLES="$2" SET_ROLES=1; shift ;;
    --modules) need "$@"; OPT_MODULES="$2" SET_MODULES=1; shift ;;
    --profile) need "$@"; OPT_PROFILE="$2"; shift ;;
    --host-name) need "$@"; OPT_HOST="$2"; shift ;;
    --dns-address) need "$@"; OPT_DNS_ADDRESS="$2" SET_DNS_ADDRESS=1; shift ;;
    --forwarders) need "$@"; OPT_FORWARDERS="$2" SET_FORWARDERS=1; shift ;;
    --data-dir) need "$@"; OPT_DATA_DIR="${2%/}"; shift ;;
    --version) need "$@"; OPT_VERSION="${2#v}"; shift ;;
    --language) need "$@"; OPT_LANGUAGE="$2"; shift ;;
    --admin) need "$@"; OPT_ADMIN="$2" SET_ADMIN=1; shift ;;
    --binary) need "$@"; OPT_BINARY="$2"; shift ;;
    --token) need "$@"; OPT_TOKEN="$2"; shift ;;
    --repo) need "$@"; OPT_REPO="$2"; shift ;;
    --release-url) need "$@"; OPT_RELEASE_URL="$2"; shift ;;
    --kek) need "$@"; OPT_KEK="$2"; shift ;;
    --*=*) set -- "${1%%=*}" "${1#*=}" "${@:2}"; continue ;;
    *) die "$E_USAGE" "Unknown option: $1 (see --help)" ;;
    esac
    shift
  done
  ((OPT_PURGE && !OPT_UNINSTALL)) && die "$E_USAGE" "--purge goes with --uninstall"
  OPT_VERSION="${OPT_VERSION:-latest}"
  OPT_REPO="${OPT_REPO:-${TENKO_REPO:-linkztream/tenko}}"
  OPT_TOKEN="${OPT_TOKEN:-${GITHUB_TOKEN:-}}"
  check_or_die valid_version "$OPT_VERSION" --version
  check_or_die valid_repo "$OPT_REPO" --repo
  [[ -z "$OPT_KEK" ]] || check_or_die valid_kek "$OPT_KEK" --kek
  [[ -z "$OPT_ADMIN" ]] || check_or_die valid_admin "$OPT_ADMIN" --admin
  [[ -z "$OPT_RELEASE_URL" || "$OPT_RELEASE_URL" =~ ^https?:// ]] || die "$E_USAGE" "--release-url: an http or https URL"
  DATA_DIR="${OPT_DATA_DIR:-$DEFAULT_DATA_DIR}"
  if ((OPT_PASSWORD_STDIN)); then
    IFS= read -r PASSWORD || true
    [[ -n "$PASSWORD" ]] || die "$E_USAGE" "--password-stdin: standard input has no password"
  elif [[ -n "${TENKO_ADMIN_PASSWORD:-}" ]]; then
    PASSWORD="$TENKO_ADMIN_PASSWORD"
  fi
  unset TENKO_ADMIN_PASSWORD
  export -n GITHUB_TOKEN 2>/dev/null || true
}

main() {
  parse_args "$@"
  if ((!OPT_YES)); then
    if { : >/dev/tty; } 2>/dev/null; then
      TTY=/dev/tty
    else
      die "$E_USAGE" "No terminal to ask on: pass --yes with the answers as flags"
    fi
  fi
  echo
  bold "  Tenko DDI installer"
  echo
  if [[ "$(id -u)" != 0 ]]; then
    ((OPT_DRY)) || die "$E_HOST" "Run as root (sudo bash install.sh ...)"
    warn "Not root: a dry run only, some checks are skipped"
  fi
  TMP="$(mktemp -d)"
  detect_host
  # An installation with another data directory names it in its drop-in.
  if [[ -z "$OPT_DATA_DIR" && -f "$DROPIN_DATA" ]]; then
    DATA_DIR="$(sed -n 's/^Environment=TENKO_DATA_DIR=//p' "$DROPIN_DATA" | tail -n 1)"
    DATA_DIR="${DATA_DIR:-$DEFAULT_DATA_DIR}"
  fi
  if ((OPT_UNINSTALL)); then
    uninstall
    exit 0
  fi
  detect_installed
  if [[ -n "$OLD_VERSION" ]]; then
    if ((ACTIVE)); then
      info "Installed: Tenko ${OLD_VERSION}, running"
    else
      info "Installed: Tenko ${OLD_VERSION}, not running"
    fi
  fi
  answers
  setup_answers
  get_binary
  plan_kek
  FRESH_KEY=0
  [[ -z "$KEK_MODE" ]] && FRESH_KEY=1
  step_ports
  step_account
  step_dirs
  step_binary
  WROTE_CONFIG=0 UNIT_CHANGED=0
  step_kek
  step_config
  step_config_check
  step_unit
  step_start
  step_setup
  step_use_self
  summary
  [[ -n "${SETUP_FAILED:-}" ]] && exit "$E_SETUP"
  exit 0
}

# Sourced (the tests), only the functions are defined; run (a file, bash -c, a pipe), it installs.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
