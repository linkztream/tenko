#!/usr/bin/env bash
# deploy/systemd/check-hardening.sh: the offline exposure gate of the shipped unit (check
# L1.8 of docs/plans/security-audit-plan.md). It scores deploy/systemd/tenko.service alone
# and with each drop-in with `systemd-analyze security --offline=true` and fails when a
# score reaches its gate. It needs no root and no running service manager: every
# combination is staged as /etc/systemd/system/tenko.service plus
# /etc/systemd/system/tenko.service.d/<drop-in> in a temporary tree, which
# `systemd-analyze --root=` reads the way the service manager reads an installed unit
# (drop-ins in order, an empty assignment resetting a list).
#
# Usage:
#   bash deploy/systemd/check-hardening.sh
#
# Environment:
#   UNIT_DIR        directory with tenko.service and the drop-ins (default: this script's)
#   GITHUB_STEP_SUMMARY   when set, the scores are appended to it as a table
#
# The combinations:
#   unit            tenko.service alone
#   <name>.conf     tenko.service with one drop-in of UNIT_DIR (probe.conf, dhcp-direct.conf);
#                   a drop-in without a gate below fails the check, so a new one gets measured
#   data-dir.conf   the drop-in deploy/install.sh writes for --data-dir (step_unit), with
#                   /srv/tenko as the example directory
#   kek-file.conf   the drop-in deploy/install.sh writes when the key-encryption key is not
#                   a systemd credential (step_unit)
#   memory.conf     the drop-in deploy/install.sh writes with the memory cap of the roles
#                   (step_memory), here with the budget of every role
#   all             tenko.service with every drop-in above at once
# The two installer drop-ins are written here as deploy/install.sh writes them; CI runs this
# check when either file changes, so a change to their text there must be made here too.
#
# The gates: each combination's score as measured plus 0.1, so that losing any setting
# worth 0.1 or more fails the check; the unit's gate also stays below 2.5, the ceiling of
# deploy/systemd/smoke.sh step 10. Measured on 2026-11-01 with systemd 255
# (255.4-1ubuntu8.18, Ubuntu 24.04, the systemd of ubuntu-latest). When a deliberate change
# of the unit or a drop-in moves a score, measure again and change the gate in the same
# commit, with the reason in the commit message. A newer systemd may score the same unit
# differently; measure again when the runner image moves to one.
#
# A score alone lets a setting that matters slip through while the total stays low, so each
# combination's settings are also read as the service manager would merge them (the unit,
# then its drop-ins in order, an empty assignment resetting a list) and must hold exactly:
#   User=tenko and Group=tenko, no DynamicUser= and no PermissionsStartOnly=;
#   no Exec*= command with a "+" or "!" prefix (one that would run with root's privileges or
#   without the sandbox);
#   NoNewPrivileges=yes and PrivateIPC=yes;
#   NoExecPaths=/ and ExecPaths= exactly the list below, plus the data directory's two
#   entries where the drop-in data-dir.conf is staged;
#   ReadWritePaths= exactly none, or the data directory where data-dir.conf is staged.
# Widening any of them is a deliberate change of this file in the same commit.
#
# Exit status: 0 every score is below its gate and every setting holds, 1 a score reached its
# gate, a setting does not hold or a drop-in has no gate, 2 the tools or files are missing or
# a score could not be read.

set -euo pipefail

# combination -> the gate (the score must be below it)
declare -A GATE=(
  [unit]=1.5
  [probe.conf]=1.7
  [dhcp-direct.conf]=1.7
  [data-dir.conf]=1.5
  [kek-file.conf]=1.5
  [memory.conf]=1.5
  [all]=1.7
)
# What the service may execute (tenko.service, "Execution"), and the data directory of the
# example data-dir.conf.
readonly EXEC_PATHS="/usr -/var/lib/tenko/updates -/var/lib/tenko/plugins"
readonly EXAMPLE_DATA_DIR=/srv/tenko
# The ceiling of the weekly smoke for the unit alone (deploy/systemd/smoke.sh, MAX_EXPOSURE).
readonly UNIT_CEILING=2.5

UNIT_DIR="${UNIT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
readonly UNIT_DIR

die() {
  echo "error: $*" >&2
  exit 2
}

command -v systemd-analyze > /dev/null || die "systemd-analyze is not installed"
[[ -f "$UNIT_DIR/tenko.service" ]] || die "$UNIT_DIR/tenko.service does not exist"
version="$(systemd-analyze --version | head -n 1)"
major="$(sed -E 's/^systemd ([0-9]+).*/\1/' <<< "$version")"
[[ "$major" =~ ^[0-9]+$ ]] || die "cannot read the systemd version from '$version'"
((major >= 250)) || die "systemd-analyze security --offline needs systemd 250 or later, this is $version"

if awk -v g="${GATE[unit]}" -v c="$UNIT_CEILING" 'BEGIN { exit !(g > c) }'; then
  die "the unit's gate ${GATE[unit]} is above the ceiling $UNIT_CEILING of smoke.sh"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The installer's drop-ins, as deploy/install.sh step_unit writes them.
installer_dropin() {
  case "$1" in
    data-dir.conf)
      echo "# Written by the Tenko installer: the data directory is /srv/tenko."
      echo "[Service]"
      echo "Environment=TENKO_DATA_DIR=/srv/tenko"
      echo "ReadWritePaths=/srv/tenko"
      echo "ExecPaths=-/srv/tenko/updates -/srv/tenko/plugins"
      echo "ExecStart="
      echo "ExecStart=/srv/tenko/updates/current/tenko serve --config /etc/tenko/tenko.toml"
      ;;
    kek-file.conf)
      echo "# Written by the Tenko installer. The key-encryption key is not a systemd credential"
      echo "# on this host: no LoadCredentialEncrypted= (an empty assignment resets the list),"
      echo "# and tenko.toml's [kek] section decides the provider."
      echo "[Service]"
      echo "LoadCredentialEncrypted="
      echo "UnsetEnvironment=TENKO_KEK__PROVIDER TENKO_KEK__CREDENTIAL"
      ;;
    memory.conf)
      echo "# Written by the Tenko installer: the memory cap of the roles controller, dns, dhcp, probe"
      echo "# (budget 7936 MiB)."
      echo "# To change it, run systemctl edit tenko and set MemoryHigh= and MemoryMax= under"
      echo "# [Service] (infinity removes the cap); the installer rewrites this file, not the override."
      echo "[Service]"
      echo "MemoryHigh=7142M"
      echo "MemoryMax=7936M"
      ;;
    *) die "no installer drop-in named $1" ;;
  esac
}

# Every drop-in: the files of UNIT_DIR, then the installer's.
dropins=()
shopt -s nullglob
for file in "$UNIT_DIR"/*.conf; do
  dropins+=("$(basename "$file")")
done
shopt -u nullglob
dropins+=(data-dir.conf kek-file.conf memory.conf)

# stage <name> <drop-in>...: a tree with the unit and the given drop-ins.
stage() {
  local root="$WORK/$1" name
  shift
  install -d "$root/etc/systemd/system/tenko.service.d"
  cp "$UNIT_DIR/tenko.service" "$root/etc/systemd/system/tenko.service"
  for name in "$@"; do
    if [[ -f "$UNIT_DIR/$name" ]]; then
      cp "$UNIT_DIR/$name" "$root/etc/systemd/system/tenko.service.d/$name"
    else
      installer_dropin "$name" > "$root/etc/systemd/system/tenko.service.d/$name"
    fi
  done
  echo "$root"
}

failed=0
rows=()

# service_lines <root>: the [Service] assignments of the staged unit and then of its drop-ins
# in the order of their names, as the service manager reads them, one "Key=value" per line.
service_lines() {
  local root="$1" file LC_ALL=C
  for file in "$root/etc/systemd/system/tenko.service" "$root/etc/systemd/system/tenko.service.d"/*.conf; do
    [[ -f "$file" ]] || continue
    awk '/^[[:space:]]*[#;]/ { next }
      /^[[:space:]]*\[/ { section = $0; gsub(/[[:space:]]/, "", section); next }
      section == "[Service]" && /=/ { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); print }' "$file"
  done
}

# last_value <lines> <key>: the value of the last assignment of the key, or nothing.
last_value() {
  grep -E "^$2=" <<< "$1" | tail -n 1 | cut -d= -f2-
}

# list_value <lines> <key>: the merged list of a list setting (an empty assignment resets
# it), sorted and without duplicates, separated by spaces.
list_value() {
  local line value words=() out=()
  while IFS= read -r line; do
    value="${line#*=}"
    if [[ -z "$value" ]]; then
      out=()
    else
      read -ra words <<< "$value"
      out+=("${words[@]}")
    fi
  done < <(grep -E "^$2=" <<< "$1")
  ((${#out[@]})) || return 0
  printf '%s\n' "${out[@]}" | LC_ALL=C sort -u | paste -sd ' ' -
}

# sorted_words <words>: the words sorted and without duplicates, separated by spaces.
sorted_words() {
  local words
  read -ra words <<< "$1"
  ((${#words[@]})) || return 0
  printf '%s\n' "${words[@]}" | LC_ALL=C sort -u | paste -sd ' ' -
}

# settings_problems <root> <with the data-dir drop-in: 0 or 1>: one line per setting that
# does not hold, nothing when every one does.
settings_problems() {
  local root="$1" data_dir="$2" lines want got line command prefix
  lines="$(service_lines "$root")"
  [[ "$(last_value "$lines" User)" == tenko ]] || echo "User= is '$(last_value "$lines" User)', not tenko"
  [[ "$(last_value "$lines" Group)" == tenko ]] || echo "Group= is '$(last_value "$lines" Group)', not tenko"
  grep -qE '^DynamicUser=' <<< "$lines" && echo "DynamicUser= is set"
  grep -qE '^PermissionsStartOnly=' <<< "$lines" && echo "PermissionsStartOnly= is set"
  while IFS= read -r line; do
    command="${line#*=}"
    [[ -n "$command" ]] || continue
    prefix="${command%%[!-@:+!|]*}"
    [[ "$prefix" == *[+!]* ]] && echo "a command runs with a '+' or '!' prefix: $line"
  done < <(grep -E '^Exec(Start|StartPre|StartPost|Condition|Reload|Stop|StopPost)=' <<< "$lines")
  [[ "$(last_value "$lines" NoNewPrivileges)" == yes ]] || echo "NoNewPrivileges= is not yes"
  [[ "$(last_value "$lines" PrivateIPC)" == yes ]] || echo "PrivateIPC= is not yes"
  [[ "$(list_value "$lines" NoExecPaths)" == / ]] || echo "NoExecPaths= is '$(list_value "$lines" NoExecPaths)', not /"
  want="$EXEC_PATHS"
  ((data_dir)) && want+=" -${EXAMPLE_DATA_DIR}/updates -${EXAMPLE_DATA_DIR}/plugins"
  want="$(sorted_words "$want")"
  got="$(list_value "$lines" ExecPaths)"
  [[ "$got" == "$want" ]] || echo "ExecPaths= is '$got', not '$want'"
  want=""
  ((data_dir)) && want="$EXAMPLE_DATA_DIR"
  got="$(list_value "$lines" ReadWritePaths)"
  [[ "$got" == "$want" ]] || echo "ReadWritePaths= is '$got', not '$want'"
  return 0
}

# check_settings <combination> <root> <with the data-dir drop-in: 0 or 1>
check_settings() {
  local problems
  problems="$(settings_problems "$2" "$3")"
  if [[ -z "$problems" ]]; then
    echo "PASS $1: the settings hold"
  else
    echo "FAIL $1: $(paste -sd ';' - <<< "$problems")"
    failed=1
  fi
}

# The settings check finds what it is for: each change below, made to a staged copy of the
# unit, must be refused. A check that passed one of them would pass the same change in the
# shipped unit.
self_test() {
  local root case probe ok=1
  local -a cases=(
    's|^ExecStartPre=/|ExecStartPre=+/|'
    's|^ExecStart=/|ExecStart=!/|'
    's|^ExecStart=/|ExecStart=-!!/|'
    's|^User=tenko|User=root|'
    's|^Group=tenko|Group=root|'
    's|^NoNewPrivileges=yes|NoNewPrivileges=yes\nPermissionsStartOnly=yes|'
    's|^PrivateIPC=yes|PrivateIPC=no|'
    's|^NoExecPaths=/|NoExecPaths=|'
    's|^ExecPaths=.*|&\nExecPaths=/var/lib/tenko|'
    's|^ProtectHome=yes|&\nReadWritePaths=/etc|'
    's|^NoNewPrivileges=yes|&\nDynamicUser=yes|'
  )
  root="$(stage self-test)"
  probe="$(settings_problems "$root" 0)"
  if [[ -n "$probe" ]]; then
    echo "FAIL self-test: the unchanged unit does not pass: $probe"
    failed=1
    return
  fi
  for case in "${cases[@]}"; do
    cp "$UNIT_DIR/tenko.service" "$root/etc/systemd/system/tenko.service"
    sed -i -E "$case" "$root/etc/systemd/system/tenko.service"
    if cmp -s "$UNIT_DIR/tenko.service" "$root/etc/systemd/system/tenko.service"; then
      echo "FAIL self-test: '$case' changes nothing in the unit"
      ok=0
    elif [[ -z "$(settings_problems "$root" 0)" ]]; then
      echo "FAIL self-test: the settings check passes a unit changed by '$case'"
      ok=0
    fi
  done
  if ((ok)); then
    echo "PASS self-test: the settings check refuses each of ${#cases[@]} weakened copies of the unit"
  else
    failed=1
  fi
}

# check <combination> <drop-in>...
check() {
  local combo="$1" root report line score gate data_dir=0
  shift
  gate="${GATE[$combo]:-}"
  if [[ -z "$gate" ]]; then
    echo "FAIL $combo: no gate; measure it and add it to GATE in $0"
    rows+=("| \`$combo\` | not scored | none | FAIL (no gate) |")
    failed=1
    return
  fi
  root="$(stage "$combo" "$@")"
  [[ " $* " == *" data-dir.conf "* ]] && data_dir=1
  check_settings "$combo" "$root" "$data_dir"
  report="$WORK/$combo.txt"
  # The exit status is that of --threshold (100 by default), not of the gate.
  systemd-analyze security --offline=true --no-pager --root="$root" tenko.service > "$report" 2>&1 || true
  line="$(grep 'Overall exposure level' "$report")" || {
    cat "$report" >&2
    die "systemd-analyze printed no overall exposure level for $combo"
  }
  score="$(sed -E 's/.*: ([0-9]+(\.[0-9]+)?).*/\1/' <<< "$line")"
  [[ "$score" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "cannot read the score of $combo from '$line'"
  if awk -v s="$score" -v g="$gate" 'BEGIN { exit !(s < g) }'; then
    echo "PASS $combo: exposure $score, below $gate"
    rows+=("| \`$combo\` | $score | $gate | PASS |")
  else
    echo "FAIL $combo: exposure $score, not below $gate"
    cat "$report"
    rows+=("| \`$combo\` | $score | $gate | FAIL |")
    failed=1
  fi
}

echo "$version"
self_test
check unit
for name in "${dropins[@]}"; do
  check "$name" "$name"
done
check all "${dropins[@]}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### systemd-analyze security --offline, tenko.service"
    echo
    echo "$version. A score must be below its gate."
    echo
    echo "| Combination | Exposure | Gate | Result |"
    echo "|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
  } >> "$GITHUB_STEP_SUMMARY"
fi

if ((failed)); then
  echo "The hardening check failed: a score reached its gate, a setting does not hold, or a drop-in has no gate." >&2
  exit 1
fi
echo "Every combination is below its gate, and its settings hold."
