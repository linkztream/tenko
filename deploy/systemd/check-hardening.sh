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
# Exit status: 0 every score is below its gate, 1 a score reached its gate or a drop-in has
# no gate, 2 the tools or files are missing or a score could not be read.

set -euo pipefail

# combination -> the gate (the score must be below it)
declare -A GATE=(
  [unit]=1.5
  [probe.conf]=1.7
  [dhcp-direct.conf]=1.7
  [data-dir.conf]=1.5
  [kek-file.conf]=1.5
  [all]=1.7
)
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
dropins+=(data-dir.conf kek-file.conf)

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

# check <combination> <drop-in>...
check() {
  local combo="$1" root report line score gate
  shift
  gate="${GATE[$combo]:-}"
  if [[ -z "$gate" ]]; then
    echo "FAIL $combo: no gate; measure it and add it to GATE in $0"
    rows+=("| \`$combo\` | not scored | none | FAIL (no gate) |")
    failed=1
    return
  fi
  root="$(stage "$combo" "$@")"
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
  echo "The hardening check failed: a score reached its gate, or a drop-in has no gate." >&2
  exit 1
fi
echo "Every combination is below its gate."
