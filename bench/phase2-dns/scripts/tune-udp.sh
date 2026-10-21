#!/usr/bin/env bash
# The UDP and socket sysctls of the load host for an M17 run (one node over a real link):
# raises them for the run, records the values before and after, and puts the saved values
# back afterwards. Run it on the load host only, never on the server host: the server's
# settings are part of what is measured and are recorded, not changed.
#
# The defaults of a fresh Ubuntu 24.04 host (rmem_max and wmem_max 212992 octets, a port
# range of 32768 to 60999, a backlog of 1000 packets) let a load generator lose its own
# datagrams in the socket buffers before the server sees them, and let a tool that opens
# many TCP connections run out of source ports; the raised values below take both out of
# the measurement. The sysctls are written with `sudo sysctl -w`, so they last until the
# restore or the next boot, and nothing under /etc is changed.
#
# Usage:
#   tune-udp.sh apply   [--state FILE]   save the current values to FILE, then raise them
#   tune-udp.sh restore [--state FILE]   write the saved values back and delete FILE
#   tune-udp.sh show                     print the current values
# The state file defaults to ~/.tune-udp.state. `apply` refuses to run while a state file
# exists (a second apply would save the raised values as the originals); `restore` without
# one does nothing. Every command prints the values, one "name = value" per line, for the
# results file.
set -eu
export LC_ALL=C

# The sysctls and the values of a run. rmem_max and wmem_max cap what a socket may ask
# for (dnsperf -b, flamethrower and the server's [dns.udp] buffers); the defaults are what a
# socket gets without asking.
KEYS="net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default net.core.netdev_max_backlog net.ipv4.ip_local_port_range"
value_for() {
  case "$1" in
    net.core.rmem_max | net.core.wmem_max) echo 33554432 ;;
    net.core.rmem_default | net.core.wmem_default) echo 8388608 ;;
    net.core.netdev_max_backlog) echo 30000 ;;
    net.ipv4.ip_local_port_range) echo "1024 65535" ;;
    *) return 1 ;;
  esac
}

COMMAND="${1:-}"
[ $# -eq 0 ] || shift
STATE="$HOME/.tune-udp.state"
while [ $# -gt 0 ]; do
  case "$1" in
    --state) STATE="$2"; shift 2 ;;
    -h | --help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = Linux ] || { echo "tune-udp.sh runs on a Linux load host" >&2; exit 2; }

# Prints "name = value" with the whitespace of multi-value sysctls collapsed to one space.
show() {
  local key
  for key in $KEYS; do
    printf '%s = %s\n' "$key" "$(sysctl -n "$key" | tr -s ' \t' '  ')"
  done
}

write() {
  sudo -n sysctl -q -w "$1=$2" || { echo "cannot set $1 (sudo without a password is needed)" >&2; exit 1; }
}

case "$COMMAND" in
  show)
    show
    ;;
  apply)
    [ ! -e "$STATE" ] || { echo "$STATE exists: restore first (tune-udp.sh restore)" >&2; exit 1; }
    show > "$STATE"
    echo "# before (saved to $STATE)"
    cat "$STATE"
    for key in $KEYS; do
      write "$key" "$(value_for "$key")"
    done
    echo "# after"
    show
    ;;
  restore)
    if [ ! -e "$STATE" ]; then
      echo "# no saved values in $STATE; nothing to restore"
      show
      exit 0
    fi
    while IFS= read -r line; do
      key="${line%% = *}"
      value="${line#* = }"
      [ -n "$key" ] && [ "$key" != "$line" ] || continue
      write "$key" "$value"
    done < "$STATE"
    rm -f "$STATE"
    echo "# restored"
    show
    ;;
  *)
    echo "usage: tune-udp.sh apply|restore|show [--state FILE]" >&2
    exit 2
    ;;
esac
