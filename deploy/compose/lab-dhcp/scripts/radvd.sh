#!/bin/sh
# The router of the RA rows of the round dhcp6 (WP9.2, DHCP-10): radvd on servers6, the
# node's own link, advertising 2001:db8:100::/64 every three to four seconds with the M and
# O flags the row asks for. It is no default router (router lifetime 0) and offers no
# SLAAC (A off), so the routes and addresses of the other rows stay as they are.
#
#   radvd.sh run              the container's entry point: flags from MANAGED and OTHER
#                             (on or off, default off), radvd in the foreground
#   radvd.sh flags <M> <O>    new flags (on or off): the configuration is written again
#                             and radvd reads it on SIGHUP
#
# Environment: PREFIX (default 2001:db8:100::/64), MANAGED, OTHER.
set -eu
conf=/run/lab/radvd.conf
pidfile=/run/lab/radvd.pid

write() {
  cat >"$conf" <<EOF
interface eth0 {
  AdvSendAdvert on;
  MinRtrAdvInterval 3;
  MaxRtrAdvInterval 4;
  AdvDefaultLifetime 0;
  AdvManagedFlag $1;
  AdvOtherConfigFlag $2;
  prefix ${PREFIX:-2001:db8:100::/64} {
    AdvOnLink on;
    AdvAutonomous off;
  };
};
EOF
}

case "${1:-run}" in
  run)
    mkdir -p /run/lab
    write "${MANAGED:-off}" "${OTHER:-off}"
    exec radvd --nodaemon --config "$conf" --pidfile "$pidfile" --logmethod stderr
    ;;
  flags)
    write "$2" "$3"
    kill -HUP "$(cat "$pidfile")"
    ;;
  *)
    echo "usage: radvd.sh run | flags <on|off> <on|off>" >&2
    exit 2
    ;;
esac
