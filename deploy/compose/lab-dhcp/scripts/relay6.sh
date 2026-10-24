#!/bin/sh
# The gateway of the round dhcp6 of the DHCP lab: ISC's dhcrelay relays two client links,
# lan6 and iot6, up to the node on servers6, for DHCPv6 (dhcrelay -6: the link address of
# a link is its first global address, and the relay adds the Interface-Id of RFC 8415 to
# every RELAY-FORW) and for DHCPv4 (dhcrelay -4: giaddr is the relay's address on the
# link), the second family so that one client can hold a lease of each. It also routes
# between the networks for IPv4 (a renewal is a unicast through it). The interfaces keep
# Docker's names, so that their IPv6 addresses stay when the relay starts.
#
# Environment: NODE4 and NODE6 (the node's addresses), UP4 (the relay's IPv4 address on
# servers6), LINKS4 (the relay's IPv4 addresses on the client links, blank separated).
set -eu

dev_of() {
  ip -o -4 addr show | awk -v a="$1" '{ split($4, p, "/") } p[1] == a { print $2; exit }'
}

up="$(dev_of "$UP4")"
[ -n "$up" ] || { echo "relay6: no interface has $UP4" >&2; exit 1; }
lower4=""
lower6=""
for addr in $LINKS4; do
  dev="$(dev_of "$addr")"
  [ -n "$dev" ] || { echo "relay6: no interface has $addr" >&2; exit 1; }
  lower4="$lower4 -id $dev"
  lower6="$lower6 -l $dev"
done

# dhcrelay -6 binds the global addresses: wait for the duplicate address detection.
waited=0
while ip -6 addr show tentative | grep -q inet6; do
  [ "$waited" -lt 30 ] || { echo "relay6: an IPv6 address stays tentative" >&2; exit 1; }
  sleep 1
  waited=$((waited + 1))
done
ip -br addr

# -a adds option 82 with the circuit-id (the interface's name) and takes it off the reply.
# shellcheck disable=SC2086 # the interface arguments are words on purpose
dhcrelay -4 -d -a --no-pid -iu "$up" $lower4 "$NODE4" &
# -I: the Interface-Id of RFC 8415 section 21.18 on every RELAY-FORW, also with one link.
# shellcheck disable=SC2086
exec dhcrelay -6 -d -I --no-pid $lower6 -u "$NODE6%$up"
