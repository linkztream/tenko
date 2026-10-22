#!/bin/sh
# The gateway of the DHCP lab: it routes between the four networks and relays every one of
# them to the node with ISC's dhcrelay, the node's own network included (the topology of
# E23, docs/plans/phase-3-plan.md section 2.5). Docker names the interfaces in the order it
# attaches the networks, so they are renamed after the network their address is in; the
# names are then the circuit-id of option 82 (dhcrelay -a).
#
# Environment: NODE (the node's address), NETWORKS (name=address pairs, one per network:
# the relay's own address on it).
set -eu

for pair in $NETWORKS; do
  name="${pair%%=*}"
  addr="${pair#*=}"
  dev="$(ip -o -4 addr show | awk -v a="$addr" '{ split($4, p, "/") } p[1] == a { print $2; exit }')"
  [ -n "$dev" ] || { echo "relay: no interface has $addr" >&2; exit 1; }
  if [ "$dev" != "$name" ]; then
    ip link set dev "$dev" down
    ip link set dev "$dev" name "$name"
    ip link set dev "$name" up
  fi
done
ip -br addr

# The node's network is upstream and downstream (-i); the others are downstream (-id).
# -a adds option 82 with the circuit-id (the interface's name) and takes it off the reply.
args=""
for pair in $NETWORKS; do
  name="${pair%%=*}"
  if [ "$name" = "${UPSTREAM:-servers}" ]; then
    args="$args -i $name"
  else
    args="$args -id $name"
  fi
done
# shellcheck disable=SC2086 # the interface arguments are words on purpose
exec dhcrelay -4 -d -a $args "$NODE"
