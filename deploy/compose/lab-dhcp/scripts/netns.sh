#!/bin/sh
# The network namespace of the node. The node's image has no shell and no capability, so
# this container owns the namespace, adds the route to the other networks through the
# gateway (the relay) and waits; the node joins it (network_mode: service:netns). Replies
# to a relay go to giaddr, an address of the gateway on another network.
#
# Environment: GATEWAY (the relay's address on the node's network), ROUTES (the
# destinations to reach through it).
set -eu
for net in $ROUTES; do
  ip route replace "$net" via "$GATEWAY"
done
ip -br addr
ip route
exec sleep infinity
