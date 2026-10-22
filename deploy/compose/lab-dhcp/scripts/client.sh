#!/bin/sh
# A client of the DHCP lab: its default route goes through the gateway (the relay), which
# is also what the scope's option 3 says, so that a renewal unicast to the node finds its
# way; then it waits for smoke.sh to run dhclient or udhcpc in it (docker compose exec).
#
# Environment: GATEWAY (the relay's address on the client's network).
set -eu
mkdir -p /run/lab
ip route replace default via "$GATEWAY"
exec sleep infinity
