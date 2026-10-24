#!/bin/sh
# A client of the round dhcp6 of the DHCP lab: Docker gave its interface an IPv6 address;
# that one goes, so that the address in the rows is the one the server leased. The
# default IPv4 route goes through the gateway (the relay), which is also what the scope's
# option 3 says. Then it waits for smoke.sh to run dhclient in it (docker compose exec).
#
# Environment: GATEWAY (the relay's IPv4 address on the client's network).
set -eu
mkdir -p /run/lab
ip route replace default via "$GATEWAY"
ip -6 addr flush dev eth0 scope global
exec sleep infinity
