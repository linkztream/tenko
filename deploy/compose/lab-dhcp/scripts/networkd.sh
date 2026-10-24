#!/bin/sh
# systemd-networkd as a DHCPv6 client in a container of the round dhcp6 of the DHCP lab,
# started directly (there is no systemd as process 1). Docker gave the interface an IPv6
# address; that one goes, so that the address in the rows is the one the server leased.
# networkd logs to the console, so that `docker compose logs` has what it did.
set -eu
mkdir -p /run/lab
ip -6 addr flush dev eth0 scope global
export SYSTEMD_LOG_LEVEL=debug SYSTEMD_LOG_TARGET=console
exec /lib/systemd/systemd-networkd
