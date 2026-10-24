# syntax=docker/dockerfile:1
#
# The networkd client of the round dhcp6 of the DHCP lab (deploy/compose/lab-dhcp): Debian
# 12's systemd-networkd (systemd 252) as a DHCPv6 client, started directly by
# scripts/networkd.sh (no systemd as process 1), with scripts/networkd-lab.network for eth0.
# A second client implementation next to ISC's dhclient: it sends Rapid Commit, a DUID-LL
# and asks for the NTP servers of option 56, and writes what it learns to
# /run/systemd/netif.
#
# Built by smoke.sh (ROUNDS=dhcp6) as tenko-dhcp-lab-networkd:latest, from this directory:
#   docker build -f deploy/compose/lab-dhcp/networkd.Dockerfile -t tenko-dhcp-lab-networkd deploy/compose/lab-dhcp
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends systemd iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/networkd-lab.network /etc/systemd/network/10-lab.network
COPY scripts/networkd.sh /lab/networkd.sh
RUN chmod 0755 /lab/networkd.sh
