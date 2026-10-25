# syntax=docker/dockerfile:1
#
# The Kea image of the DHCP lab (deploy/compose/lab-dhcp, WP9.3, E30): ISC Kea 2.6 from
# Debian 13's packages, so that the servers started from Tenko's export share no code
# with Tenko:
#
# - kea-dhcp4-server and kea-dhcp6-server: kea-dhcp4 and kea-dhcp6, which check the
#   exported configurations (`-t`) and then serve the lab's networks from them and from
#   the exported lease files (kea-dhcp4 in the default rows, kea-dhcp6 in the round
#   dhcp6);
# - kea.sh: copies the exported lease file into Kea's data directory and starts the
#   server of the family it is given.
#
# Built by smoke.sh as tenko-dhcp-lab-kea:latest (KEA_IMAGE), from this directory:
#   docker build -f deploy/compose/lab-dhcp/kea.Dockerfile -t tenko-dhcp-lab-kea deploy/compose/lab-dhcp
FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends kea-dhcp4-server kea-dhcp6-server \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/kea.sh /lab/kea.sh
RUN chmod 0755 /lab/kea.sh
