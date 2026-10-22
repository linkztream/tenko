# syntax=docker/dockerfile:1
#
# The Kea image of the DHCP lab (deploy/compose/lab-dhcp, WP9.3, E30's DHCPv4 rows):
# ISC Kea 2.6 from Debian 13's packages, so that the server started from Tenko's export
# shares no code with Tenko:
#
# - kea-dhcp4-server: kea-dhcp4, which checks the exported configuration (`-t`) and then
#   serves the lab's networks from it and from the exported lease file;
# - kea.sh: copies the exported lease file into Kea's data directory and starts it.
#
# Built by smoke.sh as tenko-dhcp-lab-kea:latest, from this directory:
#   docker build -f deploy/compose/lab-dhcp/kea.Dockerfile -t tenko-dhcp-lab-kea deploy/compose/lab-dhcp
FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends kea-dhcp4-server \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/kea.sh /lab/kea.sh
RUN chmod 0755 /lab/kea.sh
