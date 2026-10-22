# syntax=docker/dockerfile:1
#
# The tools image of the DHCP lab (deploy/compose/lab-dhcp): everything in the lab that is
# not Tenko, from Debian's packages, so that nothing in it shares code with Tenko:
#
# - isc-dhcp-relay: ISC's relay agent dhcrelay, the lab's gateway (it also routes);
# - isc-dhcp-client: ISC's dhclient, the clients of the four networks;
# - kea-admin: Kea's perfdhcp, which sends as a relay agent (the load rows);
# - busybox: udhcpc, a second client implementation;
# - iproute2 for the routes and the interface names, python3 for relay-test.py.
#
# Built by smoke.sh as tenko-dhcp-lab-tools:latest, from this directory:
#   docker build -f deploy/compose/lab-dhcp/tools.Dockerfile -t tenko-dhcp-lab-tools deploy/compose/lab-dhcp
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        busybox iproute2 isc-dhcp-client isc-dhcp-relay kea-admin python3 \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/ /lab/
RUN chmod 0755 /lab/*.sh /lab/*.py
