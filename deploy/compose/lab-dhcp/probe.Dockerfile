# syntax=docker/dockerfile:1
#
# The node of the round dhcp6 with the probe role's capability (WP9.2): the binary of
# TENKO_IMAGE, unchanged, with the file capability cap_net_raw+ep, which is what
# deploy/systemd/probe.conf says to do with `setcap` where systemd does not grant it. Docker
# gives a container's non-root user no capability of its own (the effective set stays
# empty), so the lab sets it on the file; the compose service adds NET_RAW to the bounding
# set and leaves no-new-privileges off for this one container, since that would ignore a
# file capability. The bytes of the binary are those of TENKO_IMAGE: the rows run the
# shipped build.
#
# Built by smoke.sh (the round dhcp6) as TENKO_PROBE_IMAGE:
#   docker build -f deploy/compose/lab-dhcp/probe.Dockerfile --build-arg TENKO_IMAGE=tenko:lab \
#     -t tenko-dhcp-lab-probe deploy/compose/lab-dhcp
ARG TENKO_IMAGE=tenko:lab

FROM ${TENKO_IMAGE} AS tenko

FROM debian:12-slim AS caps
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tenko /usr/local/bin/tenko /tenko
RUN setcap cap_net_raw+ep /tenko

FROM ${TENKO_IMAGE}
COPY --from=caps /tenko /usr/local/bin/tenko
