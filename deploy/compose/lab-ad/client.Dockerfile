# The Linux client of the AD lab: MIT Kerberos (kinit, klist), BIND's nsupdate for
# `nsupdate -g`, curl for the API of the node, and Python with the MIT GSSAPI bindings for
# gss_client.py, which runs the rows of E43 that nsupdate cannot steer (a skewed signature,
# a replay, an unknown and an expired context, an NTLM-only offer).
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-user bind9-dnsutils curl ca-certificates python3 python3-gssapi \
    && rm -rf /var/lib/apt/lists/*
