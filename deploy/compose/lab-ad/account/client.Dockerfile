# The client of the round `account` (E45): MIT Kerberos (kinit, kvno, klist, ktutil) for a
# user's service tickets and the keytabs of the import rows, curl and jq for Tenko's API,
# which the round reaches from inside the lab network. Built by account/round.sh.
FROM ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends krb5-user curl jq ca-certificates \
 && rm -rf /var/lib/apt/lists/*
