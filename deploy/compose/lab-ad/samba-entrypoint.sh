#!/bin/bash
# The domain controller of the AD lab: provisions LAB.EXAMPLE.TEST without its own DNS at
# the first start (the administrator password of the run from /lab/secrets/admin), then runs
# Samba in the foreground. Its DNS is the Tenko node (the compose file's `dns`), so its own
# samba_dnsupdate registers the controller's records there with nsupdate -g. The round
# script creates the users and Tenko's computer account with samba-tool afterwards.
set -euo pipefail

if [[ ! -f /var/lib/samba/private/sam.ldb ]]; then
  samba-tool domain provision --use-rfc2307 \
    --realm="$LAB_REALM" --domain="$LAB_DOMAIN" --server-role=dc \
    --dns-backend=NONE --adminpass="$(cat /lab/secrets/admin)" \
    --host-name=dc01 --host-ip=198.51.100.2
fi
# The lab's krb5.conf (the KDC by address, no reverse lookups), not the generated one,
# whose KDC lookup through DNS would ask the zone this controller has yet to register.
# samba_dnsupdate sets KRB5_CONFIG to the private copy, so that one is the lab's as well.
cp /lab/secrets/krb5.conf /etc/krb5.conf
cp /lab/secrets/krb5.conf /var/lib/samba/private/krb5.conf
exec samba -M single -i --no-process-group
