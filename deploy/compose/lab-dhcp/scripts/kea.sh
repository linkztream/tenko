#!/bin/sh
# The Kea server of E30 (WP9.3): kea-dhcp4 from the configuration and the lease file that
# Tenko's export wrote into /lab/kea (mounted read-only). Kea keeps its leases in its
# data directory, the only place Kea 2.6 accepts for the lease file, so the exported file
# is copied there first.
set -eu
mkdir -p /run/kea /var/lib/kea /var/log/kea
if [ -f /lab/kea/kea-leases4.csv ]; then
  cp /lab/kea/kea-leases4.csv /var/lib/kea/kea-leases4.csv
fi
exec kea-dhcp4 -c /lab/kea/kea-dhcp4.json
