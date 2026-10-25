#!/bin/sh
# The Kea servers of E30 (WP9.3): kea-dhcp4 (no argument, or `4`) or kea-dhcp6 (`6`) from
# the configuration and the lease file that Tenko's export wrote into /lab/kea (mounted
# read-only). Kea keeps its leases in its data directory, the only place Kea 2.6 accepts
# for the lease file, so the exported file is copied there first.
set -eu
family="${1:-4}"
case "$family" in
  4 | 6) ;;
  *) echo "kea.sh: the family is 4 or 6, not $family" >&2; exit 2 ;;
esac
mkdir -p /run/kea /var/lib/kea /var/log/kea
if [ -f "/lab/kea/kea-leases$family.csv" ]; then
  cp "/lab/kea/kea-leases$family.csv" "/var/lib/kea/kea-leases$family.csv"
fi
exec "kea-dhcp$family" -c "/lab/kea/kea-dhcp$family.json"
