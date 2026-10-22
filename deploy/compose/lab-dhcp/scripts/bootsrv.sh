#!/bin/sh
# The boot server of the DHCP lab (WP8.4, E27's PXE rows): TFTP (dnsmasq with its DNS and
# DHCP off) and HTTP (python3) on one address, serving the boot files of Debian's ipxe
# package (undionly.kpxe for BIOS firmware, ipxe.efi for UEFI firmware and UEFI HTTP boot),
# boot.ipxe and menu.ipxe. Both log to /run/lab (tftp.log, http.log), which smoke.sh reads.
#
# Environment: GATEWAY (the relay's address on this network), ROUTES (the networks behind
# it, where the booting machines are).
set -eu
mkdir -p /run/lab /srv/tftp /srv/http
for net in $ROUTES; do
  ip route replace "$net" via "$GATEWAY"
done
cp /usr/lib/ipxe/undionly.kpxe /usr/lib/ipxe/ipxe.efi /srv/boot/boot.ipxe /srv/tftp/
cp /usr/lib/ipxe/ipxe.efi /srv/boot/boot.ipxe /srv/boot/menu.ipxe /srv/http/
printf 'done\n' >/srv/http/done
ls -l /srv/tftp /srv/http
dnsmasq --port=0 --enable-tftp --tftp-root=/srv/tftp --log-facility=/run/lab/tftp.log \
  --user=root --pid-file=/run/lab/dnsmasq.pid
exec python3 -u -m http.server 80 --bind 0.0.0.0 --directory /srv/http 2>>/run/lab/http.log
