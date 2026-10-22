# syntax=docker/dockerfile:1
#
# The network boot image of the DHCP lab (deploy/compose/lab-dhcp, WP8.4, E27's PXE rows):
# the boot server and the machines that boot from it, from Debian's packages only, so that
# nothing on this side of the wire shares code with Tenko:
#
# - qemu-system-x86 with SeaBIOS, ipxe-qemu (the iPXE option ROMs QEMU's network cards
#   boot with) and ovmf (UEFI firmware): the machines, one in BIOS and one in UEFI mode;
# - ipxe: undionly.kpxe and ipxe.efi, the boot files the policies hand out;
# - dnsmasq-base: the TFTP server (dnsmasq with its DNS and DHCP off);
# - python3: the HTTP server; iproute2 for the bridge to the machine's tap device.
#
# Built by smoke.sh as tenko-dhcp-lab-pxe:latest, from this directory:
#   docker build -f deploy/compose/lab-dhcp/pxe.Dockerfile -t tenko-dhcp-lab-pxe deploy/compose/lab-dhcp
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dnsmasq-base iproute2 ipxe ipxe-qemu ovmf python3 qemu-system-x86 seabios \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/ /lab/
COPY boot/ /srv/boot/
RUN chmod 0755 /lab/*.sh /lab/*.py
