#!/bin/sh
# A machine that boots over the network in the DHCP lab (WP8.4, E27's PXE rows): QEMU in
# BIOS mode (SeaBIOS and the iPXE option ROM of the virtio network card, from ipxe-qemu)
# or in UEFI mode (OVMF, which boots the card with its own PXE or with the iPXE EFI driver
# of the card's ROM). The container's eth0 and the machine's tap device share a bridge, so
# the machine's DHCP broadcasts reach the lab network and the gateway relays them to the
# node. KVM when /dev/kvm is usable, else TCG, which is enough for iPXE's menu.
#
# Environment: MODE (bios or uefi), VM_MAC (the machine's MAC address).
set -eu
mkdir -p /run/lab
ip -4 addr flush dev eth0
ip link add br0 type bridge
ip link set eth0 master br0
ip tuntap add dev tap0 mode tap
ip link set tap0 master br0
ip link set tap0 up
ip link set br0 up
accel=tcg
if [ -c /dev/kvm ] && [ -w /dev/kvm ]; then
  accel=kvm
fi
set -- -machine "pc,accel=$accel" -m 512 -display none -no-reboot -boot n \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device "virtio-net-pci,netdev=net0,mac=$VM_MAC" \
  -serial file:/run/lab/console.log -monitor none
case "$MODE" in
  bios) ;;
  uefi) set -- "$@" -bios /usr/share/ovmf/OVMF.fd ;;
  *) echo "qemu-boot: MODE must be bios or uefi, not $MODE" >&2; exit 2 ;;
esac
echo "qemu-boot: $MODE on $accel with $VM_MAC"
exec qemu-system-x86_64 "$@"
