#!/bin/sh
# dhclient's script in the lab clients (dhclient -sf): it puts the leased address on the
# interface, the default route through option 3 and writes one line per event to
# /run/lab/events, which smoke.sh reads:
#   <reason> ip=<address> mask=<mask> routers=<option 3> dns=<option 6> ntp=<option 42>
#            server=<option 54> lease=<option 51> domain=<option 15>
# Debian's own dhclient-script also writes resolv.conf and runs hooks; the lab needs
# neither, and this script keeps the docker-assigned address out of the way the same way.
# dhclient sets reason, interface and the new_ and old_ variables.
# shellcheck disable=SC2154
set -u

prefix_len() {
  # The prefix length of a dotted mask.
  bits=0
  for octet in $(echo "$1" | tr . ' '); do
    case "$octet" in
      255) bits=$((bits + 8)) ;; 254) bits=$((bits + 7)) ;; 252) bits=$((bits + 6)) ;;
      248) bits=$((bits + 5)) ;; 240) bits=$((bits + 4)) ;; 224) bits=$((bits + 3)) ;;
      192) bits=$((bits + 2)) ;; 128) bits=$((bits + 1)) ;;
    esac
  done
  echo "$bits"
}

log() {
  # WP8.4: domain= (option 15) for E27's class rows.
  printf '%s ip=%s mask=%s routers=%s dns=%s ntp=%s server=%s lease=%s domain=%s\n' \
    "$reason" "${new_ip_address:-}" "${new_subnet_mask:-}" "${new_routers:-}" \
    "${new_domain_name_servers:-}" "${new_ntp_servers:-}" \
    "${new_dhcp_server_identifier:-}" "${new_dhcp_lease_time:-}" \
    "${new_domain_name:-}" >>/run/lab/events
}

case "$reason" in
  PREINIT)
    ip link set dev "$interface" up
    ;;
  BOUND | RENEW | REBIND | REBOOT)
    if [ -n "${old_ip_address:-}" ] && [ "${old_ip_address}" != "${new_ip_address}" ]; then
      ip -4 addr del "$old_ip_address/$(prefix_len "${old_subnet_mask:-255.255.255.255}")" \
        dev "$interface" 2>/dev/null || true
    fi
    # The address docker gave the container goes on the first binding.
    ip -4 addr flush dev "$interface" scope global
    ip -4 addr add "$new_ip_address/$(prefix_len "${new_subnet_mask:-255.255.255.255}")" \
      dev "$interface"
    router="${new_routers%% *}"
    if [ -n "$router" ]; then
      ip route replace default via "$router" dev "$interface"
    fi
    log
    ;;
  EXPIRE | FAIL | RELEASE | STOP)
    if [ -n "${old_ip_address:-}" ]; then
      ip -4 addr del "$old_ip_address/$(prefix_len "${old_subnet_mask:-255.255.255.255}")" \
        dev "$interface" 2>/dev/null || true
    fi
    log
    ;;
  *)
    log
    ;;
esac
exit 0
