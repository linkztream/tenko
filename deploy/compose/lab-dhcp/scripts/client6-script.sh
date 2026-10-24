#!/bin/sh
# dhclient's script for dhclient -6 in the lab clients (dhclient -sf): it puts the leased
# address on the interface and writes one line per event to /run/lab/events6, which
# smoke.sh reads:
#   <reason> ip6=<address> len=<prefix length> dns=<option 23> search=<option 24>
#            ntp=<option 56> valid=<seconds> preferred=<seconds>
# The variables dhclient passes go to /run/lab/env6.<reason> for a look at what it hands
# over. dhclient sets reason, interface and the new_ and old_ variables.
# shellcheck disable=SC2154
set -u

# ntp_servers <option 56>: the server addresses of option 56 (RFC 5908), as dhclient hands
# the option over: colon-separated octets in hex, the sub-options with two-octet codes and
# lengths; sub-option 1 is a server address. Prints them as eight groups, comma separated.
ntp_servers() {
  echo "$1" | awk -F: '
    function hex(s,   n, i) {
      n = 0
      for (i = 1; i <= length(s); i++) n = n * 16 + index("0123456789abcdef", tolower(substr(s, i, 1))) - 1
      return n
    }
    {
      i = 1
      out = ""
      while (i + 3 <= NF) {
        code = hex($i) * 256 + hex($(i + 1))
        len = hex($(i + 2)) * 256 + hex($(i + 3))
        i += 4
        if (code == 1 && len == 16) {
          addr = ""
          for (g = 0; g < 8; g++) {
            addr = addr (g ? ":" : "") sprintf("%x", hex($(i + 2 * g)) * 256 + hex($(i + 2 * g + 1)))
          }
          out = out (out == "" ? "" : ",") addr
        }
        i += len
      }
      print out
    }'
}

log() {
  printf '%s ip6=%s len=%s dns=%s search=%s ntp=%s valid=%s preferred=%s\n' \
    "$reason" "${new_ip6_address:-${old_ip6_address:-}}" \
    "${new_ip6_prefixlen:-${old_ip6_prefixlen:-}}" \
    "${new_dhcp6_name_servers:-}" "${new_dhcp6_domain_search:-}" \
    "$(ntp_servers "${new_dhcp6_ntp_server:-}")" \
    "${new_max_life:-}" "${new_preferred_life:-}" >>/run/lab/events6
}

case "$reason" in
  PREINIT6)
    ip link set dev "$interface" up
    ;;
  BOUND6 | RENEW6 | REBIND6 | REBOOT6)
    env | grep -E '^(new|old)_' | sort >"/run/lab/env6.$reason"
    if [ -n "${old_ip6_address:-}" ] && [ "${old_ip6_address}" != "${new_ip6_address:-}" ]; then
      ip -6 addr del "$old_ip6_address/${old_ip6_prefixlen:-128}" dev "$interface" 2>/dev/null || true
    fi
    ip -6 addr replace "$new_ip6_address/${new_ip6_prefixlen:-128}" dev "$interface" \
      valid_lft "${new_max_life:-forever}" preferred_lft "${new_preferred_life:-forever}"
    log
    ;;
  EXPIRE6 | RELEASE6 | STOP6 | FAIL6)
    if [ -n "${old_ip6_address:-}" ]; then
      ip -6 addr del "$old_ip6_address/${old_ip6_prefixlen:-128}" dev "$interface" 2>/dev/null || true
    fi
    log
    ;;
  *)
    log
    ;;
esac
exit 0
