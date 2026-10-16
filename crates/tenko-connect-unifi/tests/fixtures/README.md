# Fixtures of the UniFi connector

Two sets of answers of the classic API, both in the envelope `{"meta": {"rc": "ok"}, "data": [...]}` that the fake controller of `tests/support` serves.

## `classic/`

Hand-written records that follow the documented classic API, with documentation addresses (RFC 5737, RFC 3849), MAC addresses (RFC 7042) and invented names. They carry the edge cases the read and write tests need: an unadopted device, a client with an invalid MAC address, an offline client record, a wireless network of an older controller that tags the SSID itself, a `customize` profile that lists what it excludes, a network with DHCP relay. `tests/read.rs` and `tests/write.rs` assert their exact values.

## `recorded/`

The answers of a real self-hosted Network Application (version 10.6, four switches and two access points, no UniFi gateway), recorded on 2026-10-16 with the recorder in `tests/live.rs` through the plugin's own session and anonymised by `tenko_connect::sdk::anonymise` before anything was written to disk. `tests/recorded.rs` reads them through the fake controller and asserts the counts the live smoke printed the same day.

| File | Endpoint | Records |
|---|---|---|
| `device.json` | `stat/device` | 6 |
| `sta.json` | `stat/sta` | 63 |
| `networkconf.json` | `rest/networkconf` | 6 |
| `wlanconf.json` | `rest/wlanconf` | 1 |
| `portconf.json` | `rest/portconf` | 2 |
| `user.json` | `rest/user` | the records of the connected clients and three offline ones |
| `sysinfo.json` | `stat/sysinfo` | 1 |

What the anonymiser did, so that the shapes, counts and relations between records survive while nothing of the recorded environment does:

- Every MAC address became one of the documentation addresses `00:00:5e:00:53:xx` (EUI-64 identifiers `00:00:5e:ff:fe:00:xx:xx`), the same placeholder wherever the address appears, in the notation it was found in.
- Every private IPv4 /24 block became a documentation network (`192.0.2.0/24`, `198.51.100.0/24`) or a block of the benchmarking range `198.18.0.0/15`, contiguous for a wider network, with the host part kept; every public IPv4 address landed in `203.0.113.0/24`. IPv6 prefixes became `2001:db8:n::/48` with the subnet id kept and MAC-derived interface identifiers replaced; link-local addresses keep `fe80::`.
- Every record id, UUID and hash became a counter in the same format; every name (device, client, port, network, SSID, domain) became `name-n`, vendors `Vendor n`, models `Model n`, other free text `text-n`; identifiers that were not in a known format became `id-n`.
- Members whose keys name credentials (`x_*`, passwords, keys, tokens), identities, locations (`geo_info`, coordinates, country codes) and the bulky statistics no connector reads (`stat`, `sys_stats`, `system-stats`, `ssh_session_table`, `radio_table_stats`, `scan_radio_table`, `ipv4_active_leases`) were dropped. Enumeration values the plugin reads (`type`, `purpose`, `forward`, `op_mode`, `radio`, ...), numbers, booleans and timestamps were kept.

Before the files were looked at, a grep over them for IPv4 addresses outside the documentation and benchmarking ranges, for MAC addresses outside `00:00:5e:00:53`, `00:00:5e:ff:fe` and `02:00:5e`, for IPv6 addresses outside `2001:db8::/32` and `fe80::/10`, and for the host name and the account of the `.env` found nothing.

To record again: put the local account into `.env` (see `.env.example`) and run

```
TENKO_LIVE_UNIFI=1 TENKO_RECORD=1 cargo nextest run -p tenko-connect-unifi --run-ignored all -E 'test(live_record_fixtures)' --no-capture
```

It prints counts only. Repeat the grep above before reading the output, and update the counts in `tests/recorded.rs` and in this file.
