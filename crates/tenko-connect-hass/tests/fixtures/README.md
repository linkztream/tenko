# Fixtures of the Home Assistant connector

Each file holds REST answers by path and WebSocket results by command, in the layout the mock of `tests/support` serves: `{"rest": {"<path>": <answer>}, "ws": {"<command>": <result>}}`.

## `documented.json`

A hand-written instance in the shapes of the documented REST and WebSocket API, with documentation addresses (RFC 5737, RFC 3849), MAC addresses (RFC 7042) and invented names, and the edge cases the tests need (its `description` lists them). `tests/plugin.rs` asserts its exact values.

## `recorded.json`

The answers of a real Home Assistant instance (2026.10, 360 devices, 3346 entities, 2247 states, 17 areas, 89 config entries), recorded on 2026-10-16 with the recorder in `tests/live.rs` through the plugin's own client and anonymised by `tenko_connect::sdk::anonymise` before anything was written to disk. The test `the_recorded_instance_reads_like_the_live_one` in `tests/plugin.rs` reads it through the mock and asserts the counts the live smoke printed the same day: 106 hosts with 115 MAC addresses, no IP address (no entity of that instance shows one), 52 vendor facts, 9 integrations, 34 devices in an area.

What the anonymiser did, so that the shapes, counts and relations between records survive while nothing of the recorded environment does:

- Every MAC address became one of the documentation addresses `00:00:5e:00:53:xx` (Zigbee and other EUI-64 identifiers `00:00:5e:ff:fe:00:xx:xx`), the same placeholder wherever the address appears, in the notation it was found in. Other connection and identifier values became `id-n`.
- Every private IPv4 /24 block became a documentation network (`192.0.2.0/24`, `198.51.100.0/24`), with the host part kept; every public IPv4 address landed in `203.0.113.0/24`, which the plugin counts as local (the test re-reads the recording with TEST-NET-3 as the public range to check that nothing changes).
- Every registry id, config entry id and UUID became a counter in the same format; every entity id kept its domain and became `<domain>.entity_n`; every name (`name`, `name_by_user`, `original_name`, `friendly_name`, `title` of a config entry) became `name-n`, manufacturers `Vendor n`, models and model ids `Model n`, area and label slugs `id-n`, other free text `text-n`. Integration domains (`platform`, `domain`), `sw_version` and `hw_version`, units, device classes and icons were kept.
- The `attributes` of a state were reduced to the ones the plugin reads (`friendly_name`, `host_name`, `hostname`, `ip`, `ip_address`, `host`, `mac`, `mac_address`) plus `source_type`, `device_class`, `state_class`, `unit_of_measurement`, `icon`, `supported_features`, `entity_category`, `restored` and `assumed_state`; the `context` of a state was dropped; a state that is not an address, a number, a timestamp or a generic word (`on`, `home`, `not_home`, ...) became `text-n`. Of `/api/config` only `version` was kept.
- Members whose keys name credentials, keys, tokens or pictures were dropped; coordinates were zeroed.

Before the file was looked at, a grep over it for IPv4 addresses outside the documentation and benchmarking ranges, for MAC addresses outside `00:00:5e:00:53`, `00:00:5e:ff:fe` and `02:00:5e`, for IPv6 addresses outside `2001:db8::/32` and `fe80::/10`, and for the host name of the `.env` found nothing.

To record again: put the token into `.env` (see `.env.example`) and run

```
TENKO_LIVE_HASS=1 TENKO_RECORD=1 cargo nextest run -p tenko-connect-hass -E 'test(live_record_fixture)' --no-capture
```

It prints counts only. Repeat the grep above before reading the output, and update the counts in `tests/plugin.rs` and in this file.
