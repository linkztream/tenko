# Fuzz targets

This directory holds `cargo-fuzz` (libFuzzer) targets, one per parser of
network input: DNS messages, DHCPv4/DHCPv6 packets and options, zone files,
import formats and similar.

Project rule: every parser of network input ships with a fuzz target here
before it merges.

| Target | Parser |
|---|---|
| `scan_dns_message` | DNS messages of the probe: mDNS, LLMNR and reverse DNS answers (`tenko_scan::dns`) |
| `scan_snmp_message` | SNMPv3 messages and scoped PDUs (`tenko_scan::snmp::message`) |
| `scan_neighbour_tables` | The neighbour tables the probe reads: `/proc/net/arp`, `ip neigh` and `Get-NetNeighbor` CSV (`tenko_scan::methods::neighbours`) |
| `connect_hass_ws_frame` | WebSocket frames and messages of the Home Assistant connector (`tenko_connect_hass::ws`) |
| `connect_hass_inventory` | Home Assistant registry and state answers mapped to hosts and vendor facts (`tenko_connect_hass::inventory`) |
| `connect_proxmox_inventory` | Proxmox VE API answers mapped to hosts (`tenko_connect_proxmox::inventory`) |

`fuzz/Cargo.lock` is not committed; the fuzz crate resolves its dependencies when it is built.

## Running

Fuzzing requires a nightly toolchain and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run <target>
```

## Layout

- The fuzz crate is its own workspace and is excluded from the main workspace.
- `fuzz/artifacts/`, `fuzz/corpus/` and `fuzz/coverage/` are git-ignored.
- Small, meaningful seed corpora may be committed under `fuzz/seeds/<target>/`.
  Pass the directory as an extra corpus argument:
  `cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target>`.
